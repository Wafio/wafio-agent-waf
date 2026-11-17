//! The SIEM webhook sender. `Send` only queues (a bounded queue
//! of 256, four process-wide workers), a worker POSTs the event JSON with an `Idempotency-Key`
//! that stays the same across the up to three attempts (retried on a transport error, 408, 429
//! and 5xx with a 100 ms × 4^n back-off), and the counters feed heartbeat `siem_delivery`. Redirects
//! are not followed. The event itself (and what a verdict reports) is `wafio_proxy::siem`.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use wafio_proxy::{SiemEvent, SiemEventSender};

use crate::httpclient::{RequestOptions, request_with};

pub const QUEUE_FULL_MESSAGE: &str = "siem delivery queue full";
pub const PAYLOAD_TOO_LARGE_MESSAGE: &str = "siem event exceeds 64 KiB";

/// Cumulative process-local counters; `queued` excludes `in_flight`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeliveryCounts {
    pub accepted: u64,
    pub delivered: u64,
    pub failed: u64,
    pub dropped: u64,
    pub retried: u64,
    pub queued: i64,
    pub in_flight: i64,
}

impl DeliveryCounts {
    /// The `siem_delivery` object of the heartbeat host info (fixed field order).
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"accepted":{},"delivered":{},"failed":{},"dropped":{},"retried":{},"queued":{},"in_flight":{}}}"#,
            self.accepted,
            self.delivered,
            self.failed,
            self.dropped,
            self.retried,
            self.queued,
            self.in_flight
        )
    }
}

struct Job {
    url: Arc<str>,
    body: Vec<u8>,
    id: String,
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    delivered: AtomicU64,
    failed: AtomicU64,
    dropped: AtomicU64,
    retried: AtomicU64,
    queued: AtomicI64,
    in_flight: AtomicI64,
}

/// The queue and the workers every sender of the process shares.
pub struct Dispatcher {
    tx: SyncSender<Job>,
    c: Arc<Counters>,
}

impl Dispatcher {
    /// The workers live as long as the process.
    pub fn new(workers: usize, capacity: usize, backoff: Duration) -> Dispatcher {
        let (tx, rx) = sync_channel::<Job>(capacity);
        let (rx, c) = (Arc::new(Mutex::new(rx)), Arc::new(Counters::default()));
        for i in 0..workers {
            let (rx, c) = (rx.clone(), c.clone());
            let spawned = std::thread::Builder::new()
                .name(format!("siem-{i}"))
                .spawn(move || worker(&rx, &c, backoff));
            if let Err(e) = spawned {
                tracing::warn!("[siem] cannot start delivery worker: {e}");
            }
        }
        Dispatcher { tx, c }
    }

    pub fn snapshot(&self) -> DeliveryCounts {
        let c = &self.c;
        DeliveryCounts {
            accepted: c.accepted.load(Relaxed),
            delivered: c.delivered.load(Relaxed),
            failed: c.failed.load(Relaxed),
            dropped: c.dropped.load(Relaxed),
            retried: c.retried.load(Relaxed),
            queued: c.queued.load(Relaxed),
            in_flight: c.in_flight.load(Relaxed),
        }
    }
}

/// Four workers, a queue of 256, 100 ms back-off.
fn shared() -> &'static Dispatcher {
    static D: OnceLock<Dispatcher> = OnceLock::new();
    D.get_or_init(|| Dispatcher::new(4, 256, Duration::from_millis(100)))
}

/// Process-wide delivery health.
pub fn delivery_counts() -> DeliveryCounts {
    shared().snapshot()
}

fn worker(rx: &Mutex<Receiver<Job>>, c: &Counters, backoff: Duration) {
    // One runtime per worker: every delivery blocks on it.
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    loop {
        // The queue lock is held only while waiting for a job.
        let job = match rx.lock().unwrap_or_else(|e| e.into_inner()).recv() {
            Ok(j) => j,
            Err(_) => return,
        };
        c.queued.fetch_sub(1, Relaxed);
        c.in_flight.fetch_add(1, Relaxed);
        deliver(&rt, &job, c, backoff);
        c.in_flight.fetch_sub(1, Relaxed);
    }
}

/// Up to three attempts; the same `Idempotency-Key` every time.
fn deliver(rt: &tokio::runtime::Runtime, job: &Job, c: &Counters, backoff: Duration) {
    for attempt in 0..3u32 {
        let headers = [("Idempotency-Key", job.id.as_str())];
        let opts = RequestOptions {
            body: Some(("application/json", &job.body)),
            headers: &headers,
            follow: false,
            cap: 4096,
            truncate: true,
            timeout: Duration::from_secs(5),
        };
        let retry = match rt.block_on(request_with(
            "POST",
            &job.url,
            &wafio_agent_io::user_agent(),
            &opts,
        )) {
            Ok(r) if (200..300).contains(&r.status) => {
                c.delivered.fetch_add(1, Relaxed);
                return;
            }
            Ok(r) => r.status == 408 || r.status == 429 || r.status >= 500,
            // A URL the client rejects as unparsable fails the delivery at once.
            Err(e) => !crate::httpclient::is_parse_error(&e),
        };
        if !retry || attempt == 2 {
            c.failed.fetch_add(1, Relaxed);
            return;
        }
        c.retried.fetch_add(1, Relaxed);
        std::thread::sleep(backoff * (1 << (2 * attempt)));
    }
}

pub struct HttpWebhookSender {
    url: Arc<str>,
    dispatcher: &'static Dispatcher,
}

/// `None` when webhook delivery is disabled (empty URL).
pub fn sender_from_options(webhook_url: &str) -> Option<Arc<dyn SiemEventSender>> {
    (!webhook_url.is_empty()).then(|| {
        Arc::new(HttpWebhookSender {
            url: webhook_url.into(),
            dispatcher: shared(),
        }) as Arc<dyn SiemEventSender>
    })
}

impl SiemEventSender for HttpWebhookSender {
    fn send(&self, evt: &SiemEvent) -> Result<(), String> {
        send_to(&self.dispatcher.tx, &self.dispatcher.c, &self.url, evt)
    }
}

/// Queues a delivery job on a dispatcher's queue.
fn send_to(
    tx: &SyncSender<Job>,
    c: &Counters,
    url: &Arc<str>,
    evt: &SiemEvent,
) -> Result<(), String> {
    let body = evt.to_json();
    if body.len() > 64 * 1024 {
        c.dropped.fetch_add(1, Relaxed);
        return Err(PAYLOAD_TOO_LARGE_MESSAGE.into());
    }
    let mut id = [0u8; 16];
    if let Err(e) = wafio_agent_pages::crypto::fill_random_bytes(&mut id) {
        c.dropped.fetch_add(1, Relaxed);
        return Err(e.to_string());
    }
    let id = String::from_utf8(wafio_agent_pages::crypto::hex_encode(&id)).expect("hex");
    c.queued.fetch_add(1, Relaxed);
    match tx.try_send(Job {
        url: url.clone(),
        body,
        id,
    }) {
        Ok(()) => {
            c.accepted.fetch_add(1, Relaxed);
            Ok(())
        }
        Err(e) => {
            c.queued.fetch_sub(1, Relaxed);
            c.dropped.fetch_add(1, Relaxed);
            Err(match e {
                TrySendError::Full(_) | TrySendError::Disconnected(_) => QUEUE_FULL_MESSAGE.into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// What the fake webhook saw of one request: head (lower-cased header names) and body.
    #[derive(Clone, Debug)]
    struct Seen {
        head: String,
        body: Vec<u8>,
    }

    impl Seen {
        fn header(&self, name: &str) -> Option<&str> {
            self.head.lines().skip(1).find_map(|l| {
                l.split_once(": ")
                    .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v)
            })
        }
    }

    /// A webhook answering the n-th request with `statuses[n]` (the last one repeats); `gate`,
    /// when given, holds every answer until the test releases it. Sends each request to `seen`.
    fn webhook(
        statuses: &'static [u16],
        gate: Option<mpsc::Receiver<()>>,
    ) -> (String, mpsc::Receiver<Seen>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}/hook", l.local_addr().unwrap().port());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for (n, s) in l.incoming().flatten().enumerate() {
                let mut s = s;
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head_end, len) = loop {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (i + 4, len);
                    }
                    if n == 0 {
                        return;
                    }
                };
                while buf.len() < head_end + len {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let _ = tx.send(Seen {
                    head: String::from_utf8_lossy(&buf[..head_end]).into_owned(),
                    body: buf[head_end..].to_vec(),
                });
                if let Some(g) = &gate {
                    let _ = g.recv();
                }
                let st = statuses[n.min(statuses.len() - 1)];
                let _ = s.write_all(
                    format!("HTTP/1.1 {st} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                );
            }
        });
        (url, rx)
    }

    fn wait_for(d: &Dispatcher, f: impl Fn(&DeliveryCounts) -> bool) -> DeliveryCounts {
        for _ in 0..400 {
            let s = d.snapshot();
            if f(&s) {
                return s;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("stats never reached the expected state: {:?}", d.snapshot());
    }

    fn sender(d: &Dispatcher, url: &str) -> impl Fn(&SiemEvent) -> Result<(), String> {
        let (tx, c, url): (SyncSender<Job>, Arc<Counters>, Arc<str>) =
            (d.tx.clone(), d.c.clone(), url.into());
        move |e| send_to(&tx, &c, &url, e)
    }

    #[test]
    fn delivers_the_event_json_with_an_idempotency_key() {
        let (url, seen) = webhook(&[204], None);
        let d = Dispatcher::new(1, 4, Duration::from_millis(1));
        let send = sender(&d, &url);
        let evt = SiemEvent {
            action: "block".into(),
            score: 180,
            categories: vec!["SQLi".into()],
            match_source: b"query:q".to_vec(),
            ..Default::default()
        };
        send(&evt).unwrap();
        let s = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(s.head.starts_with("POST /hook HTTP/1.1\r\n"), "{}", s.head);
        assert_eq!(s.header("content-type"), Some("application/json"));
        let id = s.header("idempotency-key").unwrap();
        assert!(
            id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "{id}"
        );
        assert_eq!(s.body, evt.to_json());
        let st = wait_for(&d, |s| s.delivered == 1);
        assert_eq!(
            (
                st.accepted,
                st.failed,
                st.dropped,
                st.retried,
                st.queued,
                st.in_flight
            ),
            (1, 0, 0, 0, 0, 0)
        );
    }

    /// `TestRetryKeepsDeliveryIdentity`: a 429 is retried with the same key and then delivered.
    #[test]
    fn retry_keeps_the_delivery_identity() {
        let (url, seen) = webhook(&[429, 202], None);
        let d = Dispatcher::new(1, 1, Duration::from_millis(1));
        sender(&d, &url)(&SiemEvent::default()).unwrap();
        let (a, b) = (
            seen.recv_timeout(Duration::from_secs(5)).unwrap(),
            seen.recv_timeout(Duration::from_secs(5)).unwrap(),
        );
        assert!(
            a.header("idempotency-key").is_some_and(|k| !k.is_empty())
                && a.header("idempotency-key") == b.header("idempotency-key")
        );
        let st = wait_for(&d, |s| s.delivered + s.failed == 1);
        assert_eq!((st.delivered, st.retried, st.failed), (1, 1, 0));
    }

    /// Credentials in the webhook URL go out as `Authorization: Basic` (taken
    /// from the URL userinfo, percent-decoded); a URL that does not parse fails without a retry.
    #[test]
    fn webhook_url_credentials_become_basic_auth() {
        let (url, seen) = webhook(&[204], None);
        let url = url.replacen("http://", "http://hook:s%3Fcret@", 1);
        let d = Dispatcher::new(1, 4, Duration::from_millis(1));
        sender(&d, &url)(&SiemEvent::default()).unwrap();
        let s = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(s.header("authorization"), Some("Basic aG9vazpzP2NyZXQ="));
        assert!(s.head.starts_with("POST /hook HTTP/1.1\r\n"), "{}", s.head);
        wait_for(&d, |s| s.delivered == 1);
        sender(&d, "http://a b:c@127.0.0.1:1/")(&SiemEvent::default()).unwrap();
        let st = wait_for(&d, |s| s.failed == 1);
        assert_eq!((st.retried, st.delivered), (0, 1));
    }

    /// A 5xx and a refused connection are retried up to three attempts, then failed.
    #[test]
    fn a_server_error_is_retried_three_times_then_failed() {
        let (url, seen) = webhook(&[503], None);
        let d = Dispatcher::new(1, 1, Duration::from_millis(1));
        sender(&d, &url)(&SiemEvent::default()).unwrap();
        let st = wait_for(&d, |s| s.failed == 1);
        assert_eq!((st.delivered, st.retried), (0, 2));
        assert_eq!(seen.try_iter().count(), 3);
        // Nothing listens: transport errors retry the same way.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = format!("http://127.0.0.1:{}/", closed.local_addr().unwrap().port());
        drop(closed);
        sender(&d, &dead)(&SiemEvent::default()).unwrap();
        let st = wait_for(&d, |s| s.failed == 2);
        assert_eq!(st.retried, 4);
    }

    /// `TestPermanentFailureDoesNotRetry` (and a redirect is a final answer, never followed).
    #[test]
    fn a_client_error_or_redirect_is_not_retried() {
        for status in [400, 404, 302] {
            let statuses: &'static [u16] = Box::leak(Box::new([status]));
            let (url, seen) = webhook(statuses, None);
            let d = Dispatcher::new(1, 1, Duration::from_millis(1));
            sender(&d, &url)(&SiemEvent::default()).unwrap();
            let st = wait_for(&d, |s| s.failed == 1);
            assert_eq!((st.retried, st.delivered), (0, 0), "{status}");
            assert_eq!(seen.try_iter().count(), 1, "{status}");
        }
    }

    /// `TestSendQueuesWithoutWaitingAndReportsOverflow`: with one worker stuck in the network and
    /// a queue of one, the second event queues and the third is dropped as `queue full`.
    #[test]
    fn send_queues_without_waiting_and_reports_overflow() {
        let (release, gate) = mpsc::channel();
        let (url, seen) = webhook(&[204], Some(gate));
        let d = Dispatcher::new(1, 1, Duration::from_millis(1));
        let send = sender(&d, &url);
        let t = std::time::Instant::now();
        send(&SiemEvent::default()).unwrap();
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "Send waited for the network"
        );
        seen.recv_timeout(Duration::from_secs(5)).unwrap(); // the worker is inside the request
        send(&SiemEvent::default()).unwrap();
        assert_eq!(
            send(&SiemEvent::default()),
            Err(QUEUE_FULL_MESSAGE.to_string())
        );
        let st = d.snapshot();
        assert_eq!(
            (st.accepted, st.dropped, st.queued, st.in_flight),
            (2, 1, 1, 1)
        );
        drop(release); // answer the held requests
        wait_for(&d, |s| s.delivered == 2);
    }

    /// `TestOversizedEventNeverEntersQueue`.
    #[test]
    fn an_oversized_event_never_enters_the_queue() {
        let d = Dispatcher::new(1, 1, Duration::from_millis(1));
        let evt = SiemEvent {
            uri: vec![b'a'; 64 * 1024],
            ..Default::default()
        };
        assert_eq!(
            sender(&d, "http://127.0.0.1:1/")(&evt),
            Err(PAYLOAD_TOO_LARGE_MESSAGE.to_string())
        );
        let st = d.snapshot();
        assert_eq!((st.accepted, st.dropped), (0, 1));
    }

    #[test]
    fn stats_json_and_sender_options() {
        assert_eq!(
            DeliveryCounts {
                accepted: 3,
                queued: 1,
                ..Default::default()
            }
            .to_json(),
            r#"{"accepted":3,"delivered":0,"failed":0,"dropped":0,"retried":0,"queued":1,"in_flight":0}"#
        );
        assert!(sender_from_options("").is_none());
        assert!(sender_from_options("https://siem.example/hook").is_some());
    }
}
