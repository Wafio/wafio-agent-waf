//! Decisions go into a bounded queue (1024) without blocking the request path; a full queue
//! drops and counts it in the metrics. A single drainer sends them over the live stream and
//! drops them silently while no stream is up.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use tokio::sync::mpsc;
use wafio_proto::v1::WafDecisionEvent;

/// Capacity of the decision queue.
pub const TELEMETRY_QUEUE_CAP: usize = 1024;

/// One WAF decision. Request data is raw bytes; it is made valid UTF-8
/// only where it crosses into proto.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionEvent {
    pub app_id: Vec<u8>,
    pub host: Vec<u8>,
    pub method: Vec<u8>,
    pub uri: Vec<u8>,
    pub remote_address: Vec<u8>,
    pub user_agent: Vec<u8>,
    pub content_type: Vec<u8>,
    /// "block" | "allow" | "monitor" | "upstream_error" | ...
    pub action: Vec<u8>,
    pub score: i64,
    pub categories: Vec<Vec<u8>>,
    pub cwe: Vec<u8>,
    pub match_detail: Vec<u8>,
    pub analyze_method: Vec<u8>,
    pub body_size: i64,
    pub latency_us: i64,
    pub body_preview: Vec<u8>,
    /// Unix seconds of the event time; 0 means "now" at emit.
    pub event_time_unix: i64,
    pub match_source: Vec<u8>,
    /// The engine named `match_source` itself.
    pub match_source_exact: bool,
    /// The flagged part's value; read by redaction only, never sent.
    pub match_value: Option<Vec<u8>>,
    pub request_headers: HashMap<Vec<u8>, Vec<u8>>,
    pub request_body: Vec<u8>,
    pub query_params: Vec<u8>,
    pub payload_type: Vec<u8>,
    /// Semantic-scan gap flags; empty = complete.
    pub coverage: Vec<u8>,
    /// The HTTP status the client received; 0 = not recorded.
    pub status: i64,
}

/// Credential redaction applied to every decision before it leaves the agent. Must clear
/// `match_value`.
pub type Redactor = fn(&mut DecisionEvent);

/// The agent's own view of what it reported and what it lost.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TelemetryStats {
    /// Decisions offered to the queue.
    pub decisions: u64,
    /// Of those, blocks.
    pub blocks: u64,
    /// Dropped because the queue was full.
    pub dropped: u64,
    /// Handed to the stream.
    pub sent: u64,
    /// Refused by the stream.
    pub send_failed: u64,
    pub queue_len: usize,
    pub queue_cap: usize,
}

pub(crate) struct Telemetry {
    pub(crate) decisions: AtomicU64,
    pub(crate) blocks: AtomicU64,
    pub(crate) dropped: AtomicU64,
    pub(crate) sent: AtomicU64,
    pub(crate) send_fail: AtomicU64,
    last_warn: AtomicI64,
    last_drop: AtomicU64,
    tx: mpsc::Sender<WafDecisionEvent>,
    pub(crate) rx: Mutex<Option<mpsc::Receiver<WafDecisionEvent>>>,
}

impl Telemetry {
    pub(crate) fn new() -> Self {
        let (tx, rx) = mpsc::channel(TELEMETRY_QUEUE_CAP);
        Telemetry {
            decisions: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            send_fail: AtomicU64::new(0),
            last_warn: AtomicI64::new(0),
            last_drop: AtomicU64::new(0),
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    pub(crate) fn stats(&self) -> TelemetryStats {
        TelemetryStats {
            decisions: self.decisions.load(Ordering::Relaxed),
            blocks: self.blocks.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            sent: self.sent.load(Ordering::Relaxed),
            send_failed: self.send_fail.load(Ordering::Relaxed),
            queue_len: self.tx.max_capacity() - self.tx.capacity(),
            queue_cap: self.tx.max_capacity(),
        }
    }

    /// Count, then a non-blocking enqueue; drop when full.
    pub(crate) fn emit(&self, ev: DecisionEvent) {
        let block = ev.action == b"block";
        let out = to_proto(ev);
        self.decisions.fetch_add(1, Ordering::Relaxed);
        if block {
            self.blocks.fetch_add(1, Ordering::Relaxed);
        }
        if self.tx.try_send(out).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            self.warn_about_drops();
        }
    }

    /// Logs at most once a minute, and only when the drop count moved.
    pub(crate) fn warn_about_drops(&self) {
        let total = self.dropped.load(Ordering::Relaxed);
        if total == self.last_drop.load(Ordering::Relaxed) {
            return;
        }
        let now = crate::timestamp::Timestamp::from_system(std::time::SystemTime::now()).unix;
        let last = self.last_warn.load(Ordering::Relaxed);
        if now - last < 60 {
            return;
        }
        if self
            .last_warn
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return; // another thread is logging this window
        }
        let since = total - self.last_drop.swap(total, Ordering::Relaxed);
        let s = self.stats();
        tracing::info!(
            "[agent-grpc] telemetry queue full: {since} decision(s) dropped in the last window, {total} total (queue {}/{})",
            s.queue_len,
            s.queue_cap
        );
    }
}

/// The proto event for `ev`: every string made valid UTF-8, numbers
/// clamped to int32, a zero timestamp replaced by now.
pub fn to_proto(ev: DecisionEvent) -> WafDecisionEvent {
    let mut out = WafDecisionEvent {
        ts_unix: ev.event_time_unix,
        method: replace_invalid_utf8(&ev.method),
        host: replace_invalid_utf8(&ev.host),
        uri: replace_invalid_utf8(&ev.uri),
        remote_ip: replace_invalid_utf8(&ev.remote_address),
        status: clamp_i32(ev.status),
        score: clamp_i32(ev.score),
        action: replace_invalid_utf8(&ev.action),
        categories: ev
            .categories
            .iter()
            .map(|c| replace_invalid_utf8(c))
            .collect(),
        match_detail: replace_invalid_utf8(&ev.match_detail),
        analyze_method: replace_invalid_utf8(&ev.analyze_method),
        app_id: replace_invalid_utf8(&ev.app_id),
        user_agent: replace_invalid_utf8(&ev.user_agent),
        content_type: replace_invalid_utf8(&ev.content_type),
        body_size: clamp_i32(ev.body_size),
        body_preview: replace_invalid_utf8(&ev.body_preview),
        cwe: replace_invalid_utf8(&ev.cwe),
        latency_us: clamp_i32(ev.latency_us),
        match_source: replace_invalid_utf8(&ev.match_source),
        // Keys too: two keys that sanitize alike collapse onto one entry (accepted).
        request_headers: ev
            .request_headers
            .iter()
            .map(|(k, v)| (replace_invalid_utf8(k), replace_invalid_utf8(v)))
            .collect(),
        request_body: replace_invalid_utf8(&ev.request_body),
        query_params: replace_invalid_utf8(&ev.query_params),
        payload_type: replace_invalid_utf8(&ev.payload_type),
        coverage: replace_invalid_utf8(&ev.coverage),
        match_source_exact: ev.match_source_exact,
    };
    if out.ts_unix == 0 {
        out.ts_unix = crate::timestamp::Timestamp::from_system(std::time::SystemTime::now()).unix;
    }
    out
}

/// Each run of invalid bytes becomes one U+FFFD (Rust's `from_utf8_lossy` writes one per
/// maximal invalid subpart instead).
pub fn replace_invalid_utf8(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let mut invalid = false;
    for chunk in b.utf8_chunks() {
        if !chunk.valid().is_empty() {
            out.push_str(chunk.valid());
            invalid = false;
        }
        if !chunk.invalid().is_empty() && !invalid {
            out.push('\u{FFFD}');
            invalid = true;
        }
    }
    out
}

pub fn clamp_i32(v: i64) -> i32 {
    v.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn ev(uri: &str, action: &str) -> DecisionEvent {
        DecisionEvent {
            uri: uri.into(),
            action: action.into(),
            ..Default::default()
        }
    }

    #[test]
    fn the_proto_event_carries_the_http_status() {
        let mut e = ev("/a", "block");
        e.status = 403;
        assert_eq!(to_proto(e).status, 403);
        assert_eq!(to_proto(ev("/a", "allow")).status, 0, "0 = not recorded");
    }

    #[test]
    fn sanitize_leaves_valid_strings_alone() {
        for s in [
            "",
            "/index.php?id=1",
            "harga: Rp1.000 — ✓ 日本語",
            "' OR 1=1--",
            "\u{FFFD}",
        ] {
            assert_eq!(replace_invalid_utf8(s.as_bytes()), s);
        }
    }

    #[test]
    fn sanitize_replaces_each_invalid_run_once() {
        let cases: [(&[u8], &str); 9] = [
            (b"/a\xffb", "/a\u{FFFD}b"),
            (b"\xc3", "\u{FFFD}"),
            (b"\xe2\x82", "\u{FFFD}"),
            (b"\xed\xa0\x80", "\u{FFFD}"),
            (b"\xf5\x80\x80\x80", "\u{FFFD}"),
            (b"\xc0\xaf", "\u{FFFD}"),
            (b"q=\xff\xfe", "q=\u{FFFD}"),
            (b"\xe2\x82A\xffB", "\u{FFFD}A\u{FFFD}B"),
            (b"\xf0\x80\x80", "\u{FFFD}"),
        ];
        for (input, want) in cases {
            assert_eq!(replace_invalid_utf8(input), want, "{input:?}");
        }
        assert!(!replace_invalid_utf8(b"\xc0\xaf").contains('/'));
    }

    #[test]
    fn sanitized_decision_event_marshals() {
        let mut e = DecisionEvent {
            method: b"GET".to_vec(),
            host: b"www\xff.example.com".to_vec(),
            uri: b"/search?q=\xff\xfe".to_vec(),
            remote_address: b"203.0.113.9".to_vec(),
            action: b"block".to_vec(),
            categories: vec![b"sqli".to_vec(), b"gener\xffic".to_vec()],
            match_detail: b"matched \xc3".to_vec(),
            body_preview: b"\x00\xff\xfe binary".to_vec(),
            score: i64::MAX,
            body_size: -1 << 40,
            ..Default::default()
        };
        e.request_headers
            .insert(b"X-Junk\xff".to_vec(), b"v\xff".to_vec());
        let out = to_proto(e);
        let back = WafDecisionEvent::decode(out.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.uri, "/search?q=\u{FFFD}");
        assert_eq!(back.method, "GET");
        assert_eq!(back.score, i32::MAX);
        assert_eq!(back.body_size, i32::MIN);
        assert_eq!(back.request_headers["X-Junk\u{FFFD}"], "v\u{FFFD}");
        assert!(back.ts_unix > 0);
    }

    #[test]
    fn counts_decisions_blocks_and_drops() {
        let t = Telemetry::new();
        t.emit(ev("/a", "allow"));
        t.emit(ev("/b", "block"));
        t.emit(ev("/c", "block"));
        let s = t.stats();
        assert_eq!(
            (s.decisions, s.blocks, s.dropped, s.queue_len, s.queue_cap),
            (3, 2, 0, 3, TELEMETRY_QUEUE_CAP)
        );

        let t = Telemetry::new();
        let start = std::time::Instant::now();
        for _ in 0..TELEMETRY_QUEUE_CAP + 50 {
            t.emit(ev("/flood", "allow"));
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "enqueue blocked"
        );
        let s = t.stats();
        assert_eq!(s.decisions, (TELEMETRY_QUEUE_CAP + 50) as u64);
        assert_eq!(s.dropped, 50);
    }

    #[test]
    fn warn_on_drops_is_rate_limited() {
        let t = std::sync::Arc::new(Telemetry::new());
        let threads: Vec<_> = (0..50)
            .map(|_| {
                let t = t.clone();
                std::thread::spawn(move || {
                    t.dropped.fetch_add(1, Ordering::Relaxed);
                    t.warn_about_drops();
                })
            })
            .collect();
        threads.into_iter().for_each(|h| h.join().unwrap());
        let first = t.last_warn.load(Ordering::Relaxed);
        t.dropped.fetch_add(1, Ordering::Relaxed);
        t.warn_about_drops();
        assert_eq!(
            t.last_warn.load(Ordering::Relaxed),
            first,
            "logged twice inside the window"
        );
    }
}
