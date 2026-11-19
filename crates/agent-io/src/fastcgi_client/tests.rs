//! Connection cap, timeout and upstream host tests, plus protocol tests against a fake FastCGI
//! responder.

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::ReadBuf;
use tokio::net::TcpListener;

use super::*;

/// No-op connection for pool accounting: reads EOF, accepts writes (or fails them), records
/// when it is dropped (closed).
struct FakeConn {
    closed: Arc<AtomicBool>,
    broken_write: bool,
}

impl Drop for FakeConn {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for FakeConn {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FakeConn {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        if self.broken_write {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A pool whose dial hands out fake connections; the flags record closes.
type CloseFlags = Arc<Mutex<Vec<Arc<AtomicBool>>>>;

fn fake_pool(max_conns: i64) -> (Arc<FastCgiConnectionPool>, CloseFlags) {
    let flags: CloseFlags = Arc::default();
    let f = flags.clone();
    let pool =
        FastCgiConnectionPool::new("tcp", "fake-addr", max_conns, FastCgiDeadlines::default())
            .with_dial(move || {
                let closed = Arc::new(AtomicBool::new(false));
                f.lock().unwrap().push(closed.clone());
                Box::pin(async move {
                    Ok(Box::new(FakeConn {
                        closed,
                        broken_write: false,
                    }) as Box<dyn FcgiStream>)
                })
            });
    (pool, flags)
}

#[tokio::test]
async fn dropping_a_connection_closes_it_and_frees_its_slot() {
    let (p, flags) = fake_pool(1);
    let first = p.get().await.unwrap();
    let first_id = first.id;
    assert_eq!(p.open_connection_count(), 1);
    drop(first);
    assert!(
        flags.lock().unwrap()[0].load(Ordering::SeqCst),
        "dropped connection was not closed"
    );
    assert_eq!(p.open_connection_count(), 0);
    let second = p.get().await.unwrap();
    assert_ne!(second.id, first_id);
    assert_eq!(
        flags.lock().unwrap().len(),
        2,
        "a new connection was dialled"
    );
}

#[tokio::test]
async fn pool_exhausted_after_wait() {
    let (p, _) = fake_pool(1);
    let p = {
        let mut p = p;
        Arc::get_mut(&mut p).unwrap().timeouts.slot_wait = Duration::from_millis(30);
        p
    };
    let _held = p.get().await.unwrap();
    assert_eq!(
        p.get().await.err().unwrap(),
        "fcgi pool exhausted (max 1 conns)"
    );
}

/// A write that fails is retried once on a new connection. Neither connection stays open, and the
/// first one's slot is free for the retry although the cap is 1.
#[tokio::test]
async fn failed_attempts_close_their_connections() {
    let flags: CloseFlags = Arc::default();
    let dialled = flags.clone();
    let pool = FastCgiConnectionPool::new("tcp", "fake-addr", 1, FastCgiDeadlines::default())
        .with_dial(move || {
            let closed = Arc::new(AtomicBool::new(false));
            let mut all = dialled.lock().unwrap();
            all.push(closed.clone());
            let broken_write = all.len() == 1;
            Box::pin(async move {
                Ok(Box::new(FakeConn {
                    closed,
                    broken_write,
                }) as Box<dyn FcgiStream>)
            })
        });
    let err = pool
        .send_request(b"GET", b"/", b"h", b"r", &[], b"")
        .await
        .unwrap_err();
    assert_eq!(
        err, "fcgi: read header: unexpected EOF",
        "the retry did not run"
    );
    let all = flags.lock().unwrap();
    assert_eq!(all.len(), 2);
    assert!(
        all.iter().all(|f| f.load(Ordering::SeqCst)),
        "a connection was left open"
    );
    assert_eq!(pool.open_connection_count(), 0);
}

#[test]
fn honours_configured_timeouts() {
    let s = Duration::from_secs;
    let p = FastCgiConnectionPool::new(
        "tcp",
        "fake-addr",
        4,
        FastCgiDeadlines {
            read: s(180),
            write: s(120),
            dial: s(3),
            slot_wait: s(7),
            unlimited: false,
        },
    );
    assert_eq!(
        p.timeouts(),
        FastCgiDeadlines {
            read: s(180),
            write: s(120),
            dial: s(3),
            slot_wait: s(7),
            unlimited: false
        }
    );
    let d = FastCgiConnectionPool::new(
        "unix",
        "/run/php/php8.4-fpm.sock",
        8,
        FastCgiDeadlines::default(),
    )
    .timeouts();
    assert_eq!(
        d,
        FastCgiDeadlines {
            read: s(30),
            write: s(30),
            dial: s(5),
            slot_wait: s(5),
            unlimited: false
        }
    );
    let partial = FastCgiConnectionPool::new(
        "tcp",
        "fake-addr",
        2,
        FastCgiDeadlines {
            read: s(200),
            ..Default::default()
        },
    )
    .timeouts();
    assert_eq!((partial.read, partial.write), (s(200), s(30)));
    let u = FastCgiConnectionPool::new(
        "unix",
        "/x.sock",
        8,
        FastCgiDeadlines {
            unlimited: true,
            read: s(9),
            ..Default::default()
        },
    )
    .timeouts();
    assert_eq!(
        u,
        FastCgiDeadlines {
            read: Duration::ZERO,
            write: Duration::ZERO,
            dial: s(5),
            slot_wait: s(5),
            unlimited: true
        }
    );
    assert_eq!(
        FastCgiConnectionPool::new("tcp", "x", 0, FastCgiDeadlines::default()).connection_limit,
        256
    );
}

fn as_map(params: &[(Vec<u8>, Vec<u8>)]) -> std::collections::HashMap<String, String> {
    params
        .iter()
        .map(|(k, v)| {
            (
                String::from_utf8_lossy(k).into_owned(),
                String::from_utf8_lossy(v).into_owned(),
            )
        })
        .collect()
}

fn lines(h: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    h.iter()
        .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

#[test]
fn build_cgi_variables_sets_http_host() {
    let mut p = FastCgiConnectionPool::new("tcp", "x", 1, FastCgiDeadlines::default());
    let pm = Arc::get_mut(&mut p).unwrap();
    pm.site_root = b"/srv/site".to_vec();
    pm.index = b"index.php".to_vec();
    let params = p.build_cgi_variables(
        b"GET",
        b"/?a=1",
        b"www.example.com",
        b"203.0.113.7",
        &lines(&[("X-Forwarded-Proto", "https"), ("User-Agent", "t")]),
        b"",
        0,
    );
    let m = as_map(&params);
    assert_eq!(m["HTTP_HOST"], "www.example.com");
    assert_eq!(m["SERVER_NAME"], "www.example.com");
    assert_eq!(
        (m["HTTPS"].as_str(), m["SERVER_PORT"].as_str()),
        ("on", "443")
    );
    assert_eq!(params.iter().filter(|(k, _)| k == b"HTTP_HOST").count(), 1);
    assert_eq!(m["SCRIPT_FILENAME"], "/srv/site/index.php");
    assert_eq!(m["SCRIPT_NAME"], "/index.php");
    assert_eq!(m["QUERY_STRING"], "a=1");
    assert_eq!(m["HTTP_USER_AGENT"], "t");
    assert_eq!(m["HTTP_X_FORWARDED_PROTO"], "https");
}

/// httpoxy: a `Proxy:` header must never reach PHP as `HTTP_PROXY`.
#[test]
fn build_cgi_variables_drops_httpoxy_proxy_header() {
    let p = FastCgiConnectionPool::new("tcp", "x", 1, FastCgiDeadlines::default());
    let h = lines(&[
        ("Proxy", "http://evil.example:8080"),
        ("proxy", "x"),
        ("X-Proxy", "ok"),
    ]);
    let m = as_map(&p.build_cgi_variables(b"GET", b"/", b"h", b"1.2.3.4", &h, b"", 0));
    assert!(!m.contains_key("HTTP_PROXY"), "{m:?}");
    assert_eq!(m["HTTP_X_PROXY"], "ok");
}

#[test]
fn cgi_header_param_folds_case_and_dashes() {
    for n in ["X-Real-IP", "x_real_ip", "X-Real_IP", "X_REAL-ip"] {
        assert_eq!(cgi_header_param(n.as_bytes()), b"HTTP_X_REAL_IP", "{n}");
    }
}

#[test]
fn build_cgi_variables_script_and_headers() {
    let mut p = FastCgiConnectionPool::new("tcp", "x", 1, FastCgiDeadlines::default());
    Arc::get_mut(&mut p).unwrap().site_root = b"/srv".to_vec();
    Arc::get_mut(&mut p).unwrap().index = b"index.php".to_vec();
    let h = lines(&[
        ("Host", "h"),
        ("Content-Type", "a/b"),
        ("X-A", "1"),
        ("X-A", "2"),
        ("x-a", "3"),
    ]);
    let params = p.build_cgi_variables(
        b"POST",
        b"/../../etc/x.php?q",
        b"h:8080",
        b"1.2.3.4",
        &h,
        b"a/b",
        5,
    );
    let m = as_map(&params);
    assert_eq!(m["SCRIPT_FILENAME"], "/srv/etc/x.php");
    assert_eq!(m["SCRIPT_NAME"], "/../../etc/x.php");
    assert_eq!(
        (m["SERVER_NAME"].as_str(), m["SERVER_PORT"].as_str()),
        ("h", "8080")
    );
    assert_eq!(
        (m["CONTENT_TYPE"].as_str(), m["CONTENT_LENGTH"].as_str()),
        ("a/b", "5")
    );
    // "X-A" and "x-a" are separate header names: two HTTP_X_A params
    let xa: Vec<&[u8]> = params
        .iter()
        .filter(|(k, _)| k == b"HTTP_X_A")
        .map(|(_, v)| v.as_slice())
        .collect();
    assert_eq!(xa, vec![&b"1, 2"[..], &b"3"[..]]);
    assert!(!m.contains_key("HTTP_CONTENT_TYPE") && !m.contains_key("HTTPS"));
    let mut bare = FastCgiConnectionPool::new("tcp", "x", 1, FastCgiDeadlines::default());
    Arc::get_mut(&mut bare).unwrap().index = b"index.php".to_vec();
    let m = as_map(&bare.build_cgi_variables(b"GET", b"/a/b", b"h", b"r", &[], b"", 0));
    assert_eq!(
        (m["SCRIPT_FILENAME"].as_str(), m["SCRIPT_NAME"].as_str()),
        ("/index.php", "/a/b")
    );
}

#[test]
fn encode_name_value_pairs_lengths() {
    let long = vec![b'v'; 200];
    let enc = encode_name_value_pairs(&[(b"K".to_vec(), long.clone())]);
    assert_eq!(&enc[..6], &[1, 0x80, 0, 0, 200, b'K']);
    assert_eq!(enc.len(), 1 + 4 + 1 + 200);
    assert_eq!(
        encode_name_value_pairs(&[(b"A".to_vec(), b"bc".to_vec())]),
        vec![1, 2, b'A', b'b', b'c']
    );
}

#[tokio::test]
async fn write_record_chunks_and_pads() {
    let mut out: Vec<u8> = Vec::new();
    let body = vec![7u8; FCGI_MAX_CONTENT + 3];
    send_record(&mut out, None, 1, FCGI_STDIN, &body)
        .await
        .unwrap();
    // first record: 65535 bytes, 1 byte padding
    assert_eq!(&out[..8], &[1, FCGI_STDIN, 0, 1, 0xff, 0xff, 1, 0]);
    let second = 8 + FCGI_MAX_CONTENT + 1;
    assert_eq!(&out[second..second + 8], &[1, FCGI_STDIN, 0, 1, 0, 3, 5, 0]);
    assert_eq!(out.len(), second + 8 + 3 + 5);
    let mut empty: Vec<u8> = Vec::new();
    send_record(&mut empty, None, 1, FCGI_STDIN, b"")
        .await
        .unwrap();
    assert!(empty.is_empty());
}

#[test]
fn parse_stdout_variants() {
    let r = parse_cgi_reply(
        b"Status: 404 Not Found\r\nX-A: 1\r\nX-A: 2\r\nContent-type: text/html\r\n\r\n<p>hi</p>",
    );
    assert_eq!(r.status, 404);
    assert_eq!(
        r.headers,
        vec![
            (b"X-A".to_vec(), vec![b"1".to_vec(), b"2".to_vec()]),
            (b"Content-type".to_vec(), vec![b"text/html".to_vec()])
        ]
    );
    assert_eq!(r.body, b"<p>hi</p>");
    let r = parse_cgi_reply(b"Location: /x\n\nbody");
    assert_eq!((r.status, r.body.as_slice()), (200, &b"body"[..]));
    let r = parse_cgi_reply(b"no header boundary");
    assert_eq!(
        (r.headers.len(), r.body.as_slice()),
        (0, &b"no header boundary"[..])
    );
    let r = parse_cgi_reply(b"Status: abc\r\nnocolon\r\nA: b\r\n\r\n");
    assert_eq!((r.status, r.headers.len()), (200, 1));
    let r = parse_cgi_reply(b"A: 1\n\r\nB: 2\n\nx");
    assert_eq!(r.headers.len(), 1, "a bare CR line ends the headers");
}

#[test]
fn parse_upstream_forms() {
    let p = parse_upstream_spec(
        "fcgi:unix:/run/php/fpm.sock?root=/var/www&index=app.php",
        "",
        "",
        4,
        FastCgiDeadlines::default(),
    )
    .unwrap();
    assert_eq!(
        (p.network.as_str(), p.address.as_str()),
        ("unix", "/run/php/fpm.sock")
    );
    assert_eq!(
        (p.site_root.as_slice(), p.index.as_slice()),
        (&b"/var/www"[..], &b"app.php"[..])
    );
    let p = parse_upstream_spec(
        "fcgi:unix:/run/php/fpm.sock:",
        "/srv",
        "i.php",
        4,
        FastCgiDeadlines::default(),
    )
    .unwrap();
    assert_eq!(
        (
            p.address.as_str(),
            p.site_root.as_slice(),
            p.index.as_slice()
        ),
        ("/run/php/fpm.sock", &b"/srv"[..], &b"i.php"[..])
    );
    let p =
        parse_upstream_spec("fcgi://127.0.0.1", "", "", 4, FastCgiDeadlines::default()).unwrap();
    assert_eq!(
        (p.network.as_str(), p.address.as_str(), p.index.as_slice()),
        ("tcp", "127.0.0.1:9000", &b"index.php"[..])
    );
    let p = parse_upstream_spec(
        "fcgi://php:9001?root=/a",
        "",
        "",
        4,
        FastCgiDeadlines::default(),
    )
    .unwrap();
    assert_eq!(
        (p.address.as_str(), p.site_root.as_slice()),
        ("php:9001", &b"/a"[..])
    );
    for bad in [
        "http://x",
        "fcgi:unix:",
        "fcgi:unix::",
        "fcgi:",
        "fcgi:///path",
    ] {
        assert!(
            parse_upstream_spec(bad, "", "", 1, FastCgiDeadlines::default()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn normalize_path_matches_reference() {
    for (input, want) in [
        ("", "."),
        ("/", "/"),
        ("a/b/../c", "a/c"),
        ("/../../etc/passwd", "/etc/passwd"),
        ("../a", "../a"),
        ("a/../..", ".."),
        ("//a//b/./", "/a/b"),
        ("/a/b/..", "/a"),
    ] {
        assert_eq!(
            String::from_utf8(normalize_path(input.as_bytes())).unwrap(),
            want,
            "{input:?}"
        );
    }
    assert_eq!(join_paths(&[b"/srv", b"/x.php"]), b"/srv/x.php");
    assert_eq!(join_paths(&[b"", b""]), b"");
}

/// A fake PHP-FPM that never closes a connection itself, so a closed connection is one the client
/// closed. It answers each request with STDERR, STDOUT and END_REQUEST records that carry the request
/// id `reply_id(record type)`, and reports the params and stdin.
struct FakeFpm {
    addr: std::net::SocketAddr,
    /// Connections accepted.
    accepted: Arc<AtomicU64>,
    /// Connections that ended, whoever ended them.
    closed: Arc<AtomicU64>,
    /// The flags byte of each FCGI_BEGIN_REQUEST.
    begin_flags: Arc<Mutex<Vec<u8>>>,
    requests: tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, Vec<u8>)>,
}

async fn fake_responder(reply_id: impl Fn(u8) -> u16 + Send + Sync + 'static) -> FakeFpm {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let accepted = Arc::new(AtomicU64::new(0));
    let closed = Arc::new(AtomicU64::new(0));
    let begin_flags: Arc<Mutex<Vec<u8>>> = Arc::default();
    let (acc, clo, flags) = (accepted.clone(), closed.clone(), begin_flags.clone());
    let (tx, requests) = tokio::sync::mpsc::unbounded_channel();
    let reply_id = Arc::new(reply_id);
    tokio::spawn(async move {
        loop {
            let (mut c, _) = ln.accept().await.unwrap();
            acc.fetch_add(1, Ordering::SeqCst);
            let (tx, clo, flags, reply_id) =
                (tx.clone(), clo.clone(), flags.clone(), reply_id.clone());
            tokio::spawn(async move {
                loop {
                    let (mut params, mut stdin) = (Vec::new(), Vec::new());
                    loop {
                        let mut h = [0u8; 8];
                        if c.read_exact(&mut h).await.is_err() {
                            clo.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                        assert_eq!(h[0], FCGI_VERSION);
                        let len = usize::from(h[4]) << 8 | usize::from(h[5]);
                        let mut content = vec![0u8; len + usize::from(h[6])];
                        c.read_exact(&mut content).await.unwrap();
                        content.truncate(len);
                        match h[1] {
                            FCGI_BEGIN_REQUEST => flags.lock().unwrap().push(content[2]),
                            FCGI_PARAMS => params.extend(content),
                            FCGI_STDIN if len == 0 => break,
                            FCGI_STDIN => stdin.extend(content),
                            t => panic!("record type {t}"),
                        }
                    }
                    tx.send((params, stdin.clone())).unwrap();
                    let mut out: Vec<u8> = Vec::new();
                    send_record(
                        &mut out,
                        None,
                        reply_id(FCGI_STDERR),
                        FCGI_STDERR,
                        b"PHP notice",
                    )
                    .await
                    .unwrap();
                    let mut stdout = b"Status: 201 Created\r\nX-Echo: yes\r\n\r\n".to_vec();
                    stdout.extend_from_slice(&stdin);
                    send_record(&mut out, None, reply_id(FCGI_STDOUT), FCGI_STDOUT, &stdout)
                        .await
                        .unwrap();
                    send_empty_record(&mut out, None, reply_id(FCGI_STDOUT), FCGI_STDOUT)
                        .await
                        .unwrap();
                    send_record(
                        &mut out,
                        None,
                        reply_id(FCGI_END_REQUEST),
                        FCGI_END_REQUEST,
                        &[0; 8],
                    )
                    .await
                    .unwrap();
                    let _ = c.write_all(&out).await;
                }
            });
        }
    });
    FakeFpm {
        addr,
        accepted,
        closed,
        begin_flags,
        requests,
    }
}

/// Waits until the counter reaches `want` (or five seconds pass).
async fn wait_for(n: &AtomicU64, want: u64) {
    let end = Instant::now() + Duration::from_secs(5);
    while n.load(Ordering::SeqCst) < want && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn decode_params(mut b: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let len = |b: &mut &[u8]| -> usize {
        if b[0] < 128 {
            let n = usize::from(b[0]);
            *b = &b[1..];
            n
        } else {
            let n = (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x7fff_ffff) as usize;
            *b = &b[4..];
            n
        }
    };
    while !b.is_empty() {
        let (kl, vl) = (len(&mut b), len(&mut b));
        out.push((b[..kl].to_vec(), b[kl..kl + vl].to_vec()));
        b = &b[kl + vl..];
    }
    out
}

#[tokio::test]
async fn do_request_against_fake_responder() {
    let mut fpm = fake_responder(|_| FCGI_REQUEST_ID).await;
    let pool = parse_upstream_spec(
        &format!("fcgi://{}", fpm.addr),
        "/srv",
        "",
        4,
        FastCgiDeadlines::default(),
    )
    .unwrap();
    let body = vec![b'x'; 70_000];
    let headers = lines(&[
        ("Content-Type", "text/plain"),
        ("X-Forwarded-For", "1.2.3.4"),
    ]);
    let resp = pool
        .send_request(
            b"POST",
            b"/up.php?a=1",
            b"site",
            b"203.0.113.9",
            &headers,
            &body,
        )
        .await
        .unwrap();
    assert_eq!(resp.status, 201);
    assert_eq!(
        resp.headers,
        vec![(b"X-Echo".to_vec(), vec![b"yes".to_vec()])]
    );
    assert_eq!(resp.body, body);
    let (params, stdin) = fpm.requests.recv().await.unwrap();
    assert_eq!(stdin, body);
    let m = as_map(&decode_params(&params));
    assert_eq!(m["SCRIPT_FILENAME"], "/srv/up.php");
    assert_eq!(m["CONTENT_LENGTH"], "70000");
    assert_eq!(m["CONTENT_TYPE"], "text/plain");
    assert_eq!(m["HTTP_X_FORWARDED_FOR"], "1.2.3.4");
    assert_eq!(m["REMOTE_ADDR"], "203.0.113.9");
    assert_eq!(pool.open_connection_count(), 0);
}

#[tokio::test]
async fn each_request_gets_its_own_connection_and_flags_zero() {
    let fpm = fake_responder(|_| FCGI_REQUEST_ID).await;
    let pool =
        FastCgiConnectionPool::new("tcp", &fpm.addr.to_string(), 4, FastCgiDeadlines::default());
    for _ in 0..2 {
        let resp = pool
            .send_request(b"GET", b"/", b"site", b"203.0.113.9", &[], b"")
            .await
            .unwrap();
        assert_eq!(resp.status, 201);
    }
    assert_eq!(
        fpm.accepted.load(Ordering::SeqCst),
        2,
        "two requests, two connections"
    );
    assert_eq!(
        *fpm.begin_flags.lock().unwrap(),
        [0, 0],
        "FCGI_BEGIN_REQUEST flags"
    );
    wait_for(&fpm.closed, 2).await;
    assert_eq!(
        fpm.closed.load(Ordering::SeqCst),
        2,
        "the client closes each connection after its reply"
    );
    assert_eq!(pool.open_connection_count(), 0);
}

/// A reply record for another request fails the request, whichever record it is, and the
/// connection is closed.
#[tokio::test]
async fn a_record_for_another_request_fails_the_request() {
    for (record, other) in [(FCGI_STDERR, 2), (FCGI_STDOUT, 0), (FCGI_END_REQUEST, 7)] {
        let fpm = fake_responder(move |t| if t == record { other } else { FCGI_REQUEST_ID }).await;
        let pool = FastCgiConnectionPool::new(
            "tcp",
            &fpm.addr.to_string(),
            2,
            FastCgiDeadlines::default(),
        );
        let err = pool
            .send_request(b"GET", b"/", b"h", b"r", &[], b"")
            .await
            .unwrap_err();
        assert_eq!(
            err,
            format!("fcgi: reply record for request {other}, expected 1"),
            "record type {record}"
        );
        assert_eq!(pool.open_connection_count(), 0, "record type {record}");
        wait_for(&fpm.closed, 1).await;
        assert_eq!(
            fpm.closed.load(Ordering::SeqCst),
            1,
            "connection left open, record type {record}"
        );
    }
}

#[tokio::test]
async fn read_timeout_and_dial_error() {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    tokio::spawn(async move {
        let (_c, _) = ln.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });
    let pool = FastCgiConnectionPool::new(
        "tcp",
        &addr.to_string(),
        2,
        FastCgiDeadlines {
            read: Duration::from_millis(100),
            ..Default::default()
        },
    );
    let err = pool
        .send_request(b"GET", b"/", b"h", b"r", &[], b"")
        .await
        .unwrap_err();
    assert_eq!(err, "fcgi: read header: timed out");
    assert_eq!(
        pool.open_connection_count(),
        0,
        "a failed connection keeps no slot"
    );
    let dead = FastCgiConnectionPool::new(
        "unix",
        "/nonexistent/php.sock",
        2,
        FastCgiDeadlines::default(),
    );
    let err = dead
        .send_request(b"GET", b"/", b"h", b"r", &[], b"")
        .await
        .unwrap_err();
    assert!(
        err.starts_with("fcgi dial unix:/nonexistent/php.sock: "),
        "{err}"
    );
    assert_eq!(dead.open_connection_count(), 0);
}
