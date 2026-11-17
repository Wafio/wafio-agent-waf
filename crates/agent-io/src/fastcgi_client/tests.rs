//! Pool, timeout and upstream host tests, plus protocol tests against a fake FastCGI
//! responder.

use std::sync::atomic::AtomicBool;
use std::task::{Context, Poll};

use tokio::io::ReadBuf;
use tokio::net::TcpListener;

use super::*;

/// No-op connection for pool accounting: reads EOF, accepts writes, records
/// when it is dropped (closed).
struct FakeConn(Arc<AtomicBool>);

impl Drop for FakeConn {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
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

fn fake_pool(max_conns: i64, ttl: Duration) -> (Arc<FastCgiConnectionPool>, CloseFlags) {
    let flags: Arc<Mutex<Vec<Arc<AtomicBool>>>> = Arc::default();
    let f = flags.clone();
    let pool = FastCgiConnectionPool::new(
        "tcp",
        "fake-addr",
        max_conns,
        FastCgiDeadlines {
            max_idle_age: ttl,
            ..Default::default()
        },
    )
    .with_dial(move || {
        let flag = Arc::new(AtomicBool::new(false));
        f.lock().unwrap().push(flag.clone());
        Box::pin(async move { Ok(Box::new(FakeConn(flag)) as Box<dyn FcgiStream>) })
    });
    (pool, flags)
}

fn force_stale(p: &FastCgiConnectionPool) {
    let mut st = p.lock();
    let n = st.idle.len();
    st.idle[n - 1].last_used_at = Instant::now() - Duration::from_secs(120);
}

#[tokio::test]
async fn stale_idle_no_slot_leak() {
    const MAX: i64 = 8;
    let (p, _) = fake_pool(MAX, Duration::from_secs(60));
    for i in 0..MAX + 4 {
        let c = p
            .get()
            .await
            .unwrap_or_else(|e| panic!("get() iteration {i}: {e}"));
        p.put(c);
        force_stale(&p);
        assert_eq!(p.open_connection_count(), 1, "iteration {i}");
    }
    p.close();
    assert_eq!(p.open_connection_count(), 0);
}

#[tokio::test]
async fn fresh_idle_reuses_slot() {
    let (p, _) = fake_pool(4, Duration::from_secs(60));
    let first = p.get().await.unwrap();
    let id = first.id;
    p.put(first);
    let c = p.get().await.unwrap();
    assert_eq!(c.id, id, "fresh idle connection was not reused");
    assert_eq!(p.open_connection_count(), 1);
    p.close();
}

#[tokio::test]
async fn lifo() {
    let (p, _) = fake_pool(4, Duration::from_secs(60));
    let mut conns = Vec::new();
    for _ in 0..3 {
        conns.push(p.get().await.unwrap());
    }
    let last = conns[2].id;
    for c in conns {
        p.put(c);
    }
    assert_eq!(p.get().await.unwrap().id, last);
    p.close();
}

#[tokio::test]
async fn shrinks_after_burst() {
    let ttl = Duration::from_millis(250);
    let (p, flags) = fake_pool(16, ttl);
    let mut burst = Vec::new();
    for _ in 0..10 {
        burst.push(p.get().await.unwrap());
    }
    for c in burst {
        p.put(c);
    }
    let end = Instant::now() + 4 * ttl;
    while Instant::now() < end {
        let c = p.get().await.unwrap();
        p.put(c);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        p.open_connection_count(),
        1,
        "open connections under light traffic"
    );
    let closed = flags.lock().unwrap()[..10]
        .iter()
        .filter(|f| f.load(Ordering::SeqCst))
        .count();
    assert!(closed >= 9, "burst connections closed: {closed}");
    let deadline = Instant::now() + 20 * ttl;
    while p.open_connection_count() != 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!((p.open_connection_count(), p.idle_count()), (0, 0));
    p.close();
}

#[tokio::test]
async fn put_after_close() {
    let (p, flags) = fake_pool(4, Duration::from_secs(60));
    let c = p.get().await.unwrap();
    p.close();
    p.put(c);
    assert!(
        flags.lock().unwrap()[0].load(Ordering::SeqCst),
        "connection returned after close was not closed"
    );
    assert_eq!((p.open_connection_count(), p.idle_count()), (0, 0));
}

#[tokio::test]
async fn pool_exhausted_after_wait() {
    let (p, _) = fake_pool(1, Duration::from_secs(60));
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
            max_idle_age: s(15),
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
            max_idle_age: s(15),
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
            max_idle_age: s(60),
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
            max_idle_age: s(60),
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

/// A fake PHP-FPM: answers every request on a connection (FCGI_KEEP_CONN)
/// with STDERR + STDOUT + END_REQUEST and reports the params and stdin.
async fn fake_responder() -> (
    std::net::SocketAddr,
    Arc<AtomicU64>,
    tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, Vec<u8>)>,
) {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let accepted = Arc::new(AtomicU64::new(0));
    let acc = accepted.clone();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut c, _) = ln.accept().await.unwrap();
            acc.fetch_add(1, Ordering::SeqCst);
            let tx = tx.clone();
            tokio::spawn(async move {
                loop {
                    let (mut params, mut stdin) = (Vec::new(), Vec::new());
                    loop {
                        let mut h = [0u8; 8];
                        if c.read_exact(&mut h).await.is_err() {
                            return;
                        }
                        assert_eq!(h[0], FCGI_VERSION);
                        let len = usize::from(h[4]) << 8 | usize::from(h[5]);
                        let mut content = vec![0u8; len + usize::from(h[6])];
                        c.read_exact(&mut content).await.unwrap();
                        content.truncate(len);
                        match h[1] {
                            FCGI_BEGIN_REQUEST => assert_eq!(
                                content,
                                [0, FCGI_RESPONDER, FCGI_KEEP_CONN, 0, 0, 0, 0, 0]
                            ),
                            FCGI_PARAMS => params.extend(content),
                            FCGI_STDIN if len == 0 => break,
                            FCGI_STDIN => stdin.extend(content),
                            t => panic!("record type {t}"),
                        }
                    }
                    tx.send((params, stdin.clone())).unwrap();
                    let mut out: Vec<u8> = Vec::new();
                    send_record(&mut out, None, 1, FCGI_STDERR, b"PHP notice")
                        .await
                        .unwrap();
                    let mut stdout = b"Status: 201 Created\r\nX-Echo: yes\r\n\r\n".to_vec();
                    stdout.extend_from_slice(&stdin);
                    send_record(&mut out, None, 1, FCGI_STDOUT, &stdout)
                        .await
                        .unwrap();
                    send_empty_record(&mut out, None, 1, FCGI_STDOUT)
                        .await
                        .unwrap();
                    send_record(&mut out, None, 1, FCGI_END_REQUEST, &[0; 8])
                        .await
                        .unwrap();
                    c.write_all(&out).await.unwrap();
                }
            });
        }
    });
    (addr, accepted, rx)
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
async fn do_request_against_fake_responder_keeps_connection() {
    let (addr, accepted, mut rx) = fake_responder().await;
    let pool = parse_upstream_spec(
        &format!("fcgi://{addr}"),
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
    let (params, stdin) = rx.recv().await.unwrap();
    assert_eq!(stdin, body);
    let m = as_map(&decode_params(&params));
    assert_eq!(m["SCRIPT_FILENAME"], "/srv/up.php");
    assert_eq!(m["CONTENT_LENGTH"], "70000");
    assert_eq!(m["CONTENT_TYPE"], "text/plain");
    assert_eq!(m["HTTP_X_FORWARDED_FOR"], "1.2.3.4");
    assert_eq!(m["REMOTE_ADDR"], "203.0.113.9");

    let resp = pool
        .send_request(b"GET", b"/", b"site", b"203.0.113.9", &[], b"")
        .await
        .unwrap();
    assert_eq!((resp.status, resp.body.len()), (201, 0));
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "FCGI_KEEP_CONN connection not reused"
    );
    assert_eq!((pool.open_connection_count(), pool.idle_count()), (1, 1));
    pool.close();
    assert_eq!(pool.open_connection_count(), 0);
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
    assert_eq!(err, "fcgi: read header: i/o timeout");
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
