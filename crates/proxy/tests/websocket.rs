//! Black-box WebSocket verdicts: relay, frame block 1008, oversize 1009, blocked
//! handshake and origin check never reach the upstream. Open sessions and event streams end when
//! maintenance mode turns on for their client, and sessions end when the listener goes away.

mod common;
#[path = "common/fake_engine.rs"]
mod fake_engine;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use wafio_agent_io::ws_frame::{WsConnection, WsError};

#[derive(Clone, Default)]
struct Echo {
    accepts: Arc<AtomicUsize>,
    got: Arc<Mutex<Vec<Vec<u8>>>>,
    heads: Arc<Mutex<Vec<String>>>,
    /// How each session ended on the upstream side.
    ends: Arc<Mutex<Vec<WsError>>>,
}

/// A WebSocket echo upstream (agent-io server side), recording messages and handshake heads.
async fn echo_upstream() -> (SocketAddr, Echo) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let e = Echo::default();
    let e2 = e.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            e2.accepts.fetch_add(1, Ordering::SeqCst);
            let e3 = e2.clone();
            tokio::spawn(async move {
                // Peek the head for the header assertions, then complete the handshake.
                let mut buf = vec![0u8; 4096];
                let n = s.peek(&mut buf).await.unwrap();
                e3.heads
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let Ok(c) = WsConnection::server(Box::new(s)).await else {
                    return;
                };
                loop {
                    match c.next_data_message().await {
                        Ok((kind, msg)) => {
                            e3.got.lock().unwrap().push(msg.clone());
                            if c.send_data_message(kind, &msg).await.is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            e3.ends.lock().unwrap().push(e);
                            return;
                        }
                    }
                }
            });
        }
    });
    (addr, e)
}

async fn ws_client(
    proxy: SocketAddr,
    path: &str,
    headers: &[(String, String)],
) -> Result<WsConnection, WsError> {
    let s = TcpStream::connect(proxy).await.unwrap();
    WsConnection::client(Box::new(s), "app.test", path, headers)
        .await
        .map(|(c, _)| c)
        .map_err(|(e, _)| e)
}

fn ws_app(port: u16, up: SocketAddr, rules: &str) -> wafio_proxy::AppSpec {
    let mut a = app("ws", port, &format!("http://{up}"));
    a.rules_json = rules.as_bytes().to_vec();
    a
}

#[tokio::test]
async fn relays_and_blocks_attack_frames() {
    let (up, echo) = echo_upstream().await;
    let port = free_port();
    let (h, proxy) = Harness::serve_with_fake_engine(vec![ws_app(port, up, "")]);
    let c = ws_client(
        proxy,
        "/chat?room=1",
        &[("Origin".into(), "https://app.test".into())],
    )
    .await
    .unwrap();
    c.send_data_message(1, b"hello there").await.unwrap();
    assert_eq!(
        c.next_data_message().await.unwrap(),
        (1, b"hello there".to_vec())
    );
    let head = echo.heads.lock().unwrap()[0].clone();
    assert!(head.starts_with("GET /chat?room=1 HTTP/1.1"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("x-forwarded-for: 127.0.0.1"),
        "{head}"
    );
    assert!(head.contains("Origin: https://app.test"), "{head}");
    c.send_data_message(1, br#"{"q":"wafio-test-sql"}"#)
        .await
        .unwrap();
    match c.next_data_message().await {
        Err(WsError::Close { code, .. }) => assert_eq!(code, 1008),
        other => panic!("expected close 1008, got {other:?}"),
    }
    settle().await;
    assert_eq!(
        *echo.got.lock().unwrap(),
        vec![b"hello there".to_vec()],
        "the attack frame never reached the upstream"
    );
    let ev = h.last_event();
    assert_eq!(
        (
            s(&ev.action),
            s(&ev.method),
            s(&ev.match_source),
            s(&ev.analyze_method)
        ),
        ("block", "WEBSOCKET", "ws:client", "ws_frame_scan")
    );
}

#[tokio::test]
async fn a_log_only_engine_lets_its_frame_through_and_another_engine_still_blocks() {
    let (up, echo) = echo_upstream().await;
    let port = free_port();
    let mut a = ws_app(port, up, "");
    a.analysis = analysis_setup(r#"{"semantic_policies":{"sql":{"action":"log"}}}"#);
    let (h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let c = ws_client(proxy, "/chat", &[]).await.unwrap();
    let sqli = br#"{"q":"wafio-test-sql"}"#;
    c.send_data_message(1, sqli).await.unwrap();
    assert_eq!(c.next_data_message().await.unwrap(), (1, sqli.to_vec()));
    settle().await;
    let ev = h.last_event();
    assert_eq!(
        (s(&ev.action), s(&ev.analyze_method), s(&ev.coverage)),
        ("log", "ws_frame_scan", "engine_log_only:sql")
    );
    assert!(ev.score > 0, "{ev:?}");
    assert_eq!(*echo.got.lock().unwrap(), vec![sqli.to_vec()]);

    c.send_data_message(1, br#"{"q":"wafio-test-xss"}"#)
        .await
        .unwrap();
    match c.next_data_message().await {
        Err(WsError::Close { code, .. }) => assert_eq!(code, 1008),
        other => panic!("expected close 1008, got {other:?}"),
    }
    settle().await;
    assert_eq!(s(&h.last_event().action), "block");
}

#[tokio::test]
async fn a_weak_frame_is_logged_unless_weak_detections_are_not_recorded() {
    for (rules, logged) in [
        ("{}", true),
        (
            r#"{"semantic_policies":{"record_weak_detections":false}}"#,
            false,
        ),
    ] {
        let (up, echo) = echo_upstream().await;
        let port = free_port();
        let mut a = ws_app(port, up, "");
        a.analysis = analysis_setup(rules);
        let (h, proxy) = Harness::serve_with_fake_engine(vec![a]);
        let c = ws_client(proxy, "/chat", &[]).await.unwrap();
        let weak = br#"{"q":"wafio-test-weak"}"#;
        c.send_data_message(1, weak).await.unwrap();
        assert_eq!(c.next_data_message().await.unwrap(), (1, weak.to_vec()));
        settle().await;
        let frames: Vec<_> = h
            .events()
            .into_iter()
            .filter(|e| s(&e.analyze_method) == "ws_frame_scan")
            .collect();
        assert_eq!(frames.len(), usize::from(logged), "{rules}");
        if logged {
            assert_eq!((s(&frames[0].action), frames[0].score), ("log", 115));
        }
        assert_eq!(*echo.got.lock().unwrap(), vec![weak.to_vec()], "{rules}");
    }
}

#[tokio::test]
async fn oversize_text_closes_1009() {
    let (up, echo) = echo_upstream().await;
    let port = free_port();
    let (h, proxy) = Harness::serve_with_fake_engine(vec![ws_app(
        port,
        up,
        r#"{"websocket":{"limits":{"max_text_bytes":64}}}"#,
    )]);
    let c = ws_client(proxy, "/ws", &[]).await.unwrap();
    c.send_data_message(1, &[b'a'; 100]).await.unwrap();
    match c.next_data_message().await {
        Err(WsError::Close { code, .. }) => assert_eq!(code, 1009),
        other => panic!("expected close 1009, got {other:?}"),
    }
    settle().await;
    assert!(echo.got.lock().unwrap().is_empty());
    assert_eq!(s(&h.last_event().match_detail), "ws_text_oversize");
}

/// A handshake for a path outside the app's path prefix is answered `404` like any request there,
/// and never reaches the upstream; one under the prefix is relayed with the public path.
#[tokio::test]
async fn a_handshake_outside_the_path_prefix_never_reaches_the_upstream() {
    let (up, echo) = echo_upstream().await;
    let port = free_port();
    let mut a = ws_app(port, up, "");
    a.proxy_config = br#"{"strip_path_prefix":"/shop"}"#.to_vec();
    let (h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let err = ws_client(proxy, "/admin/ws", &[])
        .await
        .err()
        .expect("handshake refused");
    assert!(matches!(err, WsError::Handshake(_)), "{err:?}");
    settle().await;
    assert_eq!(echo.accepts.load(Ordering::SeqCst), 0);
    assert_eq!(h.last_event().status, 404);

    let c = ws_client(proxy, "/shop/ws", &[]).await.unwrap();
    c.send_data_message(1, b"hi").await.unwrap();
    assert_eq!(c.next_data_message().await.unwrap(), (1, b"hi".to_vec()));
    let head = echo.heads.lock().unwrap()[0].clone();
    assert!(head.starts_with("GET /shop/ws HTTP/1.1"), "{head}");
}

#[tokio::test]
async fn blocked_handshake_and_origin_check_never_reach_upstream() {
    let (up, echo) = echo_upstream().await;
    let (p1, p2) = (free_port(), free_port());
    let (h, proxy) = Harness::serve_with_fake_engine(vec![
        ws_app(p1, up, ""),
        ws_app(
            p2,
            up,
            r#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://good.test"]}}}"#,
        ),
    ]);
    let err = ws_client(proxy, "/ws?id=wafio-test-sql", &[])
        .await
        .err()
        .expect("handshake refused");
    assert!(matches!(err, WsError::Handshake(_)), "{err:?}");
    let ev = h.last_event();
    assert_eq!(
        (s(&ev.action), s(&ev.method), s(&ev.match_source)),
        ("block", "WEBSOCKET", "ws:handshake")
    );
    let p2: SocketAddr = format!("127.0.0.1:{p2}").parse().unwrap();
    assert!(
        ws_client(p2, "/ws", &[("Origin".into(), "https://evil.test".into())])
            .await
            .is_err()
    );
    assert_eq!(s(&h.last_event().match_detail), "ws_origin_rejected");
    let c = ws_client(p2, "/ws", &[("Origin".into(), "https://good.test".into())])
        .await
        .unwrap();
    c.send_data_message(1, b"ok").await.unwrap();
    assert_eq!(c.next_data_message().await.unwrap().1, b"ok");
    assert_eq!(
        echo.accepts.load(Ordering::SeqCst),
        1,
        "only the allowed handshake reached the upstream"
    );
}

#[tokio::test]
async fn websocket_disabled_proxies_upgrade_as_http() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.rules_json = br#"{"websocket":{"enabled":false}}"#.to_vec();
    let (_h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let raw = b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    assert_eq!(one(proxy, raw).await.status, 200);
    assert_eq!(up.last().header("upgrade"), None);
}

/// `scan_binary_hashes`: a binary frame whose SHA-256 is in the executor's malware database
/// is an unconditional block tier (1008, `ws_binary_malware`) that never reaches the upstream; any
/// other binary frame passes.
#[tokio::test]
async fn binary_frame_with_a_known_hash_is_blocked() {
    use wafio_application::deps::engine::HashMatcher;
    let (up, echo) = echo_upstream().await;
    let port = free_port();
    let eng = Arc::new(HashMatcher::new(10, 0.01));
    // SHA-256 of "hello".
    eng.insert_hex_hash(
        b"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        b"Test.Hash",
    )
    .unwrap();
    let mut ex = wafio_proxy::testing::analysis_setup(RULES.as_bytes());
    ex.analyze.malware_hash_engine = Some(eng);
    let mut a = ws_app(port, up, r#"{"websocket":{"scan_binary_hashes":true}}"#);
    a.analysis = Arc::new(ex);
    let (h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let c = ws_client(proxy, "/ws", &[]).await.unwrap();
    c.send_data_message(2, b"other bytes").await.unwrap();
    assert_eq!(
        c.next_data_message().await.unwrap(),
        (2, b"other bytes".to_vec())
    );
    c.send_data_message(2, b"hello").await.unwrap();
    match c.next_data_message().await {
        Err(WsError::Close { code, .. }) => assert_eq!(code, 1008),
        other => panic!("expected close 1008, got {other:?}"),
    }
    settle().await;
    assert_eq!(
        *echo.got.lock().unwrap(),
        vec![b"other bytes".to_vec()],
        "the malware frame never reached the upstream"
    );
    let ev = h.last_event();
    assert_eq!(
        (s(&ev.action), s(&ev.match_detail), s(&ev.match_source)),
        ("block", "ws_binary_malware", "ws:client")
    );
}

// ── sessions and streams that end ───────────────────────────────────────────

const ON: &str = r#"{"enabled":true"#;

/// The app of a test of this section: client addresses come from `X-Forwarded-For`, which the
/// loopback peer is trusted to send.
fn session_app(id: &str, port: u16, up: SocketAddr, maintenance: &str) -> wafio_proxy::AppSpec {
    let mut a = app(id, port, &format!("http://{up}"));
    a.proxy_config = br#"{"trust_forwarded":true,"trusted_proxies":["127.0.0.1"]}"#.to_vec();
    a.maintenance = maintenance.as_bytes().to_vec();
    a
}

fn from(client: &str) -> Vec<(String, String)> {
    vec![("X-Forwarded-For".into(), client.into())]
}

async fn echoes(c: &WsConnection, text: &str) {
    c.send_data_message(1, text.as_bytes()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), c.next_data_message())
        .await
        .expect("an echo")
        .unwrap();
    assert_eq!(got, (1, text.as_bytes().to_vec()));
}

/// The error the session ends with, within `max`.
async fn ends_with(c: &WsConnection, max: Duration) -> WsError {
    match tokio::time::timeout(max, c.next_data_message()).await {
        Ok(Err(e)) => e,
        Ok(Ok(m)) => panic!("expected the session to end, got a message {m:?}"),
        Err(_) => panic!("the session did not end within {max:?}"),
    }
}

fn close(code: u16, text: &str) -> WsError {
    WsError::Close {
        code,
        text: text.into(),
    }
}

#[tokio::test]
async fn an_open_session_is_closed_when_maintenance_turns_on() {
    let (up, echo) = echo_upstream().await;
    let port = free_port();
    let (h, proxy) = Harness::serve_with_fake_engine(vec![session_app("ws", port, up, "")]);
    let c = ws_client(proxy, "/chat", &[]).await.unwrap();
    echoes(&c, "before").await;

    let turned_on = Instant::now();
    h.proxy
        .apply(vec![session_app("ws", port, up, &format!("{ON}}}"))])
        .unwrap();
    assert_eq!(
        ends_with(&c, Duration::from_secs(2)).await,
        close(1001, "Maintenance")
    );
    assert!(turned_on.elapsed() < Duration::from_secs(2));

    // The upstream side got a close frame too (or at least its end).
    let t = Instant::now();
    while echo.ends.lock().unwrap().is_empty() {
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "the upstream session ended"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let ends = echo.ends.lock().unwrap().clone();
    assert!(
        ends[0] == close(1001, "Maintenance")
            || matches!(&ends[0], WsError::Close { code: 1006, .. }),
        "{ends:?}"
    );
    // The handshake that follows is the 503 page.
    assert!(matches!(
        ws_client(proxy, "/chat", &[]).await.err(),
        Some(WsError::Handshake(_))
    ));
}

#[tokio::test]
async fn sessions_of_allowed_clients_survive_until_the_lists_change() {
    let (up, _echo) = echo_upstream().await;
    let port = free_port();
    let (h, proxy) = Harness::serve_with_fake_engine(vec![session_app("ws", port, up, "")]);
    let by_ip = ws_client(proxy, "/chat", &from("203.0.113.9"))
        .await
        .unwrap();
    let by_path = ws_client(proxy, "/safe/room", &from("198.51.100.1"))
        .await
        .unwrap();
    let other = ws_client(proxy, "/chat", &from("198.51.100.2"))
        .await
        .unwrap();
    for c in [&by_ip, &by_path, &other] {
        echoes(c, "hi").await;
    }
    let on = |ips: &str, paths: &str| {
        session_app(
            "ws",
            port,
            up,
            &format!(r#"{ON},"allow_ips":[{ips}],"allow_paths":[{paths}]}}"#),
        )
    };

    h.proxy
        .apply(vec![on(r#""203.0.113.9""#, r#""/safe""#)])
        .unwrap();
    assert_eq!(
        ends_with(&other, Duration::from_secs(2)).await,
        close(1001, "Maintenance")
    );
    echoes(&by_ip, "still here").await;
    echoes(&by_path, "still here").await;

    // Another change that leaves both allowed keeps them.
    h.proxy
        .apply(vec![on(r#""203.0.113.9","10.0.0.0/8""#, r#""/safe","/x""#)])
        .unwrap();
    settle().await;
    echoes(&by_ip, "again").await;
    echoes(&by_path, "again").await;

    // The path leaves the list: its session ends, the address one stays.
    h.proxy.apply(vec![on(r#""203.0.113.9""#, "")]).unwrap();
    assert_eq!(
        ends_with(&by_path, Duration::from_secs(2)).await,
        close(1001, "Maintenance")
    );
    echoes(&by_ip, "alone").await;

    // The address leaves the list.
    h.proxy.apply(vec![on(r#""10.0.0.1""#, "")]).unwrap();
    assert_eq!(
        ends_with(&by_ip, Duration::from_secs(2)).await,
        close(1001, "Maintenance")
    );
}

#[tokio::test]
async fn turning_maintenance_off_leaves_sessions_alone() {
    let (up, _echo) = echo_upstream().await;
    let port = free_port();
    let on = session_app(
        "ws",
        port,
        up,
        &format!(r#"{ON},"allow_ips":["203.0.113.9"]}}"#),
    );
    let (h, proxy) = Harness::serve_with_fake_engine(vec![on]);
    // Opened during maintenance, as an allowed client.
    let c = ws_client(proxy, "/chat", &from("203.0.113.9"))
        .await
        .unwrap();
    echoes(&c, "one").await;
    for off in ["", r#"{"enabled":false}"#] {
        h.proxy
            .apply(vec![session_app("ws", port, up, off)])
            .unwrap();
        settle().await;
        echoes(&c, "off").await;
        // And it is still judged by what it was: maintenance for everybody but its address.
        h.proxy
            .apply(vec![session_app(
                "ws",
                port,
                up,
                &format!(r#"{ON},"allow_ips":["203.0.113.9"]}}"#),
            )])
            .unwrap();
        settle().await;
        echoes(&c, "on again").await;
    }
    // A session opened while it is off ends when it comes on for everybody.
    h.proxy
        .apply(vec![session_app("ws", port, up, "")])
        .unwrap();
    let late = ws_client(proxy, "/chat", &from("198.51.100.7"))
        .await
        .unwrap();
    echoes(&late, "late").await;
    h.proxy
        .apply(vec![session_app("ws", port, up, &format!("{ON}}}"))])
        .unwrap();
    assert_eq!(
        ends_with(&late, Duration::from_secs(2)).await,
        close(1001, "Maintenance")
    );
    assert_eq!(
        ends_with(&c, Duration::from_secs(2)).await,
        close(1001, "Maintenance"),
        "the allowed address went with the list"
    );
}

#[tokio::test]
async fn an_app_on_another_listener_keeps_its_session() {
    let (up, _echo) = echo_upstream().await;
    let (p1, p2) = (free_port(), free_port());
    let spec = |maintenance_on_first: bool| {
        vec![
            session_app(
                "one",
                p1,
                up,
                if maintenance_on_first {
                    r#"{"enabled":true}"#
                } else {
                    ""
                },
            ),
            session_app("two", p2, up, ""),
        ]
    };
    let (h, first) = Harness::serve_with_fake_engine(spec(false));
    let second: SocketAddr = format!("127.0.0.1:{p2}").parse().unwrap();
    let a = ws_client(first, "/chat", &[]).await.unwrap();
    let b = ws_client(second, "/chat", &[]).await.unwrap();
    h.proxy.apply(spec(true)).unwrap();
    assert_eq!(
        ends_with(&a, Duration::from_secs(2)).await,
        close(1001, "Maintenance")
    );
    settle().await;
    echoes(&b, "untouched").await;
    // Plain requests are proxied (the upstream here only speaks WebSocket, so they get 502).
    assert_eq!(one(second, &get("/")).await.status, 502);
    assert_eq!(one(first, &get("/")).await.status, 503);
}

#[tokio::test]
async fn a_session_ends_with_going_away_when_the_listener_stops() {
    // The app leaves the bundle.
    let (up, echo) = echo_upstream().await;
    let (p1, p2) = (free_port(), free_port());
    let (h, first) = Harness::serve_with_fake_engine(vec![
        session_app("one", p1, up, ""),
        session_app("two", p2, up, ""),
    ]);
    let second: SocketAddr = format!("127.0.0.1:{p2}").parse().unwrap();
    let gone = ws_client(first, "/chat", &[]).await.unwrap();
    let kept = ws_client(second, "/chat", &[]).await.unwrap();
    h.proxy.apply(vec![session_app("two", p2, up, "")]).unwrap();
    assert_eq!(
        ends_with(&gone, Duration::from_secs(2)).await,
        close(1001, "Going away")
    );
    echoes(&kept, "kept").await;

    // The listener is shut down, as a reload hands over to a successor: well before the drain
    // timeout of 30 seconds.
    let started = Instant::now();
    let shutdown = tokio::spawn(async move { h.proxy.shutdown(true).await });
    assert_eq!(
        ends_with(&kept, Duration::from_secs(2)).await,
        close(1001, "Going away")
    );
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .expect("the drain ends once the session is closed")
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert!(echo.ends.lock().unwrap().len() >= 2, "{:?}", echo.ends);
}

// ── event streams and downloads ─────────────────────────────────────────────

struct Stream {
    addr: SocketAddr,
    /// Set when the proxy dropped the connection.
    dropped: Arc<AtomicBool>,
}

/// An upstream that answers every request with a chunked body: a piece every 50 ms, `total`
/// pieces (`None` = until the proxy drops the connection).
async fn chunked_upstream(content_type: &'static str, total: Option<usize>) -> Stream {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = Stream {
        addr: l.local_addr().unwrap(),
        dropped: Arc::default(),
    };
    let dropped = stream.dropped.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let dropped = dropped.clone();
            tokio::spawn(async move {
                let (rd, mut wr) = s.into_split();
                let mut rd = BufReader::new(rd);
                if read_head(&mut rd).await.ok().flatten().is_none() {
                    return;
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\r\n"
                );
                if wr.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                let mut n = 0;
                // A closed proxy side shows as EOF on the read half or a failed write.
                let mut probe = [0u8; 1];
                loop {
                    if total.is_some_and(|t| n >= t) {
                        let _ = wr.write_all(b"0\r\n\r\n").await;
                        return;
                    }
                    let piece = format!("data: {n}\n\n");
                    let chunk = format!("{:x}\r\n{piece}\r\n", piece.len());
                    tokio::select! {
                        r = rd.read(&mut probe) => {
                            if matches!(r, Ok(0) | Err(_)) {
                                dropped.store(true, Ordering::SeqCst);
                                return;
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {
                            if wr.write_all(chunk.as_bytes()).await.is_err() {
                                dropped.store(true, Ordering::SeqCst);
                                return;
                            }
                            n += 1;
                        }
                    }
                }
            });
        }
    });
    stream
}

/// Opens a request and reads the head; the connection stays open for the chunks.
async fn open_stream(proxy: SocketAddr, client: &str, accept: &str) -> BufReader<TcpStream> {
    let mut c = BufReader::new(TcpStream::connect(proxy).await.unwrap());
    let raw = format!(
        "GET /events HTTP/1.1\r\nHost: app.test\r\nAccept: {accept}\r\nX-Forwarded-For: {client}\r\n\r\n"
    );
    c.get_mut().write_all(raw.as_bytes()).await.unwrap();
    let (line, headers) = read_head(&mut c).await.unwrap().unwrap();
    assert!(line.contains(" 200"), "{line}");
    assert_eq!(header(&headers, "transfer-encoding"), Some("chunked"));
    c
}

/// The data of the next chunk, `None` at the closing chunk.
async fn next_chunk(r: &mut BufReader<TcpStream>) -> Option<String> {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(3), r.read_line(&mut line))
        .await
        .expect("a chunk in time")
        .unwrap();
    let n =
        usize::from_str_radix(line.trim(), 16).unwrap_or_else(|_| panic!("chunk size {line:?}"));
    let mut data = vec![0; n + 2];
    r.read_exact(&mut data).await.unwrap();
    (n > 0).then(|| String::from_utf8(data[..n].to_vec()).unwrap())
}

#[tokio::test]
async fn an_event_stream_ends_cleanly_when_maintenance_turns_on() {
    let events = chunked_upstream("text/event-stream; charset=utf-8", None).await;
    let port = free_port();
    let (h, proxy) =
        Harness::serve_with_fake_engine(vec![session_app("sse", port, events.addr, "")]);
    let mut c = open_stream(proxy, "198.51.100.1", "text/event-stream").await;
    assert!(next_chunk(&mut c).await.unwrap().starts_with("data: 0"));

    h.proxy
        .apply(vec![session_app(
            "sse",
            port,
            events.addr,
            r#"{"enabled":true}"#,
        )])
        .unwrap();
    // Pieces that were already on their way arrive, then the closing chunk and the end.
    let ended = Instant::now();
    while next_chunk(&mut c).await.is_some() {
        assert!(
            ended.elapsed() < Duration::from_secs(2),
            "the stream went on"
        );
    }
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), c.read_to_end(&mut rest))
        .await
        .expect("the connection closes")
        .unwrap();
    assert!(rest.is_empty(), "{rest:?}");
    // The upstream connection was dropped, not kept for the next request.
    let t = Instant::now();
    while !events.dropped.load(Ordering::SeqCst) {
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "the upstream connection stayed open"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn an_allowed_clients_event_stream_continues() {
    let events = chunked_upstream("text/event-stream", None).await;
    let port = free_port();
    let (h, proxy) =
        Harness::serve_with_fake_engine(vec![session_app("sse", port, events.addr, "")]);
    let mut c = open_stream(proxy, "203.0.113.9", "text/event-stream").await;
    next_chunk(&mut c).await.unwrap();
    h.proxy
        .apply(vec![session_app(
            "sse",
            port,
            events.addr,
            r#"{"enabled":true,"allow_ips":["203.0.113.9"]}"#,
        )])
        .unwrap();
    for _ in 0..4 {
        assert!(next_chunk(&mut c).await.is_some(), "the stream goes on");
    }
    assert!(!events.dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_chunked_download_finishes_during_maintenance() {
    let download = chunked_upstream("application/octet-stream", Some(8)).await;
    let port = free_port();
    let (h, proxy) =
        Harness::serve_with_fake_engine(vec![session_app("dl", port, download.addr, "")]);
    let mut c = open_stream(proxy, "198.51.100.1", "*/*").await;
    assert!(next_chunk(&mut c).await.unwrap().starts_with("data: 0"));
    h.proxy
        .apply(vec![session_app(
            "dl",
            port,
            download.addr,
            r#"{"enabled":true}"#,
        )])
        .unwrap();
    let mut pieces = 1;
    while next_chunk(&mut c).await.is_some() {
        pieces += 1;
    }
    assert_eq!(pieces, 8, "every piece of the download arrived");
}
