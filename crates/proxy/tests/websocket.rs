//! Black-box WebSocket verdicts: relay, frame block 1008, oversize 1009, blocked
//! handshake and origin check never reach the upstream.

mod common;
#[path = "common/fake_engine.rs"]
mod fake_engine;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::*;
use tokio::net::{TcpListener, TcpStream};
use wafio_agent_io::ws_frame::{WsConnection, WsError};

#[derive(Clone, Default)]
struct Echo {
    accepts: Arc<AtomicUsize>,
    got: Arc<Mutex<Vec<Vec<u8>>>>,
    heads: Arc<Mutex<Vec<String>>>,
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
                while let Ok((kind, msg)) = c.next_data_message().await {
                    e3.got.lock().unwrap().push(msg.clone());
                    if c.send_data_message(kind, &msg).await.is_err() {
                        return;
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
