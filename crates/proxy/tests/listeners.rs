//! Per-app listeners through the public API: they follow the bundle's apps, and the apply
//! errors have fixed texts.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::*;

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

#[tokio::test]
async fn listeners_follow_the_bundle() {
    let u1 = http_upstream_with("X-Tag: u1\r\n", b"ok").await;
    let u2 = http_upstream_with("X-Tag: u2\r\n", b"ok").await;
    let slow = http_upstream_delayed("X-Tag: slow\r\n", b"ok", Duration::from_millis(800)).await;
    let h = Harness::new();
    let (a, b) = (free_port(), free_port());
    let up = |u: &TestUpstream| format!("http://{}", u.addr);

    h.proxy.apply(vec![app("A", a, &up(&slow))]).unwrap();
    let mut keep_a = Client::connect(addr(a)).await.unwrap();
    assert_eq!(
        keep_a.send(&get("/")).await.unwrap().header("x-tag"),
        Some("slow")
    );
    assert!(
        Client::connect(addr(b)).await.is_err(),
        "B not configured yet"
    );

    // A's upstream changes in place on a live keep-alive connection, B appears.
    h.proxy
        .apply(vec![app("A", a, &up(&u1)), app("B", b, &up(&u2))])
        .unwrap();
    assert_eq!(
        keep_a.send(&get("/")).await.unwrap().header("x-tag"),
        Some("u1"),
        "same connection, new route"
    );
    assert_eq!(one(addr(b), &get("/")).await.header("x-tag"), Some("u2"));

    // A request in flight on A when A is removed still completes; the port refuses at once.
    h.proxy
        .apply(vec![app("A", a, &up(&slow)), app("B", b, &up(&u2))])
        .unwrap();
    let in_flight = tokio::spawn(async move {
        Client::connect(addr(a))
            .await
            .unwrap()
            .send(&get("/slow"))
            .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t = Instant::now();
    h.proxy.apply(vec![app("B", b, &up(&u2))]).unwrap();
    assert!(
        t.elapsed() < Duration::from_millis(100),
        "apply does not wait for the drain"
    );
    assert!(
        Client::connect(addr(a)).await.is_err(),
        "removed port refuses at once"
    );
    let resp = in_flight.await.unwrap().unwrap();
    assert_eq!((resp.status, resp.header("x-tag")), (200, Some("slow")));
    assert_eq!(h.proxy.addresses(), vec![format!("127.0.0.1:{b}")]);

    // The port can be bound again by a later bundle; apps without a port are ignored.
    let mut no_port = app("C", 0, &up(&u1));
    no_port.listen_host.clear();
    h.proxy
        .apply(vec![app("A", a, &up(&u1)), app("B", b, &up(&u2)), no_port])
        .unwrap();
    assert_eq!(one(addr(a), &get("/")).await.header("x-tag"), Some("u1"));
}

#[tokio::test]
async fn idle_keepalive_connection_is_closed_on_removal() {
    let u1 = http_upstream().await;
    let a = free_port();
    let (h, _) = Harness::serve(vec![app("A", a, &format!("http://{}", u1.addr))]);
    let mut c = Client::connect(addr(a)).await.unwrap();
    assert_eq!(c.send(&get("/")).await.unwrap().status, 200);
    h.proxy.apply(vec![]).unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut c.0, &mut buf),
    )
    .await
    .unwrap();
    assert!(
        matches!(n, Ok(0) | Err(_)),
        "idle connection closed, not held for the drain timeout"
    );
}

#[tokio::test]
async fn apply_errors_change_nothing() {
    let u1 = http_upstream_with("X-Tag: u1\r\n", b"ok").await;
    let u2 = http_upstream_with("X-Tag: u2\r\n", b"ok").await;
    let a = free_port();
    let (h, _) = Harness::serve(vec![app("A", a, &format!("http://{}", u1.addr))]);
    let up2 = format!("http://{}", u2.addr);
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_port = busy.local_addr().unwrap().port();
    assert_eq!(
        h.proxy
            .apply(vec![app("A", a, &up2), app("X", busy_port, &up2)]),
        Err("failed to bind WAF route listener".into())
    );
    assert_eq!(
        h.proxy.apply(vec![app("A", a, &up2), app("B", a, &up2)]),
        Err("duplicate listener in WAF bundle".into())
    );
    assert_eq!(
        h.proxy.apply(vec![app("A", a, "ftp://x")]),
        Err("invalid app route in WAF bundle".into())
    );
    let mut bad_ws = app("A", a, &up2);
    bad_ws.rules_json = br#"{"websocket":{"limits":{"max_text_bytes":-1}}}"#.to_vec();
    assert_eq!(
        h.proxy.apply(vec![bad_ws]),
        Err("invalid app route in WAF bundle".into())
    );
    let mut limits = app("A", a, &up2);
    limits.proxy_config = br#"{"max_body_bytes":2048}"#.to_vec();
    assert_eq!(
        h.proxy.apply(vec![limits]),
        Err("route listener limits or timeouts changed; agent restart required".into())
    );
    // A keeps its old route and stays up.
    assert_eq!(one(addr(a), &get("/")).await.header("x-tag"), Some("u1"));
    // Other proxy_config fields change in place.
    let mut hdr = app("A", a, &up2);
    hdr.proxy_config = br#"{"resp_headers":{"add":{"x-new":"1"}}}"#.to_vec();
    h.proxy.apply(vec![hdr]).unwrap();
    let r = one(addr(a), &get("/")).await;
    assert_eq!(
        (r.header("x-tag"), r.header("x-new")),
        (Some("u2"), Some("1"))
    );
}

/// Many apps coming and going: 200 listeners added, then half removed, under one process.
#[tokio::test]
async fn many_listeners_churn() {
    let u1 = http_upstream().await;
    let h = Harness::new();
    let held: Vec<_> = (0..200)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<u16> = held
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    drop(held);
    let apps = |ps: &[u16]| {
        ps.iter()
            .map(|&p| app(&format!("app{p}"), p, &format!("http://{}", u1.addr)))
            .collect::<Vec<_>>()
    };
    let t = Instant::now();
    h.proxy.apply(apps(&ports)).unwrap();
    let add = t.elapsed();
    for &p in ports.iter().step_by(37) {
        assert_eq!(one(addr(p), &get("/")).await.status, 200);
    }
    let t = Instant::now();
    h.proxy.apply(apps(&ports[..100])).unwrap();
    let remove = t.elapsed();
    assert!(Client::connect(addr(ports[150])).await.is_err());
    assert_eq!(one(addr(ports[50]), &get("/")).await.status, 200);
    eprintln!("apply: 200 listeners added in {add:?}, 100 removed in {remove:?}");
}

#[tokio::test]
async fn stop_accepting_returns_before_the_connections_drain_and_closes_the_door() {
    let slow = http_upstream_delayed("X-Tag: slow\r\n", b"ok", Duration::from_millis(800)).await;
    let h = Harness::new();
    let port = free_port();
    h.proxy
        .apply(vec![app("A", port, &format!("http://{}", slow.addr))])
        .unwrap();
    let in_flight = tokio::spawn(async move {
        Client::connect(addr(port))
            .await
            .unwrap()
            .send(&get("/slow"))
            .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let t = Instant::now();
    h.proxy.stop_accepting(false).await;
    assert!(
        t.elapsed() < Duration::from_millis(400),
        "the stop does not wait for the request in flight: {:?}",
        t.elapsed()
    );
    assert!(
        Client::connect(addr(port)).await.is_err(),
        "nothing is accepted after the stop"
    );
    assert_eq!(
        h.proxy
            .apply(vec![app("A", port, &format!("http://{}", slow.addr))])
            .unwrap_err(),
        "agent is shutting down"
    );
    let resp = in_flight.await.unwrap().unwrap();
    assert_eq!((resp.status, resp.header("x-tag")), (200, Some("slow")));
    h.proxy.shutdown(false).await;
}
