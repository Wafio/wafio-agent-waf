//! The decision event carries the HTTP status the client received: the block page, the challenge
//! page, the upstream's own status and the 502 of an unreachable upstream.

mod common;
#[path = "common/fake_engine.rs"]
mod fake_engine;

use common::*;

const SQLI: &str = "/item?id=wafio-test-sql";
const CHALLENGE: &str = r#"{"challenge":{"enabled":true,"type":"js_challenge","trigger":"always","allow_local_ips":false,"secret_key":"0123456789abcdef0123456789abcdef"}}"#;

#[tokio::test]
async fn a_blocked_request_records_the_block_status() {
    let up = http_upstream().await;
    let port = free_port();
    let (h, addr) =
        Harness::serve_with_fake_engine(vec![app("blk", port, &format!("http://{}", up.addr))]);
    let resp = one(addr, &get(SQLI)).await;
    assert_eq!(resp.status, 403);
    assert_eq!(h.last_event().status, 403);
}

#[tokio::test]
async fn a_forwarded_request_records_the_upstream_status() {
    let up = http_upstream().await;
    let port = free_port();
    let (h, addr) =
        Harness::serve_with_fake_engine(vec![app("fwd", port, &format!("http://{}", up.addr))]);
    let resp = one(addr, &get("/home")).await;
    assert_eq!(resp.status, 200);
    let ev = h.last_event();
    assert_eq!((s(&ev.action), ev.status), ("allow", 200));
}

#[tokio::test]
async fn the_challenge_gate_records_the_page_status() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.analysis = analysis_setup(CHALLENGE);
    let (h, addr) = Harness::serve_with_fake_engine(vec![a]);
    let browser = b"GET /home HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    let resp = one(addr, browser).await;
    let ev = h.last_event();
    assert_eq!(s(&ev.action), "challenge");
    assert_eq!(ev.status, i64::from(resp.status));
}

#[tokio::test]
async fn an_unreachable_upstream_records_502() {
    let port = free_port();
    let dead = free_port();
    let (h, addr) = Harness::serve_with_fake_engine(vec![app(
        "dead",
        port,
        &format!("http://127.0.0.1:{dead}"),
    )]);
    let resp = one(addr, &get("/home")).await;
    assert_eq!(resp.status, 502);
    let ev = h.last_event();
    assert_eq!((s(&ev.action), ev.status), ("upstream_error", 502));
}

#[tokio::test]
async fn a_switched_off_detector_is_listed_in_the_event_and_is_not_a_gap() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.analysis = analysis_setup(r#"{"semantic_policies":{"xss":{"disabled":true}}}"#);
    let (h, addr) = Harness::serve_with_fake_engine(vec![a]);
    let resp = one(addr, &get("/p?q=%3Cb%3Ehello%3C%2Fb%3E%20world")).await;
    assert_eq!(resp.status, 200);
    let ev = h.last_event();
    assert_eq!(s(&ev.action), "allow", "{ev:?}");
    assert_eq!(s(&ev.coverage), "engine_disabled:xss");
    assert!(s(&ev.match_detail).is_empty());
}
