//! A proxy without a detection engine forwards what no other check stops, and its decisions say that no engine
//! looked at the request. This file installs no engine.

mod common;

use common::*;

#[tokio::test]
async fn a_request_is_forwarded_and_the_decision_says_no_engine_inspected_it() {
    let up = http_upstream().await;
    let port = free_port();
    let (h, addr) = Harness::serve(vec![app("fwd", port, &format!("http://{}", up.addr))]);

    let resp = one(addr, &get("/home")).await;
    assert_eq!(resp.status, 200);
    let ev = h.last_event();
    assert_eq!((s(&ev.action), ev.status), ("allow", 200));
    assert_eq!(s(&ev.coverage), "engine_absent", "{ev:?}");

    // Text that a real engine would block is forwarded: nothing here detects.
    let resp = one(addr, &get("/item?id=wafio-test-sql")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(s(&h.last_event().coverage), "engine_absent");
    assert_eq!(up.count(), 2);
}

#[tokio::test]
async fn what_does_not_need_an_engine_still_blocks_and_carries_no_mark() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("flood", port, &format!("http://{}", up.addr));
    a.analysis =
        analysis_setup(r#"{"l7_flood":{"enabled":true,"max_requests":1,"window_sec":60}}"#);
    let (h, addr) = Harness::serve(vec![a]);
    assert_eq!(one(addr, &get("/")).await.status, 200);
    let resp = one(addr, &get("/")).await;
    assert_ne!(resp.status, 200);
    let ev = h.last_event();
    assert_eq!(s(&ev.action), "block", "{ev:?}");
    // The flood limit decided before the stage where an engine would run.
    assert_eq!(s(&ev.coverage), "", "{ev:?}");
}
