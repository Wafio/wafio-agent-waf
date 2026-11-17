//! Black-box: what a log-only engine does to the response, the upstream and the recorded decision, in block
//! mode and in monitor mode.

mod common;
#[path = "common/fake_engine.rs"]
mod fake_engine;

use common::*;

const SQLI: &str = "/item?id=wafio-test-sql";
const SQLI_AND_XSS: &str = "/item?id=wafio-test-sql&n=wafio-test-xss";
const SQL_LOGS: &str = r#"{"semantic_policies":{"sql":{"action":"log"}}}"#;

#[tokio::test]
async fn a_log_only_engine_forwards_the_request_and_records_a_log() {
    let up = http_upstream().await;
    let (pb, pm) = (free_port(), free_port());
    let mut block = app("blk", pb, &format!("http://{}", up.addr));
    block.analysis = analysis_setup(SQL_LOGS);
    let mut monitor = app("mon", pm, &format!("http://{}", up.addr));
    monitor.mode = "monitor".into();
    monitor.analysis = analysis_setup(SQL_LOGS);
    let (h, block_addr) = Harness::serve_with_fake_engine(vec![block, monitor]);

    assert_eq!(one(block_addr, &get(SQLI)).await.status, 200);
    let ev = h.last_event();
    assert_eq!((s(&ev.action), s(&ev.mode)), ("log", "block"));
    assert!(ev.score > 0 && !ev.categories.is_empty(), "{ev:?}");
    assert_eq!(s(&ev.coverage), "engine_log_only:sql");
    assert_eq!(up.count(), 1);

    // Monitor mode records what the verdict is: a log, not a monitored block.
    let mon = format!("127.0.0.1:{pm}").parse().unwrap();
    assert_eq!(one(mon, &get(SQLI)).await.status, 200);
    let ev = h.last_event();
    assert_eq!((s(&ev.action), s(&ev.mode)), ("log", "monitor"));
    assert_eq!(s(&ev.coverage), "engine_log_only:sql");
    assert_eq!(up.count(), 2);
}

#[tokio::test]
async fn another_engine_still_blocks_and_is_still_monitored() {
    let up = http_upstream().await;
    let (pb, pm) = (free_port(), free_port());
    let mut block = app("blk", pb, &format!("http://{}", up.addr));
    block.analysis = analysis_setup(SQL_LOGS);
    let mut monitor = app("mon", pm, &format!("http://{}", up.addr));
    monitor.mode = "monitor".into();
    monitor.analysis = analysis_setup(SQL_LOGS);
    let (h, block_addr) = Harness::serve_with_fake_engine(vec![block, monitor]);

    assert_eq!(one(block_addr, &get(SQLI_AND_XSS)).await.status, 403);
    let ev = h.last_event();
    assert_eq!(s(&ev.action), "block");
    assert_eq!(s(&ev.coverage), "");
    assert_eq!(up.count(), 0);

    let mon = format!("127.0.0.1:{pm}").parse().unwrap();
    assert_eq!(one(mon, &get(SQLI_AND_XSS)).await.status, 200);
    assert_eq!(s(&h.last_event().action), "monitor");
}
