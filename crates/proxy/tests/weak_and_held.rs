//! Weak detections, tuning that holds strong detections as LOG, and the rules keys of earlier versions that
//! still say something about them. The fake engine finds `wafio-test-sql` and `wafio-test-xss` (strong) and
//! `wafio-test-weak` (weak).

mod common;
#[path = "common/fake_engine.rs"]
mod fake_engine;

use common::*;

const SQLI: &str = "/item?id=wafio-test-sql";
const XSS: &str = "/item?id=wafio-test-xss";
const WEAK: &str = "/item?id=wafio-test-weak";

/// The status the client got, the action, the score and the coverage text of the last event, for one request on an
/// app with `rules` that forwards to a live upstream.
async fn run(rules: &str, path: &str) -> (u16, String, i64, String) {
    run_with(rules, &get(path)).await
}

async fn run_with(rules: &str, raw: &[u8]) -> (u16, String, i64, String) {
    let up = http_upstream().await;
    let mut a = app("a", free_port(), &format!("http://{}", up.addr));
    a.analysis = analysis_setup(rules);
    let (h, addr) = Harness::serve_with_fake_engine(vec![a]);
    let status = one(addr, raw).await.status;
    let ev = h.last_event();
    (
        status,
        s(&ev.action).to_string(),
        ev.score,
        s(&ev.coverage).to_string(),
    )
}

#[tokio::test]
async fn a_weak_detection_is_a_log_decision_and_the_request_goes_on() {
    let (status, action, score, coverage) = run("{}", WEAK).await;
    assert_eq!((status, action.as_str(), score), (200, "log", 115));
    assert_eq!(coverage, "");
}

#[tokio::test]
async fn a_strong_detection_blocks_with_the_fixed_score_of_its_category() {
    assert_eq!(run("{}", SQLI).await.0, 403);
    let (_, action, score, _) = run("{}", SQLI).await;
    assert_eq!((action.as_str(), score), ("block", 180));
    let (_, action, score, _) = run("{}", XSS).await;
    assert_eq!((action.as_str(), score), ("block", 150));
}

#[tokio::test]
async fn record_weak_detections_false_lets_a_weak_detection_through_unrecorded() {
    let off = r#"{"semantic_policies":{"record_weak_detections":false}}"#;
    let (status, action, score, _) = run(off, WEAK).await;
    assert_eq!((status, action.as_str(), score), (200, "allow", 0));
    // Strong detections are not affected.
    let (status, action, ..) = run(off, SQLI).await;
    assert_eq!((status, action.as_str()), (403, "block"));
    // A strong detection that a log-only engine holds is not a weak one: it stays a LOG.
    let held = r#"{"semantic_policies":{"record_weak_detections":false,"sql":{"action":"log"}}}"#;
    let (status, action, _, coverage) = run(held, SQLI).await;
    assert_eq!((status, action.as_str()), (200, "log"));
    assert_eq!(coverage, "engine_log_only:sql");
}

#[tokio::test]
async fn a_log_threshold_that_is_not_below_the_block_threshold_reads_as_record_weak_detections_false()
 {
    let legacy = r#"{"thresholds":{"log":150,"block":150}}"#;
    assert_eq!(run(legacy, WEAK).await.1, "allow");
    // The new key decides when both are there.
    let both = r#"{"thresholds":{"log":150,"block":150},"semantic_policies":{"record_weak_detections":true}}"#;
    assert_eq!(run(both, WEAK).await.1, "log");
    // Thresholds that leave a band for weak detections change nothing.
    let band = r#"{"thresholds":{"log":80,"block":150}}"#;
    assert_eq!(run(band, WEAK).await.1, "log");
    // A block threshold alone moves nothing that blocks.
    let low = r#"{"thresholds":{"block":20,"log":10}}"#;
    assert_eq!(run(low, SQLI).await.0, 403);
    assert_eq!(run(low, WEAK).await.1, "log");
}

#[tokio::test]
async fn an_engine_base_score_of_zero_switches_that_engine_off() {
    let off = r#"{"semantic_policies":{"sql":{"base_score":0}}}"#;
    let (status, action, _, coverage) = run(off, SQLI).await;
    assert_eq!((status, action.as_str()), (200, "allow"));
    assert_eq!(coverage, "engine_disabled:sql");
    assert_eq!(run(off, XSS).await.0, 403);
    // Any other base score means nothing: the engine blocks as before.
    assert_eq!(
        run(r#"{"semantic_policies":{"sql":{"base_score":10}}}"#, SQLI)
            .await
            .0,
        403
    );
    // A category of score 0 switches off the engine that has none of its own.
    let cat = r#"{"categories":{"SQLi":{"base_score":0},"XSS":{"base_score":0}},"semantic_policies":{"xss":{"base_score":150}}}"#;
    assert_eq!(run(cat, SQLI).await.0, 200);
    assert_eq!(run(cat, XSS).await.0, 403);
}

#[tokio::test]
async fn a_path_override_base_score_of_zero_switches_the_engine_off_for_the_path() {
    let doc =
        r#"{"path_exceptions":[{"path":"/off","semantic_override":{"sql":{"base_score":0}}}]}"#;
    assert_eq!(run(doc, "/off?id=wafio-test-sql").await.0, 200);
    assert_eq!(run(doc, SQLI).await.0, 403);
}

#[tokio::test]
async fn a_tuning_action_of_log_holds_strong_detections_of_the_matched_path_as_log() {
    let doc = r#"{"path_exceptions":[{"path":"/tuned","tuning":{"effect":{"action":"log"}}}]}"#;
    let (status, action, score, coverage) = run(doc, "/tuned?id=wafio-test-sql").await;
    assert_eq!((status, action.as_str(), score), (200, "log", 180));
    assert_eq!(coverage, "engine_log_only:sql");
    // Every engine is held the same way, and another path blocks as before.
    assert_eq!(run(doc, "/tuned?id=wafio-test-xss").await.1, "log");
    assert_eq!(run(doc, SQLI).await.0, 403);
}

#[tokio::test]
async fn a_weaken_that_lowers_scores_or_raises_the_block_threshold_reads_as_log() {
    for weaken in [
        r#"{"score_multiplier":0.5}"#,
        r#"{"threshold_delta":{"block":40}}"#,
        r#"{"sensitivity_delta":-1,"score_multiplier":0.9,"threshold_delta":{"block":0,"log":5}}"#,
    ] {
        let doc = format!(
            r#"{{"path_exceptions":[{{"path":"/tuned","tuning":{{"effect":{{"weaken":{weaken}}}}}}}]}}"#
        );
        let (status, action, _, coverage) = run(&doc, "/tuned?id=wafio-test-sql").await;
        assert_eq!((status, action.as_str()), (200, "log"), "{weaken}");
        assert_eq!(coverage, "engine_log_only:sql", "{weaken}");
    }
    // Any other weaken says nothing a detection can show: it blocks.
    for weaken in [
        r#"{"score_multiplier":1.5}"#,
        r#"{"score_multiplier":1}"#,
        r#"{"threshold_delta":{"block":-40,"log":30}}"#,
        r#"{"sensitivity_delta":2}"#,
        r#"{}"#,
    ] {
        let doc = format!(
            r#"{{"path_exceptions":[{{"path":"/tuned","tuning":{{"effect":{{"weaken":{weaken}}}}}}}]}}"#
        );
        assert_eq!(
            run(&doc, "/tuned?id=wafio-test-sql").await.0,
            403,
            "{weaken}"
        );
    }
}

#[tokio::test]
async fn the_bot_score_mode_blocks_at_the_bot_score_threshold() {
    // The score mode decides after the semantic stage found something, so the request carries a weak detection.
    let bot = |extra: &str| {
        format!(
            r#"{{{extra}"bot_protection":{{"enabled":true,"mode":"score","base_score":120,"ua_blocklist":["BadBot"]}}}}"#
        )
    };
    let raw = b"GET /item?id=wafio-test-weak HTTP/1.1\r\nHost: app.test\r\nUser-Agent: BadBot/1.0\r\n\r\n";
    // The default threshold is 150, and a bot of score 120 stays below it.
    assert_eq!(run_with(&bot(""), raw).await.0, 200);
    // A threshold of version 1 is not the bot threshold.
    assert_eq!(
        run_with(&bot(r#""thresholds":{"block":100,"log":50},"#), raw)
            .await
            .0,
        200
    );
    let own = r#"{"bot_protection":{"enabled":true,"mode":"score","base_score":120,"score_threshold":100,"ua_blocklist":["BadBot"]}}"#;
    assert_eq!(run_with(own, raw).await.0, 403);
    let high = r#"{"bot_protection":{"enabled":true,"mode":"score","base_score":120,"score_threshold":121,"ua_blocklist":["BadBot"]}}"#;
    assert_eq!(run_with(high, raw).await.0, 200);
}
