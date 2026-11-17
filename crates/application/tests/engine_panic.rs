//! A panic inside the engine fails open: the request is allowed without analysis and the panic is counted.

use std::sync::atomic::Ordering;

use wafio_application::{
    AnalyzeConfig, RECOVERED_ANALYZE_PANICS, analyze, cache_base_semantic_config,
};
use wafio_domain::{ANALYZE_METHOD_ERROR, IncomingRequest};
use wafio_engine_fake::PANIC_MARKER;

#[test]
fn engine_panic_fails_open() {
    wafio_engine_fake::install();
    let mut cfg = AnalyzeConfig::default();
    cache_base_semantic_config(&mut cfg);
    let req = IncomingRequest {
        method: "GET".into(),
        uri: format!("/?q={PANIC_MARKER}").into(),
        remote_address: b"203.0.113.4:1234".to_vec(),
        ..Default::default()
    };
    let before = RECOVERED_ANALYZE_PANICS.load(Ordering::Relaxed);
    let r = analyze(&req, &cfg);
    assert_eq!(r.action, "allow");
    assert_eq!(r.analyze_method, ANALYZE_METHOD_ERROR);
    assert_eq!(r.message, b"analysis error");
    assert_eq!(RECOVERED_ANALYZE_PANICS.load(Ordering::Relaxed), before + 1);
}
