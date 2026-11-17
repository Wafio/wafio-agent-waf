//! The engine of a process that installs none finds nothing and says so.

use wafio_domain::IncomingRequest;
use wafio_engine_api::{ScanRequest, SemanticConfig, Tier, engine};

#[test]
fn a_process_without_an_installed_engine_has_the_one_that_detects_nothing() {
    let e = engine();
    assert!(!e.info().installed);
    assert_eq!(e.info().name, "none");

    let request = IncomingRequest::default();
    let config = SemanticConfig::default();
    let out = e.scan_request(&ScanRequest {
        request: &request,
        config: &config,
        normalized_input: b"/a?b=wafio-test-sql",
        forwarded_path: b"/a",
        project_id: b"p",
        scan_all_headers: true,
        regex_incomplete: false,
        run_scan: true,
        track_params: None,
    });
    assert_eq!((out.tier, out.reason.as_str()), (Tier::Clean, ""));
    assert!(out.held.is_none());
    assert!(out.coverage.engine_absent);
    // Not a gap: it never raises an allow to a log line.
    assert!(out.coverage.complete());

    assert_eq!(e.scan_value(b"anything at all", &config).tier, Tier::Clean);
    assert!(!e.graphql_batch_over_limit(b"[{},{},{}]", 1));
    assert!(!e.new_param_baseline().observe(b"p", b"q"));
    assert_eq!(e.frame_fields(b"{}").0.len(), 0);
}
