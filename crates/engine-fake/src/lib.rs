//! An engine for the tests of the open crates. It knows three things: text that holds [`SQL_MARKER`] is an SQL
//! injection, text that holds [`XSS_MARKER`] is a cross-site scripting attempt (both strong) and text that holds
//! [`WEAK_MARKER`] is a weak open-redirect detection. Text that holds [`PANIC_MARKER`] makes a scan of a request
//! panic, to test the fail-open path of the callers. That is enough to drive the plumbing around an engine
//! (verdicts, modes, log-only engines, weak detections, decision events, WebSocket closes). What real detection
//! finds is tested where the real engine lives.

#![forbid(unsafe_code)]

use std::sync::Arc;

use wafio_domain::IncomingRequest;
use wafio_engine_api::{
    BotSeeds, Engine, EngineCounters, EngineInfo, FrameCoverage, FrameField, Held, ParamBaseline,
    REASON_SEMANTIC_OPEN_REDIRECT, REASON_SEMANTIC_SQL, REASON_SEMANTIC_XSS, ScanOutcome,
    ScanRequest, SemanticConfig, SemanticScanResult, Tier,
};

/// Text that this engine takes for an SQL injection.
pub const SQL_MARKER: &str = "wafio-test-sql";
/// Text that this engine takes for a cross-site scripting attempt.
pub const XSS_MARKER: &str = "wafio-test-xss";

/// Text that this engine takes for a weak detection: the request is logged and goes on.
pub const WEAK_MARKER: &str = "wafio-test-weak";

/// Text that makes `scan_request` panic.
pub const PANIC_MARKER: &str = "wafio-test-panic";

/// What each marker is: the marker, the reason of the finding, the key of the detector and the tier.
const FINDINGS: [(&str, &str, &str, Tier); 3] = [
    (SQL_MARKER, REASON_SEMANTIC_SQL, "sql", Tier::Strong),
    (XSS_MARKER, REASON_SEMANTIC_XSS, "xss", Tier::Strong),
    (
        WEAK_MARKER,
        REASON_SEMANTIC_OPEN_REDIRECT,
        "open_redirect",
        Tier::Weak,
    ),
];

#[derive(Clone, Copy, Debug, Default)]
pub struct FakeEngine;

struct EmptyBaseline;

impl ParamBaseline for EmptyBaseline {
    fn observe(&self, _project_id: &[u8], _param: &[u8]) -> bool {
        false
    }
}

fn holds(text: &[u8], marker: &str) -> bool {
    text.windows(marker.len()).any(|w| w == marker.as_bytes())
}

fn holds_any_marker(text: &[u8]) -> bool {
    FINDINGS.iter().any(|(marker, ..)| holds(text, marker))
}

/// Where the marker sits in the request, if it does: the query, the body or a header.
fn place(scan: &ScanRequest<'_>, marker: &str) -> Option<Vec<u8>> {
    let req = scan.request;
    if holds(scan.normalized_input, marker) {
        Some(b"query".to_vec())
    } else if holds(&req.body, marker) {
        Some(b"body".to_vec())
    } else {
        req.headers
            .iter()
            .find(|(_, values)| values.iter().any(|v| holds(v, marker)))
            .map(|(name, _)| [b"header:".as_slice(), name].concat())
    }
}

impl Engine for FakeEngine {
    fn info(&self) -> EngineInfo {
        EngineInfo {
            installed: true,
            name: "fake",
        }
    }

    fn scan_request(&self, scan: &ScanRequest<'_>) -> ScanOutcome {
        let mut out = ScanOutcome::default();
        if !scan.run_scan {
            return out;
        }
        if place(scan, PANIC_MARKER).is_some() {
            panic!("fake engine panic");
        }
        for (marker, reason, key, tier) in FINDINGS {
            if scan.config.is_disabled(key) {
                continue;
            }
            let Some(source) = place(scan, marker) else {
                continue;
            };
            if tier == Tier::Strong && scan.config.is_log_only(key) {
                out.held.get_or_insert(Held {
                    reason: reason.into(),
                    detail: b"test_marker".to_vec(),
                    source,
                    source_exact: true,
                    value: Vec::new(),
                });
            } else if tier > out.tier {
                out.tier = tier;
                out.reason = reason.into();
                out.detail = b"test_marker".to_vec();
                out.source = source;
                out.source_exact = true;
            }
        }
        out
    }

    fn frame_fields(&self, payload: &[u8]) -> (Vec<FrameField>, FrameCoverage) {
        let field = FrameField {
            value: payload.to_vec(),
            source: b"body".to_vec(),
            summary: false,
        };
        (vec![field], FrameCoverage::default())
    }

    fn scan_value(&self, value: &[u8], config: &SemanticConfig) -> SemanticScanResult {
        for (marker, reason, key, tier) in FINDINGS {
            if !config.is_disabled(key) && holds(value, marker) {
                return SemanticScanResult {
                    tier,
                    reason,
                    detail: b"test_marker".to_vec(),
                    engines: 1,
                    ..Default::default()
                };
            }
        }
        SemanticScanResult::default()
    }

    fn graphql_batch_over_limit(&self, _body: &[u8], _max_batch: i64) -> bool {
        false
    }

    fn guess_match_source(&self, _request: &IncomingRequest) -> Vec<u8> {
        Vec::new()
    }

    fn header_value_looks_suspicious(&self, value: &[u8]) -> bool {
        holds_any_marker(value)
    }

    fn prepare_thread(&self, _stack_budget_bytes: usize) {}

    fn counters(&self) -> EngineCounters {
        EngineCounters::default()
    }

    fn bot_seeds(&self) -> BotSeeds {
        BotSeeds::default()
    }

    fn new_param_baseline(&self) -> Arc<dyn ParamBaseline> {
        Arc::new(EmptyBaseline)
    }
}

/// Installs the fake engine for the test process. Only the first call counts, so every test may call it.
pub fn install() {
    wafio_engine_api::install(&FakeEngine);
}
