//! The coverage text of a decision: what the semantic stage could not fully analyze.

use std::sync::atomic::AtomicU64;

use crate::analyze::AnalyzeConfig;
use crate::deps::engine::{COVERAGE_FLAG_REGEX_BUDGET, ScanCoverage};

/// Requests whose semantic scan did not cover the whole request.
pub static PARTIAL_COVERAGE_REQUESTS: AtomicU64 = AtomicU64::new(0);

/// "coverage:<flags>", "" when complete.
pub(crate) fn coverage_marker(c: &ScanCoverage) -> String {
    let mut flags: Vec<String> = Vec::new();
    let mut flag = |on: bool, f: &str| {
        if on {
            flags.push(f.to_string());
        }
    };
    flag(c.truncated, "truncated");
    flag(c.field_cap, "field_cap");
    flag(c.query_cap, "query_cap");
    if !c.body_skipped.is_empty() {
        flags.push(format!("body_{}", c.body_skipped));
    }
    if c.binary_text {
        flags.push("body_binary_text".into());
    }
    if !c.transport.is_empty() {
        flags.push(format!("body_{}", c.transport));
    }
    let mut flag = |on: bool, f: &str| {
        if on {
            flags.push(f.to_string());
        }
    };
    flag(c.header_count, "header_count");
    flag(c.header_len, "header_len");
    flag(c.header_skip, "headers_unscanned");
    flag(c.engine_panic, "engine_panic");
    flag(c.budget, "parse_budget");
    if c.regex_budget {
        flags.push(COVERAGE_FLAG_REGEX_BUDGET.into());
    }
    if flags.is_empty() {
        return String::new();
    }
    format!("coverage:{}", flags.join(","))
}

impl AnalyzeConfig {
    /// A weak detection becomes a LOG decision (default) or is let through unrecorded
    /// (semantic_policies.record_weak_detections = false).
    pub fn records_weak_detections(&self) -> bool {
        self.semantic_policies
            .as_ref()
            .is_none_or(|sp| sp.record_weak_detections.is_none_or(|v| v))
    }

    /// Every non-structural header is scanned (default) or only the legacy set
    /// (semantic_policies.scan_all_headers = false).
    pub fn inspects_all_headers(&self) -> bool {
        self.semantic_policies
            .as_ref()
            .is_none_or(|sp| sp.scan_all_headers.is_none_or(|v| v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::engine::SemanticScanResult;

    #[test]
    fn marker_is_deterministic() {
        let c = ScanCoverage {
            truncated: true,
            field_cap: true,
            body_skipped: "binary".into(),
            transport: "decompress_error".into(),
            header_count: true,
            header_len: true,
            engine_panic: true,
            budget: true,
            ..Default::default()
        };
        assert_eq!(
            coverage_marker(&c),
            "coverage:truncated,field_cap,body_binary,body_decompress_error,header_count,header_len,engine_panic,parse_budget"
        );
        assert!(ScanCoverage::default().complete());
        for r in [
            SemanticScanResult {
                truncated: true,
                ..Default::default()
            },
            SemanticScanResult {
                engine_panicked: true,
                ..Default::default()
            },
            SemanticScanResult {
                budget_exhausted: true,
                ..Default::default()
            },
        ] {
            let mut cov = ScanCoverage::default();
            cov.merge_scan(&r);
            assert!(!cov.complete());
        }
    }

    #[test]
    fn marker_order() {
        let cov = ScanCoverage {
            truncated: true,
            field_cap: true,
            transport: "decompress_limit".into(),
            header_skip: true,
            regex_budget: true,
            ..Default::default()
        };
        assert_eq!(
            coverage_marker(&cov),
            "coverage:truncated,field_cap,body_decompress_limit,headers_unscanned,regex_budget"
        );
        assert_eq!(coverage_marker(&ScanCoverage::default()), "");
        assert!(cov.body_uninspected() && cov.other_uninspected() && !cov.complete());
    }
}
