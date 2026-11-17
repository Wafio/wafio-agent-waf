//! Script rule handling, plus the script rule runner interface (script rules run in the agent's interpreter).

use wafio_domain::{ANALYZE_METHOD_CUSTOM_RULE, AnalysisResult};

use crate::coverage::PARTIAL_COVERAGE_REQUESTS;
use crate::deps::engine::{
    COVERAGE_FLAG_SCRIPT_TIMEOUT, RequestRuleContext, ScriptBudget, ScriptResult,
};

/// Runs a request's script rules. The runner holds the rules it runs, compiled when the bundle was applied; the
/// call stays on the request's thread.
pub trait ScriptRunner: Send + Sync {
    fn run_script_rules(&self, ctx: &RequestRuleContext, budget: ScriptBudget) -> ScriptResult;
}

/// An allow becomes LOG, block and log keep their action, the verdict carries the script coverage flags.
/// With `semantic_partial` the semantic coverage marker renders the flags.
pub fn mark_script_incomplete(out: &mut AnalysisResult, sr: &ScriptResult, semantic_partial: bool) {
    if out.action != "block" && out.action != "log" {
        out.action = "log".into();
        out.analyze_method = ANALYZE_METHOD_CUSTOM_RULE.into();
        out.message = [
            b"custom_script_rule_incomplete:".as_slice(),
            sr.incomplete_rule.as_bytes(),
        ]
        .concat();
    }
    let flags = if sr.coverage.is_empty() {
        COVERAGE_FLAG_SCRIPT_TIMEOUT
    } else {
        sr.coverage.as_str()
    };
    out.coverage = merge_coverage_flags(&out.coverage, flags);
    if semantic_partial {
        return;
    }
    PARTIAL_COVERAGE_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if !out.match_detail.is_empty() {
        out.match_detail.extend_from_slice(b"; ");
    }
    out.match_detail.extend_from_slice(b"coverage:");
    out.match_detail.extend_from_slice(flags.as_bytes());
}

/// Merges two comma-separated flag lists, first appearance order, duplicates dropped.
pub fn merge_coverage_flags(a: &str, b: &str) -> String {
    if a.is_empty() {
        return b.to_string();
    }
    if b.is_empty() {
        return a.to_string();
    }
    let mut flags: Vec<&str> = Vec::new();
    for f in a.split(',').chain(b.split(',')) {
        if !f.is_empty() && !flags.contains(&f) {
            flags.push(f);
        }
    }
    flags.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_flags() {
        assert_eq!(merge_coverage_flags("", "a"), "a");
        assert_eq!(merge_coverage_flags("a", ""), "a");
        assert_eq!(merge_coverage_flags("a,b", "b,c,,a"), "a,b,c");
    }

    // An unfinished script turns allow into LOG.
    #[test]
    fn incomplete_allow_becomes_log() {
        let mut out = AnalysisResult {
            action: "allow".into(),
            ..Default::default()
        };
        let sr = ScriptResult {
            incomplete: true,
            incomplete_rule: "r1".into(),
            ..Default::default()
        };
        mark_script_incomplete(&mut out, &sr, false);
        assert_eq!(out.action, "log");
        assert_eq!(out.message, b"custom_script_rule_incomplete:r1");
        assert_eq!(out.coverage, "script_timeout");
        assert_eq!(out.match_detail, b"coverage:script_timeout");

        let mut blocked = AnalysisResult {
            action: "block".into(),
            match_detail: b"x".to_vec(),
            ..Default::default()
        };
        let sr = ScriptResult {
            incomplete: true,
            coverage: "script_error".into(),
            ..Default::default()
        };
        mark_script_incomplete(&mut blocked, &sr, true);
        assert_eq!(blocked.action, "block");
        assert_eq!(blocked.coverage, "script_error");
        assert_eq!(blocked.match_detail, b"x");
    }
}
