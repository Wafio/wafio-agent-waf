//! The uninspected floor: no clean allow over content no engine inspected.

use std::sync::atomic::Ordering;

use wafio_bytetext::strings::contains;
use wafio_domain::{
    ANALYZE_METHOD_ERROR, ANALYZE_METHOD_SEMANTIC, AnalysisResult,
    BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET,
};

use crate::coverage::PARTIAL_COVERAGE_REQUESTS;
use crate::deps::engine::{
    SemanticPoliciesConfig, UNINSPECTED_POLICY_BLOCK, UNINSPECTED_POLICY_LOG,
};
use crate::script_rules::merge_coverage_flags;

/// Built only for a request the semantic stage inspected.
#[derive(Clone, Debug, Default)]
pub(crate) struct UnscannedContentFloor {
    /// UNINSPECTED_POLICY_LOG or UNINSPECTED_POLICY_BLOCK.
    pub action: &'static str,
    pub body_gap: bool,
    pub other_gap: bool,
    /// IncomingRequest.body_scan_skipped.
    pub withheld: String,
    /// Content scanning is on and owns a withheld body.
    pub content_scan_owns: bool,
    /// The semantic coverage marker runs after this floor and renders the flags.
    pub semantic_marked: bool,
    pub script_incomplete: bool,
    pub script_content: bool,
}

pub(crate) fn apply_uninspected_action(sp: Option<&SemanticPoliciesConfig>) -> &'static str {
    if sp.is_some_and(|sp| sp.on_uninspected == UNINSPECTED_POLICY_BLOCK) {
        UNINSPECTED_POLICY_BLOCK
    } else {
        UNINSPECTED_POLICY_LOG
    }
}

impl UnscannedContentFloor {
    /// (raise, hard): uninspected content, and whether any of it is content-induced (may BLOCK).
    fn gap(&self) -> (bool, bool) {
        let (mut raise, mut hard) = (false, false);
        let load_body = self.withheld == BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET;
        let body_owned = !self.withheld.is_empty() && self.content_scan_owns;
        if !self.withheld.is_empty() && !body_owned {
            (raise, hard) = (true, !load_body);
        }
        if self.other_gap {
            (raise, hard) = (true, true);
        }
        if self.body_gap && !body_owned {
            (raise, hard) = (true, hard || !load_body);
        }
        if self.script_incomplete {
            (raise, hard) = (true, hard || self.script_content);
        }
        (raise, hard)
    }

    fn cause(&self) -> String {
        if !self.withheld.is_empty() && !self.content_scan_owns {
            return format!("body_{}", self.withheld);
        }
        "partial_coverage".into()
    }

    pub fn apply(&self, r: &mut AnalysisResult) {
        if r.analyze_method == ANALYZE_METHOD_ERROR {
            return;
        }
        let (raise, hard) = self.gap();
        if !raise {
            return;
        }
        let mut action = self.action;
        if action == UNINSPECTED_POLICY_BLOCK && !hard {
            action = UNINSPECTED_POLICY_LOG;
        }
        if r.action != "block" && (r.action != "log" || action == UNINSPECTED_POLICY_BLOCK) {
            r.action = action.into();
            r.message = format!("inspection_incomplete:{}", self.cause()).into_bytes();
            r.coverage_raised = true;
            r.analyze_method = ANALYZE_METHOD_SEMANTIC.into();
        }
        if self.semantic_marked || self.withheld.is_empty() || self.content_scan_owns {
            return;
        }
        // A withheld body the semantic coverage marker does not name: name it here.
        let prev = r.coverage.clone();
        if prev.is_empty() {
            PARTIAL_COVERAGE_REQUESTS.fetch_add(1, Ordering::Relaxed);
        }
        r.coverage = merge_coverage_flags(&prev, &format!("body_{}", self.withheld));
        if r.action != "block" && r.action != "log" {
            return;
        }
        let prev_note = format!("coverage:{prev}").into_bytes();
        if !prev.is_empty() && contains(&r.match_detail, &prev_note) {
            let new_note = format!("coverage:{}", r.coverage).into_bytes();
            r.match_detail = replace_once(&r.match_detail, &prev_note, &new_note);
        } else if !contains(&r.match_detail, b"coverage:") {
            if !r.match_detail.is_empty() {
                r.match_detail.extend_from_slice(b"; ");
            }
            r.match_detail.extend_from_slice(b"coverage:");
            r.match_detail.extend_from_slice(r.coverage.as_bytes());
        }
    }
}

/// Replaces the first `old` in `s` with `new` (`old` non-empty).
fn replace_once(s: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    match memchr::memmem::find(s, old) {
        Some(i) => [&s[..i], new, &s[i + old.len()..]].concat(),
        None => s.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn floor() -> UnscannedContentFloor {
        UnscannedContentFloor {
            action: UNINSPECTED_POLICY_LOG,
            ..Default::default()
        }
    }

    fn allow() -> AnalysisResult {
        AnalysisResult {
            action: "allow".into(),
            analyze_method: "semantic".into(),
            ..Default::default()
        }
    }

    // A semantic gap raises a clean allow to LOG.
    #[test]
    fn semantic_gap_raises_to_log() {
        let f = UnscannedContentFloor {
            other_gap: true,
            semantic_marked: true,
            ..floor()
        };
        let mut r = allow();
        f.apply(&mut r);
        assert_eq!(r.action, "log");
        assert_eq!(r.message, b"inspection_incomplete:partial_coverage");
        assert!(r.coverage_raised);
        assert_eq!(r.analyze_method, "semantic");
    }

    #[test]
    fn block_mode_and_hard_gaps() {
        let f = UnscannedContentFloor {
            action: UNINSPECTED_POLICY_BLOCK,
            other_gap: true,
            ..floor()
        };
        let mut r = allow();
        f.apply(&mut r);
        assert_eq!(r.action, "block");

        // A LOG becomes BLOCK in block mode for a hard gap.
        let f = UnscannedContentFloor {
            action: UNINSPECTED_POLICY_BLOCK,
            body_gap: true,
            ..floor()
        };
        let mut r = AnalysisResult {
            action: "log".into(),
            ..allow()
        };
        f.apply(&mut r);
        assert_eq!(r.action, "block");
    }

    #[test]
    fn withheld_body_names_itself() {
        let f = UnscannedContentFloor {
            action: UNINSPECTED_POLICY_BLOCK,
            withheld: "decompress_error".into(),
            ..Default::default()
        };
        let mut r = AnalysisResult {
            action: "allow".into(),
            analyze_method: "semantic".into(),
            ..Default::default()
        };
        f.apply(&mut r);
        assert_eq!(r.action, "block");
        assert_eq!(r.message, b"inspection_incomplete:body_decompress_error");
        assert_eq!(r.analyze_method, "semantic");
        assert_eq!(r.coverage, "body_decompress_error");
        assert_eq!(r.match_detail, b"coverage:body_decompress_error");

        // Load-induced decode budget skip: LOG only, and an existing note grows.
        let f = UnscannedContentFloor {
            withheld: BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET.into(),
            ..f
        };
        let mut r = AnalysisResult {
            action: "allow".into(),
            coverage: "regex_budget".into(),
            match_detail: b"x; coverage:regex_budget".to_vec(),
            ..Default::default()
        };
        f.apply(&mut r);
        assert_eq!(r.action, "log");
        assert_eq!(r.coverage, "regex_budget,body_decompress_budget");
        assert_eq!(
            r.match_detail,
            b"x; coverage:regex_budget,body_decompress_budget"
        );
    }

    #[test]
    fn content_scan_owns_withheld_body() {
        let f = UnscannedContentFloor {
            withheld: "decompress_limit".into(),
            content_scan_owns: true,
            ..floor()
        };
        let mut r = allow();
        f.apply(&mut r);
        assert_eq!(r.action, "allow");
    }

    #[test]
    fn on_uninspected() {
        assert_eq!(apply_uninspected_action(None), "log");
        let sp = SemanticPoliciesConfig {
            on_uninspected: "block".into(),
            ..Default::default()
        };
        assert_eq!(apply_uninspected_action(Some(&sp)), "block");
    }
}
