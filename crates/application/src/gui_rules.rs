//! GUI rule handling: the verdict of terminal rules and the application of log and challenge rules.

use std::sync::atomic::Ordering;

use wafio_bytetext::strings::contains;
use wafio_domain::{ANALYZE_METHOD_CUSTOM_RULE, ANALYZE_METHOD_ERROR, AnalysisResult};

use crate::coverage::PARTIAL_COVERAGE_REQUESTS;
use crate::deps::engine::{COVERAGE_FLAG_REGEX_BUDGET, GuiRuleOutcome};
use crate::script_rules::merge_coverage_flags;

fn rule_note(id: &str) -> Vec<u8> {
    [b"custom_gui_rule:".as_slice(), id.as_bytes()].concat()
}

/// The verdict of a terminal (allow/block) GUI rule.
pub fn verdict_for_gui_rule(gui: &GuiRuleOutcome) -> AnalysisResult {
    AnalysisResult {
        action: gui.action.clone(),
        message: rule_note(&gui.rule_id),
        categories: vec!["CustomRule".into()],
        analyze_method: ANALYZE_METHOD_CUSTOM_RULE.into(),
        ..Default::default()
    }
}

/// The matched log and challenge GUI rules applied to the verdict the pipeline reached. Block stays block;
/// an allow becomes the rule's verdict; with a challenge rule anything short of block becomes "challenge"
/// with the replaced verdict in `challenge_fallback`.
pub fn run_gui_record_rules(r: &mut AnalysisResult, gui: &GuiRuleOutcome) {
    if r.analyze_method == ANALYZE_METHOD_ERROR {
        return;
    }
    match r.action.as_str() {
        "allow" => {
            let (mut id, mut action) = (gui.challenge_rule_id.as_str(), "allow");
            if !gui.log_rule_id.is_empty() {
                action = "log";
                if id.is_empty() {
                    id = &gui.log_rule_id;
                }
            }
            r.action = action.into();
            r.analyze_method = ANALYZE_METHOD_CUSTOM_RULE.into();
            r.message = rule_note(id);
            r.categories = vec!["CustomRule".into()];
            r.match_detail.clear();
        }
        "log" | "block" => {
            if r.analyze_method != ANALYZE_METHOD_CUSTOM_RULE {
                record_gui_rule_hit(r, &gui.log_rule_id);
                record_gui_rule_hit(r, &gui.challenge_rule_id);
            }
        }
        _ => return,
    }
    if !gui.challenge_rule_id.is_empty() && r.action != "block" {
        r.challenge_fallback = std::mem::replace(&mut r.action, "challenge".into());
    }
}

/// Appends a matched GUI rule to the match detail once.
fn record_gui_rule_hit(r: &mut AnalysisResult, id: &str) {
    if id.is_empty() {
        return;
    }
    let note = rule_note(id);
    if contains(&r.match_detail, &note) {
        return;
    }
    if !r.match_detail.is_empty() {
        r.match_detail.extend_from_slice(b"; ");
    }
    r.match_detail.extend_from_slice(&note);
}

/// An allow becomes LOG, the verdict carries coverage regex_budget.
pub fn mark_regex_budget_incomplete(r: &mut AnalysisResult) {
    if r.analyze_method == ANALYZE_METHOD_ERROR {
        return;
    }
    let recorded = r
        .coverage
        .split(',')
        .any(|f| f == COVERAGE_FLAG_REGEX_BUDGET);
    let mut converted = false;
    if r.action != "block" && r.action != "log" {
        r.action = "log".into();
        r.analyze_method = ANALYZE_METHOD_CUSTOM_RULE.into();
        r.message = [
            b"custom_rule_incomplete:".as_slice(),
            COVERAGE_FLAG_REGEX_BUDGET.as_bytes(),
        ]
        .concat();
        r.categories = vec!["CustomRule".into()];
        converted = true;
    }
    r.coverage = merge_coverage_flags(&r.coverage, COVERAGE_FLAG_REGEX_BUDGET);
    if !recorded {
        PARTIAL_COVERAGE_REQUESTS.fetch_add(1, Ordering::Relaxed);
    }
    if (converted || !recorded) && !contains(&r.match_detail, b"coverage:") {
        if !r.match_detail.is_empty() {
            r.match_detail.extend_from_slice(b"; ");
        }
        r.match_detail.extend_from_slice(b"coverage:");
        r.match_detail.extend_from_slice(r.coverage.as_bytes());
    }
}

/// The allow message when inspection is off: which setting switched it off.
pub fn bypass_message(by_project: bool) -> &'static str {
    if by_project {
        "inspection off: project setting"
    } else {
        "inspection off: path exception"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(log: &str, challenge: &str) -> GuiRuleOutcome {
        GuiRuleOutcome {
            log_rule_id: log.into(),
            challenge_rule_id: challenge.into(),
            ..Default::default()
        }
    }

    #[test]
    fn allow_becomes_log_or_challenge() {
        let mut r = AnalysisResult {
            action: "allow".into(),
            match_detail: b"x".to_vec(),
            ..Default::default()
        };
        run_gui_record_rules(&mut r, &outcome("l1", ""));
        assert_eq!(
            (r.action.as_str(), r.message.as_slice()),
            ("log", b"custom_gui_rule:l1".as_slice())
        );
        assert!(r.match_detail.is_empty());
        assert_eq!(r.challenge_fallback, "");

        let mut r = AnalysisResult {
            action: "allow".into(),
            ..Default::default()
        };
        run_gui_record_rules(&mut r, &outcome("l1", "c1"));
        assert_eq!(r.action, "challenge");
        assert_eq!(r.challenge_fallback, "log");
        assert_eq!(r.message, b"custom_gui_rule:c1");

        let mut r = AnalysisResult {
            action: "allow".into(),
            ..Default::default()
        };
        run_gui_record_rules(&mut r, &outcome("", "c1"));
        assert_eq!(
            (r.action.as_str(), r.challenge_fallback.as_str()),
            ("challenge", "allow")
        );
    }

    #[test]
    fn engine_verdicts_keep_detail() {
        let mut r = AnalysisResult {
            action: "block".into(),
            analyze_method: "semantic".into(),
            match_detail: b"sqli".to_vec(),
            ..Default::default()
        };
        run_gui_record_rules(&mut r, &outcome("l1", "c1"));
        assert_eq!(r.action, "block");
        assert_eq!(
            r.match_detail,
            b"sqli; custom_gui_rule:l1; custom_gui_rule:c1"
        );

        let mut r = AnalysisResult {
            action: "log".into(),
            analyze_method: "semantic".into(),
            ..Default::default()
        };
        run_gui_record_rules(&mut r, &outcome("l1", ""));
        run_gui_record_rules(&mut r, &outcome("l1", ""));
        assert_eq!(r.match_detail, b"custom_gui_rule:l1");

        let mut r = AnalysisResult {
            action: "allow".into(),
            analyze_method: ANALYZE_METHOD_ERROR.into(),
            ..Default::default()
        };
        run_gui_record_rules(&mut r, &outcome("l1", ""));
        assert_eq!(r.action, "allow");
    }

    #[test]
    fn regex_budget() {
        let mut r = AnalysisResult {
            action: "allow".into(),
            ..Default::default()
        };
        mark_regex_budget_incomplete(&mut r);
        assert_eq!(r.action, "log");
        assert_eq!(r.coverage, "regex_budget");
        assert_eq!(r.match_detail, b"coverage:regex_budget");
        assert_eq!(r.message, b"custom_rule_incomplete:regex_budget");

        let mut r = AnalysisResult {
            action: "block".into(),
            coverage: "field_cap,regex_budget".into(),
            match_detail: b"coverage:field_cap,regex_budget".to_vec(),
            ..Default::default()
        };
        mark_regex_budget_incomplete(&mut r);
        assert_eq!(r.match_detail, b"coverage:field_cap,regex_budget");
    }

    #[test]
    fn messages() {
        assert_eq!(bypass_message(true), "inspection off: project setting");
        assert_eq!(bypass_message(false), "inspection off: path exception");
    }
}
