//! Script rules: the budget types, and the result of a request whose script rules cannot run at all.
//!
//! The rules run in the agent (`wafio-waf-agent`, `script_rules.rs`); the sandbox limits, the verdicts and the
//! incomplete reasons are the interpreter's. Without a runner every enabled rule is unfinished
//! (`not_configured`, LOG, coverage script_timeout), never a silent allow.

use std::time::Duration;

use crate::custom_rules::{CustomScriptRule, RequestRuleContext, ScriptResult, sorted_by_priority};

pub const DEFAULT_PER_SCRIPT_TIMEOUT: Duration = Duration::from_millis(5);
pub const DEFAULT_SCRIPT_BATCH_BUDGET: Duration = Duration::from_millis(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptBudget {
    pub per_script: Duration,
    pub total: Duration,
}

impl ScriptBudget {
    /// A zero field falls back to its production default (a `Duration` cannot be negative).
    pub fn filled_with_defaults(mut self) -> ScriptBudget {
        if self.per_script.is_zero() {
            self.per_script = DEFAULT_PER_SCRIPT_TIMEOUT;
        }
        if self.total.is_zero() {
            self.total = DEFAULT_SCRIPT_BATCH_BUDGET;
        }
        self
    }
}

pub fn script_budget_default() -> ScriptBudget {
    ScriptBudget {
        per_script: DEFAULT_PER_SCRIPT_TIMEOUT,
        total: DEFAULT_SCRIPT_BATCH_BUDGET,
    }
}

/// The incomplete reason reported while no runner is configured.
pub const SCRIPT_NOT_CONFIGURED: &str = "not_configured";

/// What a request's script rules report when they could not run at all: every enabled rule is
/// unfinished for `reason`, in evaluation order (LOG with coverage script_timeout, never a silent
/// allow).
pub fn unfinished_result(rules: &[CustomScriptRule], reason: &str) -> ScriptResult {
    let mut res = ScriptResult::default();
    for r in sorted_by_priority(rules, |r| (r.priority, r.created_at, r.id.clone())) {
        if r.enabled {
            res.record_incomplete(&r.id, reason);
        }
    }
    res
}

/// Evaluation with no runner: every enabled rule is unfinished ("not configured").
pub fn run_script_rules(
    rules: &[CustomScriptRule],
    _ctx: &RequestRuleContext,
    _budget: ScriptBudget,
) -> ScriptResult {
    unfinished_result(rules, SCRIPT_NOT_CONFIGURED)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, enabled: bool, priority: i64, created_at: i64) -> CustomScriptRule {
        CustomScriptRule {
            id: id.into(),
            enabled,
            priority,
            created_at,
            script: "waf_block()".into(),
            ..Default::default()
        }
    }

    #[test]
    fn script_budget_defaults() {
        assert_eq!(
            ScriptBudget {
                per_script: Duration::ZERO,
                total: Duration::ZERO
            }
            .filled_with_defaults(),
            script_budget_default()
        );
        let b = ScriptBudget {
            per_script: Duration::from_secs(1),
            total: Duration::ZERO,
        };
        assert_eq!(
            b.filled_with_defaults(),
            ScriptBudget {
                per_script: Duration::from_secs(1),
                total: DEFAULT_SCRIPT_BATCH_BUDGET
            }
        );
    }

    #[test]
    fn unfinished_marks_every_enabled_rule_in_order() {
        let rules = [
            rule("b", true, 1, 0),
            rule("off", false, 0, 0),
            rule("a", true, 1, 0),
        ];
        let r = unfinished_result(&rules, "canceled");
        assert!(r.incomplete);
        assert_eq!(
            (r.incomplete_rule.as_str(), r.incomplete_reason.as_str()),
            ("a", "canceled")
        );
        assert_eq!(r.coverage, "script_timeout");
        assert!(
            !r.content_incomplete,
            "a load-induced reason is never a reason to BLOCK"
        );
        assert_eq!(
            unfinished_result(&[rule("off", false, 0, 0)], "timeout"),
            ScriptResult::default()
        );
        assert!(!unfinished_result(&rules, "timeout").content_incomplete);
        assert!(
            unfinished_result(&rules, SCRIPT_NOT_CONFIGURED).content_incomplete,
            "not_configured is not a load reason"
        );
    }
}
