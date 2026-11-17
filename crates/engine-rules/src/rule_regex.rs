//! Compiled rule regexes with a program-size budget (`RULE_REGEX_PROGRAM_LIMIT`) and a per-request
//! work budget (`REQUEST_REGEX_BUDGET`, charged instructions × input bytes).
//!
//! Program size and validity come from the regexp syntax parser (pattern_compile.rs): the
//! instruction count of the simplified program compiled from the pattern in Perl syntax.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use wafio_bytetext::pattern::CompiledRegex;

/// Compiled RE2 instructions a rule pattern may take.
pub const RULE_REGEX_PROGRAM_LIMIT: usize = 256;

/// Instructions × input bytes per request.
pub const REQUEST_REGEX_BUDGET: i64 = 1 << 19;

/// The error text for a pattern that compiles to too many instructions.
pub const RULE_REGEX_TOO_COMPLEX_MESSAGE: &str = "regex too complex";

static DROPPED_REGEX_RULE_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn dropped_regex_rule_count() -> u64 {
    DROPPED_REGEX_RULE_COUNT.load(Ordering::Relaxed)
}

pub(crate) fn note_rule_dropped() {
    DROPPED_REGEX_RULE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// A compiled rule regex: None = invalid or over budget (never matches).
#[derive(Clone, Debug)]
pub struct RuleRegexEntry {
    pub regex: Option<CompiledRegex>,
    pub instruction_count: usize,
}

/// Returns (regex, program size) or the error text.
pub fn compile_rule_pattern(pattern: &str) -> Result<(CompiledRegex, usize), String> {
    // Order: parse error, then the size budget, then compile.
    let n = crate::pattern_compile::program_size(pattern)?;
    if n > RULE_REGEX_PROGRAM_LIMIT {
        return Err(format!(
            "{RULE_REGEX_TOO_COMPLEX_MESSAGE}: compiles to {n} instructions (max {RULE_REGEX_PROGRAM_LIMIT})"
        ));
    }
    Ok((crate::pattern_compile::compile(pattern)?, n))
}

/// "" when the pattern is usable, else the error text.
pub fn unusable_pattern_error(pattern: &str) -> String {
    compile_rule_pattern(pattern).err().unwrap_or_default()
}

static CACHE: LazyLock<Mutex<HashMap<String, RuleRegexEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The cached entry of a pattern (compiled on first use).
pub fn cached_rule_regex(pattern: &str) -> RuleRegexEntry {
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = c.get(pattern) {
        return e.clone();
    }
    let e = match compile_rule_pattern(pattern) {
        Ok((re, n)) => RuleRegexEntry {
            regex: Some(re),
            instruction_count: n,
        },
        Err(_) => RuleRegexEntry {
            regex: None,
            instruction_count: 0,
        },
    };
    // shortcut: this cache is unbounded; upgrade with the bundle-apply path by capping it at 16 MiB
    // of estimated bytes per generation and swapping generations on bundle apply.
    c.insert(pattern.to_string(), e.clone());
    e
}

/// RegexBudget bounds one request's regex condition work.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegexBudget {
    remaining: i64,
    exhausted: bool,
}

impl RegexBudget {
    pub fn new(units: i64) -> RegexBudget {
        RegexBudget {
            remaining: units,
            exhausted: false,
        }
    }
    pub fn exhausted(&self) -> bool {
        self.exhausted
    }
    /// charge: reserves insts × max(n, 1); false (and exhausted) when it cannot.
    pub fn charge(&mut self, insts: usize, n: usize) -> bool {
        let cost = insts as i64 * n.max(1) as i64;
        if self.exhausted || cost > self.remaining {
            self.exhausted = true;
            return false;
        }
        self.remaining -= cost;
        true
    }
}

/// The number of instructions the pattern compiles to, or None when the parser rejects it.
pub fn regex_program_size(pattern: &str) -> Option<usize> {
    crate::pattern_compile::program_size(pattern).ok()
}

/// The first unusable regex of a rule's conditions or target, "" if none.
pub fn first_unusable_regex(
    conds: &[crate::custom_rules::RuleCondition],
    target: &crate::custom_rules_v2::TuningTarget,
) -> String {
    for (i, c) in conds.iter().enumerate() {
        if is_regex_condition_operator(&c.operator) {
            let msg = unusable_pattern_error(&c.value);
            if !msg.is_empty() {
                return format!("condition {}: {msg}", i + 1);
            }
        }
    }
    let mut problem = String::new();
    target_regex_patterns(target, |p| {
        if problem.is_empty() {
            let msg = unusable_pattern_error(p);
            if !msg.is_empty() {
                problem = format!(
                    "target {}: {msg}",
                    wafio_domain::text_helpers::quote(p.as_bytes())
                );
            }
        }
    });
    problem
}

/// The rules whose every regex compiles within the budget; each
/// dropped rule is logged and counted (`dropped_regex_rule_count`).
pub fn retain_usable_regex_rules(
    gui: Vec<crate::custom_rules::CustomGuiRule>,
    tuning: Vec<crate::custom_rules_v2::TuningRule>,
) -> (
    Vec<crate::custom_rules::CustomGuiRule>,
    Vec<crate::custom_rules_v2::TuningRule>,
) {
    let dropped = |kind: &str, id: &str, problem: String| {
        if problem.is_empty() {
            return false;
        }
        note_rule_dropped();
        tracing::info!("custom {kind} rule {id} dropped: unusable regex: {problem}");
        true
    };
    let no_target = crate::custom_rules_v2::TuningTarget::default();
    let gui = gui
        .into_iter()
        .filter(|r| {
            !dropped(
                "gui",
                &r.id,
                first_unusable_regex(&r.conditions, &no_target),
            )
        })
        .collect();
    let tuning = tuning
        .into_iter()
        .filter(|r| {
            !dropped(
                "tuning",
                &r.id,
                first_unusable_regex(&r.scope.conditions, &r.target),
            )
        })
        .collect();
    (gui, tuning)
}

pub fn is_regex_condition_operator(op: &str) -> bool {
    op == "matches" || op == "regex"
}

/// The patterns a regex-mode tuning target compiles.
pub fn target_regex_patterns(t: &crate::custom_rules_v2::TuningTarget, mut f: impl FnMut(&str)) {
    if wafio_bytetext::strings::to_lowercase(wafio_bytetext::strings::trim_whitespace(
        t.match_.as_bytes(),
    )) != b"regex"
    {
        return;
    }
    for comp in &t.components {
        if let Some(name) =
            crate::tuning::component_name(wafio_domain::text_helpers::trim_whitespace_str(comp))
            && !name.is_empty()
        {
            f(&name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom_rules::{CustomGuiRule, RuleCondition};
    use crate::custom_rules_v2::{TuningRule, TuningScope, TuningTarget};

    fn cond(op: &str, value: &str) -> RuleCondition {
        RuleCondition {
            field: "path".into(),
            operator: op.into(),
            value: value.into(),
            ..Default::default()
        }
    }

    // A rule with an unusable regex never applies (a negated condition that
    // cannot match would match everything); the rest keep their order; each drop is counted.
    #[test]
    fn unusable_regex_rules_are_retained_out_and_counted() {
        let gui = |id: &str, c: RuleCondition| CustomGuiRule {
            id: id.into(),
            enabled: true,
            conditions: vec![c],
            ..Default::default()
        };
        let gui_rules = vec![
            gui("ok", cond("regex", "^/a")),
            gui("bad", cond("matches", "(")),
            gui("eq", cond("equals", "(")),
            gui("big", cond("regex", &"(a|b)".repeat(200))),
        ];
        let tuning = |id: &str, target: TuningTarget, c: Vec<RuleCondition>| TuningRule {
            id: id.into(),
            scope: TuningScope {
                logic: "and".into(),
                conditions: c,
            },
            target,
            ..Default::default()
        };
        let regex_target = TuningTarget {
            components: vec!["param:(".into()],
            match_: "regex".into(),
        };
        let exact_target = TuningTarget {
            components: vec!["param:(".into()],
            match_: "exact".into(),
        };
        let tuning_rules = vec![
            tuning("t-ok", exact_target, vec![cond("regex", "x")]),
            tuning("t-target", regex_target, vec![]),
            tuning("t-cond", TuningTarget::default(), vec![cond("regex", "[")]),
        ];
        let before = dropped_regex_rule_count();
        let (gui, tuning) = retain_usable_regex_rules(gui_rules, tuning_rules);
        let ids: Vec<_> = gui.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["ok", "eq"], "only regex operators are checked");
        assert_eq!(
            tuning.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["t-ok"]
        );
        assert_eq!(dropped_regex_rule_count() - before, 4);
    }
}
