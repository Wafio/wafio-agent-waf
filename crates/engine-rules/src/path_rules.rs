//! Custom rules evaluated on both path readings.

use crate::custom_rules::{
    CustomGuiRule, RequestRuleContext, gui_rule_matches, sorted_by_priority,
};
use crate::custom_rules_v2::{TuningPlan, TuningRule};
use crate::forwarded_path::RequestPathReadings;
use crate::tuning::{compute_tuning_plan, scope_matches};
use wafio_bytetext::strings;

impl RequestRuleContext {
    /// A copy for the alternate path reading (the regex budget stays shared).
    pub fn with_alternate_path(&self, p: &[u8]) -> RequestRuleContext {
        let mut alt = self.clone();
        alt.path = p.to_vec();
        let ext = path_extension(p);
        alt.path_extension = strings::to_lowercase(ext.strip_prefix(b".").unwrap_or(ext));
        alt.uri = p.to_vec();
        if !self.query.is_empty() {
            alt.uri.push(b'?');
            alt.uri.extend_from_slice(&self.query);
        }
        alt
    }
}

fn path_extension(p: &[u8]) -> &[u8] {
    let mut i = p.len();
    while i > 0 && p[i - 1] != b'/' {
        i -= 1;
        if p[i] == b'.' {
            return &p[i..];
        }
    }
    b""
}

fn is_restrictive_action(action: &str) -> bool {
    matches!(
        strings::to_lowercase(strings::trim_whitespace(action.as_bytes())).as_slice(),
        b"block" | b"challenge"
    )
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuiRuleOutcome {
    pub action: String,
    pub rule_id: String,
    pub log_rule_id: String,
    pub challenge_rule_id: String,
}

pub fn evaluate_gui_rules_on_paths(
    rules: &[CustomGuiRule],
    ctx: &RequestRuleContext,
    alt: Option<&RequestRuleContext>,
    rp: &RequestPathReadings,
) -> GuiRuleOutcome {
    let mut out = GuiRuleOutcome::default();
    for r in sorted_by_priority(rules, |r| (r.priority, r.created_at, r.id.clone())) {
        if !r.enabled {
            continue;
        }
        let action = String::from_utf8_lossy(&strings::to_lowercase(strings::trim_whitespace(
            r.action.as_bytes(),
        )))
        .into_owned();
        match action.as_str() {
            "allow" => {
                if rp.no_exemption
                    || !gui_rule_matches(&r, ctx)
                    || alt.is_some_and(|a| !gui_rule_matches(&r, a))
                {
                    continue;
                }
                out.action = action;
                out.rule_id = r.id.clone();
                return out;
            }
            "block" | "log" | "challenge" => {
                if !gui_rule_matches(&r, ctx) && alt.is_none_or(|a| !gui_rule_matches(&r, a)) {
                    continue;
                }
            }
            _ => continue,
        }
        match action.as_str() {
            "block" => {
                out.action = action;
                out.rule_id = r.id.clone();
                return out;
            }
            "log" if out.log_rule_id.is_empty() => out.log_rule_id = r.id.clone(),
            "challenge" if out.challenge_rule_id.is_empty() => out.challenge_rule_id = r.id.clone(),
            _ => {}
        }
    }
    out
}

pub fn compute_tuning_plan_on_paths(
    rules: &[TuningRule],
    ctx: &RequestRuleContext,
    alt: Option<&RequestRuleContext>,
    rp: &RequestPathReadings,
) -> Option<TuningPlan> {
    if rp.no_exemption {
        return None;
    }
    let Some(alt) = alt else {
        return compute_tuning_plan(rules, ctx);
    };
    let both: Vec<TuningRule> = rules
        .iter()
        .filter(|r| r.enabled && scope_matches(&r.scope, alt))
        .cloned()
        .collect();
    compute_tuning_plan(&both, ctx)
}

pub fn merge_script_actions(
    rp: &RequestPathReadings,
    primary: &str,
    primary_id: &str,
    alternate: &str,
    alternate_id: &str,
) -> (String, String) {
    let (alternate, alternate_id) = if rp.unresolved.is_empty() {
        (primary, primary_id)
    } else {
        (alternate, alternate_id)
    };
    if is_restrictive_action(primary) {
        return (primary.into(), primary_id.into());
    }
    if is_restrictive_action(alternate) {
        return (alternate.into(), alternate_id.into());
    }
    if rp.no_exemption || primary != alternate {
        return (String::new(), String::new());
    }
    (primary.into(), primary_id.into())
}
