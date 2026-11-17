//! Engine tuning rules resolved into a per-request TuningPlan.
//!
//! A rule's `skip_crs` list is not read, and a rule scoped to the engine `crs` changes nothing but its `scan_mode`.

use crate::custom_rules::{RequestRuleContext, evaluate_condition, sorted_by_priority};
use crate::custom_rules_v2::{TuningEffect, TuningPlan, TuningRule, TuningScope};

fn lower_trim(s: &str) -> String {
    String::from_utf8_lossy(&wafio_bytetext::strings::to_lowercase(
        wafio_bytetext::strings::trim_whitespace(s.as_bytes()),
    ))
    .into_owned()
}

/// None when no rule's scope matches.
pub fn compute_tuning_plan(rules: &[TuningRule], ctx: &RequestRuleContext) -> Option<TuningPlan> {
    if rules.is_empty() {
        return None;
    }
    let mut plan: Option<TuningPlan> = None;
    for r in sorted_by_priority(rules, |r| (r.priority, r.created_at, r.id.clone())) {
        if !r.enabled || !scope_matches(&r.scope, ctx) {
            continue;
        }
        let p = plan.get_or_insert_with(TuningPlan::default);
        p.matched_rule_ids.push(r.id.clone());
        if p.scan_mode.is_empty() && !r.effect.scan_mode.is_empty() {
            p.scan_mode = read_scan_mode(&r.effect.scan_mode);
            let m = p.scan_mode.clone();
            set_scan_mode(p, &m);
        }
        let mut eff = r.effect.clone();
        if lower_trim(&r.engine) == "crs" {
            // A rule scoped to the retired engine skips nothing here.
            eff.skip_semantic.clear();
            eff.action.clear();
            eff.weaken = None;
        }
        plan = Some(merge_effect_into_plan(plan, &eff));
    }
    plan
}

/// Merges an effect into the plan (scan_mode ignored).
pub fn merge_effect_into_plan(plan: Option<TuningPlan>, effect: &TuningEffect) -> TuningPlan {
    let mut plan = plan.unwrap_or_default();
    merge_semantic_skips(&mut plan, effect);
    plan
}

pub(crate) fn scope_matches(s: &TuningScope, ctx: &RequestRuleContext) -> bool {
    if s.conditions.is_empty() {
        return true;
    }
    let or = lower_trim(&s.logic) == "or";
    for c in &s.conditions {
        let m = evaluate_condition(c, ctx);
        if or && m {
            return true;
        }
        if !or && !m {
            return false;
        }
    }
    !or
}

/// The scan mode of a rule as this agent reads it: `semantic_only` and `crs_only`, which stored rules
/// of earlier versions still carry, read as `default`.
fn read_scan_mode(raw: &str) -> String {
    match lower_trim(raw).as_str() {
        "semantic_only" | "crs_only" => "default".into(),
        m => m.into(),
    }
}

fn set_scan_mode(p: &mut TuningPlan, mode: &str) {
    match mode {
        "disabled" => p.skip_semantic_all = true,
        "both" => {
            p.skip_semantic_all = false;
            p.skip_semantic_engines.clear();
        }
        _ => {}
    }
}

fn merge_semantic_skips(p: &mut TuningPlan, e: &TuningEffect) {
    for s in &e.skip_semantic {
        let s = lower_trim(s);
        match s.as_str() {
            "" => continue,
            "*" => p.skip_semantic_all = true,
            _ => {
                p.skip_semantic_engines.insert(s);
            }
        }
    }
    p.log_only |= e.holds_detections_as_log();
}

impl TuningPlan {
    pub fn skips_semantic_engine(&self, engine: &str) -> bool {
        self.skip_semantic_all || self.skip_semantic_engines.contains(&lower_trim(engine))
    }
    pub fn skips_any_semantic_engine(&self) -> bool {
        self.skip_semantic_all || !self.skip_semantic_engines.is_empty()
    }
}

pub fn json_pointer_to_dotted(pointer: &str) -> String {
    if pointer.is_empty() {
        return String::new();
    }
    let p = pointer.strip_prefix('/').unwrap_or(pointer);
    p.replace("~1", "/").replace("~0", "~").replace('/', ".")
}

/// The name a target component carries and whether the component names the whole request.
fn split_component(comp: &str) -> (String, bool) {
    let lower = String::from_utf8_lossy(&wafio_bytetext::strings::to_lowercase(comp.as_bytes()))
        .into_owned();
    if matches!(
        lower.as_str(),
        "" | "request" | "args" | "multipart:filename"
    ) {
        return (String::new(), true);
    }
    let mut comp_name = String::new();
    for prefix in [
        "query:",
        "form:",
        "json:",
        "header:",
        "cookie:",
        "multipart:filename:",
        "multipart:",
    ] {
        if lower.starts_with(prefix) {
            comp_name = comp.get(prefix.len()..).unwrap_or_default().to_string();
            break;
        }
    }
    if comp_name.is_empty() {
        return (comp.to_string(), false);
    }
    if comp_name.starts_with('/') {
        comp_name = json_pointer_to_dotted(&comp_name);
    }
    (comp_name, false)
}

pub fn component_name(comp: &str) -> Option<String> {
    let (name, whole) = split_component(comp);
    if whole { None } else { Some(name) }
}
