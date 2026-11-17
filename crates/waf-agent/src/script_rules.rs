//! Script rules, run in this process by the uddin interpreter (`uddin-waf`).
//!
//! A bundle's rules are compiled once, when it is applied, into the runner of their app. A request runs them in
//! rule order on its own thread, each under the script deadline and all under the request's script budget. A rule
//! that does not finish (runtime error, limit, deadline, panic, budget spent) is marked unfinished: the verdict is
//! LOG at worst and the coverage says script_error or script_timeout, never a silent allow.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::btree_map;
use std::slice;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use uddin_waf::{Json, Limits, Profile, RequestContext, Verdict, WafRunner, WafScript};
use wafio_application::ScriptRunner;
use wafio_engine_rules::{
    CustomScriptRule, DynamicJson, RequestRuleContext, ScriptBudget, ScriptResult,
    all_field_values, read_field_value,
};

/// The `Hello.features` entry of this agent: it runs script rules itself.
pub const FEATURE_SCRIPT_RULES: &str = "script_rules";

/// Heartbeat field 11 / `wafio_waf_script_incomplete`: rules that did not finish, one per rule and request.
static INCOMPLETE: AtomicU64 = AtomicU64::new(0);
/// Heartbeat field 12 / `wafio_waf_script_errors`: the share of them that ended in a runtime error.
static ERRORS: AtomicU64 = AtomicU64::new(0);
/// Heartbeat field 13 / `wafio_waf_script_rules_rejected`: rules dropped because they did not compile.
static REJECTED: AtomicU64 = AtomicU64::new(0);
/// Heartbeat field 14 / `wafio_waf_script_runs_in_flight`: runs executing right now.
static IN_FLIGHT: AtomicI64 = AtomicI64::new(0);
/// `wafio_waf_apps_with_script_rules`: apps of the bundle in force with an enabled script rule.
static APPS_WITH_RULES: AtomicU64 = AtomicU64::new(0);

pub fn incomplete_total() -> u64 {
    INCOMPLETE.load(Ordering::Relaxed)
}

pub fn errors_total() -> u64 {
    ERRORS.load(Ordering::Relaxed)
}

pub fn rejected_total() -> u64 {
    REJECTED.load(Ordering::Relaxed)
}

pub fn runs_in_flight() -> i64 {
    IN_FLIGHT.load(Ordering::Relaxed)
}

pub fn apps_with_script_rules() -> u64 {
    APPS_WITH_RULES.load(Ordering::Relaxed)
}

/// Records the per-bundle count behind `wafio_waf_apps_with_script_rules`.
pub fn set_apps_with_script_rules(apps: u64) {
    APPS_WITH_RULES.store(apps, Ordering::Relaxed);
}

thread_local! {
    /// One interpreter state per request thread; it keeps its memory from run to run.
    static RUNNER: RefCell<WafRunner> = RefCell::new(WafRunner::new());
}

/// The sandbox profile and the limits of one script, read once.
fn sandbox() -> &'static (Profile, Limits) {
    static SANDBOX: OnceLock<(Profile, Limits)> = OnceLock::new();
    SANDBOX.get_or_init(|| {
        let profile = uddin_waf::profile();
        let limits = profile.limits();
        (profile, limits)
    })
}

struct Compiled {
    id: String,
    priority: i64,
    created_at: i64,
    script: WafScript,
}

/// The compiled script rules of one app, in the order they run: priority, creation time, id.
pub struct Scripts {
    rules: Vec<Compiled>,
}

/// Compiles the enabled rules of an app. A rule that does not compile is dropped with a log line and counted as
/// rejected; the rest are returned with the runner that holds the compiled ones.
pub fn compile(
    app_id: &str,
    rules: Vec<CustomScriptRule>,
) -> (Vec<CustomScriptRule>, Arc<Scripts>) {
    let profile = &sandbox().0;
    let (mut kept, mut compiled) = (Vec::with_capacity(rules.len()), Vec::new());
    for r in rules {
        if r.enabled {
            match WafScript::compile(r.script.as_bytes(), profile) {
                Ok(script) => compiled.push(Compiled {
                    id: r.id.clone(),
                    priority: r.priority,
                    created_at: r.created_at,
                    script,
                }),
                Err(e) => {
                    REJECTED.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        "[waf-bundle] app={app_id}: script rule {} dropped: {e}",
                        r.id
                    );
                    continue;
                }
            }
        }
        kept.push(r);
    }
    compiled
        .sort_by(|a, b| (a.priority, a.created_at, &a.id).cmp(&(b.priority, b.created_at, &b.id)));
    (kept, Arc::new(Scripts { rules: compiled }))
}

/// Marks one rule unfinished and counts it.
fn unfinished(res: &mut ScriptResult, id: &str, reason: &str) {
    INCOMPLETE.fetch_add(1, Ordering::Relaxed);
    if reason == "error" {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    if reason == "panic" {
        tracing::warn!(
            "[script-rules] the interpreter failed inside rule {id}; the rule is unfinished"
        );
    }
    res.record_incomplete(id, reason);
}

impl ScriptRunner for Scripts {
    fn run_script_rules(&self, ctx: &RequestRuleContext, budget: ScriptBudget) -> ScriptResult {
        let mut res = ScriptResult::default();
        if self.rules.is_empty() {
            return res;
        }
        let budget = budget.filled_with_defaults();
        let end = Instant::now() + budget.total;
        let mut limits = sandbox().1.clone();
        limits.deadline = Some(budget.per_script);
        let view = View(ctx);
        for rule in &self.rules {
            if Instant::now() >= end {
                unfinished(&mut res, &rule.id, "budget");
                continue;
            }
            IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
            let run = RUNNER.with_borrow_mut(|r| r.run(&rule.script, &view, &limits, Some(end)));
            IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);
            if let Some(reason) = run.incomplete() {
                unfinished(&mut res, &rule.id, reason);
                continue;
            }
            let Some(verdict) = run.verdict else { continue };
            // An allow after a rule that did not finish proves nothing: that rule might have blocked.
            if verdict == Verdict::Allow && res.incomplete {
                continue;
            }
            res.action = verdict.as_str().into();
            res.rule_id = rule.id.clone();
            return res;
        }
        res
    }
}

/// The request as the interpreter reads it: slices of the agent's own request, copied only when a script asks.
struct View<'a>(&'a RequestRuleContext);

impl RequestContext for View<'_> {
    fn method(&self) -> &[u8] {
        &self.0.method
    }

    fn path(&self) -> &[u8] {
        &self.0.path
    }

    fn query(&self) -> &[u8] {
        &self.0.query
    }

    fn ip(&self) -> &[u8] {
        &self.0.ip
    }

    fn country(&self) -> &[u8] {
        &self.0.country
    }

    fn ua(&self) -> &[u8] {
        &self.0.ua
    }

    fn body(&self) -> &[u8] {
        &self.0.body
    }

    fn score(&self) -> f64 {
        self.0.score
    }

    fn action(&self) -> &[u8] {
        self.0.action.as_bytes()
    }

    fn header_count(&self) -> usize {
        self.0.headers.len()
    }

    fn header(&self, i: usize) -> (&[u8], &[u8]) {
        let (name, value) = &self.0.headers[i];
        (name, value)
    }

    fn detected_count(&self) -> usize {
        self.0.detected.len()
    }

    fn detected(&self, i: usize) -> &[u8] {
        self.0.detected[i].as_bytes()
    }

    fn json(&self) -> Option<Cow<'_, Json>> {
        let doc = self.0.parsed.as_ref()?.json.as_ref()?;
        Some(Cow::Owned(json_of(doc)))
    }

    fn field(&self, name: &[u8]) -> Cow<'_, [u8]> {
        Cow::Owned(read_field_value(&String::from_utf8_lossy(name), "", self.0))
    }

    fn field_values(&self, name: &[u8], each: &mut dyn FnMut(&[u8])) {
        for v in all_field_values(&String::from_utf8_lossy(name), self.0) {
            each(&v);
        }
    }
}

/// The document the interpreter hands to `waf_json`. Built without recursion: a body may nest ten thousand levels
/// and a request thread's stack is small.
fn json_of(root: &DynamicJson) -> Json {
    enum Open<'a> {
        Array(slice::Iter<'a, DynamicJson>, Vec<Json>),
        Object(
            btree_map::Iter<'a, String, DynamicJson>,
            Vec<(Vec<u8>, Json)>,
            &'a [u8],
        ),
    }
    let mut open: Vec<Open> = Vec::new();
    let mut enter = Some(root);
    let mut done: Option<Json> = None;
    loop {
        if let Some(node) = enter.take() {
            match node {
                DynamicJson::Null => done = Some(Json::Null),
                DynamicJson::Bool(b) => done = Some(Json::Bool(*b)),
                DynamicJson::Number(n) => done = Some(Json::Number(n.clone())),
                DynamicJson::String(s) => done = Some(Json::String(s.as_bytes().to_vec())),
                DynamicJson::Array(a) => {
                    open.push(Open::Array(a.iter(), Vec::with_capacity(a.len())))
                }
                DynamicJson::Object(m) => {
                    open.push(Open::Object(m.iter(), Vec::with_capacity(m.len()), b""));
                }
            }
        }
        if let Some(value) = done.take() {
            match open.last_mut() {
                None => return value,
                Some(Open::Array(_, out)) => out.push(value),
                Some(Open::Object(_, out, key)) => out.push((key.to_vec(), value)),
            }
        }
        match open.last_mut() {
            Some(Open::Array(rest, _)) => match rest.next() {
                Some(child) => enter = Some(child),
                None => {
                    if let Some(Open::Array(_, out)) = open.pop() {
                        done = Some(Json::Array(out));
                    }
                }
            },
            Some(Open::Object(rest, _, key)) => match rest.next() {
                Some((name, child)) => {
                    *key = name.as_bytes();
                    enter = Some(child);
                }
                None => {
                    if let Some(Open::Object(_, out, _)) = open.pop() {
                        done = Some(Json::Object(out));
                    }
                }
            },
            None => unreachable!("the root is entered before the first pass"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn rule(id: &str, priority: i64, script: &str) -> CustomScriptRule {
        CustomScriptRule {
            id: id.into(),
            enabled: true,
            priority,
            script: script.into(),
            ..Default::default()
        }
    }

    fn budget(per_script_ms: u64) -> ScriptBudget {
        ScriptBudget {
            per_script: Duration::from_millis(per_script_ms),
            total: Duration::from_secs(5),
        }
    }

    fn run(rules: Vec<CustomScriptRule>, b: ScriptBudget) -> ScriptResult {
        let ctx = RequestRuleContext {
            method: b"GET".to_vec(),
            path: b"/".to_vec(),
            ..Default::default()
        };
        compile("a", rules).1.run_script_rules(&ctx, b)
    }

    #[test]
    fn a_rule_that_does_not_compile_is_dropped_and_counted() {
        let mut off = rule("off", 0, "x = (");
        off.enabled = false;
        let rules = vec![
            rule("ok", 0, "waf_log()"),
            rule("syntax", 0, "x = ("),
            rule("stray", 0, "break"),
            off,
        ];
        let before = rejected_total();
        let (kept, scripts) = compile("a", rules);
        let ids: Vec<&str> = kept.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            ["ok", "off"],
            "a disabled rule is kept, never compiled"
        );
        assert!(rejected_total() >= before + 2);
        assert_eq!(scripts.rules.len(), 1);
    }

    #[test]
    fn the_first_verdict_in_rule_order_decides() {
        let r = run(
            vec![
                rule("late", 5, "waf_block()"),
                rule("first", 1, "waf_log()"),
                rule("quiet", 0, "x = 1"),
            ],
            budget(5),
        );
        assert_eq!((r.action.as_str(), r.rule_id.as_str()), ("log", "first"));
        assert!(!r.incomplete);
    }

    #[test]
    fn a_runtime_error_is_unfinished_and_an_allow_after_it_is_dropped() {
        let before = (incomplete_total(), errors_total());
        let r = run(
            vec![rule("bad", 0, "x = 1 / 0"), rule("allow", 1, "waf_allow()")],
            budget(5),
        );
        assert_eq!(r.action, "");
        assert_eq!(
            (r.incomplete_rule.as_str(), r.incomplete_reason.as_str()),
            ("bad", "error")
        );
        assert_eq!(r.coverage, "script_error");
        assert!(r.content_incomplete);
        assert!(incomplete_total() > before.0 && errors_total() > before.1);
        // A block after the failed rule still applies.
        let r = run(
            vec![rule("bad", 0, "x = 1 / 0"), rule("block", 1, "waf_block()")],
            budget(5),
        );
        assert_eq!((r.action.as_str(), r.rule_id.as_str()), ("block", "block"));
        assert!(r.incomplete);
    }

    #[test]
    fn a_decision_before_a_failure_stands() {
        let r = run(vec![rule("r", 0, "waf_block()\nx = 1 / 0")], budget(5));
        assert_eq!((r.action.as_str(), r.incomplete), ("block", false));
    }

    #[test]
    fn a_limit_is_unfinished_with_the_timeout_mark() {
        let r = run(vec![rule("loop", 0, "while (true):\nend")], budget(5000));
        assert_eq!(r.incomplete_reason, "op_limit");
        assert_eq!(r.coverage, "script_timeout");
        assert!(
            r.content_incomplete,
            "a limit the request causes may raise the verdict"
        );
    }

    #[test]
    fn the_deadline_stops_a_script_and_the_spent_budget_skips_the_rest() {
        let tiny = ScriptBudget {
            per_script: Duration::from_nanos(1),
            total: Duration::from_secs(5),
        };
        let r = run(vec![rule("slow", 0, "while (true):\nend")], tiny);
        assert_eq!(r.incomplete_reason, "timeout");
        assert_eq!(r.coverage, "script_timeout");
        assert!(
            !r.content_incomplete,
            "time is load, never a reason to block"
        );
        let spent = ScriptBudget {
            per_script: Duration::from_secs(1),
            total: Duration::from_nanos(1),
        };
        let r = run(vec![rule("a", 0, "waf_block()")], spent);
        assert_eq!(
            (r.action.as_str(), r.incomplete_reason.as_str()),
            ("", "budget")
        );
    }
}
