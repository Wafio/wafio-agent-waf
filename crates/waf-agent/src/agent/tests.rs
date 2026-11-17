use std::sync::Mutex;

use wafio_application::RateLimitStore;
use wafio_application::blocklist::BlockStore;

use super::*;
use crate::executor::startup_executor;
use crate::ready::ReadyActions;

/// Records what the proxy would get; fails when told to.
#[derive(Default)]
struct FakeProxy {
    applied: Mutex<Vec<Vec<(String, u16, String)>>>,
    fail: Mutex<Option<String>>,
}

impl RouteSink for FakeProxy {
    fn apply(&self, apps: Vec<AppSpec>) -> Result<(), String> {
        if let Some(e) = self.fail.lock().unwrap().clone() {
            return Err(e);
        }
        self.applied.lock().unwrap().push(
            apps.iter()
                .map(|a| (a.app_id.clone(), a.listen_port, a.mode.clone()))
                .collect(),
        );
        Ok(())
    }
}

fn agent() -> (Arc<Agent>, Arc<FakeProxy>, Arc<Ready>) {
    let stores = Stores::new();
    let base = startup_executor(&stores, "", None).unwrap();
    let proxy = Arc::new(FakeProxy::default());
    let ready = Arc::new(Ready::new(ReadyActions::default()));
    let a = Arc::new(Agent::new(
        base,
        stores,
        proxy.clone(),
        Arc::new(VerifiedBotChecker::new()),
        ready.clone(),
    ));
    (a, proxy, ready)
}

fn apply(a: &Agent, json: &str, generation: i64) -> Result<(), BundleError> {
    let mut b = decode_bundle(json.as_bytes()).map_err(BundleError::Decode)?;
    b.generation = generation;
    a.install_bundle(&b)
}

const APP: &str = r#"{"app_id":"a1","listen_host":"127.0.0.1","listen_port":18080,"upstream":"http://127.0.0.1:9000","mode":"monitor"}"#;

#[test]
fn first_bundle_applies_and_signals_ready() {
    let (a, proxy, ready) = agent();
    assert!(!ready.signaled());
    apply(
        &a,
        &format!(r#"{{"agent_id":"x","project_id":"p1","apps":[{APP}]}}"#),
        3,
    )
    .unwrap();
    assert!(ready.signaled());
    assert_eq!(
        proxy.applied.lock().unwrap()[0],
        vec![("a1".to_string(), 18080, "monitor".to_string())]
    );
    assert_eq!(a.generation(), (3, "x".to_string()));
    let e = a.app_executor("a1").unwrap();
    assert_eq!(e.analyze.project_id, "p1");
    assert!(a.shared_executor().is_some());
}

/// Collects the text of every tracing event.
struct Collect(Arc<Mutex<Vec<String>>>);

impl tracing::Subscriber for Collect {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Text(String);
        impl tracing::field::Visit for Text {
            fn record_debug(&mut self, _: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{v:?} "));
            }
        }
        let mut t = Text(String::new());
        event.record(&mut t);
        self.0.lock().unwrap().push(t.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn a_default_bundle_logs_no_line_about_a_missing_engine() {
    let (a, _, _) = agent();
    let lines = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Collect(lines.clone()), || {
        apply(
            &a,
            &format!(r#"{{"agent_id":"x","project_id":"p1","apps":[{APP}]}}"#),
            1,
        )
        .unwrap();
    });
    let lines = lines.lock().unwrap().join("\n");
    for word in [
        "rule-based",
        "CRS",
        "semantic-only",
        "semantic_only",
        "no rule engine",
    ] {
        assert!(!lines.contains(word), "{word} in {lines:?}");
    }
}

#[test]
fn fields_of_earlier_bundles_are_read_and_ignored() {
    // A bundle of an earlier control plane: sensitivity, paranoia and exclude_rules belong to the rule
    // set that no longer exists; the rules document carries the body buffer limits of the old engine.
    let (a, _, _) = agent();
    let json = r#"{"agent_id":"x","project_id":"p1","sensitivity":9,
        "rules_json":{"request_body_in_memory_limit":"1M","response_body_limit":"2M"},
        "apps":[{"app_id":"a1","upstream":"http://u","paranoia":4,"sensitivity":-1,"exclude_rules":["942100"],
                 "rules_json":{"request_body_in_memory_limit":"4M"}}]}"#;
    apply(&a, json, 1).unwrap();
    assert!(a.app_executor("a1").is_some());
}

#[test]
fn bundle_level_refusals_use_the_wire_texts() {
    let (a, _, ready) = agent();
    let cases = [
        (
            r#"{"apps":[{"app_id":"a","upstream":"http://u"},{"app_id":"a","upstream":"http://u"}]}"#,
            "duplicate app in WAF bundle",
        ),
        (
            r#"{"apps":[{"app_id":"a","upstream":""}]}"#,
            "invalid app route in WAF bundle",
        ),
        (
            r#"{"apps":[{"app_id":"a","upstream":"ftp://u"}]}"#,
            "invalid app route in WAF bundle",
        ),
        (
            r#"{"apps":[{"app_id":"a","upstream":"http://u","listen_port":80},{"app_id":"b","upstream":"http://u","listen_port":80,"listen_host":"0.0.0.0"}]}"#,
            "duplicate listener in WAF bundle",
        ),
        (
            r#"{"apps":[{"app_id":"a","upstream":"http://u","listen_port":70000}]}"#,
            "failed to bind WAF route listener",
        ),
        (
            r#"{"rules_json":{"Thresholds":{"block":100},"thresholds":{"block":110}}}"#,
            "invalid WAF configuration",
        ),
        (
            r#"{"unblock_entries":[{"type":"ratelimit","key":"1.2.3.4"}]}"#,
            "invalid rate-limit unblock identity",
        ),
        (
            r#"{"unblock_entries":[{"type":"login_scope"}]}"#,
            "invalid login unblock scope",
        ),
        (
            r#"{"unblock_entries":[{"type":"blockpolicy"}]}"#,
            "invalid block-policy unblock key",
        ),
        (
            r#"{"unblock_entries":[{"type":"other","key":"k"}],"management_only":true}"#,
            "unsupported unblock command",
        ),
    ];
    for (json, want) in cases {
        assert_eq!(
            apply(&a, json, 1),
            Err(BundleError::Apply(want.into())),
            "{json}"
        );
    }
    assert!(!ready.signaled(), "a refused bundle signals nothing");
}

#[test]
fn stale_generation_only_within_one_agent_identity() {
    let (a, _, _) = agent();
    apply(&a, r#"{"agent_id":"x"}"#, 5).unwrap();
    assert_eq!(
        apply(&a, r#"{"agent_id":"x"}"#, 4),
        Err(BundleError::Apply("stale WAF bundle generation".into()))
    );
    apply(&a, r#"{"agent_id":"x"}"#, 5).unwrap();
    apply(&a, r#"{"agent_id":"y"}"#, 1).unwrap();
    apply(&a, r#"{"agent_id":"y"}"#, 0).unwrap();
}

#[test]
fn proxy_refusal_publishes_nothing() {
    let (a, proxy, ready) = agent();
    *proxy.fail.lock().unwrap() = Some("failed to bind WAF route listener".into());
    assert_eq!(
        apply(&a, &format!(r#"{{"apps":[{APP}]}}"#), 2),
        Err(BundleError::Apply(
            "failed to bind WAF route listener".into()
        ))
    );
    assert!(a.app_executor("a1").is_none());
    assert_eq!(a.generation().0, 0);
    assert!(!ready.signaled());
}

#[test]
fn stores_survive_reloads_and_unblock_reaches_every_store() {
    let (a, _, _) = agent();
    let two = format!(
        r#"{{"apps":[{APP},{{"app_id":"a2","upstream":"http://u","rules_json":{{"request_body_limit":"120K"}}}}]}}"#
    );
    apply(&a, &two, 1).unwrap();
    let s1 = a.stores(Some("a1")).unwrap();
    let e2 = a.app_executor("a2").unwrap();
    assert_eq!(e2.analyze.request_body_limit, 120 << 10, "app rules");
    let shared = a.stores(None).unwrap();
    s1.block.record_block(b"k");
    s1.block
        .set_block_until(b"k", SystemTime::now() + std::time::Duration::from_secs(60));
    shared
        .block
        .set_block_until(b"k", SystemTime::now() + std::time::Duration::from_secs(60));
    apply(&a, &two, 2).unwrap();
    let s1b = a.stores(Some("a1")).unwrap();
    assert!(
        Arc::ptr_eq(&s1.block, &s1b.block),
        "per-app stores carried over"
    );
    assert!(Arc::ptr_eq(&s1.rate, &s1b.rate));
    assert!(s1b.block.block_until(b"k").is_some());
    assert!(
        !Arc::ptr_eq(&s1.block, &a.stores(Some("a2")).unwrap().block),
        "apps never share stores"
    );

    apply(
        &a,
        r#"{"management_only":true,"unblock_entries":[{"type":"blockpolicy","key":"k"}]}"#,
        0,
    )
    .unwrap();
    assert!(s1b.block.block_until(b"k").is_none());
    assert!(shared.block.block_until(b"k").is_none());
    assert_eq!(
        a.generation().0,
        2,
        "management bundles never change the configuration"
    );
}

#[test]
fn empty_app_rules_inherit_the_project_and_challenge_falls_back() {
    let (a, _, _) = agent();
    let json = r#"{"rules_json":{"request_body_limit":"140K","challenge":{"enabled":true}},
        "apps":[{"app_id":"inherit","upstream":"http://u","rules_json":{}},
                {"app_id":"spaced","upstream":"http://u","rules_json":{ }},
                {"app_id":"own","upstream":"http://u","rules_json":{"request_body_limit":"200K"}}]}"#;
    apply(&a, json, 1).unwrap();
    let inherit = a.app_executor("inherit").unwrap();
    assert_eq!(
        inherit.analyze.request_body_limit,
        140 << 10,
        "{{}} inherits the project's rules"
    );
    assert!(inherit.challenge.as_ref().is_some_and(|c| c.enabled));
    let spaced = a.app_executor("spaced").unwrap();
    assert_eq!(
        spaced.analyze.request_body_limit, 0,
        "\"{{ }}\" is no canonical empty: its own executor, no limit set"
    );
    let own = a.app_executor("own").unwrap();
    assert_eq!(own.analyze.request_body_limit, 200 << 10);
    assert!(
        own.challenge.as_ref().is_some_and(|c| c.enabled),
        "no app challenge → the project's enabled one"
    );
}

#[test]
fn custom_rules_decode_and_unusable_regex_rules_drop() {
    let (a, _, _) = agent();
    let json = r#"{"apps":[{"app_id":"a","upstream":"http://u",
        "custom_gui_rules":[{"id":"g1","enabled":true,"action":"block","conditions":[{"field":"uri","operator":"regex","value":"("}]},
                            {"id":"g2","enabled":true,"action":"log","conditions":[{"field":"uri","operator":"contains","value":"x"}]},
                            {"id":5},null],
        "custom_script_rules":[{"id":"s1","script":"waf_block()"}],
        "custom_tuning_rules":[{"id":"t1","enabled":true}]}]}"#;
    apply(&a, json, 1).unwrap();
    let e = a.app_executor("a").unwrap();
    let ids: Vec<&str> = e
        .analyze
        .custom_gui_rules
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec!["g2", ""],
        "bad regex dropped, type error skipped, null kept as a zero rule"
    );
    assert_eq!(e.analyze.custom_script_rules.len(), 1);
    assert_eq!(e.analyze.custom_tuning_rules.len(), 1);
    assert!(crate::gaps::regex_rules_dropped_total() >= 1);
}

#[test]
fn decode_errors_are_not_apply_errors() {
    let (a, _, _) = agent();
    let s = Sink(a);
    assert!(matches!(
        s.apply(b"{\"apps\":{}}", 1),
        Err(BundleError::Decode(_))
    ));
    assert!(s.check(b"not json").is_err());
    assert!(s.apply(b"{}", 7).is_ok());
}

#[test]
fn closed_agent_refuses_bundles() {
    let (a, _, _) = agent();
    a.close();
    assert_eq!(
        apply(&a, "{}", 1),
        Err(BundleError::Apply("agent is shutting down".into()))
    );
}

#[test]
fn rate_limit_unblock_and_login_scope() {
    let (a, _, _) = agent();
    apply(&a, &format!(r#"{{"apps":[{APP}]}}"#), 1).unwrap();
    let s = a.stores(Some("a1")).unwrap();
    for _ in 0..3 {
        s.rate.allow_login(b"login:p:/x", b"1.2.3.4", 2, 60, 600);
    }
    assert!(
        !s.rate.allow_login(b"login:p:/x", b"1.2.3.4", 2, 60, 600),
        "locked out"
    );
    apply(&a, r#"{"management_only":true,"unblock_entries":[{"type":"ratelimit","scope":"login:p:/x","key":"1.2.3.4"}]}"#, 0).unwrap();
    assert!(
        s.rate.allow_login(b"login:p:/x", b"1.2.3.4", 2, 60, 600),
        "unblocked"
    );
}
