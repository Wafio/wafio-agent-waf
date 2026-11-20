use std::sync::Mutex;

use wafio_application::RateLimitStore;
use wafio_application::blocklist::BlockStore;

use super::*;
use crate::executor::startup_executor;
use crate::ready::ReadyActions;
use crate::tls::dir::tests::{Scratch, my_uid};
use crate::tls::tests::make_pem;

/// Records what the proxy would get; fails when told to.
#[derive(Default)]
struct FakeProxy {
    applied: Mutex<Vec<Vec<(String, u16, String)>>>,
    /// The HTTPS site of each app of each apply.
    tls: Mutex<Vec<Vec<Option<wafio_proxy::TlsSite>>>>,
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
        self.tls
            .lock()
            .unwrap()
            .push(apps.iter().map(|a| a.tls.clone()).collect());
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

const SHOP: &str = "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11";
const BLOG: &str = "6f1c0c64-4f7e-4a06-8cf3-0b7c2a6d1e90";
const CERT: &str = "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77";

/// An app entry of a bundle, with a `tls` object when `tls` is given.
fn app_json(id: &str, port: u32, tls: Option<&str>) -> String {
    let tls = tls.map_or(String::new(), |t| format!(r#","tls":{t}"#));
    format!(
        r#"{{"app_id":"{id}","listen_host":"127.0.0.1","listen_port":{port},"upstream":"http://127.0.0.1:9000","mode":"monitor"{tls}}}"#
    )
}

fn bundle_of(apps: &[String]) -> String {
    format!(
        r#"{{"agent_id":"x","project_id":"p1","apps":[{}]}}"#,
        apps.join(",")
    )
}

fn tls_object(host: &str, cert: &str, leaf: &str) -> String {
    format!(
        r#"{{"listen":"0.0.0.0:443","hosts":["{host}"],"source":"uploaded","certificate_id":"{cert}","leaf_sha256":"{leaf}"}}"#
    )
}

/// An agent with a key directory in a scratch directory.
fn agent_with_keys() -> (Arc<Agent>, Arc<FakeProxy>, Scratch) {
    let scratch = Scratch::new();
    let stores = Stores::new();
    let base = startup_executor(&stores, "", None).unwrap();
    let proxy = Arc::new(FakeProxy::default());
    let dir = KeyDir::open(&scratch.dir(), my_uid()).unwrap();
    let a = Agent::new(
        base,
        stores,
        proxy.clone(),
        Arc::new(VerifiedBotChecker::new()),
        Arc::new(Ready::new(ReadyActions::default())),
    )
    .with_key_dir(dir);
    (Arc::new(a), proxy, scratch)
}

#[test]
fn only_an_app_with_a_tls_object_is_served_over_https() {
    let (a, proxy, _dir) = agent_with_keys();
    let other = app_json(BLOG, 18081, None);
    let shop = app_json(
        SHOP,
        18080,
        Some(&tls_object("shop.example.com", CERT, &"ab".repeat(32))),
    );
    apply(&a, &bundle_of(&[shop, other]), 1).unwrap();
    let sites = &proxy.tls.lock().unwrap()[0];
    let site = sites[0].as_ref().unwrap();
    assert_eq!(site.listen, "0.0.0.0:443");
    assert_eq!(site.hosts, ["shop.example.com"]);
    assert!(
        site.certificate.is_none(),
        "its file is not in the directory"
    );
    assert!(sites[1].is_none());
    let apps = a.tls_apps();
    assert_eq!(apps.len(), 1);
    assert_eq!((apps[0].0.as_str(), &apps[0].2), (SHOP, &None));
}

#[test]
fn the_certificate_in_the_key_directory_goes_to_the_proxy_with_its_app() {
    let (a, proxy, dir) = agent_with_keys();
    let (pem, leaf) = make_pem(&dir.0, "shop");
    std::fs::write(dir.dir().join(format!("{CERT}.pem")), &pem).unwrap();
    let shop = app_json(
        SHOP,
        18080,
        Some(&tls_object("shop.example.com", CERT, &leaf)),
    );
    apply(&a, &bundle_of(std::slice::from_ref(&shop)), 1).unwrap();
    let site = proxy.tls.lock().unwrap()[0][0].clone().unwrap();
    let entry = site.certificate.expect("the proxy gets the certificate");
    assert!(!entry.placeholder);
    assert_eq!(
        a.tls_apps()[0].2.as_deref(),
        Some(format!("{CERT}.pem").as_str())
    );

    // The same bundle again reads nothing and hands over the same key.
    std::fs::remove_file(dir.dir().join(format!("{CERT}.pem"))).unwrap();
    apply(&a, &bundle_of(&[shop]), 2).unwrap();
    let again = proxy.tls.lock().unwrap()[1][0].clone().unwrap();
    assert!(Arc::ptr_eq(&entry.key, &again.certificate.unwrap().key));
}

#[test]
fn the_bundle_address_of_an_app_served_over_https_is_not_checked() {
    let (a, proxy, _dir) = agent_with_keys();
    // blog is plain on the address shop's bundle entry names; big names a port that cannot be bound.
    let tls = tls_object("shop.example.com", CERT, &"ab".repeat(32));
    let shop = app_json(SHOP, 18080, Some(&tls));
    let blog = app_json(BLOG, 18080, None);
    let big = app_json(
        "1a2b3c4d-0000-4000-8000-000000000001",
        70000,
        Some(&tls.replace("shop", "big")),
    );
    apply(&a, &bundle_of(&[shop.clone(), blog.clone(), big]), 1).unwrap();
    assert_eq!(proxy.applied.lock().unwrap()[0].len(), 3);

    // The same entries without a tls object are still refused.
    let (plain, _, _) = agent();
    let plain_shop = app_json(SHOP, 18080, None);
    assert_eq!(
        apply(&plain, &bundle_of(&[plain_shop, blog]), 1),
        Err(BundleError::Apply(
            "duplicate listener in WAF bundle".into()
        ))
    );
    assert_eq!(
        apply(&plain, &bundle_of(&[app_json(SHOP, 70000, None)]), 1),
        Err(BundleError::Apply(
            "failed to bind WAF route listener".into()
        ))
    );
}

#[test]
fn an_entry_that_fails_a_check_refuses_the_whole_bundle_and_the_previous_one_serves_on() {
    let (a, proxy, _dir) = agent_with_keys();
    let good = tls_object("shop.example.com", CERT, &"ab".repeat(32));
    let shop = app_json(SHOP, 18080, Some(&good));
    apply(&a, &bundle_of(std::slice::from_ref(&shop)), 1).unwrap();

    let lines = Arc::new(Mutex::new(Vec::new()));
    let bad = app_json(
        BLOG,
        18081,
        Some(&good.replace("shop.example.com", "*.example.com")),
    );
    let refused = tracing::subscriber::with_default(Collect(lines.clone()), || {
        apply(&a, &bundle_of(&[shop.clone(), bad]), 2)
    });
    assert_eq!(
        refused,
        Err(BundleError::Apply("invalid TLS site settings".into()))
    );
    assert_eq!(
        proxy.applied.lock().unwrap().len(),
        1,
        "the proxy was not asked"
    );
    assert_eq!(a.generation().0, 1);
    assert_eq!(a.app_ids(), [SHOP]);
    let lines = lines.lock().unwrap().join("\n");
    assert!(lines.contains(BLOG) && lines.contains("hosts"), "{lines}");

    // An app id that is no UUID cannot name files either.
    let named = app_json("shop", 18082, Some(&good));
    assert_eq!(
        apply(&a, &bundle_of(&[shop, named]), 3),
        Err(BundleError::Apply("invalid TLS site settings".into()))
    );
}

#[test]
fn without_a_key_directory_the_tls_object_is_not_read() {
    let (a, proxy, _) = agent();
    let broken = app_json(SHOP, 18080, Some(r#"{"hosts":["*"],"listen":"x"}"#));
    apply(&a, &bundle_of(&[broken]), 1).unwrap();
    assert!(
        proxy.tls.lock().unwrap()[0][0].is_none(),
        "served as its bundle says"
    );
    assert!(a.tls_apps().is_empty());
}

#[test]
fn the_apply_lock_keeps_a_bundle_out_between_a_check_and_its_commit() {
    let (a, _proxy, _dir) = agent_with_keys();
    let tls = tls_object("shop.example.com", CERT, &"ab".repeat(32));
    apply(&a, &bundle_of(&[app_json(SHOP, 18080, Some(&tls))]), 1).unwrap();

    let lock = a.apply_lock();
    // The check of an install: the app and its settings in the bundle in force.
    let checked = lock
        .settings(SHOP)
        .cloned()
        .expect("the bundle names the app");
    assert!(lock.settings(BLOG).is_none());

    // A bundle that takes the app out waits for the lock.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let applier = {
        let a = a.clone();
        std::thread::spawn(move || {
            let r = apply(&a, &bundle_of(&[app_json(BLOG, 18081, None)]), 2);
            done_tx.send(()).unwrap();
            r
        })
    };
    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "the bundle applied while a check was waiting for its commit"
    );
    // The commit: what the check saw is still what the bundle in force says.
    let committed = lock.settings(SHOP).cloned();
    assert_eq!(committed, Some(checked));
    drop(lock);

    applier.join().unwrap().unwrap();
    assert!(
        a.apply_lock().settings(SHOP).is_none(),
        "the app left with the bundle"
    );
    assert_eq!(a.generation().0, 2);
}

#[test]
fn a_refusal_for_an_address_that_cannot_be_bound_is_told_apart() {
    let (a, proxy, _dir) = agent_with_keys();
    *proxy.fail.lock().unwrap() = Some(wafio_proxy::listeners::BIND_ERROR.into());
    assert_eq!(
        apply(&a, &bundle_of(&[app_json(SHOP, 18080, None)]), 1),
        Err(BundleError::Bind(wafio_proxy::listeners::BIND_ERROR.into()))
    );
    *proxy.fail.lock().unwrap() = Some("duplicate listener in WAF bundle".into());
    assert_eq!(
        apply(&a, &bundle_of(&[app_json(SHOP, 18080, None)]), 1),
        Err(BundleError::Apply(
            "duplicate listener in WAF bundle".into()
        ))
    );
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
    *proxy.fail.lock().unwrap() = Some("invalid app route in WAF bundle".into());
    assert_eq!(
        apply(&a, &format!(r#"{{"apps":[{APP}]}}"#), 2),
        Err(BundleError::Apply("invalid app route in WAF bundle".into()))
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

#[test]
fn every_install_is_answered_not_in_bundle_while_the_agent_keeps_no_certificates() {
    let mut install = CertificateInstall::default();
    assert_eq!(
        Certificates.install(&mut install),
        Err(AckCode::NotInBundle)
    );
}
