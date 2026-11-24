use std::sync::Mutex;

use wafio_application::RateLimitStore;
use wafio_application::blocklist::BlockStore;
use wafio_control::CertificateStatus;

use super::*;
use crate::executor::startup_executor;
use crate::ready::ReadyActions;
use crate::tls::dir::tests::{Scratch, my_uid};
use crate::tls::install::tests::{Made, fixture};
use crate::tls::pacer::{Offer, Offers, Statuses};
use crate::tls::status::{REFUSED_SETTINGS, unix_now};
use crate::tls::tests::make_pem;
use std::time::Duration;

/// Records what the proxy would get; fails when told to.
#[derive(Default)]
struct FakeProxy {
    applied: Mutex<Vec<Vec<(String, u16, String)>>>,
    /// The HTTPS site of each app of each apply.
    tls: Mutex<Vec<Vec<Option<wafio_proxy::TlsSite>>>>,
    /// The compression of each app of each apply.
    compression: Mutex<Vec<Vec<Option<CompressionSpec>>>>,
    /// What the proxy counts, by app.
    counted: Mutex<HashMap<String, CompressionCounters>>,
    fail: Mutex<Option<String>>,
    /// What an apply that fails with `BIND_ERROR` says it could not bind.
    unbound: Mutex<Option<(String, std::io::ErrorKind)>>,
    book: Arc<CertBook>,
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
        self.compression
            .lock()
            .unwrap()
            .push(apps.iter().map(|a| a.compression).collect());
        // The book follows the bundle, as the proxy's does.
        self.book.follow(
            apps.iter()
                .filter_map(|a| Some((a.app_id.clone(), a.tls.as_ref()?.certificate.clone())))
                .collect(),
        );
        Ok(())
    }

    fn certificates(&self) -> Arc<CertBook> {
        self.book.clone()
    }

    fn bind_failure(&self) -> Option<(String, std::io::ErrorKind)> {
        self.unbound.lock().unwrap().clone()
    }

    fn compression_counters(&self, app_id: &str) -> Option<CompressionCounters> {
        self.counted.lock().unwrap().get(app_id).copied()
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
        matches!(site.certificate, BookChange::Clear),
        "its file is not in the directory, so the app holds nothing"
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
    let BookChange::Set(entry) = site.certificate else {
        panic!("the proxy gets the certificate");
    };
    assert!(!entry.placeholder);
    assert_eq!(
        a.tls_apps()[0].2.as_deref(),
        Some(format!("{CERT}.pem").as_str())
    );

    // The same bundle again reads nothing and hands over the same key.
    std::fs::remove_file(dir.dir().join(format!("{CERT}.pem"))).unwrap();
    apply(&a, &bundle_of(&[shop]), 2).unwrap();
    let again = proxy.tls.lock().unwrap()[1][0].clone().unwrap();
    let BookChange::Set(again) = again.certificate else {
        panic!("the proxy gets the certificate again");
    };
    assert!(Arc::ptr_eq(&entry.key, &again.key));
}

#[test]
fn an_app_whose_bundle_names_no_certificate_any_more_has_the_one_it_had_cleared_in_the_proxy() {
    let (a, proxy, dir) = agent_with_keys();
    let (pem, leaf) = make_pem(&dir.0, "shop");
    let file = dir.dir().join(format!("{CERT}.pem"));
    std::fs::write(&file, &pem).unwrap();
    let with = |tls: String| bundle_of(&[app_json(SHOP, 18080, Some(&tls))]);
    apply(&a, &with(tls_object("shop.example.com", CERT, &leaf)), 1).unwrap();
    assert_eq!(
        a.tls_apps()[0].2.as_deref(),
        Some(format!("{CERT}.pem").as_str())
    );

    // Uploaded with no certificate named, source empty, a source this agent does not know.
    let none = [
        r#"{"hosts":["shop.example.com"],"source":"uploaded"}"#,
        r#"{"hosts":["shop.example.com"],"source":""}"#,
        r#"{"hosts":["shop.example.com"],"source":"mystery"}"#,
    ];
    for (n, tls) in none.iter().enumerate() {
        let generation = 2 + n as i64;
        std::fs::write(&file, &pem).unwrap();
        apply(
            &a,
            &with(tls_object("shop.example.com", CERT, &leaf)),
            generation * 10,
        )
        .unwrap();
        apply(&a, &with((*tls).to_owned()), generation * 10 + 1).unwrap();
        let sent = proxy.tls.lock().unwrap();
        let site = sent.last().unwrap()[0].as_ref().unwrap();
        assert!(matches!(site.certificate, BookChange::Clear), "{tls}");
        assert_eq!(a.tls_apps()[0].2, None, "{tls}");
        assert!(!file.exists(), "its file goes with it: {tls}");
    }
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

    let bad = app_json(
        BLOG,
        18081,
        Some(&good.replace("shop.example.com", "*.example.com")),
    );
    let (refused, lines) = logged(|| apply(&a, &bundle_of(&[shop.clone(), bad]), 2));
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
    let ((), lines) = logged(|| apply(&a, &bundle_of(&[broken]), 1).unwrap());
    assert!(
        lines.contains("1 app(s) are ignored") && lines.contains("plain HTTP"),
        "{lines}"
    );
    assert!(
        proxy.tls.lock().unwrap()[0][0].is_none(),
        "served as its bundle says"
    );
    assert!(a.tls_apps().is_empty());
}

#[test]
fn a_process_that_is_closing_does_not_take_the_key_directory_lock() {
    let (a, _proxy, dir) = agent_with_keys();
    assert!(a.holds_keys() && !a.waits_for_keys());
    // Another process holds the lock, as the one this replaces does.
    a.release_keys();
    let mut other = KeyDir::open(&dir.dir(), my_uid()).unwrap();
    assert!(other.holds_lock());
    assert!(a.waits_for_keys() && !a.take_over_keys());

    other.release_lock();
    a.close();
    assert!(a.take_over_keys(), "nothing is left to wait for");
    assert!(!a.holds_keys(), "but the lock stays free for the successor");
    assert!(other.try_lock());
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

/// Everything the process logs at `info` and above while the tests run, which `capture_logs`
/// starts to keep.
static LOG: Mutex<String> = Mutex::new(String::new());

/// Texts that make the next log line holding one of them panic, once for each. It stands for an
/// error in the middle of the code that logs, which a test cannot cause any other way.
static PANIC_AT: Mutex<Vec<String>> = Mutex::new(Vec::new());

thread_local! {
    /// What this thread logs, at every level, while `logged` runs.
    static MINE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// The one subscriber of the test process. A subscriber set for a scope only would race with
/// tracing's cache of which log sites are enabled: a site that another thread registers at that
/// moment can stay cached as disabled, and the scope then sees no line from it.
struct Capture;

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mine = MINE.try_with(|m| m.borrow().is_some()).unwrap_or(false);
        let shared = *event.metadata().level() <= tracing::Level::INFO;
        if !mine && !shared {
            return;
        }
        struct Text(String);
        impl tracing::field::Visit for Text {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?} ", field.name()));
            }
        }
        let mut text = Text(String::new());
        event.record(&mut text);
        if mine {
            let _ = MINE.try_with(|m| {
                if let Some(lines) = m.borrow_mut().as_mut() {
                    lines.push_str(&text.0);
                    lines.push('\n');
                }
            });
        }
        if !shared {
            return;
        }
        LOG.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_str(&format!("{}\n", text.0));
        let hit = {
            let mut at = PANIC_AT.lock().unwrap_or_else(|e| e.into_inner());
            at.iter()
                .position(|needle| text.0.contains(needle.as_str()))
                .map(|i| at.remove(i))
        };
        if let Some(needle) = hit {
            panic!("a log line with {needle:?}");
        }
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Sets [`Capture`] for the whole process, once, and makes every log site that was registered
/// before it enabled again.
fn capture_logs() {
    static SET: std::sync::Once = std::sync::Once::new();
    SET.call_once(|| {
        let _ = tracing::subscriber::set_global_default(Capture);
    });
    tracing::callsite::rebuild_interest_cache();
}

/// Runs `f` and returns what this thread logged meanwhile, every level, one line per event.
fn logged<R>(f: impl FnOnce() -> R) -> (R, String) {
    capture_logs();
    MINE.with(|m| *m.borrow_mut() = Some(String::new()));
    let out = f();
    let lines = MINE.with(|m| m.borrow_mut().take()).unwrap_or_default();
    (out, lines)
}

#[test]
fn a_default_bundle_logs_no_line_about_a_missing_engine() {
    let (a, _, _) = agent();
    let ((), lines) = logged(|| {
        apply(
            &a,
            &format!(r#"{{"agent_id":"x","project_id":"p1","apps":[{APP}]}}"#),
            1,
        )
        .unwrap()
    });
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

const ACME_APP: &str = "1a2b3c4d-0000-4000-8000-000000000002";
const BARE_APP: &str = "1a2b3c4d-0000-4000-8000-000000000003";
const NO_CERT_APP: &str = "1a2b3c4d-0000-4000-8000-000000000004";

/// An agent with a key directory and the statuses it offers, which the test reads.
fn agent_with_statuses() -> (Arc<Agent>, Arc<FakeProxy>, Scratch, Offers) {
    let scratch = Scratch::new();
    let stores = Stores::new();
    let base = startup_executor(&stores, "", None).unwrap();
    let proxy = Arc::new(FakeProxy::default());
    let (statuses, offers) = Statuses::channel();
    let a = Agent::new(
        base,
        stores,
        proxy.clone(),
        Arc::new(VerifiedBotChecker::new()),
        Arc::new(Ready::new(ReadyActions::default())),
    )
    .with_statuses(statuses)
    .with_key_dir(KeyDir::open(&scratch.dir(), my_uid()).unwrap());
    (Arc::new(a), proxy, scratch, offers)
}

fn install_of(made: &Made, app: &str, cert: &str) -> CertificateInstall {
    CertificateInstall {
        command_id: "c1".into(),
        app_id: app.into(),
        certificate_id: cert.into(),
        chain_pem: made.cert.clone(),
        key_pem: made.key.clone(),
        leaf_sha256: made.leaf.clone(),
    }
}

/// The offer a call made, which must be the only one.
fn only(offers: &mut Offers) -> Offer {
    let mut all = offers.drain();
    assert_eq!(all.len(), 1, "one offer");
    all.remove(0)
}

fn summary(statuses: &[CertificateStatus]) -> Vec<(String, String, String)> {
    statuses
        .iter()
        .map(|s| (s.app_id.clone(), s.source.clone(), s.state.clone()))
        .collect()
}

fn states(offer: &Offer) -> Vec<(String, String, String)> {
    summary(&offer.statuses)
}

#[test]
fn an_uploaded_certificate_is_installed_served_from_the_next_handshake_and_reported_active() {
    let (a, proxy, dir, mut offers) = agent_with_statuses();
    let f = fixture();
    let shop = app_json(
        SHOP,
        18080,
        Some(&tls_object("shop.example.com", CERT, &f.ec.leaf)),
    );
    apply(&a, &bundle_of(std::slice::from_ref(&shop)), 1).unwrap();

    // The bundle names a certificate the agent does not hold: it asks for it.
    a.report_bundle();
    let first = only(&mut offers);
    assert!(first.forced && first.whole);
    assert_eq!(
        states(&first),
        [(SHOP.into(), "uploaded".into(), "missing".into())]
    );
    let missing = &first.statuses[0];
    assert_eq!(missing.certificate_id, CERT);
    assert!(missing.chain_pem.is_empty() && missing.leaf_sha256.is_empty());
    assert_eq!((missing.error.as_str(), missing.next_attempt_unix), ("", 0));
    assert!(proxy.certificates().get(SHOP).is_none());

    let mut install = install_of(&f.ec, SHOP, CERT);
    assert_eq!(Certificates(a.clone()).install(&mut install), Ok(()));
    let held = proxy.certificates().get(SHOP).expect("the book serves it");
    assert_eq!(wafio_proxy::cert_store::leaf_sha256(&held.key), f.ec.leaf);
    assert!(dir.dir().join(format!("{CERT}.pem")).exists());

    // `active` with the chain as DER gives it, and with the certificate named.
    let second = only(&mut offers);
    assert!(!second.forced && !second.whole);
    let active = &second.statuses[0];
    assert_eq!(
        (active.state.as_str(), active.certificate_id.as_str()),
        ("active", CERT)
    );
    assert_eq!(active.leaf_sha256, f.ec.leaf);
    assert_eq!(active.chain_pem, f.ec.cert);
    assert_eq!(active.request_id, "");

    // The next bundle that names it hands the proxy the key that is in the book, and reports it.
    apply(&a, &bundle_of(&[shop]), 2).unwrap();
    let site = proxy.tls.lock().unwrap().last().unwrap()[0]
        .clone()
        .unwrap();
    let BookChange::Set(entry) = site.certificate else {
        panic!("the proxy gets the certificate");
    };
    assert!(Arc::ptr_eq(&entry.key, &held.key));
    a.report_bundle();
    assert_eq!(
        states(&only(&mut offers)),
        [(SHOP.into(), "uploaded".into(), "active".into())]
    );
}

#[test]
fn an_install_for_what_the_bundle_does_not_name_is_not_in_bundle_and_nothing_is_kept() {
    let (a, proxy, dir, mut offers) = agent_with_statuses();
    let f = fixture();
    let tls = tls_object("shop.example.com", CERT, &f.ec.leaf);
    apply(&a, &bundle_of(&[app_json(SHOP, 18080, Some(&tls))]), 1).unwrap();
    let sink = Certificates(a.clone());
    for (what, mut install) in [
        (
            "an app that is not in the bundle",
            install_of(&f.ec, BLOG, CERT),
        ),
        (
            "a certificate id the bundle does not name",
            install_of(&f.ec, SHOP, ORPHAN),
        ),
        (
            "a leaf the bundle does not name",
            install_of(&f.rsa, SHOP, CERT),
        ),
    ] {
        assert_eq!(
            sink.install(&mut install),
            Err(AckCode::NotInBundle),
            "{what}"
        );
    }
    assert!(offers.drain().is_empty(), "a refusal reports nothing");
    assert!(proxy.certificates().get(SHOP).is_none());
    assert!(!dir.dir().join(format!("{CERT}.pem")).exists());

    // An app that was in the bundle and left it.
    apply(&a, &bundle_of(&[app_json(BLOG, 18081, None)]), 2).unwrap();
    let mut install = install_of(&f.ec, SHOP, CERT);
    assert_eq!(sink.install(&mut install), Err(AckCode::NotInBundle));
    assert!(proxy.certificates().get(SHOP).is_none());

    // An agent with no key directory takes no certificate either.
    let (plain, _, _) = agent();
    let mut install = install_of(&f.ec, SHOP, CERT);
    assert_eq!(
        Certificates(plain).install(&mut install),
        Err(AckCode::NotInBundle)
    );
}

const ORPHAN: &str = "7e1f3a90-2c1d-4b8e-9a55-1d3c4f6a8b02";

#[test]
fn only_an_app_with_a_certificate_to_report_gets_a_status_after_a_bundle() {
    let (a, _proxy, _dir, mut offers) = agent_with_statuses();
    let f = fixture();
    let listen =
        |port: u16| format!(r#""listen":"0.0.0.0:{port}","hosts":["h{port}.example.com"]"#);
    let shop = app_json(
        SHOP,
        18080,
        Some(&tls_object("shop.example.com", CERT, &f.ec.leaf)),
    );
    let acme = app_json(
        ACME_APP,
        18081,
        Some(&format!(
            "{{{},\"source\":\"acme\",\"acme_request_id\":\"r1\"}}",
            listen(444)
        )),
    );
    let empty = app_json(
        BARE_APP,
        18082,
        Some(&format!("{{{},\"source\":\"\"}}", listen(445))),
    );
    let none = app_json(
        NO_CERT_APP,
        18083,
        Some(&format!("{{{},\"source\":\"uploaded\"}}", listen(446))),
    );
    let plain = app_json(BLOG, 18084, None);
    apply(&a, &bundle_of(&[shop, acme, empty, none, plain]), 1).unwrap();
    a.report_bundle();
    let offer = only(&mut offers);
    assert!(offer.forced && offer.whole);
    assert_eq!(
        states(&offer),
        [
            (SHOP.into(), "uploaded".into(), "missing".into()),
            (ACME_APP.into(), "acme".into(), "pending".into())
        ],
        "no status for source empty, for uploaded without a certificate, or for an app without a tls entry; an ordered certificate reports through its order, pending before the first"
    );
}

#[test]
fn a_bundle_refused_for_its_tls_settings_gives_each_gateway_app_in_it_failed_with_a_fixed_phrase() {
    let (a, _proxy, _dir, mut offers) = agent_with_statuses();
    let f = fixture();
    let tls = tls_object("shop.example.com", CERT, &f.ec.leaf);
    let shop = app_json(SHOP, 18080, Some(&tls));
    apply(&a, &bundle_of(std::slice::from_ref(&shop)), 1).unwrap();
    assert_eq!(
        a.install_certificate(&install_of(&f.ec, SHOP, CERT)),
        Ok(())
    );
    offers.drain();

    let bad = r#"{"listen":"0.0.0.0:443","hosts":["*.example.com"],"source":"uploaded","certificate_id":"7e1f3a90-2c1d-4b8e-9a55-1d3c4f6a8b02","leaf_sha256":"abababababababababababababababababababababababababababababababab"}"#;
    let acme = r#"{"listen":"0.0.0.0:444","hosts":["acme.example.com"],"source":"acme","acme_request_id":"r1"}"#;
    let empty = r#"{"listen":"0.0.0.0:445","hosts":["bare.example.com"],"source":""}"#;
    let refused = apply(
        &a,
        &bundle_of(&[
            shop.clone(),
            app_json(BLOG, 18081, Some(bad)),
            app_json(ACME_APP, 18082, Some(acme)),
            app_json(BARE_APP, 18083, Some(empty)),
            app_json(NO_CERT_APP, 18084, None),
        ]),
        2,
    );
    assert_eq!(
        refused,
        Err(BundleError::Apply("invalid TLS site settings".into()))
    );
    a.report_bundle();
    let offer = only(&mut offers);
    assert!(
        offer.forced && !offer.whole,
        "the apps that are not named keep what they have"
    );
    assert_eq!(
        states(&offer),
        [
            (SHOP.into(), "uploaded".into(), "failed".into()),
            (BLOG.into(), "uploaded".into(), "failed".into()),
        ],
        "an ordered certificate reports through its order, and a `failed` here would stay on it"
    );
    for s in &offer.statuses {
        assert_eq!(s.error, REFUSED_SETTINGS);
        assert_eq!(
            s.next_attempt_unix, 0,
            "a retry of the same bundle fails the same check"
        );
    }
    let [shop_status, blog_status] = &offer.statuses[..] else {
        panic!("two statuses");
    };
    // The uploaded one names its certificate the bundle carries.
    assert_eq!(blog_status.certificate_id, ORPHAN);
    // The certificate an app is served meanwhile stays described.
    assert_eq!(shop_status.leaf_sha256, f.ec.leaf);
    assert_eq!(shop_status.chain_pem, f.ec.cert);
    assert!(blog_status.chain_pem.is_empty());
    // The bundle in force is what the apps go back to.
    assert_eq!(
        summary(&offer.in_force),
        [(SHOP.into(), "uploaded".into(), "active".into())]
    );
}

#[test]
fn a_refused_bundle_is_answered_for_the_ordered_apps_in_force_with_the_state_of_their_order() {
    let (a, _proxy, _dir, mut offers) = agent_with_statuses();
    let acme = r#"{"listen":"0.0.0.0:444","hosts":["acme.example.com"],"source":"acme","acme_request_id":"r1"}"#;
    let ordered = app_json(ACME_APP, 18081, Some(acme));
    apply(&a, &bundle_of(std::slice::from_ref(&ordered)), 1).unwrap();
    a.report_bundle();
    offers.drain();

    let bad = r#"{"listen":"0.0.0.0:443","hosts":["*.example.com"],"source":"uploaded","certificate_id":"7e1f3a90-2c1d-4b8e-9a55-1d3c4f6a8b02","leaf_sha256":"abababababababababababababababababababababababababababababababab"}"#;
    let refused = apply(
        &a,
        &bundle_of(&[ordered, app_json(BLOG, 18082, Some(bad))]),
        2,
    );
    assert!(refused.is_err());
    a.report_bundle();
    let offer = only(&mut offers);
    assert!(offer.forced && !offer.whole);
    let mut told = states(&offer);
    told.sort();
    assert_eq!(
        told,
        [
            (ACME_APP.into(), "acme".into(), "pending".into()),
            (BLOG.into(), "uploaded".into(), "failed".into()),
        ],
        "the ordered app of the bundle in force hears its state, like after any live bundle"
    );
    assert_eq!(
        summary(&offer.in_force),
        [(ACME_APP.into(), "acme".into(), "pending".into())]
    );
}

#[test]
fn a_refused_bundle_answers_an_ordered_app_only_while_it_orders_it_as_the_bundle_in_force() {
    let (a, proxy, _dir, mut offers) = agent_with_statuses();
    let acme = |port: u16, host: &str, id: &str| {
        format!(
            r#"{{"listen":"127.0.0.1:{port}","hosts":["{host}"],"source":"acme","acme_request_id":"{id}"}}"#
        )
    };
    let in_force = [
        app_json(
            ACME_APP,
            18081,
            Some(&acme(18444, "acme.example.com", "r1")),
        ),
        app_json(SHOP, 18083, Some(&acme(18445, "shop.example.com", "r1"))),
    ];
    apply(&a, &bundle_of(&in_force), 1).unwrap();
    a.report_bundle();
    offers.drain();

    // The refused bundle switches one ordered app to an upload and asks the other for a new
    // certificate: the control plane holds neither the old source nor the old id for them now.
    let upload = tls_object("acme.example.com", CERT, &"ab".repeat(32));
    *proxy.fail.lock().unwrap() = Some(wafio_proxy::listeners::BIND_ERROR.into());
    *proxy.unbound.lock().unwrap() = Some(("0.0.0.0:443".into(), std::io::ErrorKind::AddrInUse));
    let refused = apply(
        &a,
        &bundle_of(&[
            app_json(ACME_APP, 18081, Some(&upload)),
            app_json(SHOP, 18083, Some(&acme(18445, "shop.example.com", "r2"))),
        ]),
        2,
    );
    assert_eq!(
        refused,
        Err(BundleError::Bind(wafio_proxy::listeners::BIND_ERROR.into()))
    );
    a.report_bundle();
    let offer = only(&mut offers);
    assert_eq!(
        states(&offer),
        [(ACME_APP.into(), "uploaded".into(), "failed".into())],
        "one status for the switched app, the refusal; none under an id the control plane dropped"
    );
    assert_eq!(
        offer.statuses[0].error,
        "cannot listen on 0.0.0.0:443: address in use"
    );
}

#[test]
fn a_bundle_refused_for_an_address_it_cannot_bind_says_which_and_why_for_an_https_address_only() {
    let (a, proxy, _dir, mut offers) = agent_with_statuses();
    let f = fixture();
    let tls = |listen: &str, redirect: &str| {
        format!(
            r#"{{"listen":"{listen}","hosts":["shop.example.com"],"redirect_listen":"{redirect}","source":"uploaded","certificate_id":"{CERT}","leaf_sha256":"{}"}}"#,
            f.ec.leaf
        )
    };
    let acme = r#"{"listen":"127.0.0.1:18444","hosts":["acme.example.com"],"source":"acme","acme_request_id":"r1"}"#;
    let bundle = |listen: &str, redirect: &str| {
        bundle_of(&[
            app_json(SHOP, 18080, Some(&tls(listen, redirect))),
            app_json(ACME_APP, 18081, Some(acme)),
            app_json(BLOG, 18082, None),
        ])
    };
    let fail = |address: &str| {
        *proxy.fail.lock().unwrap() = Some(wafio_proxy::listeners::BIND_ERROR.into());
        *proxy.unbound.lock().unwrap() = Some((address.into(), std::io::ErrorKind::AddrInUse));
    };

    // The HTTPS address, and then the redirect address: every gateway app of the bundle fails.
    for address in ["127.0.0.1:18443", "127.0.0.1:18080"] {
        fail(address);
        let got = apply(&a, &bundle("127.0.0.1:18443", "127.0.0.1:18080"), 1);
        assert_eq!(
            got,
            Err(BundleError::Bind(wafio_proxy::listeners::BIND_ERROR.into()))
        );
        a.report_bundle();
        let offer = only(&mut offers);
        assert!(offer.forced && !offer.whole);
        assert!(offer.in_force.is_empty(), "no bundle is in force yet");
        assert_eq!(
            states(&offer),
            [(SHOP.into(), "uploaded".into(), "failed".into())]
        );
        for s in &offer.statuses {
            assert_eq!(
                s.error,
                format!("cannot listen on {address}: address in use")
            );
            // The bundle is tried again after the longest wait of a retry, for as long as it takes.
            let retry = unix_now() + i64::try_from(WAF_BUNDLE_RETRY_MAX.as_secs()).unwrap();
            assert!(
                (retry - 10..=retry).contains(&s.next_attempt_unix),
                "{} for {retry}",
                s.next_attempt_unix
            );
        }
    }

    // An address of a plain app that cannot be bound is none of the HTTPS settings: the apps
    // keep reporting the state they are in.
    fail("127.0.0.1:18082");
    assert!(apply(&a, &bundle("127.0.0.1:18443", "127.0.0.1:18080"), 1).is_err());
    a.report_bundle();
    let offer = only(&mut offers);
    assert!(offer.whole, "nothing was applied, so no app is in force");
    assert!(offer.statuses.is_empty());

    // A refusal that has nothing to do with HTTPS is not reported as a failure of it either.
    *proxy.fail.lock().unwrap() = Some("duplicate listener in WAF bundle".into());
    assert!(apply(&a, &bundle("127.0.0.1:18443", "127.0.0.1:18080"), 1).is_err());
    a.report_bundle();
    assert!(only(&mut offers).statuses.is_empty());

    // The same bundle once the address is free: the state of each app, and the old failure is not
    // reported again.
    *proxy.fail.lock().unwrap() = None;
    apply(&a, &bundle("127.0.0.1:18443", "127.0.0.1:18080"), 1).unwrap();
    a.report_bundle();
    let offer = only(&mut offers);
    assert_eq!(
        states(&offer),
        [
            (SHOP.into(), "uploaded".into(), "missing".into()),
            (ACME_APP.into(), "acme".into(), "pending".into())
        ],
        "an ordered certificate had no `failed` from the refusals: it reports through its order"
    );
    a.report_bundle();
    assert_eq!(states(&only(&mut offers)), states(&offer));
}

/// Runs the pacer on a paused clock beside an agent, so a test can say what the control plane
/// hears and when. The agent is called outside the runtime, as the link calls it from a blocking
/// thread.
struct Clocked {
    rt: tokio::runtime::Runtime,
    origin: tokio::time::Instant,
    heard: Arc<Mutex<Vec<(u64, String, String)>>>,
}

impl Clocked {
    fn start(offers: Offers) -> Clocked {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let origin = rt.block_on(async { tokio::time::Instant::now() });
        let heard = Arc::new(Mutex::new(Vec::new()));
        let log = heard.clone();
        rt.spawn(crate::tls::pacer::run(offers, move |s| {
            log.lock()
                .unwrap()
                .push((origin.elapsed().as_secs(), s.app_id, s.state));
        }));
        Clocked { rt, origin, heard }
    }

    /// Lets the clock run to `secs` after the start, and the pacer with it.
    fn at(&self, secs: u64) {
        let until = self.origin + Duration::from_secs(secs);
        self.rt
            .block_on(async move { tokio::time::sleep_until(until).await });
    }

    /// What the control plane heard of `app`: (seconds since the start, state).
    fn heard(&self, app: &str) -> Vec<(u64, String)> {
        self.heard
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, id, _)| id == app)
            .map(|(at, _, state)| (*at, state.clone()))
            .collect()
    }
}

fn at_state(at: u64, state: &str) -> (u64, String) {
    (at, state.to_owned())
}

#[test]
fn a_bundle_refused_for_a_bind_does_not_end_the_request_for_a_certificate_still_missing() {
    let (a, proxy, _dir, offers) = agent_with_statuses();
    let f = fixture();
    let clock = Clocked::start(offers);
    let shop = app_json(
        SHOP,
        18080,
        Some(&tls_object("shop.example.com", CERT, &f.ec.leaf)),
    );
    // A second gateway app on an address that something else holds.
    let blog = app_json(
        BLOG,
        18081,
        Some(
            &tls_object("blog.example.com", ORPHAN, &f.other_ec.leaf)
                .replace("0.0.0.0:443", "127.0.0.1:18444"),
        ),
    );
    let taken = || {
        *proxy.fail.lock().unwrap() = Some(wafio_proxy::listeners::BIND_ERROR.into());
        *proxy.unbound.lock().unwrap() =
            Some(("127.0.0.1:18444".into(), std::io::ErrorKind::AddrInUse));
    };

    // The bundle in force names a certificate the agent does not hold: it asks for it.
    apply(&a, &bundle_of(std::slice::from_ref(&shop)), 1).unwrap();
    a.report_bundle();
    clock.at(20);
    assert_eq!(clock.heard(SHOP), [at_state(0, "missing")]);

    // A bundle that adds the second app is refused for its address. Each gateway app in it hears
    // `failed`, and the first goes on asking for its certificate a few seconds later: the bundle
    // in force still names it.
    taken();
    assert!(apply(&a, &bundle_of(&[shop.clone(), blog.clone()]), 2).is_err());
    a.report_bundle();
    clock.at(60);
    assert_eq!(
        clock.heard(SHOP),
        [
            at_state(0, "missing"),
            at_state(20, "failed"),
            at_state(30, "missing")
        ]
    );
    assert_eq!(clock.heard(BLOG), [at_state(20, "failed")]);

    // The retry fails the same way a minute later, and the request goes on after each.
    clock.at(80);
    taken();
    assert!(apply(&a, &bundle_of(&[shop, blog]), 2).is_err());
    a.report_bundle();
    clock.at(100);
    assert_eq!(
        clock.heard(SHOP),
        [
            at_state(0, "missing"),
            at_state(20, "failed"),
            at_state(30, "missing"),
            at_state(80, "failed"),
            at_state(90, "missing")
        ]
    );
    assert_eq!(
        clock.heard(BLOG),
        [at_state(20, "failed"), at_state(80, "failed")],
        "the second app is not in the bundle in force, so nothing is asked for"
    );

    // The certificate arrives, which the bundle in force allows: `active`, and no more asking.
    assert_eq!(
        a.install_certificate(&install_of(&f.ec, SHOP, CERT)),
        Ok(())
    );
    clock.at(500);
    let shop_heard = clock.heard(SHOP);
    assert_eq!(shop_heard.last(), Some(&at_state(100, "active")));
    assert_eq!(shop_heard.len(), 6, "{shop_heard:?}");
}

#[test]
fn a_refusal_that_was_not_reported_is_not_reported_for_a_later_bundle_that_cannot_be_read() {
    let (a, proxy, _dir, mut offers) = agent_with_statuses();
    let f = fixture();
    let tls = tls_object("shop.example.com", CERT, &f.ec.leaf);
    let bundle = bundle_of(&[app_json(
        SHOP,
        18443,
        Some(&tls.replace("0.0.0.0:443", "127.0.0.1:18443")),
    )]);

    // A bundle the proxy cannot bind, applied without anyone asking for a report, as the cached
    // bundle of a start is.
    *proxy.fail.lock().unwrap() = Some(wafio_proxy::listeners::BIND_ERROR.into());
    *proxy.unbound.lock().unwrap() =
        Some(("127.0.0.1:18443".into(), std::io::ErrorKind::AddrInUse));
    let sink = Sink(a.clone());
    assert!(sink.apply(bundle.as_bytes(), 1).is_err());

    // A live bundle that does not decode never reaches the agent's apply: the control plane hears
    // the state in force, not the failure of the bundle before it.
    assert!(sink.apply(b"{", 2).is_err());
    a.report_bundle();
    let offer = only(&mut offers);
    assert!(
        offer.whole && offer.statuses.is_empty(),
        "{:?}",
        offer.statuses
    );
}

#[test]
fn an_agent_without_a_key_directory_reports_nothing() {
    let stores = Stores::new();
    let base = startup_executor(&stores, "", None).unwrap();
    let (statuses, mut offers) = Statuses::channel();
    let a = Agent::new(
        base,
        stores,
        Arc::new(FakeProxy::default()),
        Arc::new(VerifiedBotChecker::new()),
        Arc::new(Ready::new(ReadyActions::default())),
    )
    .with_statuses(statuses);
    let tls = tls_object("shop.example.com", CERT, &"ab".repeat(32));
    apply(&a, &bundle_of(&[app_json(SHOP, 18080, Some(&tls))]), 1).unwrap();
    a.report_bundle();
    assert!(offers.drain().is_empty());
}

static GATE: (Mutex<u8>, std::sync::Condvar) = (Mutex::new(0), std::sync::Condvar::new());

/// Reads the key as the agent does, but stops in the middle of the check until the test says go.
fn gated_load(
    der: &rustls::pki_types::PrivateKeyDer<'_>,
) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
    let mut step = GATE.0.lock().unwrap();
    *step = 1;
    GATE.1.notify_all();
    let step = GATE.1.wait_while(step, |s| *s != 2).unwrap();
    drop(step);
    crate::tls::install::load_key(der)
}

#[test]
fn a_bundle_cannot_be_applied_between_the_check_of_an_install_and_its_commit() {
    let (a, proxy, dir) = agent_with_keys();
    let f = fixture();
    let tls = tls_object("shop.example.com", CERT, &f.ec.leaf);
    apply(&a, &bundle_of(&[app_json(SHOP, 18080, Some(&tls))]), 1).unwrap();

    let installer = {
        let a = a.clone();
        let install = install_of(&f.ec, SHOP, CERT);
        std::thread::spawn(move || a.install_certificate_with(&install, gated_load))
    };
    // The install has read the bundle in force and is in the middle of its check.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut step = GATE.0.lock().unwrap();
    while *step != 1 {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(!left.is_zero(), "the install never reached its check");
        step = GATE.1.wait_timeout(step, left).unwrap().0;
    }
    drop(step);

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
        done_rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the bundle applied while an install was between its check and its commit"
    );
    *GATE.0.lock().unwrap() = 2;
    GATE.1.notify_all();

    // The install commits against the bundle it checked, and then the bundle takes the app out:
    // nothing is served for it, and its file goes.
    assert_eq!(installer.join().unwrap(), Ok(()));
    applier.join().unwrap().unwrap();
    assert!(proxy.certificates().get(SHOP).is_none());
    assert!(!dir.dir().join(format!("{CERT}.pem")).exists());
    assert_eq!(a.generation().0, 2);
}

mod edge;
mod orders;
