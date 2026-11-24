//! The edge parts of an app (main host name, path prefix, compression, static files) from the bundle: what goes
//! to the proxy, what the bundle refuses, what the control plane hears of them, and how a cache
//! purge is answered.

use super::*;
use wafio_domain::strip_path_prefix_fault;

const PREFIX: &str = r#""proxy_config":{"strip_path_prefix":"/shop"}"#;

/// An app entry with `extra` members (comma-led JSON) after the usual ones.
fn app_with(id: &str, port: u32, extra: &str) -> String {
    format!(
        r#"{{"app_id":"{id}","listen_host":"127.0.0.1","listen_port":{port},"upstream":"http://127.0.0.1:9000","mode":"monitor"{extra}}}"#
    )
}

fn tls_with_main(canonical: &str) -> String {
    format!(
        r#""tls":{{"listen":"0.0.0.0:443","hosts":["shop.example.com","www.shop.example.com"],"source":"uploaded","certificate_id":"{CERT}","leaf_sha256":"{}","canonical_host":"{canonical}"}}"#,
        "ab".repeat(32)
    )
}

fn features(s: &EdgeStatus) -> Vec<(&str, &str)> {
    s.features
        .iter()
        .map(|f| (f.feature.as_str(), f.state.as_str()))
        .collect()
}

#[test]
fn a_bundle_with_the_edge_parts_on_gives_the_proxy_the_settings_and_the_control_plane_a_status_for_each_app()
 {
    let (a, proxy, _dir) = agent_with_keys();
    let everything = app_with(
        SHOP,
        18080,
        &format!(
            r#",{},{},"compression":{{"enabled":true,"min_bytes":2048}}"#,
            tls_with_main(" WWW.shop.example.com "),
            PREFIX
        ),
    );
    let compress_only = app_with(BLOG, 18081, r#","compression":{"enabled":true}"#);
    let off = app_with("b2", 18082, r#","compression":{}"#);
    let none = app_with("b3", 18083, "");
    apply(&a, &bundle_of(&[everything, compress_only, off, none]), 7).unwrap();

    let sent = proxy.compression.lock().unwrap()[0].clone();
    assert_eq!(
        sent,
        vec![
            Some(CompressionSpec { min_bytes: 2048 }),
            Some(CompressionSpec { min_bytes: 1024 }),
            None,
            None
        ]
    );
    let site = proxy.tls.lock().unwrap()[0][0].clone().unwrap();
    assert_eq!(site.canonical_host.as_deref(), Some("www.shop.example.com"));

    proxy.counted.lock().unwrap().insert(
        BLOG.into(),
        CompressionCounters {
            responses: 5,
            skipped_streamed: 2,
            bytes_saved: 9000,
        },
    );
    let statuses = a.edge_statuses(false);
    let mut ids: Vec<_> = statuses.iter().map(|s| s.app_id.as_str()).collect();
    ids.sort_unstable();
    let mut want = [SHOP, BLOG];
    want.sort_unstable();
    assert_eq!(ids, want, "the refresh leaves an app with no edge part out");
    let by_id = |id: &str| statuses.iter().find(|s| s.app_id == id).unwrap();
    let shop = by_id(SHOP);
    assert_eq!(
        features(shop),
        [("redirects", "applied"), ("compression", "applied")]
    );
    assert_eq!(shop.generation, 7);
    assert!(shop.cache.is_none() && shop.unix_time > 0);
    assert_eq!(
        shop.compression,
        Some(EdgeCompressionCounters::default()),
        "an app that counted nothing yet reports zeros"
    );
    let blog = by_id(BLOG);
    assert_eq!(features(blog), [("compression", "applied")]);
    assert_eq!(
        blog.compression,
        Some(EdgeCompressionCounters {
            responses: 5,
            skipped_streamed: 2,
            bytes_saved: 9000
        })
    );
    for s in &statuses {
        assert!(
            s.features
                .iter()
                .all(|f| f.code.is_empty() && f.detail.is_empty() && !f.running_previous)
        );
    }

    // After a bundle every app is told, those with no part on with nothing in the status.
    let every = a.edge_statuses(true);
    assert_eq!(every.len(), 4);
    for id in ["b2", "b3"] {
        let s = every.iter().find(|s| s.app_id == id).unwrap();
        assert_eq!((s.generation, s.features.is_empty()), (7, true), "{id}");
        assert!(s.cache.is_none() && s.compression.is_none(), "{id}");
        assert!(s.unix_time > 0, "{id}");
    }
}

#[test]
fn a_prefix_alone_is_a_redirects_part_and_an_app_with_no_part_on_is_told_after_a_bundle_only() {
    let (a, _proxy, _ready) = agent();
    assert!(a.edge_statuses(true).is_empty(), "before the first bundle");
    apply(
        &a,
        &bundle_of(&[
            app_with("p1", 18080, &format!(",{PREFIX}")),
            app_with("p2", 18081, ""),
        ]),
        2,
    )
    .unwrap();
    let statuses = a.edge_statuses(false);
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].app_id, "p1");
    assert_eq!(features(&statuses[0]), [("redirects", "applied")]);
    assert!(statuses[0].compression.is_none(), "no compression part");
    let every = a.edge_statuses(true);
    let told: Vec<_> = every
        .iter()
        .map(|s| (s.app_id.as_str(), s.generation, s.features.len()))
        .collect();
    assert_eq!(told, [("p1", 2, 1), ("p2", 2, 0)]);
}

/// The control plane waits for the generation an app runs after a save, so the save that switches
/// the last part off must be answered too: with no features at the new generation.
#[test]
fn switching_the_last_part_off_is_answered_with_a_status_with_no_features_at_the_new_generation() {
    let (a, _proxy, _ready) = agent();
    let on = r#","compression":{"enabled":true}"#;
    apply(&a, &bundle_of(&[app_with("p1", 18080, on)]), 2).unwrap();
    let s = a.edge_statuses(true);
    assert_eq!((s.len(), s[0].generation, s[0].features.len()), (1, 2, 1));
    assert!(s[0].compression.is_some());

    apply(&a, &bundle_of(&[app_with("p1", 18080, "")]), 3).unwrap();
    assert!(
        a.edge_statuses(false).is_empty(),
        "the refresh has nothing to say of an app with no part on"
    );
    let s = a.edge_statuses(true);
    assert_eq!(s.len(), 1);
    assert_eq!((s[0].app_id.as_str(), s[0].generation), ("p1", 3));
    assert!(s[0].features.is_empty(), "no part runs");
    assert!(
        s[0].compression.is_none() && s[0].cache.is_none(),
        "the old numbers are gone"
    );
    assert!(s[0].unix_time > 0);

    // An app that leaves the bundle is not told of.
    apply(&a, &bundle_of(&[app_with("p2", 18081, "")]), 4).unwrap();
    let ids: Vec<_> = a
        .edge_statuses(true)
        .into_iter()
        .map(|s| s.app_id)
        .collect();
    assert_eq!(ids, ["p2"]);
}

#[test]
fn a_bundle_with_a_main_host_that_is_not_one_of_the_hosts_is_refused_and_the_previous_one_serves_on()
 {
    let (a, proxy, _dir) = agent_with_keys();
    let good = app_with(
        SHOP,
        18080,
        &format!(",{}", tls_with_main("shop.example.com")),
    );
    apply(&a, &bundle_of(std::slice::from_ref(&good)), 1).unwrap();

    let bad = app_with(
        SHOP,
        18080,
        &format!(",{}", tls_with_main("other.example.com")),
    );
    assert_eq!(
        apply(&a, &bundle_of(&[bad]), 2),
        Err(BundleError::Apply("invalid TLS site settings".into()))
    );
    assert_eq!(proxy.applied.lock().unwrap().len(), 1);
    assert_eq!(a.generation().0, 1);
    assert_eq!(
        a.edge_statuses(false).len(),
        1,
        "the first bundle's part still runs"
    );
}

#[test]
fn a_prefix_or_a_size_the_proxy_cannot_take_refuses_the_bundle() {
    let (a, proxy, _ready) = agent();
    for extra in [
        r#","proxy_config":{"strip_path_prefix":"/a/../b"}"#,
        r#","proxy_config":{"strip_path_prefix":"shop"}"#,
        r#","proxy_config":{"strip_path_prefix":"/shop/"}"#,
        r#","compression":{"enabled":true,"min_bytes":-1}"#,
        r#","compression":{"enabled":true,"min_bytes":1048577}"#,
    ] {
        assert_eq!(
            apply(&a, &bundle_of(&[app_with("p1", 18080, extra)]), 1),
            Err(BundleError::Apply("invalid app route in WAF bundle".into())),
            "{extra}"
        );
    }
    assert!(proxy.applied.lock().unwrap().is_empty());
    // The edges of the range pass: no size at all, and one megabyte.
    for extra in [
        r#","compression":{"enabled":true,"min_bytes":0}"#,
        r#","compression":{"enabled":true,"min_bytes":1048576}"#,
        r#","compression":{"enabled":false,"min_bytes":-1}"#,
    ] {
        apply(&a, &bundle_of(&[app_with("p1", 18080, extra)]), 2).unwrap();
    }
}

fn purge(scope: &str, url: &str, app: &str) -> CachePurge {
    CachePurge {
        command_id: "c".into(),
        app_id: app.into(),
        scope: scope.into(),
        url: url.into(),
    }
}

#[test]
fn a_purge_is_refused_by_its_scope_and_address_then_by_the_bundle_and_then_for_having_no_cache() {
    let (a, _proxy, _ready) = agent();
    apply(&a, &bundle_of(&[app_with("p1", 18080, "")]), 1).unwrap();

    for (scope, url) in [
        ("", ""),
        ("everything", ""),
        ("URL", "/a"),
        ("app", "/a"),
        ("url", ""),
        ("prefix", ""),
        ("url", "a/b"),
        ("url", "ftp://shop.example.com/a"),
        ("url", "http://"),
        ("prefix", "https://"),
    ] {
        assert_eq!(
            a.purge_cache(&purge(scope, url, "p1")),
            Err(PurgeCode::Invalid),
            "{scope:?} {url:?}"
        );
    }
    // A scope that is fine says what is wrong with the app next.
    for (scope, url) in [
        ("app", ""),
        ("url", "/a?b=1"),
        ("prefix", "/shop"),
        ("url", "http://shop.example.com/a"),
        ("prefix", "https://shop.example.com/a"),
    ] {
        assert_eq!(
            a.purge_cache(&purge(scope, url, "p1")),
            Err(PurgeCode::CacheOff),
            "{scope:?} {url:?}: this build has no cache"
        );
        assert_eq!(
            a.purge_cache(&purge(scope, url, "p9")),
            Err(PurgeCode::NotInBundle),
            "{scope:?} {url:?}"
        );
    }
    // An invalid purge for an app that is not there is invalid first: nothing is looked up.
    assert_eq!(
        a.purge_cache(&purge("sideways", "", "p9")),
        Err(PurgeCode::Invalid)
    );
}

#[test]
fn the_edge_sink_hands_the_agents_answers_to_the_link() {
    let (a, _proxy, _ready) = agent();
    apply(
        &a,
        &bundle_of(&[app_with("p1", 18080, &format!(",{PREFIX}"))]),
        4,
    )
    .unwrap();
    let sink = Edge(a);
    let statuses = sink.statuses(false);
    assert_eq!(
        (
            statuses.len(),
            statuses[0].generation,
            statuses[0].app_id.as_str()
        ),
        (1, 4, "p1")
    );
    assert_eq!(
        sink.purge(&purge("app", "", "p1")),
        Err(PurgeCode::CacheOff)
    );
}

// The case table of the control plane, `delivery-checks.json`. The agent is never stricter than
// the control plane: a case the control plane accepts (no `message`) must pass here, or a bundle
// it sends would be refused whole. The cases it refuses must be refused here too, with one
// exception that the compression test names. The file is a copy kept by `scripts/sync-proto.sh`.

fn delivery_cases(section: &str, at_least: usize) -> Vec<serde_json::Value> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../proxy/tests/data/delivery-checks.json"
    );
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let cases = doc[section].as_array().expect(section).clone();
    assert!(cases.len() >= at_least, "{section}: {} cases", cases.len());
    assert!(
        cases.iter().any(|c| c.get("message").is_some())
            && cases.iter().any(|c| c.get("message").is_none()),
        "{section} holds both cases that pass and cases that are refused"
    );
    cases
}

#[test]
fn the_path_prefix_cases_of_the_control_plane_get_the_same_answer() {
    let (a, _proxy, _ready) = agent();
    for (i, case) in delivery_cases("strip_path_prefix", 20).iter().enumerate() {
        let name = case["name"].as_str().unwrap();
        let prefix = case["in"].as_str().unwrap();
        let refused = case.get("message").is_some();
        assert_eq!(strip_path_prefix_fault(prefix).is_some(), refused, "{name}");

        // The same through a bundle: the route is refused whole, or the bundle goes in.
        let app = serde_json::json!({
            "app_id": "p1", "listen_host": "127.0.0.1", "listen_port": 18080,
            "upstream": "http://127.0.0.1:9000", "mode": "monitor",
            "proxy_config": {"strip_path_prefix": prefix},
        });
        let bundle = format!(r#"{{"apps":[{app}]}}"#);
        let generation = i64::try_from(i).unwrap() + 1;
        assert_eq!(
            apply(&a, &bundle, generation).is_err(),
            refused,
            "{name}: as a bundle"
        );
    }
}

#[test]
fn the_main_host_cases_of_the_control_plane_get_the_same_answer() {
    for case in delivery_cases("canonical_host", 5) {
        let name = case["name"].as_str().unwrap();
        let hosts = case["hosts"].as_array().unwrap();
        let entry = crate::bundle::TlsEntry {
            listen: "0.0.0.0:443".into(),
            hosts: hosts.iter().map(|h| h.as_str().unwrap().into()).collect(),
            source: "uploaded".into(),
            certificate_id: CERT.into(),
            leaf_sha256: "ab".repeat(32),
            canonical_host: case["host"].as_str().unwrap().into(),
            ..Default::default()
        };
        let got = crate::tls::entry::check(SHOP, &entry);
        match case.get("message") {
            Some(_) => assert_eq!(got.err().map(|r| r.field), Some("canonical_host"), "{name}"),
            None => assert!(got.is_ok(), "{name}: {:?}", got.as_ref().err()),
        }
    }
}

/// `min_bytes` through a bundle: `null` is not sent, and the size the agent runs with is the
/// `result` of the case. The one difference: a size out of range is refused by the agent only
/// while compression is on. The control plane checks it while it is off too, so such a bundle is
/// never sent, and the agent has no reason to refuse a bundle for a setting that does nothing.
#[test]
fn the_compression_cases_of_the_control_plane_get_the_same_answer() {
    let (a, proxy, _ready) = agent();
    for (i, case) in delivery_cases("compression", 7).iter().enumerate() {
        let name = case["name"].as_str().unwrap();
        let enabled = case["in"]["enabled"].as_bool().unwrap();
        let size = case["in"]["min_bytes"]
            .as_i64()
            .map(|n| format!(r#","min_bytes":{n}"#))
            .unwrap_or_default();
        let extra = format!(r#","compression":{{"enabled":{enabled}{size}}}"#);
        let generation = i64::try_from(i).unwrap() + 1;
        let got = apply(&a, &bundle_of(&[app_with("p1", 18080, &extra)]), generation);

        if case.get("message").is_some() && enabled {
            assert_eq!(
                got,
                Err(BundleError::Apply("invalid app route in WAF bundle".into())),
                "{name}"
            );
            continue;
        }
        got.unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let running = proxy.compression.lock().unwrap().last().unwrap()[0];
        let want = case["result"]["min_bytes"].as_u64();
        match (enabled, want) {
            (true, Some(min_bytes)) => assert_eq!(
                running,
                Some(CompressionSpec {
                    min_bytes: usize::try_from(min_bytes).unwrap()
                }),
                "{name}"
            ),
            (false, _) => assert_eq!(running, None, "{name}: off"),
            (true, None) => panic!("{name}: a case that passes has a result"),
        }
    }
}

// Static files.

/// A folder made for a test, removed at the end of it.
struct Folder(std::path::PathBuf);

impl Folder {
    fn new(tag: &str) -> Folder {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "wafio-agent-static-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Folder(dir.canonicalize().unwrap())
    }

    fn path(&self) -> String {
        self.0.to_str().unwrap().to_owned()
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn files_part(root: &str, missing: &str, max_age_s: i64) -> String {
    format!(
        r#","static_files":{{"enabled":true,"root":{},"missing":"{missing}","max_age_s":{max_age_s}}}"#,
        serde_json::json!(root)
    )
}

/// The `static_files` feature of an app's status: state, code, detail, `running_previous`.
fn static_feature(s: &EdgeStatus) -> Option<(String, String, String, bool)> {
    s.features
        .iter()
        .find(|f| f.feature == "static_files")
        .map(|f| {
            (
                f.state.clone(),
                f.code.clone(),
                f.detail.clone(),
                f.running_previous,
            )
        })
}

fn running_folder(proxy: &FakeProxy) -> Option<String> {
    proxy.static_files.lock().unwrap().last().unwrap()[0]
        .as_ref()
        .map(|spec| spec.root().to_owned())
}

#[test]
fn a_bundle_with_a_folder_gives_the_proxy_its_folder_and_the_control_plane_an_applied_status() {
    let (a, proxy, _ready) = agent();
    let folder = Folder::new("applied");
    let on = files_part(&folder.path(), "not_found", 3600);
    let both = format!(r#"{on},"compression":{{"enabled":true}}"#);
    apply(
        &a,
        &bundle_of(&[
            app_with("p1", 18080, &on),
            app_with("p2", 18081, &both),
            app_with("p3", 18082, ""),
        ]),
        5,
    )
    .unwrap();
    let sent = proxy.static_files.lock().unwrap()[0].clone();
    assert_eq!(
        sent[0].as_ref().map(|s| s.root()),
        Some(folder.path().as_str())
    );
    assert!(sent[1].is_some() && sent[2].is_none());

    // The refresh names the app that has the part and no other.
    let statuses = a.edge_statuses(false);
    let ids: Vec<_> = statuses.iter().map(|s| s.app_id.as_str()).collect();
    assert_eq!(ids, ["p1", "p2"]);
    let p1 = &statuses[0];
    assert_eq!(features(p1), [("static_files", "applied")]);
    assert_eq!(
        static_feature(p1),
        Some(("applied".into(), String::new(), String::new(), false))
    );
    assert!(
        p1.compression.is_none() && p1.cache.is_none(),
        "no counters for the folder"
    );
    assert_eq!(
        features(&statuses[1]),
        [("compression", "applied"), ("static_files", "applied")]
    );
    assert_eq!(p1.generation, 5);
}

#[test]
fn a_folder_the_agent_cannot_use_leaves_the_bundle_in_and_says_why() {
    let (a, proxy, _ready) = agent();
    let scratch = Folder::new("refused");
    let file = scratch.0.join("a-file");
    std::fs::write(&file, b"x").unwrap();
    for (generation, (root, missing, max_age, code)) in [
        (
            scratch.0.join("nowhere").to_str().unwrap().to_owned(),
            "app",
            0,
            "root_missing",
        ),
        (
            file.to_str().unwrap().to_owned(),
            "app",
            0,
            "root_not_directory",
        ),
        ("/etc".to_owned(), "app", 0, "root_forbidden"),
        (
            "/usr/share/nginx/html".to_owned(),
            "app",
            0,
            "root_forbidden",
        ),
        ("/".to_owned(), "app", 0, "root_forbidden"),
        ("/home/deploy/site".to_owned(), "app", 0, "root_unreadable"),
        ("relative/folder".to_owned(), "app", 0, "invalid"),
        ("/var/www/../etc".to_owned(), "app", 0, "invalid"),
        (scratch.path(), "both", 0, "invalid"),
        (scratch.path(), "app", -1, "invalid"),
        (scratch.path(), "app", 31_536_001, "invalid"),
    ]
    .into_iter()
    .enumerate()
    {
        let generation = i64::try_from(generation).unwrap() + 1;
        apply(
            &a,
            &bundle_of(&[app_with("p1", 18080, &files_part(&root, missing, max_age))]),
            generation,
        )
        .unwrap_or_else(|e| panic!("{root}: the bundle is not refused for a folder: {e:?}"));
        assert_eq!(a.generation().0, generation, "{root}");
        assert_eq!(running_folder(&proxy), None, "{root}: nothing serves");
        let statuses = a.edge_statuses(false);
        assert_eq!(
            statuses.len(),
            1,
            "{root}: the refusal is reported with the refresh too"
        );
        let (state, got, detail, previous) = static_feature(&statuses[0]).unwrap();
        assert_eq!(
            (state.as_str(), got.as_str(), previous),
            ("refused", code, false),
            "{root}"
        );
        assert!(
            detail.len() <= 256 && !detail.chars().any(char::is_control),
            "{root}: {detail}"
        );
    }
    // The detail names the folder.
    apply(
        &a,
        &bundle_of(&[app_with("p1", 18080, &files_part("/etc/wafio", "app", 0))]),
        50,
    )
    .unwrap();
    assert_eq!(
        static_feature(&a.edge_statuses(false)[0]).unwrap().2,
        "/etc/wafio"
    );
}

/// A bundle whose folder the agent refuses keeps the folder the app already has, and says so; a
/// bundle without the part turns it off for good.
#[test]
fn a_refused_folder_keeps_the_folder_that_ran_before_and_switching_it_off_ends_that() {
    let (a, proxy, _ready) = agent();
    let good = Folder::new("kept");
    let gone = Folder::new("gone");
    apply(
        &a,
        &bundle_of(&[app_with("p1", 18080, &files_part(&good.path(), "app", 60))]),
        1,
    )
    .unwrap();
    assert_eq!(running_folder(&proxy), Some(good.path()));

    // The next bundle names a folder that is not there: the old one serves on.
    let missing = gone.path() + "/removed";
    apply(
        &a,
        &bundle_of(&[app_with("p1", 18080, &files_part(&missing, "app", 60))]),
        2,
    )
    .unwrap();
    assert_eq!(
        running_folder(&proxy),
        Some(good.path()),
        "the earlier folder serves on"
    );
    let s = a.edge_statuses(true);
    assert_eq!(
        static_feature(&s[0]),
        Some((
            "refused".into(),
            "root_missing".into(),
            missing.clone(),
            true
        ))
    );
    assert_eq!(s[0].generation, 2);

    // And again: the folder that runs is still the first one.
    apply(
        &a,
        &bundle_of(&[app_with("p1", 18080, &files_part("/etc", "app", 60))]),
        3,
    )
    .unwrap();
    assert_eq!(running_folder(&proxy), Some(good.path()));
    assert!(static_feature(&a.edge_statuses(true)[0]).unwrap().3);

    // A good folder replaces it.
    let other = Folder::new("other");
    apply(
        &a,
        &bundle_of(&[app_with("p1", 18080, &files_part(&other.path(), "app", 60))]),
        4,
    )
    .unwrap();
    assert_eq!(running_folder(&proxy), Some(other.path()));
    assert_eq!(
        static_feature(&a.edge_statuses(true)[0]).unwrap().0,
        "applied"
    );

    // The part is left out: off, and no status for it.
    apply(&a, &bundle_of(&[app_with("p1", 18080, "")]), 5).unwrap();
    assert_eq!(running_folder(&proxy), None);
    assert_eq!(static_feature(&a.edge_statuses(true)[0]), None);
    assert!(a.edge_statuses(false).is_empty());
    // A refusal now has nothing to keep running.
    apply(
        &a,
        &bundle_of(&[app_with("p1", 18080, &files_part(&missing, "app", 60))]),
        6,
    )
    .unwrap();
    assert_eq!(running_folder(&proxy), None);
    assert_eq!(
        static_feature(&a.edge_statuses(true)[0]),
        Some(("refused".into(), "root_missing".into(), missing, false))
    );
    // `enabled: false` is off like an absent part.
    let off = r#","static_files":{"enabled":false,"root":"/etc","missing":"bogus","max_age_s":-5}"#;
    apply(&a, &bundle_of(&[app_with("p1", 18080, off)]), 7).unwrap();
    assert_eq!(running_folder(&proxy), None);
    assert_eq!(static_feature(&a.edge_statuses(true)[0]), None);
}

/// What the part is for each app is its own: one app's refusal does not touch another's.
#[test]
fn the_folders_of_two_apps_are_kept_apart() {
    let (a, proxy, _ready) = agent();
    let (one, two) = (Folder::new("one"), Folder::new("two"));
    apply(
        &a,
        &bundle_of(&[
            app_with("p1", 18080, &files_part(&one.path(), "app", 0)),
            app_with("p2", 18081, &files_part(&two.path(), "not_found", 0)),
        ]),
        1,
    )
    .unwrap();
    apply(
        &a,
        &bundle_of(&[
            app_with("p1", 18080, &files_part("/etc", "app", 0)),
            app_with("p2", 18081, &files_part(&two.path(), "not_found", 0)),
        ]),
        2,
    )
    .unwrap();
    let running = proxy.static_files.lock().unwrap().last().unwrap().clone();
    assert_eq!(
        running[0].as_ref().map(|s| s.root()),
        Some(one.path().as_str())
    );
    assert_eq!(
        running[1].as_ref().map(|s| s.root()),
        Some(two.path().as_str())
    );
    let s = a.edge_statuses(false);
    assert_eq!(
        static_feature(&s[0]).map(|f| (f.0, f.3)),
        Some(("refused".into(), true))
    );
    assert_eq!(
        static_feature(&s[1]).map(|f| (f.0, f.3)),
        Some(("applied".into(), false))
    );
    // An app that leaves the bundle takes its folder with it.
    apply(
        &a,
        &bundle_of(&[app_with(
            "p2",
            18081,
            &files_part(&two.path(), "not_found", 0),
        )]),
        3,
    )
    .unwrap();
    apply(
        &a,
        &bundle_of(&[app_with("p1", 18080, &files_part("/etc", "app", 0))]),
        4,
    )
    .unwrap();
    assert_eq!(
        running_folder(&proxy),
        None,
        "the folder of a removed app does not come back"
    );
}

/// The control plane's cases for `static_files`. It sends the part in its normal form, so a case
/// that passes is run with its `result`; a case it refuses must be `invalid` here too. What the
/// disk says about a folder that does not exist is another matter (`root_missing`) and is not
/// what these cases are about.
#[test]
fn the_static_files_cases_of_the_control_plane_get_the_same_answer() {
    for case in delivery_cases("static_files", 15) {
        let name = case["name"].as_str().unwrap();
        let refused = case.get("message").is_some();
        let from = if refused {
            &case["in"]
        } else {
            &case["result"]
        };
        let root = match from["root"].as_str().unwrap() {
            // A part that is off carries no folder, and the agent never gets it.
            "" if !refused => "/srv/x",
            root => root,
        };
        let got = wafio_proxy::StaticSpec::check(
            root,
            from["missing"].as_str().unwrap(),
            from["max_age_s"].as_i64().unwrap(),
        );
        let invalid = got
            .as_ref()
            .err()
            .is_some_and(|e| e.code == wafio_proxy::RefusalCode::Invalid);
        assert_eq!(invalid, refused, "{name}: {got:?}");
    }
}
