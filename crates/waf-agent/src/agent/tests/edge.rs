//! The edge parts of an app (main host name, path prefix, compression) from the bundle: what goes
//! to the proxy, what the bundle refuses, what the control plane hears of them, and how a cache
//! purge is answered.

use super::*;

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
    let statuses = a.edge_statuses();
    let mut ids: Vec<_> = statuses.iter().map(|s| s.app_id.as_str()).collect();
    ids.sort_unstable();
    let mut want = [SHOP, BLOG];
    want.sort_unstable();
    assert_eq!(ids, want, "an app with no edge part gets none");
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
}

#[test]
fn a_prefix_alone_is_a_redirects_part_and_an_app_with_no_part_on_has_no_status() {
    let (a, _proxy, _ready) = agent();
    assert!(a.edge_statuses().is_empty(), "before the first bundle");
    apply(
        &a,
        &bundle_of(&[
            app_with("p1", 18080, &format!(",{PREFIX}")),
            app_with("p2", 18081, ""),
        ]),
        2,
    )
    .unwrap();
    let statuses = a.edge_statuses();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].app_id, "p1");
    assert_eq!(features(&statuses[0]), [("redirects", "applied")]);
    assert!(statuses[0].compression.is_none(), "no compression part");

    // The next bundle turns it off: nothing is said of the app any more.
    apply(&a, &bundle_of(&[app_with("p1", 18080, "")]), 3).unwrap();
    assert!(a.edge_statuses().is_empty());
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
        a.edge_statuses().len(),
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
    let statuses = sink.statuses();
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
