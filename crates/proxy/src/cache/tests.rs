//! Tests of what is kept, what is looked up and under which key: the settings, the plan of a
//! request, and the decision about an answer.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use pingora::connectors::TransportConnector;
use pingora::connectors::http::Connector;
use wafio_domain::ip_address::{IpAddress, parse_ip_address};

use super::*;
use crate::config::{AppSpec, build_route};
use crate::edge_stats::EdgeStats;
use crate::static_files::DiskGate;

struct Dir(PathBuf);

impl Dir {
    fn new() -> Dir {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "wafio-cache-plan-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir.canonicalize().unwrap())
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A route of an app named `t` with the cache on and a store behind it, in a directory of its own.
struct Site {
    route: Route,
    _host: Arc<CacheHost>,
    _dir: Dir,
}

fn site(spec: Option<CacheSpec>, proxy_config: &str, session: &[&str]) -> Site {
    let dir = Dir::new();
    let host = CacheHost::open(&dir.0, nix::unistd::geteuid().as_raw()).unwrap();
    let mut route = build_route(&AppSpec {
        app_id: "t".into(),
        listen_host: String::new(),
        listen_port: 0,
        upstream: "http://127.0.0.1:1".into(),
        mode: "block".into(),
        proxy_config: proxy_config.as_bytes().to_vec(),
        rules_json: Vec::new(),
        fcgi_doc_root: String::new(),
        fcgi_index: String::new(),
        fcgi_keep_conn: false,
        maintenance: Vec::new(),
        analysis: Arc::new(crate::testing::analysis_setup(b"{}")),
        tls: None,
        compression: None,
        static_files: None,
        cache: spec,
        session_cookies: session.iter().map(|s| (*s).to_owned()).collect(),
    })
    .unwrap();
    if let Some(cache) = route.cache.as_mut() {
        cache.app = host.app("t");
    }
    Site {
        route,
        _host: host,
        _dir: dir,
    }
}

fn with_rules(rules: Vec<CacheRule>) -> CacheSpec {
    CacheSpec {
        rules,
        ..CacheSpec::default()
    }
}

fn keep(prefix: &str, ttl_s: u32, signed_in: bool) -> CacheRule {
    CacheRule {
        prefix: prefix.into(),
        bypass: false,
        ttl_s,
        signed_in,
    }
}

fn bypass(prefix: &str) -> CacheRule {
    CacheRule {
        prefix: prefix.into(),
        bypass: true,
        ttl_s: 0,
        signed_in: false,
    }
}

fn request(method: &str, target: &str, head: &str) -> InboundRequest {
    InboundRequest::from_head(
        format!("{method} {target} HTTP/1.1\r\nHost: shop.test\r\n{head}\r\n").as_bytes(),
    )
}

fn get(target: &str, head: &str) -> InboundRequest {
    request("GET", target, head)
}

fn client() -> IpAddress {
    parse_ip_address(b"203.0.113.9").unwrap()
}

fn proxy() -> IpAddress {
    parse_ip_address(b"10.1.2.3").unwrap()
}

fn planned(site: &Site, req: &InboundRequest) -> Plan {
    plan(&site.route, req, "allow", false, &client())
}

fn ask(plan: Plan) -> Box<Ask> {
    match plan {
        Plan::Lookup(ask) => ask,
        Plan::Off => panic!("the app has no cache"),
        Plan::Bypass => panic!("bypass"),
    }
}

fn is_bypass(plan: &Plan) -> bool {
    matches!(plan, Plan::Bypass)
}

// The settings.

#[test]
fn the_defaults_are_those_of_the_dashboard_and_pass_the_check() {
    let spec = CacheSpec::default();
    assert_eq!(
        (
            spec.default_ttl_s,
            spec.stale_if_error_s,
            spec.disk_bytes,
            spec.memory_bytes,
            spec.max_object_bytes
        ),
        (3600, 600, 1 << 30, 32 << 20, 8 << 20)
    );
    assert_eq!(spec.check(), Ok(()));
}

#[test]
fn every_setting_has_its_range_and_the_refusal_names_it() {
    let bad = |field: &str, edit: &dyn Fn(&mut CacheSpec)| {
        let mut spec = CacheSpec::default();
        edit(&mut spec);
        let refused = spec.check().unwrap_err();
        assert_eq!(refused.code, CacheRefusalCode::Invalid, "{field}");
        assert_eq!(refused.detail, field);
    };
    let ok = |edit: &dyn Fn(&mut CacheSpec)| {
        let mut spec = CacheSpec::default();
        edit(&mut spec);
        assert_eq!(spec.check(), Ok(()));
    };
    ok(&|s| s.default_ttl_s = MAX_TTL_S);
    bad("default_ttl_s", &|s| s.default_ttl_s = MAX_TTL_S + 1);
    ok(&|s| s.stale_if_error_s = 0);
    bad("stale_if_error_s", &|s| s.stale_if_error_s = 86_401);
    ok(&|s| {
        s.disk_bytes = MIN_DISK_BYTES;
        s.max_object_bytes = MIN_DISK_BYTES;
    });
    bad("disk_bytes", &|s| s.disk_bytes = MIN_DISK_BYTES - 1);
    bad("disk_bytes", &|s| s.disk_bytes = MAX_DISK_BYTES + 1);
    ok(&|s| s.memory_bytes = 0);
    ok(&|s| s.memory_bytes = MAX_MEMORY_BYTES);
    bad("memory_bytes", &|s| s.memory_bytes = MAX_MEMORY_BYTES + 1);
    bad("max_object_bytes", &|s| {
        s.max_object_bytes = MIN_OBJECT_BYTES - 1
    });
    bad("max_object_bytes", &|s| {
        s.max_object_bytes = MAX_OBJECT_BYTES + 1
    });
    bad("max_object_bytes", &|s| {
        s.disk_bytes = MIN_DISK_BYTES;
        s.max_object_bytes = MIN_DISK_BYTES + 1;
    });
    let names = |n: usize| (0..n).map(|i| format!("c{i:03}")).collect::<Vec<_>>();
    ok(&|s| s.session_cookies = names(20));
    bad("session_cookies", &|s| s.session_cookies = names(21));
    ok(&|s| s.session_cookies = vec!["a".repeat(64), ".AspNetCore.Session".into()]);
    let long_name = "a".repeat(65);
    for name in [
        "", "a b", "a,b", "a;b", "a=b", "séssion", "a\tb", &long_name,
    ] {
        bad("session_cookies", &|s| {
            s.session_cookies = vec![name.to_owned()]
        });
    }
    let rules = |n: usize| {
        (0..n)
            .map(|i| bypass(&format!("/p{i}")))
            .collect::<Vec<_>>()
    };
    ok(&|s| s.rules = rules(50));
    bad("rules", &|s| s.rules = rules(51));
    ok(&|s| s.rules = vec![keep("/", MAX_TTL_S, true), bypass("/a")]);
    let long_prefix = format!("/{}", "a".repeat(256));
    for prefix in ["blog", "", "/a?b=1", "/a#b", "/a b", &long_prefix] {
        bad("rules.prefix", &|s| s.rules = vec![bypass(prefix)]);
    }
    bad("rules.prefix", &|s| {
        s.rules = vec![bypass("/a"), keep("/a", 5, false)]
    });
    bad("rules.ttl_s", &|s| s.rules = vec![keep("/a", 0, false)]);
    bad("rules.ttl_s", &|s| {
        s.rules = vec![keep("/a", MAX_TTL_S + 1, false)]
    });
    ok(&|s| s.rules = vec![bypass("/a")]);
}

#[test]
fn the_longest_rule_that_matches_decides() {
    let spec = with_rules(vec![
        keep("/", 10, false),
        bypass("/admin/"),
        keep("/admin/public/", 20, false),
    ]);
    let s = Settings::new(&spec);
    let ttl = |path: &str| s.rule_for(path.as_bytes()).map(|r| (r.bypass, r.ttl_s));
    assert_eq!(ttl("/blog"), Some((false, 10)));
    assert_eq!(ttl("/admin/users"), Some((true, 0)));
    assert_eq!(ttl("/admin/public/x"), Some((false, 20)));
    assert_eq!(
        ttl("/admin"),
        Some((false, 10)),
        "a prefix is text, not a folder"
    );
    assert!(
        Settings::new(&CacheSpec::default())
            .rule_for(b"/x")
            .is_none()
    );
}

// What a request is.

#[test]
fn an_app_without_a_cache_has_no_plan() {
    let s = site(None, "", &[]);
    assert!(matches!(planned(&s, &get("/", "")), Plan::Off));
    assert!(planned(&s, &get("/", "")).label().is_none());
    // The settings are there but no store has been bound: the same.
    let mut unbound = site(Some(CacheSpec::default()), "", &[]);
    unbound.route.cache.as_mut().unwrap().app = None;
    assert!(matches!(planned(&unbound, &get("/", "")), Plan::Off));
}

#[test]
fn only_an_allowed_get_or_head_is_looked_up_and_everything_else_is_bypassed() {
    let s = site(Some(CacheSpec::default()), "", &[]);
    let looked = |req: &InboundRequest| matches!(planned(&s, req), Plan::Lookup(_));
    assert!(looked(&get("/", "")));
    assert!(looked(&request("HEAD", "/", "")));
    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PROPFIND"] {
        assert!(
            is_bypass(&planned(&s, &request(method, "/", ""))),
            "{method}"
        );
    }
    // Log and monitor go upstream as they are, and so does a block turned into a monitor.
    for action in ["log", "monitor", "block", "challenge"] {
        assert!(
            is_bypass(&plan(&s.route, &get("/", ""), action, false, &client())),
            "{action}"
        );
    }
    assert!(is_bypass(&planned(
        &s,
        &get("/", "Upgrade: h2c\r\nConnection: Upgrade\r\n")
    )));
    assert_eq!(Plan::Bypass.label(), Some(Label::Bypass));
    assert_eq!(planned(&s, &get("/", "")).label(), Some(Label::Miss));
}

#[test]
fn a_get_with_a_body_and_a_method_override_are_never_read_or_stored() {
    let s = site(Some(CacheSpec::default()), "", &[]);
    for head in [
        "Content-Length: 5\r\n",
        "X-HTTP-Method-Override: DELETE\r\n",
        "x-http-method: PUT\r\n",
        "X-Method-Override: POST\r\n",
        // A CGI parameter folds `_` into `-`: the application reads these as the same headers.
        "X_HTTP_Method_Override: DELETE\r\n",
        "X_Http_Method: PUT\r\n",
        "x_method_override: POST\r\n",
    ] {
        assert!(is_bypass(&planned(&s, &get("/", head))), "{head}");
        assert!(
            is_bypass(&planned(&s, &request("HEAD", "/", head))),
            "{head}"
        );
    }
    // A chunked request keeps its `Transfer-Encoding` line while its body has bytes in it.
    let raw = b"GET / HTTP/1.1\r\nHost: shop.test\r\nTransfer-Encoding: chunked\r\n\r\n";
    let head = crate::head_parser::parse_head(raw).unwrap();
    let parts = crate::head_parser::uri_parts(&head.host, &head.request_target).unwrap();
    let chunked = InboundRequest::from_parsed(&head, parts, &[], false);
    assert!(is_bypass(&planned(&s, &chunked)));
    // A zero length is no body; a body that was read is one whatever the headers say.
    assert!(matches!(
        planned(&s, &get("/", "Content-Length: 0\r\n")),
        Plan::Lookup(_)
    ));
    assert!(is_bypass(&plan(
        &s.route,
        &get("/", ""),
        "allow",
        true,
        &client()
    )));
}

#[test]
fn rules_send_a_path_one_way_or_the_other_and_a_semicolon_under_a_rule_is_never_kept() {
    let spec = with_rules(vec![bypass("/admin/"), keep("/static/", 60, false)]);
    let s = site(Some(spec), "", &[]);
    assert!(is_bypass(&planned(&s, &get("/admin/users", ""))));
    let looked = ask(planned(&s, &get("/static/a.css", "")));
    assert_eq!(looked.rule_ttl, Some(60));
    assert_eq!(ask(planned(&s, &get("/blog", ""))).rule_ttl, None);
    // `..;` is `..` to some servers: what the rule matches may be another path.
    assert!(is_bypass(&planned(&s, &get("/static/..;/admin/x", ""))));
    assert!(is_bypass(&planned(&s, &get("/admin/..;/x", ""))));
    assert!(is_bypass(&planned(&s, &get("/static/a;b=1", ""))));
    // A `;` where no rule matches is an ordinary key.
    assert!(matches!(
        planned(&s, &get("/blog;x=1", "")),
        Plan::Lookup(_)
    ));
}

#[test]
fn a_request_may_fill_when_it_is_a_get_without_a_range() {
    let s = site(Some(CacheSpec::default()), "", &[]);
    let fills = |req: &InboundRequest| ask(planned(&s, req)).fillable;
    assert!(fills(&get("/", "")));
    assert!(fills(&get("/", "Cookie: theme=dark\r\n")));
    assert!(!fills(&request("HEAD", "/", "")));
    assert!(!fills(&get("/", "Range: bytes=0-9\r\n")));
}

#[test]
fn a_visitor_who_is_signed_in_is_never_looked_up_or_filled_unless_a_rule_opens_the_path() {
    let spec = with_rules(vec![keep("/docs/", 60, true), keep("/blog/", 60, false)]);
    let s = site(Some(spec), "", &["MyAuth"]);
    // Signed in: by `Authorization`, by a name the agent knows, by a name the app gave, by the
    // userinfo of an absolute-form target.
    let signed_in = |path: &str| -> Vec<InboundRequest> {
        let mut all: Vec<InboundRequest> = [
            "Authorization: Bearer t\r\n",
            "Cookie: PHPSESSID=1\r\n",
            "Cookie: myauth=1\r\n",
            "Cookie: theme=dark; myauth=1\r\n",
        ]
        .iter()
        .map(|head| get(path, head))
        .collect();
        all.push(InboundRequest::from_head(
            format!("GET http://u:p@shop.test{path} HTTP/1.1\r\nHost: shop.test\r\n\r\n")
                .as_bytes(),
        ));
        all
    };
    for path in ["/", "/blog/a"] {
        for req in signed_in(path) {
            assert!(
                is_bypass(&planned(&s, &req)),
                "{path}, a rule without the signed-in box or none: {:?}",
                req.lines
            );
        }
    }
    for req in signed_in("/docs/a") {
        let a = ask(planned(&s, &req));
        assert!(a.fillable && a.rule_signed_in, "{:?}", req.lines);
    }
    // Not signed in: a cookie that no list names, the same path.
    assert!(matches!(
        planned(&s, &get("/", "Cookie: theme=dark\r\n")),
        Plan::Lookup(_)
    ));
    // A rule for the signed in does not make a `Range` fill.
    let ranged = ask(planned(
        &s,
        &get("/docs/a", "Cookie: PHPSESSID=1\r\nRange: bytes=0-1\r\n"),
    ));
    assert!(!ranged.fillable);
}

#[test]
fn the_key_is_the_exact_target_the_scheme_the_host_and_the_encoding() {
    let s = site(Some(CacheSpec::default()), "", &[]);
    let key = |req: &InboundRequest| ask(planned(&s, req)).primary_id;
    let base = key(&get("/p?a=1&b=2", ""));
    assert_eq!(
        base,
        key(&get("/p?a=1&b=2", "Accept: text/html\r\nUser-Agent: x\r\n"))
    );
    for other in [
        key(&get("/p?b=2&a=1", "")),
        key(&get("/p?a=1&b=2", "Accept-Encoding: gzip\r\n")),
        key(&get("/p?a=1&b=2", "Accept-Encoding: br, gzip\r\n")),
        key(&get("/P?a=1&b=2", "")),
        key(&get("/p?a=1&b=2&", "")),
        key(&InboundRequest::from_head(
            b"GET /p?a=1&b=2 HTTP/1.1\r\nHost: other.test\r\n\r\n",
        )),
        // Two queries that differ only after a leading slash in the first parameter.
        key(&get("/p?/a&page=1", "")),
        key(&get("/p?/b&page=1", "")),
    ] {
        assert_ne!(base, other);
    }
    assert_ne!(key(&get("/p?/a&page=1", "")), key(&get("/p?/b&page=1", "")));
    // `gzip, deflate` and `gzip;q=0.8` are the gzip bucket, and `identity` is no encoding at all.
    assert_eq!(
        key(&get("/x", "Accept-Encoding: gzip, deflate\r\n")),
        key(&get("/x", "Accept-Encoding: gzip;q=0.8\r\n"))
    );
    assert_eq!(
        key(&get("/x", "Accept-Encoding: identity\r\n")),
        key(&get("/x", ""))
    );
    // The host's own default port is not part of it.
    let with_port = InboundRequest::from_head(b"GET /x HTTP/1.1\r\nHost: shop.test:80\r\n\r\n");
    assert_eq!(key(&with_port), key(&get("/x", "")));
}

#[test]
fn headers_of_an_untrusted_peer_are_not_in_the_key_and_a_trusted_proxys_are() {
    let untrusting = site(Some(CacheSpec::default()), "", &[]);
    let trusting = site(
        Some(CacheSpec::default()),
        r#"{"trust_forwarded":true}"#,
        &[],
    );
    let key = |s: &Site, req: &InboundRequest, peer: &IpAddress| {
        ask(plan(&s.route, req, "allow", false, peer)).primary_id
    };
    let plain = get("/x", "");
    let odd = get(
        "/x",
        "X-Forwarded-Port: 8443\r\nX-Original-URL: /admin\r\nX-Host: evil.test\r\nForwarded: host=evil\r\n",
    );
    // No proxy is trusted: nothing a peer says there reaches the key (and none of it the upstream).
    assert_eq!(
        key(&untrusting, &plain, &client()),
        key(&untrusting, &odd, &client())
    );
    assert!(drops_unkeyed_inputs(&untrusting.route, &client()));
    assert!(drops_unkeyed_inputs(&untrusting.route, &proxy()));
    // A trusted proxy: the same headers are keyed, and a public client still is not trusted.
    assert!(!drops_unkeyed_inputs(&trusting.route, &proxy()));
    assert!(drops_unkeyed_inputs(&trusting.route, &client()));
    assert_ne!(
        key(&trusting, &plain, &proxy()),
        key(&trusting, &odd, &proxy())
    );
    assert_eq!(
        key(&trusting, &plain, &client()),
        key(&trusting, &odd, &client())
    );
    // The scheme is the word of any peer, trusted or not: a front proxy that ends TLS and is not
    // trusted still tells the application, and a value other than `https` is the http key.
    let https = get("/x", "X-Forwarded-Proto: https\r\n");
    for (site, peer) in [
        (&trusting, proxy()),
        (&trusting, client()),
        (&untrusting, proxy()),
        (&untrusting, client()),
    ] {
        assert_ne!(
            key(site, &plain, &peer),
            key(site, &https, &peer),
            "{peer:?}"
        );
        for other in [
            "X-Forwarded-Proto: http\r\n",
            "X-Forwarded-Proto: wss, https\r\n",
        ] {
            assert_eq!(
                key(site, &plain, &peer),
                key(site, &get("/x", other), &peer),
                "{other}"
            );
        }
    }
    // Two values differ, and more than 256 bytes of them are not cached.
    let one = get("/x", "X-Forwarded-Port: 1\r\n");
    let two = get("/x", "X-Forwarded-Port: 2\r\n");
    assert_ne!(
        key(&trusting, &one, &proxy()),
        key(&trusting, &two, &proxy())
    );
    let fat = get("/x", &format!("X-Original-URL: {}\r\n", "a".repeat(300)));
    assert!(is_bypass(&plan(
        &trusting.route,
        &fat,
        "allow",
        false,
        &proxy()
    )));
}

// What is kept.

fn answer(status: u16, headers: &[(&str, &str)], body: &[u8]) -> OutboundResponse {
    let mut all = vec![("Content-Type", "text/html")];
    all.extend_from_slice(headers);
    let mut r = OutboundResponse::from_upstream(
        status,
        false,
        all.iter().map(|(k, v)| (k.as_bytes(), v.as_bytes())),
    );
    r.body = body.to_vec().into();
    r
}

const NOW: u64 = 1_700_000_000;

fn settings() -> Settings {
    Settings::new(&CacheSpec::default())
}

fn decided(
    settings: &Settings,
    req: &InboundRequest,
    resp: &OutboundResponse,
) -> Result<Prepared, NotKept> {
    let s = site(Some(CacheSpec::default()), "", &[]);
    decide(settings, &ask(planned(&s, req)), req, resp, NOW)
}

fn kept(headers: &[(&str, &str)]) -> Result<Prepared, NotKept> {
    decided(&settings(), &get("/p", ""), &answer(200, headers, b"body"))
}

const PUBLIC: (&str, &str) = ("Cache-Control", "public, max-age=600");

#[test]
fn an_answer_with_a_lifetime_is_kept_for_that_long() {
    let p = kept(&[PUBLIC]).unwrap();
    assert_eq!(p.times.stored_at, NOW);
    assert_eq!(p.times.fresh_until, NOW + 600);
    assert_eq!(p.times.initial_age, 0);
    assert!(p.names.is_empty());
    assert_eq!(p.id, file_id(&p.key, b""));
    // The age the application gave counts against the lifetime.
    let aged = kept(&[PUBLIC, ("Age", "100")]).unwrap();
    assert_eq!(
        (aged.times.fresh_until, aged.times.initial_age),
        (NOW + 500, 100)
    );
    assert_eq!(
        kept(&[PUBLIC, ("Age", "600")]).err(),
        Some(NotKept::NoLifetime)
    );
    // The window the answer allows itself past its life.
    let stale = kept(&[(
        "Cache-Control",
        "max-age=60, stale-while-revalidate=30, stale-if-error=90",
    )])
    .unwrap();
    assert_eq!(stale.times.stale_window, 90);
}

#[test]
fn the_lifetime_comes_from_the_answer_then_the_rule_then_the_type() {
    let life = |p: Result<Prepared, NotKept>| p.map(|p| p.times.fresh_until - NOW);
    assert_eq!(
        life(kept(&[("Cache-Control", "s-maxage=10, max-age=99")])),
        Ok(10)
    );
    assert_eq!(life(kept(&[("Cache-Control", "max-age=99")])), Ok(99));
    let date = crate::response::http_date(NOW);
    let later = crate::response::http_date(NOW + 300);
    assert_eq!(life(kept(&[("Date", &date), ("Expires", &later)])), Ok(300));
    // Nothing said: a page is not kept, a file is for the default time, and a rule gives its own.
    assert_eq!(kept(&[]).err(), Some(NotKept::NoLifetime));
    let file = |ty: &str| {
        decided(
            &settings(),
            &get("/a", ""),
            &answer(200, &[("Content-Type", ty)], b"x"),
        )
    };
    for ty in [
        "image/png",
        "font/woff2",
        "video/mp4",
        "audio/mpeg",
        "text/css; charset=utf-8",
        "text/javascript",
        "application/javascript",
        "application/wasm",
    ] {
        assert_eq!(life(file(ty)), Ok(3600), "{ty}");
    }
    for ty in [
        "text/html",
        "application/json",
        "text/plain",
        "application/pdf",
    ] {
        assert_eq!(file(ty).err(), Some(NotKept::NoLifetime), "{ty}");
    }
    let off = Settings::new(&CacheSpec {
        default_ttl_s: 0,
        ..CacheSpec::default()
    });
    let png = answer(200, &[("Content-Type", "image/png")], b"x");
    assert_eq!(
        decided(&off, &get("/a", ""), &png).err(),
        Some(NotKept::NoLifetime)
    );
    // An explicit `max-age=0` is a lifetime of none, whatever a rule or a type would give.
    assert_eq!(
        life(decided(
            &settings(),
            &get("/a", ""),
            &answer(
                200,
                &[
                    ("Content-Type", "image/png"),
                    ("Cache-Control", "max-age=0")
                ],
                b"x"
            )
        )),
        Err(NotKept::NoLifetime)
    );
    // At most 365 days.
    assert_eq!(
        life(kept(&[("Cache-Control", "max-age=99999999")])),
        Ok(31_536_000)
    );
}

#[test]
fn a_rule_gives_the_lifetime_an_answer_does_not() {
    let s = site(Some(with_rules(vec![keep("/blog/", 120, false)])), "", &[]);
    let req = get("/blog/a", "");
    let a = ask(planned(&s, &req));
    let resp = answer(200, &[], b"x");
    let p = decide(&settings(), &a, &req, &resp, NOW).unwrap();
    assert_eq!(p.times.fresh_until, NOW + 120);
    let own = answer(200, &[("Cache-Control", "max-age=30")], b"x");
    assert_eq!(
        decide(&settings(), &a, &req, &own, NOW)
            .unwrap()
            .times
            .fresh_until,
        NOW + 30
    );
}

#[test]
fn only_these_statuses_are_kept_and_404_and_410_only_with_a_lifetime_of_their_own() {
    for status in [200, 203, 300, 301, 308] {
        let r = answer(status, &[PUBLIC], b"x");
        assert!(decided(&settings(), &get("/p", ""), &r).is_ok(), "{status}");
    }
    for status in [
        201, 202, 204, 206, 302, 303, 304, 307, 400, 401, 403, 429, 500, 502, 503,
    ] {
        let r = answer(status, &[PUBLIC], b"x");
        assert_eq!(
            decided(&settings(), &get("/p", ""), &r).err(),
            Some(NotKept::Status),
            "{status}"
        );
    }
    for status in [404, 410] {
        let own = answer(status, &[("Cache-Control", "max-age=60")], b"x");
        assert!(
            decided(&settings(), &get("/p", ""), &own).is_ok(),
            "{status}"
        );
        // A missing image is not kept for the hour that a found image is.
        let image = answer(status, &[("Content-Type", "image/png")], b"x");
        assert_eq!(
            decided(&settings(), &get("/p", ""), &image).err(),
            Some(NotKept::NoLifetime)
        );
    }
}

#[test]
fn what_is_private_is_never_kept() {
    for (name, value) in [
        ("Cache-Control", "private, max-age=60"),
        ("Cache-Control", "no-store, max-age=60"),
        ("Cache-Control", "no-cache, max-age=60"),
        ("Cache-Control", "public, max-age=60, private"),
        ("Cache-Control", "max-age=60, no-cache=\"Set-Cookie\""),
        ("Set-Cookie", "a=1"),
    ] {
        let headers = if name == "Set-Cookie" {
            vec![(name, value), PUBLIC]
        } else {
            vec![(name, value)]
        };
        assert_eq!(
            kept(&headers).err(),
            Some(NotKept::Private),
            "{name}: {value}"
        );
    }
    // A Cache-Control that cannot be read is not trusted either.
    for value in ["max-age=abc", "max-age=60, max-age=90", "max-age=-5"] {
        assert_eq!(
            kept(&[("Cache-Control", value)]).err(),
            Some(NotKept::Control),
            "{value}"
        );
    }
}

#[test]
fn the_request_cache_control_is_ignored() {
    let req = get("/p", "Cache-Control: no-cache\r\nPragma: no-cache\r\n");
    assert!(decided(&settings(), &req, &answer(200, &[PUBLIC], b"x")).is_ok());
}

#[test]
fn an_answer_that_varies_by_something_a_copy_cannot_tell_apart_is_not_kept() {
    for vary in ["*", "Cookie", "Accept, Authorization", "a, b, c, d, e"] {
        assert_eq!(
            kept(&[PUBLIC, ("Vary", vary)]).err(),
            Some(NotKept::Vary),
            "{vary}"
        );
    }
    assert_eq!(
        kept(&[PUBLIC, ("Vary", &"a".repeat(257))]).err(),
        Some(NotKept::Vary)
    );
    // Four names pass, and the variant is in the key.
    let four = kept(&[
        PUBLIC,
        ("Vary", "Accept-Language, User-Agent, Accept, X-Region"),
    ])
    .unwrap();
    assert_eq!(four.names.len(), 4);
    let id_of = |lang: &str| {
        let req = get("/p", &format!("Accept-Language: {lang}\r\n"));
        decided(
            &settings(),
            &req,
            &answer(200, &[PUBLIC, ("Vary", "Accept-Language")], b"x"),
        )
        .unwrap()
        .id
    };
    assert_ne!(id_of("id"), id_of("en"));
    assert_eq!(id_of("id"), id_of("id"));
    // `Accept-Encoding` is replaced by the bucket: two clients that take gzip share a copy.
    let by_encoding = |accept: &str| {
        let req = get("/p", &format!("Accept-Encoding: {accept}\r\n"));
        decided(
            &settings(),
            &req,
            &answer(200, &[PUBLIC, ("Vary", "Accept-Encoding")], b"x"),
        )
        .unwrap()
        .id
    };
    assert_eq!(by_encoding("gzip"), by_encoding("gzip, deflate"));
    assert_ne!(by_encoding("gzip"), by_encoding("br"));
}

#[test]
fn an_answer_in_an_encoding_other_than_the_buckets_is_not_kept() {
    let req_gzip = get("/p", "Accept-Encoding: gzip\r\n");
    let encoded = |enc: &str, req: &InboundRequest| {
        decided(
            &settings(),
            req,
            &answer(200, &[PUBLIC, ("Content-Encoding", enc)], b"x"),
        )
    };
    assert!(encoded("gzip", &req_gzip).is_ok());
    assert!(encoded("GZIP", &req_gzip).is_ok());
    assert!(encoded("identity", &req_gzip).is_ok());
    assert_eq!(encoded("br", &req_gzip).err(), Some(NotKept::Encoding));
    assert_eq!(encoded("zstd", &req_gzip).err(), Some(NotKept::Encoding));
    assert_eq!(
        encoded("gzip", &get("/p", "")).err(),
        Some(NotKept::Encoding)
    );
    assert!(encoded("br", &get("/p", "Accept-Encoding: br\r\n")).is_ok());
}

#[test]
fn an_answer_over_the_largest_object_or_with_a_head_too_long_is_not_kept() {
    let small = Settings::new(&CacheSpec {
        max_object_bytes: MIN_OBJECT_BYTES,
        ..CacheSpec::default()
    });
    let r = |n: usize| answer(200, &[PUBLIC], &vec![0; n]);
    assert!(decided(&small, &get("/p", ""), &r(1024)).is_ok());
    assert_eq!(
        decided(&small, &get("/p", ""), &r(1025)).err(),
        Some(NotKept::TooLarge)
    );
    let big_head = answer(200, &[PUBLIC, ("X-Big", &"a".repeat(70_000))], b"x");
    assert_eq!(
        decided(&settings(), &get("/p", ""), &big_head).err(),
        Some(NotKept::Length)
    );
}

#[test]
fn a_request_with_a_cookie_gets_only_an_answer_that_is_the_same_for_everyone() {
    let cookie = get("/p", "Cookie: jwt=eyJ.x.y; theme=dark\r\n");
    let max_age = ("Cache-Control", "max-age=60");
    let check =
        |headers: &[(&str, &str)]| decided(&settings(), &cookie, &answer(200, headers, b"x")).err();
    // An unlisted cookie with `max-age` alone: a login the agent cannot see is not shared.
    assert_eq!(check(&[max_age]), Some(NotKept::Cookie));
    assert_eq!(
        check(&[("Cache-Control", "max-age=60, must-revalidate")]),
        Some(NotKept::Cookie)
    );
    // `public`, `s-maxage` and a file type are the same for everyone.
    assert_eq!(check(&[PUBLIC]), None);
    assert_eq!(check(&[("Cache-Control", "s-maxage=60")]), None);
    let image = decided(
        &settings(),
        &cookie,
        &answer(200, &[("Content-Type", "image/png"), max_age], b"x"),
    );
    assert!(image.is_ok());
    // A rule behind the path does not, as the application may put a login behind a cookie the agent
    // does not know: only a rule that is for signed-in visitors does.
    let plain = site(Some(with_rules(vec![keep("/p", 60, false)])), "", &[]);
    let a = ask(planned(&plain, &cookie));
    let bare = answer(200, &[], b"x");
    assert_eq!(
        decide(&settings(), &a, &cookie, &bare, NOW).err(),
        Some(NotKept::Cookie)
    );
    // The same rule keeps a public answer, which the visitor's cookie does not change.
    let public = answer(200, &[PUBLIC], b"x");
    assert!(decide(&settings(), &a, &cookie, &public, NOW).is_ok());
    let open = site(Some(with_rules(vec![keep("/p", 60, true)])), "", &[]);
    let a = ask(planned(&open, &cookie));
    assert!(decide(&settings(), &a, &cookie, &bare, NOW).is_ok());
    // With no cookie the rule alone gives the lifetime, as before.
    let a = ask(planned(&plain, &get("/p", "")));
    assert!(decide(&settings(), &a, &get("/p", ""), &bare, NOW).is_ok());
}

#[test]
fn a_stored_head_has_no_cookie_no_connection_header_and_no_per_answer_header() {
    let r = answer(
        200,
        &[
            PUBLIC,
            ("Connection", "keep-alive, X-Hop"),
            ("X-Hop", "1"),
            ("Keep-Alive", "timeout=5"),
            ("Age", "3"),
            ("Date", "Mon, 02 Jan 2006 15:04:05 GMT"),
            ("X-Cache", "HIT"),
            ("X-Keep", "yes"),
            ("Content-Encoding", "identity"),
        ],
        b"x",
    );
    let p = decided(&settings(), &get("/p", ""), &r).unwrap();
    let head = StoredHead::decode(&p.head).unwrap();
    let names: Vec<String> = head
        .lines
        .iter()
        .map(|(n, _)| String::from_utf8_lossy(n).to_ascii_lowercase())
        .collect();
    for gone in [
        "connection",
        "x-hop",
        "keep-alive",
        "age",
        "date",
        "x-cache",
        "set-cookie",
    ] {
        assert!(!names.contains(&gone.to_owned()), "{gone}: {names:?}");
    }
    for kept in [
        "content-type",
        "cache-control",
        "x-keep",
        "content-encoding",
    ] {
        assert!(names.contains(&kept.to_owned()), "{kept}: {names:?}");
    }
    assert_eq!(head.status, 200);
}

#[test]
fn x_cache_goes_on_an_answer_in_place_of_the_applications_and_each_label_is_counted() {
    let s = site(Some(CacheSpec::default()), "", &[]);
    let mut r = answer(200, &[("X-Cache", "from-upstream")], b"x");
    for (label, text) in [
        (Label::HitDisk, "HIT"),
        (Label::HitMemory, "HIT"),
        (Label::Stale, "STALE"),
        (Label::Miss, "MISS"),
        (Label::Bypass, "BYPASS"),
    ] {
        tag(&s.route, &mut r, label);
        assert_eq!(r.values(b"X-Cache").count(), 1, "{text}");
        assert_eq!(r.peek(b"X-Cache"), Some(text.as_bytes()));
    }
    let (_, app) = s.route.cache_active().unwrap();
    let hour = app.hour(store::now());
    assert_eq!(
        (
            hour.hits_disk,
            hour.hits_memory,
            hour.stale,
            hour.misses,
            hour.bypass,
            hour.requests
        ),
        (1, 1, 1, 1, 1, 5)
    );
    // An app with no cache has nothing to count and nothing to tag.
    let off = site(None, "", &[]);
    tag(&off.route, &mut r, Label::Miss);
    assert_eq!(r.peek(b"X-Cache"), Some(&b"MISS"[..]));
}

// How far past its life a copy is used, and what an answer that is not kept leads to.

fn copy_saying(lines: &[&str]) -> Loaded {
    Loaded {
        times: Times {
            stored_at: 1,
            fresh_until: 2,
            initial_age: 0,
            stale_window: 0,
        },
        head: StoredHead {
            status: 200,
            http10: false,
            reason: b"OK".to_vec(),
            lines: lines
                .iter()
                .map(|l| (b"Cache-Control".to_vec(), l.as_bytes().to_vec()))
                .collect(),
        },
        body: Vec::new(),
        size: 0,
    }
}

fn windows(lines: &[&str], setting: u32) -> (u64, u64) {
    let w = Windows::of(&copy_saying(lines), setting);
    (w.revalidate, w.error)
}

#[test]
fn the_window_for_an_error_is_the_answers_own_else_the_setting_and_one_for_revalidating_only_its_own()
 {
    assert_eq!(windows(&["public, max-age=60"], 600), (0, 600));
    assert_eq!(windows(&["public, max-age=60"], 0), (0, 0));
    assert_eq!(windows(&[], 30), (0, 30), "an answer that says nothing");
    assert_eq!(
        windows(&["max-age=60, stale-while-revalidate=30"], 600),
        (30, 600)
    );
    assert_eq!(windows(&["max-age=60, stale-if-error=5"], 600), (0, 5));
    assert_eq!(
        windows(&["max-age=60", "stale-if-error=9"], 600),
        (0, 9),
        "every line is read"
    );
    assert_eq!(windows(&["max-age=60, stale-if-error=0"], 600), (0, 0));
}

#[test]
fn an_answer_that_must_be_revalidated_has_no_window_unless_it_names_its_own() {
    for never in [
        "max-age=60, must-revalidate",
        "max-age=60, proxy-revalidate",
        "s-maxage=60",
        "MUST-REVALIDATE, max-age=60",
    ] {
        assert_eq!(windows(&[never], 600), (0, 0), "{never}");
    }
    // Its own windows count, only those, and the setting does not fill in for the other.
    assert_eq!(
        windows(&["max-age=60, must-revalidate, stale-if-error=7"], 600),
        (0, 7)
    );
    assert_eq!(
        windows(&["s-maxage=60, stale-while-revalidate=20"], 600),
        (20, 0)
    );
    assert_eq!(
        windows(
            &["proxy-revalidate, stale-while-revalidate=1, stale-if-error=2"],
            600
        ),
        (1, 2)
    );
}

#[test]
fn what_is_not_kept_is_counted_where_the_dashboard_has_a_line_and_marks_the_key_unless_it_may_pass()
{
    let r = |status, headers: &[(&str, &str)]| answer(status, headers, b"x");
    let plain = r(200, &[]);
    for (why, count) in [
        (NotKept::NoLifetime, Some(Count::SkippedNoLifetime)),
        (NotKept::Private, Some(Count::SkippedPrivate)),
        (NotKept::Control, Some(Count::SkippedPrivate)),
        (NotKept::Vary, Some(Count::SkippedPrivate)),
        (NotKept::Cookie, Some(Count::SkippedPrivate)),
        (NotKept::TooLarge, Some(Count::SkippedTooLarge)),
        (NotKept::Status, None),
        (NotKept::Encoding, None),
        (NotKept::Length, None),
    ] {
        assert_eq!(skipped(why), count, "{why:?}");
    }
    // Thirty seconds, unless the answer says it is private for longer, and never past ten minutes.
    for why in [
        NotKept::NoLifetime,
        NotKept::Control,
        NotKept::Vary,
        NotKept::TooLarge,
        NotKept::Encoding,
        NotKept::Length,
    ] {
        assert_eq!(mark_seconds(why, &plain), Some(30), "{why:?}");
    }
    assert_eq!(mark_seconds(NotKept::Status, &r(302, &[])), Some(30));
    assert_eq!(mark_seconds(NotKept::Status, &r(404, &[])), Some(30));
    assert_eq!(
        mark_seconds(NotKept::Status, &r(500, &[])),
        None,
        "a server error may pass"
    );
    assert_eq!(mark_seconds(NotKept::Status, &r(503, &[])), None);
    for status in [304, 412] {
        assert_eq!(
            mark_seconds(NotKept::Status, &r(status, &[])),
            None,
            "{status} answers a condition and says nothing of the page"
        );
    }
    assert_eq!(
        mark_seconds(NotKept::Cookie, &plain),
        None,
        "that is about the visitor"
    );
    let private = |cc: &str| mark_seconds(NotKept::Private, &r(200, &[("Cache-Control", cc)]));
    assert_eq!(private("private"), Some(30));
    assert_eq!(private("private, max-age=120"), Some(120));
    assert_eq!(private("no-store, max-age=45"), Some(45));
    assert_eq!(private("private, max-age=86400"), Some(600));
    assert_eq!(private("private, max-age=0"), Some(30));
    assert_eq!(
        private("no-cache, max-age=120"),
        Some(30),
        "only private and no-store say it"
    );
    assert_eq!(
        mark_seconds(NotKept::Private, &r(200, &[("Set-Cookie", "a=b")])),
        Some(30)
    );
}

#[test]
fn a_request_that_is_not_filled_is_looked_up_and_carries_the_purge_count_it_came_with() {
    let s = site(Some(CacheSpec::default()), "", &["sid"]);
    let a = ask(planned(&s, &get("/p", "")));
    assert!(a.fillable);
    assert!(!ask(planned(&s, &get("/p", "Range: bytes=0-1\r\n"))).fillable);
    assert!(!ask(planned(&s, &request("HEAD", "/p", ""))).fillable);
    // A rule for the signed in lets them fill, and only a rule for them is read as one.
    let open = site(
        Some(with_rules(vec![
            keep("/shared", 60, true),
            keep("/own", 60, false),
        ])),
        "",
        &["sid"],
    );
    let shared = ask(planned(&open, &get("/shared", "Cookie: sid=1\r\n")));
    assert!(shared.fillable && shared.rule_signed_in);
    assert!(is_bypass(&planned(
        &open,
        &get("/own", "Cookie: sid=1\r\n")
    )));
    assert!(!ask(planned(&open, &get("/own", ""))).rule_signed_in);
    let (_, app) = s.route.cache_active().unwrap();
    assert_eq!(a.purge_gen, app.purge_count());
}

#[test]
fn a_refresh_in_the_background_ends_at_the_upstream_timeout_or_after_a_minute_when_there_is_none() {
    let bounded = site(
        Some(CacheSpec::default()),
        r#"{"timeouts":{"upstream_ms":4000}}"#,
        &[],
    );
    assert_eq!(refresh::limit(&bounded.route), Duration::from_secs(4));
    let unlimited = site(
        Some(CacheSpec::default()),
        r#"{"timeouts":{"upstream_ms":-1}}"#,
        &[],
    );
    assert_eq!(refresh::limit(&unlimited.route), Duration::from_secs(60));
}

#[tokio::test]
async fn a_request_that_leads_keeps_the_copy_enter_read_and_reads_nothing_again() {
    let Site {
        route,
        _host: host,
        _dir: dir,
    } = site(Some(CacheSpec::default()), "", &[]);
    host.commit(&[CacheLimits {
        app_id: "t".into(),
        disk_bytes: 1 << 20,
        memory_bytes: 0,
        stale_if_error_s: 0,
    }]);
    assert!(host.wait_writable(Duration::from_secs(5)));
    let route = Arc::new(route);
    let req = get("/p", "");
    let ask = ask(plan(&route, &req, "allow", false, &client()));
    let (settings, app) = route.cache_active().unwrap();
    // A copy that ended its life a minute ago and has a tag to ask about.
    let past = answer(
        200,
        &[("Cache-Control", "max-age=30"), ("ETag", "\"v1\"")],
        b"body",
    );
    let p = decide(settings, &ask, &req, &past, store::now() - 90).unwrap();
    let path = format::path_of(&dir.0.join("t"), &p.id);
    app.store(Store {
        purge_gen: ask.purge_gen,
        id: p.id,
        primary: p.primary,
        key: p.key,
        primary_len: p.primary_len,
        names: p.names,
        head: p.head,
        body: past.body.clone(),
        times: p.times,
    })
    .unwrap();
    let shared = Arc::new(Shared {
        decisions: Arc::new(|_| {}),
        ip_rep: None,
        good_bots: None,
        captcha: None,
        connector: Connector::new(None),
        transport: TransportConnector::new(None),
        book: Arc::default(),
        edge: EdgeStats::default(),
        disk: DiskGate::new(4, Duration::from_secs(5)),
        cache: None,
    });
    let peer = client();
    let cx = Ctx {
        shared: &shared,
        route: &route,
        req: &req,
        peer: &peer,
        remote: "203.0.113.9",
    };
    let Entered::Go(mut pending) = enter(&cx, &ask).await else {
        panic!("a copy past its life is not an answer");
    };
    assert!(pending.validator().is_some());
    // The file is damaged after `enter` read it: a second read would find it and count it.
    let mut bytes = std::fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(take_turn(&cx, &ask, &mut pending).await.is_none());
    assert!(pending.guard.is_some(), "it leads");
    assert!(pending.validator().is_some(), "and asks about what it read");
    assert_eq!(host.counters("t").unwrap().corrupt, 0, "nothing was read");
    assert_eq!(app.usage().0, 1);
}
