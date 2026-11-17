//! Login protection through `analyze`, every spelling of path, query, body and
//! identifier counted at the baseline limit.

use std::sync::Arc;

use wafio_application::deps::engine::{PathExceptionConfig, login_scope_key};
use wafio_application::{AnalyzeConfig, analyze, blocklist, cache_base_semantic_config, ratelimit};
use wafio_domain::{AnalysisResult, BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET, IncomingRequest};
use wafio_engine_rules::{PathLoginProtection, decode_forwarded_path};

const LOGIN_MAX: i64 = 3;
const LOGIN_ATTEMPTS: usize = 20;
const WANT_FIRST: usize = LOGIN_MAX as usize + 1;
const WANT_BLOCKED: usize = LOGIN_ATTEMPTS - LOGIN_MAX as usize;
const PATH_WIDE_RUN: usize = 60;
const PATH_WIDE_FIRST: usize = 51;
const FIXED_IP: &str = "203.0.113.7:40000";

fn rotating_ip(i: usize) -> String {
    format!("198.51.100.{}:40000", i + 1)
}

fn login_config_with(
    identifier: &str,
    by_ip: bool,
    m: impl Fn(&mut PathExceptionConfig),
) -> (AnalyzeConfig, Arc<ratelimit::MemoryStore>) {
    let mut exc = PathExceptionConfig::default(); // private compiled-regex fields
    exc.path = "/login".into();
    exc.match_ = "exact".into();
    exc.login_protection = Some(PathLoginProtection {
        enabled: true,
        max_attempts: LOGIN_MAX,
        window_sec: 60,
        lockout_sec: 300,
        by_ip,
        identifier_field: identifier.into(),
        methods: vec!["POST".into()],
        by_user_agent: false,
    });
    m(&mut exc);
    path_config(vec![exc])
}

fn login_config(identifier: &str, by_ip: bool) -> AnalyzeConfig {
    login_config_with(identifier, by_ip, |_| {}).0
}

/// A config with the path exceptions, its stores and project "p1".
fn path_config(exc: Vec<PathExceptionConfig>) -> (AnalyzeConfig, Arc<ratelimit::MemoryStore>) {
    let store = Arc::new(ratelimit::MemoryStore::new());
    let mut cfg = AnalyzeConfig {
        rate_limit_store: Some(store.clone()),
        block_store: Some(Arc::new(blocklist::MemoryStore::new())),
        path_exceptions: exc,
        project_id: "p1".into(),
        ..Default::default()
    };
    cache_base_semantic_config(&mut cfg);
    (cfg, store)
}

fn request(method: &str, uri: &str, ct: &str, body: &[u8], remote: &str) -> IncomingRequest {
    IncomingRequest {
        method: method.into(),
        uri: uri.into(),
        remote_address: remote.into(),
        content_type: ct.into(),
        body: body.to_vec(),
        ..Default::default()
    }
}

fn form(uri: &str, body: &str, remote: &str) -> IncomingRequest {
    request(
        "POST",
        uri,
        "application/x-www-form-urlencoded",
        body.as_bytes(),
        remote,
    )
}

fn json(uri: &str, body: &str, remote: &str) -> IncomingRequest {
    request("POST", uri, "application/json", body.as_bytes(), remote)
}

fn multipart(uri: &str, remote: &str, fields: &[(&str, &str)]) -> IncomingRequest {
    let mut b = String::new();
    for (k, v) in fields {
        b.push_str(&format!(
            "--BNDRY\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
        ));
    }
    b.push_str("--BNDRY--\r\n");
    request(
        "POST",
        uri,
        "multipart/form-data; boundary=BNDRY",
        b.as_bytes(),
        remote,
    )
}

fn is_login_block(r: &AnalysisResult) -> bool {
    r.action == "block" && r.categories.first().is_some_and(|c| c == "LoginProtection")
}

fn run(cfg: &AnalyzeConfig, n: usize, mk: impl Fn(usize) -> IncomingRequest) -> (usize, usize) {
    let (mut first, mut blocked) = (0, 0);
    for i in 0..n {
        if is_login_block(&analyze(&mk(i), cfg)) {
            blocked += 1;
            if first == 0 {
                first = i + 1;
            }
        }
    }
    (first, blocked)
}

#[track_caller]
fn want_baseline(name: &str, cfg: &AnalyzeConfig, mk: impl Fn(usize) -> IncomingRequest) {
    assert_eq!(
        run(cfg, LOGIN_ATTEMPTS, mk),
        (WANT_FIRST, WANT_BLOCKED),
        "{name}"
    );
}

#[track_caller]
fn want_path_wide(name: &str, cfg: &AnalyzeConfig, mk: impl Fn(usize) -> IncomingRequest) {
    assert_eq!(
        run(cfg, PATH_WIDE_RUN, mk),
        (PATH_WIDE_FIRST, PATH_WIDE_RUN - PATH_WIDE_FIRST + 1),
        "{name}"
    );
}

fn esc(s: &str) -> String {
    s.replace('~', "\\")
}

#[test]
fn baseline() {
    want_baseline("form, one client", &login_config("username", true), |i| {
        form(
            "/login",
            &format!("username=admin&password=pw{i}"),
            FIXED_IP,
        )
    });
    want_baseline("form, rotating", &login_config("username", false), |i| {
        form(
            "/login",
            &format!("username=admin&password=pw{i}"),
            &rotating_ip(i),
        )
    });
}

#[test]
fn query_does_not_split_bucket() {
    want_baseline("?r=N, one client", &login_config("", true), |i| {
        form(
            &format!("/login?r={i}"),
            &format!("username=admin&password=pw{i}"),
            FIXED_IP,
        )
    });
    want_baseline("?r=N, rotating", &login_config("username", false), |i| {
        form(
            &format!("/login?r={i}"),
            &format!("username=admin&password=pw{i}"),
            &rotating_ip(i),
        )
    });
}

#[test]
fn bad_form_pair_does_not_hide_identifier() {
    for tail in ["&x=%zz", "&x=%", "&%zz=1", "&x=1;y=2"] {
        want_baseline(tail, &login_config("username", false), |i| {
            form(
                "/login",
                &format!("username=admin&password=pw{i}{tail}"),
                &rotating_ip(i),
            )
        });
    }
}

#[test]
fn json_identifier_decoded() {
    for tmpl in [
        r#"{"username":"admin","password":"pwN"}"#,
        r#"{"~u0075sername":"admin","password":"pwN"}"#,
        r#"{"username":"adm~u0069n","password":"pwN"}"#,
        r#"{ "username" : "admin" , "password":"pwN"}"#,
        r#"{"USERNAME":"admin","password":"pwN"}"#,
        r#"{"username":["admin"],"password":"pwN"}"#,
        r#"{"username":1234,"password":"pwN"}"#,
        r#"{"username":"admin","password":"pwN"} "#,
    ] {
        want_baseline(tmpl, &login_config("username", false), |i| {
            json(
                "/login",
                &esc(&tmpl.replace("pwN", &format!("pw{i}"))),
                &rotating_ip(i),
            )
        });
    }
    want_baseline("dotted path", &login_config("user.email", false), |i| {
        json(
            "/login",
            &format!(r#"{{"user":{{"email":"a@example.com","password":"pw{i}"}}}}"#),
            &rotating_ip(i),
        )
    });
    want_baseline("BOM", &login_config("username", false), |i| {
        json(
            "/login",
            &format!("\u{FEFF}{{\"username\":\"admin\",\"password\":\"pw{i}\"}}"),
            &rotating_ip(i),
        )
    });
    let mixed = [
        json("/login", r#"{"username":"admin"}"#, ""),
        json("/login", &esc(r#"{"~u0075sername":"admin"}"#), ""),
        json("/login", r#"{"USERNAME":"ADMIN "}"#, ""),
        form("/login", "username=Admin&x=%zz", ""),
    ];
    want_baseline("mixed spellings", &login_config("username", false), |i| {
        let mut r = mixed[i % mixed.len()].clone();
        r.remote_address = rotating_ip(i).into_bytes();
        r
    });
}

#[test]
fn missing_identifier_counts_per_ip() {
    want_baseline(
        "form without username",
        &login_config("username", false),
        |i| form("/login", &format!("password=pw{i}"), FIXED_IP),
    );
    want_baseline(
        "json without username",
        &login_config("username", false),
        |i| json("/login", &format!(r#"{{"password":"pw{i}"}}"#), FIXED_IP),
    );
    want_baseline("undecodable body", &login_config("username", false), |i| {
        let mut r = form("/login", "", FIXED_IP);
        r.body_scan_skipped = "content_encoding:zstd".into();
        r.body = vec![0x28, 0xb5, 0x2f, 0xfd, i as u8];
        r
    });
    want_baseline("empty POST", &login_config("username", false), |_| {
        form("/login", "", FIXED_IP)
    });
}

#[test]
fn multipart_identifier() {
    want_baseline("multipart", &login_config("username", false), |i| {
        multipart(
            "/login",
            &rotating_ip(i),
            &[("username", "admin"), ("password", &format!("pw{i}"))],
        )
    });
    want_baseline(
        "multipart without username",
        &login_config("username", false),
        |i| multipart("/login", FIXED_IP, &[("password", &format!("pw{i}"))]),
    );
}

#[test]
fn path_variants_share_bucket() {
    let spellings = [
        "/login",
        "/LOGIN",
        "/Login",
        "/%6cogin",
        "/%4C%4F%47%49%4E",
        "/login/",
        "//login",
        "/./login",
        "/x/../login",
        "/login;jsessionid=1",
        "/x/..;/login",
        "/login?next=/a",
    ];
    for proxy in [false, true] {
        let mk = |i: usize| {
            let uri = spellings[i % spellings.len()];
            let mut r = form(
                uri,
                &format!("username=admin&password=pw{i}"),
                &rotating_ip(i),
            );
            if proxy {
                r.forwarded_path = decode_forwarded_path(uri.as_bytes()).0;
            }
            r
        };
        want_baseline(
            &format!("exact, proxy={proxy}"),
            &login_config("username", false),
            mk,
        );
        want_baseline(
            &format!("prefix, proxy={proxy}"),
            &login_config_with("username", false, |e| e.match_ = "prefix".into()).0,
            mk,
        );
        want_baseline(
            &format!("engine-disabling, proxy={proxy}"),
            &login_config_with("username", false, |e| e.disable_semantic = true).0,
            mk,
        );
    }
}

#[test]
fn identifier_readings() {
    for tmpl in [
        "username[]=admin&password=pwN",
        "username[0]=admin&password=pwN",
        "username%00x=admin&password=pwN",
        "username[a]=admin&password=pwN",
        "username[a][b]=admin&password=pwN",
        "USERNAME=admin&password=pwN",
        "user.name=admin&password=pwN",
        "x=1;username=admin&password=pwN",
        "username=Admin&password=pwN",
        "username=%20admin%20&password=pwN",
        "username=%C3%A1dmin&password=pwN",
        "username=ad%C2%ADmin&password=pwN",
        "username=%EF%BD%81dmin&password=pwN",
        "username=adm%69n&password=pwN",
        "username=admin&password=pwN&x=%zz%",
    ] {
        let field = if tmpl.starts_with("user.name") {
            "user_name"
        } else {
            "username"
        };
        let cfg = login_config(field, false);
        analyze(
            &form(
                "/login",
                &format!("{field}=admin&password=seed"),
                "192.0.2.200:1",
            ),
            &cfg,
        );
        let got = run(&cfg, LOGIN_ATTEMPTS, |i| {
            form(
                "/login",
                &tmpl.replace("pwN", &format!("pw{i}")),
                &rotating_ip(i),
            )
        });
        assert_eq!(got, (LOGIN_MAX as usize, WANT_BLOCKED + 1), "{tmpl}");
    }
    want_baseline(
        "identifier in query",
        &login_config("username", false),
        |i| {
            form(
                "/login?username=admin",
                &format!("password=pw{i}"),
                &rotating_ip(i),
            )
        },
    );
}

#[test]
fn ambiguous_identifier() {
    want_path_wide("dup form", &login_config("username", false), |i| {
        form(
            "/login",
            &format!("username=decoy{i}&username=victim"),
            &rotating_ip(i),
        )
    });
    want_path_wide("dup json", &login_config("username", false), |i| {
        json(
            "/login",
            &format!(r#"{{"username":"victim","username":"decoy{i}"}}"#),
            &rotating_ip(i),
        )
    });
    want_path_wide("query vs body", &login_config("username", false), |i| {
        json(
            "/login?username=victim",
            &format!(r#"{{"username":"decoy{i}"}}"#),
            &rotating_ip(i),
        )
    });
    let cfg = login_config("username", false);
    let many: String = (0..8).map(|v| format!("username=v{v}&")).collect();
    for i in 0..4 {
        analyze(&form("/login", &many, &rotating_ip(i)), &cfg);
    }
    for v in 0..8 {
        let r = analyze(
            &form(
                "/login",
                &format!("username=v{v}&password=x"),
                &rotating_ip(100 + v),
            ),
            &cfg,
        );
        assert!(
            !is_login_block(&r),
            "account v{v} locked out by requests naming 8 accounts"
        );
    }
}

#[test]
fn unreadable_identifier() {
    let big = format!("username=victim&pad={}", "a".repeat(128 << 10));
    want_path_wide(
        "body over the read limit",
        &login_config("username", false),
        |i| form("/login", &format!("{big}{i}"), &rotating_ip(i)),
    );
    want_path_wide("malformed JSON", &login_config("username", false), |i| {
        json(
            "/login",
            &format!(r#"{{"password":"pw{i}",,"username":"victim"}}"#),
            &rotating_ip(i),
        )
    });
    want_path_wide("JSON object", &login_config("username", false), |i| {
        json(
            "/login",
            &format!(r#"{{"username":{{"$ne":null}},"password":"pw{i}"}}"#),
            &rotating_ip(i),
        )
    });
    want_path_wide("too deep", &login_config("username", false), |i| {
        json(
            "/login",
            &format!(
                r#"{{"x":{}1{},"username":"victim","n":{i}}}"#,
                "[".repeat(100),
                "]".repeat(100)
            ),
            &rotating_ip(i),
        )
    });
    want_baseline(
        "malformed after the identifier",
        &login_config("username", false),
        |i| {
            json(
                "/login",
                &format!(r#"{{"username":"victim","password":"pw{i}","#),
                &rotating_ip(i),
            )
        },
    );
    let budget = |remote: String, i: usize| {
        let mut r = form("/login", &format!("\x1f\u{8b}\x08{i}"), &remote);
        r.body_scan_skipped = BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET.into();
        r
    };
    want_baseline(
        "decode budget, one client",
        &login_config("username", false),
        |i| budget(FIXED_IP.into(), i),
    );
    let (first, _) = run(&login_config("username", false), PATH_WIDE_RUN, |i| {
        budget(rotating_ip(i), i)
    });
    assert_eq!(first, 0, "decode budget, rotating clients: not path-wide");
}

#[test]
fn ipv6_counted_per_64() {
    let cfg = login_config("username", false);
    want_baseline("rotating inside one /64", &cfg, |i| {
        form(
            "/login",
            &format!("password=pw{i}"),
            &format!("[2001:db8:1:2::{:x}]:40000", i + 1),
        )
    });
    assert!(!is_login_block(&analyze(
        &form("/login", "password=x", "[2001:db8:1:3::1]:40000"),
        &cfg
    )));
}

#[test]
fn page_loads_not_counted() {
    let no_methods =
        |e: &mut PathExceptionConfig| e.login_protection.as_mut().unwrap().methods.clear();
    let cfg = login_config_with("username", false, no_methods).0;
    for _ in 0..10 {
        for m in ["GET", "HEAD", "OPTIONS"] {
            for uri in ["/login", "/login?next=%2Fdashboard"] {
                assert!(
                    !is_login_block(&analyze(&request(m, uri, "", b"", FIXED_IP), &cfg)),
                    "{m} {uri}"
                );
            }
        }
    }
    want_baseline("attempts after page loads", &cfg, |i| {
        form("/login", &format!("password=pw{i}"), FIXED_IP)
    });
    want_baseline(
        "GET with query",
        &login_config_with("username", false, no_methods).0,
        |i| {
            request(
                "GET",
                &format!("/login?username=admin&pw={i}"),
                "",
                b"",
                &rotating_ip(i),
            )
        },
    );
}

#[test]
fn scope_and_unblock() {
    let (cfg, store) = login_config_with("username", true, |_| {});
    let mut last = AnalysisResult::default();
    for i in 0..=LOGIN_MAX {
        last = analyze(
            &form(
                &format!("/login?r={i}"),
                "username=admin&password=x",
                FIXED_IP,
            ),
            &cfg,
        );
    }
    assert!(
        is_login_block(&last) && last.match_source == b"path:/login",
        "{last:?}"
    );
    store.clear_login_scope(login_scope_key("p1", "/login").as_bytes());
    assert!(!is_login_block(&analyze(
        &form("/login?r=9", "username=admin&password=x", FIXED_IP),
        &cfg
    )));
}
