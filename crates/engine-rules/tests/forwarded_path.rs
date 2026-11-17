use wafio_engine_rules::*;

#[test]
fn decode_forwarded_path_table() {
    for (raw, want, ok) in [
        ("", "/", true),
        ("/", "/", true),
        ("/a/b?q=1#f", "/a/b", true),
        (
            "/uploads/%zz/%2e%2e/%2e%2e/api/login?id=1",
            "/api/login",
            false,
        ),
        ("/%zz/../%61dmin/panel", "/admin/panel", false),
        ("/a/b%", "/a/b%", false),
        ("/a/b%4", "/a/b%4", false),
        ("/a/%Z1", "/a/%Z1", false),
        ("/a?x=%zz", "/a", true),
        ("/static/%2E%2E/api", "/api", true),
        ("/./admin", "/admin", true),
        ("/a/./b/.", "/a/b/.", true),
        ("/a/b/..", "/a/", true),
        ("/../../x", "/x", true),
        ("//admin//panel", "/admin/panel", true),
        ("//evil.example/x", "/evil.example/x", true),
        ("/a%2Fb%2f..%2fc", "/a/c", true),
        ("/admin/..;/secret", "/admin/..;/secret", true),
        ("/reports%3Bv=2/daily", "/reports;v=2/daily", true),
        ("/x%3Fy", "/x?y", true),
        ("/Admin", "/Admin", true),
        ("http://h.example/abs/../p?q=1", "/p", true),
        ("relative", "/relative", true),
    ] {
        let (got, got_ok) = decode_forwarded_path(raw.as_bytes());
        assert_eq!(
            (String::from_utf8_lossy(&got).as_ref(), got_ok),
            (want, ok),
            "{raw:?}"
        );
    }
}

#[test]
fn contains_invalid_percent_escape_table() {
    for (p, want) in [
        ("", false),
        ("/a/b", false),
        ("/a%20b", false),
        ("/%2e%2E%2f", false),
        ("/%C3%A9", false),
        ("/%zz", true),
        ("/%", true),
        ("/a%4", true),
        ("/%4g", true),
        ("/%g4", true),
        ("/%%41", true),
        ("/%41%", true),
        ("/%2541", false),
    ] {
        assert_eq!(contains_invalid_percent_escape(p.as_bytes()), want, "{p:?}");
    }
}

fn load(exc: &str) -> Vec<PathExceptionConfig> {
    load_rules_json(format!(r#"{{"path_exceptions":{exc}}}"#).as_bytes())
        .unwrap()
        .path_exceptions
}

fn matched(raw: &str, exc: &[PathExceptionConfig]) -> String {
    find_exception_for_raw_target(raw.as_bytes(), exc)
        .map(|e| e.path.clone())
        .unwrap_or_default()
}

#[test]
fn exception_matches_forwarded_path() {
    let exc = load(r#"[{"path":"/uploads","inspection_off":true},{"path":"/admin","block":{}}]"#);
    for (raw, proxy, raw_caller) in [
        ("/uploads/%zz/%2e%2e/%2e%2e/api/login?id=1", "", ""),
        ("/uploads/%zz/a.png", "/uploads", ""),
        ("/uploads/a.png", "/uploads", "/uploads"),
        ("/%zz/../%61dmin/panel", "/admin", "/admin"),
        ("/x/%2e%2e/admin", "/admin", "/admin"),
        ("/admin%3F/x", "", ""),
        ("/admin/.", "/admin", "/admin"),
        ("/admin/%2e%2e/public", "", "/admin"),
        ("/api/%2e%2e/uploads/x", "/uploads", ""),
    ] {
        assert_eq!(matched(raw, &exc), raw_caller, "raw {raw:?}");
        let (fwd, _) = decode_forwarded_path(raw.as_bytes());
        let got = find_exception_for_forwarded_path(&fwd, &exc)
            .map(|e| e.path.clone())
            .unwrap_or_default();
        assert_eq!(got, proxy, "forwarded {raw:?}");
    }
    assert!(find_exception_for_forwarded_path(b"/admin?/x", &exc).is_none());
}

#[test]
fn readings_for_raw_target_table() {
    for (raw, fwd, unresolved, no_exempt) in [
        ("/a/b?q=1", "/a/b", "", false),
        ("/a%20b", "/a b", "", false),
        (
            "/api/%2e%2e/static/x?id=1",
            "/static/x",
            "/api/../static/x",
            false,
        ),
        ("/api/../static/x", "/static/x", "/api/../static/x", false),
        ("//a//b", "/a/b", "//a//b", false),
        ("/a/./b", "/a/b", "/a/./b", false),
        ("/uploads/%zz/a.png", "/uploads/%zz/a.png", "", true),
        (
            "/uploads/%zz/%2e%2e/x",
            "/uploads/x",
            "/uploads/%zz/../x",
            true,
        ),
        ("http://h.example/p/../q", "/q", "/p/../q", false),
    ] {
        let rp = readings_for_raw_target(raw.as_bytes());
        assert_eq!(
            (
                String::from_utf8_lossy(&rp.forwarded).as_ref(),
                String::from_utf8_lossy(&rp.unresolved).as_ref(),
                rp.no_exemption
            ),
            (fwd, unresolved, no_exempt),
            "{raw:?}"
        );
    }
    let rp = readings_for_proxy_request(b"/x");
    assert!(rp.unresolved.is_empty() && !rp.no_exemption);
}

#[test]
fn exception_limits_apply_on_either_reading() {
    let limit_only = load(
        r#"[{"path":"/login","match":"exact","login_protection":{"enabled":true,"max_attempts":5,"window_sec":60,"lockout_sec":60}}]"#,
    );
    for raw in [
        "/login",
        "/login/.",
        "/x/%2e%2e/login",
        "/login/%2e%2e/login",
        "/x/..;/login",
    ] {
        assert_eq!(matched(raw, &limit_only), "/login", "{raw:?}");
    }
    let mixed = load(
        r#"[{"path":"/api","disable_semantic":true,"rate_limit":{"max_requests":5,"window_sec":60}}]"#,
    );
    assert_eq!(matched("/x/%2e%2e/api/v1", &mixed), "");
}
