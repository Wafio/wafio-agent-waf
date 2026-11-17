//! Black-box: block pages, monitor mode, the challenge gate and verify endpoint, field rules on
//! request and response bodies, L7 flood.

mod common;
#[path = "common/fake_engine.rs"]
mod fake_engine;

use common::*;
use wafio_agent_pages::field_paths::{FieldRewriter, RequestFieldRule};

const SQLI: &str = "/item?id=wafio-test-sql";
const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[tokio::test]
async fn attack_is_blocked_before_the_upstream_and_monitored_in_monitor_mode() {
    let up = http_upstream().await;
    let (pb, pm) = (free_port(), free_port());
    let mut m = app("mon", pm, &format!("http://{}", up.addr));
    m.mode = "monitor".into();
    let (h, block) =
        Harness::serve_with_fake_engine(vec![app("blk", pb, &format!("http://{}", up.addr)), m]);
    let resp = one(block, &get(SQLI)).await;
    assert_eq!(resp.status, 403);
    assert!(
        resp.header("content-type")
            .unwrap()
            .starts_with("text/html"),
        "{:?}",
        resp.headers
    );
    let ev = h.last_event();
    assert_eq!((s(&ev.action), s(&ev.mode)), ("block", "block"));
    assert!(ev.score > 0 && !ev.categories.is_empty(), "{ev:?}");
    assert_eq!(
        up.accepts(),
        0,
        "a blocked request never contacts the upstream"
    );
    let mon = format!("127.0.0.1:{pm}").parse().unwrap();
    assert_eq!(one(mon, &get(SQLI)).await.status, 200);
    let ev = h.last_event();
    assert_eq!((s(&ev.action), s(&ev.mode)), ("monitor", "monitor"));
    assert_eq!(up.count(), 1);
}

#[tokio::test]
async fn json_block_page_and_status_override() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.analysis = analysis_setup(r#"{"challenge":{"waf_block_format":"json"}}"#);
    let (_h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let resp = one(proxy, &get(SQLI)).await;
    assert_eq!(resp.status, 403);
    assert!(
        resp.header("content-type")
            .unwrap()
            .starts_with("application/json")
    );
}

const CHALLENGE: &str = r#"{"challenge":{"enabled":true,"type":"js_challenge","trigger":"always","allow_local_ips":false,"secret_key":"0123456789abcdef0123456789abcdef"}}"#;

#[tokio::test]
async fn challenge_gate_serves_page_and_skips_api_clients() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.analysis = analysis_setup(CHALLENGE);
    let (h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let browser = b"GET /home HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    let resp = one(proxy, browser).await;
    assert_eq!(
        (resp.status, resp.header("x-wafio-mitigated")),
        (200, Some("challenge"))
    );
    assert!(resp.text().contains("/_wafio/challenge/verify"));
    let ev = h.last_event();
    assert_eq!(
        (s(&ev.action), s(&ev.match_detail), s(&ev.analyze_method)),
        ("challenge", "bot_challenge", "challenge_gate")
    );
    assert_eq!(up.accepts(), 0);
    // Non-HTML Accept is never challenged.
    let api = b"GET /api HTTP/1.1\r\nHost: app.test\r\nAccept: application/json\r\n\r\n";
    assert_eq!(one(proxy, api).await.status, 200);
    // The verify endpoint is answered by the agent itself (bad submission → not 200 OK page).
    let resp = one(
        proxy,
        &post(
            "/_wafio/challenge/verify",
            "application/x-www-form-urlencoded",
            b"nonce=x&redirect=/",
        ),
    )
    .await;
    assert_ne!(resp.status, 502);
    assert_eq!(up.count(), 1, "verify never reaches the upstream");
}

/// Challenge replay and scope through the proxy: a challenge page served by a route (its app ID
/// is the scope of the token) verifies on that route and mints a cookie; the same PoW token has
/// no second outcome; the cookie passes the gate on its own app, a cookie minted for another app
/// does not, and a verify form over 16 KiB is refused.
#[tokio::test]
async fn challenge_round_trip_is_scoped_to_the_route_and_single_use() {
    use wafio_agent_pages::challenge::{
        check_pow_solution, check_pow_token, issue_challenge_cookie,
    };
    const SECRET_KEY: &str = "0123456789abcdef0123456789abcdef";
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.analysis = analysis_setup(CHALLENGE);
    let (_h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let browser = b"GET /home HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    let page = one(proxy, browser).await.text();
    let after = page
        .split(r#"name="token" id="tk" value=""#)
        .nth(1)
        .expect("a token input");
    let token = after.split('"').next().unwrap().to_string();
    let (salt, diff) =
        check_pow_token(SECRET_KEY, b"a1", token.as_bytes(), now()).expect("token scoped to a1");
    let sol = (0..10_000_000i64)
        .find(|&n| check_pow_solution(&salt, n, diff))
        .unwrap();
    let verify = |t: &str, extra: &str| {
        post(
            "/_wafio/challenge/verify",
            "application/x-www-form-urlencoded",
            format!("token={t}&solution={sol}&redirect=%2Fhome{extra}").as_bytes(),
        )
    };
    let ok = one(proxy, &verify(&token, "")).await;
    assert_eq!((ok.status, ok.header("location")), (302, Some("/home")));
    let set = ok.header("set-cookie").expect("a cookie").to_string();
    let cookie = set.split(';').next().unwrap().to_string();
    // The PoW token had its one outcome.
    let replay = one(proxy, &verify(&token, "")).await;
    assert!(replay.header("set-cookie").is_none() && replay.text().contains("rawToken"));
    // The cookie passes the gate of its own app (and reaches the upstream) ...
    let with = |c: &str| {
        format!(
            "GET /home HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nUser-Agent: Mozilla/5.0\r\nCookie: {c}\r\n\r\n"
        )
    };
    let before = up.count();
    assert_eq!(one(proxy, with(&cookie).as_bytes()).await.status, 200);
    assert_eq!(up.count(), before + 1);
    // ... a cookie bound to another app is challenged again.
    let other = format!(
        "_wafio_ch={}",
        String::from_utf8(issue_challenge_cookie(SECRET_KEY, b"other-app", now())).unwrap()
    );
    let resp = one(proxy, with(&other).as_bytes()).await;
    assert_eq!(resp.header("x-wafio-mitigated"), Some("challenge"));
    // The verify form is capped at 16 KiB.
    let big = post(
        "/_wafio/challenge/verify",
        "application/x-www-form-urlencoded",
        format!("token={}", "a".repeat(16384)).as_bytes(),
    );
    assert_eq!(one(proxy, &big).await.status, 413);
}

#[tokio::test]
async fn websocket_handshake_skips_challenge_but_plain_upgrade_does_not() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.analysis = analysis_setup(CHALLENGE);
    let (_h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    // Not a valid handshake (no key): proxied as HTTP, so it must pass the gate.
    let raw = b"GET /ws HTTP/1.1\r\nHost: a\r\nAccept: text/html\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    let resp = one(proxy, raw).await;
    assert_eq!(resp.header("x-wafio-mitigated"), Some("challenge"));
}

fn rules_with_field(rule: &str) -> String {
    format!(r#"{{"path_exceptions":[{{"path":"/pay","match":"prefix","field_rules":[{rule}]}}]}}"#)
}

#[tokio::test]
async fn encrypt_rule_rewrites_the_forwarded_json_and_mask_rule_the_record() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.analysis = analysis_setup(&rules_with_field(&format!(
        r#"{{"field":"card","action":"encrypt_aes","aes_key":"{KEY}"}},{{"field":"cvv","action":"mask"}}"#
    )));
    let (h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let body = br#"{"card":"4111111111111111","cvv":"123","name":"bob"}"#;
    assert_eq!(
        one(proxy, &post("/pay/now", "application/json", body))
            .await
            .status,
        200
    );
    let seen = up.last();
    let fwd = String::from_utf8(seen.body.clone()).unwrap();
    assert!(
        !fwd.contains("4111111111111111") && fwd.contains("\"name\":\"bob\""),
        "{fwd}"
    );
    assert_eq!(
        seen.header("content-length").unwrap(),
        seen.body.len().to_string()
    );
    // The encrypted value decrypts back with the rule's key.
    let enc = fwd
        .split("\"card\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let rule = RequestFieldRule {
        field: "card".into(),
        action: "decrypt_aes".into(),
        cipher_key_hex: KEY.into(),
        ..Default::default()
    };
    let mut dec = FieldRewriter::new(&rule);
    assert_eq!(dec.apply(enc.as_bytes()).0, b"4111111111111111");
    // The stored request body is masked; the WAF saw plaintext.
    let ev = h.last_event();
    let stored = s(&ev.request_body).to_string();
    assert!(!stored.contains("\"123\""), "{stored}");
    // Other paths are untouched.
    one(proxy, &post("/other", "application/json", body)).await;
    assert_eq!(up.last().body, body);
}

#[tokio::test]
async fn response_decrypt_returns_plaintext_with_sniffed_type() {
    let rule = RequestFieldRule {
        field: "x".into(),
        action: "encrypt_aes".into(),
        cipher_key_hex: KEY.into(),
        ..Default::default()
    };
    let mut enc = FieldRewriter::new(&rule);
    let cipher: &'static [u8] = Box::leak(
        enc.apply(b"<html><body>secret</body></html>")
            .0
            .into_boxed_slice(),
    );
    let up = http_upstream_with("Content-Type: text/plain\r\n", cipher).await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.analysis = analysis_setup(&format!(
        r#"{{"path_exceptions":[{{"path":"/files","match":"prefix","response_decrypt_aes":"{KEY}"}}]}}"#
    ));
    let (_h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let resp = one(proxy, &get("/files/a")).await;
    assert_eq!(resp.text(), "<html><body>secret</body></html>");
    assert_eq!(
        resp.header("content-type"),
        Some("text/html; charset=utf-8")
    );
}

#[tokio::test]
async fn l7_flood_limits_per_app() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.analysis =
        analysis_setup(r#"{"l7_flood":{"enabled":true,"max_requests":3,"window_sec":60}}"#);
    let (h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let mut statuses = Vec::new();
    for _ in 0..5 {
        statuses.push(one(proxy, &get("/")).await.status);
    }
    assert_eq!(&statuses[..3], &[200, 200, 200]);
    assert!(statuses[3..].iter().all(|&st| st != 200), "{statuses:?}");
    assert_eq!(up.count(), 3);
    assert_eq!(s(&h.last_event().action), "block");
}

/// A custom rule's challenge under trigger on_bot_detect reaches a real browser, which the bot gate
/// alone never challenges; clients that cannot solve it, good bots, local clients and a valid
/// cookie stay exempt.
#[tokio::test]
async fn custom_rule_challenge_skips_the_on_bot_detect_trigger_only() {
    use wafio_agent_pages::challenge::issue_challenge_cookie;
    use wafio_engine_rules::{CustomGuiRule, RuleCondition};
    const SECRET_KEY: &str = "0123456789abcdef0123456789abcdef";
    let challenge_json = |allow_local: bool| {
        format!(
            r#"{{"challenge":{{"enabled":true,"type":"js_challenge","trigger":"on_bot_detect","allow_local_ips":{allow_local},"secret_key":"{SECRET_KEY}"}}}}"#
        )
    };
    let with_rule = |allow_local: bool| {
        let mut setup =
            wafio_proxy::testing::analysis_setup(challenge_json(allow_local).as_bytes());
        setup.analyze.custom_gui_rules = vec![CustomGuiRule {
            id: "r1".into(),
            enabled: true,
            action: "challenge".into(),
            conditions: vec![RuleCondition {
                field: "path".into(),
                operator: "starts_with".into(),
                value: "/rule".into(),
                ..Default::default()
            }],
            ..Default::default()
        }];
        std::sync::Arc::new(setup)
    };
    let browser = |path: &str, accept: &str, ua: &str, extra: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: app.test\r\nAccept: {accept}\r\nAccept-Language: en\r\nSec-Fetch-Mode: navigate\r\nUser-Agent: {ua}\r\n{extra}\r\n"
        )
    };
    const CHROME: &str = "Mozilla/5.0 Chrome/120";

    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.analysis = with_rule(false);
    let (h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let challenged = |r: &ReplyParts| r.header("x-wafio-mitigated") == Some("challenge");

    let r = one(proxy, browser("/rule", "text/html", CHROME, "").as_bytes()).await;
    assert!(challenged(&r), "{r:?}");
    assert_eq!(s(&h.last_event().action), "challenge");
    let before = up.count();
    // The same browser on a path no rule matches: the bot gate leaves it alone.
    let r = one(proxy, browser("/plain", "text/html", CHROME, "").as_bytes()).await;
    assert_eq!((r.status, challenged(&r)), (200, false));
    for (what, raw) in [
        (
            "non-HTML client",
            browser("/rule", "application/json", CHROME, ""),
        ),
        (
            "good bot",
            browser("/rule", "text/html", "Googlebot/2.1", ""),
        ),
        (
            "valid cookie",
            browser(
                "/rule",
                "text/html",
                CHROME,
                &format!(
                    "Cookie: _wafio_ch={}\r\n",
                    String::from_utf8(issue_challenge_cookie(
                        SECRET_KEY,
                        b"a1",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64
                    ))
                    .unwrap()
                ),
            ),
        ),
    ] {
        let r = one(proxy, raw.as_bytes()).await;
        assert_eq!((r.status, challenged(&r)), (200, false), "{what}");
    }
    assert_eq!(
        up.count(),
        before + 4,
        "the exempt requests reach the upstream"
    );

    // allow_local_ips (the default) exempts the loopback client from a rule challenge too.
    let port = free_port();
    let mut a = app("a2", port, &format!("http://{}", up.addr));
    a.analysis = with_rule(true);
    let (_h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let r = one(proxy, browser("/rule", "text/html", CHROME, "").as_bytes()).await;
    assert_eq!((r.status, challenged(&r)), (200, false));
}
