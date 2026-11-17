//! Tests of the verify endpoint and the gate logic of the challenge handler (the local bypass
//! rule).

mod common;

use common::*;
use wafio_agent_pages::challenge::*;
use wafio_agent_pages::challenge_handler::*;
use wafio_agent_pages::crypto::{B64, encode_base64};
use wafio_agent_pages::goodbot::VerifiedBotChecker;

struct OkCaptcha;
impl CaptchaVerifier for OkCaptcha {
    fn submit_form(&self, url: &str, body: &[u8]) -> Option<Vec<u8>> {
        assert_eq!(url, TURNSTILE_VERIFY_URL);
        assert_eq!(body, b"remoteip=1.2.3.4&response=tok+1&secret=s%26k");
        Some(br#"{"Success":true}"#.to_vec())
    }
}

fn post_body(body: &str) -> ChallengeRequest<'_> {
    ChallengeRequest {
        submitted_body: body.as_bytes(),
        path: b"/_wafio/challenge/verify",
        ..Default::default()
    }
}

#[test]
fn js_challenge_headless_escalation_serves_routable_puzzle() {
    let c = challenge_settings(CHALLENGE_TYPE_JS);
    let (tok, sol) = solved_pow(&c, "");
    let r = post(
        &c,
        &[
            ("token", &tok),
            ("solution", &sol),
            ("redirect", "/"),
            ("hless", "1"),
        ],
    );
    assert!(
        r.set_cookie.is_none()
            && body(&r).contains(r#"name="ct""#)
            && body(&r).contains("adaptive")
    );
}

/// Security review: every challenge page carries a proof-of-work token; posting it back as
/// `token|x` without a solution skipped the work, and a 3-part nonce passed as difficulty 0.
#[test]
fn workless_and_non_pow_tokens_do_not_pass() {
    for t in [CHALLENGE_TYPE_JS, CHALLENGE_TYPE_ADAPTIVE] {
        let c = challenge_settings(t);
        let (pow, _) = solved_pow(&c, "");
        let nonce = String::from_utf8(issue_challenge_nonce(SECRET, NOW).unwrap()).unwrap();
        let clean_tel = "eyJkdXJhdGlvbl9tcyI6MTUwfQ==";
        for (name, pairs) in [
            (
                "pow token|x, no solution",
                vec![("token", format!("{pow}|x"))],
            ),
            (
                "pow token|, no solution",
                vec![("token", format!("{pow}|"))],
            ),
            (
                "3-part nonce|x, no solution",
                vec![("token", format!("{nonce}|x"))],
            ),
            (
                "3-part nonce + telemetry",
                vec![("token", nonce.clone()), ("telemetry", clean_tel.into())],
            ),
            (
                "3-part nonce|x + telemetry",
                vec![
                    ("token", format!("{nonce}|x")),
                    ("telemetry", clean_tel.into()),
                ],
            ),
            (
                "pow token, telemetry, no solve",
                vec![("token", pow.clone()), ("telemetry", clean_tel.into())],
            ),
        ] {
            let mut p: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
            p.push(("redirect", "/"));
            let r = post(&c, &p);
            assert!(
                !has_cookie(&r) && !body(&r).contains(r#"name="stage""#) && r.status == 200,
                "{t} / {name}: passed (cookie or puzzle served)"
            );
            assert!(
                body(&r).contains("rawToken"),
                "{t} / {name}: the challenge is served again"
            );
        }
    }
}

#[test]
fn adaptive_stage2_correct_puzzle_sets_cookie() {
    let (token, sig, clicked) = solved_puzzle(SECRET, "");
    let r = post(
        &challenge_settings(CHALLENGE_TYPE_JS),
        &[
            ("token", &token),
            ("sig", &sig),
            ("clicked", &clicked),
            ("redirect", "/"),
            ("ct", "adaptive"),
            ("stage", "2"),
        ],
    );
    assert_eq!(r.status, 302);
    let cookie = String::from_utf8(r.set_cookie.unwrap()).unwrap();
    assert!(
        cookie.starts_with("_wafio_ch=") && cookie.ends_with("; path=/; HttpOnly; SameSite=Lax"),
        "{cookie}"
    );
}

#[test]
fn js_challenge_pow_verification_and_telemetry_escalation() {
    let c = ChallengeSettings {
        pow_difficulty: 10,
        ..challenge_settings(CHALLENGE_TYPE_JS)
    };
    let token = issue_pow_token(SECRET, b"", 10, NOW).unwrap();
    let (salt, diff) = check_pow_token(SECRET, b"", &token, NOW).unwrap();
    let sol = (0..100_000)
        .find(|&n| check_pow_solution(&salt, n, diff))
        .unwrap()
        .to_string();
    let tok = String::from_utf8(token).unwrap();
    // 1. Wrong solution: rejected, no cookie, the challenge is served again.
    let wrong = failing_pow_solution(&c.secret_key, "", &tok);
    let r = post(
        &c,
        &[("token", &tok), ("solution", &wrong), ("redirect", "/")],
    );
    assert!(!has_cookie(&r) && body(&r).contains("rawToken"));
    // 2. Correct solution + clean telemetry: a cookie and a 302 (X-Forwarded-Proto https: secure).
    let clean = String::from_utf8(encode_base64(B64::Std, br#"{"dur":150}"#)).unwrap();
    let b = form(&[
        ("token", &tok),
        ("solution", &sol),
        ("telemetry", &clean),
        ("redirect", "/next"),
        ("hless", "0"),
    ]);
    let req = ChallengeRequest {
        x_forwarded_proto: b"HTTPS",
        ..post_body(&b)
    };
    let r = process_verify_request(&req, Some(&c), b"1.2.3.4", &NoCaptcha, NOW);
    assert_eq!(r.status, 302);
    assert_eq!(
        r.headers,
        vec![
            ("Location", b"/next".to_vec()),
            ("Cache-Control", b"no-store".to_vec())
        ]
    );
    assert!(
        String::from_utf8(r.set_cookie.unwrap())
            .unwrap()
            .ends_with("; HttpOnly; secure; SameSite=Lax")
    );
    // 3. Correct solution + stealth telemetry: escalates to the click puzzle. Step 2 spent the
    // first token: a PoW token has one outcome.
    let (tok3, sol3) = solved_pow(&c, "");
    let bot = String::from_utf8(encode_base64(B64::Std, br#"{"cdp":true}"#)).unwrap();
    let r = post(
        &c,
        &[
            ("token", &tok3),
            ("solution", &sol3),
            ("telemetry", &bot),
            ("redirect", "/"),
        ],
    );
    assert!(!has_cookie(&r) && body(&r).contains(r#"name="stage" value="2""#));
    // A failed PoW re-serves the JS challenge.
    let (tok4, _) = solved_pow(&c, "");
    let wrong = failing_pow_solution(&c.secret_key, "", &tok4);
    let r = post(
        &c,
        &[
            ("token", &tok4),
            ("solution", &wrong),
            ("telemetry", &clean),
        ],
    );
    assert!(
        r.status == 200 && body(&r).contains("rawToken"),
        "failed PoW re-serves the JS challenge"
    );
}

#[test]
fn verify_disabled_bad_body_turnstile_and_simulation() {
    let r = process_verify_request(&post_body(""), None, b"", &NoCaptcha, NOW);
    assert_eq!((r.status, body(&r).as_str()), (404, "not found"));
    let r = process_verify_request(
        &post_body("a=%zz"),
        Some(&challenge_settings(CHALLENGE_TYPE_JS)),
        b"",
        &NoCaptcha,
        NOW,
    );
    assert_eq!((r.status, body(&r).as_str()), (400, "bad request"));
    let mut t = challenge_settings(CHALLENGE_TYPE_TURNSTILE);
    t.secret_key = "s&k".into();
    let b = form(&[("token", "tok 1"), ("redirect", "//evil")]);
    let r = process_verify_request(&post_body(&b), Some(&t), b"1.2.3.4", &OkCaptcha, NOW);
    assert_eq!(r.status, 302);
    assert_eq!(r.headers[0], ("Location", b"/".to_vec()));
    t.simulation = true;
    let r = process_verify_request(&post_body(&b), Some(&t), b"1.2.3.4", &OkCaptcha, NOW);
    assert!(r.status == 200 && body(&r).contains("Simulation Mode") && r.set_cookie.is_none());
    let r = process_verify_request(&post_body(&b), Some(&t), b"1.2.3.4", &NoCaptcha, NOW);
    assert!(body(&r).contains("cf-turnstile"));
}

#[test]
fn gate_skips_and_serves() {
    let mut c = challenge_settings(CHALLENGE_TYPE_JS);
    finalize_challenge_settings(&mut c);
    let browser = ChallengeRequest {
        path: b"/page",
        request_target: b"/page?x=1",
        user_agent: b"Mozilla/5.0 Chrome/120",
        accept: b"text/html",
        accept_language: b"en",
        sec_fetch_mode: b"navigate",
        ..Default::default()
    };
    let r = challenge_if_required(
        &browser,
        Some(&c),
        b"8.8.8.8",
        ChallengeReason::BotGate,
        None,
        NOW,
    )
    .expect("challenge");
    assert_eq!(
        r.headers.last().unwrap(),
        &("X-WAFio-Mitigated", b"challenge".to_vec())
    );
    assert!(body(&r).contains("/page?x=1"));
    for skip in [
        ChallengeRequest {
            path: b"/app.js",
            ..browser
        },
        ChallengeRequest {
            path: b"/_wafio/x",
            ..browser
        },
        ChallengeRequest {
            accept: b"application/json",
            ..browser
        },
        ChallengeRequest {
            x_requested_with: b"xmlhttprequest",
            ..browser
        },
        ChallengeRequest {
            local_socket_client: true,
            ..browser
        },
        ChallengeRequest {
            user_agent: b"Googlebot/2.1",
            ..browser
        },
    ] {
        assert!(
            challenge_if_required(
                &skip,
                Some(&c),
                b"8.8.8.8",
                ChallengeReason::BotGate,
                None,
                NOW
            )
            .is_none()
        );
    }
    let local_off = ChallengeSettings {
        allow_local_ips: Some(false),
        ..c.clone()
    };
    assert!(
        challenge_if_required(
            &ChallengeRequest {
                local_socket_client: true,
                ..browser
            },
            Some(&local_off),
            b"",
            ChallengeReason::BotGate,
            None,
            NOW
        )
        .is_some()
    );
    let cookie = issue_challenge_cookie(SECRET, b"", NOW);
    let with_cookie = ChallengeRequest {
        challenge_cookie: &cookie,
        ..browser
    };
    assert!(
        challenge_if_required(
            &with_cookie,
            Some(&c),
            b"8.8.8.8",
            ChallengeReason::BotGate,
            None,
            NOW
        )
        .is_none()
    );
    // A forced challenge lets the same valid cookie pass too (tests/challenge_force.rs).
    assert!(
        challenge_if_required(
            &with_cookie,
            Some(&c),
            b"8.8.8.8",
            ChallengeReason::IpReputation,
            None,
            NOW
        )
        .is_none()
    );
    let gb = VerifiedBotChecker::new();
    gb.load_ranges_from_cidrs(&["8.8.8.0/24"]);
    assert!(
        challenge_if_required(
            &browser,
            Some(&c),
            b"8.8.8.8",
            ChallengeReason::BotGate,
            Some(&gb),
            NOW
        )
        .is_none()
    );
    let on_bot = ChallengeSettings {
        trigger: "on_bot_detect".into(),
        ..c.clone()
    };
    assert!(
        challenge_if_required(
            &browser,
            Some(&on_bot),
            b"8.8.8.8",
            ChallengeReason::BotGate,
            None,
            NOW
        )
        .is_none()
    );
    assert!(looks_automated(&ChallengeRequest {
        sec_fetch_mode: b"",
        ..browser
    }));
    assert!(looks_automated(&ChallengeRequest {
        user_agent: b"curl/8",
        ..browser
    }));
}

/// A challenge a custom rule asks for skips only the on_bot_detect trigger; every other exemption
/// of the bot gate still holds.
#[test]
fn rule_challenge_skips_only_the_trigger() {
    let browser = ChallengeRequest {
        path: b"/page",
        request_target: b"/page",
        user_agent: b"Mozilla/5.0 Chrome/120",
        accept: b"text/html",
        accept_language: b"en",
        sec_fetch_mode: b"navigate",
        ..Default::default()
    };
    let settings = |trigger: &str| {
        let mut c = ChallengeSettings {
            trigger: trigger.into(),
            ..challenge_settings(CHALLENGE_TYPE_JS)
        };
        finalize_challenge_settings(&mut c);
        c
    };
    let ask = |req: &ChallengeRequest,
               cfg: &ChallengeSettings,
               reason: ChallengeReason,
               good_bots: Option<&VerifiedBotChecker>| {
        challenge_if_required(req, Some(cfg), b"8.8.8.8", reason, good_bots, NOW).is_some()
    };
    let (gate, rule, iprep) = (
        ChallengeReason::BotGate,
        ChallengeReason::CustomRule,
        ChallengeReason::IpReputation,
    );

    // on_bot_detect: a real browser is challenged by a rule, and only by a rule or a reputation hit.
    let on_bot = settings("on_bot_detect");
    assert!(!looks_automated(&browser));
    assert!(!ask(&browser, &on_bot, gate, None));
    assert!(ask(&browser, &on_bot, rule, None));
    assert!(ask(&browser, &on_bot, iprep, None));

    // trigger always: the gate and a rule behave the same.
    let always = settings("always");
    assert!(ask(&browser, &always, gate, None));
    assert!(ask(&browser, &always, rule, None));

    // Challenge off for the app: nothing to serve, whatever the reason.
    let off = ChallengeSettings {
        enabled: false,
        ..on_bot.clone()
    };
    assert!(!ask(&browser, &off, rule, None));
    assert!(challenge_if_required(&browser, None, b"8.8.8.8", rule, None, NOW).is_none());

    // Clients that cannot solve the page.
    for skip in [
        ChallengeRequest {
            accept: b"application/json",
            ..browser
        },
        ChallengeRequest {
            x_requested_with: b"xmlhttprequest",
            ..browser
        },
        ChallengeRequest {
            path: b"/app.js",
            ..browser
        },
        ChallengeRequest {
            path: b"/_wafio/x",
            ..browser
        },
    ] {
        assert!(!ask(&skip, &on_bot, rule, None));
    }

    // Local clients: exempt by default, challenged when allow_local_ips is off.
    let local = ChallengeRequest {
        local_socket_client: true,
        ..browser
    };
    assert!(!ask(&local, &on_bot, rule, None));
    let local_off = ChallengeSettings {
        allow_local_ips: Some(false),
        ..on_bot.clone()
    };
    assert!(ask(&local, &local_off, rule, None));

    // Good bots stay exempt for a rule, by user agent and by verified address; not for a reputation hit.
    let googlebot = ChallengeRequest {
        user_agent: b"Googlebot/2.1",
        ..browser
    };
    assert!(!ask(&googlebot, &always, rule, None));
    assert!(ask(&googlebot, &always, iprep, None));
    let verified = VerifiedBotChecker::new();
    verified.load_ranges_from_cidrs(&["8.8.8.0/24"]);
    assert!(!ask(&browser, &on_bot, rule, Some(&verified)));
    assert!(ask(&browser, &on_bot, iprep, Some(&verified)));

    // A valid cookie passes; simulation mode ignores it and always shows the page.
    let cookie = issue_challenge_cookie(SECRET, b"", NOW);
    let solved = ChallengeRequest {
        challenge_cookie: &cookie,
        ..browser
    };
    assert!(!ask(&solved, &on_bot, rule, None));
    let simulation = ChallengeSettings {
        simulation: true,
        ..on_bot
    };
    assert!(ask(&solved, &simulation, rule, None));
}

#[test]
fn ip_rep_block_page_formats() {
    let r = respond_ip_reputation_block(None, b"1.2.3.4");
    assert!(r.status == 403 && body(&r).contains("FireHOL"));
    let c = ChallengeSettings {
        ip_rep_block_format: "json".into(),
        ..Default::default()
    };
    assert!(
        body(&respond_ip_reputation_block(Some(&c), b"<ip>")).contains(r#""ip": "\u003cip\u003e""#)
    );
    let c = ChallengeSettings {
        custom_ip_rep_block_html: "IP {{WAFIO_IP}}".into(),
        ..Default::default()
    };
    assert_eq!(
        body(&respond_ip_reputation_block(Some(&c), b"<ip>")),
        "IP <ip>"
    );
}

#[test]
fn set_cookie_layout() {
    assert_eq!(
        challenge_set_cookie(b"v", 3600, true),
        b"_wafio_ch=v; max-age=3600; path=/; HttpOnly; secure; SameSite=Lax"
    );
    assert_eq!(
        challenge_set_cookie(b"v", 0, false),
        b"_wafio_ch=v; path=/; HttpOnly; SameSite=Lax"
    );
    assert_eq!(
        challenge_set_cookie(b"v", -5, false),
        b"_wafio_ch=v; max-age=0; path=/; HttpOnly; SameSite=Lax"
    );
    assert!(captcha_success(br#"{"success":true}"#));
    assert!(!captcha_success(br#"{"success":"true"}"#));
    assert!(!captcha_success(b"[]"));
}
