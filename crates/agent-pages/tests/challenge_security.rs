//! Single use, scope, the stage rules of the verify endpoint, the body cap and the network
//! limit per cookie, through the framework-free handler.

mod common;

use common::*;
use std::sync::Mutex;
use wafio_agent_pages::challenge::*;
use wafio_agent_pages::challenge_handler::*;
use wafio_agent_pages::challenge_replay::*;

/// `ct=adaptive` + `stage=2` form of a puzzle answer.
fn stage2<'a>(
    tok: &'a str,
    sig: &'a str,
    clicked: &'a str,
    redirect: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("token", tok),
        ("sig", sig),
        ("clicked", clicked),
        ("redirect", redirect),
        ("ct", "adaptive"),
        ("stage", "2"),
    ]
}

/// ct=adaptive in the body must not move a turnstile/hcaptcha site onto the puzzle branch (its
/// answer is readable from the DOM). An empty secret_key makes the provider verification fail
/// before any network call.
#[test]
fn ct_adaptive_is_ignored_for_provider_types() {
    for t in [CHALLENGE_TYPE_TURNSTILE, CHALLENGE_TYPE_HCAPTCHA] {
        let c = ChallengeSettings {
            secret_key: String::new(),
            site_key: "site".into(),
            ..challenge_settings(t)
        };
        let (tok, sig, clicked) = solved_puzzle("", "");
        let r = post(&c, &stage2(&tok, &sig, &clicked, "/"));
        assert!(
            !has_cookie(&r),
            "{t}: ct=adaptive puzzle answer minted a cookie"
        );
    }
}

#[test]
fn pow_token_is_single_use() {
    let c = challenge_settings(CHALLENGE_TYPE_JS);
    let (tok, sol) = solved_pow(&c, "");
    let f = [
        ("token", tok.as_str()),
        ("solution", sol.as_str()),
        ("redirect", "/"),
    ];
    assert!(has_cookie(&post(&c, &f)), "first post must mint a cookie");
    assert!(
        !has_cookie(&post(&c, &f)),
        "replayed PoW token minted a second cookie"
    );
    // "token|suffix" is the same token.
    let suffixed = format!("{tok}|again");
    let r = post(
        &c,
        &[("token", &suffixed), ("solution", &sol), ("redirect", "/")],
    );
    assert!(!has_cookie(&r), "replay with a suffix minted a cookie");
}

/// The PoW token is spent when stage 1 passes: a solved PoW cannot be replayed to draw fresh
/// puzzles without new work. js_challenge escalation (hless) has the same single outcome.
#[test]
fn stage1_spends_the_pow_token() {
    let c = challenge_settings(CHALLENGE_TYPE_ADAPTIVE);
    let (tok, sol) = solved_pow(&c, "");
    let f = [
        ("token", tok.as_str()),
        ("solution", sol.as_str()),
        ("redirect", "/"),
    ];
    assert!(
        serves_puzzle(&post(&c, &f)),
        "stage 1 pass must serve the puzzle"
    );
    assert!(
        !serves_puzzle(&post(&c, &f)),
        "replayed stage-1 proof drew another puzzle"
    );

    let js = challenge_settings(CHALLENGE_TYPE_JS);
    let (tok, sol) = solved_pow(&js, "");
    let f = [
        ("token", tok.as_str()),
        ("solution", sol.as_str()),
        ("redirect", "/"),
        ("hless", "1"),
    ];
    assert!(
        serves_puzzle(&post(&js, &f)),
        "escalation must serve the puzzle"
    );
    let again = post(&js, &f);
    assert!(
        !serves_puzzle(&again) && !has_cookie(&again),
        "replayed escalation proof drew a puzzle or a cookie"
    );
}

#[test]
fn puzzle_token_is_single_use() {
    for t in [CHALLENGE_TYPE_CLICK_PUZZLE, CHALLENGE_TYPE_ADAPTIVE] {
        let c = challenge_settings(t);
        let (tok, sig, clicked) = solved_puzzle(SECRET, "");
        let f = [
            ("token", tok.as_str()),
            ("sig", sig.as_str()),
            ("clicked", clicked.as_str()),
            ("redirect", "/"),
            ("stage", "2"),
        ];
        assert!(
            has_cookie(&post(&c, &f)),
            "{t}: first post must mint a cookie"
        );
        assert!(
            !has_cookie(&post(&c, &f)),
            "{t}: replayed puzzle minted a second cookie"
        );
    }
}

/// A token with a valid MAC is spent by any attempt: a wrong answer cannot be retried against the
/// same token, even with the right answer afterwards.
#[test]
fn wrong_puzzle_answer_spends_the_token() {
    for t in [
        CHALLENGE_TYPE_CLICK_PUZZLE,
        CHALLENGE_TYPE_ADAPTIVE,
        CHALLENGE_TYPE_JS,
    ] {
        let c = challenge_settings(t);
        let (tok, sig, clicked) = solved_puzzle(SECRET, "");
        // A correct answer clicks 1-3 cells, so "" never matches.
        assert!(
            !has_cookie(&post(&c, &stage2(&tok, &sig, "", "/"))),
            "{t}: wrong answer minted a cookie"
        );
        assert!(
            !has_cookie(&post(&c, &stage2(&tok, &sig, &clicked, "/"))),
            "{t}: right answer on an already-attempted token minted a cookie"
        );
    }
}

/// A forged token is not authentic, so it is never spent and cannot fill the spent-token table.
#[test]
fn forged_puzzle_token_is_not_recorded() {
    let c = challenge_settings(CHALLENGE_TYPE_CLICK_PUZZLE);
    for i in 0..50 {
        let tok = format!(
            "00112233445566778899aabbccddee{}|red|star|ffffffffff|{}",
            10 + i,
            "0".repeat(64)
        );
        post(
            &c,
            &[
                ("token", &tok),
                ("sig", "x"),
                ("clicked", "1"),
                ("redirect", "/"),
            ],
        );
        assert!(
            record_token_spent(tok.as_bytes(), NOW + 60, NOW),
            "forged token {i} was recorded"
        );
    }
}

/// After a failed stage 2 the visitor starts over at stage 1 (a fresh PoW): a puzzle is never
/// re-served for free, for adaptive and for js_challenge sites.
#[test]
fn failed_stage2_reserves_stage1() {
    let custom = "<html>{{WAFIO_INJECT}}</html>";
    for (name, c) in [
        ("adaptive", challenge_settings(CHALLENGE_TYPE_ADAPTIVE)),
        (
            "adaptive custom puzzle",
            ChallengeSettings {
                custom_click_puzzle_html: custom.into(),
                ..challenge_settings(CHALLENGE_TYPE_ADAPTIVE)
            },
        ),
        (
            "js_challenge ct=adaptive",
            challenge_settings(CHALLENGE_TYPE_JS),
        ),
        (
            "js custom puzzle ct=adaptv",
            ChallengeSettings {
                custom_click_puzzle_html: custom.into(),
                ..challenge_settings(CHALLENGE_TYPE_JS)
            },
        ),
    ] {
        let (tok, sig, _) = solved_puzzle(SECRET, "");
        let r = post(&c, &stage2(&tok, &sig, "", "/keep?x=1"));
        let b = body(&r);
        assert!(
            !serves_puzzle(&r) && !has_cookie(&r),
            "{name}: failed stage 2 served a puzzle or a cookie"
        );
        assert!(
            b.contains("/keep?x=1") && b.contains("challenge/verify"),
            "{name}: no stage-1 page with the redirect kept"
        );
        // An unsolvable token (never minted) also lands on stage 1, not a puzzle.
        let r = post(&c, &stage2("junk", "x", "1", "/"));
        assert!(
            !serves_puzzle(&r),
            "{name}: junk stage-2 post served a puzzle"
        );
    }
}

/// click_puzzle sites get a fresh puzzle (new token) after a wrong answer.
#[test]
fn click_puzzle_wrong_answer_serves_a_new_puzzle() {
    let c = challenge_settings(CHALLENGE_TYPE_CLICK_PUZZLE);
    let (tok, sig, _) = solved_puzzle(SECRET, "");
    let r = post(
        &c,
        &[
            ("token", &tok),
            ("sig", &sig),
            ("clicked", ""),
            ("redirect", "/"),
        ],
    );
    assert!(
        serves_puzzle(&r) && !body(&r).contains(&tok),
        "want a new puzzle with another token"
    );
    assert!(body(&r).contains("Incorrect selection"));
}

/// A cookie, PoW token or puzzle of one app must not open another app of the same agent, even
/// when both have an empty secret_key.
#[test]
fn proofs_are_scoped_to_the_app() {
    let easy = ChallengeSettings {
        secret_key: String::new(),
        ..challenge_settings(CHALLENGE_TYPE_JS)
    };
    let hard = ChallengeSettings {
        secret_key: String::new(),
        ..challenge_settings(CHALLENGE_TYPE_CLICK_PUZZLE)
    };

    // PoW minted for app-a does not mint a cookie on app-b (and the wrong-scope try spends nothing).
    let (tok, sol) = solved_pow(&easy, "app-a");
    let f = [
        ("token", tok.as_str()),
        ("solution", sol.as_str()),
        ("redirect", "/"),
    ];
    assert!(
        !has_cookie(&post_scope(&easy, "app-b", &f)),
        "PoW token of app-a minted a cookie on app-b"
    );
    assert!(
        has_cookie(&post_scope(&easy, "app-a", &f)),
        "PoW token must still work on its own app"
    );

    // A cookie from app-a does not pass app-b's gate.
    let cookie = issue_challenge_cookie("", b"app-a", NOW);
    let req = |scope: &'static [u8]| ChallengeRequest {
        scope,
        challenge_cookie: &cookie,
        ..Default::default()
    };
    assert!(
        carries_valid_cookie(&req(b"app-a"), &easy, b"192.0.2.1", NOW),
        "cookie refused in its own app"
    );
    assert!(
        !carries_valid_cookie(&req(b"app-b"), &hard, b"192.0.2.1", NOW),
        "cookie of app-a accepted by app-b"
    );

    // A puzzle answer for app-a does not mint a cookie on app-b.
    let (ptok, sig, clicked) = solved_puzzle("", "app-a");
    let pf = [
        ("token", ptok.as_str()),
        ("sig", sig.as_str()),
        ("clicked", clicked.as_str()),
        ("redirect", "/"),
    ];
    assert!(
        !has_cookie(&post_scope(&hard, "app-b", &pf)),
        "puzzle of app-a minted a cookie on app-b"
    );
    assert!(
        has_cookie(&post_scope(&hard, "app-a", &pf)),
        "puzzle must still work on its own app"
    );

    // The cookie the verify handler sets is bound to the serving app.
    let (tok, sol) = solved_pow(&easy, "app-c");
    let r = post_scope(
        &easy,
        "app-c",
        &[("token", &tok), ("solution", &sol), ("redirect", "/")],
    );
    let val = cookie_value(&r);
    assert!(verify_challenge_cookie("", b"app-c", val.as_bytes(), NOW));
    assert!(!verify_challenge_cookie("", b"app-d", val.as_bytes(), NOW));
}

/// A challenge served on an app's route verifies on that same route (the proxy passes the route's
/// app ID to both `challenge_if_required` and `process_verify_request`).
#[test]
fn challenge_served_by_a_route_verifies_on_the_same_route() {
    let mut c = ChallengeSettings {
        pow_difficulty: 4,
        ..challenge_settings(CHALLENGE_TYPE_JS)
    };
    finalize_challenge_settings(&mut c);
    let browser = ChallengeRequest {
        scope: b"route-app-1",
        path: b"/home",
        request_target: b"/home?a=1",
        user_agent: b"Mozilla/5.0 Chrome/120",
        accept: b"text/html",
        ..Default::default()
    };
    let page = challenge_if_required(
        &browser,
        Some(&c),
        b"8.8.8.8",
        ChallengeReason::BotGate,
        None,
        NOW,
    )
    .expect("a JS challenge");
    let token = page_field(&body(&page), "token").expect("the page carries a token");
    let (salt, diff) = check_pow_token(SECRET, b"route-app-1", token.as_bytes(), NOW).unwrap();
    let sol = (0..1_000_000)
        .find(|&n| check_pow_solution(&salt, n, diff))
        .unwrap()
        .to_string();
    let b = form(&[("token", &token), ("solution", &sol), ("redirect", "/")]);
    let verify = |scope: &[u8]| {
        let req = ChallengeRequest {
            scope,
            submitted_body: b.as_bytes(),
            ..Default::default()
        };
        process_verify_request(&req, Some(&c), b"1.2.3.4", &NoCaptcha, NOW)
    };
    assert!(
        !has_cookie(&verify(b"")),
        "a scope mismatch (\"\" on the verify side) rejects the token"
    );
    assert!(has_cookie(&verify(b"route-app-1")));
}

/// Type "js" (not the canonical js_challenge) used to skip the stage-2 puzzle branch while serving
/// and escalating as the JS challenge: users looped. Loaded through the rules parser it is
/// js_challenge, and a bot-escalated PoW plus the right puzzle answer yields a cookie.
#[test]
fn unknown_type_escalates_without_looping() {
    let raw =
        format!(r#"{{"enabled":true,"type":"js","secret_key":"{SECRET}","pow_difficulty":4}}"#);
    let c = ChallengeSettings::from_rules_json(raw.as_bytes()).unwrap();
    assert_eq!(c.type_, CHALLENGE_TYPE_JS);
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
        !has_cookie(&r) && serves_puzzle(&r),
        "headless PoW must escalate to the puzzle"
    );
    let page = body(&r);
    let (token, sig) = (
        page_field(&page, "token").unwrap(),
        page_field(&page, "sig").unwrap(),
    );
    // The page's own token and sig; find the answer the way a solver reading the SVG would.
    let p = GeneratedPuzzle {
        token: token.clone().into_bytes(),
        sig: sig.clone().into_bytes(),
        target_label: String::new(),
        cells: Vec::new(),
    };
    let clicked = correct_clicked(&c.secret_key, "", &p);
    let r = post(&c, &stage2(&token, &sig, &clicked, "/"));
    assert!(
        has_cookie(&r),
        "correct puzzle answer did not set a cookie: the user loops"
    );
}

#[test]
fn verify_refuses_an_oversized_body() {
    let c = challenge_settings(CHALLENGE_TYPE_JS);
    let big = format!("token={}", "a".repeat(MAX_VERIFY_BODY_BYTES));
    let r = post_raw(&c, "", big.as_bytes());
    assert_eq!((r.status, body(&r).as_str()), (413, "payload too large"));
    // Exactly at the cap is parsed.
    let at_cap = format!("token={}", "a".repeat(MAX_VERIFY_BODY_BYTES - 6));
    assert_ne!(post_raw(&c, "", at_cap.as_bytes()).status, 413);
    // A form with a realistic telemetry blob is far below the cap.
    let (tok, sol) = solved_pow(&c, "");
    let tel = "A".repeat(2500);
    let r = post(
        &c,
        &[
            ("token", &tok),
            ("solution", &sol),
            ("telemetry", &tel),
            ("redirect", "/"),
        ],
    );
    assert_ne!(r.status, 413, "a normal form was refused");
}

#[test]
fn simulation_also_spends_the_token() {
    let mut c = ChallengeSettings {
        simulation: true,
        ..challenge_settings(CHALLENGE_TYPE_JS)
    };
    let (tok, sol) = solved_pow(&c, "");
    let f = [
        ("token", tok.as_str()),
        ("solution", sol.as_str()),
        ("redirect", "/"),
    ];
    let r = post(&c, &f);
    assert!(
        r.status == 200 && !has_cookie(&r),
        "simulation success page expected, got {}",
        r.status
    );
    c.simulation = false;
    assert!(
        !has_cookie(&post(&c, &f)),
        "token spent in simulation minted a cookie later"
    );
}

/// The limit is process-wide: tests that read or change it take this lock.
static LIMIT: Mutex<()> = Mutex::new(());

struct WithMax {
    prev: i64,
    _guard: std::sync::MutexGuard<'static, ()>,
}
impl WithMax {
    fn new(n: i64) -> WithMax {
        let g = LIMIT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = current_cookie_network_limit();
        set_cookie_network_limit(n);
        WithMax { prev, _guard: g }
    }
}
impl Drop for WithMax {
    fn drop(&mut self) {
        set_cookie_network_limit(self.prev);
    }
}

#[test]
fn gate_applies_the_network_limit_to_the_resolved_client_ip() {
    let _max = WithMax::new(1);
    let c = ChallengeSettings {
        secret_key: String::new(),
        ..challenge_settings(CHALLENGE_TYPE_JS)
    };
    let cookie = issue_challenge_cookie("", b"app", NOW);
    let req = ChallengeRequest {
        scope: b"app",
        challenge_cookie: &cookie,
        ..Default::default()
    };
    assert!(
        carries_valid_cookie(&req, &c, b"192.0.2.1", NOW),
        "first network refused"
    );
    assert!(
        !carries_valid_cookie(&req, &c, b"198.51.100.1", NOW),
        "second network accepted with max 1"
    );
    assert!(
        !carries_valid_cookie(&req, &c, b"192.0.2.1", NOW),
        "revoked cookie accepted"
    );
}

#[test]
fn limit_off_and_default() {
    let _max = WithMax::new(0);
    let c = challenge_settings(CHALLENGE_TYPE_JS);
    let cookie = issue_challenge_cookie(SECRET, b"", NOW);
    let req = ChallengeRequest {
        challenge_cookie: &cookie,
        ..Default::default()
    };
    for i in 1..=30 {
        assert!(carries_valid_cookie(
            &req,
            &c,
            format!("11.{i}.0.1").as_bytes(),
            NOW
        ));
    }
    assert_eq!(
        parse_cookie_network_limit("").0,
        DEFAULT_COOKIE_NETWORK_LIMIT
    );
}
