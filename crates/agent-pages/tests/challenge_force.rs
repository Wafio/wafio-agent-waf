//! A client forced into the challenge (IP reputation level 2) still passes with a valid cookie.
//! Its own test binary: the cookie network limit is process-wide.

mod common;

use common::*;
use wafio_agent_pages::challenge::*;
use wafio_agent_pages::challenge_handler::*;
use wafio_agent_pages::challenge_replay::set_cookie_network_limit;

fn browser<'a>(cookie: &'a [u8], scope: &'a [u8]) -> ChallengeRequest<'a> {
    ChallengeRequest {
        scope,
        path: b"/page",
        request_target: b"/page",
        user_agent: b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        accept: b"text/html,application/xhtml+xml",
        accept_language: b"en-US,en;q=0.9",
        sec_fetch_mode: b"navigate",
        challenge_cookie: cookie,
        ..Default::default()
    }
}

fn settings() -> ChallengeSettings {
    let mut c = challenge_settings(CHALLENGE_TYPE_JS);
    finalize_challenge_settings(&mut c);
    c
}

/// Whether a forced challenge is served for `cookie` presented on the route `scope`.
fn served(cfg: &ChallengeSettings, cookie: &[u8], scope: &str, client_ip: &[u8]) -> bool {
    challenge_if_required(
        &browser(cookie, scope.as_bytes()),
        Some(cfg),
        client_ip,
        ChallengeReason::IpReputation,
        None,
        NOW,
    )
    .is_some()
}

/// A forced challenge used to be served on every request, cookie or not, so a listed client could
/// never get through. A valid cookie passes; a missing, foreign-app or forged one does not.
#[test]
fn forced_challenge_honours_a_valid_cookie() {
    let cfg = settings();
    let good = issue_challenge_cookie(SECRET, b"app", NOW);
    let ip = b"198.51.100.5";
    assert!(served(&cfg, b"", "app", ip), "no cookie must be challenged");
    assert!(!served(&cfg, &good, "app", ip), "a valid cookie must pass");
    assert!(
        served(&cfg, &good, "other-app", ip),
        "a cookie of another app must not pass"
    );
    assert!(
        served(&cfg, b"forged:value:00", "app", ip),
        "a forged cookie must not pass"
    );
    let other_secret = issue_challenge_cookie("another-secret-key-0123456789abcd", b"app", NOW);
    assert!(
        served(&cfg, &other_secret, "app", ip),
        "a cookie signed with another key must not pass"
    );

    // Simulation mode ignores the cookie on purpose, forced or not.
    let sim = ChallengeSettings {
        simulation: true,
        ..cfg
    };
    assert!(
        served(&sim, &good, "app", ip),
        "simulation mode must serve the challenge despite the cookie"
    );
}

/// The cookie is still bound to the visitor's networks under a forced challenge.
#[test]
fn forced_challenge_cookie_stays_bound_to_networks() {
    set_cookie_network_limit(1);
    let cfg = settings();
    let cookie = issue_challenge_cookie(SECRET, b"app", NOW);
    assert!(
        !served(&cfg, &cookie, "app", b"198.51.100.1"),
        "a cookie from its own network was challenged"
    );
    assert!(
        served(&cfg, &cookie, "app", b"203.0.113.1"),
        "a cookie from a second network (limit 1) must be challenged"
    );
    assert!(
        served(&cfg, &cookie, "app", b"198.51.100.1"),
        "a revoked cookie is challenged from every network"
    );
}
