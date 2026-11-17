//! Helpers shared by the challenge handler tests (not a test binary of its own).
#![allow(dead_code)]

use wafio_agent_pages::challenge::*;
use wafio_agent_pages::challenge_handler::*;

pub const SECRET: &str = "test-secret-key-0123456789abcdef";
pub const NOW: i64 = 1_800_000_000;

pub struct NoCaptcha;
impl CaptchaVerifier for NoCaptcha {
    fn submit_form(&self, _: &str, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

pub fn challenge_settings(t: &str) -> ChallengeSettings {
    ChallengeSettings {
        enabled: true,
        type_: t.into(),
        secret_key: SECRET.into(),
        ..Default::default()
    }
}

pub fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                k,
                String::from_utf8(wafio_bytetext::url::escape_query_component(v.as_bytes()))
                    .unwrap()
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

pub fn body(r: &PageResponse) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

/// The verify handler for a POST of `pairs` on the route `scope`, from 1.2.3.4.
pub fn post_scope(cfg: &ChallengeSettings, scope: &str, pairs: &[(&str, &str)]) -> PageResponse {
    post_raw(cfg, scope, form(pairs).as_bytes())
}

pub fn post_raw(cfg: &ChallengeSettings, scope: &str, raw: &[u8]) -> PageResponse {
    let req = ChallengeRequest {
        scope: scope.as_bytes(),
        submitted_body: raw,
        path: b"/_wafio/challenge/verify",
        ..Default::default()
    };
    process_verify_request(&req, Some(cfg), b"1.2.3.4", &NoCaptcha, NOW)
}

pub fn post(cfg: &ChallengeSettings, pairs: &[(&str, &str)]) -> PageResponse {
    post_scope(cfg, "", pairs)
}

pub fn has_cookie(r: &PageResponse) -> bool {
    r.set_cookie
        .as_deref()
        .is_some_and(|c| c.starts_with(b"_wafio_ch="))
}

/// The cookie value a response sets.
pub fn cookie_value(r: &PageResponse) -> String {
    let c = String::from_utf8(r.set_cookie.clone().expect("a Set-Cookie")).unwrap();
    c.trim_start_matches("_wafio_ch=")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// Whether the response is a click-puzzle page.
pub fn serves_puzzle(r: &PageResponse) -> bool {
    body(r).contains(r#"name="clicked""#)
}

/// A fresh PoW token for `scope` (difficulty 4) and a solution of it.
pub fn solved_pow(cfg: &ChallengeSettings, scope: &str) -> (String, String) {
    let tok = issue_pow_token(&cfg.secret_key, scope.as_bytes(), 4, NOW).unwrap();
    let (salt, diff) = check_pow_token(&cfg.secret_key, scope.as_bytes(), &tok, NOW).unwrap();
    let n = (0..1_000_000)
        .find(|&n| check_pow_solution(&salt, n, diff))
        .expect("PoW solution");
    (String::from_utf8(tok).unwrap(), n.to_string())
}

/// The first number that does not solve `token`; a fixed wrong number solves one token in 2^difficulty.
pub fn failing_pow_solution(secret: &str, scope: &str, token: &str) -> String {
    let (salt, diff) = check_pow_token(secret, scope.as_bytes(), token.as_bytes(), NOW).unwrap();
    (0..)
        .find(|&n| !check_pow_solution(&salt, n, diff))
        .expect("a failing number")
        .to_string()
}

/// The clicked-cell CSV the puzzle's sig commits to: the token carries no answer, so every mask
/// (512) is tried against the validator.
pub fn correct_clicked(secret: &str, scope: &str, p: &GeneratedPuzzle) -> String {
    (0..512u32)
        .map(|mask| {
            (0..9)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",")
        })
        .find(|csv| {
            check_click_puzzle_token(
                secret,
                scope.as_bytes(),
                &p.token,
                &p.sig,
                csv.as_bytes(),
                NOW,
            )
        })
        .expect("a clicked mask matches the puzzle sig")
}

/// (token, sig, clicked) of a fresh puzzle for `scope`.
pub fn solved_puzzle(secret: &str, scope: &str) -> (String, String, String) {
    let p = issue_click_puzzle_token(secret, scope.as_bytes(), NOW).unwrap();
    let clicked = correct_clicked(secret, scope, &p);
    (
        String::from_utf8(p.token).unwrap(),
        String::from_utf8(p.sig).unwrap(),
        clicked,
    )
}

/// The first `name="<field>"` input of a page that carries a `value="..."`.
pub fn page_field(page: &str, field: &str) -> Option<String> {
    let needle = format!(r#"name="{field}""#);
    page.match_indices(&needle).find_map(|(i, _)| {
        let tag_end = page[i..].find('>')? + i;
        let tag = &page[i..tag_end];
        let v = tag.find(r#"value=""#)? + 7;
        let end = tag[v..].find('"')? + v;
        Some(tag[v..end].to_string())
    })
}
