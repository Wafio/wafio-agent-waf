//! The challenge handler: when to challenge, which page to serve, the IP reputation block
//! page and `POST /_wafio/challenge/verify`. Framework-free: the proxy fills
//! `ChallengeRequest` from the request and writes `PageResponse` back.

use crate::challenge::*;
use crate::challenge_replay::{cookie_network_allowed, pow_token_deadline, record_token_spent};
use crate::goodbot::VerifiedBotChecker;
use wafio_bytetext::strings::{contains, eq_ignore_case, to_lowercase};
use wafio_bytetext::url::{escape_query_component, first_query_value, parse_query};
use wafio_domain::json_text::{Value, key_matches, parse};

/// The request fields the challenge gate reads (header values: first value, "" when absent).
#[derive(Clone, Copy, Debug, Default)]
pub struct ChallengeRequest<'a> {
    /// The app ID of the serving route: every token and cookie is bound to it, "" outside
    /// a route.
    pub scope: &'a [u8],
    /// The decoded, normalised path.
    pub path: &'a [u8],
    /// The request target.
    pub request_target: &'a [u8],
    pub user_agent: &'a [u8],
    pub accept: &'a [u8],
    pub x_requested_with: &'a [u8],
    pub sec_ch_ua: &'a [u8],
    pub accept_language: &'a [u8],
    pub sec_fetch_mode: &'a [u8],
    pub sec_fetch_site: &'a [u8],
    pub x_forwarded_proto: &'a [u8],
    /// The `_wafio_ch` cookie.
    pub challenge_cookie: &'a [u8],
    /// Whether the request came over TLS.
    pub over_tls: bool,
    /// Whether the client connected over a local socket (agent-io client_ip).
    pub local_socket_client: bool,
    /// The POST body (verify endpoint only).
    pub submitted_body: &'a [u8],
}

/// What the handler wrote to the response. `content_type` None = never set;
/// headers in the order they were set (a second set replaces).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageResponse {
    pub status: u16,
    pub content_type: Option<&'static str>,
    pub headers: Vec<(&'static str, Vec<u8>)>,
    /// `Set-Cookie` value.
    pub set_cookie: Option<Vec<u8>>,
    pub body: Vec<u8>,
}

impl Default for PageResponse {
    fn default() -> Self {
        PageResponse {
            status: 200,
            content_type: None,
            headers: Vec::new(),
            set_cookie: None,
            body: Vec::new(),
        }
    }
}

impl PageResponse {
    fn replace_header(&mut self, k: &'static str, v: &[u8]) {
        if let Some(h) = self
            .headers
            .iter_mut()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
        {
            h.1 = v.to_vec();
        } else {
            self.headers.push((k, v.to_vec()));
        }
    }

    fn html_page(&mut self, page: Vec<u8>, nosniff: bool) {
        self.status = 200;
        self.content_type = Some("text/html; charset=utf-8");
        self.replace_header("Cache-Control", b"no-store, no-cache, must-revalidate");
        if nosniff {
            self.replace_header("X-Content-Type-Options", b"nosniff");
        }
        self.body = page;
    }
}

/// Outbound CAPTCHA verification, done by the caller's HTTP client.
pub trait CaptchaVerifier {
    /// POSTs `application/x-www-form-urlencoded` body to url; the response body, or None
    /// on a transport or read error, a timeout, or an answer longer than the verifier accepts.
    fn submit_form(&self, url: &str, body: &[u8]) -> Option<Vec<u8>>;
}

const NON_PAGE_EXTENSIONS: [&[u8]; 20] = [
    b".css", b".js", b".mjs", b".png", b".jpg", b".jpeg", b".gif", b".webp", b".svg", b".ico",
    b".woff", b".woff2", b".ttf", b".eot", b".otf", b".map", b".mp4", b".mp3", b".ogg", b".webm",
];

const BOT_USER_AGENT_PATTERN: [&[u8]; 44] = [
    b"curl/",
    b"wget/",
    b"python-requests",
    b"python-urllib",
    b"python/",
    b"go-http-client/",
    b"java/",
    b"apache-httpclient",
    b"okhttp/",
    b"libwww-perl",
    b"lwp-",
    b"scrapy/",
    b"httpx/",
    b"aiohttp/",
    b"urllib3/",
    b"http.rb/",
    b"faraday/",
    b"axios/",
    b"got/",
    b"node-fetch/",
    b"superagent/",
    b"grpc-go/",
    b"grpc-java/",
    b"postman-runtime",
    b"insomnia/",
    b"pycurl",
    b"playwright",
    b"puppeteer",
    b"selenium",
    b"headlesschrome",
    b"phantomjs",
    b"colly",
    b"undici",
    b"resty",
    b"gptbot",
    b"chatgpt-user",
    b"claudebot",
    b"anthropic-ai",
    b"bytespider",
    b"ccbot",
    b"perplexitybot",
    b"diffbot",
    b"facebookbot",
    b"amazonbot",
];
const BOT_UA_TAIL: [&[u8]; 3] = [b"omgilibot", b"youbot", b"applebot-extended"];

/// Header heuristics for trigger "on_bot_detect".
pub fn looks_automated(req: &ChallengeRequest) -> bool {
    let ua = to_lowercase(req.user_agent);
    if ua.is_empty() {
        return true;
    }
    if BOT_USER_AGENT_PATTERN
        .iter()
        .chain(BOT_UA_TAIL.iter())
        .any(|p| contains(&ua, p))
    {
        return true;
    }
    let sec_ch_ua = to_lowercase(req.sec_ch_ua);
    if contains(&sec_ch_ua, b"headlesschrome") || contains(&ua, b"headlesschrome") {
        return true;
    }
    if req.accept_language.is_empty() {
        return true;
    }
    let is_browser_ua = contains(&ua, b"mozilla/")
        && (contains(&ua, b"chrome/")
            || contains(&ua, b"firefox/")
            || contains(&ua, b"safari/")
            || contains(&ua, b"edg/"));
    is_browser_ua
        && req.sec_fetch_mode.is_empty()
        && req.sec_fetch_site.is_empty()
        && sec_ch_ua.is_empty()
}

/// Internal paths, non-HTML Accept, XHR, static assets.
pub fn can_skip_challenge(req: &ChallengeRequest) -> bool {
    if req.path.starts_with(b"/_wafio/") {
        return true;
    }
    if !req.accept.is_empty() && !contains(req.accept, b"text/html") {
        return true;
    }
    if eq_ignore_case(req.x_requested_with, b"XMLHttpRequest") {
        return true;
    }
    if let Some(i) = req.path.iter().rposition(|&c| c == b'.')
        && NON_PAGE_EXTENSIONS.contains(&to_lowercase(&req.path[i..]).as_slice())
    {
        return true;
    }
    false
}

/// A valid, unexpired cookie for this scope and secret, presented from
/// a network it is still allowed to use (`client_ip` is the resolved client).
pub fn carries_valid_cookie(
    req: &ChallengeRequest,
    cfg: &ChallengeSettings,
    client_ip: &[u8],
    now: i64,
) -> bool {
    if req.challenge_cookie.is_empty() {
        return false;
    }
    decode_challenge_cookie(&cfg.secret_key, req.scope, req.challenge_cookie, now)
        .is_some_and(|(id, expiry)| cookie_network_allowed(&id, expiry, client_ip))
}

fn redirect_or_uri(redirect_to: &[u8], req: &ChallengeRequest) -> Vec<u8> {
    let r = if redirect_to.is_empty() {
        req.request_target
    } else {
        redirect_to
    };
    if r.is_empty() {
        b"/".to_vec()
    } else {
        r.to_vec()
    }
}

fn required_pow_difficulty(cfg: &ChallengeSettings) -> i64 {
    if cfg.pow_difficulty <= 0 {
        STANDARD_POW_DIFFICULTY
    } else {
        cfg.pow_difficulty
    }
}

pub fn respond_with_js_challenge(
    resp: &mut PageResponse,
    req: &ChallengeRequest,
    cfg: &ChallengeSettings,
    redirect_to: &[u8],
    now: i64,
) {
    let Ok(nonce) = issue_pow_token(
        &cfg.secret_key,
        req.scope,
        required_pow_difficulty(cfg),
        now,
    ) else {
        return;
    };
    let redirect_to = redirect_or_uri(redirect_to, req);
    let page = if !cfg.custom_js_challenge_html.is_empty() {
        fill_custom_page(
            cfg.custom_js_challenge_html.as_bytes(),
            b"{{WAFIO_INJECT}}",
            &render_js_challenge_inline(&nonce, &redirect_to),
        )
    } else {
        render_js_challenge_page(&nonce, &redirect_to)
    };
    resp.html_page(page, true);
}

fn serve_captcha(
    resp: &mut PageResponse,
    req: &ChallengeRequest,
    cfg: &ChallengeSettings,
    redirect_to: &[u8],
    now: i64,
    turnstile: bool,
) {
    let Ok(nonce) = issue_challenge_nonce(&cfg.secret_key, now) else {
        return;
    };
    let redirect_to = redirect_or_uri(redirect_to, req);
    let page = if turnstile {
        render_turnstile_page(cfg.site_key.as_bytes(), &nonce, &redirect_to)
    } else {
        render_hcaptcha_page(cfg.site_key.as_bytes(), &nonce, &redirect_to)
    };
    resp.html_page(page, true);
}

pub fn respond_with_turnstile(
    resp: &mut PageResponse,
    req: &ChallengeRequest,
    cfg: &ChallengeSettings,
    redirect_to: &[u8],
    now: i64,
) {
    serve_captcha(resp, req, cfg, redirect_to, now, true);
}

pub fn respond_with_hcaptcha(
    resp: &mut PageResponse,
    req: &ChallengeRequest,
    cfg: &ChallengeSettings,
    redirect_to: &[u8],
    now: i64,
) {
    serve_captcha(resp, req, cfg, redirect_to, now, false);
}

pub fn respond_with_click_puzzle(
    resp: &mut PageResponse,
    req: &ChallengeRequest,
    cfg: &ChallengeSettings,
    redirect_to: &[u8],
    now: i64,
) {
    let redirect_to = redirect_or_uri(redirect_to, req);
    let page = if !cfg.custom_click_puzzle_html.is_empty() {
        let Ok(widget) =
            render_click_puzzle_widget(&cfg.secret_key, req.scope, &redirect_to, b"", b"", now)
        else {
            return;
        };
        fill_custom_page(
            cfg.custom_click_puzzle_html.as_bytes(),
            b"{{WAFIO_INJECT}}",
            &widget,
        )
    } else {
        let Ok(p) = render_click_page(&cfg.secret_key, req.scope, &redirect_to, b"", now) else {
            return;
        };
        p
    };
    resp.html_page(page, true);
}

/// The adaptive challenge, stage 1: JS.
pub fn respond_with_adaptive(
    resp: &mut PageResponse,
    req: &ChallengeRequest,
    cfg: &ChallengeSettings,
    redirect_to: &[u8],
    now: i64,
) {
    let Ok(nonce) = issue_pow_token(
        &cfg.secret_key,
        req.scope,
        required_pow_difficulty(cfg),
        now,
    ) else {
        return;
    };
    let redirect_to = redirect_or_uri(redirect_to, req);
    let page = if !cfg.custom_js_challenge_html.is_empty() {
        fill_custom_page(
            cfg.custom_js_challenge_html.as_bytes(),
            b"{{WAFIO_INJECT}}",
            &render_js_challenge_inline(&nonce, &redirect_to),
        )
    } else {
        render_adaptive_js_page(&nonce, &redirect_to)
    };
    resp.html_page(page, true);
}

/// Why the interactive gate is asked to challenge; it decides which exemptions still apply.
/// Whatever the reason, the app must have the challenge enabled, clients that cannot solve it,
/// local clients (`allow_local_ips`) and holders of a valid cookie are never challenged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeReason {
    /// The pre-WAF bot gate: the app's trigger and the good-bot exemptions apply.
    BotGate,
    /// A custom rule asked for a challenge: skips the trigger only, so a real browser is
    /// challenged under `on_bot_detect` while verified good bots stay exempt.
    CustomRule,
    /// An IP reputation hit: skips the trigger and the good-bot exemptions.
    IpReputation,
}

/// Some(response) when a challenge was served (do not proxy).
pub fn challenge_if_required(
    req: &ChallengeRequest,
    cfg: Option<&ChallengeSettings>,
    client_ip: &[u8],
    reason: ChallengeReason,
    good_bot_ips: Option<&VerifiedBotChecker>,
    now: i64,
) -> Option<PageResponse> {
    let cfg = cfg.filter(|c| c.enabled)?;
    if can_skip_challenge(req) {
        return None;
    }
    if cfg.allow_local_ips.unwrap_or(true) && req.local_socket_client {
        return None;
    }
    let good_bots_exempt = reason != ChallengeReason::IpReputation;
    if good_bots_exempt && good_bot_ips.is_some_and(|g| g.is_verified_bot_address(client_ip)) {
        return None;
    }
    if good_bots_exempt && cfg.matches_good_bot(req.user_agent) {
        return None;
    }
    if reason == ChallengeReason::BotGate && cfg.trigger == "on_bot_detect" && !looks_automated(req)
    {
        return None;
    }
    // A challenge asked for by a rule or by IP reputation still lets a valid cookie pass: it is
    // signed, scoped to the app and bound to the visitor's networks, so a client that solved the
    // challenge is not sent back to it on every request. Simulation mode ignores the cookie so the
    // page always shows.
    if !cfg.simulation && carries_valid_cookie(req, cfg, client_ip, now) {
        return None;
    }
    let request_uri = sanitize_redirect_target(req.request_target);
    let mut resp = PageResponse::default();
    match cfg.type_.as_str() {
        CHALLENGE_TYPE_TURNSTILE => respond_with_turnstile(&mut resp, req, cfg, &request_uri, now),
        CHALLENGE_TYPE_HCAPTCHA => respond_with_hcaptcha(&mut resp, req, cfg, &request_uri, now),
        CHALLENGE_TYPE_CLICK_PUZZLE => {
            respond_with_click_puzzle(&mut resp, req, cfg, &request_uri, now)
        }
        CHALLENGE_TYPE_ADAPTIVE => respond_with_adaptive(&mut resp, req, cfg, &request_uri, now),
        _ => respond_with_js_challenge(&mut resp, req, cfg, &request_uri, now),
    }
    resp.replace_header("X-WAFio-Mitigated", b"challenge");
    Some(resp)
}

/// 403 in the configured format; `remote_ip` is the remote address as text.
pub fn respond_ip_reputation_block(
    cfg: Option<&ChallengeSettings>,
    remote_ip: &[u8],
) -> PageResponse {
    let mut resp = PageResponse {
        status: 403,
        ..Default::default()
    };
    resp.replace_header("Cache-Control", b"no-store, no-cache, must-revalidate");
    let format = cfg.map_or("", |c| c.ip_rep_block_format.as_str());
    let custom = |f: fn(&ChallengeSettings) -> &String| {
        cfg.map(f).filter(|s| !s.is_empty()).map(|s| s.as_bytes())
    };
    match format {
        "json" => {
            let tmpl = custom(|c| &c.custom_ip_rep_block_json)
                .unwrap_or(STOCK_IP_REP_BLOCK_JSON.as_bytes());
            resp.content_type = Some("application/json; charset=utf-8");
            resp.body = wafio_bytetext::strings::replace_all(
                tmpl,
                b"{{WAFIO_IP}}",
                &crate::block_response::escape_for_json(remote_ip),
            );
        }
        "xml" => {
            let tmpl =
                custom(|c| &c.custom_ip_rep_block_xml).unwrap_or(STOCK_IP_REP_BLOCK_XML.as_bytes());
            resp.content_type = Some("application/xml; charset=utf-8");
            resp.body = wafio_bytetext::strings::replace_all(
                tmpl,
                b"{{WAFIO_IP}}",
                &crate::block_response::escape_for_xml(remote_ip),
            );
        }
        _ => {
            resp.content_type = Some("text/html; charset=utf-8");
            resp.body = match custom(|c| &c.custom_ip_rep_block_html) {
                Some(t) => wafio_bytetext::strings::replace_all(t, b"{{WAFIO_IP}}", remote_ip),
                None => crate::templates::IP_REP_BLOCK_DEFAULT_HTML
                    .as_bytes()
                    .to_vec(),
            };
        }
    }
    resp
}

const INCORRECT_SELECTION: &[u8] = "Incorrect selection — please try again.".as_bytes();

/// Caps the verify form (token, solution, ~2 KB telemetry, redirect and puzzle
/// fields are far below it) before it is parsed.
pub const MAX_VERIFY_BODY_BYTES: usize = 16 << 10;

/// The stage-2 click puzzle (adaptive flow, or a js challenge escalated for automation
/// signals).
fn respond_stage2_puzzle(
    resp: &mut PageResponse,
    req: &ChallengeRequest,
    cfg: &ChallengeSettings,
    redirect_to: &[u8],
    now: i64,
) {
    let page = if !cfg.custom_click_puzzle_html.is_empty() {
        render_click_puzzle_widget(
            &cfg.secret_key,
            req.scope,
            redirect_to,
            b"",
            ADAPTIVE_STAGE2,
            now,
        )
        .ok()
        .map(|widget| {
            fill_custom_page(
                cfg.custom_click_puzzle_html.as_bytes(),
                b"{{WAFIO_INJECT}}",
                &widget,
            )
        })
    } else {
        render_adaptive_click_page(&cfg.secret_key, req.scope, redirect_to, b"", now).ok()
    };
    if let Some(page) = page {
        resp.html_page(page, false);
    }
}

/// Starts the challenge over after a failed attempt: a fresh PoW token (adaptive
/// stage 1, or the JS challenge), never a puzzle for free.
fn hold_stage1_token(
    resp: &mut PageResponse,
    req: &ChallengeRequest,
    cfg: &ChallengeSettings,
    redirect_to: &[u8],
    now: i64,
) {
    if cfg.type_ == CHALLENGE_TYPE_ADAPTIVE {
        respond_with_adaptive(resp, req, cfg, redirect_to, now);
    } else {
        respond_with_js_challenge(resp, req, cfg, redirect_to, now);
    }
}

/// Marks the PoW token (without any "|proof" suffix) spent; false when it already was.
fn consume_pow_token(token: &[u8], now: i64) -> bool {
    let pow = token.split(|&c| c == b'|').next().unwrap_or_default();
    record_token_spent(pow, pow_token_deadline(pow, now), now)
}

/// Checks a puzzle answer. A token whose own MAC is valid and unexpired is spent
/// on every attempt, right or wrong; one already spent fails.
fn check_puzzle_answer(
    cfg: &ChallengeSettings,
    scope: &[u8],
    token: &[u8],
    sig: &[u8],
    clicked: &[u8],
    now: i64,
) -> bool {
    let Some(expiry) = click_puzzle_expiry(&cfg.secret_key, scope, token, now) else {
        return false;
    };
    if !record_token_spent(token, expiry, now) {
        return false;
    }
    check_click_puzzle_token(&cfg.secret_key, scope, token, sig, clicked, now)
}

/// Handles `POST /_wafio/challenge/verify`; `req.scope` is the app ID of the
/// serving route (every token and cookie is bound to it). On success it sets a signed session
/// cookie and redirects to the original URL; in simulation mode it shows a success page instead.
/// On failure it re-serves the challenge from its first step.
pub fn process_verify_request(
    req: &ChallengeRequest,
    cfg: Option<&ChallengeSettings>,
    client_ip: &[u8],
    captcha: &dyn CaptchaVerifier,
    now: i64,
) -> PageResponse {
    let mut resp = PageResponse::default();
    let Some(cfg) = cfg.filter(|c| c.enabled) else {
        resp.status = 404;
        resp.body = b"not found".to_vec();
        return resp;
    };
    if req.submitted_body.len() > MAX_VERIFY_BODY_BYTES {
        resp.status = 413;
        resp.body = b"payload too large".to_vec();
        return resp;
    }
    let (params, err) = parse_query(req.submitted_body);
    if err.is_some() {
        resp.status = 400;
        resp.body = b"bad request".to_vec();
        return resp;
    }
    let get = |k: &[u8]| first_query_value(&params, k);
    let (token, solution, telemetry, hless) = (
        get(b"token"),
        get(b"solution"),
        get(b"telemetry"),
        get(b"hless"),
    );
    let redirect_to = sanitize_redirect_target(get(b"redirect"));
    let mut verified = false;

    // Adaptive 2-stage challenge: ct=adaptive in the POST body marks the stage-2 puzzle, honoured
    // only for adaptive and js_challenge (which escalates bots to it); it must not let a
    // turnstile/hcaptcha/click_puzzle site be passed with another type's proof.
    if cfg.type_ == CHALLENGE_TYPE_ADAPTIVE
        || (cfg.type_ == CHALLENGE_TYPE_JS && get(b"ct") == b"adaptive")
    {
        if get(b"stage") == b"2" {
            // Stage 2: verify the click puzzle. A failure restarts at stage 1 (a new PoW), so a
            // puzzle is never handed out without proof of work.
            if !check_puzzle_answer(cfg, req.scope, token, get(b"sig"), get(b"clicked"), now) {
                hold_stage1_token(&mut resp, req, cfg, &redirect_to, now);
                return resp;
            }
            // Both stages passed: set the full cookie (or show the simulation success page).
            if cfg.simulation {
                respond_simulation_success(&mut resp, &redirect_to);
            } else {
                issue_cookie_and_redirect(&mut resp, req, cfg, &redirect_to, now);
            }
            return resp;
        }
        // Stage 1: verify JS PoW and telemetry (a POST with neither does no work and fails),
        // spend the PoW token, then serve the click puzzle (stage 2) whatever the headless flag
        // says: adaptive always requires the puzzle.
        let mut js_ok = false;
        if !solution.is_empty() || !telemetry.is_empty() {
            js_ok = verify_challenge_submission(
                &cfg.secret_key,
                req.scope,
                token,
                solution,
                telemetry,
                hless,
                now,
            )
            .0;
        }
        if !js_ok || !consume_pow_token(token, now) {
            // Failed stage 1: restart from the first step, preserve the original redirect.
            hold_stage1_token(&mut resp, req, cfg, &redirect_to, now);
            return resp;
        }
        respond_stage2_puzzle(&mut resp, req, cfg, &redirect_to, now);
        return resp;
    }

    match cfg.type_.as_str() {
        CHALLENGE_TYPE_TURNSTILE => {
            verified = confirm_turnstile_token(token, cfg.secret_key.as_bytes(), client_ip, captcha)
        }
        CHALLENGE_TYPE_HCAPTCHA => {
            verified = confirm_hcaptcha_token(token, cfg.secret_key.as_bytes(), client_ip, captcha)
        }
        CHALLENGE_TYPE_CLICK_PUZZLE => {
            verified = check_puzzle_answer(cfg, req.scope, token, get(b"sig"), get(b"clicked"), now)
        }
        _ => {
            // JS challenge: token = "<salt>:<expiry>:<difficulty>:<hmac>" (optionally
            // "|<proof>"). A POST with neither solution nor telemetry does no work and fails.
            let mut is_bot = false;
            if !solution.is_empty() || !telemetry.is_empty() {
                let r = verify_challenge_submission(
                    &cfg.secret_key,
                    req.scope,
                    token,
                    solution,
                    telemetry,
                    hless,
                    now,
                );
                (verified, is_bot) = (r.0, r.1);
            }
            // A solved PoW token has exactly one outcome: a cookie or the escalation puzzle.
            if verified && !consume_pow_token(token, now) {
                verified = false;
            }
            // Automated bot / tampering detected: escalate to the click puzzle even for plain
            // js_challenge. The puzzle carries the adaptive stage-2 marker so its answer is
            // validated by `check_click_puzzle_token`; without it the verify handler would
            // parse the puzzle token as a PoW token, which always fails, looping the user.
            if verified && is_bot {
                respond_stage2_puzzle(&mut resp, req, cfg, &redirect_to, now);
                return resp;
            }
        }
    }

    if !verified {
        // Re-serve the challenge on failure, preserving the original redirect from the POST body.
        match cfg.type_.as_str() {
            CHALLENGE_TYPE_TURNSTILE => {
                respond_with_turnstile(&mut resp, req, cfg, &redirect_to, now)
            }
            CHALLENGE_TYPE_HCAPTCHA => {
                respond_with_hcaptcha(&mut resp, req, cfg, &redirect_to, now)
            }
            CHALLENGE_TYPE_CLICK_PUZZLE => {
                // Fresh puzzle with a wrong-answer message.
                if let Ok(page) = render_click_page(
                    &cfg.secret_key,
                    req.scope,
                    &redirect_to,
                    INCORRECT_SELECTION,
                    now,
                ) {
                    resp.html_page(page, false);
                }
            }
            _ => respond_with_js_challenge(&mut resp, req, cfg, &redirect_to, now),
        }
        return resp;
    }
    if cfg.simulation {
        respond_simulation_success(&mut resp, &redirect_to);
        return resp;
    }
    issue_cookie_and_redirect(&mut resp, req, cfg, &redirect_to, now);
    resp
}

pub fn respond_simulation_success(resp: &mut PageResponse, redirect_to: &[u8]) {
    resp.html_page(render_simulation_page(redirect_to), false);
}

/// The `Set-Cookie` value of the challenge cookie (key, value, max-age, path, HttpOnly,
/// secure, SameSite=Lax).
pub fn challenge_set_cookie(value: &[u8], max_age: i64, secure: bool) -> Vec<u8> {
    let mut c = format!("{CHALLENGE_COOKIE}=").into_bytes();
    c.extend_from_slice(value);
    if max_age != 0 {
        c.extend_from_slice(format!("; max-age={}", max_age.max(0)).as_bytes());
    }
    c.extend_from_slice(b"; path=/; HttpOnly");
    if secure {
        c.extend_from_slice(b"; secure");
    }
    c.extend_from_slice(b"; SameSite=Lax");
    c
}

/// 302 to redirect_to with the signed cookie.
pub fn issue_cookie_and_redirect(
    resp: &mut PageResponse,
    req: &ChallengeRequest,
    cfg: &ChallengeSettings,
    redirect_to: &[u8],
    now: i64,
) {
    let val = issue_challenge_cookie_with_lifetime(
        &cfg.secret_key,
        req.scope,
        cfg.cookie_lifetime_secs(),
        now,
    );
    let secure = req.over_tls || eq_ignore_case(req.x_forwarded_proto, b"https");
    resp.set_cookie = Some(challenge_set_cookie(&val, cfg.cookie_ttl_sec, secure));
    resp.status = 302;
    resp.replace_header("Location", redirect_to);
    resp.replace_header("Cache-Control", b"no-store");
    resp.body = Vec::new();
}

pub const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
pub const HCAPTCHA_VERIFY_URL: &str = "https://api.hcaptcha.com/siteverify";

/// The verify form: secret, response and remoteip, urlencoded (keys sorted).
pub fn captcha_form_body(token: &[u8], secret: &[u8], remote_ip: &[u8]) -> Vec<u8> {
    [
        b"remoteip=".as_slice(),
        &escape_query_component(remote_ip),
        b"&response=",
        &escape_query_component(token),
        b"&secret=",
        &escape_query_component(secret),
    ]
    .concat()
}

/// The `success` flag of the JSON answer, false on any error.
pub fn captcha_success(data: &[u8]) -> bool {
    let Ok(doc) = parse(data) else { return false };
    let Value::Object(fields) = doc else {
        return false;
    };
    let mut success = false;
    for (k, v) in &fields {
        if key_matches(k, "success") {
            match v {
                Value::Bool(b) => success = *b,
                Value::Null => {}
                _ => return false,
            }
        }
    }
    success
}

/// Posts the widget token to a provider's siteverify endpoint and reports its success flag. Any
/// failure (transport, timeout, answer too long, bad JSON) is "not verified". Both providers
/// go through here; the verifier decides the time and size bounds.
pub fn verify_captcha(
    url: &str,
    token: &[u8],
    secret: &[u8],
    remote_ip: &[u8],
    captcha: &dyn CaptchaVerifier,
) -> bool {
    if token.is_empty() || secret.is_empty() {
        return false;
    }
    captcha
        .submit_form(url, &captcha_form_body(token, secret, remote_ip))
        .is_some_and(|d| captcha_success(&d))
}

pub fn confirm_turnstile_token(
    token: &[u8],
    secret: &[u8],
    remote_ip: &[u8],
    captcha: &dyn CaptchaVerifier,
) -> bool {
    verify_captcha(TURNSTILE_VERIFY_URL, token, secret, remote_ip, captcha)
}

pub fn confirm_hcaptcha_token(
    token: &[u8],
    secret: &[u8],
    remote_ip: &[u8],
    captcha: &dyn CaptchaVerifier,
) -> bool {
    verify_captcha(HCAPTCHA_VERIFY_URL, token, secret, remote_ip, captcha)
}
