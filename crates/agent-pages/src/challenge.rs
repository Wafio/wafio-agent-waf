//! Challenge configuration and defaults, good-bot UA allowlist, PoW tokens, nonces, cookies
//! (HMAC-SHA256), browser telemetry scoring, the click puzzle, and every page builder. Time is
//! passed in (`now`: Unix seconds) and randomness comes from `crypto::fill_random_bytes`;
//! `*_from` variants take the random bytes so vectors can be compared byte for byte.

use crate::crypto::{fill_random_bytes, hex_encode, hmac_equal, hmac_sha256, sha256};
use crate::seeded_rng::SeededRng;
use crate::templates as t;
use wafio_bytetext::html::escape as html_escape;
use wafio_bytetext::pattern::{CompiledRegex, escape_regex_meta};
use wafio_domain::json_text::{Value, key_matches, parse, type_mismatch_text};

pub const CHALLENGE_TYPE_JS: &str = "js_challenge";
pub const CHALLENGE_TYPE_TURNSTILE: &str = "turnstile";
pub const CHALLENGE_TYPE_HCAPTCHA: &str = "hcaptcha";
pub const CHALLENGE_TYPE_CLICK_PUZZLE: &str = "click_puzzle";
pub const CHALLENGE_TYPE_ADAPTIVE: &str = "adaptive";

pub use crate::templates::{
    STOCK_BLOCK_HTML, STOCK_CLICK_PUZZLE_HTML, STOCK_GEO_BLOCK_HTML, STOCK_GEO_BLOCK_JSON,
    STOCK_GEO_BLOCK_XML, STOCK_IP_REP_BLOCK_HTML, STOCK_IP_REP_BLOCK_JSON, STOCK_IP_REP_BLOCK_XML,
    STOCK_JS_CHALLENGE_HTML, STOCK_POLICY_BLOCK_HTML, STOCK_POLICY_BLOCK_JSON,
    STOCK_POLICY_BLOCK_XML, STOCK_WAF_BLOCK_JSON, STOCK_WAF_BLOCK_XML,
};

pub const DEFAULT_GOOD_BOT_AGENTS: [&str; 17] = [
    "Googlebot",
    "Googlebot-Image",
    "Googlebot-Video",
    "Google-InspectionTool",
    "bingbot",
    "BingPreview",
    "DuckDuckBot",
    "YandexBot",
    "Baiduspider",
    "Slurp",
    "facebookexternalhit",
    "Twitterbot",
    "LinkedInBot",
    "Applebot",
    "AhrefsBot",
    "SemrushBot",
    "MJ12bot",
];

/// The `challenge` block of rules_json.
#[derive(Clone, Debug, Default)]
pub struct ChallengeSettings {
    pub enabled: bool,
    pub type_: String,
    pub site_key: String,
    pub secret_key: String,
    pub cookie_ttl_sec: i64,
    pub trigger: String,
    pub simulation: bool,
    pub pow_difficulty: i64,
    pub template_version: i64,
    /// None (absent) or true = private/loopback peers bypass the challenge.
    pub allow_local_ips: Option<bool>,
    pub ip_rep_enabled: bool,
    pub ip_rep_block_level1: bool,
    pub ip_rep_block_level2: bool,
    pub good_bot_allowlist: Vec<String>,
    pub custom_js_challenge_html: String,
    pub custom_click_puzzle_html: String,
    pub custom_ip_rep_block_html: String,
    pub custom_block_html: String,
    pub custom_policy_block_html: String,
    pub custom_geo_block_html: String,
    pub waf_block_format: String,
    pub policy_block_format: String,
    pub geo_block_format: String,
    pub ip_rep_block_format: String,
    pub custom_waf_block_json: String,
    pub custom_policy_block_json: String,
    pub custom_geo_block_json: String,
    pub custom_ip_rep_block_json: String,
    pub custom_waf_block_xml: String,
    pub custom_policy_block_xml: String,
    pub custom_geo_block_xml: String,
    pub custom_ip_rep_block_xml: String,
    /// Built by `finalize_challenge_settings`.
    pub good_bot_matchers: Vec<CompiledRegex>,
}

// Decoding and defaults

fn type_mismatch_message(field: &str, v: &Value, ty: &str) -> String {
    type_mismatch_text(field, &v.kind_text(), ty)
}

fn set_bool(dst: &mut bool, field: &str, v: &Value) -> Result<(), String> {
    match v {
        Value::Bool(b) => *dst = *b,
        Value::Null => {}
        _ => return Err(type_mismatch_message(field, v, "bool")),
    }
    Ok(())
}

fn set_string(dst: &mut String, field: &str, v: &Value) -> Result<(), String> {
    match v {
        Value::String(s) => *dst = String::from_utf8_lossy(s).into_owned(),
        Value::Null => {}
        _ => return Err(type_mismatch_message(field, v, "string")),
    }
    Ok(())
}

fn set_int(dst: &mut i64, field: &str, v: &Value) -> Result<(), String> {
    match v {
        Value::Number(n) => {
            *dst = parse_int(n, 10).ok_or_else(|| type_mismatch_message(field, v, "int"))?
        }
        Value::Null => {}
        _ => return Err(type_mismatch_message(field, v, "int")),
    }
    Ok(())
}

impl ChallengeSettings {
    /// Keys match case-insensitively (last one wins), null leaves a field as it is (an
    /// optional bool becomes None), a wrong type is an error (decoding goes on and the error
    /// is reported; the whole block is then dropped).
    pub fn from_json_value(doc: &Value) -> Result<ChallengeSettings, String> {
        let mut c = ChallengeSettings::default();
        let fields = match doc {
            Value::Object(f) => f,
            Value::Null => return Ok(c),
            _ => {
                return Err(type_mismatch_text("", doc.type_name(), "object"));
            }
        };
        let mut first_err = None;
        for (k, v) in fields {
            let r = (|| -> Result<(), String> {
                macro_rules! s {
                    ($name:literal, $f:ident) => {
                        if key_matches(k, $name) {
                            return set_string(&mut c.$f, $name, v);
                        }
                    };
                }
                macro_rules! b {
                    ($name:literal, $f:ident) => {
                        if key_matches(k, $name) {
                            return set_bool(&mut c.$f, $name, v);
                        }
                    };
                }
                macro_rules! i {
                    ($name:literal, $f:ident) => {
                        if key_matches(k, $name) {
                            return set_int(&mut c.$f, $name, v);
                        }
                    };
                }
                b!("enabled", enabled);
                s!("type", type_);
                s!("site_key", site_key);
                s!("secret_key", secret_key);
                i!("cookie_ttl_sec", cookie_ttl_sec);
                s!("trigger", trigger);
                b!("simulation", simulation);
                i!("pow_difficulty", pow_difficulty);
                i!("template_version", template_version);
                if key_matches(k, "allow_local_ips") {
                    return match v {
                        Value::Bool(b) => {
                            c.allow_local_ips = Some(*b);
                            Ok(())
                        }
                        Value::Null => {
                            c.allow_local_ips = None;
                            Ok(())
                        }
                        _ => Err(type_mismatch_message("allow_local_ips", v, "bool")),
                    };
                }
                b!("ip_rep_enabled", ip_rep_enabled);
                b!("ip_rep_block_level1", ip_rep_block_level1);
                b!("ip_rep_block_level2", ip_rep_block_level2);
                if key_matches(k, "good_bot_allowlist") {
                    return match v {
                        Value::Array(a) => {
                            c.good_bot_allowlist = Vec::with_capacity(a.len());
                            let mut err = None;
                            for e in a {
                                let mut s = String::new();
                                if let Err(x) = set_string(&mut s, "good_bot_allowlist", e) {
                                    err.get_or_insert(x);
                                }
                                c.good_bot_allowlist.push(s);
                            }
                            err.map_or(Ok(()), Err)
                        }
                        Value::Null => {
                            c.good_bot_allowlist = Vec::new();
                            Ok(())
                        }
                        _ => Err(type_mismatch_message("good_bot_allowlist", v, "[]string")),
                    };
                }
                s!("custom_js_challenge_html", custom_js_challenge_html);
                s!("custom_click_puzzle_html", custom_click_puzzle_html);
                s!("custom_ip_rep_block_html", custom_ip_rep_block_html);
                s!("custom_block_html", custom_block_html);
                s!("custom_policy_block_html", custom_policy_block_html);
                s!("custom_geo_block_html", custom_geo_block_html);
                s!("waf_block_format", waf_block_format);
                s!("policy_block_format", policy_block_format);
                s!("geo_block_format", geo_block_format);
                s!("ip_rep_block_format", ip_rep_block_format);
                s!("custom_waf_block_json", custom_waf_block_json);
                s!("custom_policy_block_json", custom_policy_block_json);
                s!("custom_geo_block_json", custom_geo_block_json);
                s!("custom_ip_rep_block_json", custom_ip_rep_block_json);
                s!("custom_waf_block_xml", custom_waf_block_xml);
                s!("custom_policy_block_xml", custom_policy_block_xml);
                s!("custom_geo_block_xml", custom_geo_block_xml);
                s!("custom_ip_rep_block_xml", custom_ip_rep_block_xml);
                Ok(())
            })();
            if let Err(e) = r {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(c), Err)
    }

    /// The defaults filled after decoding the `challenge` block.
    pub fn apply_defaults(&mut self) {
        // Any other value (empty, "js", a typo) is served and verified as the JS challenge by the
        // default branches; make that explicit so the stage-2 puzzle check (== js_challenge) agrees
        // with them.
        if !matches!(
            self.type_.as_str(),
            CHALLENGE_TYPE_TURNSTILE
                | CHALLENGE_TYPE_HCAPTCHA
                | CHALLENGE_TYPE_CLICK_PUZZLE
                | CHALLENGE_TYPE_ADAPTIVE
        ) {
            self.type_ = CHALLENGE_TYPE_JS.into();
        }
        if self.cookie_ttl_sec <= 0 {
            self.cookie_ttl_sec = 3600;
        }
        if self.trigger.is_empty() {
            self.trigger = "always".into();
        }
        if self.good_bot_allowlist.is_empty() {
            self.good_bot_allowlist = DEFAULT_GOOD_BOT_AGENTS
                .iter()
                .map(|s| s.to_string())
                .collect();
        }
        for (f, d) in [
            (
                &mut self.custom_js_challenge_html,
                t::STOCK_JS_CHALLENGE_HTML,
            ),
            (
                &mut self.custom_click_puzzle_html,
                t::STOCK_CLICK_PUZZLE_HTML,
            ),
            (
                &mut self.custom_ip_rep_block_html,
                t::STOCK_IP_REP_BLOCK_HTML,
            ),
            (&mut self.custom_block_html, t::STOCK_BLOCK_HTML),
            (
                &mut self.custom_policy_block_html,
                t::STOCK_POLICY_BLOCK_HTML,
            ),
            (&mut self.custom_geo_block_html, t::STOCK_GEO_BLOCK_HTML),
            (&mut self.custom_waf_block_json, t::STOCK_WAF_BLOCK_JSON),
            (
                &mut self.custom_policy_block_json,
                t::STOCK_POLICY_BLOCK_JSON,
            ),
            (&mut self.custom_geo_block_json, t::STOCK_GEO_BLOCK_JSON),
            (
                &mut self.custom_ip_rep_block_json,
                t::STOCK_IP_REP_BLOCK_JSON,
            ),
            (&mut self.custom_waf_block_xml, t::STOCK_WAF_BLOCK_XML),
            (&mut self.custom_policy_block_xml, t::STOCK_POLICY_BLOCK_XML),
            (&mut self.custom_geo_block_xml, t::STOCK_GEO_BLOCK_XML),
            (&mut self.custom_ip_rep_block_xml, t::STOCK_IP_REP_BLOCK_XML),
        ] {
            if f.is_empty() {
                *f = d.to_string();
            }
        }
    }

    /// The `challenge` block: decode, defaults, `finalize_challenge_settings`.
    /// None when the block does not decode (challenge disabled).
    pub fn from_rules_json(raw: &[u8]) -> Option<ChallengeSettings> {
        let doc = parse(raw).ok()?;
        let mut c = ChallengeSettings::from_json_value(&doc).ok()?;
        c.apply_defaults();
        finalize_challenge_settings(&mut c);
        Some(c)
    }

    pub fn matches_good_bot(&self, ua: &[u8]) -> bool {
        !ua.is_empty() && self.good_bot_matchers.iter().any(|re| re.is_match(ua))
    }

    /// The cookie lifetime in seconds.
    pub fn cookie_lifetime_secs(&self) -> i64 {
        if self.cookie_ttl_sec > 0 {
            self.cookie_ttl_sec
        } else {
            3600
        }
    }
}

/// Compiles the allowlist ((?i), literal unless it holds a regex metacharacter) with regexp
/// semantics. A pattern that does not compile is skipped.
pub fn finalize_challenge_settings(c: &mut ChallengeSettings) {
    let list: Vec<String> = if c.good_bot_allowlist.is_empty() {
        DEFAULT_GOOD_BOT_AGENTS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        c.good_bot_allowlist.clone()
    };
    c.good_bot_matchers = list
        .iter()
        .filter_map(|p| {
            let p = String::from_utf8_lossy(wafio_bytetext::strings::trim_whitespace(p.as_bytes()))
                .into_owned();
            if p.is_empty() {
                return None;
            }
            let p = if p.contains(['.', '*', '+', '?', '[', ']', '(', ')', '|', '^', '$', '\\']) {
                p
            } else {
                String::from_utf8_lossy(&escape_regex_meta(p.as_bytes())).into_owned()
            };
            let expr = format!("(?i){p}");
            if !regex_repeats_within_limit(&expr) {
                return None;
            }
            CompiledRegex::compile(&expr).ok()
        })
        .collect();
}

// shortcut: RE2 syntax rules bytetext::pattern does not enforce yet (a repeat count
// above 1000, nested counted repeats whose product exceeds 1000, stacked
// repetition operators); drop once bytetext rejects these patterns itself.
fn regex_repeats_within_limit(expr: &str) -> bool {
    let p: Vec<char> = expr.chars().collect();
    let skip_escape = |i: usize| -> usize {
        match p.get(i + 1) {
            Some('x' | 'p' | 'P') if p.get(i + 2) == Some(&'{') => (i..p.len())
                .find(|&k| p[k] == '}')
                .map_or(p.len(), |k| k + 1),
            Some('Q') => (i + 2..p.len())
                .find(|&k| p[k] == '\\' && p.get(k + 1) == Some(&'E'))
                .map_or(p.len(), |k| k + 2),
            Some(_) => i + 2,
            None => i + 1,
        }
    };
    let atom = |s: &mut Vec<(u64, u64)>| {
        let f = s.last_mut().expect("root frame");
        *f = (f.0.max(f.1), 1);
    };
    // Per open group: the largest repeat product of its finished items and of its last
    // item (0 = none).
    let mut stack: Vec<(u64, u64)> = vec![(1, 0)];
    let mut rep = false; // the previous token was a repetition operator
    let mut i = 0;
    while i < p.len() {
        let was_rep = std::mem::replace(&mut rep, false);
        match p[i] {
            '\\' => {
                atom(&mut stack);
                i = skip_escape(i);
            }
            '[' => {
                atom(&mut stack);
                let mut j = i + 1;
                if p.get(j) == Some(&'^') {
                    j += 1;
                }
                let mut first = true; // a leading ']' is a literal
                while j < p.len() && (p[j] != ']' || first) {
                    first = false;
                    let named = if p[j] == '[' && p.get(j + 1) == Some(&':') {
                        (j + 2..p.len()).find(|&k| p[k] == ':' && p.get(k + 1) == Some(&']'))
                    } else {
                        None
                    };
                    j = match named {
                        Some(k) => k + 2,
                        None if p[j] == '\\' => skip_escape(j),
                        None => j + 1,
                    };
                }
                i = j + 1;
            }
            '(' => {
                if p.get(i + 1) == Some(&'?') {
                    let named = matches!(p.get(i + 2), Some('P' | '<'));
                    let j = (i + 2..p.len())
                        .find(|&k| {
                            if named {
                                p[k] == '>'
                            } else {
                                p[k] == ':' || p[k] == ')'
                            }
                        })
                        .unwrap_or(p.len());
                    i = j + 1;
                    if !named && p.get(j) != Some(&':') {
                        continue; // (?flags) opens no group
                    }
                } else {
                    i += 1;
                }
                atom(&mut stack);
                stack.push((1, 0));
            }
            ')' => {
                if stack.len() > 1 {
                    let (fin, last) = stack.pop().expect("group frame");
                    stack.last_mut().expect("root frame").1 = fin.max(last).max(1);
                }
                i += 1;
            }
            '|' => {
                let f = stack.last_mut().expect("root frame");
                *f = (f.0.max(f.1), 0);
                i += 1;
            }
            '*' | '+' | '?' => {
                if was_rep {
                    return false; // invalid nested repetition operator
                }
                i += if p.get(i + 1) == Some(&'?') { 2 } else { 1 }; // '?' = non-greedy
                rep = true;
            }
            '{' => match parse_regex_repeat_count(&p[i..]) {
                Some((min, max, n)) => {
                    let m = max.unwrap_or(min); // the max, or the min when unbounded
                    if was_rep || min > 1000 || m > 1000 || (max.is_some() && min > m) {
                        return false;
                    }
                    let f = stack.last_mut().expect("root frame");
                    let g = if m == 0 { 1 } else { m * f.1.max(1) };
                    if (min >= 2 || (max.is_some() && m >= 2)) && g > 1000 {
                        return false;
                    }
                    f.1 = g;
                    i += n;
                    if p.get(i) == Some(&'?') {
                        i += 1;
                    }
                    rep = true;
                }
                None => {
                    atom(&mut stack); // not a repeat: literal '{'
                    i += 1;
                }
            },
            _ => {
                atom(&mut stack);
                i += 1;
            }
        }
    }
    true
}

/// Parses `{min}`, `{min,}`, `{min,max}` (no leading zeros; a number of 9+ digits counts as
/// too big): (min, max (None = unbounded), length), or None for a literal `{`.
fn parse_regex_repeat_count(t: &[char]) -> Option<(u64, Option<u64>, usize)> {
    let int = |at: usize| -> Option<(u64, usize)> {
        let n = t[at..].iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 || (n >= 2 && t[at] == '0') {
            return None;
        }
        let v = t[at..at + n].iter().try_fold(0u64, |v, c| {
            (v < 100_000_000).then(|| v * 10 + c.to_digit(10).unwrap() as u64)
        });
        Some((v.unwrap_or(u64::MAX), at + n))
    };
    let (min, mut j) = int(1)?;
    let max = match t.get(j) {
        Some(',') if t.get(j + 1) == Some(&'}') => {
            j += 1;
            None
        }
        Some(',') => {
            let (m, k) = int(j + 1)?;
            j = k;
            Some(m)
        }
        _ => Some(min),
    };
    (t.get(j) == Some(&'}')).then_some((min, max, j + 1))
}

// ── tokens, nonces, cookies ─────────────────────────────────────────────────

/// How long a JS nonce stays valid (seconds).
pub const NONCE_LIFETIME: i64 = 300;
const BUILTIN_CHALLENGE_SECRET: &str = "wafio-challenge-v1";
pub const STANDARD_POW_DIFFICULTY: i64 = 12;
pub const CHALLENGE_COOKIE: &str = "_wafio_ch";
pub const VERIFY_ENDPOINT_PATH: &str = "/_wafio/challenge/verify";

/// Length caps checked before any split or MAC, so an oversized value costs nothing proportional
/// (a real PoW token is 111 bytes, a puzzle token 163, a cookie 92).
pub const MAX_TOKEN_BYTES: usize = 512;
pub const MAX_COOKIE_BYTES: usize = 256;

/// The per-agent secret that keys every challenge token and cookie whose config has no
/// `secret_key`.
static INSTANCE_SECRET: std::sync::RwLock<Option<[u8; 32]>> = std::sync::RwLock::new(None);

/// Installs the per-agent secret (the agent binary at start, from its
/// state directory, so cookies survive a restart or a SIGUSR2 successor). Replaces an earlier one.
pub fn set_instance_secret(secret: [u8; 32]) {
    *INSTANCE_SECRET
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(secret);
}

/// The installed secret; when none was set a random one is generated and kept,
/// so the public constant of the old derivation is never used. Panics when the OS CSPRNG is
/// unreadable.
fn instance_secret() -> [u8; 32] {
    if let Some(s) = *INSTANCE_SECRET
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        return s;
    }
    *INSTANCE_SECRET
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(|| {
            let mut s = [0u8; 32];
            fill_random_bytes(&mut s).expect("challenge: crypto/rand unavailable");
            s
        })
}

/// With a provider `secret_key` SHA-256("wafio-challenge-v1" ":" secret);
/// without one HMAC-SHA256(instance secret, "wafio-challenge-v1:instance").
pub fn derive_signing_key(secret_key: &str) -> [u8; 32] {
    if secret_key.is_empty() {
        return hmac_sha256(
            &instance_secret(),
            &[BUILTIN_CHALLENGE_SECRET.as_bytes(), b":instance"],
        );
    }
    sha256(
        &[
            BUILTIN_CHALLENGE_SECRET.as_bytes(),
            b":",
            secret_key.as_bytes(),
        ]
        .concat(),
    )
}

/// Hex HMAC-SHA256.
pub fn sign_message(key: &[u8], data: &[u8]) -> Vec<u8> {
    hex_encode(&hmac_sha256(key, &[data]))
}

/// `payload ":" scope`: what the MACs below cover. The scope is the app ID of the route serving
/// the request ("" outside a route), so a token or cookie of one app is worthless on another app
/// of the same agent.
fn scoped(payload: &[u8], scope: &[u8]) -> Vec<u8> {
    [payload, b":", scope].concat()
}

/// A PoW token with the 16 random salt bytes given.
pub fn issue_pow_token_from(
    secret_key: &str,
    scope: &[u8],
    difficulty: i64,
    raw: [u8; 16],
    now: i64,
) -> Vec<u8> {
    let difficulty = if difficulty <= 0 {
        STANDARD_POW_DIFFICULTY
    } else {
        difficulty
    };
    let mut payload = hex_encode(&raw);
    payload.extend_from_slice(format!(":{}:{}", now + NONCE_LIFETIME, difficulty).as_bytes());
    let mac = sign_message(&derive_signing_key(secret_key), &scoped(&payload, scope));
    payload.push(b':');
    payload.extend_from_slice(&mac);
    payload
}

/// A PoW token: "<salt>:<expiry>:<difficulty>:<hmac>", hmac over
/// "<salt>:<expiry>:<difficulty>:<scope>".
pub fn issue_pow_token(
    secret_key: &str,
    scope: &[u8],
    difficulty: i64,
    now: i64,
) -> std::io::Result<Vec<u8>> {
    let mut raw = [0u8; 16];
    fill_random_bytes(&mut raw)?;
    Ok(issue_pow_token_from(
        secret_key, scope, difficulty, raw, now,
    ))
}

/// (salt, difficulty) of a token authentic for `scope` and unexpired. Only a
/// 4-part token with difficulty 1..32 is valid; the 3-part nonce of the CAPTCHA pages is not.
pub fn check_pow_token(
    secret_key: &str,
    scope: &[u8],
    token: &[u8],
    now: i64,
) -> Option<(Vec<u8>, i64)> {
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let parts = wafio_bytetext::strings::splitn(token, b":", 5);
    if parts.len() != 4 {
        return None;
    }
    let expiry = parse_int(parts[1], 10)?;
    if now > expiry {
        return None;
    }
    let diff = parse_int(parts[2], 10)?;
    if diff <= 0 || diff > 32 {
        return None;
    }
    let payload = [parts[0], b":", parts[1], b":", parts[2], b":", scope].concat();
    let key = derive_signing_key(secret_key);
    if !hmac_equal(parts[3], &sign_message(&key, &payload)) {
        return None;
    }
    Some((parts[0].to_vec(), diff))
}

/// SHA-256(salt ":" solution) has `difficulty` leading zero bits.
pub fn check_pow_solution(salt: &[u8], solution: i64, difficulty: i64) -> bool {
    if difficulty <= 0 {
        return true;
    }
    if difficulty > 32 {
        return false;
    }
    let sum = sha256(&[salt, b":", solution.to_string().as_bytes()].concat());
    let zero_bytes = (difficulty / 8) as usize;
    let rem_bits = difficulty % 8;
    if sum[..zero_bytes].iter().any(|&b| b != 0) {
        return false;
    }
    if rem_bits > 0 {
        let mask = (0xFFu32 << (8 - rem_bits)) as u8;
        if sum[zero_bytes] & mask != 0 {
            return false;
        }
    }
    true
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BrowserSignals {
    pub webdriver: bool,
    pub no_languages: bool,
    pub screen_invalid: bool,
    pub automation_vars: bool,
    pub cdp_detected: bool,
    pub prototype_tampered: bool,
    pub worker_mismatch: bool,
    pub worker_webdriver: bool,
    pub permissions_anomaly: bool,
    pub software_renderer: bool,
    pub no_chrome_object: bool,
    pub canvas_failed: bool,
    pub audio_zero: bool,
    pub duration_ms: i64,
    pub user_agent: Vec<u8>,
    pub renderer: Vec<u8>,
}

impl BrowserSignals {
    /// None when the JSON does not decode.
    pub fn from_json_value(raw: &[u8]) -> Option<BrowserSignals> {
        let doc = parse(raw).ok()?;
        let mut t = BrowserSignals::default();
        let fields = match doc {
            Value::Object(f) => f,
            Value::Null => return Some(t),
            _ => return None,
        };
        let mut ok = true;
        for (k, v) in &fields {
            let bools: [(&str, &mut bool); 13] = [
                ("wd", &mut t.webdriver),
                ("nl", &mut t.no_languages),
                ("sd", &mut t.screen_invalid),
                ("au", &mut t.automation_vars),
                ("cdp", &mut t.cdp_detected),
                ("pt", &mut t.prototype_tampered),
                ("wm", &mut t.worker_mismatch),
                ("wwd", &mut t.worker_webdriver),
                ("pm", &mut t.permissions_anomaly),
                ("sw", &mut t.software_renderer),
                ("nc", &mut t.no_chrome_object),
                ("cf", &mut t.canvas_failed),
                ("az", &mut t.audio_zero),
            ];
            let mut done = false;
            for (name, dst) in bools {
                if !done && key_matches(k, name) {
                    done = true;
                    ok &= set_bool(dst, name, v).is_ok();
                }
            }
            if done {
                continue;
            }
            if key_matches(k, "dur") {
                ok &= set_int(&mut t.duration_ms, "dur", v).is_ok();
            } else if key_matches(k, "ua") || key_matches(k, "ren") {
                let dst = if key_matches(k, "ua") {
                    &mut t.user_agent
                } else {
                    &mut t.renderer
                };
                match v {
                    Value::String(s) => *dst = s.clone(),
                    Value::Null => {}
                    _ => ok = false,
                }
            }
        }
        ok.then_some(t)
    }
}

/// (score, isBot, reasons).
pub fn score_browser_signals(t: Option<&BrowserSignals>) -> (i64, bool, Vec<&'static str>) {
    let Some(t) = t else {
        return (100, true, vec!["missing_telemetry"]);
    };
    let mut score = 0;
    let mut reasons = Vec::new();
    let mut add = |hit: bool, pts: i64, why: &'static str| {
        if hit {
            score += pts;
            reasons.push(why);
        }
    };
    add(t.cdp_detected, 100, "cdp_detected");
    add(t.prototype_tampered, 100, "prototype_tampered");
    add(
        t.worker_webdriver || t.worker_mismatch,
        100,
        "worker_realm_mismatch",
    );
    add(t.automation_vars, 100, "automation_vars");
    add(t.webdriver, 100, "navigator_webdriver");
    add(t.software_renderer, 50, "software_renderer");
    add(t.permissions_anomaly, 50, "permissions_anomaly");
    add(t.audio_zero, 40, "audio_zero_entropy");
    add(t.screen_invalid, 40, "screen_invalid");
    add(t.no_languages, 40, "no_languages");
    add(t.canvas_failed, 30, "canvas_fingerprint_failed");
    add(
        t.no_chrome_object && wafio_bytetext::strings::contains(&t.user_agent, b"Chrome/"),
        30,
        "missing_chrome_object",
    );
    add(
        t.duration_ms > 0 && t.duration_ms < 20,
        60,
        "sub_human_duration",
    );
    (score, score >= 80, reasons)
}

/// (verified, isBot, score, reasons).
pub fn verify_challenge_submission(
    secret_key: &str,
    scope: &[u8],
    token: &[u8],
    solution_str: &[u8],
    telemetry_str: &[u8],
    hless_str: &[u8],
    now: i64,
) -> (bool, bool, i64, Vec<&'static str>) {
    let token = match token.iter().position(|&c| c == b'|') {
        Some(i) => &token[..i],
        None => token,
    };
    let Some((salt, diff)) = check_pow_token(secret_key, scope, token, now) else {
        return (false, true, 100, vec!["invalid_token"]);
    };
    if diff > 0 {
        if solution_str.is_empty() {
            return (false, true, 100, vec!["missing_pow_solution"]);
        }
        match parse_int(solution_str, 10) {
            Some(sol) if check_pow_solution(&salt, sol, diff) => {}
            _ => return (false, true, 100, vec!["invalid_pow_solution"]),
        }
    }
    let (mut is_bot, mut score, mut reasons) = (false, 0, Vec::new());
    if !telemetry_str.is_empty() {
        let (mut raw, ok) =
            crate::crypto::decode_base64_partial(crate::crypto::B64::Std, telemetry_str);
        if !ok {
            raw = crate::crypto::decode_base64_partial(crate::crypto::B64::RawStd, telemetry_str).0;
        }
        if !raw.is_empty()
            && let Some(tel) = BrowserSignals::from_json_value(&raw)
        {
            (score, is_bot, reasons) = score_browser_signals(Some(&tel));
        }
    }
    if hless_str == b"1" {
        is_bot = true;
        if score < 100 {
            score = 100;
        }
        reasons.push("headless_flag");
    }
    (true, is_bot, score, reasons)
}

/// A challenge nonce with the random bytes given: "<nonce>:<expiry>:<hmac>". The
/// Turnstile/hCaptcha pages embed it; it is not accepted as a PoW token.
pub fn issue_challenge_nonce_from(secret_key: &str, raw: [u8; 16], now: i64) -> Vec<u8> {
    let mut payload = hex_encode(&raw);
    payload.extend_from_slice(format!(":{}", now + NONCE_LIFETIME).as_bytes());
    let mac = sign_message(&derive_signing_key(secret_key), &payload);
    payload.push(b':');
    payload.extend_from_slice(&mac);
    payload
}

pub fn issue_challenge_nonce(secret_key: &str, now: i64) -> std::io::Result<Vec<u8>> {
    let mut raw = [0u8; 16];
    fill_random_bytes(&mut raw)?;
    Ok(issue_challenge_nonce_from(secret_key, raw, now))
}

/// A challenge cookie valid for 1 h.
pub fn issue_challenge_cookie(secret_key: &str, scope: &[u8], now: i64) -> Vec<u8> {
    issue_challenge_cookie_with_lifetime(secret_key, scope, 3600, now)
}

/// A challenge cookie with a TTL and the 8 id bytes given:
/// "<expiry>:<id>:<hmac>", id 16 lowercase hex chars, hmac over "<expiry>:<id>:<scope>".
pub fn issue_challenge_cookie_with_lifetime_from(
    secret_key: &str,
    scope: &[u8],
    ttl_secs: i64,
    id: [u8; 8],
    now: i64,
) -> Vec<u8> {
    let mut payload = (now + ttl_secs).to_string().into_bytes();
    payload.push(b':');
    payload.extend_from_slice(&hex_encode(&id));
    let mac = sign_message(&derive_signing_key(secret_key), &scoped(&payload, scope));
    payload.push(b':');
    payload.extend_from_slice(&mac);
    payload
}

/// A challenge cookie with a TTL. Panics when the OS CSPRNG is unreadable.
pub fn issue_challenge_cookie_with_lifetime(
    secret_key: &str,
    scope: &[u8],
    ttl_secs: i64,
    now: i64,
) -> Vec<u8> {
    let mut id = [0u8; 8];
    fill_random_bytes(&mut id).expect("challenge: crypto/rand unavailable");
    issue_challenge_cookie_with_lifetime_from(secret_key, scope, ttl_secs, id, now)
}

/// (id, expiry) of a cookie with 3 parts, a 16-hex id, unexpired and a
/// constant-time HMAC over "<expiry>:<id>:<scope>". Not bound to an IP (dual-stack, CGNAT and load
/// balancers move legitimate users): the agent limits how many networks may present one id
/// instead (`challenge_replay`). Forgery is prevented by the HMAC under the per-agent secret.
pub fn decode_challenge_cookie(
    secret_key: &str,
    scope: &[u8],
    val: &[u8],
    now: i64,
) -> Option<(Vec<u8>, i64)> {
    if val.len() > MAX_COOKIE_BYTES {
        return None;
    }
    let parts = wafio_bytetext::strings::splitn(val, b":", 4);
    if parts.len() != 3
        || parts[1].len() != 16
        || !parts[1]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    {
        return None;
    }
    let expiry = parse_int(parts[0], 10)?;
    if now > expiry {
        return None;
    }
    let payload = [parts[0], b":", parts[1]].concat();
    let want = sign_message(&derive_signing_key(secret_key), &scoped(&payload, scope));
    hmac_equal(parts[2], &want).then(|| (parts[1].to_vec(), expiry))
}

pub fn verify_challenge_cookie(
    secret_key: &str,
    scope: &[u8],
    cookie_val: &[u8],
    now: i64,
) -> bool {
    decode_challenge_cookie(secret_key, scope, cookie_val, now).is_some()
}

/// Same-origin path only, no control bytes.
pub fn sanitize_redirect_target(raw: &[u8]) -> Vec<u8> {
    if raw.is_empty()
        || raw.iter().any(|&c| c < 0x20 || c == 0x7f)
        || !raw.starts_with(b"/")
        || raw.starts_with(b"//")
        || raw.starts_with(b"/\\")
    {
        return b"/".to_vec();
    }
    raw.to_vec()
}

/// Replaces the placeholder, else inserts before the last `</body>`
/// (found in the lowercased page), else appends.
pub fn fill_custom_page(custom_html: &[u8], placeholder: &[u8], inject: &[u8]) -> Vec<u8> {
    if wafio_bytetext::strings::contains(custom_html, placeholder) {
        return wafio_bytetext::strings::replace_all(custom_html, placeholder, inject);
    }
    let lower = wafio_bytetext::strings::to_lowercase(custom_html);
    if let Some(idx) = wafio_bytetext::strings::rfind(&lower, b"</body>") {
        // The original is sliced at the lowercased index (panics past its end).
        return [&custom_html[..idx], inject, b"\n", &custom_html[idx..]].concat();
    }
    [custom_html, b"\n", inject].concat()
}

// Format helpers

/// Formats the page templates: each %s/%d/%q takes the next (preformatted) arg,
/// %% is a percent sign.
pub(crate) fn fill_format_template(format: &str, args: &[&[u8]]) -> Vec<u8> {
    let f = format.as_bytes();
    let mut out = Vec::with_capacity(f.len() + args.iter().map(|a| a.len()).sum::<usize>());
    let mut next = args.iter();
    let mut i = 0;
    while i < f.len() {
        if f[i] == b'%' && i + 1 < f.len() {
            match f[i + 1] {
                b'%' => out.push(b'%'),
                b's' | b'd' | b'q' => {
                    out.extend_from_slice(next.next().expect("page template: missing argument"))
                }
                c => panic!("page template: unsupported verb %{}", c as char),
            }
            i += 2;
            continue;
        }
        out.push(f[i]);
        i += 1;
    }
    out
}

/// Quotes a string (the %q verb).
pub fn quote_literal(s: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = vec![b'"'];
    let mut i = 0;
    while i < s.len() {
        let (r, w) = if s[i] < 0x80 {
            (s[i] as i32, 1)
        } else {
            wafio_bytetext::utf8::decode_code_point(&s[i..])
        };
        if w == 1 && r == 0xFFFD {
            out.extend_from_slice(&[
                b'\\',
                b'x',
                HEX[(s[i] >> 4) as usize],
                HEX[(s[i] & 15) as usize],
            ]);
            i += 1;
            continue;
        }
        if r == '"' as i32 || r == '\\' as i32 {
            out.extend_from_slice(&[b'\\', r as u8]);
        } else if wafio_bytetext::unicode::is_print(r) {
            out.extend_from_slice(&s[i..i + w]);
        } else {
            match r {
                7 => out.extend_from_slice(b"\\a"),
                8 => out.extend_from_slice(b"\\b"),
                12 => out.extend_from_slice(b"\\f"),
                10 => out.extend_from_slice(b"\\n"),
                13 => out.extend_from_slice(b"\\r"),
                9 => out.extend_from_slice(b"\\t"),
                11 => out.extend_from_slice(b"\\v"),
                r if r < 0x20 || r == 0x7f => {
                    out.extend_from_slice(format!("\\x{:02x}", r).as_bytes())
                }
                r if r < 0x10000 => out.extend_from_slice(format!("\\u{:04x}", r).as_bytes()),
                r => out.extend_from_slice(format!("\\U{:08x}", r).as_bytes()),
            }
        }
        i += w;
    }
    out.push(b'"');
    out
}

/// Parses an integer in base 10 or 16 (optional sign, no prefix, no '_').
pub fn parse_int(s: &[u8], base: u32) -> Option<i64> {
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let u = parse_uint(digits, base, 64)?;
    if neg {
        if u > 1u64 << 63 {
            return None;
        }
        Some((u as i64).wrapping_neg())
    } else {
        if u >= 1u64 << 63 {
            return None;
        }
        Some(u as i64)
    }
}

/// Parses an unsigned integer in base 10 or 16.
pub fn parse_uint(s: &[u8], base: u32, bits: u32) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &c in s {
        let d = (c as char).to_digit(base)? as u64;
        n = n.checked_mul(base as u64)?.checked_add(d)?;
    }
    if bits < 64 && n >= 1u64 << bits {
        return None;
    }
    Some(n)
}

// ── page builders ───────────────────────────────────────────────────────────

/// The JS challenge script (escapes redirectTo once more).
fn render_js_challenge_script(token: &[u8], redirect_to: &[u8], extra_inputs: &[u8]) -> Vec<u8> {
    let redirect_to = html_escape(redirect_to);
    fill_format_template(
        t::BUILD_JS_CHALLENGE_SCRIPT_FMT,
        &[
            VERIFY_ENDPOINT_PATH.as_bytes(),
            token,
            &redirect_to,
            extra_inputs,
            &quote_literal(token),
        ],
    )
}

pub fn render_js_challenge_inline(nonce: &[u8], redirect_to: &[u8]) -> Vec<u8> {
    render_js_challenge_script(nonce, redirect_to, b"")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PuzzleCell {
    pub shape: &'static str,
    pub color: &'static str,
}

const PUZZLE_SHAPES: [&str; 4] = ["circle", "square", "triangle", "star"];
const PUZZLE_COLORS: [&str; 5] = ["red", "blue", "green", "yellow", "purple"];

fn puzzle_color_hex(c: &str) -> &'static str {
    match c {
        "red" => "#ef4444",
        "blue" => "#3b82f6",
        "green" => "#10b981",
        "yellow" => "#f59e0b",
        "purple" => "#8b5cf6",
        _ => "",
    }
}

fn puzzle_shape_plural(s: &str) -> &'static str {
    match s {
        "circle" => "circles",
        "square" => "squares",
        "triangle" => "triangles",
        "star" => "stars",
        _ => "",
    }
}

pub fn puzzle_cell_svg(cell: PuzzleCell) -> String {
    let c = puzzle_color_hex(cell.color);
    match cell.shape {
        "circle" => format!(
            r#"<svg viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"><circle cx="30" cy="30" r="22" fill="{c}"/></svg>"#
        ),
        "square" => format!(
            r#"<svg viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"><rect x="9" y="9" width="42" height="42" rx="5" fill="{c}"/></svg>"#
        ),
        "triangle" => format!(
            r#"<svg viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"><polygon points="30,6 54,54 6,54" fill="{c}"/></svg>"#
        ),
        "star" => format!(
            r#"<svg viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg"><polygon points="30,5 36,22 54,22 40,33 45,50 30,40 15,50 20,33 6,22 24,22" fill="{c}"/></svg>"#
        ),
        _ => String::new(),
    }
}

/// A generated click puzzle: token, signature, "blue circles", and the 9 cells.
#[derive(Clone, Debug)]
pub struct GeneratedPuzzle {
    pub token: Vec<u8>,
    pub sig: Vec<u8>,
    pub target_label: String,
    pub cells: Vec<PuzzleCell>,
}

/// The PRNG seed of a puzzle grid, the first 8 bytes of
/// HMAC-SHA256(key, "cpgrid:<scope>:<seedHex>"), big-endian. The seed in the token alone does not
/// reproduce the cells or the answer mask.
fn grid_seed_for(key: &[u8], scope: &[u8], seed_hex: &[u8]) -> i64 {
    let mac = hmac_sha256(key, &[b"cpgrid:", scope, b":", seed_hex]);
    i64::from_be_bytes(mac[..8].try_into().expect("8 bytes"))
}

/// Draws the target, its 1-3 positions and the decoys from `rng`.
fn layout_click_grid(rng: &mut SeededRng) -> (&'static str, &'static str, Vec<PuzzleCell>, u16) {
    let target_color = PUZZLE_COLORS[rng.next_below(PUZZLE_COLORS.len())];
    let target_shape = PUZZLE_SHAPES[rng.next_below(PUZZLE_SHAPES.len())];
    let target_count = 1 + rng.next_below(3);
    let perm = rng.shuffled_indices(9);
    let positions = &perm[..target_count];
    let mut cells = Vec::with_capacity(9);
    let mut correct_mask: u16 = 0;
    for i in 0..9 {
        if positions.contains(&i) {
            cells.push(PuzzleCell {
                shape: target_shape,
                color: target_color,
            });
            correct_mask |= 1 << i;
        } else {
            loop {
                let s = PUZZLE_SHAPES[rng.next_below(PUZZLE_SHAPES.len())];
                let c = PUZZLE_COLORS[rng.next_below(PUZZLE_COLORS.len())];
                if !(s == target_shape && c == target_color) {
                    cells.push(PuzzleCell { shape: s, color: c });
                    break;
                }
            }
        }
    }
    (target_color, target_shape, cells, correct_mask)
}

/// "cpuzzle:<scope>:<token>|<mask %04x>".
fn puzzle_answer_message(scope: &[u8], token: &[u8], mask: u16) -> Vec<u8> {
    [
        b"cpuzzle:".as_slice(),
        scope,
        b":",
        token,
        format!("|{mask:04x}").as_bytes(),
    ]
    .concat()
}

/// A click puzzle token with the 16 seed bytes given. The token carries no answer:
///
/// ```text
/// token = "<seedHex>|<color>|<shape>|<expiryHex>|<tmac>"
/// tmac  = hex HMAC("cptoken:<scope>:<seedHex>|<color>|<shape>|<expiryHex>")
/// sig   = hex HMAC("cpuzzle:<scope>:<token>|<mask %04x>")
/// ```
///
/// tmac authenticates the token alone, so the agent can spend it on any attempt without knowing
/// the answer; sig commits to the answer mask (bit i = cell i).
pub fn issue_click_puzzle_token_from(
    secret_key: &str,
    scope: &[u8],
    seed: [u8; 16],
    now: i64,
) -> GeneratedPuzzle {
    let seed_hex = hex_encode(&seed);
    let key = derive_signing_key(secret_key);
    let mut rng = SeededRng::new(grid_seed_for(&key, scope, &seed_hex));
    let (target_color, target_shape, cells, correct_mask) = layout_click_grid(&mut rng);
    let expiry = now + 300;
    let mut token = seed_hex;
    token.extend_from_slice(format!("|{target_color}|{target_shape}|{expiry:x}").as_bytes());
    let tmac = sign_message(&key, &[b"cptoken:", scope, b":", &token].concat());
    token.push(b'|');
    token.extend_from_slice(&tmac);
    let sig = sign_message(&key, &puzzle_answer_message(scope, &token, correct_mask));
    GeneratedPuzzle {
        token,
        sig,
        target_label: format!("{target_color} {}", puzzle_shape_plural(target_shape)),
        cells,
    }
}

pub fn issue_click_puzzle_token(
    secret_key: &str,
    scope: &[u8],
    now: i64,
) -> std::io::Result<GeneratedPuzzle> {
    let mut seed = [0u8; 16];
    fill_random_bytes(&mut seed)?;
    Ok(issue_click_puzzle_token_from(secret_key, scope, seed, now))
}

/// The expiry of a puzzle token that authenticates on its own (5 fields,
/// unexpired, tmac valid for `scope`). The agent spends a token on every attempt that passes this,
/// right answer or not.
pub fn click_puzzle_expiry(secret_key: &str, scope: &[u8], token: &[u8], now: i64) -> Option<i64> {
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let parts = wafio_bytetext::strings::splitn(token, b"|", 6);
    if parts.len() != 5 {
        return None;
    }
    let expiry = parse_int(parts[3], 16)?;
    if now > expiry {
        return None;
    }
    let body = &token[..token.len() - parts[4].len() - 1];
    let want = sign_message(
        &derive_signing_key(secret_key),
        &[b"cptoken:", scope, b":", body].concat(),
    );
    hmac_equal(parts[4], &want).then_some(expiry)
}

/// Checks that the token authenticates (`click_puzzle_expiry`) and sig
/// commits to exactly the cells clicked. `clicked_csv` is a comma-separated list of cell indices
/// 0..8 like "0,2,5"; any invalid index fails. Keeps no state: single use is the caller's job
/// (`challenge_replay`).
pub fn check_click_puzzle_token(
    secret_key: &str,
    scope: &[u8],
    token: &[u8],
    sig: &[u8],
    clicked_csv: &[u8],
    now: i64,
) -> bool {
    if click_puzzle_expiry(secret_key, scope, token, now).is_none() {
        return false;
    }
    if clicked_csv.len() > 64 {
        // 9 indices need at most 17 bytes.
        return false;
    }
    let mut clicked: u16 = 0;
    if !clicked_csv.is_empty() {
        for s in clicked_csv.split(|&c| c == b',') {
            let s = wafio_bytetext::strings::trim_whitespace(s);
            if s.is_empty() {
                continue;
            }
            match parse_int(s, 10) {
                Some(idx) if (0..=8).contains(&idx) => clicked |= 1 << idx,
                _ => return false,
            }
        }
    }
    let want = sign_message(
        &derive_signing_key(secret_key),
        &puzzle_answer_message(scope, token, clicked),
    );
    hmac_equal(sig, &want)
}

fn puzzle_grid(cells: &[PuzzleCell]) -> Vec<u8> {
    let mut g = Vec::new();
    for (i, cell) in cells.iter().enumerate() {
        g.extend_from_slice(
            format!(
                r#"<div class="cell" data-idx="{i}">{}<div class="ck">&#10003;</div></div>"#,
                puzzle_cell_svg(*cell)
            )
            .as_bytes(),
        );
    }
    g
}

fn error_banner_html(error_msg: &[u8]) -> Vec<u8> {
    if error_msg.is_empty() {
        Vec::new()
    } else {
        [b"<div class=\"err\">".as_slice(), error_msg, b"</div>"].concat()
    }
}

/// The click puzzle widget from a generated puzzle.
pub fn render_click_puzzle_widget_from(
    p: &GeneratedPuzzle,
    redirect_to: &[u8],
    error_msg: &[u8],
    extra: &[u8],
) -> Vec<u8> {
    let redirect_to = html_escape(redirect_to);
    fill_format_template(
        t::BUILD_CLICK_PUZZLE_WIDGET_FMT,
        &[
            t::CLICK_WIDGET_STYLES.as_bytes(),
            &error_banner_html(error_msg),
            p.target_label.as_bytes(),
            &puzzle_grid(&p.cells),
            VERIFY_ENDPOINT_PATH.as_bytes(),
            &p.token,
            &p.sig,
            &redirect_to,
            extra,
        ],
    )
}

pub fn render_click_puzzle_widget(
    secret_key: &str,
    scope: &[u8],
    redirect_to: &[u8],
    error_msg: &[u8],
    extra: &[u8],
    now: i64,
) -> std::io::Result<Vec<u8>> {
    Ok(render_click_puzzle_widget_from(
        &issue_click_puzzle_token(secret_key, scope, now)?,
        redirect_to,
        error_msg,
        extra,
    ))
}

pub fn render_js_challenge_page(nonce: &[u8], redirect_to: &[u8]) -> Vec<u8> {
    let body = render_js_challenge_script(nonce, &html_escape(redirect_to), b"");
    fill_format_template(t::BUILD_JS_CHALLENGE_PAGE_FMT, &[&body])
}

pub fn render_turnstile_page(site_key: &[u8], nonce: &[u8], redirect_to: &[u8]) -> Vec<u8> {
    let r = html_escape(redirect_to);
    fill_format_template(
        t::BUILD_TURNSTILE_CHALLENGE_PAGE_FMT,
        &[site_key, VERIFY_ENDPOINT_PATH.as_bytes(), &r, nonce],
    )
}

pub fn render_hcaptcha_page(site_key: &[u8], nonce: &[u8], redirect_to: &[u8]) -> Vec<u8> {
    let r = html_escape(redirect_to);
    fill_format_template(
        t::BUILD_H_CAPTCHA_CHALLENGE_PAGE_FMT,
        &[site_key, VERIFY_ENDPOINT_PATH.as_bytes(), &r, nonce],
    )
}

fn assemble_click_page(
    p: &GeneratedPuzzle,
    redirect_to: &[u8],
    error_msg: &[u8],
    extra: &[u8],
) -> Vec<u8> {
    let r = html_escape(redirect_to);
    fill_format_template(
        t::CLICK_CHALLENGE_PAGE_TEMPLATE,
        &[
            &error_banner_html(error_msg),
            p.target_label.as_bytes(),
            &puzzle_grid(&p.cells),
            VERIFY_ENDPOINT_PATH.as_bytes(),
            &p.token,
            &p.sig,
            &r,
            extra,
        ],
    )
}

const ADAPTIVE_STAGE2_INPUTS: &[u8] = br#"<input type="hidden" name="ct" value="adaptive"><input type="hidden" name="stage" value="2">"#;

/// The click challenge page from a generated puzzle.
pub fn render_click_page_from(
    p: &GeneratedPuzzle,
    redirect_to: &[u8],
    error_msg: &[u8],
) -> Vec<u8> {
    assemble_click_page(p, redirect_to, error_msg, b"")
}

pub fn render_click_page(
    secret_key: &str,
    scope: &[u8],
    redirect_to: &[u8],
    error_msg: &[u8],
    now: i64,
) -> std::io::Result<Vec<u8>> {
    Ok(render_click_page_from(
        &issue_click_puzzle_token(secret_key, scope, now)?,
        redirect_to,
        error_msg,
    ))
}

/// The adaptive click challenge page from a generated puzzle.
pub fn render_adaptive_click_page_from(
    p: &GeneratedPuzzle,
    redirect_to: &[u8],
    error_msg: &[u8],
) -> Vec<u8> {
    assemble_click_page(p, redirect_to, error_msg, ADAPTIVE_STAGE2_INPUTS)
}

pub fn render_adaptive_click_page(
    secret_key: &str,
    scope: &[u8],
    redirect_to: &[u8],
    error_msg: &[u8],
    now: i64,
) -> std::io::Result<Vec<u8>> {
    Ok(render_adaptive_click_page_from(
        &issue_click_puzzle_token(secret_key, scope, now)?,
        redirect_to,
        error_msg,
    ))
}

pub fn render_adaptive_js_page(nonce: &[u8], redirect_to: &[u8]) -> Vec<u8> {
    let body = render_js_challenge_script(
        nonce,
        &html_escape(redirect_to),
        br#"<input type="hidden" name="ct" value="adaptive">"#,
    );
    fill_format_template(t::BUILD_ADAPTIVE_JS_CHALLENGE_PAGE_FMT, &[&body])
}

pub fn render_simulation_page(redirect_to: &[u8]) -> Vec<u8> {
    let mut r = html_escape(redirect_to);
    if r.is_empty() {
        r = b"/".to_vec();
    }
    fill_format_template(t::BUILD_SIMULATION_SUCCESS_PAGE_FMT, &[&r])
}

pub(crate) const ADAPTIVE_STAGE2: &[u8] = ADAPTIVE_STAGE2_INPUTS;

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const SECRET: &str = "cookie-secret-0123456789abcdef";

    #[test]
    fn cookie_validates_without_ip_and_rejects_expired_tampered_legacy() {
        let c = issue_challenge_cookie_with_lifetime(SECRET, b"", 3600, NOW);
        assert!(verify_challenge_cookie(SECRET, b"", &c, NOW));
        assert!(!verify_challenge_cookie(
            SECRET,
            b"",
            &issue_challenge_cookie_with_lifetime(SECRET, b"", -60, NOW),
            NOW
        ));
        assert!(!verify_challenge_cookie(
            "a-different-secret-value-000000",
            b"",
            &c,
            NOW
        ));
        assert!(!verify_challenge_cookie(
            SECRET,
            b"",
            &[c.as_slice(), b"x"].concat(),
            NOW
        ));
        assert!(!verify_challenge_cookie(SECRET, b"", b"not-a-cookie", NOW));
        assert!(!verify_challenge_cookie(
            SECRET,
            b"",
            b"9999999999:1.2.3.4:deadbeef",
            NOW
        ));
    }

    // Round trip: id of 16 hex chars, every cookie unique.
    #[test]
    fn cookie_round_trip_and_unique_ids() {
        for secret in [SECRET, ""] {
            let c = issue_challenge_cookie_with_lifetime(secret, b"", 3600, NOW);
            let (id, exp) = decode_challenge_cookie(secret, b"", &c, NOW).unwrap();
            assert_eq!((id.len(), exp), (16, NOW + 3600), "secret {secret:?}");
            assert_ne!(
                issue_challenge_cookie_with_lifetime(secret, b"", 3600, NOW),
                c,
                "two cookies minted in the same second must differ"
            );
        }
    }

    // The key of the old derivation (a public constant) signs nothing, the 2-part form is gone,
    // the id is 16 lowercase hex chars.
    #[test]
    fn cookie_rejects_old_public_key_and_two_part_form() {
        let exp = (NOW + 3600).to_string();
        let public = sha256(b"wafio-challenge-v1:");
        let inst = derive_signing_key("");
        assert_ne!(public, inst);
        let sign =
            |k: &[u8], msg: String| String::from_utf8(sign_message(k, msg.as_bytes())).unwrap();
        for (name, c) in [
            (
                "old 2-part, public key",
                format!("{exp}:{}", sign(&public, exp.clone())),
            ),
            (
                "3-part, public key",
                format!(
                    "{exp}:0123456789abcdef:{}",
                    sign(&public, format!("{exp}:0123456789abcdef:"))
                ),
            ),
            (
                "bad id (uppercase)",
                format!(
                    "{exp}:0123456789ABCDEF:{}",
                    sign(&inst, format!("{exp}:0123456789ABCDEF:"))
                ),
            ),
            (
                "bad id (short)",
                format!("{exp}:0123:{}", sign(&inst, format!("{exp}:0123:"))),
            ),
            (
                "2-part, instance key",
                format!("{exp}:{}", sign(&inst, exp.clone())),
            ),
            (
                "4-part",
                format!(
                    "{exp}:0123456789abcdef:{}:x",
                    sign(&inst, format!("{exp}:0123456789abcdef:"))
                ),
            ),
        ] {
            assert!(
                !verify_challenge_cookie("", b"", c.as_bytes(), NOW),
                "{name}"
            );
        }
    }

    // A token or cookie of one app opens no other app, with or without a provider secret_key.
    #[test]
    fn macs_are_bound_to_scope() {
        for secret in ["", SECRET] {
            let c = issue_challenge_cookie_with_lifetime(secret, b"app-a", 3600, NOW);
            assert!(
                verify_challenge_cookie(secret, b"app-a", &c, NOW),
                "secret {secret:?}"
            );
            for other in [&b"app-b"[..], b""] {
                assert!(!verify_challenge_cookie(secret, other, &c, NOW));
            }
            let pow = issue_pow_token(secret, b"app-a", 4, NOW).unwrap();
            assert!(check_pow_token(secret, b"app-a", &pow, NOW).is_some());
            assert!(check_pow_token(secret, b"app-b", &pow, NOW).is_none());
            let p = issue_click_puzzle_token(secret, b"app-a", NOW).unwrap();
            let csv = expected_puzzle_answer(secret, b"app-a", &p);
            assert!(click_puzzle_expiry(secret, b"app-b", &p.token, NOW).is_none());
            assert!(!check_click_puzzle_token(
                secret,
                b"app-b",
                &p.token,
                &p.sig,
                csv.as_bytes(),
                NOW
            ));
            assert!(check_click_puzzle_token(
                secret,
                b"app-a",
                &p.token,
                &p.sig,
                csv.as_bytes(),
                NOW
            ));
        }
    }

    /// The clicked-cell CSV a puzzle's sig commits to: the token carries no answer, so try every
    /// mask (512) against the validator. Exactly one must match.
    fn expected_puzzle_answer(secret: &str, scope: &[u8], p: &GeneratedPuzzle) -> String {
        let found: Vec<String> = (0..512u32)
            .map(|mask| {
                (0..9)
                    .filter(|i| mask & (1 << i) != 0)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .filter(|csv| {
                check_click_puzzle_token(secret, scope, &p.token, &p.sig, csv.as_bytes(), NOW)
            })
            .collect();
        assert_eq!(
            found.len(),
            1,
            "want exactly one accepted mask, got {found:?}"
        );
        found.into_iter().next().unwrap()
    }

    #[test]
    fn safe_redirect_cases() {
        for (inp, want) in [
            ("", "/"),
            ("/dashboard", "/dashboard"),
            ("/a?b=c&d=e", "/a?b=c&d=e"),
            ("//evil.com", "/"),
            ("/\\evil.com", "/"),
            ("https://evil.com", "/"),
            ("evil.com", "/"),
            ("/ok\r\nSet-Cookie: x=1", "/"),
            ("/path\twith-tab", "/"),
            ("/\"><script>x</script>", "/\"><script>x</script>"),
        ] {
            assert_eq!(
                sanitize_redirect_target(inp.as_bytes()),
                want.as_bytes(),
                "{inp:?}"
            );
        }
    }

    #[test]
    fn pages_escape_redirect() {
        let payload = b"/\"><script>alert(1)</script>";
        let p = issue_click_puzzle_token_from("secret-0123456789abcdef", b"", [7; 16], NOW);
        for page in [
            render_js_challenge_page(b"nonce", payload),
            render_adaptive_js_page(b"nonce", payload),
            render_turnstile_page(b"sitekey", b"nonce", payload),
            render_simulation_page(payload),
            render_click_page_from(&p, payload, b""),
        ] {
            assert!(!wafio_bytetext::strings::contains(
                &page,
                b"\"><script>alert(1)"
            ));
        }
    }

    #[test]
    fn pow_token_generation_and_validation() {
        let tok = issue_pow_token(SECRET, b"", 12, NOW).unwrap();
        let (salt, diff) = check_pow_token(SECRET, b"", &tok, NOW).unwrap();
        assert!(!salt.is_empty());
        assert_eq!(diff, 12);
        let mut tampered = tok.clone();
        tampered[0] = if tampered[0] == b'a' { b'b' } else { b'a' };
        assert!(check_pow_token(SECRET, b"", &tampered, NOW).is_none());
        assert!(check_pow_token("wrong", b"", &tok, NOW).is_none());
        assert!(check_pow_token(SECRET, b"", &tok, NOW + 301).is_none());
    }

    #[test]
    fn pow_token_rejects_extra_colons_and_old_mac_input() {
        let tok = issue_pow_token(SECRET, b"app", 4, NOW).unwrap();
        assert!(check_pow_token(SECRET, b"app", &[tok.as_slice(), b":x"].concat(), NOW).is_none());
        // A MAC computed without the scope suffix (the previous input) is not valid.
        let p: Vec<&[u8]> = tok.split(|&c| c == b':').collect();
        let body = [p[0], b":", p[1], b":", p[2]].concat();
        let old = [
            body.clone(),
            b":".to_vec(),
            sign_message(&derive_signing_key(SECRET), &body),
        ]
        .concat();
        assert!(check_pow_token(SECRET, b"app", &old, NOW).is_none());
    }

    #[test]
    fn pow_solver_and_validator() {
        let salt = b"abcdef0123456789";
        let sol = (0..100_000)
            .find(|&s| check_pow_solution(salt, s, 12))
            .expect("solution");
        assert!(check_pow_solution(salt, sol, 12));
        assert!(!check_pow_solution(salt, sol, 28) || check_pow_solution(salt, sol, 28));
        assert!(check_pow_solution(salt, 1, 0));
        assert!(!check_pow_solution(salt, 1, 33));
    }

    #[test]
    fn telemetry_scoring_and_submission() {
        let clean = BrowserSignals {
            duration_ms: 150,
            user_agent: b"Mozilla/5.0 Chrome/120".to_vec(),
            ..Default::default()
        };
        let (score, bot, reasons) = score_browser_signals(Some(&clean));
        assert_eq!((score, bot, reasons.len()), (0, false, 0));
        let stealth = BrowserSignals {
            cdp_detected: true,
            prototype_tampered: true,
            software_renderer: true,
            ..Default::default()
        };
        let (score, bot, reasons) = score_browser_signals(Some(&stealth));
        assert!(bot && score >= 100 && reasons.len() > 1);

        let tok = issue_pow_token(SECRET, b"", 8, NOW).unwrap();
        let (salt, _) = check_pow_token(SECRET, b"", &tok, NOW).unwrap();
        let sol = (0..1_000_000)
            .find(|&s| check_pow_solution(&salt, s, 8))
            .unwrap();
        let tel = crate::crypto::encode_base64(
            crate::crypto::B64::Std,
            br#"{"wd":false,"dur":150,"ua":"Mozilla Chrome/1"}"#,
        );
        let (ok, bot, _, _) = verify_challenge_submission(
            SECRET,
            b"",
            &tok,
            sol.to_string().as_bytes(),
            &tel,
            b"0",
            NOW,
        );
        assert!(ok && !bot);
        let (ok, ..) = verify_challenge_submission(
            SECRET,
            b"",
            &tok,
            (sol + 1).to_string().as_bytes(),
            b"",
            b"0",
            NOW,
        );
        assert!(!ok || check_pow_solution(&salt, sol + 1, 8));
        let bad =
            crate::crypto::encode_base64(crate::crypto::B64::RawStd, br#"{"cdp":true,"pt":true}"#);
        let (ok, bot, _, reasons) = verify_challenge_submission(
            SECRET,
            b"",
            &tok,
            sol.to_string().as_bytes(),
            &bad,
            b"0",
            NOW,
        );
        assert!(ok && bot && !reasons.is_empty());
        // Wrong field type: the telemetry does not decode and is ignored.
        let typed = crate::crypto::encode_base64(crate::crypto::B64::Std, br#"{"cdp":1}"#);
        let (_, bot, score, _) = verify_challenge_submission(
            SECRET,
            b"",
            &tok,
            sol.to_string().as_bytes(),
            &typed,
            b"0",
            NOW,
        );
        assert!(!bot && score == 0);
    }

    // A 3-part nonce (what turnstile/hcaptcha pages embed) is not a PoW token: it never
    // verifies, with or without telemetry.
    #[test]
    fn submission_rejects_non_pow_tokens() {
        let nonce = issue_challenge_nonce(SECRET, NOW).unwrap();
        let pow0 = format!("salt:{}:0", NOW + 60);
        let signed0 = format!(
            "{pow0}:{}",
            String::from_utf8(sign_message(
                &derive_signing_key(SECRET),
                format!("{pow0}:").as_bytes()
            ))
            .unwrap()
        );
        for (name, tok) in [
            ("3-part nonce", nonce.clone()),
            ("nonce with proof", [nonce.as_slice(), b"|x"].concat()),
            ("empty", Vec::new()),
            ("difficulty 0 signed", signed0.into_bytes()),
        ] {
            for tel in [&b""[..], b"e30="] {
                for hless in [&b"0"[..], b"1"] {
                    let (ok, ..) =
                        verify_challenge_submission(SECRET, b"", &tok, b"", tel, hless, NOW);
                    assert!(!ok, "{name} (telemetry {tel:?}) verified");
                }
            }
        }
    }

    #[test]
    fn click_puzzle_round_trip() {
        let p = issue_click_puzzle_token_from(SECRET, b"", [1; 16], NOW);
        let mask: Vec<String> = p
            .cells
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                p.target_label.starts_with(c.color) && p.target_label.contains(c.shape)
            })
            .map(|(i, _)| i.to_string())
            .collect();
        let v = |sig: &[u8], csv: &[u8], now| {
            check_click_puzzle_token(SECRET, b"", &p.token, sig, csv, now)
        };
        assert!(v(&p.sig, mask.join(", ").as_bytes(), NOW));
        assert!(!v(&p.sig, b"9", NOW));
        assert!(!v(&p.sig, mask.join(",").as_bytes(), NOW + 301));
        assert_eq!(expected_puzzle_answer(SECRET, b"", &p), mask.join(","));
    }

    #[test]
    fn click_puzzle_token_carries_no_answer() {
        for _ in 0..50 {
            let p = issue_click_puzzle_token(SECRET, b"app", NOW).unwrap();
            let mut parts: Vec<Vec<u8>> =
                p.token.split(|&c| c == b'|').map(<[u8]>::to_vec).collect();
            assert!(
                parts.len() == 5 && parts[0].len() == 32 && parts[4].len() == 64,
                "token shape: {:?}",
                String::from_utf8_lossy(&p.token)
            );
            let csv = expected_puzzle_answer(SECRET, b"app", &p);
            assert!(!csv.is_empty(), "the answer clicks at least one cell");
            let v = |csv: &str| {
                check_click_puzzle_token(SECRET, b"app", &p.token, &p.sig, csv.as_bytes(), NOW)
            };
            assert!(
                v(&format!("{csv},{csv}")),
                "duplicate indices of the right cells"
            );
            for bad in [
                format!("{csv},9"),
                format!("{csv},-1"),
                format!("{csv},x"),
                "1,".repeat(100),
            ] {
                assert!(!v(&bad), "clicked {bad:?} accepted");
            }
            // tmac covers the expiry: a tampered token is not authentic.
            parts[3] = b"ffffffffff".to_vec();
            assert!(click_puzzle_expiry(SECRET, b"app", &parts.join(&b'|'), NOW).is_none());
        }
        let a = issue_click_puzzle_token(SECRET, b"", NOW).unwrap();
        let b = issue_click_puzzle_token(SECRET, b"", NOW).unwrap();
        let csv = expected_puzzle_answer(SECRET, b"", &a);
        assert!(
            !check_click_puzzle_token(SECRET, b"", &b.token, &a.sig, csv.as_bytes(), NOW),
            "sig of one token validated another"
        );
    }

    #[test]
    fn click_puzzle_token_expiry_rejects_expired_and_malformed() {
        let p = issue_click_puzzle_token(SECRET, b"", NOW).unwrap();
        assert_eq!(
            click_puzzle_expiry(SECRET, b"", &p.token, NOW),
            Some(NOW + 300)
        );
        assert_eq!(click_puzzle_expiry(SECRET, b"", &p.token, NOW + 301), None);
        let t = String::from_utf8(p.token.clone()).unwrap();
        let fields: Vec<&str> = t.split('|').collect();
        for (name, bad) in [
            ("empty", String::new()),
            ("4 fields", fields[..4].join("|")),
            ("6 fields", format!("{t}|x")),
            ("no tmac", t[..t.rfind('|').unwrap() + 1].to_string()),
            (
                "old format",
                "00112233445566778899aabbccddeeff|red|star|01ff|ffffffff".to_string(),
            ),
        ] {
            assert!(
                click_puzzle_expiry(SECRET, b"", bad.as_bytes(), NOW).is_none(),
                "{name} accepted"
            );
        }
    }

    // The cells come from an HMAC-keyed seed.
    #[test]
    fn click_puzzle_grid_needs_the_key_not_just_the_seed() {
        let key = derive_signing_key(SECRET);
        for i in 0..20u8 {
            let seed = [i + 1; 16];
            let p = issue_click_puzzle_token_from(SECRET, b"app-a", seed, NOW);
            let cells = |rng_seed: i64| {
                layout_click_grid(&mut SeededRng::new(rng_seed))
                    .2
                    .iter()
                    .map(|c| (c.shape, c.color))
                    .collect::<Vec<_>>()
            };
            let shown: Vec<_> = p.cells.iter().map(|c| (c.shape, c.color)).collect();
            // The raw token seed (the old derivation) must not give the shown cells.
            assert_ne!(
                cells(i64::from_be_bytes(seed[..8].try_into().unwrap())),
                shown
            );
            // Documented derivation: first 8 bytes of HMAC-SHA256(key, "cpgrid:<scope>:<seedHex>").
            let mac = hmac_sha256(&key, &[b"cpgrid:app-a:", &hex_encode(&seed)]);
            assert_eq!(
                cells(i64::from_be_bytes(mac[..8].try_into().unwrap())),
                shown
            );
        }
    }

    // Oversized values are refused before any split or MAC.
    #[test]
    fn parsers_reject_huge_inputs() {
        let huge_token = b"a:".repeat(4 << 20);
        let huge_cookie = b"a:".repeat(8 << 10);
        let huge_puzzle = b"a|".repeat(4 << 20);
        assert!(check_pow_token(SECRET, b"", &huge_token, NOW).is_none());
        assert!(decode_challenge_cookie(SECRET, b"", &huge_cookie, NOW).is_none());
        assert!(click_puzzle_expiry(SECRET, b"", &huge_puzzle, NOW).is_none());
        let p = issue_click_puzzle_token(SECRET, b"", NOW).unwrap();
        let huge_csv = b"1,".repeat(4 << 20);
        assert!(!check_click_puzzle_token(
            SECRET, b"", &p.token, &p.sig, &huge_csv, NOW
        ));
        // Exactly at the caps a well-formed value still parses past the length check.
        assert!(check_pow_token(SECRET, b"", &b"x".repeat(MAX_TOKEN_BYTES), NOW).is_none());
    }

    #[test]
    fn challenge_type_is_normalised_at_load() {
        for (typ, want) in [
            ("", "js_challenge"),
            ("js", "js_challenge"),
            ("JS_CHALLENGE", "js_challenge"),
            ("nonsense", "js_challenge"),
            ("js_challenge", "js_challenge"),
            ("turnstile", "turnstile"),
            ("hcaptcha", "hcaptcha"),
            ("click_puzzle", "click_puzzle"),
            ("adaptive", "adaptive"),
        ] {
            let raw = format!(r#"{{"enabled":true,"type":"{typ}"}}"#);
            let c = ChallengeSettings::from_rules_json(raw.as_bytes()).unwrap();
            assert_eq!(c.type_, want, "type {typ:?}");
        }
    }

    #[test]
    fn inject_and_quote() {
        assert_eq!(
            fill_custom_page(b"<p>{{X}}</p>", b"{{X}}", b"I"),
            b"<p>I</p>"
        );
        assert_eq!(
            fill_custom_page(b"<BODY>a</BODY>", b"{{X}}", b"I"),
            b"<BODY>aI\n</BODY>"
        );
        assert_eq!(fill_custom_page(b"a", b"{{X}}", b"I"), b"a\nI");
        assert_eq!(
            quote_literal(b"a\"b\\\n\x01\xff\xe2\x80\xa8"),
            b"\"a\\\"b\\\\\\n\\x01\\xff\\u2028\""
        );
    }

    #[test]
    fn config_from_json_defaults_and_good_bots() {
        let c = ChallengeSettings::from_rules_json(br#"{"Enabled":true,"good_bot_allowlist":["  ","curl{2}","bad(","Mozilla.*Bot"],"allow_local_ips":false}"#).unwrap();
        assert!(
            c.enabled
                && c.allow_local_ips == Some(false)
                && c.type_ == "js_challenge"
                && c.cookie_ttl_sec == 3600
        );
        assert_eq!(c.good_bot_matchers.len(), 2);
        assert!(c.matches_good_bot(b"xx CURL{2} yy"));
        assert!(c.matches_good_bot(b"Mozilla/5.0 FooBot"));
        assert!(!c.matches_good_bot(b""));
        assert!(ChallengeSettings::from_rules_json(br#"{"enabled":"yes"}"#).is_none());
        assert!(ChallengeSettings::from_rules_json(br#"{"cookie_ttl_sec":1.5}"#).is_none());
        let d = ChallengeSettings::from_rules_json(b"null").unwrap();
        assert!(d.matches_good_bot(b"Mozilla/5.0 (compatible; Googlebot/2.1)"));
    }

    // Regexp semantics: ASCII \b \d \s, repeat limits.
    #[test]
    fn good_bot_patterns_follow_reference_regex_rules() {
        let cfg = |list: &[&str]| {
            let mut c = ChallengeSettings {
                good_bot_allowlist: list.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            };
            finalize_challenge_settings(&mut c);
            c
        };
        let c = cfg(&["\\bbot\\b", "MyBot\\d", "Bot\\sX", "^x{1001}"]);
        assert_eq!(c.good_bot_matchers.len(), 3);
        assert!(c.matches_good_bot("ébot/1.0".as_bytes()));
        assert!(!c.matches_good_bot("MyBot١".as_bytes()));
        let ws = cfg(&["Bot\\sX"]);
        assert!(
            ws.matches_good_bot(b"Bot X")
                && !ws.matches_good_bot("Bot\u{a0}X".as_bytes())
                && !ws.matches_good_bot(b"Bot\x0bX")
        );
        assert!(!c.matches_good_bot("x".repeat(1001).as_bytes()));
        assert!(c.matches_good_bot(b"a\xffbot"));
        for (pat, ok) in [
            ("(a{30}){40}", false),
            ("(b{30}){33}", true),
            ("c**", false),
            ("d*?", true),
            ("^e{2}{3}", false),
            ("q{2}??", false),
            ("(?:h{10}|i){101}", false),
            ("(?P<n>j{2}){500}", true),
            ("(?:y{600}){1,}", true),
            ("(?:y{600}){2,}", false),
            ("[[:alpha:]{]{1000}", true),
            ("\\Q{2000}\\E", true),
            ("^a{1000000000}", false),
            ("e{2}{3}", true), // no metacharacter: escaped literal,
        ] {
            assert_eq!(cfg(&[pat]).good_bot_matchers.len(), ok as usize, "{pat}");
        }
    }
}
