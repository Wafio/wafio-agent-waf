//! Bot protection L1 (User-Agent, client hints, headers) and L2 (JA4 / JA3 fingerprints).

use std::collections::{BTreeMap, HashSet};
use wafio_bytetext::base64::STANDARD;
use wafio_bytetext::pattern::{CompiledRegex as ByteRegex, escape_regex_meta};
use wafio_bytetext::strings::{
    contains, eq_ignore_case, to_lowercase_cow as to_lowercase, trim_whitespace,
};

/// For an ASCII char set.
fn contains_any_of(s: &[u8], chars: &[u8]) -> bool {
    s.iter().any(|c| chars.contains(c))
}

/// Trims bytes of an ASCII cutset from both ends.
fn trim_chars<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
    let mut end = s.len();
    while end > 0 && cutset.contains(&s[end - 1]) {
        end -= 1;
    }
    let mut start = 0;
    while start < end && cutset.contains(&s[start]) {
        start += 1;
    }
    &s[start..end]
}

pub const REASON_BOT_UA_EMPTY: &str = "BOT_UA_EMPTY";
pub const REASON_BOT_UA_BLOCK: &str = "BOT_UA_BLOCK";
pub const REASON_BOT_UA_ALLOW: &str = "BOT_UA_ALLOW";
pub const REASON_BOT_HEADERS: &str = "BOT_HEADERS";
pub const REASON_BOT_JA4_BLOCK: &str = "BOT_JA4_BLOCK";
pub const REASON_BOT_JA4_ALLOW: &str = "BOT_JA4_ALLOW";
pub const REASON_BOT_JA3_BLOCK: &str = "BOT_JA3_BLOCK";
pub const REASON_BOT_JA3_ALLOW: &str = "BOT_JA3_ALLOW";
pub const REASON_BOT_CLIENT_HINTS_MISMATCH: &str = "BOT_CLIENT_HINTS_MISMATCH";
pub const REASON_BOT_MISSING_CLIENT_HINTS: &str = "BOT_MISSING_CLIENT_HINTS";
pub const REASON_BOT_HEADLESS: &str = "BOT_HEADLESS";
pub const REASON_BOT_BROWSER_IMPERSONATION: &str = "BOT_BROWSER_IMPERSONATION";
pub const REASON_BOT_AI_CRAWLER: &str = "BOT_AI_CRAWLER";

/// Request headers as wafio-domain carries them (name → values; sorted map).
pub type Headers = BTreeMap<Vec<u8>, Vec<Vec<u8>>>;

/// The request fields bot detection reads.
#[derive(Clone, Copy, Debug)]
pub struct BotRequest<'a> {
    pub method: &'a [u8],
    pub uri: &'a [u8],
    pub user_agent: &'a [u8],
    pub ja3: &'a [u8],
    pub ja4: &'a [u8],
    pub headers: &'a Headers,
}

/// The rules_json "bot_protection" block. Call
/// `compile_bot_protection` once after filling the public fields.
#[derive(Default)]
pub struct BotProtectionConfig {
    pub enabled: bool,
    /// "off" | "log" | "block" | "score"
    pub mode: String,
    pub base_score: i64,
    /// In Score mode the bot score blocks from this value on.
    pub score_threshold: i64,
    pub empty_ua_block: bool,
    pub ua_blocklist: Vec<String>,
    pub ua_allowlist: Vec<String>,
    pub ja4_blocklist: Vec<String>,
    pub ja4_allowlist: Vec<String>,
    pub ja3_blocklist: Vec<String>,
    pub ja3_allowlist: Vec<String>,
    pub header_checks: bool,
    pub client_hints_check: bool,
    pub browser_impersonation_check: bool,
    pub block_ai_crawlers: bool,
    ua_block_regex: Option<ByteRegex>,
    ua_allow_regex: Option<ByteRegex>,
    ai_crawler_regex: Option<ByteRegex>,
    ja4_block_set: HashSet<Vec<u8>>,
    ja4_allow_set: HashSet<Vec<u8>>,
    ja3_block_set: HashSet<Vec<u8>>,
    ja3_allow_set: HashSet<Vec<u8>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BotResult {
    /// 0 = not a bot / allowlist hit.
    pub score: i64,
    pub reason: &'static str,
    pub match_detail: Vec<u8>,
}

/// Compiles the regexes and builds the sets.
pub fn compile_bot_protection(cfg: &mut BotProtectionConfig) {
    cfg.ua_block_regex = build_combined_regex(&cfg.ua_blocklist);
    cfg.ua_allow_regex = build_combined_regex(&cfg.ua_allowlist);
    cfg.ja4_block_set = slice_to_set(&cfg.ja4_blocklist);
    cfg.ja4_allow_set = slice_to_set(&cfg.ja4_allowlist);
    cfg.ja3_block_set = slice_to_set(&cfg.ja3_blocklist);
    cfg.ja3_allow_set = slice_to_set(&cfg.ja3_allowlist);
    if cfg.block_ai_crawlers {
        cfg.ai_crawler_regex = Some(ByteRegex::compile_or_panic(
            r"(?i)(?:gptbot|chatgpt-user|claudebot|anthropic-ai|bytespider|ccbot|perplexitybot|diffbot|facebookbot|amazonbot|omgilibot|youbot|applebot-extended)",
        ));
    }
}

/// Builds one case-insensitive alternation; patterns
/// without regex metacharacters are literals. None when empty or invalid.
fn build_combined_regex(patterns: &[String]) -> Option<ByteRegex> {
    let mut parts: Vec<String> = Vec::new();
    for p in patterns {
        let p = trim_whitespace(p.as_bytes());
        if p.is_empty() {
            continue;
        }
        let p = if contains_any_of(p, b".*+?[]()|^$\\") {
            p.to_vec()
        } else {
            escape_regex_meta(p)
        };
        parts.push(String::from_utf8_lossy(&p).into_owned());
    }
    if parts.is_empty() {
        return None;
    }
    ByteRegex::compile(&format!("(?i)(?:{})", parts.join("|"))).ok()
}

/// Trimmed, lower-cased fingerprints as a set; empty ones dropped.
fn slice_to_set(list: &[String]) -> HashSet<Vec<u8>> {
    list.iter()
        .map(|s| trim_whitespace(&to_lowercase(s.as_bytes())).to_vec())
        .filter(|s| !s.is_empty())
        .collect()
}

fn hit(cfg: &BotProtectionConfig, reason: &'static str, detail: &[u8]) -> BotResult {
    BotResult {
        score: cfg.base_score,
        reason,
        match_detail: detail.to_vec(),
    }
}

fn with_prefix(prefix: &str, rest: &[u8]) -> Vec<u8> {
    let mut v = prefix.as_bytes().to_vec();
    v.extend_from_slice(rest);
    v
}

/// Classifies a request: L2 (JA4, JA3) first, then L1 (user agent, client hints, headers).
pub fn classify_bot(req: &BotRequest<'_>, cfg: Option<&BotProtectionConfig>) -> BotResult {
    let Some(cfg) = cfg else {
        return BotResult::default();
    };
    if !cfg.enabled || cfg.mode == "off" {
        return BotResult::default();
    }
    if !req.ja4.is_empty() && (!cfg.ja4_allow_set.is_empty() || !cfg.ja4_block_set.is_empty()) {
        let ja4 = to_lowercase(req.ja4);
        let ja4 = trim_whitespace(&ja4);
        if !ja4.is_empty() {
            if cfg.ja4_allow_set.contains(ja4) {
                return BotResult {
                    reason: REASON_BOT_JA4_ALLOW,
                    ..Default::default()
                };
            }
            if cfg.ja4_block_set.contains(ja4) {
                return hit(cfg, REASON_BOT_JA4_BLOCK, &with_prefix("ja4:", ja4));
            }
        }
    }
    if !req.ja3.is_empty() && (!cfg.ja3_allow_set.is_empty() || !cfg.ja3_block_set.is_empty()) {
        let ja3 = to_lowercase(req.ja3);
        let ja3 = trim_whitespace(&ja3);
        if !ja3.is_empty() {
            if cfg.ja3_allow_set.contains(ja3) {
                return BotResult {
                    reason: REASON_BOT_JA3_ALLOW,
                    ..Default::default()
                };
            }
            if cfg.ja3_block_set.contains(ja3) {
                return hit(cfg, REASON_BOT_JA3_BLOCK, &with_prefix("ja3:", ja3));
            }
        }
    }
    let ua = trim_whitespace(req.user_agent);
    let ua_lower = to_lowercase(ua);
    if cfg.ua_allow_regex.as_ref().is_some_and(|r| r.is_match(ua)) {
        return BotResult {
            reason: REASON_BOT_UA_ALLOW,
            ..Default::default()
        };
    }
    if cfg.empty_ua_block && (ua.is_empty() || ua == b"-") {
        return hit(cfg, REASON_BOT_UA_EMPTY, b"empty_ua");
    }
    if cfg.block_ai_crawlers
        && cfg
            .ai_crawler_regex
            .as_ref()
            .is_some_and(|r| r.is_match(ua))
    {
        return hit(cfg, REASON_BOT_AI_CRAWLER, &with_prefix("ai_crawler:", ua));
    }
    let sec_ch_ua = header_value(req.headers, "Sec-CH-UA");
    if contains(&to_lowercase(sec_ch_ua), b"headlesschrome")
        || contains(&ua_lower, b"headlesschrome")
    {
        return hit(cfg, REASON_BOT_HEADLESS, b"headless_chrome");
    }
    if cfg.ua_block_regex.as_ref().is_some_and(|r| r.is_match(ua)) {
        return hit(cfg, REASON_BOT_UA_BLOCK, &with_prefix("ua:", ua));
    }
    if cfg.client_hints_check && !ua.is_empty() {
        let is_chromium = (contains(&ua_lower, b"chrome/") || contains(&ua_lower, b"edg/"))
            && !contains(&ua_lower, b"bot")
            && !contains(&ua_lower, b"crawler")
            && !contains(&ua_lower, b"spider");
        if is_chromium {
            let sec_fetch_mode = header_value(req.headers, "Sec-Fetch-Mode");
            if sec_ch_ua.is_empty()
                && sec_fetch_mode.is_empty()
                && !is_websocket_opening_handshake(req)
            {
                return hit(cfg, REASON_BOT_MISSING_CLIENT_HINTS, b"missing_sec_ch_ua");
            }
            let platform =
                to_lowercase(header_value(req.headers, "Sec-CH-UA-Platform")).into_owned();
            let platform = trim_chars(&platform, b"\"");
            if !platform.is_empty() {
                let p = platform;
                if contains(&ua_lower, b"windows")
                    && matches!(p, b"linux" | b"android" | b"macos" | b"ios")
                {
                    return hit(
                        cfg,
                        REASON_BOT_CLIENT_HINTS_MISMATCH,
                        &with_prefix("platform_mismatch:ua_windows_ch_", p),
                    );
                }
                if contains(&ua_lower, b"macintosh")
                    && matches!(p, b"windows" | b"linux" | b"android")
                {
                    return hit(
                        cfg,
                        REASON_BOT_CLIENT_HINTS_MISMATCH,
                        &with_prefix("platform_mismatch:ua_mac_ch_", p),
                    );
                }
            }
        }
    }
    if cfg.browser_impersonation_check && !ua.is_empty() {
        let is_browser = ua.starts_with(b"Mozilla/")
            && (contains(&ua_lower, b"chrome/")
                || contains(&ua_lower, b"firefox/")
                || contains(&ua_lower, b"safari/"));
        if is_browser {
            let accept = header_value(req.headers, "Accept");
            if req.method == b"GET"
                && (req.uri == b"/" || req.uri.ends_with(b".html"))
                && accept == b"*/*"
            {
                return hit(
                    cfg,
                    REASON_BOT_BROWSER_IMPERSONATION,
                    b"browser_accept_star",
                );
            }
            let accept_lang = header_value(req.headers, "Accept-Language");
            let sec_fetch_mode = header_value(req.headers, "Sec-Fetch-Mode");
            if accept_lang.is_empty() && sec_fetch_mode.is_empty() && accept.is_empty() {
                return hit(
                    cfg,
                    REASON_BOT_BROWSER_IMPERSONATION,
                    b"missing_browser_headers",
                );
            }
        }
    }
    if cfg.header_checks && !ua.is_empty() {
        let accept = header_value(req.headers, "Accept");
        let accept_lang = header_value(req.headers, "Accept-Language");
        if accept.is_empty() && accept_lang.is_empty() {
            return hit(cfg, REASON_BOT_HEADERS, b"missing_accept_accept_language");
        }
    }
    BotResult::default()
}

/// Whether the request is a WebSocket opening handshake (RFC 6455 §4.1).
fn is_websocket_opening_handshake(req: &BotRequest<'_>) -> bool {
    if req.method != b"GET" {
        return false;
    }
    if !header_lists_token(req.headers, "Upgrade", "websocket")
        || !header_lists_token(req.headers, "Connection", "upgrade")
    {
        return false;
    }
    if header_value(req.headers, "Sec-WebSocket-Version") != b"13" {
        return false;
    }
    STANDARD
        .decode(header_value(req.headers, "Sec-WebSocket-Key"))
        .is_ok_and(|k| k.len() == 16)
}

fn header_lists_token(headers: &Headers, name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|(k, _)| eq_ignore_case(k, name.as_bytes()))
        .any(|(_, vals)| {
            vals.iter().any(|v| {
                v.split(|&c| c == b',')
                    .any(|part| eq_ignore_case(trim_whitespace(part), token.as_bytes()))
            })
        })
}

/// Canonical MIME header key (`Content-Type` form) for a valid ASCII header name.
fn canonical_header_name(name: &str) -> Vec<u8> {
    let b = name.as_bytes();
    if !b
        .iter()
        .all(|&c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
    {
        return b.to_vec();
    }
    let mut upper = true;
    b.iter()
        .map(|&c| {
            let o = if upper {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            upper = c == b'-';
            o
        })
        .collect()
}

/// Canonical key first, then a case-insensitive scan
/// (sorted key order, so the pick does not depend on map order).
pub fn header_value<'a>(headers: &'a Headers, name: &str) -> &'a [u8] {
    if let Some(vals) = headers.get(&canonical_header_name(name))
        && let Some(v) = vals.first()
    {
        return trim_whitespace(v);
    }
    let lower = to_lowercase(name.as_bytes());
    for (k, v) in headers {
        if to_lowercase(k) == lower
            && let Some(first) = v.first()
        {
            return trim_whitespace(first);
        }
    }
    b""
}
