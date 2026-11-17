//! Rules JSON (the default document, loading and validation with the agent's semantics), the policy
//! blocks the WAF agent reads, and path-exception matching. Stored documents of earlier versions
//! still load: keys this agent no longer reads are ignored, and `disable_semantic` still means
//! "inspection off".

use std::collections::{BTreeMap, BTreeSet};

use wafio_bytetext::pattern::CompiledRegex;
use wafio_domain::text_helpers::{eq_ignore_case, trim_whitespace_str};

use crate::custom_rules_v2::{
    TuningEffect, TuningTarget, decode_tuning_effect, decode_tuning_target,
};
use crate::custom_rules_validate::{check_tuning_effect, is_unknown_semantic_engine};
use crate::forwarded_path::{
    RequestPathReadings, readings_for_proxy_request, readings_for_raw_target,
};
use crate::ip_network::{self, IpNetwork};
use crate::json_decode::{self, DecodeTrace, JsonDecodeError, Value};

/// What a bot check in Score mode compares the bot score with when the document names no `score_threshold`.
pub const DEFAULT_BOT_SCORE_THRESHOLD: i64 = 150;

/// The thresholds of version 1 documents: only their relation is still read (see `weak_detections_off`).
const LEGACY_BLOCK_THRESHOLD: i64 = 150;
const LEGACY_LOG_THRESHOLD: i64 = 80;

const BUILTIN_RULES_JSON: &str = r#"{"geo":{"allow_ips":[],"block_ips":[],"allow_countries":[],"block_countries":[]},"siem":{"enabled":false,"webhook_url":""},"ssrf":{},"bot_protection":{"enabled":false,"mode":"off","base_score":100},"l7_flood":{"enabled":true,"key_fields":["remote_addr","user_agent"],"window_sec":60,"max_requests":500,"allow_ips":[]},"challenge":{"enabled":false,"type":"js_challenge","site_key":"","secret_key":"","cookie_ttl_sec":3600,"trigger":"always","simulation":false,"ip_rep_enabled":false,"ip_rep_block_level1":true,"ip_rep_block_level2":false,"good_bot_allowlist":["Googlebot","Googlebot-Image","Googlebot-Video","Google-InspectionTool","bingbot","BingPreview","DuckDuckBot","YandexBot","Baiduspider","Slurp","facebookexternalhit","Twitterbot","LinkedInBot","Applebot","AhrefsBot","SemrushBot","MJ12bot"],"template_version":3},"semantic_policies":{"sql":{"block_threshold":4.0,"soft_threshold":2.5},"xss":{"block_threshold":3.8,"soft_threshold":2.2},"cmd":{"block_threshold":3.2,"soft_threshold":1.6},"lfi":{"block_threshold":3.2,"soft_threshold":1.5},"ssrf":{"block_threshold":2.5,"soft_threshold":1.5},"php":{"block_threshold":3.2,"soft_threshold":1.6},"python":{"block_threshold":3.2,"soft_threshold":1.6},"java":{"block_threshold":3.2,"soft_threshold":1.6},"nosql":{"block_threshold":3.0,"soft_threshold":1.5},"ssti":{"block_threshold":3.0,"soft_threshold":1.8},"xxe":{"block_threshold":2.5,"soft_threshold":1.5},"deser":{"block_threshold":2.5,"soft_threshold":1.5}},"block_policy":{"enabled":true,"key_fields":["remote_addr","user_agent"],"block_duration_sec":3600,"block_after_n_blocks":100},"request_body_limit":"5M"}"#;

/// Returns the default rules JSON for new project configs.
pub fn builtin_rules_json() -> &'static [u8] {
    BUILTIN_RULES_JSON.as_bytes()
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SiemConfig {
    pub enabled: bool,
    pub webhook_url: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BlockPolicyConfig {
    pub enabled: bool,
    pub block_after_n_blocks: i64,
    pub block_duration_sec: i64,
    pub key_field: String,
    pub key_fields: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SsrfBlocklistConfig {
    pub ssrf_blocklist_path: String,
    pub ssrf_blocklist: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SemanticPoliciesConfig {
    pub sql: Option<SemanticPolicyJson>,
    pub xss: Option<SemanticPolicyJson>,
    pub cmd: Option<SemanticPolicyJson>,
    pub php: Option<SemanticPolicyJson>,
    pub python: Option<SemanticPolicyJson>,
    pub lfi: Option<SemanticPolicyJson>,
    pub ssrf: Option<SemanticPolicyJson>,
    pub java: Option<SemanticPolicyJson>,
    pub nosql: Option<SemanticPolicyJson>,
    pub ssti: Option<SemanticPolicyJson>,
    pub xxe: Option<SemanticPolicyJson>,
    pub deser: Option<SemanticPolicyJson>,
    pub ldap: Option<SemanticPolicyJson>,
    pub proto_pollution: Option<SemanticPolicyJson>,
    pub jwt: Option<SemanticPolicyJson>,
    pub graphql: Option<SemanticPolicyJson>,
    /// The detectors below take only `disabled` and `action`: they have no thresholds.
    pub header_injection: Option<SemanticPolicyJson>,
    pub open_redirect: Option<SemanticPolicyJson>,
    pub prompt_injection: Option<SemanticPolicyJson>,
    pub anomaly: Option<SemanticPolicyJson>,
    /// Inspection is off for the whole project.
    pub inspection_off: bool,
    /// The key `inspection_off` replaced: still read as the same switch.
    pub disable_semantic: bool,
    pub scan_all_headers: Option<bool>,
    pub on_uninspected: String,
    /// Whether a weak detection becomes a LOG decision. Absent means true; false lets it through unrecorded.
    pub record_weak_detections: Option<bool>,
}

pub const UNINSPECTED_POLICY_LOG: &str = "log";
pub const UNINSPECTED_POLICY_BLOCK: &str = "block";

/// One engine's semantic policy.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SemanticPolicyJson {
    /// How much evidence makes a strong detection, for the detectors that read one (0 = the engine's own).
    pub block_threshold: f64,
    /// How much evidence makes a weak one (0 = the engine's own).
    pub soft_threshold: f64,
    pub disabled: bool,
    /// "log" holds the engine's strong detections back as LOG; "" (absent) inherits, "block" blocks.
    pub action: String,
    /// The `base_score` a document of version 1 named. It means nothing but one thing: 0 reads as `disabled` on
    /// an engine that has a base score (not on `header_injection`, `open_redirect`, `prompt_injection` and
    /// `anomaly`, which only switch), and a category of score 0 switches off only the engines that named none.
    pub base_score: Option<i64>,
}

/// `action` value: the engine's strong detections become LOG.
pub const ENGINE_ACTION_LOG: &str = "log";
/// `action` value: the engine blocks (the default).
pub const ENGINE_ACTION_BLOCK: &str = "block";

impl SemanticPoliciesConfig {
    fn slots(&mut self) -> [&mut Option<SemanticPolicyJson>; 20] {
        [
            &mut self.sql,
            &mut self.xss,
            &mut self.cmd,
            &mut self.php,
            &mut self.python,
            &mut self.lfi,
            &mut self.ssrf,
            &mut self.java,
            &mut self.nosql,
            &mut self.ssti,
            &mut self.xxe,
            &mut self.deser,
            &mut self.ldap,
            &mut self.proto_pollution,
            &mut self.jwt,
            &mut self.graphql,
            &mut self.header_injection,
            &mut self.open_redirect,
            &mut self.prompt_injection,
            &mut self.anomaly,
        ]
    }

    /// Whether the project switches inspection off: `inspection_off`, or the older `disable_semantic`.
    pub fn is_inspection_off(&self) -> bool {
        self.inspection_off || self.disable_semantic
    }

    /// The policies of the detectors that read evidence thresholds, in a fixed order.
    pub fn threshold_policy_map(&self) -> [(&'static str, Option<&SemanticPolicyJson>); 12] {
        [
            ("sql", self.sql.as_ref()),
            ("xss", self.xss.as_ref()),
            ("cmd", self.cmd.as_ref()),
            ("php", self.php.as_ref()),
            ("python", self.python.as_ref()),
            ("lfi", self.lfi.as_ref()),
            ("ssrf", self.ssrf.as_ref()),
            ("java", self.java.as_ref()),
            ("nosql", self.nosql.as_ref()),
            ("ssti", self.ssti.as_ref()),
            ("xxe", self.xxe.as_ref()),
            ("deser", self.deser.as_ref()),
        ]
    }

    /// Every engine policy by engine key, in a fixed order (the engines with thresholds first, then the
    /// detectors that only take `disabled`).
    pub fn engine_policies(&self) -> [(&'static str, Option<&SemanticPolicyJson>); 20] {
        [
            ("sql", self.sql.as_ref()),
            ("xss", self.xss.as_ref()),
            ("cmd", self.cmd.as_ref()),
            ("php", self.php.as_ref()),
            ("python", self.python.as_ref()),
            ("lfi", self.lfi.as_ref()),
            ("ssrf", self.ssrf.as_ref()),
            ("java", self.java.as_ref()),
            ("nosql", self.nosql.as_ref()),
            ("ssti", self.ssti.as_ref()),
            ("xxe", self.xxe.as_ref()),
            ("deser", self.deser.as_ref()),
            ("ldap", self.ldap.as_ref()),
            ("proto_pollution", self.proto_pollution.as_ref()),
            ("jwt", self.jwt.as_ref()),
            ("graphql", self.graphql.as_ref()),
            ("header_injection", self.header_injection.as_ref()),
            ("open_redirect", self.open_redirect.as_ref()),
            ("prompt_injection", self.prompt_injection.as_ref()),
            ("anomaly", self.anomaly.as_ref()),
        ]
    }
}

/// L7 flood protection block.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct L7FloodConfig {
    pub enabled: bool,
    pub max_requests: i64,
    pub window_sec: i64,
    pub key_field: String,
    pub key_fields: Vec<String>,
    pub allow_ips: Vec<String>,
    /// Set by the parser; None for a config built in code.
    pub compiled_allow_nets: Option<Vec<IpNetwork>>,
}

impl L7FloodConfig {
    /// The client in remote_addr ("ip" or "ip:port") is in allow_ips.
    pub fn exempts_ip(&self, remote_addr: &str) -> bool {
        if self.allow_ips.is_empty() {
            return false;
        }
        let client_ip = ip_network::parse_client_ip(remote_addr);
        let Some(nets) = &self.compiled_allow_nets else {
            return ip_network::ip_in_list(&client_ip, &self.allow_ips);
        };
        let Some(ip) = ip_network::parse_ip(&client_ip) else {
            return false;
        };
        nets.iter().any(|n| n.contains(&ip))
    }
}

/// Geoblocking block.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GeoConfig {
    pub block_countries: Vec<String>,
    pub allow_countries: Vec<String>,
    pub block_ips: Vec<String>,
    pub allow_ips: Vec<String>,
    compiled: Option<GeoCompiled>,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct GeoCompiled {
    allow_nets: Vec<IpNetwork>,
    block_nets: Vec<IpNetwork>,
    allow_countries: BTreeSet<String>,
    block_countries: BTreeSet<String>,
}

pub fn compile_geo_config(g: &mut GeoConfig) {
    g.compiled = Some(GeoCompiled {
        allow_nets: parse_ip_networks(&g.allow_ips),
        block_nets: parse_ip_networks(&g.block_ips),
        allow_countries: normalize_country_codes(&g.allow_countries),
        block_countries: normalize_country_codes(&g.block_countries),
    });
}

fn parse_ip_networks(list: &[String]) -> Vec<IpNetwork> {
    let mut out = Vec::with_capacity(list.len());
    for s in list {
        let s = trim_whitespace_str(s);
        if s.is_empty() {
            continue;
        }
        if s.contains('/') {
            if let Some((_, n)) = ip_network::parse_network_prefix(s) {
                out.push(n);
            }
        } else if let Some(ip) = ip_network::parse_ip(s) {
            out.push(match ip_network::to_ipv4_octets(&ip) {
                Some(v4) => IpNetwork {
                    ip: v4,
                    mask: vec![0xff; 4],
                },
                None => IpNetwork {
                    ip,
                    mask: vec![0xff; 16],
                },
            });
        }
    }
    out
}

fn normalize_country_codes(list: &[String]) -> BTreeSet<String> {
    list.iter()
        .map(|c| {
            String::from_utf8_lossy(&wafio_bytetext::strings::to_uppercase(
                trim_whitespace_str(c).as_bytes(),
            ))
            .into_owned()
        })
        .filter(|c| !c.is_empty())
        .collect()
}

impl GeoConfig {
    /// `ip` (as bytes) is in allow_ips.
    pub fn allows_ip(&self, ip: &[u8]) -> bool {
        match &self.compiled {
            Some(c) => c.allow_nets.iter().any(|n| n.contains(ip)),
            None => ip_network::ip_in_list(&ip_string(ip), &self.allow_ips),
        }
    }
    pub fn blocks_ip(&self, ip: &[u8]) -> bool {
        match &self.compiled {
            Some(c) => c.block_nets.iter().any(|n| n.contains(ip)),
            None => ip_network::ip_in_list(&ip_string(ip), &self.block_ips),
        }
    }
    pub fn allows_country(&self, country: &str) -> bool {
        if self.allow_countries.is_empty() {
            return false;
        }
        match &self.compiled {
            Some(c) => c.allow_countries.contains(country),
            None => self
                .allow_countries
                .iter()
                .any(|c| upper_trim(c) == country),
        }
    }
    pub fn blocks_country(&self, country: &str) -> bool {
        match &self.compiled {
            Some(c) => c.block_countries.contains(country),
            None => self
                .block_countries
                .iter()
                .any(|c| upper_trim(c) == country),
        }
    }
}

fn upper_trim(s: &str) -> String {
    String::from_utf8_lossy(&wafio_bytetext::strings::to_uppercase(
        trim_whitespace_str(s).as_bytes(),
    ))
    .into_owned()
}

/// The printed form of a parsed address (4 or 16 bytes).
fn ip_string(ip: &[u8]) -> String {
    if let Some(v4) = ip_network::to_ipv4_octets(ip) {
        return format!("{}.{}.{}.{}", v4[0], v4[1], v4[2], v4[3]);
    }
    if ip.len() == 16 {
        let mut b = [0u8; 16];
        b.copy_from_slice(ip);
        return std::net::Ipv6Addr::from(b).to_string();
    }
    String::new()
}

/// Per-path semantic engine overrides.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PathSemanticOverride {
    pub sql: Option<SemanticPolicyJson>,
    pub xss: Option<SemanticPolicyJson>,
    pub cmd: Option<SemanticPolicyJson>,
    pub php: Option<SemanticPolicyJson>,
    pub python: Option<SemanticPolicyJson>,
    pub lfi: Option<SemanticPolicyJson>,
    pub ssrf: Option<SemanticPolicyJson>,
    pub java: Option<SemanticPolicyJson>,
    pub nosql: Option<SemanticPolicyJson>,
    pub ssti: Option<SemanticPolicyJson>,
    pub xxe: Option<SemanticPolicyJson>,
    pub deser: Option<SemanticPolicyJson>,
    pub ldap: Option<SemanticPolicyJson>,
    pub proto_pollution: Option<SemanticPolicyJson>,
    pub jwt: Option<SemanticPolicyJson>,
    pub graphql: Option<SemanticPolicyJson>,
    pub header_injection: Option<SemanticPolicyJson>,
    pub open_redirect: Option<SemanticPolicyJson>,
    pub prompt_injection: Option<SemanticPolicyJson>,
    pub anomaly: Option<SemanticPolicyJson>,
    /// Keys no detector has (a control plane newer than this agent): ignored, and logged at load.
    pub unknown_keys: Vec<String>,
}

/// The engine keys PathSemanticOverride accepts (exact spelling).
pub const PATH_SEMANTIC_OVERRIDE_KEYS: [&str; 20] = [
    "sql",
    "xss",
    "cmd",
    "php",
    "python",
    "lfi",
    "ssrf",
    "java",
    "nosql",
    "ssti",
    "xxe",
    "deser",
    "ldap",
    "proto_pollution",
    "jwt",
    "graphql",
    "header_injection",
    "open_redirect",
    "prompt_injection",
    "anomaly",
];

impl PathSemanticOverride {
    fn slots(&mut self) -> [&mut Option<SemanticPolicyJson>; 20] {
        [
            &mut self.sql,
            &mut self.xss,
            &mut self.cmd,
            &mut self.php,
            &mut self.python,
            &mut self.lfi,
            &mut self.ssrf,
            &mut self.java,
            &mut self.nosql,
            &mut self.ssti,
            &mut self.xxe,
            &mut self.deser,
            &mut self.ldap,
            &mut self.proto_pollution,
            &mut self.jwt,
            &mut self.graphql,
            &mut self.header_injection,
            &mut self.open_redirect,
            &mut self.prompt_injection,
            &mut self.anomaly,
        ]
    }

    /// Every override by engine key, in field order.
    pub fn policies(&self) -> [(&'static str, Option<&SemanticPolicyJson>); 20] {
        [
            ("sql", self.sql.as_ref()),
            ("xss", self.xss.as_ref()),
            ("cmd", self.cmd.as_ref()),
            ("php", self.php.as_ref()),
            ("python", self.python.as_ref()),
            ("lfi", self.lfi.as_ref()),
            ("ssrf", self.ssrf.as_ref()),
            ("java", self.java.as_ref()),
            ("nosql", self.nosql.as_ref()),
            ("ssti", self.ssti.as_ref()),
            ("xxe", self.xxe.as_ref()),
            ("deser", self.deser.as_ref()),
            ("ldap", self.ldap.as_ref()),
            ("proto_pollution", self.proto_pollution.as_ref()),
            ("jwt", self.jwt.as_ref()),
            ("graphql", self.graphql.as_ref()),
            ("header_injection", self.header_injection.as_ref()),
            ("open_redirect", self.open_redirect.as_ref()),
            ("prompt_injection", self.prompt_injection.as_ref()),
            ("anomaly", self.anomaly.as_ref()),
        ]
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PathIpRules {
    pub mode: String,
    pub ips: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PathFieldRule {
    pub field: String,
    pub source: String,
    pub action: String,
    pub aes_key: String,
    pub methods: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PathLoginProtection {
    pub enabled: bool,
    pub max_attempts: i64,
    pub window_sec: i64,
    pub lockout_sec: i64,
    pub by_ip: bool,
    pub by_user_agent: bool,
    pub identifier_field: String,
    pub methods: Vec<String>,
}

/// An empty list matches every method.
pub fn allows_method(methods: &[String], method: &[u8]) -> bool {
    if methods.is_empty() {
        return true;
    }
    let method =
        wafio_bytetext::strings::to_uppercase(wafio_bytetext::strings::trim_whitespace(method));
    methods
        .iter()
        .any(|m| wafio_bytetext::strings::to_uppercase(trim_whitespace_str(m).as_bytes()) == method)
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResponseFieldRule {
    pub field: String,
    pub action: String,
    pub aes_key: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PathBlockConfig {
    pub status: i64,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PathRateLimitConfig {
    pub max_requests: i64,
    pub window_sec: i64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PathTuningConfig {
    pub target: TuningTarget,
    pub effect: TuningEffect,
}

/// One per-path WAF exception rule.
#[derive(Clone, Debug, Default)]
pub struct PathExceptionConfig {
    pub disabled: bool,
    pub path: String,
    /// JSON `match`.
    pub match_: String,
    pub case_insensitive: Option<bool>,
    /// Inspection is off on this path.
    pub inspection_off: bool,
    /// The key `inspection_off` replaced: still read as the same switch.
    pub disable_semantic: bool,
    pub comment: String,
    pub semantic_override: Option<PathSemanticOverride>,
    pub tuning: Option<PathTuningConfig>,
    pub ip_rules: Option<PathIpRules>,
    pub body_size_limit: i64,
    pub login_protection: Option<PathLoginProtection>,
    pub block: Option<PathBlockConfig>,
    pub rate_limit: Option<PathRateLimitConfig>,
    pub field_rules: Vec<PathFieldRule>,
    pub response_decrypt_aes: String,
    pub response_field_rules: Vec<ResponseFieldRule>,
    compiled_regex: Option<CompiledRegex>,
    compiled_regex_fold: bool,
    compiled_fold_regex: Option<CompiledRegex>,
}

impl PartialEq for PathExceptionConfig {
    fn eq(&self, o: &Self) -> bool {
        self.disabled == o.disabled
            && self.path == o.path
            && self.match_ == o.match_
            && self.case_insensitive == o.case_insensitive
            && self.inspection_off == o.inspection_off
            && self.disable_semantic == o.disable_semantic
            && self.comment == o.comment
            && self.semantic_override == o.semantic_override
            && self.tuning == o.tuning
            && self.ip_rules == o.ip_rules
            && self.body_size_limit == o.body_size_limit
            && self.login_protection == o.login_protection
            && self.block == o.block
            && self.rate_limit == o.rate_limit
            && self.field_rules == o.field_rules
            && self.response_decrypt_aes == o.response_decrypt_aes
            && self.response_field_rules == o.response_field_rules
    }
}

impl PathExceptionConfig {
    pub fn matches_case_insensitively(&self) -> bool {
        self.case_insensitive
            .unwrap_or_else(|| self.limits_access())
    }

    pub fn limits_access(&self) -> bool {
        if self.block.is_some() || self.ip_rules.is_some() {
            return true;
        }
        self.has_any_limit() && !self.exempts()
    }

    pub fn has_any_limit(&self) -> bool {
        self.rate_limit.is_some() || self.login_protection.is_some() || self.body_size_limit > 0
    }

    /// Whether inspection is off on this path: `inspection_off`, or the older `disable_semantic`.
    pub fn is_inspection_off(&self) -> bool {
        self.inspection_off || self.disable_semantic
    }

    pub fn exempts(&self) -> bool {
        self.is_inspection_off()
            || self.semantic_override.is_some()
            || self.tuning.is_some()
            || !self.field_rules.is_empty()
    }

    /// The parser compiled the regex this exception matches with.
    pub fn regex_compiled(&self) -> bool {
        self.compiled_regex.is_some()
    }

    /// The parser compiled the case-folding regex for the limit reading.
    pub fn fold_regex_compiled(&self) -> bool {
        self.compiled_fold_regex.is_some()
    }

    pub fn limit_matches_case_insensitively(&self) -> bool {
        self.case_insensitive.is_none_or(|v| v)
    }
}

fn exception_regex_source(pattern: &str, fold: bool) -> String {
    if fold {
        format!("(?i){pattern}")
    } else {
        pattern.to_string()
    }
}

// ---- challenge / bot protection / content scan data --------------------------------------

/// The `challenge` block's JSON fields. The template defaults and the challenge preparation
/// belong to agent-pages: an empty template field here means "the built-in default".
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ChallengeConfig {
    pub enabled: bool,
    pub type_: String,
    pub site_key: String,
    pub secret_key: String,
    pub cookie_ttl_sec: i64,
    pub trigger: String,
    pub simulation: bool,
    pub pow_difficulty: i64,
    pub template_version: i64,
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
}

pub const CHALLENGE_TYPE_JS: &str = "js_challenge";

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

const CHALLENGE_FIELDS: [&str; 32] = [
    "enabled",
    "type",
    "site_key",
    "secret_key",
    "cookie_ttl_sec",
    "trigger",
    "simulation",
    "pow_difficulty",
    "template_version",
    "allow_local_ips",
    "ip_rep_enabled",
    "ip_rep_block_level1",
    "ip_rep_block_level2",
    "good_bot_allowlist",
    "custom_js_challenge_html",
    "custom_click_puzzle_html",
    "custom_ip_rep_block_html",
    "custom_block_html",
    "custom_policy_block_html",
    "custom_geo_block_html",
    "waf_block_format",
    "policy_block_format",
    "geo_block_format",
    "ip_rep_block_format",
    "custom_waf_block_json",
    "custom_policy_block_json",
    "custom_geo_block_json",
    "custom_ip_rep_block_json",
    "custom_waf_block_xml",
    "custom_policy_block_xml",
    "custom_geo_block_xml",
    "custom_ip_rep_block_xml",
];

fn challenge_str_field(c: &mut ChallengeConfig, i: usize) -> &mut String {
    match i {
        1 => &mut c.type_,
        2 => &mut c.site_key,
        3 => &mut c.secret_key,
        5 => &mut c.trigger,
        14 => &mut c.custom_js_challenge_html,
        15 => &mut c.custom_click_puzzle_html,
        16 => &mut c.custom_ip_rep_block_html,
        17 => &mut c.custom_block_html,
        18 => &mut c.custom_policy_block_html,
        19 => &mut c.custom_geo_block_html,
        20 => &mut c.waf_block_format,
        21 => &mut c.policy_block_format,
        22 => &mut c.geo_block_format,
        23 => &mut c.ip_rep_block_format,
        24 => &mut c.custom_waf_block_json,
        25 => &mut c.custom_policy_block_json,
        26 => &mut c.custom_geo_block_json,
        27 => &mut c.custom_ip_rep_block_json,
        28 => &mut c.custom_waf_block_xml,
        29 => &mut c.custom_policy_block_xml,
        30 => &mut c.custom_geo_block_xml,
        _ => &mut c.custom_ip_rep_block_xml,
    }
}

fn decode_challenge(
    d: &mut DecodeTrace,
    v: &Value,
    c: &mut ChallengeConfig,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "engine.ChallengeConfig",
        "ChallengeConfig",
        &CHALLENGE_FIELDS,
        |d, i, v| {
            match i {
                0 => json_decode::boolean(d, v, &mut c.enabled),
                4 => json_decode::int(d, v, &mut c.cookie_ttl_sec),
                6 => json_decode::boolean(d, v, &mut c.simulation),
                7 => json_decode::int(d, v, &mut c.pow_difficulty),
                8 => json_decode::int(d, v, &mut c.template_version),
                9 => {
                    json_decode::optional(d, v, &mut c.allow_local_ips, |d, v, b| {
                        json_decode::boolean(d, v, b);
                        Ok(())
                    })?;
                }
                10 => json_decode::boolean(d, v, &mut c.ip_rep_enabled),
                11 => json_decode::boolean(d, v, &mut c.ip_rep_block_level1),
                12 => json_decode::boolean(d, v, &mut c.ip_rep_block_level2),
                13 => json_decode::strings(d, v, &mut c.good_bot_allowlist)?,
                _ => json_decode::string(d, v, challenge_str_field(c, i)),
            }
            Ok(())
        },
    )
}

/// The `bot_protection` block's JSON fields.
/// The parser merges the user lists after the default lists it is given (engine-misc
/// owns the default bad-bot, JA4 and JA3 lists and `compile_bot_protection`): see
/// [`BotProtectionConfig::merge_default_lists`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BotProtectionConfig {
    pub enabled: bool,
    pub mode: String,
    /// The score a detected bot gets.
    pub base_score: i64,
    /// In Score mode the bot score blocks from this value on; 0 in a document reads as the default.
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
}

impl BotProtectionConfig {
    /// The default-list merge the rules loader does: each list becomes the defaults
    /// followed by the user entries not already present (UA entries kept as written and
    /// "" dropped; JA4/JA3 entries trimmed and lower-cased).
    pub fn merge_default_lists(
        &mut self,
        default_ua: &[String],
        default_ja4: &[String],
        default_ja3: &[String],
    ) {
        fn merge(
            defaults: &[String],
            user: &[String],
            norm: impl Fn(&str) -> String,
        ) -> Vec<String> {
            let mut seen: BTreeSet<String> = defaults.iter().cloned().collect();
            let mut out = defaults.to_vec();
            for p in user {
                let p = norm(p);
                if p.is_empty() {
                    continue;
                }
                if seen.insert(p.clone()) {
                    out.push(p);
                }
            }
            out
        }
        let fp = |h: &str| {
            String::from_utf8_lossy(wafio_bytetext::strings::trim_whitespace(
                &wafio_bytetext::strings::to_lowercase(h.as_bytes()),
            ))
            .into_owned()
        };
        self.ua_blocklist = merge(default_ua, &self.ua_blocklist, |p| p.to_string());
        self.ja4_blocklist = merge(default_ja4, &self.ja4_blocklist, fp);
        self.ja3_blocklist = merge(default_ja3, &self.ja3_blocklist, fp);
    }
}

fn decode_bot(
    d: &mut DecodeTrace,
    v: &Value,
    b: &mut BotProtectionConfig,
) -> Result<(), JsonDecodeError> {
    const F: [&str; 15] = [
        "enabled",
        "mode",
        "base_score",
        "score_threshold",
        "empty_ua_block",
        "ua_blocklist",
        "ua_allowlist",
        "ja4_blocklist",
        "ja4_allowlist",
        "ja3_blocklist",
        "ja3_allowlist",
        "header_checks",
        "client_hints_check",
        "browser_impersonation_check",
        "block_ai_crawlers",
    ];
    json_decode::object(
        d,
        v,
        "engine.BotProtectionConfig",
        "BotProtectionConfig",
        &F,
        |d, i, v| {
            match i {
                0 => json_decode::boolean(d, v, &mut b.enabled),
                1 => json_decode::string(d, v, &mut b.mode),
                2 => json_decode::int(d, v, &mut b.base_score),
                3 => json_decode::int(d, v, &mut b.score_threshold),
                4 => json_decode::boolean(d, v, &mut b.empty_ua_block),
                5 => json_decode::strings(d, v, &mut b.ua_blocklist)?,
                6 => json_decode::strings(d, v, &mut b.ua_allowlist)?,
                7 => json_decode::strings(d, v, &mut b.ja4_blocklist)?,
                8 => json_decode::strings(d, v, &mut b.ja4_allowlist)?,
                9 => json_decode::strings(d, v, &mut b.ja3_blocklist)?,
                10 => json_decode::strings(d, v, &mut b.ja3_allowlist)?,
                11 => json_decode::boolean(d, v, &mut b.header_checks),
                12 => json_decode::boolean(d, v, &mut b.client_hints_check),
                13 => json_decode::boolean(d, v, &mut b.browser_impersonation_check),
                _ => json_decode::boolean(d, v, &mut b.block_ai_crawlers),
            }
            Ok(())
        },
    )
}

pub use crate::content_scan::{ContentScanConfig, standard_content_scan_config};

// ---- LoadResult -----------------------------------------------------------------------

/// A stored value the parser dropped instead of failing the whole config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IgnoredValue {
    pub key: String,
    pub value: String,
    pub want: String,
    pub fallback: String,
}

/// LoadResult holds the WAF options of a rules JSON.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LoadResult {
    pub request_body_limit: i64,
    pub siem: Option<SiemConfig>,
    pub block_policy: Option<BlockPolicyConfig>,
    /// The `ssrf` and `fast_scan` blocks fill the same field.
    pub ssrf_blocklist: Option<SsrfBlocklistConfig>,
    pub geo: Option<GeoConfig>,
    pub l7_flood: Option<L7FloodConfig>,
    pub bot_protection: Option<BotProtectionConfig>,
    pub semantic_policies: Option<SemanticPoliciesConfig>,
    pub path_exceptions: Vec<PathExceptionConfig>,
    pub challenge: Option<ChallengeConfig>,
    pub content_scan: Option<ContentScanConfig>,
    pub ignored: Vec<IgnoredValue>,
}

// ---- decoders ---------------------------------------------------------------------------

/// A category of a document of version 1: only its `base_score` is read, to find out that it is 0.
fn decode_category_base_score(
    d: &mut DecodeTrace,
    v: &Value,
    base_score: &mut Option<i64>,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "engine.CategoryMeta",
        "CategoryMeta",
        &["base_score"],
        |d, _, v| {
            json_decode::optional(d, v, base_score, |d, v, n| {
                json_decode::int(d, v, n);
                Ok(())
            })
        },
    )
}

/// Decodes one semantic policy (only reached for a non-null value).
fn decode_semantic_policy(
    d: &mut DecodeTrace,
    v: &Value,
    out: &mut SemanticPolicyJson,
) -> Result<(), JsonDecodeError> {
    let _ = d;
    // Decoded as a plain struct: error messages name the type "plain".
    let mut p = SemanticPolicyJson::default();
    json_decode::decode_value_into(v, &mut p, |d, v, p| {
        json_decode::object(
            d,
            v,
            "engine.plain",
            "plain",
            &[
                "block_threshold",
                "soft_threshold",
                "base_score",
                "disabled",
                "action",
            ],
            |d, i, v| {
                match i {
                    0 => json_decode::float(d, v, &mut p.block_threshold),
                    1 => json_decode::float(d, v, &mut p.soft_threshold),
                    2 => json_decode::optional(d, v, &mut p.base_score, |d, v, n| {
                        json_decode::int(d, v, n);
                        Ok(())
                    })?,
                    3 => json_decode::boolean(d, v, &mut p.disabled),
                    _ => json_decode::string(d, v, &mut p.action),
                }
                Ok(())
            },
        )
    })?;
    *out = p;
    Ok(())
}

fn decode_optional_policy(
    d: &mut DecodeTrace,
    v: &Value,
    out: &mut Option<SemanticPolicyJson>,
) -> Result<(), JsonDecodeError> {
    json_decode::optional(d, v, out, decode_semantic_policy)
}

fn decode_semantic_policies(
    d: &mut DecodeTrace,
    v: &Value,
    sp: &mut SemanticPoliciesConfig,
) -> Result<(), JsonDecodeError> {
    const F: [&str; 25] = [
        "sql",
        "xss",
        "cmd",
        "php",
        "python",
        "lfi",
        "ssrf",
        "java",
        "nosql",
        "ssti",
        "xxe",
        "deser",
        "ldap",
        "proto_pollution",
        "jwt",
        "graphql",
        "inspection_off",
        "disable_semantic",
        "scan_all_headers",
        "on_uninspected",
        "header_injection",
        "open_redirect",
        "prompt_injection",
        "anomaly",
        "record_weak_detections",
    ];
    json_decode::object(
        d,
        v,
        "engine.SemanticPoliciesConfig",
        "SemanticPoliciesConfig",
        &F,
        |d, i, v| {
            match i {
                0 => decode_optional_policy(d, v, &mut sp.sql)?,
                1 => decode_optional_policy(d, v, &mut sp.xss)?,
                2 => decode_optional_policy(d, v, &mut sp.cmd)?,
                3 => decode_optional_policy(d, v, &mut sp.php)?,
                4 => decode_optional_policy(d, v, &mut sp.python)?,
                5 => decode_optional_policy(d, v, &mut sp.lfi)?,
                6 => decode_optional_policy(d, v, &mut sp.ssrf)?,
                7 => decode_optional_policy(d, v, &mut sp.java)?,
                8 => decode_optional_policy(d, v, &mut sp.nosql)?,
                9 => decode_optional_policy(d, v, &mut sp.ssti)?,
                10 => decode_optional_policy(d, v, &mut sp.xxe)?,
                11 => decode_optional_policy(d, v, &mut sp.deser)?,
                12 => decode_optional_policy(d, v, &mut sp.ldap)?,
                13 => decode_optional_policy(d, v, &mut sp.proto_pollution)?,
                14 => decode_optional_policy(d, v, &mut sp.jwt)?,
                15 => decode_optional_policy(d, v, &mut sp.graphql)?,
                16 => json_decode::boolean(d, v, &mut sp.inspection_off),
                17 => json_decode::boolean(d, v, &mut sp.disable_semantic),
                18 => json_decode::optional(d, v, &mut sp.scan_all_headers, |d, v, b| {
                    json_decode::boolean(d, v, b);
                    Ok(())
                })?,
                19 => json_decode::string(d, v, &mut sp.on_uninspected),
                20 => decode_optional_policy(d, v, &mut sp.header_injection)?,
                21 => decode_optional_policy(d, v, &mut sp.open_redirect)?,
                22 => decode_optional_policy(d, v, &mut sp.prompt_injection)?,
                23 => decode_optional_policy(d, v, &mut sp.anomaly)?,
                _ => json_decode::optional(d, v, &mut sp.record_weak_detections, |d, v, b| {
                    json_decode::boolean(d, v, b);
                    Ok(())
                })?,
            }
            Ok(())
        },
    )
}

/// Decodes a path semantic override, except that a key no detector has is kept in `unknown_keys`
/// instead of failing the document: a control plane newer than this agent may name a detector this
/// build does not have. A key of a known name in the wrong case still fails.
fn decode_path_semantic_override(
    d: &mut DecodeTrace,
    v: &Value,
    out: &mut PathSemanticOverride,
) -> Result<(), JsonDecodeError> {
    let _ = d;
    let fields = json_decode::raw_map(v)?;
    let mut unknown_keys = Vec::new();
    if let Some(fields) = &fields {
        for key in fields.keys() {
            if PATH_SEMANTIC_OVERRIDE_KEYS.contains(&key.as_str()) {
                continue;
            }
            if PATH_SEMANTIC_OVERRIDE_KEYS
                .iter()
                .any(|k| eq_ignore_case(k.as_bytes(), key.as_bytes()))
            {
                return Err(JsonDecodeError::from_message(format!(
                    "semantic_override.{key} is unsupported"
                )));
            }
            unknown_keys.push(key.clone());
        }
    }
    let mut value = PathSemanticOverride::default();
    json_decode::decode_value_into(v, &mut value, |d, v, o| {
        json_decode::object(
            d,
            v,
            "engine.plain",
            "plain",
            &PATH_SEMANTIC_OVERRIDE_KEYS,
            |d, i, v| {
                let slot = o.slots().into_iter().nth(i).unwrap();
                decode_optional_policy(d, v, slot)
            },
        )
    })?;
    value.unknown_keys = unknown_keys;
    *out = value;
    Ok(())
}

fn decode_path_exception(
    d: &mut DecodeTrace,
    v: &Value,
    e: &mut PathExceptionConfig,
) -> Result<(), JsonDecodeError> {
    const F: [&str; 17] = [
        "disabled",
        "path",
        "match",
        "case_insensitive",
        "inspection_off",
        "disable_semantic",
        "comment",
        "semantic_override",
        "tuning",
        "ip_rules",
        "body_size_limit",
        "login_protection",
        "block",
        "rate_limit",
        "field_rules",
        "response_decrypt_aes",
        "response_field_rules",
    ];
    json_decode::object(
        d,
        v,
        "engine.PathExceptionConfig",
        "PathExceptionConfig",
        &F,
        |d, i, v| {
            match i {
                0 => json_decode::boolean(d, v, &mut e.disabled),
                1 => json_decode::string(d, v, &mut e.path),
                2 => json_decode::string(d, v, &mut e.match_),
                3 => json_decode::optional(d, v, &mut e.case_insensitive, |d, v, b| {
                    json_decode::boolean(d, v, b);
                    Ok(())
                })?,
                4 => json_decode::boolean(d, v, &mut e.inspection_off),
                5 => json_decode::boolean(d, v, &mut e.disable_semantic),
                6 => json_decode::string(d, v, &mut e.comment),
                7 => json_decode::optional(
                    d,
                    v,
                    &mut e.semantic_override,
                    decode_path_semantic_override,
                )?,
                8 => json_decode::optional(d, v, &mut e.tuning, |d, v, t| {
                    json_decode::object(
                        d,
                        v,
                        "engine.PathTuningConfig",
                        "PathTuningConfig",
                        &["target", "effect"],
                        |d, i, v| match i {
                            0 => decode_tuning_target(d, v, &mut t.target),
                            _ => decode_tuning_effect(d, v, &mut t.effect),
                        },
                    )
                })?,
                9 => json_decode::optional(d, v, &mut e.ip_rules, |d, v, r| {
                    json_decode::object(
                        d,
                        v,
                        "engine.PathIPRules",
                        "PathIPRules",
                        &["mode", "ips"],
                        |d, i, v| match i {
                            0 => {
                                json_decode::string(d, v, &mut r.mode);
                                Ok(())
                            }
                            _ => json_decode::strings(d, v, &mut r.ips),
                        },
                    )
                })?,
                10 => json_decode::int_as(d, v, &mut e.body_size_limit, "int64"),
                11 => json_decode::optional(d, v, &mut e.login_protection, |d, v, l| {
                    const LF: [&str; 8] = [
                        "enabled",
                        "max_attempts",
                        "window_sec",
                        "lockout_sec",
                        "by_ip",
                        "by_user_agent",
                        "identifier_field",
                        "methods",
                    ];
                    json_decode::object(
                        d,
                        v,
                        "engine.PathLoginProtection",
                        "PathLoginProtection",
                        &LF,
                        |d, i, v| {
                            match i {
                                0 => json_decode::boolean(d, v, &mut l.enabled),
                                1 => json_decode::int(d, v, &mut l.max_attempts),
                                2 => json_decode::int(d, v, &mut l.window_sec),
                                3 => json_decode::int(d, v, &mut l.lockout_sec),
                                4 => json_decode::boolean(d, v, &mut l.by_ip),
                                5 => json_decode::boolean(d, v, &mut l.by_user_agent),
                                6 => json_decode::string(d, v, &mut l.identifier_field),
                                _ => json_decode::strings(d, v, &mut l.methods)?,
                            }
                            Ok(())
                        },
                    )
                })?,
                12 => json_decode::optional(d, v, &mut e.block, |d, v, b| {
                    json_decode::object(
                        d,
                        v,
                        "engine.PathBlockConfig",
                        "PathBlockConfig",
                        &["status", "message"],
                        |d, i, v| {
                            match i {
                                0 => json_decode::int(d, v, &mut b.status),
                                _ => json_decode::string(d, v, &mut b.message),
                            }
                            Ok(())
                        },
                    )
                })?,
                13 => json_decode::optional(d, v, &mut e.rate_limit, |d, v, r| {
                    json_decode::object(
                        d,
                        v,
                        "engine.PathRateLimitConfig",
                        "PathRateLimitConfig",
                        &["max_requests", "window_sec"],
                        |d, i, v| {
                            match i {
                                0 => json_decode::int(d, v, &mut r.max_requests),
                                _ => json_decode::int(d, v, &mut r.window_sec),
                            }
                            Ok(())
                        },
                    )
                })?,
                14 => json_decode::slice(
                    d,
                    v,
                    &mut e.field_rules,
                    "[]engine.PathFieldRule",
                    |d, v, f| {
                        json_decode::object(
                            d,
                            v,
                            "engine.PathFieldRule",
                            "PathFieldRule",
                            &["field", "source", "action", "aes_key", "methods"],
                            |d, i, v| {
                                match i {
                                    0 => json_decode::string(d, v, &mut f.field),
                                    1 => json_decode::string(d, v, &mut f.source),
                                    2 => json_decode::string(d, v, &mut f.action),
                                    3 => json_decode::string(d, v, &mut f.aes_key),
                                    _ => json_decode::strings(d, v, &mut f.methods)?,
                                }
                                Ok(())
                            },
                        )
                    },
                )?,
                15 => json_decode::string(d, v, &mut e.response_decrypt_aes),
                _ => json_decode::slice(
                    d,
                    v,
                    &mut e.response_field_rules,
                    "[]engine.ResponseFieldRule",
                    |d, v, f| {
                        json_decode::object(
                            d,
                            v,
                            "engine.ResponseFieldRule",
                            "ResponseFieldRule",
                            &["field", "action", "aes_key"],
                            |d, i, v| {
                                match i {
                                    0 => json_decode::string(d, v, &mut f.field),
                                    1 => json_decode::string(d, v, &mut f.action),
                                    _ => json_decode::string(d, v, &mut f.aes_key),
                                }
                                Ok(())
                            },
                        )
                    },
                )?,
            }
            Ok(())
        },
    )
}

// ---- rules JSON loading -----------------------------------------------------------------

/// Parses rules from JSON bytes (same format as rules.json).
pub fn load_rules_json(data: &[u8]) -> Result<LoadResult, JsonDecodeError> {
    read_rule_map_json(data)
}

fn decode_struct<T: Default>(
    v: &Value,
    f: impl FnOnce(&mut DecodeTrace, &Value, &mut T) -> Result<(), JsonDecodeError>,
) -> Option<T> {
    let mut t = T::default();
    json_decode::decode_value_into(v, &mut t, f).ok().map(|_| t)
}

fn read_rule_map_json(data: &[u8]) -> Result<LoadResult, JsonDecodeError> {
    let doc = json_decode::parse(data)?;
    let mut raw = json_decode::raw_map(&doc)?.unwrap_or_default();

    let mut ignored: Vec<IgnoredValue> = Vec::new();
    let mut request_body_limit = 0;
    // A document of version 1 with a log threshold that is not below its block threshold never recorded a
    // weak detection.
    let weak_off = raw.remove("thresholds").is_some_and(weak_detections_off);
    if let Some(v) = raw.remove("request_body_limit") {
        request_body_limit = parse_size_text_from_json(v);
    }
    let siem = raw.remove("siem").and_then(|v| {
        decode_struct::<SiemConfig>(v, |d, v, s| {
            json_decode::object(
                d,
                v,
                "engine.SIEMConfig",
                "SIEMConfig",
                &["enabled", "webhook_url"],
                |d, i, v| {
                    match i {
                        0 => json_decode::boolean(d, v, &mut s.enabled),
                        _ => json_decode::string(d, v, &mut s.webhook_url),
                    }
                    Ok(())
                },
            )
        })
    });
    let block_policy = raw.remove("block_policy").and_then(|v| {
        let mut b = decode_struct::<BlockPolicyConfig>(v, |d, v, b| {
            json_decode::object(
                d,
                v,
                "engine.BlockPolicyConfig",
                "BlockPolicyConfig",
                &[
                    "enabled",
                    "block_after_n_blocks",
                    "block_duration_sec",
                    "key_field",
                    "key_fields",
                ],
                |d, i, v| {
                    match i {
                        0 => json_decode::boolean(d, v, &mut b.enabled),
                        1 => json_decode::int(d, v, &mut b.block_after_n_blocks),
                        2 => json_decode::int(d, v, &mut b.block_duration_sec),
                        3 => json_decode::string(d, v, &mut b.key_field),
                        _ => json_decode::strings(d, v, &mut b.key_fields)?,
                    }
                    Ok(())
                },
            )
        })?;
        if b.key_fields.is_empty() {
            b.key_fields = if !b.key_field.is_empty() {
                vec![trim_whitespace_str(&b.key_field).to_string()]
            } else {
                vec!["remote_addr".into()]
            };
        }
        if b.block_after_n_blocks <= 0 {
            b.block_after_n_blocks = 5;
        }
        if b.block_duration_sec <= 0 {
            b.block_duration_sec = 3600;
        }
        Some(b)
    });
    let mut ssrf_blocklist = None;
    for key in ["ssrf", "fast_scan"] {
        if let Some(v) = raw.remove(key) {
            ssrf_blocklist = decode_struct::<SsrfBlocklistConfig>(v, |d, v, f| {
                json_decode::object(
                    d,
                    v,
                    "engine.SSRFBlocklistConfig",
                    "SSRFBlocklistConfig",
                    &["ssrf_blocklist_path", "ssrf_blocklist"],
                    |d, i, v| match i {
                        0 => {
                            json_decode::string(d, v, &mut f.ssrf_blocklist_path);
                            Ok(())
                        }
                        _ => json_decode::strings(d, v, &mut f.ssrf_blocklist),
                    },
                )
            });
            break;
        }
    }
    let geo = raw.remove("geo").and_then(|v| {
        let mut g = decode_struct::<GeoConfig>(v, |d, v, g| {
            json_decode::object(
                d,
                v,
                "engine.GeoConfig",
                "GeoConfig",
                &[
                    "block_countries",
                    "allow_countries",
                    "block_ips",
                    "allow_ips",
                ],
                |d, i, v| match i {
                    0 => json_decode::strings(d, v, &mut g.block_countries),
                    1 => json_decode::strings(d, v, &mut g.allow_countries),
                    2 => json_decode::strings(d, v, &mut g.block_ips),
                    _ => json_decode::strings(d, v, &mut g.allow_ips),
                },
            )
        })?;
        compile_geo_config(&mut g);
        Some(g)
    });
    let l7_flood = match raw.remove("l7_flood") {
        None => None,
        Some(v) => decode_struct::<L7FloodConfig>(v, |d, v, f| {
            json_decode::object(
                d,
                v,
                "engine.L7FloodConfig",
                "L7FloodConfig",
                &[
                    "enabled",
                    "max_requests",
                    "window_sec",
                    "key_field",
                    "key_fields",
                    "allow_ips",
                ],
                |d, i, v| {
                    match i {
                        0 => json_decode::boolean(d, v, &mut f.enabled),
                        1 => json_decode::int(d, v, &mut f.max_requests),
                        2 => json_decode::int(d, v, &mut f.window_sec),
                        3 => json_decode::string(d, v, &mut f.key_field),
                        4 => json_decode::strings(d, v, &mut f.key_fields)?,
                        _ => json_decode::strings(d, v, &mut f.allow_ips)?,
                    }
                    Ok(())
                },
            )
        })
        .map(|mut f| {
            if f.key_fields.is_empty() && !f.key_field.is_empty() {
                f.key_fields = vec![trim_whitespace_str(&f.key_field).to_string()];
            }
            if f.key_fields.is_empty() {
                f.key_fields = vec!["remote_addr".into()];
            }
            let mut valid = Vec::new();
            for (i, entry) in f.allow_ips.iter().enumerate() {
                if is_valid_ip_or_cidr(entry) {
                    valid.push(entry.clone());
                    continue;
                }
                ignored.push(IgnoredValue {
                    key: format!("l7_flood.allow_ips[{i}]"),
                    value: wafio_domain::text_helpers::quote(entry.as_bytes()),
                    want: "an IP or CIDR (e.g. 1.2.3.4, 10.0.0.0/8)".into(),
                    fallback: "the entry exempts no client".into(),
                });
            }
            f.compiled_allow_nets = Some(parse_ip_networks(&valid));
            f.allow_ips = valid;
            f
        }),
    };
    let bot_protection = raw.remove("bot_protection").and_then(|v| {
        let mut b = decode_struct::<BotProtectionConfig>(v, decode_bot)?;
        if b.mode.is_empty() {
            b.mode = "log".into();
        }
        if b.base_score <= 0 {
            b.base_score = 100;
        }
        if b.score_threshold <= 0 {
            b.score_threshold = DEFAULT_BOT_SCORE_THRESHOLD;
        }
        // Default lists: merged by the owner of the default bot lists.
        b.merge_default_lists(&[], &[], &[]);
        Some(b)
    });

    let mut semantic_policies = None;
    if let Some(v) = raw.remove("semantic_policies") {
        json_decode::raw_map(v).map_err(|e| e.wrap("semantic_policies"))?;
        let mut sp = SemanticPoliciesConfig::default();
        json_decode::decode_value_into(v, &mut sp, decode_semantic_policies)
            .map_err(|e| e.wrap("semantic_policies"))?;
        read_base_scores_of_zero(sp.slots());
        ignored.extend(discard_unknown_actions("semantic_policies", sp.slots()));
        if !matches!(
            sp.on_uninspected.as_str(),
            "" | UNINSPECTED_POLICY_LOG | UNINSPECTED_POLICY_BLOCK
        ) {
            {
                ignored.push(IgnoredValue {
                    key: "semantic_policies.on_uninspected".into(),
                    value: wafio_domain::text_helpers::quote(sp.on_uninspected.as_bytes()),
                    want: r#""log" or "block""#.into(),
                    fallback: "log".into(),
                });
                sp.on_uninspected.clear();
            }
        }
        semantic_policies = Some(sp);
    }
    if weak_off {
        let sp = semantic_policies.get_or_insert_with(SemanticPoliciesConfig::default);
        sp.record_weak_detections.get_or_insert(false);
    }
    if let Some(v) = raw.remove("categories") {
        let zero = categories_scored_zero(v);
        if !zero.is_empty() {
            let sp = semantic_policies.get_or_insert_with(SemanticPoliciesConfig::default);
            switch_off_engines_of(sp, &zero);
        }
    }
    let challenge = raw.remove("challenge").and_then(|v| {
        let mut c = decode_struct::<ChallengeConfig>(v, decode_challenge)?;
        // Any other value (empty, "js", a typo) is served and verified as the JS challenge by the
        // agent's default branches: make that explicit so the stage-2 puzzle check agrees.
        if !matches!(
            c.type_.as_str(),
            "turnstile" | "hcaptcha" | "click_puzzle" | "adaptive"
        ) {
            c.type_ = CHALLENGE_TYPE_JS.into();
        }
        if c.cookie_ttl_sec <= 0 {
            c.cookie_ttl_sec = 3600;
        }
        if c.trigger.is_empty() {
            c.trigger = "always".into();
        }
        if c.good_bot_allowlist.is_empty() {
            c.good_bot_allowlist = DEFAULT_GOOD_BOT_AGENTS
                .iter()
                .map(|s| s.to_string())
                .collect();
        }
        Some(c)
    });

    let mut content_scan = None;
    if let Some(v) = raw.remove("content_scan") {
        let mut cs = standard_content_scan_config();
        cs.enabled = false;
        json_decode::decode_value_into(v, &mut cs, crate::content_scan::decode_content_scan_config)
            .map_err(|e| e.wrap("content_scan"))?;
        cs.prepare().map_err(JsonDecodeError::Message)?;
        content_scan = Some(cs);
    }

    let mut path_exceptions = Vec::new();
    if let Some(v) = raw.remove("path_exceptions") {
        let mut arr: Vec<PathExceptionConfig> = Vec::new();
        json_decode::decode_value_into(v, &mut arr, |d, v, arr| {
            json_decode::slice(
                d,
                v,
                arr,
                "[]engine.PathExceptionConfig",
                decode_path_exception,
            )
        })
        .map_err(|e| e.wrap("path_exceptions"))?;
        for e in arr.iter_mut() {
            if e.match_.is_empty() {
                e.match_ = "prefix".into();
            }
            if e.match_ == "regex" {
                let fold = e.matches_case_insensitively();
                if let Ok(re) =
                    crate::pattern_compile::compile(&exception_regex_source(&e.path, fold))
                {
                    e.compiled_regex = Some(re);
                    e.compiled_regex_fold = fold;
                }
                if !fold
                    && e.has_any_limit()
                    && e.limit_matches_case_insensitively()
                    && let Ok(re) =
                        crate::pattern_compile::compile(&exception_regex_source(&e.path, true))
                {
                    e.compiled_fold_regex = Some(re);
                }
            }
        }
        // exact > prefix (longer first) > regex; stable.
        arr.sort_by(|a, b| {
            use std::cmp::Ordering;
            let (ea, eb) = (a.match_ == "exact", b.match_ == "exact");
            if ea && !eb {
                return Ordering::Less;
            }
            if eb && !ea {
                return Ordering::Greater;
            }
            b.path.len().cmp(&a.path.len())
        });
        path_exceptions = arr;
    }

    for (i, exc) in path_exceptions.iter_mut().enumerate() {
        let at = format!("path_exceptions[{i}]");
        if let Some(ov) = exc.semantic_override.as_mut() {
            read_base_scores_of_zero(ov.slots());
            ignored.extend(discard_unknown_actions(
                &format!("{at}.semantic_override"),
                ov.slots(),
            ));
            ignored.extend(ov.unknown_keys.iter().map(|key| IgnoredValue {
                key: format!("{at}.semantic_override"),
                value: wafio_domain::text_helpers::quote(key.as_bytes()),
                want: "the key of a detector".into(),
                fallback: "the key switches nothing".into(),
            }));
        }
        if let Some(t) = &exc.tuning {
            ignored.extend(
                t.effect
                    .skip_semantic
                    .iter()
                    .filter(|s| is_unknown_semantic_engine(s))
                    .map(|name| IgnoredValue {
                        key: format!("{at}.tuning.effect.skip_semantic"),
                        value: wafio_domain::text_helpers::quote(name.as_bytes()),
                        want: "the key of a detector or \"*\"".into(),
                        fallback: "the entry skips nothing".into(),
                    }),
            );
        }
    }
    Ok(LoadResult {
        request_body_limit,
        siem,
        block_policy,
        ssrf_blocklist,
        geo,
        l7_flood,
        bot_protection,
        semantic_policies,
        path_exceptions,
        challenge,
        content_scan,
        ignored,
    })
}

/// Whether the `thresholds` of a document of version 1 leave no room for a weak detection: the log threshold,
/// which a value of 0 or none sets to its default, is not below the block threshold.
fn weak_detections_off(v: &Value) -> bool {
    let mut th: (Option<i64>, Option<i64>) = (None, None);
    let r = json_decode::decode_value_into(v, &mut th, |d, v, th| {
        json_decode::object(
            d,
            v,
            "struct { Block *int \"json:\\\"block\\\"\"; Log *int \"json:\\\"log\\\"\" }",
            "",
            &["block", "log"],
            |d, i, v| {
                let slot = if i == 0 { &mut th.0 } else { &mut th.1 };
                json_decode::optional(d, v, slot, |d, v, n| {
                    json_decode::int(d, v, n);
                    Ok(())
                })
            },
        )
    });
    if r.is_err() {
        return false;
    }
    let mut block = th.0.unwrap_or(LEGACY_BLOCK_THRESHOLD);
    let mut log = th.1.unwrap_or(LEGACY_LOG_THRESHOLD.min(block));
    if block <= 0 {
        block = LEGACY_BLOCK_THRESHOLD;
    }
    if log <= 0 {
        log = LEGACY_LOG_THRESHOLD;
    }
    log >= block
}

/// The engines that a category of version 1 stood for when they named no base score of their own.
const CATEGORY_ENGINES: [(&str, &str); 8] = [
    ("SQLi", "sql"),
    ("XSS", "xss"),
    ("RCE", "cmd"),
    ("PHP", "php"),
    ("Python", "python"),
    ("LFI", "lfi"),
    ("SSRF", "ssrf"),
    ("Java", "java"),
];

/// The engines of the categories whose `base_score` is 0. Anything else in `categories` means nothing now,
/// and a block that does not parse is left out.
fn categories_scored_zero(v: &Value) -> Vec<&'static str> {
    let Ok(Some(map)) = json_decode::raw_map(v) else {
        return Vec::new();
    };
    CATEGORY_ENGINES
        .iter()
        .filter(|(name, _)| {
            let Some(meta) = map.get(*name) else {
                return false;
            };
            let mut base: Option<i64> = None;
            json_decode::decode_value_into(meta, &mut base, decode_category_base_score).is_ok()
                && base == Some(0)
        })
        .map(|(_, key)| *key)
        .collect()
}

/// A `base_score` of 0 switched an engine off in documents of version 1; it reads as `disabled` now. The four
/// detectors that only switch (the last of the twenty keys) had no base score, so theirs means nothing.
fn read_base_scores_of_zero(slots: [&mut Option<SemanticPolicyJson>; 20]) {
    for p in slots.into_iter().take(16).flatten() {
        if p.base_score == Some(0) {
            p.disabled = true;
        }
    }
}

/// Switches the engines off that did not name a base score of their own.
fn switch_off_engines_of(sp: &mut SemanticPoliciesConfig, keys: &[&str]) {
    for (slot, key) in sp.slots().into_iter().zip(PATH_SEMANTIC_OVERRIDE_KEYS) {
        if !keys.contains(&key) || slot.as_ref().is_some_and(|p| p.base_score.is_some()) {
            continue;
        }
        slot.get_or_insert_with(SemanticPolicyJson::default)
            .disabled = true;
    }
}

fn discard_unknown_actions(
    at: &str,
    policies: [&mut Option<SemanticPolicyJson>; 20],
) -> Vec<IgnoredValue> {
    let mut dropped = Vec::new();
    for (p, key) in policies.into_iter().zip(PATH_SEMANTIC_OVERRIDE_KEYS) {
        let Some(p) = p.as_mut() else { continue };
        if matches!(
            p.action.as_str(),
            "" | ENGINE_ACTION_BLOCK | ENGINE_ACTION_LOG
        ) {
            continue;
        }
        dropped.push(IgnoredValue {
            key: format!("{at}.{key}.action"),
            value: wafio_domain::text_helpers::quote(p.action.as_bytes()),
            want: r#""block" or "log""#.into(),
            fallback: "the engine keeps the action it inherits, block when none is set".into(),
        });
        p.action.clear();
    }
    dropped
}

// ---- folded duplicate keys --------------------------------------------------------------

/// The field-name folding of the control plane's JSON decoder.
pub fn fold_key_case(s: &[u8]) -> Vec<u8> {
    use wafio_bytetext::{unicode::next_case_fold_equivalent, utf8};
    let mut b = Vec::with_capacity(s.len());
    for mut r in utf8::to_code_points(s) {
        if r < 0x80 {
            let mut c = r as u8;
            c.make_ascii_uppercase();
            b.push(c);
            continue;
        }
        loop {
            let f = next_case_fold_equivalent(r);
            if f <= r {
                r = f;
                break;
            }
            r = f;
        }
        utf8::push_code_point(&mut b, r);
    }
    b
}

fn short_key(key: &[u8]) -> String {
    let mut k = key.to_vec();
    if k.len() > 48 {
        k.truncate(48);
        k.extend_from_slice("…".as_bytes());
    }
    use wafio_bytetext::{unicode, utf8};
    for r in utf8::to_code_points(&k) {
        if !(r == '_' as i32 || r == '-' as i32 || unicode::is_letter(r) || unicode::is_digit(r)) {
            return String::from_utf8_lossy(&wafio_bytetext::literal::quote(&k)).into_owned();
        }
    }
    String::from_utf8_lossy(&k).into_owned()
}

fn join_key_segments(path: &str, key: &[u8]) -> String {
    if path.is_empty() {
        short_key(key)
    } else {
        format!("{path}.{}", short_key(key))
    }
}

/// Rejects an object holding two keys the control plane's JSON decoder reads as
/// the same field. data must be valid JSON.
pub fn reject_folded_duplicate_keys(data: &[u8]) -> Result<(), JsonDecodeError> {
    let doc = json_decode::parse(data).map_err(|e| e.wrap("rules_json invalid"))?;
    fn walk(v: &Value, path: &str) -> Result<(), JsonDecodeError> {
        match v {
            Value::Object(members) => {
                // A duplicate is reported when its key is reached, after every earlier member's
                // value was walked.
                let mut keys: BTreeMap<Vec<u8>, &[u8]> = BTreeMap::new();
                for (k, child) in members {
                    let folded = fold_key_case(k);
                    if let Some(first) = keys.get(&folded) {
                        let shown = if path.is_empty() {
                            "the top level".to_string()
                        } else {
                            path.to_string()
                        };
                        return Err(JsonDecodeError::from_message(format!(
                            "duplicate key {} (also {}) in rules_json at {shown}; keys in one object may not differ only in case",
                            short_key(k),
                            short_key(first)
                        )));
                    }
                    keys.insert(folded, k);
                    walk(child, &join_key_segments(path, k))?;
                }
                Ok(())
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    walk(child, &format!("{path}[{i}]"))?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    walk(&doc, "")
}

// ---- byte sizes, validation -------------------------------------------------------------

/// A JSON number (bytes) or a string "1M", "512K", "1G".
fn parse_size_text_from_json(v: &Value) -> i64 {
    match v {
        Value::String(s) => parse_size_with_suffix(&String::from_utf8_lossy(s)),
        Value::Null => parse_size_with_suffix(""),
        Value::Number(lit) => match json_decode::parse_int(lit) {
            Some(n) if n > 0 => n,
            _ => 0,
        },
        _ => 0,
    }
}

pub fn parse_size_with_suffix(s: &str) -> i64 {
    let up =
        String::from_utf8_lossy(&wafio_bytetext::strings::to_uppercase(s.as_bytes())).into_owned();
    let mut s = trim_whitespace_str(&up);
    if s.is_empty() {
        return 0;
    }
    let mut mult: i64 = 1;
    if let Some(r) = s.strip_suffix('K') {
        mult = 1024;
        s = r;
    } else if let Some(r) = s.strip_suffix('M') {
        mult = 1024 * 1024;
        s = r;
    } else if let Some(r) = s.strip_suffix('G') {
        mult = 1024 * 1024 * 1024;
        s = r;
    }
    match wafio_bytetext::literal::parse_decimal(trim_whitespace_str(s).as_bytes()) {
        Ok(n) if n > 0 => n.wrapping_mul(mult),
        _ => 0,
    }
}

/// The agent's validation; dropped values are logged, not rejected.
/// Returns the log lines to print (`rules_json: … ignored …`) on success.
pub fn check_rules_json(data: &[u8]) -> Result<Vec<String>, JsonDecodeError> {
    let Some(res) = check_rules(data)? else {
        return Ok(Vec::new());
    };
    Ok(res
        .ignored
        .iter()
        .map(|iv| {
            format!(
                "rules_json: {} = {} ignored (must be {}); {}",
                iv.key, iv.value, iv.want, iv.fallback
            )
        })
        .collect())
}

/// Parse, reject keys that differ only in case, check ranges and formats.
pub fn check_rules(data: &[u8]) -> Result<Option<LoadResult>, JsonDecodeError> {
    if data.is_empty() {
        return Ok(None);
    }
    let res = load_rules_json(data).map_err(|e| e.wrap("rules_json invalid"))?;
    reject_folded_duplicate_keys(data)?;
    check_load_result(&res, data)?;
    Ok(Some(res))
}

fn validation_error(s: impl Into<String>) -> JsonDecodeError {
    JsonDecodeError::Message(s.into())
}

fn check_load_result(r: &LoadResult, raw: &[u8]) -> Result<(), JsonDecodeError> {
    const MAX_BODY_BYTES: i64 = 1024 * 1024 * 1024;
    if let Some(bp) = &r.block_policy {
        if !(1..=999).contains(&bp.block_after_n_blocks) {
            return Err(validation_error(
                "block_policy.block_after_n_blocks must be 1–999",
            ));
        }
        if !(1..=604800).contains(&bp.block_duration_sec) {
            return Err(validation_error(
                "block_policy.block_duration_sec must be 1–604800 (max 7 days)",
            ));
        }
        for k in &bp.key_fields {
            let k = trim_whitespace_str(k);
            if !k.is_empty() && !is_allowed_block_key_name(k) {
                return Err(validation_error(format!(
                    "block_policy.key_fields: field not supported: {} (allowed: remote_addr, user_agent, host, request_id, or header:Header-Name)",
                    wafio_domain::text_helpers::quote(k.as_bytes())
                )));
            }
        }
    }
    if r.request_body_limit > MAX_BODY_BYTES {
        return Err(validation_error("request_body_limit max 1G"));
    }
    if let Some(b) = &r.bot_protection {
        if !["off", "log", "block", "score"].contains(&b.mode.as_str()) {
            return Err(validation_error(
                "bot_protection.mode must be one of: off, log, block, score",
            ));
        }
        if !(0..=999).contains(&b.base_score) {
            return Err(validation_error("bot_protection.base_score must be 0–999"));
        }
        if !(1..=9999).contains(&b.score_threshold) {
            return Err(validation_error(
                "bot_protection.score_threshold must be 1–9999",
            ));
        }
    }
    if let Some(g) = &r.geo {
        for (name, list) in [
            ("block_countries", &g.block_countries),
            ("allow_countries", &g.allow_countries),
        ] {
            for c in list {
                let c = trim_whitespace_str(c);
                if !c.is_empty() && !ip_network::is_valid_country_code(c) {
                    return Err(validation_error(format!(
                        "geo.{name}: invalid country code (ISO 3166-1 alpha-2): {}",
                        wafio_domain::text_helpers::quote(c.as_bytes())
                    )));
                }
            }
        }
        for (name, list) in [("block_ips", &g.block_ips), ("allow_ips", &g.allow_ips)] {
            for entry in list {
                if !is_valid_ip_or_cidr(entry) {
                    return Err(validation_error(format!(
                        "geo.{name}: not a valid IP or CIDR: {} (e.g. 1.2.3.4, 10.0.0.0/8)",
                        wafio_domain::text_helpers::quote(entry.as_bytes())
                    )));
                }
            }
        }
    }
    if let Some(f) = r.l7_flood.as_ref().filter(|f| f.enabled) {
        if !(1..=100000).contains(&f.max_requests) {
            return Err(validation_error("l7_flood.max_requests must be 1–100000"));
        }
        if !(1..=86400).contains(&f.window_sec) {
            return Err(validation_error(
                "l7_flood.window_sec must be 1–86400 (max 24 hours)",
            ));
        }
        for k in &f.key_fields {
            let k = trim_whitespace_str(k);
            if !k.is_empty() && !is_allowed_block_key_name(k) {
                return Err(validation_error(format!(
                    "l7_flood.key_fields: field not supported: {} (allowed: remote_addr, user_agent, host, request_id, or header:Header-Name)",
                    wafio_domain::text_helpers::quote(k.as_bytes())
                )));
            }
        }
    }
    if let Some(s) = &r.siem
        && !s.webhook_url.is_empty()
        && !valid_webhook_url(&s.webhook_url)
    {
        return Err(validation_error(
            "siem.webhook_url must be a valid URL (http or https)",
        ));
    }
    check_semantic_policies(r.semantic_policies.as_ref())?;
    if r.path_exceptions.len() > 50 {
        return Err(validation_error(format!(
            "path_exceptions: max 50 exceptions allowed (got {})",
            r.path_exceptions.len()
        )));
    }
    for (i, exc) in r.path_exceptions.iter().enumerate() {
        if let Some(ov) = &exc.semantic_override {
            let mut sp = SemanticPoliciesConfig::default();
            let mut slots = [
                &mut sp.sql,
                &mut sp.xss,
                &mut sp.cmd,
                &mut sp.php,
                &mut sp.python,
                &mut sp.lfi,
                &mut sp.ssrf,
                &mut sp.java,
                &mut sp.nosql,
                &mut sp.ssti,
                &mut sp.xxe,
                &mut sp.deser,
                &mut sp.ldap,
                &mut sp.proto_pollution,
                &mut sp.jwt,
                &mut sp.graphql,
            ];
            for (slot, (_, p)) in slots.iter_mut().zip(ov.policies()) {
                **slot = p.cloned();
            }
            check_semantic_policies(Some(&sp))
                .map_err(|e| e.wrap(&format!("path_exceptions[{i}]")))?;
        }
        if let Some(t) = &exc.tuning {
            // An entry that names no detector is dropped at load (see `unknown_keys`), not refused.
            let mut effect = t.effect.clone();
            effect
                .skip_semantic
                .retain(|s| !is_unknown_semantic_engine(s));
            check_tuning_effect(&effect, &t.target, false)
                .map_err(|e| validation_error(format!("path_exceptions[{i}].tuning: {e}")))?;
        }
        if exc.path.is_empty() {
            return Err(validation_error(format!(
                "path_exceptions[{i}].path must not be empty"
            )));
        }
        if exc.path.len() > 500 {
            return Err(validation_error(format!(
                "path_exceptions[{i}].path too long (max 500 chars)"
            )));
        }
        match exc.match_.as_str() {
            "" | "prefix" | "exact" => {}
            "regex" => {
                if let Err(e) = crate::pattern_compile::compile(&exc.path) {
                    return Err(validation_error(format!(
                        "path_exceptions[{i}].path invalid regex: {e}"
                    )));
                }
            }
            m => {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].match must be 'prefix', 'exact', or 'regex' (got {})",
                    wafio_domain::text_helpers::quote(m.as_bytes())
                )));
            }
        }
        if let Some(ipr) = &exc.ip_rules {
            if ipr.mode != "allowlist" && ipr.mode != "blocklist" {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].ip_rules.mode must be 'allowlist' or 'blocklist'"
                )));
            }
            if ipr.ips.is_empty() {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].ip_rules.ips must not be empty when ip_rules is set"
                )));
            }
        }
        if let Some(b) = &exc.block {
            if b.status != 0 && !(400..=599).contains(&b.status) {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].block.status must be 400..599 (default 403)"
                )));
            }
            if b.message.len() > 200 {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].block.message too long (max 200 chars)"
                )));
            }
        }
        if let Some(rl) = &exc.rate_limit {
            if !(1..=1_000_000).contains(&rl.max_requests) {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].rate_limit.max_requests must be 1..1000000"
                )));
            }
            if !(1..=86400).contains(&rl.window_sec) {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].rate_limit.window_sec must be 1..86400"
                )));
            }
        }
        if exc.body_size_limit < 0 {
            return Err(validation_error(format!(
                "path_exceptions[{i}].body_size_limit must be >= 0"
            )));
        }
        if let Some(lp) = exc.login_protection.as_ref().filter(|l| l.enabled) {
            if lp.max_attempts <= 0 {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].login_protection.max_attempts must be > 0"
                )));
            }
            if lp.window_sec <= 0 {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].login_protection.window_sec must be > 0"
                )));
            }
        }
        for (j, fr) in exc.field_rules.iter().enumerate() {
            if fr.field.is_empty() {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].field_rules[{j}].field must not be empty"
                )));
            }
            if fr.action != "mask" && fr.action != "encrypt_aes" && fr.action != "decrypt_aes" {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].field_rules[{j}].action must be 'mask', 'encrypt_aes', or 'decrypt_aes'"
                )));
            }
            if (fr.action == "encrypt_aes" || fr.action == "decrypt_aes") && fr.aes_key.len() != 64
            {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].field_rules[{j}].aes_key must be 64 hex chars (AES-256)"
                )));
            }
        }
        if !exc.response_decrypt_aes.is_empty() && exc.response_decrypt_aes.len() != 64 {
            return Err(validation_error(format!(
                "path_exceptions[{i}].response_decrypt_aes must be 64 hex chars (AES-256)"
            )));
        }
        for (j, rfr) in exc.response_field_rules.iter().enumerate() {
            if rfr.field.is_empty() {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].response_field_rules[{j}].field must not be empty"
                )));
            }
            if rfr.action != "decrypt_aes" {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].response_field_rules[{j}].action must be 'decrypt_aes'"
                )));
            }
            if rfr.aes_key.len() != 64 {
                return Err(validation_error(format!(
                    "path_exceptions[{i}].response_field_rules[{j}].aes_key must be 64 hex chars (AES-256)"
                )));
            }
        }
    }
    if let Some(cs) = r.content_scan.as_ref().filter(|c| c.enabled) {
        if !cs.mode.is_empty() && cs.mode != "block" && cs.mode != "log" && cs.mode != "disabled" {
            return Err(validation_error(
                "content_scan.mode must be 'block', 'log', or 'disabled'",
            ));
        }
        if cs.max_scan_size_bytes < 0 {
            return Err(validation_error(
                "content_scan.max_scan_size_bytes must be >= 0",
            ));
        }
    }
    check_body_limits_in_raw(raw)
}

/// An absolute URL whose scheme is http or https in any case (the forms a webhook URL takes).
fn valid_webhook_url(u: &str) -> bool {
    // shortcut: the full URL grammar is not implemented; an absolute URI whose scheme is
    // http/https (any case) and that has no space or control byte passes, which holds for
    // every practical webhook URL. Upgrade when the regression replay shows a difference.
    let Some((scheme, rest)) = u.split_once(':') else {
        return false;
    };
    if !rest.starts_with('/') {
        return false; // an opaque URI is rejected
    }
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b'.')
    {
        return false;
    }
    if u.bytes().any(|c| c < 0x20 || c == 0x7f || c == b' ') {
        return false;
    }
    let s = scheme.to_ascii_lowercase();
    s == "http" || s == "https"
}

fn check_semantic_policies(p: Option<&SemanticPoliciesConfig>) -> Result<(), JsonDecodeError> {
    let Some(p) = p else { return Ok(()) };
    for (name, pol) in p.threshold_policy_map() {
        let Some(pol) = pol else { continue };
        if pol.block_threshold < 0.0 || pol.block_threshold > 100.0 {
            return Err(validation_error(format!(
                "semantic_policies.{name}.block_threshold must be 0–100"
            )));
        }
        if pol.soft_threshold < 0.0 || pol.soft_threshold > 100.0 {
            return Err(validation_error(format!(
                "semantic_policies.{name}.soft_threshold must be 0–100"
            )));
        }
        if pol.soft_threshold > 0.0
            && pol.block_threshold > 0.0
            && pol.soft_threshold > pol.block_threshold
        {
            return Err(validation_error(format!(
                "semantic_policies.{name}.soft_threshold must not exceed block_threshold"
            )));
        }
    }
    Ok(())
}

/// Whether `s` is an IP or a CIDR ("" is valid).
pub fn is_valid_ip_or_cidr(s: &str) -> bool {
    let s = trim_whitespace_str(s);
    if s.is_empty() {
        return true;
    }
    if s.contains('/') {
        return ip_network::parse_network_prefix(s).is_some();
    }
    ip_network::parse_ip(s).is_some()
}

fn is_allowed_block_key_name(s: &str) -> bool {
    if ["remote_addr", "user_agent", "host", "request_id"].contains(&s) {
        return true;
    }
    s.starts_with("header:") && !trim_whitespace_str(&s[7..]).is_empty()
}

fn check_body_limits_in_raw(data: &[u8]) -> Result<(), JsonDecodeError> {
    let Ok(doc) = json_decode::parse(data) else {
        return Ok(());
    };
    let Ok(Some(raw)) = json_decode::raw_map(&doc) else {
        return Ok(());
    };
    for key in ["request_body_limit"] {
        let Some(Value::String(s)) = raw.get(key).copied() else {
            continue;
        };
        if s.is_empty() {
            continue;
        }
        let n = parse_size_with_suffix(&String::from_utf8_lossy(s));
        if n == 0 {
            return Err(validation_error(format!(
                "{key}: invalid format (e.g. 1M, 512K, 128K)"
            )));
        }
        if n > 1024 * 1024 * 1024 {
            return Err(validation_error(format!("{key}: max 1G")));
        }
    }
    Ok(())
}

// ---- path exception matching ------------------------------------------------------------

/// The exception governing a raw request-target (no proxy).
pub fn find_exception_for_raw_target<'a>(
    uri: &[u8],
    exceptions: &'a [PathExceptionConfig],
) -> Option<&'a PathExceptionConfig> {
    if exceptions.is_empty() {
        return None;
    }
    first_exception_over_readings(&readings_for_raw_target(uri), exceptions, false)
}

/// The exception for an inline-proxy request's forwarded path.
pub fn find_exception_for_forwarded_path<'a>(
    forwarded_path: &[u8],
    exceptions: &'a [PathExceptionConfig],
) -> Option<&'a PathExceptionConfig> {
    first_exception_over_readings(
        &readings_for_proxy_request(forwarded_path),
        exceptions,
        false,
    )
}

pub fn find_exception_for_raw_target_with_field_rules<'a>(
    uri: &[u8],
    exceptions: &'a [PathExceptionConfig],
) -> Option<&'a PathExceptionConfig> {
    if exceptions.is_empty() {
        return None;
    }
    first_exception_over_readings(&readings_for_raw_target(uri), exceptions, true)
}

pub fn find_exception_for_forwarded_path_with_field_rules<'a>(
    forwarded_path: &[u8],
    exceptions: &'a [PathExceptionConfig],
) -> Option<&'a PathExceptionConfig> {
    first_exception_over_readings(
        &readings_for_proxy_request(forwarded_path),
        exceptions,
        true,
    )
}

fn first_exception_over_readings<'a>(
    rp: &RequestPathReadings,
    exceptions: &'a [PathExceptionConfig],
    require_field_rules: bool,
) -> Option<&'a PathExceptionConfig> {
    if exceptions.is_empty() {
        return None;
    }
    first_exception_on_reading(
        rp,
        &request_path_readings(rp),
        exceptions,
        require_field_rules,
    )
    .map(|i| &exceptions[i])
}

/// The index of the first matching exception.
pub(crate) fn first_exception_on_reading(
    rp: &RequestPathReadings,
    readings: &[PathReading],
    exceptions: &[PathExceptionConfig],
    require_field_rules: bool,
) -> Option<usize> {
    for (i, exc) in exceptions.iter().enumerate() {
        if exc.disabled || (require_field_rules && exc.field_rules.is_empty()) {
            continue;
        }
        let restricts = exc.limits_access();
        if !restricts && rp.no_exemption {
            continue;
        }
        let mut matched = !restricts;
        for r in readings {
            let hit = exception_matches_path(&r.path, &r.folded, exc);
            if restricts && hit {
                matched = true;
                break;
            }
            if !restricts && !hit {
                matched = false;
                break;
            }
        }
        if matched {
            return Some(i);
        }
    }
    None
}

/// One reading of the request path, cleaned for matching, with its lower-cased form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathReading {
    pub path: Vec<u8>,
    pub folded: Vec<u8>,
}

pub fn request_path_readings(rp: &RequestPathReadings) -> Vec<PathReading> {
    let (servlet, literal) = forwarded_path_readings(&rp.forwarded);
    let mut readings: Vec<PathReading> = Vec::with_capacity(3);
    let mut add = |p: Vec<u8>| {
        if readings.iter().any(|r| r.path == p) {
            return;
        }
        let folded = wafio_bytetext::strings::to_lowercase(&p);
        readings.push(PathReading { path: p, folded });
    };
    add(servlet);
    add(literal);
    if !rp.unresolved.is_empty() {
        add(unresolved_path_reading(&rp.unresolved));
    }
    readings
}

fn unresolved_path_reading(p: &[u8]) -> Vec<u8> {
    let mut p = p.to_vec();
    while wafio_bytetext::strings::contains(&p, b"//") {
        p = wafio_bytetext::strings::replace_all(&p, b"//", b"/");
    }
    p = strip_path_parameters(&p);
    if p.len() > 1 {
        while p.last() == Some(&b'/') {
            p.pop();
        }
        if p.is_empty() {
            p = b"/".to_vec();
        }
    }
    if !p.starts_with(b"/") {
        p.insert(0, b'/');
    }
    p
}

/// The (servlet, literal) readings of the forwarded path.
pub fn forwarded_path_readings(forwarded: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let servlet = normalize_rooted_path(&strip_path_parameters(forwarded));
    if !forwarded.contains(&b';') {
        return (servlet.clone(), servlet);
    }
    let literal = strip_path_parameters(&normalize_rooted_path(forwarded));
    (servlet, literal)
}

fn normalize_rooted_path(p: &[u8]) -> Vec<u8> {
    if p.starts_with(b"/") {
        normalize_path(p)
    } else {
        normalize_path(&[&b"/"[..], p].concat())
    }
}

pub fn normalize_path(p: &[u8]) -> Vec<u8> {
    if p.is_empty() {
        return b".".to_vec();
    }
    let rooted = p[0] == b'/';
    let n = p.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let (mut r, mut dotdot) = (0, 0);
    if rooted {
        out.push(b'/');
        r = 1;
        dotdot = 1;
    }
    while r < n {
        if p[r] == b'/' || p[r] == b'.' && (r + 1 == n || p[r + 1] == b'/') {
            r += 1;
        } else if p[r] == b'.' && p[r + 1] == b'.' && (r + 2 == n || p[r + 2] == b'/') {
            r += 2;
            if out.len() > dotdot {
                let mut w = out.len() - 1;
                while w > dotdot && out[w] != b'/' {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(b"..");
                dotdot = out.len();
            }
        } else {
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && p[r] != b'/' {
                out.push(p[r]);
                r += 1;
            }
        }
    }
    if out.is_empty() {
        return b".".to_vec();
    }
    out
}

/// Each ';' drops the rest of its segment.
pub fn strip_path_parameters(p: &[u8]) -> Vec<u8> {
    if !p.contains(&b';') {
        return p.to_vec();
    }
    let mut b = Vec::with_capacity(p.len());
    let mut i = 0;
    while i < p.len() {
        if p[i] != b';' {
            b.push(p[i]);
            i += 1;
            continue;
        }
        match p[i..].iter().position(|&c| c == b'/') {
            Some(next) => i += next,
            None => break,
        }
    }
    b
}

pub fn exception_matches_path(
    clean_path: &[u8],
    folded_path: &[u8],
    exc: &PathExceptionConfig,
) -> bool {
    exception_matches_path_folded(
        clean_path,
        folded_path,
        exc,
        exc.matches_case_insensitively(),
    )
}

pub fn exception_matches_path_folded(
    clean_path: &[u8],
    folded_path: &[u8],
    exc: &PathExceptionConfig,
    fold: bool,
) -> bool {
    match exc.match_.as_str() {
        "exact" => {
            if fold {
                return folded_path
                    == wafio_bytetext::strings::to_lowercase(exc.path.as_bytes()).as_slice();
            }
            clean_path == exc.path.as_bytes()
        }
        "regex" => {
            if let Some(re) = &exc.compiled_regex
                && exc.compiled_regex_fold == fold
            {
                return re.is_match(clean_path);
            }
            if fold && let Some(re) = &exc.compiled_fold_regex {
                return re.is_match(clean_path);
            }
            match crate::pattern_compile::compile(&exception_regex_source(&exc.path, fold)) {
                Ok(re) => re.is_match(clean_path),
                Err(_) => false,
            }
        }
        _ => {
            let mut p = exc.path.as_bytes();
            while p.last() == Some(&b'/') {
                p = &p[..p.len() - 1];
            }
            if p.is_empty() {
                return true;
            }
            let (p, req): (Vec<u8>, &[u8]) = if fold {
                (wafio_bytetext::strings::to_lowercase(p), folded_path)
            } else {
                (p.to_vec(), clean_path)
            };
            req == p.as_slice() || (req.starts_with(&p) && req.get(p.len()) == Some(&b'/'))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_json_passes_its_own_validator() {
        let res = load_rules_json(builtin_rules_json()).unwrap();
        assert_eq!(res.request_body_limit, 5 * 1024 * 1024);
        let sp = res.semantic_policies.unwrap();
        assert_eq!(sp.record_weak_detections, None);
        assert!(
            sp.engine_policies()
                .iter()
                .all(|(_, p)| p.is_none_or(|p| !p.disabled))
        );
        assert_eq!(
            check_rules_json(builtin_rules_json()).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn normalize_path_matches_reference() {
        for (i, w) in [
            ("/a/b/../c", "/a/c"),
            ("/../x", "/x"),
            ("/a//b/./", "/a/b"),
            ("", "."),
            ("/", "/"),
            ("a/..", "."),
        ] {
            assert_eq!(normalize_path(i.as_bytes()), w.as_bytes(), "{i}");
        }
    }

    #[test]
    fn folded_duplicates_rejected() {
        let e = reject_folded_duplicate_keys(
            br#"{"semantic_policies":{"sql":{"base_score":0,"BASE_SCORE":200}}}"#,
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "duplicate key BASE_SCORE (also base_score) in rules_json at semantic_policies.sql; keys in one object may not differ only in case"
        );
    }
}
