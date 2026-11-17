//! The WAF decision pipeline. The semantic engines inspect the request; the SIEM sender is not wired here.

use std::borrow::Cow;
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use wafio_bytetext::strings::to_lowercase_cow;
use wafio_bytetext::strings::{eq_ignore_case, to_lowercase, to_uppercase, trim_whitespace};
use wafio_bytetext::url::unescape_query_component_cow;
use wafio_domain::{
    ANALYZE_METHOD_BODY_LIMIT, ANALYZE_METHOD_BOT, ANALYZE_METHOD_CONTENT_SCAN,
    ANALYZE_METHOD_CUSTOM_RULE, ANALYZE_METHOD_ERROR, ANALYZE_METHOD_GEO, ANALYZE_METHOD_POLICY,
    ANALYZE_METHOD_SEMANTIC, AnalysisResult, BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET, Headers,
    IncomingRequest,
};
use wafio_engine_api::{ParamBaseline, ScanOutcome, ScanRequest, engine};

use crate::blocklist::BlockStore;
use crate::coverage::{PARTIAL_COVERAGE_REQUESTS, coverage_marker};
use crate::deps::engine::*;
use crate::geo::{GeoLookup, ip_in_list, parse_client_ip};
use crate::gui_rules::{
    bypass_message, mark_regex_budget_incomplete, run_gui_record_rules, verdict_for_gui_rule,
};
use crate::login_protection::evaluate_login_protection;
use crate::ratelimit::RateLimitStore;
use crate::script_rules::{ScriptRunner, mark_script_incomplete, merge_coverage_flags};
use crate::uninspected::{UnscannedContentFloor, apply_uninspected_action};

/// Query-component unescape of `s` (`%` escapes and `+`), or the input unchanged on error.
pub fn decode_or_keep_url_escapes(s: &[u8]) -> Vec<u8> {
    decode_or_keep_url_escapes_cow(s).into_owned()
}

/// `decode_or_keep_url_escapes` that borrows `s` back when nothing decodes (no `%` escape, no `+`) or
/// the decode fails; for a caller that only reads the result.
pub fn decode_or_keep_url_escapes_cow(s: &[u8]) -> Cow<'_, [u8]> {
    unescape_query_component_cow(s).unwrap_or(Cow::Borrowed(s))
}

/// Whether the lower-cased `name` equals `lower` (which holds no ASCII upper case): an ASCII
/// name is compared without a copy, any other name is lower-cased.
fn lower_equals(name: &[u8], lower: &[u8]) -> bool {
    if name.is_ascii() {
        name.eq_ignore_ascii_case(lower)
    } else {
        to_lowercase(name) == lower
    }
}

const BLOCK_POLICY_KEY_SEP: &[u8] = b"\x00";

/// The score a matched upload hash carries on the wire.
const MALWARE_HASH_SCORE: i64 = 150;

/// Dependencies and configuration of the analyze use case.
#[derive(Clone, Default)]
pub struct AnalyzeConfig {
    pub block_store: Option<Arc<dyn BlockStore>>,
    /// None = no L7 flood, per-path rate limit or login protection check.
    pub rate_limit_store: Option<Arc<dyn RateLimitStore>>,
    pub block_policy: Option<BlockPolicyConfig>,
    /// Max request body in bytes; 0 = no check; exceeding = block.
    pub request_body_limit: i64,
    /// Max GraphQL operations per batch body; 0 = DEFAULT_GRAPHQL_MAX_BATCH.
    pub graphql_max_batch: i64,
    pub content_scan: Option<ContentScanConfig>,
    pub malware_hash_engine: Option<Arc<HashMatcher>>,
    pub ssrf_config: Option<Arc<SsrfConfig>>,
    pub geo: Option<GeoConfig>,
    /// None = country rules skipped (IP rules still apply).
    pub geo_lookup: Option<Arc<dyn GeoLookup>>,
    pub l7_flood: Option<L7FloodConfig>,
    /// Prepared detector config (`bot_protection_from_rules`).
    pub bot_protection: Option<Arc<BotProtectionConfig>>,
    /// Scope of the L7 flood rate limit and login protection.
    pub project_id: String,
    /// The baseline of query parameter names, None = none is kept.
    pub param_anomaly: Option<Arc<dyn ParamBaseline>>,
    pub semantic_policies: Option<SemanticPoliciesConfig>,
    /// From `semantic_policies.inspection_off` or the older `disable_semantic`.
    pub inspection_off: bool,
    pub path_exceptions: Vec<PathExceptionConfig>,
    pub custom_gui_rules: Vec<CustomGuiRule>,
    pub custom_script_rules: Vec<CustomScriptRule>,
    /// None = the default script budget.
    pub script_budget: Option<ScriptBudget>,
    /// Runs `custom_script_rules`; None = every enabled rule is unfinished.
    pub script_runner: Option<Arc<dyn ScriptRunner>>,
    pub custom_tuning_rules: Vec<TuningRule>,
    /// Set by `cache_base_semantic_config` (public so callers can build the
    /// config with struct-update syntax).
    pub cached_semantic_config: Option<Arc<SemanticConfig>>,
}

impl AnalyzeConfig {
    /// The precomputed base semantic configuration.
    pub fn base_semantic_config(&self) -> Option<&SemanticConfig> {
        self.cached_semantic_config.as_deref()
    }
}

/// Builds the base SemanticConfig once. Call after every field is set.
pub fn cache_base_semantic_config(cfg: &mut AnalyzeConfig) {
    let mut sc = SemanticConfig {
        ssrf_config: cfg.ssrf_config.clone(),
        ..Default::default()
    };
    apply_policy_overrides(&mut sc, cfg.semantic_policies.as_ref());
    cfg.cached_semantic_config = Some(Arc::new(sc));
}

/// Engine keys of `SemanticConfig.disabled_engines` that tuning can skip.
const SEMANTIC_ENGINE_KEYS: &[&str] = &[
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

/// The detector keys this scope switches off (project, path override or tuning skip), in the order of
/// [`SEMANTIC_ENGINE_KEYS`]. `sc` is the config with the path override and tuning plan applied.
fn keys_switched_off(sc: &SemanticConfig) -> Vec<String> {
    SEMANTIC_ENGINE_KEYS
        .iter()
        .filter(|key| sc.is_disabled(key))
        .map(|key| (*key).to_string())
        .collect()
}

/// The plan's per-engine semantic skips.
fn tune_semantic_config(sc: &mut SemanticConfig, plan: Option<&TuningPlan>) {
    let Some(plan) = plan else { return };
    // A matched request is held like one under the log action of every engine.
    if plan.log_only {
        sc.log_only_engines = Some(SEMANTIC_ENGINE_KEYS.iter().map(|k| k.to_string()).collect());
    }
    if !plan.skips_any_semantic_engine() {
        return;
    }
    let skip_all = plan.skip_semantic_all || plan.skip_semantic_engines.contains("*");
    let skipped: Vec<&str> = SEMANTIC_ENGINE_KEYS
        .iter()
        .copied()
        .filter(|key| skip_all || plan.skips_semantic_engine(key))
        .collect();
    if skipped.is_empty() {
        return;
    }
    let disabled = sc.disabled_engines.get_or_insert_with(HashMap::new);
    for key in skipped {
        disabled.insert(key.to_string(), true);
    }
}

/// The canonical MIME header key (an invalid name comes back unchanged).
fn canonical_header_name(s: &[u8]) -> Cow<'_, [u8]> {
    let valid = |c: u8| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c);
    let mut upper = true;
    let mut needs = false;
    for &c in s {
        if !valid(c) {
            return Cow::Borrowed(s);
        }
        if (upper && c.is_ascii_lowercase()) || (!upper && c.is_ascii_uppercase()) {
            needs = true;
            break;
        }
        upper = c == b'-';
    }
    if !needs {
        return Cow::Borrowed(s);
    }
    // canonicalMIMEHeaderKey: a space anywhere (or another invalid byte) leaves it as is.
    if s.iter().any(|&c| !valid(c)) {
        return Cow::Borrowed(s);
    }
    let mut out = s.to_vec();
    let mut upper = true;
    for c in out.iter_mut() {
        if upper && c.is_ascii_lowercase() {
            *c -= 32;
        } else if !upper && c.is_ascii_uppercase() {
            *c += 32;
        }
        upper = *c == b'-';
    }
    Cow::Owned(out)
}

/// The first value of a header, matched case-insensitively.
pub fn first_header_value<'a>(headers: &'a Headers, name: &[u8]) -> &'a [u8] {
    if name.is_empty() {
        return b"";
    }
    if let Some(vals) = headers.get(canonical_header_name(name).as_ref())
        && let Some(v) = vals.first()
    {
        return v;
    }
    let lower = to_lowercase(name);
    for (k, vals) in headers {
        if lower_equals(k, &lower)
            && let Some(v) = vals.first()
        {
            return v;
        }
    }
    b""
}

/// The composite key of the request's key fields (AND).
pub fn composite_block_key(req: &IncomingRequest, fields: &[String]) -> Vec<u8> {
    if fields.is_empty() {
        return req.remote_address.clone();
    }
    let mut parts: Vec<&[u8]> = Vec::with_capacity(fields.len());
    for f in fields {
        let f = trim_whitespace(f.as_bytes());
        if f.is_empty() {
            continue;
        }
        let v: &[u8] = match f {
            b"remote_addr" => &req.remote_address,
            b"user_agent" => &req.user_agent,
            b"host" => &req.host,
            b"request_id" => &req.request_id,
            _ if to_lowercase(f).starts_with(b"header:") => {
                let name = trim_whitespace(f.get(7..).unwrap_or_default());
                if name.is_empty() {
                    b""
                } else {
                    first_header_value(&req.headers, name)
                }
            }
            _ => b"",
        };
        parts.push(v);
    }
    parts.join(BLOCK_POLICY_KEY_SEP)
}

/// Panics recovered on the inline path (request allowed unanalysed).
pub static RECOVERED_ANALYZE_PANICS: AtomicU64 = AtomicU64::new(0);

/// Runs the pipeline; a panic fails open (ALLOW).
pub fn analyze(req: &IncomingRequest, cfg: &AnalyzeConfig) -> AnalysisResult {
    match catch_unwind(AssertUnwindSafe(|| {
        let mut d = Defers::default();
        let r = inspect_request(req, cfg, &mut d);
        d.run(r)
    })) {
        Ok(r) => r,
        Err(e) => {
            RECOVERED_ANALYZE_PANICS.fetch_add(1, Ordering::Relaxed);
            let msg = e
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            tracing::error!("[analyze] PANIC recovered (request allowed unanalysed): {msg}");
            AnalysisResult {
                action: "allow".into(),
                analyze_method: ANALYZE_METHOD_ERROR.into(),
                message: b"analysis error".to_vec(),
                ..Default::default()
            }
        }
    }
}

/// The pipeline's deferred adjustments, run in reverse registration order (gui, regex budget, content scan
/// evidence, body incomplete, coverage marker, uninspected floor are registered in that order). The floor
/// is read when it runs, not when it is registered.
#[derive(Default)]
struct Defers {
    gui: Option<GuiRuleOutcome>,
    /// A GraphQL batch over the limit under a log-only `graphql` key: becomes the verdict of a request that
    /// would otherwise be allowed.
    batch_log: Option<AnalysisResult>,
    engines_off: Vec<String>,
    /// No engine is installed: the decision says so.
    engine_absent: bool,
    regex_budget: bool,
    scan_result: Option<AnalysisResult>,
    incomplete: Option<AnalysisResult>,
    marker: Option<String>,
    floor: Option<UnscannedContentFloor>,
}

impl Defers {
    fn run(self, mut result: AnalysisResult) -> AnalysisResult {
        if let Some(log) = self.batch_log
            && result.analyze_method != ANALYZE_METHOD_ERROR
            && result.action == "allow"
        {
            result = log;
        }
        if let Some(floor) = &self.floor {
            floor.apply(&mut result);
        }
        if let Some(marker) = &self.marker
            && result.analyze_method != ANALYZE_METHOD_ERROR
        {
            result.coverage = merge_coverage_flags(
                marker.strip_prefix("coverage:").unwrap_or(marker),
                &result.coverage,
            );
            if result.action == "block" || result.action == "log" {
                if !result.match_detail.is_empty() {
                    result.match_detail.extend_from_slice(b"; ");
                }
                result.match_detail.extend_from_slice(b"coverage:");
                result
                    .match_detail
                    .extend_from_slice(result.coverage.as_bytes());
            }
        }
        if let Some(mut incomplete) = self.incomplete
            && result.analyze_method != ANALYZE_METHOD_ERROR
            && result.action == "allow"
        {
            if !result.coverage.is_empty() {
                incomplete.coverage = result.coverage.clone();
            }
            result = incomplete;
        }
        if let Some(scan) = self.scan_result
            && result.analyze_method != ANALYZE_METHOD_ERROR
        {
            if result.action == "allow" && scan.action == "log" {
                result = scan;
            } else {
                if !result.match_detail.is_empty() {
                    result.match_detail.extend_from_slice(b"; ");
                }
                result.match_detail.extend_from_slice(&scan.match_detail);
            }
        }
        if self.regex_budget {
            mark_regex_budget_incomplete(&mut result);
        }
        if let Some(gui) = &self.gui {
            run_gui_record_rules(&mut result, gui);
        }
        if result.analyze_method != ANALYZE_METHOD_ERROR {
            result.engines_off = self.engines_off;
            result.engine_absent = self.engine_absent;
        }
        result
    }
}

fn block(message: &[u8], category: &str, method: &str) -> AnalysisResult {
    AnalysisResult {
        action: "block".into(),
        message: message.to_vec(),
        categories: vec![category.into()],
        analyze_method: method.into(),
        ..Default::default()
    }
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn regex_exhausted(ctx: &RequestRuleContext) -> bool {
    ctx.regex_budget
        .as_ref()
        .is_some_and(|b| b.lock().unwrap_or_else(|e| e.into_inner()).exhausted())
}

/// Records a block under the block policy; Some(until) when it opened a
/// temporary block window.
fn record_policy_block(
    cfg: &AnalyzeConfig,
    bp: &BlockPolicyConfig,
    key: &[u8],
) -> Option<SystemTime> {
    // A missing block store panics here (fail open).
    let store = cfg
        .block_store
        .as_ref()
        .expect("block policy without a block store");
    store.record_block(key);
    let count = store.block_count(key);
    if count >= bp.block_after_n_blocks {
        let until = SystemTime::now() + Duration::from_secs(bp.block_duration_sec.max(0) as u64);
        store.set_block_until(key, until);
        return Some(until);
    }
    None
}

fn enabled_block_policy(cfg: &AnalyzeConfig) -> Option<&BlockPolicyConfig> {
    cfg.block_policy.as_ref().filter(|bp| bp.enabled)
}

/// What the `graphql` key says for this request: whether it is off, and whether it only logs. Both are read from
/// the project's rules, the path exception that matches (`semantic_override` names the key either way) and a
/// tuning rule's `skip_semantic`. The batch check runs before the path and the tuning rules are read, so this
/// reads them again; it is called only for a batch body over the limit.
fn graphql_switches(req: &IncomingRequest, cfg: &AnalyzeConfig) -> (bool, bool) {
    let rp = path_readings(req);
    let exc = find_path_rules_for_request(&rp, &cfg.path_exceptions)
        .0
        .map(|i| &cfg.path_exceptions[i]);
    let (mut off, mut log_only) = match cfg.base_semantic_config() {
        Some(c) => (c.is_disabled("graphql"), c.is_log_only("graphql")),
        None => cfg
            .semantic_policies
            .as_ref()
            .and_then(|sp| sp.graphql.as_ref())
            .map_or((false, false), |p| {
                (p.disabled, p.action == ENGINE_ACTION_LOG)
            }),
    };
    if let Some(exc) = exc
        && !cfg.inspection_off
        && !exc.is_inspection_off()
        && let Some(p) = exc
            .semantic_override
            .as_ref()
            .and_then(|o| o.graphql.as_ref())
    {
        off = p.disabled;
        match p.action.as_str() {
            ENGINE_ACTION_LOG => log_only = true,
            ENGINE_ACTION_BLOCK => log_only = false,
            _ => {}
        }
    }
    let mut plan: Option<TuningPlan> = None;
    if !cfg.custom_tuning_rules.is_empty() {
        let ctx = rule_context_for_request(req, &rp.forwarded, cfg);
        let alt = (!rp.unresolved.is_empty()).then(|| ctx.with_alternate_path(&rp.unresolved));
        plan = compute_tuning_plan_on_paths(&cfg.custom_tuning_rules, &ctx, alt.as_ref(), &rp);
    }
    if let Some(t) = exc.and_then(|e| e.tuning.as_ref()) {
        plan = Some(merge_effect_into_plan(plan, &t.effect));
    }
    let off = off
        || plan
            .as_ref()
            .is_some_and(|p| p.skips_semantic_engine("graphql"));
    (off, log_only)
}

fn inspect_request(req: &IncomingRequest, cfg: &AnalyzeConfig, d: &mut Defers) -> AnalysisResult {
    let mut effective_size = req.body.len() as i64;
    if req.body_size > 0 {
        effective_size = req.body_size;
    }
    if cfg.request_body_limit > 0 && effective_size > cfg.request_body_limit {
        return block(
            b"Request body exceeds configured limit",
            "BodyLimit",
            ANALYZE_METHOD_BODY_LIMIT,
        );
    }

    // Request-smuggling lock: non-bypassable.
    let detail = smuggling_indicator(&req.headers);
    if !detail.is_empty() {
        return AnalysisResult {
            match_detail: detail.as_bytes().to_vec(),
            match_source: b"header:fraction".to_vec(),
            status_code: 400,
            ..block(
                b"Request smuggling indicators",
                "ProtocolAttack",
                ANALYZE_METHOD_POLICY,
            )
        };
    }

    // GraphQL batch abuse: infra-tier, off only with the `graphql` key.
    if engine().graphql_batch_over_limit(&req.body, cfg.graphql_max_batch) {
        let (off, log_only) = graphql_switches(req, cfg);
        if !off {
            let hit = AnalysisResult {
                match_detail: b"graphql_batch_abuse".to_vec(),
                match_source: b"body".to_vec(),
                status_code: 400,
                ..block(
                    b"GraphQL batch exceeds operation limit",
                    "ProtocolAttack",
                    ANALYZE_METHOD_POLICY,
                )
            };
            if !log_only {
                return hit;
            }
            // A log-only key lets the request on; the verdict is this LOG unless something else decides.
            d.batch_log = Some(AnalysisResult {
                action: "log".into(),
                status_code: 0,
                message: b"GraphQL batch exceeds operation limit; logged (engine is log only)."
                    .to_vec(),
                engines_log_only: vec!["graphql".into()],
                ..hit
            });
        }
    }

    // One set of path readings for every path matcher below.
    let rp = path_readings(req);
    let fwd_path = rp.forwarded.clone();

    // Per-path exceptions; flood/block/geo/bot below are never bypassed by them.
    let mut inspection_off_for_path = cfg.inspection_off;
    let mut path_exc: Option<&PathExceptionConfig> = None;
    let mut limits = PathLimits::default(); // indices into cfg.path_exceptions
    if !cfg.path_exceptions.is_empty() {
        let (exc, l) = find_path_rules_for_request(&rp, &cfg.path_exceptions);
        limits = l;
        if let Some(exc) = exc.map(|i| &cfg.path_exceptions[i]) {
            path_exc = Some(exc);
            inspection_off_for_path |= exc.is_inspection_off();
        }
    }
    if let Some(bs) = limits.body_size.map(|i| &cfg.path_exceptions[i])
        && effective_size > bs.body_size_limit
    {
        return block(
            b"Request body exceeds path-specific size limit",
            "BodyLimit",
            ANALYZE_METHOD_BODY_LIMIT,
        );
    }
    // Per-path hard block.
    if let Some(pe) = path_exc
        && let Some(b) = &pe.block
    {
        let status = if b.status == 0 { 403 } else { b.status };
        let msg = if b.message.is_empty() {
            "Path not allowed"
        } else {
            b.message.as_str()
        };
        return AnalysisResult {
            match_source: cat(&[b"path:", pe.path.as_bytes()]),
            status_code: status,
            ..block(msg.as_bytes(), "PathBlock", ANALYZE_METHOD_POLICY)
        };
    }
    // Per-path rate limit: every governing limit counts the request.
    if !limits.rate_limit.is_empty()
        && let Some(store) = &cfg.rate_limit_store
    {
        let mut over: Option<&PathExceptionConfig> = None;
        for exc in limits.rate_limit.iter().map(|&i| &cfg.path_exceptions[i]) {
            let rl = exc
                .rate_limit
                .as_ref()
                .expect("rate limit exception without rate_limit");
            let scope = cat(&[b"path_rl:", exc.path.as_bytes()]);
            if !store.allow(
                &scope,
                &strip_port(&req.remote_address),
                rl.max_requests,
                rl.window_sec,
            ) && over.is_none()
            {
                over = Some(exc);
            }
        }
        if let Some(over) = over {
            return AnalysisResult {
                match_source: cat(&[b"path:", over.path.as_bytes()]),
                status_code: 429,
                ..block(
                    b"Rate limit exceeded for this path",
                    "PathRateLimit",
                    ANALYZE_METHOD_POLICY,
                )
            };
        }
    }
    // L7 HTTP flood; l7_flood.allow_ips exempts trusted clients from this check only.
    if let Some(f) = &cfg.l7_flood
        && f.enabled
        && let Some(store) = &cfg.rate_limit_store
        && !f.key_fields.is_empty()
        && !f.exempts_ip(&String::from_utf8_lossy(&req.remote_address))
    {
        let client_key = composite_block_key(req, &f.key_fields);
        let scope = if cfg.project_id.is_empty() {
            "default"
        } else {
            cfg.project_id.as_str()
        };
        if !store.allow(scope.as_bytes(), &client_key, f.max_requests, f.window_sec) {
            return block(
                b"L7 HTTP flood: request rate exceeded",
                "L7Flood",
                ANALYZE_METHOD_POLICY,
            );
        }
    }
    let mut key: Vec<u8> = Vec::new();
    if let Some(bp) = &cfg.block_policy
        && bp.enabled
        && !bp.key_fields.is_empty()
    {
        key = composite_block_key(req, &bp.key_fields);
        let store = cfg
            .block_store
            .as_ref()
            .expect("block policy without a block store");
        if let Some(until) = store.block_until(&key)
            && SystemTime::now() < until
        {
            return AnalysisResult {
                block_until: Some(until),
                ..block(
                    b"blocked by policy (temporary block window)",
                    "Policy",
                    ANALYZE_METHOD_POLICY,
                )
            };
        }
    }

    // Geoblocking (before the semantic scan).
    if cfg.geo.is_some() {
        let (blocked, msg) = enforce_country_rules(req, cfg);
        if blocked {
            return block(msg.as_bytes(), "Geo", ANALYZE_METHOD_GEO);
        }
    }

    // Bot protection (UA/headers + JA3/JA4).
    let mut bot_result = BotResult::default();
    if let Some(bp) = &cfg.bot_protection
        && bp.enabled
        && bp.mode != "off"
    {
        let breq = BotRequest {
            method: &req.method,
            uri: &req.uri,
            user_agent: &req.user_agent,
            ja3: &req.ja3,
            ja4: &req.ja4,
            headers: &req.headers,
        };
        bot_result = classify_bot(&breq, Some(bp));
        if bot_result.score > 0 && bp.mode == "block" {
            let mut out = AnalysisResult {
                score: bot_result.score,
                match_detail: bot_result.match_detail.clone(),
                match_source: b"header:User-Agent".to_vec(),
                ..block(
                    format!("bot detected: {}", bot_result.reason).as_bytes(),
                    "Bot",
                    ANALYZE_METHOD_BOT,
                )
            };
            if let Some(pol) = enabled_block_policy(cfg)
                && !key.is_empty()
            {
                out.block_until = record_policy_block(cfg, pol, &key);
            }
            return out;
        }
    }

    // Custom GUI rules: the rule context is built once when any custom-rule
    // flavour is configured and reused by tuning and script rules.
    let mut waf_ctx: Option<RequestRuleContext> = None;
    let mut alt_ctx: Option<RequestRuleContext> = None; // the unresolved path reading
    if !cfg.custom_gui_rules.is_empty()
        || !cfg.custom_script_rules.is_empty()
        || !cfg.custom_tuning_rules.is_empty()
    {
        let ctx = rule_context_for_request(req, &fwd_path, cfg);
        if !rp.unresolved.is_empty() {
            alt_ctx = Some(ctx.with_alternate_path(&rp.unresolved));
        }
        waf_ctx = Some(ctx);
    }
    let mut gui = GuiRuleOutcome::default();
    if !cfg.custom_gui_rules.is_empty()
        && let Some(ctx) = &waf_ctx
    {
        gui = evaluate_gui_rules_on_paths(&cfg.custom_gui_rules, ctx, alt_ctx.as_ref(), &rp);
        // Only allow and block end inspection.
        if !gui.log_rule_id.is_empty() || !gui.challenge_rule_id.is_empty() {
            d.gui = Some(gui.clone());
        }
        if gui.action == "block" {
            let mut res = verdict_for_gui_rule(&gui);
            if regex_exhausted(ctx) {
                res.coverage = COVERAGE_FLAG_REGEX_BUDGET.into();
                PARTIAL_COVERAGE_REQUESTS.fetch_add(1, Ordering::Relaxed);
            }
            return res;
        }
    }

    // Custom Rules v2 tuning: one per-request plan before any engine runs.
    let mut tuning_plan: Option<TuningPlan> = None;
    if !cfg.custom_tuning_rules.is_empty()
        && let Some(ctx) = &waf_ctx
    {
        tuning_plan =
            compute_tuning_plan_on_paths(&cfg.custom_tuning_rules, ctx, alt_ctx.as_ref(), &rp);
    }
    if let Some(pe) = path_exc
        && let Some(t) = &pe.tuning
    {
        tuning_plan = Some(merge_effect_into_plan(tuning_plan, &t.effect));
    }
    let plan = tuning_plan.as_ref();
    // `skip_semantic: ["*"]` stops the engines; `scan_mode: disabled` does too and counts as inspection off.
    let tuning_skip_semantic = plan.is_some_and(|p| p.skip_semantic_all);
    let tuning_inspection_off = plan.is_some_and(|p| p.scan_mode == "disabled");

    // Regex conditions skipped for lack of budget make the verdict incomplete.
    let regex_incomplete = waf_ctx.as_ref().is_some_and(regex_exhausted);
    if regex_incomplete {
        d.regex_budget = true;
    }

    // Per-path IP rules.
    if let Some(pe) = path_exc
        && let Some(ipr) = &pe.ip_rules
        && !ipr.ips.is_empty()
    {
        let in_list = ip_in_list(&geo_client_ip(req), &ipr.ips);
        if ipr.mode == "allowlist" && !in_list {
            return block(
                b"IP not in path allowlist",
                "PathIPRule",
                ANALYZE_METHOD_POLICY,
            );
        } else if ipr.mode == "blocklist" && in_list {
            return block(
                b"IP blocked by path rule",
                "PathIPRule",
                ANALYZE_METHOD_POLICY,
            );
        }
    }

    // Per-path login protection.
    let login: Vec<&PathExceptionConfig> = limits
        .login
        .iter()
        .map(|&i| &cfg.path_exceptions[i])
        .collect();
    if let Some(res) = evaluate_login_protection(req, &login, cfg) {
        return res;
    }

    // GUI allow rule: ends inspection after the path access controls.
    if gui.action == "allow" && !regex_incomplete {
        return verdict_for_gui_rule(&gui);
    }

    // Content scanning: separate body input; binary bytes never enter semantic parsing.
    if let Some(cs) = &cfg.content_scan
        && cs.enabled
        && cs.mode != "disabled"
        && (cs.scan_raw_body
            || (cs.scan_multipart
                && to_lowercase_cow(&req.content_type).starts_with(b"multipart/")))
    {
        let body: &[u8] = req.content_scan_body.as_deref().unwrap_or(&req.body);
        let encoding = trim_whitespace(first_header_value(&req.headers, b"Content-Encoding"));
        let not_scanned = |reason: &str| FileScanResult {
            status: "not_scanned".into(),
            reason: reason.into(),
            ..Default::default()
        };
        let (files, matched) = if !encoding.is_empty() && !eq_ignore_case(encoding, b"identity") {
            (vec![not_scanned("unsupported_content_encoding")], None)
        } else if req.body_size > body.len() as i64 {
            (vec![not_scanned("transport_truncated")], None)
        } else {
            scan_uploaded_files(
                &req.content_type,
                body,
                cs,
                cfg.malware_hash_engine.as_deref(),
            )
        };
        if !files.is_empty() {
            let mut scan_result = AnalysisResult {
                action: "allow".into(),
                analyze_method: ANALYZE_METHOD_CONTENT_SCAN.into(),
                match_detail: render_scan_results(&files),
                ..Default::default()
            };
            if let Some(m) = &matched {
                // A matched hash is a block, or a log line in log mode.
                scan_result.action = if cs.mode == "log" { "log" } else { "block" }.into();
                scan_result.score = MALWARE_HASH_SCORE;
                scan_result.categories = vec!["Malware".into()];
                scan_result.message = cat(&[b"Known upload hash matched: ", &m.threat_name]);
                // Not exact: the flagged part is a file no stored copy holds.
                scan_result.match_source = cat(&[b"body:", &m.field_name]);
                scan_result.cwe = "CWE-434".into();
            } else if files
                .iter()
                .any(|f| f.status == "error" || f.status == "not_scanned")
            {
                let mut action = if cs.on_incomplete.is_empty() {
                    "log"
                } else {
                    cs.on_incomplete.as_str()
                };
                if cs.mode == "log" && action == "block" {
                    action = "log";
                }
                scan_result.action = action.into();
                scan_result.categories = vec!["ContentScanIncomplete".into()];
                scan_result.message = b"Upload hash scan incomplete".to_vec();
            }
            if scan_result.action == "block" {
                return scan_result;
            }
            d.scan_result = Some(scan_result);
        }
    }

    // Body the transport could not hand over complete: content_scan.on_incomplete.
    if let Some(cs) = &cfg.content_scan
        && !req.body_scan_skipped.is_empty()
        && cs.enabled
        && cs.mode != "disabled"
        && !(inspection_off_for_path || tuning_inspection_off)
    {
        let mut action = if cs.on_incomplete.is_empty() {
            "log"
        } else {
            cs.on_incomplete.as_str()
        };
        if cs.mode == "log" && action == "block" {
            action = "log";
        }
        // A decode budget skip is load-induced: capped at log.
        if req.body_scan_skipped == BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET && action == "block" {
            action = "log";
        }
        if action == "block" || action == "log" {
            let incomplete = AnalysisResult {
                action: action.into(),
                message: b"Request body inspection incomplete".to_vec(),
                categories: vec!["ContentScanIncomplete".into()],
                analyze_method: ANALYZE_METHOD_CONTENT_SCAN.into(),
                match_detail: format!("body_scan_incomplete:{}", req.body_scan_skipped)
                    .into_bytes(),
                match_source: b"body".to_vec(),
                coverage: format!("body_{}", req.body_scan_skipped),
                ..Default::default()
            };
            if action == "block" {
                return incomplete;
            }
            d.incomplete = Some(incomplete);
        }
    }

    let normalized_input = decoded_request_uri(req);

    // Inspection off: allow after the infra checks; script rules still decide.
    if inspection_off_for_path {
        let mut res = AnalysisResult {
            action: "allow".into(),
            message: bypass_message(cfg.inspection_off).as_bytes().to_vec(),
            analyze_method: ANALYZE_METHOD_POLICY.into(),
            ..Default::default()
        };
        if !cfg.custom_script_rules.is_empty()
            && let Some(ctx) = waf_ctx.as_mut()
        {
            ctx.score = 0.0;
            ctx.action = "allow".into();
            let sr = run_script_rules_on_paths(cfg, ctx, &rp);
            if !sr.action.is_empty() {
                res = script_verdict(&sr);
            }
            if sr.incomplete {
                mark_script_incomplete(&mut res, &sr, false);
            }
        }
        return res;
    }

    let mut semantic_config: SemanticConfig = match &cfg.cached_semantic_config {
        Some(c) => (**c).clone(),
        None => {
            let mut sc = SemanticConfig {
                ssrf_config: cfg.ssrf_config.clone(),
                ..Default::default()
            };
            apply_policy_overrides(&mut sc, cfg.semantic_policies.as_ref());
            sc
        }
    };
    if !tuning_skip_semantic
        && let Some(pe) = path_exc
        && let Some(ov) = &pe.semantic_override
    {
        apply_path_semantic_override(ov, &mut semantic_config);
    }
    tune_semantic_config(&mut semantic_config, plan);
    d.engines_off = keys_switched_off(&semantic_config);

    let ScanOutcome {
        tier: mut semantic_tier,
        reason: mut semantic_reason,
        detail: mut semantic_match_detail,
        source: mut match_source,
        source_exact: mut match_source_exact,
        value: mut match_value,
        coverage,
        // The detection of a log-only engine that would have blocked, held back from the verdict.
        mut held,
    } = engine().scan_request(&ScanRequest {
        request: req,
        config: &semantic_config,
        normalized_input: &normalized_input,
        forwarded_path: &fwd_path,
        project_id: cfg.project_id.as_bytes(),
        scan_all_headers: cfg.inspects_all_headers(),
        regex_incomplete,
        run_scan: !tuning_skip_semantic,
        track_params: cfg.param_anomaly.as_deref(),
    });
    d.engine_absent = coverage.engine_absent;
    if !tuning_skip_semantic {
        // Partial coverage: counted, and BLOCK/LOG verdicts say so.
        let marker = coverage_marker(&coverage);
        if !marker.is_empty() {
            PARTIAL_COVERAGE_REQUESTS.fetch_add(1, Ordering::Relaxed);
            d.marker = Some(marker);
        }
    }

    let semantic_ran = !tuning_skip_semantic;

    // No clean allow over content no engine inspected.
    let mut floor = UnscannedContentFloor {
        action: apply_uninspected_action(cfg.semantic_policies.as_ref()),
        withheld: req.body_scan_skipped.clone(),
        ..Default::default()
    };
    if let Some(cs) = &cfg.content_scan
        && cs.enabled
        && cs.mode != "disabled"
    {
        floor.content_scan_owns = true;
    }
    if semantic_ran {
        floor.body_gap = coverage.body_uninspected();
        floor.other_gap = coverage.other_uninspected();
        floor.semantic_marked = !coverage.complete();
        d.floor = Some(floor);
    }

    if semantic_tier == Tier::Strong {
        let mut out = semantic_block_result(
            &semantic_reason,
            &semantic_match_detail,
            &match_source,
            match_source_exact,
            &match_value,
        );
        if let Some(bp) = enabled_block_policy(cfg)
            && let Some(until) = record_policy_block(cfg, bp, &key)
        {
            out.block_until = Some(until);
            out.message =
                b"Request blocked; temporary block applied (exceeded threshold).".to_vec();
        }
        return out;
    }
    // No other engine blocks: the detection of the log-only engine is the verdict, as a LOG.
    let mut log_only_key: Option<String> = None;
    if let Some(h) = held.take() {
        log_only_key = Some(disabled_key_from_reason(&h.reason));
        semantic_tier = Tier::Strong;
        semantic_reason = h.reason;
        semantic_match_detail = h.detail;
        match_source = h.source;
        match_source_exact = h.source_exact;
        match_value = h.value;
    }

    // The semantic stage ran, found nothing and covered the whole request: allow it.
    let is_multipart = to_lowercase_cow(&req.content_type).starts_with(b"multipart/");
    let mut semantic_clean = !is_multipart
        && semantic_ran
        && semantic_tier == Tier::Clean
        && semantic_reason.is_empty()
        && coverage.complete();

    if semantic_clean
        && !cfg.custom_script_rules.is_empty()
        && let Some(ctx) = waf_ctx.as_mut()
    {
        ctx.score = 0.0;
        ctx.action = "allow".into();
        let sr = run_script_rules_on_paths(cfg, ctx, &rp);
        if !sr.action.is_empty() && (!sr.incomplete || sr.action == "block") {
            let mut res = script_verdict(&sr);
            if sr.incomplete {
                mark_script_incomplete(&mut res, &sr, false);
            }
            return res;
        }
        // An unfinished script cannot vouch for a clean request.
        if sr.incomplete {
            semantic_clean = false;
        }
    }
    if semantic_clean {
        return AnalysisResult {
            action: "allow".into(),
            message: b"semantic clean".to_vec(),
            analyze_method: ANALYZE_METHOD_SEMANTIC.into(),
            ..Default::default()
        };
    }

    // Bot protection score mode.
    let mut total_score = 0;
    let mut blocked = false;
    let mut block_due_to_bot_score = false;
    if let Some(bp) = &cfg.bot_protection
        && bp.enabled
        && bp.mode == "score"
        && bot_result.score > 0
    {
        total_score = bot_result.score;
        let threshold = if bp.score_threshold > 0 {
            bp.score_threshold
        } else {
            DEFAULT_BOT_SCORE_THRESHOLD
        };
        if total_score >= threshold {
            blocked = true;
            block_due_to_bot_score = true;
        }
    }

    let mut categories: Vec<String> = Vec::new();
    if let Some(bp) = &cfg.bot_protection
        && bp.enabled
        && bot_result.score > 0
        && (bp.mode == "score" || bp.mode == "log")
    {
        categories.push("Bot".into());
    }
    let analyze_method = if block_due_to_bot_score {
        ANALYZE_METHOD_BOT
    } else {
        ANALYZE_METHOD_SEMANTIC
    };
    let mut out = AnalysisResult {
        action: if blocked { "block" } else { "allow" }.into(),
        score: total_score,
        categories,
        analyze_method: analyze_method.into(),
        ..Default::default()
    };
    out.match_source = engine().guess_match_source(req);
    if let Some(bp) = &cfg.bot_protection
        && ((bp.mode == "log" && bot_result.score > 0) || block_due_to_bot_score)
        && out.match_detail.is_empty()
    {
        out.match_detail = cat(&[b"bot:", &bot_result.match_detail]);
    }
    if !blocked {
        out.message = b"Request allowed.".to_vec();
    }

    // A strong detection a log-only engine held back, or a weak one the policy records, is a LOG.
    let logged_semantic =
        log_only_key.is_some() || (semantic_tier == Tier::Weak && cfg.records_weak_detections());
    if !blocked && logged_semantic && !semantic_reason.is_empty() {
        let (display_reason, md_norm) =
            siem_reason_and_detail(&semantic_reason, &semantic_match_detail);
        let (categories, _) = block_response_for_semantic_reason(&semantic_reason);
        let tax = classify_semantic_reason(&display_reason, &md_norm);
        out.action = "log".into();
        out.score = decision_score(&semantic_reason, semantic_tier);
        out.analyze_method = ANALYZE_METHOD_SEMANTIC.into();
        out.categories = categories;
        out.message = if log_only_key.is_some() {
            b"Request allowed; logged (engine is log only).".to_vec()
        } else {
            b"Request allowed; logged (category disabled).".to_vec()
        };
        out.engines_log_only = log_only_key.into_iter().collect();
        out.match_detail = md_norm;
        out.match_source = match_source;
        out.match_source_exact = match_source_exact;
        out.match_value = exact_match_value(match_source_exact, match_value);
        set_taxonomy(&mut out, tax);
    }

    // Custom script rules: post-decision override with full context.
    if !cfg.custom_script_rules.is_empty()
        && let Some(ctx) = waf_ctx.as_mut()
    {
        ctx.score = total_score as f64;
        ctx.action = out.action.clone();
        ctx.detected = out.categories.clone();
        let sr = run_script_rules_on_paths(cfg, ctx, &rp);
        if !sr.action.is_empty() {
            out.action = sr.action.clone();
            out.analyze_method = ANALYZE_METHOD_CUSTOM_RULE.into();
            out.message = cat(&[b"custom_script_rule:", sr.rule_id.as_bytes()]);
            if sr.action == "block" {
                blocked = true;
            }
        }
        if sr.incomplete {
            mark_script_incomplete(&mut out, &sr, !coverage.complete());
            if let Some(f) = d.floor.as_mut() {
                f.script_incomplete = true;
                f.script_content = sr.content_incomplete;
            }
        }
    }

    // Tuning attribution: matched tuning rule ids when no category claimed the verdict.
    if let Some(p) = plan
        && !p.matched_rule_ids.is_empty()
        && (out.action == "block" || out.action == "log")
        && out.categories.is_empty()
    {
        out.categories.extend(
            p.matched_rule_ids
                .iter()
                .map(|id| format!("tuning_rule:{id}")),
        );
    }

    if blocked {
        if let Some(bp) = enabled_block_policy(cfg)
            && let Some(until) = record_policy_block(cfg, bp, &key)
        {
            out.block_until = Some(until);
            out.message = b"blocked; temporary block applied (exceeded threshold)".to_vec();
        }
        if out.message.is_empty() {
            out.message = message_for_categories(&out.categories).into_bytes();
        }
    }
    out
}

/// The semantic BLOCK verdict.
fn semantic_block_result(
    reason: &str,
    detail: &[u8],
    source: &[u8],
    exact: bool,
    value: &[u8],
) -> AnalysisResult {
    let (display_reason, md_norm) = siem_reason_and_detail(reason, detail);
    let (categories, msg) = block_response_for_semantic_reason(reason);
    let tax = classify_semantic_reason(&display_reason, &md_norm);
    AnalysisResult {
        action: "block".into(),
        score: decision_score(reason, Tier::Strong),
        categories,
        message: msg.as_bytes().to_vec(),
        analyze_method: ANALYZE_METHOD_SEMANTIC.into(),
        match_detail: md_norm,
        match_source: source.to_vec(),
        match_source_exact: exact,
        match_value: exact_match_value(exact, value.to_vec()),
        cwe: tax.cwe.to_string(),
        mitre_techniques: tax.mitre_techniques.iter().map(|t| t.to_string()).collect(),
        ..Default::default()
    }
}

fn set_taxonomy(out: &mut AnalysisResult, tax: AttackClassification) {
    out.cwe = tax.cwe.to_string();
    out.mitre_techniques = tax.mitre_techniques.iter().map(|t| t.to_string()).collect();
}

fn script_verdict(sr: &ScriptResult) -> AnalysisResult {
    AnalysisResult {
        action: sr.action.clone(),
        analyze_method: ANALYZE_METHOD_CUSTOM_RULE.into(),
        message: cat(&[b"custom_script_rule:", sr.rule_id.as_bytes()]),
        ..Default::default()
    }
}

/// The block store only (no WAF).
pub fn check_block_store(key: &[u8], store: &dyn BlockStore) -> Option<SystemTime> {
    store.block_until(key)
}

/// The URL-decoded URI for the whole-request pass.
fn decoded_request_uri(req: &IncomingRequest) -> Cow<'_, [u8]> {
    decode_or_keep_url_escapes_cow(&req.uri)
}

fn exact_match_value(exact: bool, v: Vec<u8>) -> Option<Vec<u8>> {
    exact.then_some(v)
}

/// Category and block-page message per semantic reason.
fn category_for_semantic_reason(reason: &str) -> Option<(&'static str, &'static str)> {
    Some(match reason {
        REASON_SEMANTIC_SQL => ("SQLi", "Request blocked: potential SQL injection detected."),
        REASON_SEMANTIC_XSS => ("XSS", "Request blocked: potential XSS detected."),
        REASON_SEMANTIC_CMD => (
            "RCE",
            "Request blocked: potential command injection detected.",
        ),
        REASON_SEMANTIC_PHP => ("PHP", "Request blocked: potential PHP injection detected."),
        REASON_SEMANTIC_PYTHON => (
            "Python",
            "Request blocked: potential Python injection detected.",
        ),
        REASON_SEMANTIC_LFI => (
            "LFI",
            "Request blocked: potential path traversal / local file inclusion detected.",
        ),
        REASON_SEMANTIC_SSRF => (
            "SSRF",
            "Request blocked: potential server-side request forgery (SSRF) detected.",
        ),
        REASON_SEMANTIC_JAVA => (
            "Java",
            "Request blocked: potential Java/EL injection detected.",
        ),
        REASON_SEMANTIC_LDAP => (
            "LDAP",
            "Request blocked: potential LDAP injection detected.",
        ),
        REASON_SEMANTIC_PROTO_POLLUTION => (
            "PrototypePollution",
            "Request blocked: potential prototype pollution detected.",
        ),
        REASON_SEMANTIC_SSTI => (
            "SSTI",
            "Request blocked: potential server-side template injection detected.",
        ),
        REASON_SEMANTIC_XXE => (
            "XXE",
            "Request blocked: potential XML external entity (XXE) injection detected.",
        ),
        REASON_SEMANTIC_DESER => (
            "Deserialization",
            "Request blocked: potential unsafe deserialization detected.",
        ),
        REASON_SEMANTIC_NOSQL => (
            "NoSQLi",
            "Request blocked: potential NoSQL injection detected.",
        ),
        REASON_SEMANTIC_OPEN_REDIRECT => (
            "OpenRedirect",
            "Request blocked: potential open redirect detected.",
        ),
        REASON_SEMANTIC_HEADER_INJECTION => (
            "HeaderInjection",
            "Request blocked: potential header (CRLF) injection detected.",
        ),
        REASON_SEMANTIC_PROMPT_INJECTION => (
            "PromptInjection",
            "Request blocked: potential prompt injection detected.",
        ),
        REASON_SEMANTIC_ANOMALY => ("Anomaly", "Request blocked: anomalous input detected."),
        REASON_SEMANTIC_GRAPHQL => (
            "GraphQL",
            "Request blocked: GraphQL introspection detected.",
        ),
        REASON_SEMANTIC_JWT => (
            "JWT",
            "Request blocked: potential JWT header attack detected.",
        ),
        _ => return None,
    })
}

/// An unknown reason gets a neutral category.
fn block_response_for_semantic_reason(reason: &str) -> (Vec<String>, &'static str) {
    match category_for_semantic_reason(reason) {
        Some((c, m)) => (vec![c.to_string()], m),
        None => (
            vec!["Semantic".into()],
            "Request blocked: suspicious input detected.",
        ),
    }
}

/// RemoteAddr only (the proxy applied the trust policy).
pub(crate) fn geo_client_ip(req: &IncomingRequest) -> Vec<u8> {
    parse_client_ip(&req.remote_address)
}

fn enforce_country_rules(req: &IncomingRequest, cfg: &AnalyzeConfig) -> (bool, &'static str) {
    let Some(g) = &cfg.geo else {
        return (false, "");
    };
    let client_ip = geo_client_ip(req);
    if client_ip.is_empty() {
        return (false, "");
    }
    let parsed = ip_network::parse_ip(&String::from_utf8_lossy(&client_ip));
    if let Some(ip) = &parsed
        && !g.allow_ips.is_empty()
        && g.allows_ip(ip)
    {
        return (false, "");
    }
    if let Some(ip) = &parsed
        && !g.block_ips.is_empty()
        && g.blocks_ip(ip)
    {
        return (
            true,
            "Request blocked: geoblocking (IP or range not allowed).",
        );
    }
    let Some(lookup) = &cfg.geo_lookup else {
        return (false, "");
    };
    let Ok(country) = lookup.country(&client_ip) else {
        return (false, "");
    };
    let country = String::from_utf8_lossy(&to_uppercase(trim_whitespace(&country))).into_owned();
    if country.is_empty() {
        return (false, "");
    }
    if !g.allow_countries.is_empty() {
        if g.allows_country(&country) {
            return (false, "");
        }
        return (true, "Request blocked: geoblocking (country not allowed).");
    }
    if !g.block_countries.is_empty() && g.blocks_country(&country) {
        return (true, "Request blocked: geoblocking (country not allowed).");
    }
    (false, "")
}

fn message_for_categories(categories: &[String]) -> String {
    if categories.is_empty() {
        return "Request blocked by rules.".into();
    }
    format!("Request blocked: {}.", categories.join(", "))
}

const PARSED_BODY_BYTE_LIMIT: usize = 64 << 10;

/// The proxy's forwarded path, or both readings of the raw URI.
fn path_readings(req: &IncomingRequest) -> RequestPathReadings {
    if !req.forwarded_path.is_empty() {
        return readings_for_proxy_request(&req.forwarded_path);
    }
    readings_for_raw_target(&req.uri)
}

/// Script rules on each path reading, merged.
fn run_script_rules_on_paths(
    cfg: &AnalyzeConfig,
    ctx: &RequestRuleContext,
    rp: &RequestPathReadings,
) -> ScriptResult {
    let budget = cfg
        .script_budget
        .unwrap_or_else(wafio_engine_rules::script_budget_default);
    let run = |ctx: &RequestRuleContext| match cfg.script_runner.as_deref() {
        Some(runner) => runner.run_script_rules(ctx, budget),
        None => wafio_engine_rules::run_script_rules(&cfg.custom_script_rules, ctx, budget),
    };
    let sr = run(ctx);
    if rp.unresolved.is_empty() && !rp.no_exemption {
        return sr;
    }
    let alt = if rp.unresolved.is_empty() {
        ScriptResult::default()
    } else {
        run(&ctx.with_alternate_path(&rp.unresolved))
    };
    merge_script_results(rp, &sr, &alt)
}

/// After the first '?', up to a '#'; none when '#' comes first.
pub(crate) fn raw_query_of_uri(uri: &[u8]) -> &[u8] {
    let Some(q) = uri.iter().position(|&c| c == b'?') else {
        return b"";
    };
    match uri.iter().position(|&c| c == b'#') {
        Some(h) if h < q => b"",
        Some(h) => &uri[q + 1..h],
        None => &uri[q + 1..],
    }
}

fn path_extension(p: &[u8]) -> &[u8] {
    for i in (0..p.len()).rev() {
        if p[i] == b'/' {
            break;
        }
        if p[i] == b'.' {
            return &p[i..];
        }
    }
    b""
}

/// The custom/tuning/script rule context; path is the forwarded path.
fn rule_context_for_request(
    req: &IncomingRequest,
    fwd_path: &[u8],
    cfg: &AnalyzeConfig,
) -> RequestRuleContext {
    // A later equal-fold name overwrites an earlier one.
    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(req.headers.len());
    for (k, vs) in &req.headers {
        if let Some(v) = vs.first() {
            let k = to_lowercase(k);
            match headers.iter_mut().find(|(n, _)| *n == k) {
                Some(e) => e.1 = v.clone(),
                None => headers.push((k, v.clone())),
            }
        }
    }
    let header = |name: &[u8]| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let body_len = req.body.len();
    let body = req.body[..body_len.min(4096)].to_vec();
    let query = raw_query_of_uri(&req.uri);
    let uri = if query.is_empty() {
        fwd_path.to_vec()
    } else {
        cat(&[fwd_path, b"?", query])
    };
    let host = if req.host.is_empty() {
        header(b"host")
    } else {
        req.host.clone()
    };
    let mut country = Vec::new();
    if let Some(lookup) = &cfg.geo_lookup
        && let Ok(c) = lookup.country(&geo_client_ip(req))
    {
        country = c;
    }
    let body_size = (body_len as i64).max(req.body_size);
    let parsed = if body_len > 0 {
        Some(parse_body_for_rules(
            &req.content_type,
            &req.body[..body_len.min(PARSED_BODY_BYTE_LIMIT)],
        ))
    } else {
        None
    };
    let cookies = parse_cookie_pairs(&header(b"cookie")).unwrap_or_default();
    let ext = path_extension(fwd_path);
    RequestRuleContext {
        method: req.method.clone(),
        path: fwd_path.to_vec(),
        query: query.to_vec(),
        ip: geo_client_ip(req),
        country,
        ua: req.user_agent.clone(),
        headers,
        body,
        host,
        cookies,
        uri,
        path_extension: to_lowercase(ext.strip_prefix(b".").unwrap_or(ext)),
        body_size,
        body_truncated: body_len > 4096,
        parsed,
        regex_budget: Some(Arc::new(Mutex::new(RegexBudget::new(REQUEST_REGEX_BUDGET)))),
        ..Default::default()
    }
}

/// Name → value, best effort; later duplicates win.
fn parse_cookie_pairs(raw: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    if raw.is_empty() {
        return None;
    }
    let mut cookies: Option<Vec<(Vec<u8>, Vec<u8>)>> = None;
    for pair in raw.split(|&c| c == b';') {
        let Some(eq) = pair.iter().position(|&c| c == b'=') else {
            continue;
        };
        if eq == 0 {
            continue;
        }
        let name = trim_whitespace(&pair[..eq]);
        if name.is_empty() {
            continue;
        }
        let mut value = trim_whitespace(&pair[eq + 1..]);
        if value.len() >= 2 && value[0] == b'"' && value[value.len() - 1] == b'"' {
            value = &value[1..value.len() - 1];
        }
        let c = cookies.get_or_insert_with(Vec::new);
        match c.iter_mut().find(|(n, _)| n == name) {
            Some(e) => e.1 = value.to_vec(),
            None => c.push((name.to_vec(), value.to_vec())),
        }
    }
    cookies
}

/// "ip:port" → "ip" for a single colon; IPv6 unchanged.
pub(crate) fn strip_port(ip: &[u8]) -> Vec<u8> {
    if let Some(i) = ip.iter().rposition(|&c| c == b':')
        && ip.iter().position(|&c| c == b':') == Some(i)
    {
        return ip[..i].to_vec();
    }
    ip.to_vec()
}

/// CL+TE together, or disagreeing duplicate CLs.
fn smuggling_indicator(headers: &Headers) -> &'static str {
    let (mut cl, mut te): (&[Vec<u8>], &[Vec<u8>]) = (&[], &[]);
    for (name, vals) in headers {
        if lower_equals(name, b"content-length") {
            cl = vals;
        } else if lower_equals(name, b"transfer-encoding") {
            te = vals;
        }
    }
    if !cl.is_empty() && !te.is_empty() {
        return "smuggling_cl_te";
    }
    if cl.len() > 1 {
        let first = trim_whitespace(&cl[0]);
        if cl[1..].iter().any(|v| trim_whitespace(v) != first) {
            return "smuggling_duplicate_cl";
        }
    }
    ""
}

#[cfg(test)]
mod tests;
