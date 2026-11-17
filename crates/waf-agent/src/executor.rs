//! The base executor built at start and the per-app executors built from a bundle's rules_json
//! (`AnalyzeConfig`).

use std::sync::Arc;

use wafio_agent_io::ip_jail::JailTracker;
use wafio_agent_pages::challenge::ChallengeSettings;
use wafio_application::blocklist;
use wafio_application::deps::engine::bot_protection_from_rules;
use wafio_application::ratelimit;
use wafio_application::{
    AnalyzeConfig, DisabledGeoLookup, GeoLookup, cache_base_semantic_config, default_malware_engine,
};
use wafio_engine_api::{
    ParamBaseline, SsrfConfig, engine, parse_ssrf_blocklist_lines, read_ssrf_blocklist_file,
};
use wafio_engine_rules::LoadResult;
use wafio_engine_rules::bot_defaults::{
    default_bad_bot_ua_blocklist, default_ja3_blocklist, default_ja4_blocklist,
};
use wafio_proxy::AppAnalysisSetup;

/// The executor built at start: the base every bundle executor copies.
#[derive(Clone)]
pub struct BaseExecutor {
    pub config: AnalyzeConfig,
    /// None = challenge disabled.
    pub challenge: Option<ChallengeSettings>,
    /// Shared by every executor built from this one.
    pub jail: Option<Arc<JailTracker>>,
}

/// The concrete stores behind an executor (the cleaner and unblock commands need them).
#[derive(Clone)]
pub struct Stores {
    pub block: Arc<blocklist::MemoryStore>,
    pub rate: Arc<ratelimit::MemoryStore>,
    pub param_anomaly: Arc<dyn ParamBaseline>,
}

impl Stores {
    pub fn new() -> Stores {
        let cap = wafio_agent_io::store_limits::store_entry_cap() as usize;
        Stores {
            block: Arc::new(blocklist::MemoryStore::with_cap(cap)),
            rate: Arc::new(ratelimit::MemoryStore::with_cap(cap)),
            param_anomaly: engine().new_param_baseline(),
        }
    }
}

impl Default for Stores {
    fn default() -> Self {
        Stores::new()
    }
}

/// The agent-pages challenge config for a rules document whose `challenge` block the
/// engine-rules loader accepted (decoded, defaults applied and prepared).
fn challenge_of(rules_json: &[u8], load: &LoadResult) -> Option<ChallengeSettings> {
    load.challenge.as_ref()?;
    // The raw "challenge" member: exact key, last one wins.
    let doc = wafio_domain::json_text::parse(rules_json).ok()?;
    let wafio_domain::json_text::Value::Object(members) = &doc else {
        return None;
    };
    let block = members
        .iter()
        .rev()
        .find(|(k, _)| k.as_slice() == b"challenge")?;
    let raw = encode(&block.1);
    ChallengeSettings::from_rules_json(&raw)
}

/// Compact JSON of a parsed value (only re-read by JSON decoders, so whitespace and
/// escapes do not matter; member order and duplicates are kept).
fn encode(v: &wafio_domain::json_text::Value) -> Vec<u8> {
    use wafio_domain::json_text::{Value, encode_string};
    match v {
        Value::Null => b"null".to_vec(),
        Value::Bool(b) => {
            if *b {
                b"true".to_vec()
            } else {
                b"false".to_vec()
            }
        }
        Value::Number(n) => n.clone(),
        Value::String(s) => encode_string(s),
        Value::Array(items) => {
            let parts: Vec<Vec<u8>> = items.iter().map(encode).collect();
            [b"[".to_vec(), parts.join(&b","[..]), b"]".to_vec()].concat()
        }
        Value::Object(m) => {
            let parts: Vec<Vec<u8>> = m
                .iter()
                .map(|(k, v)| [encode_string(k), b":".to_vec(), encode(v)].concat())
                .collect();
            [b"{".to_vec(), parts.join(&b","[..]), b"}".to_vec()].concat()
        }
    }
}

/// The fields of `AnalyzeConfig` a rules document decides (shared by
/// the startup and the per-app executors).
fn apply_rules(cfg: &mut AnalyzeConfig, load: &LoadResult) {
    cfg.block_policy = load.block_policy.clone();
    cfg.request_body_limit = load.request_body_limit;
    cfg.geo = load.geo.clone();
    cfg.l7_flood = load.l7_flood.clone();
    cfg.bot_protection = load.bot_protection.as_ref().map(|b| {
        let mut b = b.clone();
        b.merge_default_lists(
            &default_bad_bot_ua_blocklist(),
            &default_ja4_blocklist(engine().bot_seeds().ja4_block),
            &default_ja3_blocklist(),
        );
        Arc::new(bot_protection_from_rules(&b))
    });
    cfg.semantic_policies = load.semantic_policies.clone();
    cfg.path_exceptions = load.path_exceptions.clone();
    cfg.inspection_off = load
        .semantic_policies
        .as_ref()
        .is_some_and(|sp| sp.is_inspection_off());
    cfg.content_scan = load.content_scan.clone();
}

/// Opens the MaxMind country database when one is configured and
/// it opens, else `DisabledGeoLookup` (country rules never match; the failure is logged).
fn open_geo_lookup(country_db: &str) -> Arc<dyn GeoLookup> {
    if !country_db.is_empty() {
        match wafio_geo::open_country_lookup(country_db) {
            Ok(l) => return l,
            Err(e) => tracing::info!("agent geo db open failed ({country_db}): {e}"),
        }
    }
    Arc::new(DisabledGeoLookup)
}

/// The startup executor of `wafio-waf-agent` (rules path never set → the builtin rules,
/// project "agent-local").
pub fn startup_executor(
    stores: &Stores,
    geo_country_db: &str,
    jail: Option<Arc<JailTracker>>,
) -> Result<BaseExecutor, String> {
    let rules = wafio_engine_rules::builtin_rules_json();
    let load = wafio_engine_rules::load_rules_json(rules).map_err(|e| e.to_string())?;
    let mut cfg = AnalyzeConfig {
        param_anomaly: Some(stores.param_anomaly.clone()),
        block_store: Some(stores.block.clone()),
        rate_limit_store: Some(stores.rate.clone()),
        geo_lookup: Some(open_geo_lookup(geo_country_db)),
        project_id: "agent-local".into(),
        // One engine shared by every app.
        malware_hash_engine: Some(default_malware_engine()),
        ..Default::default()
    };
    apply_rules(&mut cfg, &load);
    if let Some(spec) = &load.ssrf_blocklist {
        let bl = if !spec.ssrf_blocklist.is_empty() {
            Some(parse_ssrf_blocklist_lines(&spec.ssrf_blocklist))
        } else if !spec.ssrf_blocklist_path.is_empty() {
            read_ssrf_blocklist_file(std::path::Path::new(&spec.ssrf_blocklist_path)).ok()
        } else {
            None
        };
        cfg.ssrf_config = bl.map(|bl| {
            Arc::new(SsrfConfig {
                blocklist: Some(Arc::new(bl)),
            })
        });
    }
    cache_base_semantic_config(&mut cfg);
    Ok(BaseExecutor {
        config: cfg,
        challenge: challenge_of(rules, &load),
        jail,
    })
}

/// An executor for `rules_json` on top of the startup
/// executor `base` (shared GeoIP lookup), keeping the stores of `prior` (same app or the
/// shared executor of the previous bundle) so limits survive a bundle reload. Returns the
/// stores it uses so the caller can clean and unblock them.
pub fn executor_for_rules(
    base: &BaseExecutor,
    rules_json: &[u8],
    project_id: &str,
    prior: Option<&Stores>,
) -> Result<(AppAnalysisSetup, Stores), String> {
    match wafio_engine_rules::check_rules_json(rules_json) {
        Ok(ignored) => ignored.iter().for_each(|l| tracing::info!("{l}")),
        Err(_) => return Err("invalid WAF configuration".into()),
    }
    let load = wafio_engine_rules::load_rules_json(rules_json)
        .map_err(|e| format!("load per-app rules_json: {e}"))?;
    let mut cfg = base.config.clone();
    cfg.project_id = project_id.to_string();
    apply_rules(&mut cfg, &load);
    // Per-app rate-limit and block stores so limits aren't shared across apps.
    let stores = prior.cloned().unwrap_or_default();
    cfg.block_store = Some(stores.block.clone());
    cfg.rate_limit_store = Some(stores.rate.clone());
    cfg.param_anomaly = Some(stores.param_anomaly.clone());
    cfg.ssrf_config = None;
    if let Some(spec) = &load.ssrf_blocklist {
        let bl = if !spec.ssrf_blocklist.is_empty() {
            Some(parse_ssrf_blocklist_lines(&spec.ssrf_blocklist))
        } else if !spec.ssrf_blocklist_path.is_empty() {
            Some(
                read_ssrf_blocklist_file(std::path::Path::new(&spec.ssrf_blocklist_path))
                    .map_err(|_| "failed to load SSRF blocklist".to_string())?,
            )
        } else {
            None
        };
        cfg.ssrf_config = bl.map(|bl| {
            Arc::new(SsrfConfig {
                blocklist: Some(Arc::new(bl)),
            })
        });
    }
    cfg.custom_gui_rules.clear();
    cfg.custom_script_rules.clear();
    cfg.custom_tuning_rules.clear();
    cache_base_semantic_config(&mut cfg);
    // Per-app SIEM sender (when SIEM is enabled with a webhook URL, else none).
    let siem = load
        .siem
        .as_ref()
        .filter(|s| s.enabled)
        .and_then(|s| crate::siem::sender_from_options(&s.webhook_url));
    let exec = AppAnalysisSetup {
        analyze: cfg,
        challenge: challenge_of(rules_json, &load),
        jail: base.jail.clone(),
        siem,
    };
    Ok((exec, stores))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafio_domain::IncomingRequest;

    fn verdict(exec: &AppAnalysisSetup, ip: &str) -> String {
        let req = IncomingRequest {
            method: b"GET".to_vec(),
            uri: b"/".to_vec(),
            remote_address: ip.as_bytes().to_vec(),
            ..Default::default()
        };
        wafio_application::analyze(&req, &exec.analyze).action
    }

    /// The default document of this version gives the challenge settings of the one before it; the
    /// template version it stamps is the dashboard's and the agent does not read it.
    #[test]
    fn the_default_document_gives_the_challenge_settings_of_version_1() {
        let v1 = include_str!("../../engine-rules/tests/data/v1_default_rules.json");
        let settings = |doc: &[u8]| {
            let load = wafio_engine_rules::load_rules_json(doc).unwrap();
            let mut c = challenge_of(doc, &load).expect("the default has a challenge block");
            let version = std::mem::take(&mut c.template_version);
            (format!("{c:?}"), version)
        };
        let (old, old_version) = settings(v1.as_bytes());
        let (new, new_version) = settings(wafio_engine_rules::builtin_rules_json());
        assert_eq!((old_version, new_version), (0, 3));
        assert_eq!(old, new);
    }

    /// No database → `DisabledGeoLookup` (country rules never match); an
    /// unreadable one → the same, with a log line.
    #[test]
    fn missing_country_database_means_no_country_rules() {
        let rules = br#"{"geo":{"block_countries":["US"]}}"#;
        for db in ["", "/nonexistent/country.mmdb"] {
            let base = startup_executor(&Stores::new(), db, None).unwrap();
            let (exec, _) = executor_for_rules(&base, rules, "p", None).unwrap();
            assert_eq!(verdict(&exec, "8.8.8.8"), "allow", "db {db:?}");
        }
    }

    /// Security review ("malware engine not wired"): the executors this binary builds hold the
    /// default malware engine, so a known-malware upload (the builtin EICAR signature) is
    /// blocked when content scanning is on.
    #[test]
    fn known_malware_upload_is_blocked_through_the_built_executor() {
        let base = startup_executor(&Stores::new(), "", None).unwrap();
        let rules = br#"{"content_scan":{"enabled":true,"mode":"block","scan_multipart":true}}"#;
        let (exec, _) = executor_for_rules(&base, rules, "p", None).unwrap();
        let eicar = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let upload = |content: &[u8]| {
            let mut body = b"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.com\"\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
            body.extend_from_slice(content);
            body.extend_from_slice(b"\r\n--B--\r\n");
            let req = IncomingRequest {
                method: b"POST".to_vec(),
                uri: b"/upload".to_vec(),
                remote_address: b"9.9.9.9".to_vec(),
                content_type: b"multipart/form-data; boundary=B".to_vec(),
                body_size: body.len() as i64,
                body,
                ..Default::default()
            };
            wafio_application::analyze(&req, &exec.analyze)
        };
        let bad = upload(eicar);
        assert_eq!(bad.action, "block", "{bad:?}");
        assert_eq!(upload(b"just a text file").action, "allow");
    }

    /// Script rules run in the agent: a compiled rule that blocks blocks the request, and one that fails
    /// at run time leaves an unfinished-rule LOG that is counted, never a silent allow.
    #[test]
    fn script_rules_run_in_the_agent() {
        let base = startup_executor(&Stores::new(), "", None).unwrap();
        let (mut exec, _) = executor_for_rules(&base, b"{}", "p", None).unwrap();
        let rule = |id: &str, script: &str| wafio_engine_rules::CustomScriptRule {
            id: id.into(),
            enabled: true,
            script: script.into(),
            ..Default::default()
        };
        let req = IncomingRequest {
            method: b"GET".to_vec(),
            uri: b"/".to_vec(),
            remote_address: b"9.9.9.9".to_vec(),
            ..Default::default()
        };
        let mut run = |script: &str| {
            let (rules, runner) = crate::script_rules::compile("a", vec![rule("s1", script)]);
            exec.analyze.custom_script_rules = rules;
            exec.analyze.script_runner = Some(runner);
            wafio_application::analyze(&req, &exec.analyze)
        };
        let v = run("waf_block(\"x\")");
        assert_eq!(v.action, "block", "{v:?}");
        let before = crate::script_rules::incomplete_total();
        let v = run("x = 1 / 0");
        assert_eq!(v.action, "log", "{v:?}");
        assert_eq!(v.message, b"custom_script_rule_incomplete:s1");
        assert!(crate::script_rules::incomplete_total() > before);
    }

    /// Country geoblocking against the real database (`WAFIO_TEST_GEO_COUNTRY_DB`, skipped
    /// without it): 8.8.8.8 is US, 1.1.1.1 is not.
    #[test]
    fn country_rules_use_the_maxmind_database() {
        let Ok(db) = std::env::var("WAFIO_TEST_GEO_COUNTRY_DB") else {
            return;
        };
        let base = startup_executor(&Stores::new(), &db, None).unwrap();
        let (block, _) =
            executor_for_rules(&base, br#"{"geo":{"block_countries":["US"]}}"#, "p", None).unwrap();
        assert_eq!(verdict(&block, "8.8.8.8"), "block");
        assert_eq!(verdict(&block, "1.1.1.1"), "allow");
        let (allow, _) =
            executor_for_rules(&base, br#"{"geo":{"allow_countries":["US"]}}"#, "p", None).unwrap();
        assert_eq!(verdict(&allow, "8.8.8.8"), "allow");
        assert_eq!(verdict(&allow, "1.1.1.1"), "block");
    }
}
