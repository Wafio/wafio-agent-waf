//! Test and example support: an [`AppAnalysisSetup`] from a rules JSON, wired like the conformance
//! runner (in-memory stores). The binary owns the full setup (stores carried over, custom rules,
//! SSRF blocklist files, SIEM, malware engine).

use std::sync::Arc;

use wafio_agent_pages::challenge::{ChallengeSettings, finalize_challenge_settings};
use wafio_application::deps::engine::{bot_protection_from_rules, load_rules_json};
use wafio_application::{
    AnalyzeConfig, DisabledGeoLookup, blocklist, cache_base_semantic_config, ratelimit,
};
use wafio_domain::json_text::{Value, parse};

use crate::config::AppAnalysisSetup;

#[doc(hidden)]
pub fn analysis_setup(rules_json: &[u8]) -> AppAnalysisSetup {
    let res = load_rules_json(rules_json).unwrap_or_else(|e| panic!("rules_json: {e:?}"));
    let mut cfg = AnalyzeConfig {
        block_store: Some(Arc::new(blocklist::MemoryStore::new())),
        rate_limit_store: Some(Arc::new(ratelimit::MemoryStore::new())),
        block_policy: res.block_policy.clone(),
        request_body_limit: res.request_body_limit,
        geo: res.geo.clone(),
        geo_lookup: Some(Arc::new(DisabledGeoLookup)),
        l7_flood: res.l7_flood.clone(),
        bot_protection: res
            .bot_protection
            .as_ref()
            .map(|b| Arc::new(bot_protection_from_rules(b))),
        project_id: "test-project".into(),
        semantic_policies: res.semantic_policies.clone(),
        path_exceptions: res.path_exceptions.clone(),
        content_scan: res.content_scan.clone(),
        ..Default::default()
    };
    cfg.inspection_off = res
        .semantic_policies
        .as_ref()
        .is_some_and(|sp| sp.is_inspection_off());
    cache_base_semantic_config(&mut cfg);
    let challenge = match parse(rules_json) {
        Ok(Value::Object(fields)) => fields
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(b"challenge"))
            .and_then(|(_, v)| {
                let mut c = ChallengeSettings::from_json_value(v).ok()?;
                c.apply_defaults();
                finalize_challenge_settings(&mut c);
                Some(c)
            }),
        _ => None,
    };
    AppAnalysisSetup {
        analyze: cfg,
        challenge,
        jail: None,
        siem: None,
    }
}
