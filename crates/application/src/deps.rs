//! Every item this crate calls in other crates, in one place.
//! Items no crate has published yet are private copies.

pub mod engine {
    //! The engine boundary (crate engine-api) and the rules (crate engine-rules).

    pub use crate::semantic_config::{apply_path_semantic_override, apply_policy_overrides};
    pub use wafio_engine_api::{
        AttackClassification, REASON_SEMANTIC_ANOMALY, REASON_SEMANTIC_CMD, REASON_SEMANTIC_DESER,
        REASON_SEMANTIC_GRAPHQL, REASON_SEMANTIC_HEADER_INJECTION, REASON_SEMANTIC_JAVA,
        REASON_SEMANTIC_JWT, REASON_SEMANTIC_LDAP, REASON_SEMANTIC_LFI, REASON_SEMANTIC_NOSQL,
        REASON_SEMANTIC_OPEN_REDIRECT, REASON_SEMANTIC_PHP, REASON_SEMANTIC_PROMPT_INJECTION,
        REASON_SEMANTIC_PROTO_POLLUTION, REASON_SEMANTIC_PYTHON, REASON_SEMANTIC_SQL,
        REASON_SEMANTIC_SSRF, REASON_SEMANTIC_SSTI, REASON_SEMANTIC_XSS, REASON_SEMANTIC_XXE,
        ScanCoverage, SemanticConfig, SemanticScanResult, SsrfBlocklist, SsrfConfig, Tier,
        classify_semantic_reason, decision_score, disabled_key_from_reason,
        parse_ssrf_blocklist_lines, siem_reason_and_detail,
    };
    pub use wafio_engine_rules::bot::{
        BotProtectionConfig, BotRequest, BotResult, classify_bot, compile_bot_protection,
    };
    pub use wafio_engine_rules::ip_network;
    pub use wafio_engine_rules::{
        BlockPolicyConfig, COVERAGE_FLAG_REGEX_BUDGET, COVERAGE_FLAG_SCRIPT_TIMEOUT,
        ContentScanConfig, CustomGuiRule, CustomScriptRule, DEFAULT_BOT_SCORE_THRESHOLD,
        ENGINE_ACTION_BLOCK, ENGINE_ACTION_LOG, FormKeyMatcher, GeoConfig, GuiRuleOutcome,
        L7FloodConfig, LoadResult, PathExceptionConfig, PathLimits, REQUEST_REGEX_BUDGET,
        RegexBudget, RequestPathReadings, RequestRuleContext, ScriptBudget, ScriptResult,
        SemanticPoliciesConfig, TuningPlan, TuningRule, UNINSPECTED_POLICY_BLOCK,
        UNINSPECTED_POLICY_LOG, allows_method, builtin_rules_json, compute_tuning_plan_on_paths,
        evaluate_gui_rules_on_paths, find_path_rules_for_request, load_rules_json, login_scope_key,
        merge_effect_into_plan, merge_script_results, parse_body_for_rules,
        readings_for_proxy_request, readings_for_raw_target, unescape_form_leniently,
    };

    /// The bot protection config the rules JSON parser builds
    /// turned into the prepared detector config.
    pub fn bot_protection_from_rules(
        c: &wafio_engine_rules::BotProtectionConfig,
    ) -> BotProtectionConfig {
        // Private compiled fields: fill the public ones on a default value.
        let mut b = BotProtectionConfig::default();
        b.enabled = c.enabled;
        b.mode = c.mode.clone();
        b.base_score = c.base_score;
        b.score_threshold = c.score_threshold;
        b.empty_ua_block = c.empty_ua_block;
        b.ua_blocklist = c.ua_blocklist.clone();
        b.ua_allowlist = c.ua_allowlist.clone();
        b.ja4_blocklist = c.ja4_blocklist.clone();
        b.ja4_allowlist = c.ja4_allowlist.clone();
        b.ja3_blocklist = c.ja3_blocklist.clone();
        b.ja3_allowlist = c.ja3_allowlist.clone();
        b.header_checks = c.header_checks;
        b.client_hints_check = c.client_hints_check;
        b.browser_impersonation_check = c.browser_impersonation_check;
        b.block_ai_crawlers = c.block_ai_crawlers;
        compile_bot_protection(&mut b);
        b
    }

    // The upload scan (engine-rules has not published it) and the malware database
    pub use crate::content_scan::{
        FileScanResult, HashMatcher, SnapshotStatus, Timestamp, default_malware_engine,
        render_scan_results, scan_uploaded_files,
    };
}

pub mod bodyinspect {
    //! Body preparation (crate bodyinspect).
    pub use wafio_bodyinspect::{attach_notes, prepare_body_for_engines};
}
