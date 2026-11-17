//! Stand-ins for functions other crates have not published yet. Each names the function it
//! stands for; replace the body with a call once it lands.

/// Heartbeat field 20 / `wafio_waf_regex_rules_dropped`.
pub fn regex_rules_dropped_total() -> u64 {
    wafio_engine_rules::dropped_regex_rule_count()
}

/// Reported in `Hello.features` when no semantic engine is installed: nothing inspects a request for attacks.
pub const FEATURE_NO_SEMANTIC_ENGINE: &str = "no_semantic_engine";
