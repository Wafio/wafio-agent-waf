//! The default document of version 1 (scores, thresholds and categories) and the current one give the engines the
//! same configuration.

use wafio_application::deps::engine::{SemanticConfig, apply_policy_overrides, load_rules_json};
use wafio_engine_rules::builtin_rules_json;

const V1_DEFAULT: &str = include_str!("../../engine-rules/tests/data/v1_default_rules.json");

fn semantic(doc: &[u8]) -> SemanticConfig {
    let res = load_rules_json(doc).unwrap();
    let mut sc = SemanticConfig::default();
    apply_policy_overrides(&mut sc, res.semantic_policies.as_ref());
    sc
}

#[test]
fn the_v1_default_gives_the_engines_the_same_configuration_as_the_new_default() {
    let (old, new) = (
        semantic(V1_DEFAULT.as_bytes()),
        semantic(builtin_rules_json()),
    );
    assert_eq!(format!("{old:?}"), format!("{new:?}"));
    assert!(old.sql_semantic_policy.is_some() && old.deser_semantic_policy.is_some());
    assert!(old.disabled_engines.is_none() && old.log_only_engines.is_none());
}
