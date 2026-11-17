//! The `action` key of an engine policy, in the project policies and in a path override.

use wafio_engine_rules::*;

fn action(p: &Option<SemanticPolicyJson>) -> Option<&str> {
    p.as_ref().map(|p| p.action.as_str())
}

#[test]
fn the_action_reads_in_the_project_policies_and_in_a_path_override() {
    let doc = r#"{"semantic_policies":{"sql":{"action":"log"},"xss":{"action":"block"},"jwt":{"action":"log","disabled":true},"anomaly":{}},
        "path_exceptions":[{"path":"/p","semantic_override":{"sql":{"action":"block"},"graphql":{"action":"log"},"ldap":{"base_score":0}}}]}"#;
    assert_eq!(
        check_rules_json(doc.as_bytes()).unwrap(),
        Vec::<String>::new()
    );
    let load = load_rules_json(doc.as_bytes()).unwrap();
    let sp = load.semantic_policies.unwrap();
    assert_eq!(action(&sp.sql), Some(ENGINE_ACTION_LOG));
    assert_eq!(action(&sp.xss), Some(ENGINE_ACTION_BLOCK));
    assert_eq!(action(&sp.jwt), Some(ENGINE_ACTION_LOG));
    assert!(sp.jwt.as_ref().unwrap().disabled);
    // No key, no action: the engine inherits, and the default is block.
    assert_eq!(action(&sp.anomaly), Some(""));
    assert_eq!(action(&sp.php), None);
    let ov = load.path_exceptions[0].semantic_override.as_ref().unwrap();
    assert_eq!(action(&ov.sql), Some(ENGINE_ACTION_BLOCK));
    assert_eq!(action(&ov.graphql), Some(ENGINE_ACTION_LOG));
    assert_eq!(action(&ov.ldap), Some(""));
}

#[test]
fn a_value_that_is_neither_block_nor_log_is_dropped_and_named() {
    let doc = r#"{"semantic_policies":{"sql":{"action":"warn"},"xss":{"action":"Log"}},
        "path_exceptions":[{"path":"/p","semantic_override":{"anomaly":{"action":"x"},"sql":{"action":"log"}}}]}"#;
    let lines = check_rules_json(doc.as_bytes()).unwrap();
    assert_eq!(lines.len(), 3, "{lines:?}");
    for key in [
        "semantic_policies.sql.action",
        "semantic_policies.xss.action",
        "path_exceptions[0].semantic_override.anomaly.action",
    ] {
        assert!(lines.iter().any(|l| l.contains(key)), "{key} in {lines:?}");
    }
    let load = load_rules_json(doc.as_bytes()).unwrap();
    let sp = load.semantic_policies.unwrap();
    assert_eq!(action(&sp.sql), Some(""));
    assert_eq!(action(&sp.xss), Some(""));
    let ov = load.path_exceptions[0].semantic_override.as_ref().unwrap();
    assert_eq!(action(&ov.anomaly), Some(""));
    assert_eq!(action(&ov.sql), Some(ENGINE_ACTION_LOG));
}

#[test]
fn no_default_document_names_an_action() {
    let sp = load_rules_json(builtin_rules_json())
        .unwrap()
        .semantic_policies
        .unwrap();
    for (key, p) in sp.engine_policies() {
        assert!(p.is_none_or(|p| p.action.is_empty()), "{key}");
    }
}
