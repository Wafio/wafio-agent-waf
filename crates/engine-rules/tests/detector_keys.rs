//! The keys of `header_injection`, `open_redirect`, `prompt_injection` and `anomaly` in a rules document,
//! and what the agent does with a key it does not know: a control plane newer than the agent may send one.

use wafio_engine_rules::*;

const NEW_KEYS: [&str; 4] = [
    "header_injection",
    "open_redirect",
    "prompt_injection",
    "anomaly",
];

fn disabled(p: &Option<SemanticPolicyJson>) -> Option<bool> {
    p.as_ref().map(|p| p.disabled)
}

#[test]
fn the_four_keys_read_in_the_project_policies() {
    let doc = r#"{"semantic_policies":{
        "header_injection":{"disabled":true},"open_redirect":{"disabled":true},
        "prompt_injection":{"disabled":false},"anomaly":{"disabled":true}}}"#;
    assert_eq!(
        check_rules_json(doc.as_bytes()).unwrap(),
        Vec::<String>::new()
    );
    let sp = load_rules_json(doc.as_bytes())
        .unwrap()
        .semantic_policies
        .unwrap();
    assert_eq!(disabled(&sp.header_injection), Some(true));
    assert_eq!(disabled(&sp.open_redirect), Some(true));
    assert_eq!(disabled(&sp.prompt_injection), Some(false));
    assert_eq!(disabled(&sp.anomaly), Some(true));
    assert_eq!(sp.engine_policies().len(), 20);
    let keys: Vec<_> = sp.engine_policies().iter().map(|(k, _)| *k).collect();
    for k in NEW_KEYS {
        assert!(keys.contains(&k), "{k}");
        assert!(SEMANTIC_ENGINE_KEY_NAMES.contains(&k), "{k}");
        assert!(PATH_SEMANTIC_OVERRIDE_KEYS.contains(&k), "{k}");
    }
}

#[test]
fn a_document_without_the_keys_leaves_them_unset() {
    let sp = load_rules_json(br#"{"semantic_policies":{"sql":{"disabled":true}}}"#)
        .unwrap()
        .semantic_policies
        .unwrap();
    for (key, p) in sp.engine_policies() {
        assert_eq!(p.is_some_and(|p| p.disabled), key == "sql", "{key}");
    }
    let builtin = load_rules_json(builtin_rules_json()).unwrap();
    for (key, p) in builtin.semantic_policies.unwrap().engine_policies() {
        assert!(!p.is_some_and(|p| p.disabled), "{key}");
    }
}

#[test]
fn the_four_keys_read_in_a_path_override() {
    let doc = r#"{"path_exceptions":[{"path":"/p","semantic_override":{
        "header_injection":{"disabled":true},"open_redirect":{"disabled":true},
        "prompt_injection":{"disabled":true},"anomaly":{"disabled":false}}}]}"#;
    assert_eq!(
        check_rules_json(doc.as_bytes()).unwrap(),
        Vec::<String>::new()
    );
    let load = load_rules_json(doc.as_bytes()).unwrap();
    let ov = load.path_exceptions[0].semantic_override.as_ref().unwrap();
    assert_eq!(disabled(&ov.header_injection), Some(true));
    assert_eq!(disabled(&ov.open_redirect), Some(true));
    assert_eq!(disabled(&ov.prompt_injection), Some(true));
    assert_eq!(disabled(&ov.anomaly), Some(false));
    assert!(ov.unknown_keys.is_empty());
}

#[test]
fn the_four_keys_pass_as_skip_semantic_entries() {
    let doc = r#"{"path_exceptions":[{"path":"/p","tuning":{"effect":{"skip_semantic":
        ["header_injection","open_redirect","Prompt_Injection","anomaly","*"]}}}]}"#;
    assert_eq!(
        check_rules_json(doc.as_bytes()).unwrap(),
        Vec::<String>::new()
    );
    assert!(load_rules_json(doc.as_bytes()).unwrap().ignored.is_empty());
}

#[test]
fn a_key_no_detector_has_does_not_refuse_the_document() {
    // In the project policies.
    let doc =
        br#"{"semantic_policies":{"future_detector":{"disabled":true},"sql":{"disabled":true}}}"#;
    assert_eq!(check_rules_json(doc).unwrap(), Vec::<String>::new());
    assert!(
        load_rules_json(doc)
            .unwrap()
            .semantic_policies
            .unwrap()
            .sql
            .unwrap()
            .disabled
    );

    // In a path override: ignored, and named in the log lines the load prints.
    let doc = br#"{"path_exceptions":[{"path":"/p","semantic_override":{"future_detector":{"disabled":true},"anomaly":{"disabled":true}}}]}"#;
    let lines = check_rules_json(doc).unwrap();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("future_detector"), "{lines:?}");
    assert!(
        lines[0].contains("path_exceptions[0].semantic_override"),
        "{lines:?}"
    );
    let load = load_rules_json(doc).unwrap();
    let ov = load.path_exceptions[0].semantic_override.as_ref().unwrap();
    assert_eq!(ov.unknown_keys, vec!["future_detector".to_string()]);
    assert_eq!(disabled(&ov.anomaly), Some(true));

    // In the skip_semantic of a path's tuning: the known names stay.
    let doc = br#"{"path_exceptions":[{"path":"/p","tuning":{"effect":{"skip_semantic":["sqli","header_injection"]}}}]}"#;
    let lines = check_rules_json(doc).unwrap();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("sqli"), "{lines:?}");
    let load = load_rules_json(doc).unwrap();
    let tuning = load.path_exceptions[0].tuning.as_ref().unwrap();
    assert_eq!(
        tuning.effect.skip_semantic,
        vec!["sqli", "header_injection"]
    );
}

#[test]
fn a_known_key_in_the_wrong_case_still_refuses_the_document() {
    let doc = br#"{"path_exceptions":[{"path":"/a","semantic_override":{"SQL":{}}}]}"#;
    assert!(load_rules_json(doc).is_err());
    assert!(check_rules_json(doc).is_err());
    let doc = br#"{"path_exceptions":[{"path":"/a","semantic_override":{"Anomaly":{}}}]}"#;
    assert!(load_rules_json(doc).is_err());
}

#[test]
fn the_save_check_of_a_tuning_rule_names_the_four_keys() {
    let effect = |name: &str| TuningEffect {
        skip_semantic: vec![name.into()],
        ..Default::default()
    };
    let target = TuningTarget::default();
    for k in NEW_KEYS {
        assert!(
            check_tuning_effect(&effect(k), &target, true).is_ok(),
            "{k}"
        );
    }
    let err = check_tuning_effect(&effect("sqli"), &target, true).unwrap_err();
    assert!(
        err.contains("header_injection") && err.contains("anomaly"),
        "{err}"
    );
}
