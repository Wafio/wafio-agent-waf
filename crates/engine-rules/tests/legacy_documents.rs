//! Rules documents of earlier versions: every key that was renamed or retired still loads, and
//! means what the new reading says. The stored documents of customers run through this.

use wafio_engine_rules::*;

const V1_DEFAULT: &str = include_str!("data/v1_default_rules.json");

fn load(doc: &str) -> LoadResult {
    load_rules_json(doc.as_bytes()).unwrap_or_else(|e| panic!("{doc}: {e:?}"))
}

fn project_off(doc: &str) -> bool {
    load(doc)
        .semantic_policies
        .is_some_and(|sp| sp.is_inspection_off())
}

#[test]
fn the_old_switch_pair_and_disable_semantic_alone_switch_inspection_off() {
    assert!(project_off(
        r#"{"semantic_policies":{"disable_semantic":true,"disable_rule_based":true}}"#
    ));
    assert!(project_off(
        r#"{"semantic_policies":{"disable_semantic":true}}"#
    ));
    assert!(project_off(
        r#"{"semantic_policies":{"inspection_off":true}}"#
    ));
    assert!(project_off(
        r#"{"semantic_policies":{"inspection_off":true,"disable_semantic":false}}"#
    ));
}

#[test]
fn disable_rule_based_alone_means_nothing() {
    assert!(!project_off(
        r#"{"semantic_policies":{"disable_rule_based":true}}"#
    ));
    assert!(!project_off(
        r#"{"semantic_policies":{"inspection_off":false,"disable_semantic":false,"disable_rule_based":true}}"#
    ));
    let doc = r#"{"path_exceptions":[{"path":"/p","disable_rule_based":true}]}"#;
    let exc = &load(doc).path_exceptions[0];
    assert!(!exc.is_inspection_off() && !exc.exempts());
    assert_eq!(check_rules_json(doc.as_bytes()).unwrap().len(), 0);
}

#[test]
fn the_path_exception_reads_both_spellings() {
    for exc in [
        r#"{"path":"/p","inspection_off":true}"#,
        r#"{"path":"/p","disable_semantic":true}"#,
        r#"{"path":"/p","disable_semantic":true,"disable_rule_based":true}"#,
    ] {
        let doc = format!(r#"{{"path_exceptions":[{exc}]}}"#);
        let exc = &load(&doc).path_exceptions[0];
        assert!(exc.is_inspection_off() && exc.exempts(), "{doc}");
    }
}

#[test]
fn skip_coraza_when_clean_is_ignored_whatever_its_value() {
    let without = load(r#"{"semantic_policies":{"sql":{"disabled":true}}}"#);
    for v in ["true", "false"] {
        let with = load(&format!(
            r#"{{"semantic_policies":{{"skip_coraza_when_clean":{v},"sql":{{"disabled":true}}}}}}"#
        ));
        assert_eq!(with, without, "skip_coraza_when_clean {v}");
    }
}

#[test]
fn the_retired_category_entries_are_accepted_and_ignored() {
    let doc = r#"{"categories":{"RFI":{"base_score":180,"confidence":0.85,"sensitivity":1},
        "Method":{"base_score":60},"Generic":{"sensitivity":2},"Scanner":{"disabled":true},
        "Protocol":{"base_score":5000},"Multipart":{"base_score":120},
        "SessionFixation":{"base_score":140,"sensitivity":2},"SQLi":{"base_score":250,"sensitivity":9}}}"#;
    assert_eq!(check_rules_json(doc.as_bytes()).unwrap().len(), 0);
    assert_eq!(load(doc), load("{}"));
}

#[test]
fn the_v1_default_document_reads_as_the_new_default() {
    let mut old = load(V1_DEFAULT);
    let mut new = load(std::str::from_utf8(builtin_rules_json()).unwrap());
    // The scores, thresholds and categories of the old document mean nothing now: every engine is on and
    // weak detections are recorded, as in the new default.
    let sp = old.semantic_policies.take().unwrap();
    assert_eq!(sp.record_weak_detections, None);
    assert!(
        sp.engine_policies()
            .iter()
            .all(|(_, p)| p.is_none_or(|p| !p.disabled))
    );
    new.semantic_policies = None;
    // The new default stamps the template version the dashboard writes; nothing in the agent reads it.
    assert_eq!(old.challenge.as_ref().unwrap().template_version, 0);
    assert_eq!(new.challenge.as_ref().unwrap().template_version, 3);
    new.challenge.as_mut().unwrap().template_version = 0;
    assert_eq!(old, new);
    assert_eq!(check_rules_json(V1_DEFAULT.as_bytes()).unwrap().len(), 0);
    assert_eq!(check_rules_json(builtin_rules_json()).unwrap().len(), 0);
}

#[test]
fn the_body_buffer_limits_of_the_old_engine_are_ignored() {
    let doc = r#"{"request_body_limit":"5M","request_body_in_memory_limit":"1M","response_body_limit":"bogus"}"#;
    assert_eq!(check_rules_json(doc.as_bytes()).unwrap().len(), 0);
    assert_eq!(load(doc), load(r#"{"request_body_limit":"5M"}"#));
}

fn rule(engine: &str, effect: TuningEffect) -> TuningRule {
    TuningRule {
        id: "t".into(),
        enabled: true,
        engine: engine.into(),
        effect,
        ..Default::default()
    }
}

fn plan(engine: &str, effect: TuningEffect) -> TuningPlan {
    compute_tuning_plan(&[rule(engine, effect)], &RequestRuleContext::default()).unwrap()
}

fn scan_mode(mode: &str) -> TuningEffect {
    TuningEffect {
        scan_mode: mode.into(),
        ..Default::default()
    }
}

#[test]
fn scan_modes_of_the_retired_engines_read_as_default() {
    for mode in ["crs_only", "semantic_only", "default", "CRS_ONLY"] {
        let p = plan("", scan_mode(mode));
        assert_eq!(p.scan_mode, "default", "{mode}");
        assert!(!p.skip_semantic_all, "{mode}");
        assert!(
            check_tuning_rule(&rule("", scan_mode(mode))).is_ok(),
            "{mode}"
        );
    }
    let p = plan("", scan_mode("disabled"));
    assert_eq!(
        (p.scan_mode.as_str(), p.skip_semantic_all),
        ("disabled", true)
    );
    assert!(!plan("", scan_mode("both")).skip_semantic_all);
    let err = check_tuning_rule(&rule("", scan_mode("fast"))).unwrap_err();
    assert!(err.contains("default|both|disabled"), "{err}");
}

#[test]
fn a_rule_of_the_retired_engine_and_skip_crs_change_nothing() {
    let skip_sql = TuningEffect {
        skip_semantic: vec!["sql".into()],
        weaken: Some(TuningWeaken {
            score_multiplier: 0.5,
            ..Default::default()
        }),
        ..Default::default()
    };
    // Scoped to `crs`: no semantic skip, no log hold. Scoped to `semantic` or `both`: as before.
    let p = plan("crs", skip_sql.clone());
    assert!(p.skip_semantic_engines.is_empty() && !p.log_only);
    assert!(check_tuning_rule(&rule("crs", skip_sql.clone())).is_ok());
    for engine in ["", "semantic", "both"] {
        let p = plan(engine, skip_sql.clone());
        assert!(p.skip_semantic_engines.contains("sql"), "{engine}");
        assert!(p.log_only, "{engine}");
    }
    // `skip_crs` in a stored path tuning is not read, and no entry of it is validated.
    let doc = r#"{"path_exceptions":[{"path":"/p","tuning":{"effect":{"skip_crs":["*","not an entry"],"skip_semantic":["sql"]}}}]}"#;
    assert_eq!(check_rules_json(doc.as_bytes()).unwrap().len(), 0);
    let loaded = load(doc);
    let effect = &loaded.path_exceptions[0].tuning.as_ref().unwrap().effect;
    assert_eq!(effect.skip_semantic, vec!["sql"]);
}

#[test]
fn a_path_rule_override_is_ignored_and_does_not_exempt_the_path() {
    let doc = r#"{"path_exceptions":[{"path":"/p","rate_limit":{"max_requests":5,"window_sec":60},
        "rule_override":{"block_threshold":"x","log_threshold":90,"categories":{"SQLi":{"base_score":10}}}}]}"#;
    assert_eq!(check_rules_json(doc.as_bytes()).unwrap().len(), 0);
    let exc = &load(doc).path_exceptions[0];
    assert!(!exc.exempts() && exc.limits_access());
}
