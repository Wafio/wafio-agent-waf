//! Rules documents that still carry scores, thresholds and categories: they load, and the keys that said
//! something about detection read as the contract says. Nothing here is an error.

use wafio_engine_rules::*;

fn load(doc: &str) -> LoadResult {
    load_rules_json(doc.as_bytes()).unwrap_or_else(|e| panic!("{doc}: {e:?}"))
}

fn records_weak(doc: &str) -> Option<bool> {
    load(doc)
        .semantic_policies
        .and_then(|sp| sp.record_weak_detections)
}

fn disabled(doc: &str) -> Vec<&'static str> {
    load(doc)
        .semantic_policies
        .map(|sp| {
            sp.engine_policies()
                .into_iter()
                .filter(|(_, p)| p.is_some_and(|p| p.disabled))
                .map(|(k, _)| k)
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_log_threshold_that_is_not_below_the_block_threshold_means_weak_detections_are_not_recorded() {
    for doc in [
        r#"{"thresholds":{"log":150,"block":150}}"#,
        r#"{"thresholds":{"log":200,"block":150}}"#,
        r#"{"thresholds":{"block":50}}"#,
        r#"{"thresholds":{"log":90,"block":90},"semantic_policies":{"sql":{"disabled":true}}}"#,
    ] {
        assert_eq!(records_weak(doc), Some(false), "{doc}");
    }
    for doc in [
        r#"{}"#,
        r#"{"thresholds":{"log":80,"block":150}}"#,
        r#"{"thresholds":{"log":149,"block":150}}"#,
        r#"{"thresholds":{"block":100}}"#,
        r#"{"thresholds":{"log":0,"block":0}}"#,
        r#"{"thresholds":{"log":"x"}}"#,
        r#"{"thresholds":null}"#,
    ] {
        assert_eq!(records_weak(doc), None, "{doc}");
    }
}

#[test]
fn record_weak_detections_decides_over_the_thresholds() {
    assert_eq!(
        records_weak(r#"{"semantic_policies":{"record_weak_detections":false}}"#),
        Some(false)
    );
    assert_eq!(
        records_weak(r#"{"semantic_policies":{"record_weak_detections":true}}"#),
        Some(true)
    );
    assert_eq!(
        records_weak(
            r#"{"thresholds":{"log":150,"block":150},"semantic_policies":{"record_weak_detections":true}}"#
        ),
        Some(true)
    );
    assert_eq!(
        records_weak(
            r#"{"thresholds":{"log":10,"block":150},"semantic_policies":{"record_weak_detections":false}}"#
        ),
        Some(false)
    );
}

#[test]
fn an_engine_base_score_of_zero_reads_as_disabled_and_any_other_value_means_nothing() {
    let doc = r#"{"semantic_policies":{"ldap":{"base_score":0},"proto_pollution":{"base_score":185},
        "nosql":{"block_threshold":3.0,"base_score":0},"sql":{"base_score":9999},"jwt":{"base_score":0},
        "graphql":{"base_score":-5},"xss":{"base_score":99999},"header_injection":{"base_score":0},
        "open_redirect":{"base_score":0},"prompt_injection":{"base_score":0},"anomaly":{"base_score":0}}}"#;
    assert_eq!(check_rules_json(doc.as_bytes()).unwrap().len(), 0);
    assert_eq!(disabled(doc), vec!["nosql", "ldap", "jwt"]);
    let sp = load(doc).semantic_policies.unwrap();
    assert_eq!(sp.nosql.unwrap().block_threshold, 3.0);
}

#[test]
fn a_path_override_base_score_of_zero_switches_the_engine_off_for_the_path() {
    let doc = r#"{"path_exceptions":[{"path":"/p","semantic_override":{"ldap":{"base_score":0},
        "sql":{"base_score":10},"xss":{"disabled":false,"base_score":0},"anomaly":{"base_score":0}}}]}"#;
    let load = load(doc);
    let ov = load.path_exceptions[0].semantic_override.as_ref().unwrap();
    let off = |k: &str| {
        ov.policies()
            .into_iter()
            .find(|(n, _)| *n == k)
            .and_then(|(_, p)| p.map(|p| p.disabled))
    };
    assert_eq!(
        (
            off("ldap"),
            off("sql"),
            off("xss"),
            off("cmd"),
            off("anomaly")
        ),
        (Some(true), Some(false), Some(true), None, Some(false))
    );
}

#[test]
fn a_category_of_score_zero_switches_off_the_engines_that_have_no_base_score_of_their_own() {
    let doc = r#"{"categories":{"SQLi":{"base_score":0},"XSS":{"base_score":0},"RCE":{"base_score":120},
        "LFI":{"base_score":0}},"semantic_policies":{"xss":{"base_score":150},"lfi":{"block_threshold":3.2}}}"#;
    assert_eq!(disabled(doc), vec!["sql", "lfi"]);
    assert_eq!(
        disabled(r#"{"categories":{"RFI":{"base_score":0},"ProtocolAttack":{"base_score":0}}}"#),
        Vec::<&str>::new()
    );
    assert_eq!(
        disabled(r#"{"categories":"not an object"}"#),
        Vec::<&str>::new()
    );
}

#[test]
fn the_bot_score_threshold_has_its_own_key_and_a_default() {
    let threshold = |doc: &str| load(doc).bot_protection.unwrap().score_threshold;
    assert_eq!(threshold(r#"{"bot_protection":{"mode":"score"}}"#), 150);
    assert_eq!(
        threshold(r#"{"bot_protection":{"mode":"score","score_threshold":220}}"#),
        220
    );
    assert_eq!(
        threshold(r#"{"bot_protection":{"mode":"score","score_threshold":0}}"#),
        150
    );
    // The threshold of version 1 is not the bot threshold: the control plane copies it when it rewrites a stored document.
    assert_eq!(
        threshold(r#"{"thresholds":{"block":300},"bot_protection":{"mode":"score"}}"#),
        150
    );
    assert!(
        check_rules_json(br#"{"bot_protection":{"mode":"score","score_threshold":10000}}"#)
            .is_err()
    );
    assert!(
        check_rules_json(br#"{"bot_protection":{"mode":"score","score_threshold":9999}}"#).is_ok()
    );
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

fn holds_as_log(effect: TuningEffect) -> bool {
    compute_tuning_plan(&[rule("", effect)], &RequestRuleContext::default())
        .unwrap()
        .log_only
}

fn weaken(multiplier: f64, block: i64, log: i64) -> TuningEffect {
    TuningEffect {
        weaken: Some(TuningWeaken {
            score_multiplier: multiplier,
            threshold_delta: Some(TuningThresholdDelta { block, log }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn a_tuning_action_of_log_holds_strong_detections_as_log() {
    assert!(!holds_as_log(TuningEffect::default()));
    assert!(holds_as_log(TuningEffect {
        action: "log".into(),
        ..Default::default()
    }));
    assert!(
        check_tuning_rule(&rule(
            "",
            TuningEffect {
                action: "log".into(),
                ..Default::default()
            }
        ))
        .is_ok()
    );
    let err = check_tuning_rule(&rule(
        "",
        TuningEffect {
            action: "block".into(),
            ..Default::default()
        },
    ))
    .unwrap_err();
    assert!(err.contains("invalid action"), "{err}");
}

#[test]
fn a_weaken_that_lowered_scores_or_raised_the_block_threshold_reads_as_log() {
    assert!(holds_as_log(weaken(0.5, 0, 0)));
    assert!(holds_as_log(weaken(0.99, 0, 0)));
    assert!(holds_as_log(weaken(0.0, 20, 0)));
    assert!(holds_as_log(weaken(1.0, 1, -10)));
    // Not weaker: unset or neutral multiplier, a block threshold that falls, a log threshold that moves alone.
    assert!(!holds_as_log(weaken(0.0, 0, 0)));
    assert!(!holds_as_log(weaken(1.0, 0, 0)));
    assert!(!holds_as_log(weaken(2.0, -30, 0)));
    assert!(!holds_as_log(weaken(0.0, 0, 40)));
    assert!(!holds_as_log(TuningEffect {
        weaken: Some(TuningWeaken {
            sensitivity_delta: -1,
            ..Default::default()
        }),
        ..Default::default()
    }));
    // A weaken outside [0, 1] is no longer refused.
    assert!(check_tuning_rule(&rule("", weaken(5.0, 0, 0))).is_ok());
}

#[test]
fn a_path_tuning_weaken_reads_as_log_through_the_same_merge() {
    let doc = r#"{"path_exceptions":[{"path":"/p","tuning":{"effect":{"weaken":{"score_multiplier":0.4}}}},
        {"path":"/q","tuning":{"effect":{"action":"log"}}},{"path":"/r","tuning":{"effect":{"weaken":{"score_multiplier":1.5}}}}]}"#;
    assert_eq!(check_rules_json(doc.as_bytes()).unwrap().len(), 0);
    let load = load(doc);
    let log_only: Vec<bool> = load
        .path_exceptions
        .iter()
        .map(|e| merge_effect_into_plan(None, &e.tuning.as_ref().unwrap().effect).log_only)
        .collect();
    assert_eq!(log_only, [true, true, false]);
}
