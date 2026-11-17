//! The policy blocks of a rules document written into the semantic scan configuration.

use std::collections::{HashMap, HashSet};

use wafio_engine_api::{
    CmdPolicy, DeserPolicy, JavaPolicy, LfiPolicy, NosqlPolicy, PhpPolicy, PythonPolicy,
    SemanticConfig, SqlPolicy, SsrfPolicy, SstiPolicy, XssPolicy, XxePolicy,
};

use wafio_engine_rules::{
    ENGINE_ACTION_BLOCK, ENGINE_ACTION_LOG, PathSemanticOverride, SemanticPoliciesConfig,
    SemanticPolicyJson,
};

fn th(j: &SemanticPolicyJson) -> (f64, f64) {
    (j.block_threshold, j.soft_threshold)
}

macro_rules! threshold_policy {
    ($name:ident, $ty:ident) => {
        fn $name(j: Option<&SemanticPolicyJson>) -> Option<$ty> {
            j.map(|j| $ty {
                block_threshold: th(j).0,
                soft_threshold: th(j).1,
            })
        }
    };
}
threshold_policy!(sql_policy_from_json, SqlPolicy);
threshold_policy!(xss_policy_from_json, XssPolicy);
threshold_policy!(cmd_policy_from_json, CmdPolicy);
threshold_policy!(lfi_policy_from_json, LfiPolicy);
threshold_policy!(ssrf_policy_from_json, SsrfPolicy);
threshold_policy!(php_policy_from_json, PhpPolicy);
threshold_policy!(python_policy_from_json, PythonPolicy);
threshold_policy!(java_policy_from_json, JavaPolicy);
threshold_policy!(nosql_policy_from_json, NosqlPolicy);
threshold_policy!(ssti_policy_from_json, SstiPolicy);
threshold_policy!(xxe_policy_from_json, XxePolicy);
threshold_policy!(deser_policy_from_json, DeserPolicy);

/// ApplySemanticPolicies.
pub fn apply_policy_overrides(sc: &mut SemanticConfig, sp: Option<&SemanticPoliciesConfig>) {
    let Some(sp) = sp else { return };
    sc.sql_semantic_policy = sql_policy_from_json(sp.sql.as_ref());
    sc.xss_semantic_policy = xss_policy_from_json(sp.xss.as_ref());
    sc.cmd_semantic_policy = cmd_policy_from_json(sp.cmd.as_ref());
    sc.php_semantic_policy = php_policy_from_json(sp.php.as_ref());
    sc.python_semantic_policy = python_policy_from_json(sp.python.as_ref());
    sc.lfi_semantic_policy = lfi_policy_from_json(sp.lfi.as_ref());
    sc.ssrf_semantic_policy = ssrf_policy_from_json(sp.ssrf.as_ref());
    sc.java_semantic_policy = java_policy_from_json(sp.java.as_ref());
    sc.nosql_semantic_policy = nosql_policy_from_json(sp.nosql.as_ref());
    sc.ssti_semantic_policy = ssti_policy_from_json(sp.ssti.as_ref());
    sc.xxe_semantic_policy = xxe_policy_from_json(sp.xxe.as_ref());
    sc.deser_semantic_policy = deser_policy_from_json(sp.deser.as_ref());
    let disabled: HashMap<String, bool> = sp
        .engine_policies()
        .iter()
        .filter(|(_, p)| p.is_some_and(|p| p.disabled))
        .map(|(k, _)| (k.to_string(), true))
        .collect();
    if !disabled.is_empty() {
        sc.disabled_engines = Some(disabled);
    }
    let log_only: HashSet<String> = sp
        .engine_policies()
        .iter()
        .filter(|(_, p)| p.is_some_and(|p| p.action == ENGINE_ACTION_LOG))
        .map(|(k, _)| k.to_string())
        .collect();
    if !log_only.is_empty() {
        sc.log_only_engines = Some(log_only);
    }
}

/// PathSemanticOverride.ApplyTo.
pub fn apply_path_semantic_override(ov: &PathSemanticOverride, cfg: &mut SemanticConfig) {
    let mut disabled = cfg.disabled_engines.clone().unwrap_or_default();
    macro_rules! set {
        ($f:ident, $dst:ident, $conv:ident, $key:literal) => {
            if let Some(p) = ov.$f.as_ref() {
                cfg.$dst = $conv(Some(p));
                disabled.insert($key.to_string(), p.disabled);
            }
        };
    }
    set!(sql, sql_semantic_policy, sql_policy_from_json, "sql");
    set!(xss, xss_semantic_policy, xss_policy_from_json, "xss");
    set!(cmd, cmd_semantic_policy, cmd_policy_from_json, "cmd");
    set!(php, php_semantic_policy, php_policy_from_json, "php");
    set!(
        python,
        python_semantic_policy,
        python_policy_from_json,
        "python"
    );
    set!(lfi, lfi_semantic_policy, lfi_policy_from_json, "lfi");
    set!(ssrf, ssrf_semantic_policy, ssrf_policy_from_json, "ssrf");
    set!(java, java_semantic_policy, java_policy_from_json, "java");
    set!(
        nosql,
        nosql_semantic_policy,
        nosql_policy_from_json,
        "nosql"
    );
    set!(ssti, ssti_semantic_policy, ssti_policy_from_json, "ssti");
    set!(xxe, xxe_semantic_policy, xxe_policy_from_json, "xxe");
    set!(
        deser,
        deser_semantic_policy,
        deser_policy_from_json,
        "deser"
    );
    // These detectors take only `disabled` (and `action`); an override that names one decides it for the path.
    for (key, p) in [
        ("ldap", ov.ldap.as_ref()),
        ("proto_pollution", ov.proto_pollution.as_ref()),
        ("jwt", ov.jwt.as_ref()),
        ("graphql", ov.graphql.as_ref()),
        ("header_injection", ov.header_injection.as_ref()),
        ("open_redirect", ov.open_redirect.as_ref()),
        ("prompt_injection", ov.prompt_injection.as_ref()),
        ("anomaly", ov.anomaly.as_ref()),
    ] {
        if let Some(p) = p {
            disabled.insert(key.to_string(), p.disabled);
        }
    }
    // An override that names an action sets it for the path; one that does not inherits the project's.
    if ov
        .policies()
        .iter()
        .any(|(_, p)| p.is_some_and(|p| !p.action.is_empty()))
    {
        let mut log_only = cfg.log_only_engines.take().unwrap_or_default();
        for (key, p) in ov.policies() {
            match p.map(|p| p.action.as_str()) {
                Some(ENGINE_ACTION_LOG) => {
                    log_only.insert(key.to_string());
                }
                Some(ENGINE_ACTION_BLOCK) => {
                    log_only.remove(key);
                }
                _ => {}
            }
        }
        cfg.log_only_engines = (!log_only.is_empty()).then_some(log_only);
    }
    cfg.disabled_engines = Some(disabled);
}
