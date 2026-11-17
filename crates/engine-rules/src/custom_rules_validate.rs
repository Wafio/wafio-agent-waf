//! Condition, tuning rule and tuning effect validation.

use crate::custom_rules::RuleCondition;
use crate::custom_rules_v2::{TuningEffect, TuningRule, TuningTarget};
use crate::rule_regex::compile_rule_pattern;
use crate::tuning::json_pointer_to_dotted;
use wafio_domain::text_helpers::{quote, trim_whitespace_str};

pub const CONDITION_LIMIT_PER_RULE: usize = 64;
pub const TRANSFORM_LIMIT_PER_CONDITION: usize = 16;
pub const CONDITION_VALUE_LEN_LIMIT: usize = 2048;
pub const RULE_LIMIT_PER_APP: usize = 200;

/// One selectable condition field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConditionFieldSpec {
    pub name: &'static str,
    pub requires_name: bool,
    pub name_hint: &'static str,
}

/// The condition fields (name, requires_name, name_hint).
pub const CONDITION_FIELD_SPECS: [ConditionFieldSpec; 24] = [
    ConditionFieldSpec {
        name: "uri",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "path",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "path_ext",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "query",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "query:<name>",
        requires_name: true,
        name_hint: "parameter name",
    },
    ConditionFieldSpec {
        name: "method",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "host",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "header:<name>",
        requires_name: true,
        name_hint: "header name",
    },
    ConditionFieldSpec {
        name: "cookie:<name>",
        requires_name: true,
        name_hint: "cookie name",
    },
    ConditionFieldSpec {
        name: "param:<name>",
        requires_name: true,
        name_hint: "name or dot path, e.g. user.email",
    },
    ConditionFieldSpec {
        name: "body",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "body_size",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "body_truncated",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "json",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "json:<pointer>",
        requires_name: true,
        name_hint: "RFC 6901 pointer, e.g. /user/name or /items/*/sku",
    },
    ConditionFieldSpec {
        name: "form:<field>",
        requires_name: true,
        name_hint: "urlencoded field name",
    },
    ConditionFieldSpec {
        name: "multipart:<field>",
        requires_name: true,
        name_hint: "part field name",
    },
    ConditionFieldSpec {
        name: "multipart:filename",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "multipart:filename:<field>",
        requires_name: true,
        name_hint: "file part field name",
    },
    ConditionFieldSpec {
        name: "multipart:content_type",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "files_count",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "ip",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "country",
        requires_name: false,
        name_hint: "",
    },
    ConditionFieldSpec {
        name: "user_agent",
        requires_name: false,
        name_hint: "",
    },
];

pub const ALLOWED_CONDITION_OPERATORS: [&str; 22] = [
    "contains",
    "not_contains",
    "contains_word",
    "starts_with",
    "ends_with",
    "equals",
    "not_equals",
    "matches",
    "regex",
    "wildcard",
    "in",
    "not_in",
    "cidr",
    "not_cidr",
    "exists",
    "len_eq",
    "len_gt",
    "len_lt",
    "num_gt",
    "num_ge",
    "num_lt",
    "num_le",
];

/// Names of the valid transforms.
pub const ALLOWED_TRANSFORMS: [&str; 27] = [
    "lowercase",
    "uppercase",
    "trim",
    "trim_left",
    "trim_right",
    "url_decode",
    "url_decode_uni",
    "html_entity_decode",
    "js_decode",
    "css_decode",
    "base64_decode",
    "hex_decode",
    "sql_hex_decode",
    "normalize_path",
    "normalize_path_win",
    "compress_whitespace",
    "remove_whitespace",
    "remove_nulls",
    "replace_nulls",
    "remove_comments_char",
    "replace_comments",
    "cmd_line",
    "escape_seq_decode",
    "md5",
    "sha1",
    "sha256",
    "length",
];

fn lower(s: &str) -> String {
    String::from_utf8_lossy(&wafio_bytetext::strings::to_lowercase(s.as_bytes())).into_owned()
}

fn condition_field_root(base: &str) -> Option<ConditionFieldSpec> {
    // Later entries with the same base win.
    CONDITION_FIELD_SPECS
        .iter()
        .rev()
        .find(|f| lower(f.name.split(':').next().unwrap()) == base)
        .copied()
}

pub fn check_condition(c: &RuleCondition) -> Result<(), String> {
    let field = trim_whitespace_str(&c.field);
    if field.is_empty() {
        return Err("field is required".into());
    }
    let (base, name, has_name) = match field.split_once(':') {
        Some((b, n)) => (lower(b), n, true),
        None => (lower(field), "", false),
    };
    let Some(spec) = condition_field_root(&base) else {
        return Err(format!(
            "unknown condition field {}",
            quote(c.field.as_bytes())
        ));
    };
    match base.as_str() {
        "json" => {
            if has_name && !name.is_empty() && !name.starts_with('/') {
                return Err(format!(
                    "json pointer in field {} must start with '/'",
                    quote(c.field.as_bytes())
                ));
            }
        }
        "multipart" => {
            if !has_name || name.is_empty() {
                return Err(format!(
                    "field {} requires a part name, 'filename', 'filename:<field>' or 'content_type'",
                    quote(c.field.as_bytes())
                ));
            }
            if name.strip_prefix("filename:") == Some("") {
                return Err(format!(
                    "field {} requires a file field name after 'filename:'",
                    quote(c.field.as_bytes())
                ));
            }
        }
        _ => {
            if spec.requires_name && (!has_name || trim_whitespace_str(name).is_empty()) {
                return Err(format!(
                    "field {} requires a {}",
                    quote(c.field.as_bytes()),
                    spec.name_hint
                ));
            }
        }
    }
    let op = lower(trim_whitespace_str(&c.operator));
    if op.is_empty() {
        return Err("operator is required".into());
    }
    if !ALLOWED_CONDITION_OPERATORS.contains(&op.as_str()) {
        return Err(format!("unknown operator {}", quote(c.operator.as_bytes())));
    }
    if c.value.len() > CONDITION_VALUE_LEN_LIMIT {
        return Err(format!("value exceeds {CONDITION_VALUE_LEN_LIMIT} bytes"));
    }
    if c.transforms.len() > TRANSFORM_LIMIT_PER_CONDITION {
        return Err(format!(
            "too many transforms (max {TRANSFORM_LIMIT_PER_CONDITION})"
        ));
    }
    for t in &c.transforms {
        if !ALLOWED_TRANSFORMS.contains(&trim_whitespace_str(t)) {
            return Err(format!("unknown transform {}", quote(t.as_bytes())));
        }
    }
    if !c.body_scope.is_empty()
        && !matches!(
            lower(trim_whitespace_str(&c.body_scope)).as_str(),
            "all" | "key" | "value"
        )
    {
        return Err(format!(
            "invalid body_scope {} (all|key|value)",
            quote(c.body_scope.as_bytes())
        ));
    }
    let v = trim_whitespace_str(&c.value);
    match op.as_str() {
        "len_eq" | "len_gt" | "len_lt"
            if wafio_bytetext::literal::parse_decimal(v.as_bytes()).is_err() =>
        {
            return Err(format!(
                "operator {} requires an integer value",
                quote(op.as_bytes())
            ));
        }
        "num_gt" | "num_ge" | "num_lt" | "num_le" if parse_finite_number(v).is_none() => {
            return Err(format!(
                "operator {} requires a numeric value",
                quote(op.as_bytes())
            ));
        }
        "matches" | "regex" => {
            if let Err(e) = compile_rule_pattern(&c.value) {
                return Err(format!("invalid regex {}: {e}", quote(c.value.as_bytes())));
            }
        }
        "wildcard" if crate::custom_rules::glob_match(c.value.as_bytes(), b"").is_none() => {
            return Err(format!(
                "invalid wildcard pattern {}",
                quote(c.value.as_bytes())
            ));
        }
        "cidr" | "not_cidr" if crate::ip_network::parse_network_prefix(v).is_none() => {
            return Err(format!(
                "operator {} requires a valid CIDR network",
                quote(op.as_bytes())
            ));
        }
        _ => {}
    }
    Ok(())
}

/// Some(value) when `s` parses as a 64-bit float; a syntax error and an out-of-range value
/// are both None.
pub fn parse_finite_number(s: &str) -> Option<f64> {
    wafio_bytetext::literal::parse_float(s.as_bytes())
}

pub fn check_gui_conditions(conds: &[RuleCondition], logic: &str) -> Result<(), String> {
    if conds.len() > CONDITION_LIMIT_PER_RULE {
        return Err(format!(
            "too many conditions (max {CONDITION_LIMIT_PER_RULE})"
        ));
    }
    let l = lower(trim_whitespace_str(logic));
    if !l.is_empty() && l != "and" && l != "or" {
        return Err(format!(
            "invalid condition logic {} (and|or)",
            quote(logic.as_bytes())
        ));
    }
    for (i, c) in conds.iter().enumerate() {
        check_condition(c).map_err(|e| format!("condition {}: {e}", i + 1))?;
    }
    Ok(())
}

/// The engine `crs` of a stored rule is still accepted.
pub fn check_tuning_rule(t: &TuningRule) -> Result<(), String> {
    check_gui_conditions(&t.scope.conditions, &t.scope.logic).map_err(|e| format!("scope: {e}"))?;
    if !matches!(
        lower(trim_whitespace_str(&t.engine)).as_str(),
        "" | "semantic" | "crs" | "both"
    ) {
        return Err(format!(
            "invalid engine {} (semantic|crs|both)",
            quote(t.engine.as_bytes())
        ));
    }
    check_tuning_effect(&t.effect, &t.target, true)
}

fn check_tuning_target(t: &TuningTarget) -> Result<(), String> {
    let mode = lower(trim_whitespace_str(&t.match_));
    if !matches!(mode.as_str(), "" | "exact" | "prefix" | "regex" | "any") {
        return Err(format!(
            "invalid match mode {} (exact|prefix|regex|any)",
            quote(t.match_.as_bytes())
        ));
    }
    for comp in &t.components {
        check_target_component(comp, &mode)?;
    }
    Ok(())
}

fn check_target_component(comp: &str, mode: &str) -> Result<(), String> {
    let comp = trim_whitespace_str(comp);
    if comp.is_empty() {
        return Err("empty target component".into());
    }
    let l = lower(comp);
    if matches!(
        l.as_str(),
        "request" | "args" | "multipart:filename" | "multipart:content_type"
    ) {
        return Ok(());
    }
    let Some(prefix) = [
        "query:",
        "form:",
        "json:",
        "header:",
        "cookie:",
        "multipart:filename:",
        "multipart:",
    ]
    .into_iter()
    .find(|p| l.starts_with(p)) else {
        return Err(format!(
            "target component {} must use a known prefix (query:|form:|json:|header:|cookie:|multipart:) or be 'request'/'args'",
            quote(comp.as_bytes())
        ));
    };
    let name = trim_whitespace_str(comp.get(prefix.len()..).unwrap_or_default());
    if name.is_empty() {
        return Err(format!(
            "target component {} requires a name after the prefix",
            quote(comp.as_bytes())
        ));
    }
    if prefix == "json:" && !name.starts_with('/') {
        return Err(format!(
            "json target component {} requires an RFC 6901 pointer starting with '/'",
            quote(comp.as_bytes())
        ));
    }
    if mode == "regex" {
        let pattern = if prefix == "json:" {
            json_pointer_to_dotted(name)
        } else {
            name.to_string()
        };
        if let Err(e) = compile_rule_pattern(&pattern) {
            return Err(format!(
                "target component {} is not a valid regex: {e}",
                quote(comp.as_bytes())
            ));
        }
    }
    Ok(())
}

pub const SEMANTIC_ENGINE_KEY_NAMES: [&str; 20] = [
    "sql",
    "xss",
    "cmd",
    "php",
    "python",
    "lfi",
    "ssrf",
    "java",
    "nosql",
    "ssti",
    "xxe",
    "deser",
    "ldap",
    "proto_pollution",
    "jwt",
    "graphql",
    "header_injection",
    "open_redirect",
    "prompt_injection",
    "anomaly",
];

/// Whether a `skip_semantic` entry is a name that no detector has (not empty, not `*`).
pub fn is_unknown_semantic_engine(s: &str) -> bool {
    let s = lower(trim_whitespace_str(s));
    !s.is_empty() && s != "*" && !SEMANTIC_ENGINE_KEY_NAMES.contains(&s.as_str())
}

pub fn check_tuning_effect(
    effect: &TuningEffect,
    target: &TuningTarget,
    allow_scan_mode: bool,
) -> Result<(), String> {
    check_tuning_target(target).map_err(|e| format!("target: {e}"))?;
    for s in &effect.skip_semantic {
        let s = lower(trim_whitespace_str(s));
        if s.is_empty() {
            return Err("effect: skip_semantic: empty entry".into());
        }
        if s != "*" && !SEMANTIC_ENGINE_KEY_NAMES.contains(&s.as_str()) {
            return Err(format!(
                "effect: skip_semantic: unknown semantic engine {} (known: sql, xss, cmd, php, python, lfi, ssrf, java, nosql, ssti, xxe, deser, ldap, proto_pollution, jwt, graphql, header_injection, open_redirect, prompt_injection, anomaly, or \"*\")",
                quote(s.as_bytes())
            ));
        }
    }
    if !allow_scan_mode && !trim_whitespace_str(&effect.scan_mode).is_empty() {
        return Err("effect: scan_mode is not supported in path-rule tuning; use the path rule's inspection_off switch to change the scan mode".into());
    }
    if !matches!(
        lower(trim_whitespace_str(&effect.scan_mode)).as_str(),
        "" | "default" | "semantic_only" | "crs_only" | "both" | "disabled"
    ) {
        return Err(format!(
            "effect: invalid scan_mode {} (default|both|disabled)",
            quote(effect.scan_mode.as_bytes())
        ));
    }
    if !matches!(effect.action.as_str(), "" | "log") {
        return Err(format!(
            "effect: invalid action {} (only \"log\")",
            quote(effect.action.as_bytes())
        ));
    }
    Ok(())
}
