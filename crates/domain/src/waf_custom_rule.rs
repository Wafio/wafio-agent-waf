//! App-scoped WAF custom rule types (GUI, script, tuning). JSON names match the control plane's;
//! `omitempty` fields are skipped when empty on output.

use serde::{Deserialize, Serialize};

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}

/// An app-scoped WAF custom rule.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRule {
    pub id: String,
    pub app_id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: i64,
    pub mode: String,
    pub conditions: Option<Vec<CustomRuleCondition>>,
    pub condition_logic: String,
    pub action: String,
    pub script: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tuning: Option<CustomRuleTuning>,
    /// RFC 3339.
    pub created_at: String,
    pub updated_at: String,
    /// Computed per response: why a regex of the rule is unusable ("" = fine).
    pub regex_error: String,
}

/// A single predicate in a GUI rule.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRuleCondition {
    pub field: String,
    pub operator: String,
    pub value: String,
    #[serde(skip_serializing_if = "is_false")]
    pub negate: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub case_sensitive: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transforms: Vec<String>,
    /// "key", "value" or "all" (default). GUI rules only.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body_scope: String,
}

/// The config payload of a mode="tuning" rule.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRuleTuning {
    pub scope: CustomRuleTuningScope,
    pub target: CustomRuleTuningTarget,
    /// semantic | both; a stored `crs` is read and changes nothing.
    pub engine: String,
    pub effect: CustomRuleTuningEffect,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRuleTuningScope {
    /// and | or
    pub logic: String,
    pub conditions: Option<Vec<CustomRuleCondition>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRuleTuningTarget {
    /// "request", "query:<name>", "form:<field>", "json:<pointer>",
    /// "header:<name>", "cookie:<name>", "multipart:filename", "args".
    pub components: Option<Vec<String>>,
    /// exact | prefix | regex | any
    #[serde(rename = "match")]
    pub match_: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRuleTuningEffect {
    /// Semantic engine names or "*".
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skip_semantic: Vec<String>,
    /// default | both | disabled; a stored `semantic_only` or `crs_only` reads as default.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub scan_mode: String,
    /// "log": a strong detection of a matched request is recorded as LOG and let through.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub action: String,
    /// The key of a rule written before `action`: read, never written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weaken: Option<CustomRuleTuningWeaken>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRuleTuningWeaken {
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub sensitivity_delta: i64,
    #[serde(skip_serializing_if = "is_zero_f64")]
    pub score_multiplier: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold_delta: Option<CustomRuleTuningThresholdDelta>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRuleTuningThresholdDelta {
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub block: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub log: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_names_match_wire_keys() {
        let r: CustomRule = serde_json::from_str(
            r#"{"id":"r1","mode":"tuning","tuning":{"target":{"components":["args"],"match":"any"},
            "effect":{"skip_semantic":["*"],"weaken":{"threshold_delta":{"block":5}}}}}"#,
        )
        .unwrap();
        let t = r.tuning.as_ref().unwrap();
        assert_eq!(t.target.match_, "any");
        assert_eq!(
            t.effect
                .weaken
                .as_ref()
                .unwrap()
                .threshold_delta
                .as_ref()
                .unwrap()
                .block,
            5
        );
        let out = serde_json::to_string(&CustomRuleCondition {
            field: "a".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(out, r#"{"field":"a","operator":"","value":""}"#);
    }
}
