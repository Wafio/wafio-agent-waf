//! The Custom Rules v2 data contracts (parsed body, tuning rule and plan), plus their JSON decoders.

use std::collections::{BTreeMap, BTreeSet};

use crate::custom_rules::{RuleCondition, decode_rule_condition};
use crate::json_decode::{self, DecodeTrace, JsonDecodeError, Value};

/// A decoded JSON document of any shape: objects are maps (duplicate keys: last wins),
/// numbers float64.
#[derive(Clone, Debug, PartialEq)]
pub enum DynamicJson {
    Null,
    Bool(bool),
    /// A number, kept as its literal text.
    Number(String),
    String(String),
    Array(Vec<DynamicJson>),
    Object(BTreeMap<String, DynamicJson>),
}

/// ParsedBody is the content-type-aware parse of a request body.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParsedBody {
    pub content_type: String,
    /// Parsed JSON document when the body is JSON; None otherwise.
    pub json: Option<DynamicJson>,
    pub json_flat: BTreeMap<String, String>,
    pub form: BTreeMap<String, String>,
    pub form_pairs: Vec<FormValue>,
    pub multipart: BTreeMap<String, String>,
    pub multipart_parts: Vec<MultipartPart>,
    pub multipart_filenames: BTreeMap<String, String>,
    pub multipart_content_types: BTreeMap<String, String>,
    pub files_count: i64,
    pub parse_error: String,
}

/// One name=value pair of a form body or query string (byte strings: request data).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FormValue {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// One named multipart part.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MultipartPart {
    pub names: Vec<Vec<u8>>,
    pub value: Vec<u8>,
    pub filename: Vec<u8>,
    pub content_type: Vec<u8>,
}

/// A mode="tuning" rule.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TuningRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: i64,
    pub created_at: i64,
    pub scope: TuningScope,
    pub target: TuningTarget,
    pub engine: String,
    pub effect: TuningEffect,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TuningScope {
    pub logic: String,
    pub conditions: Vec<RuleCondition>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TuningTarget {
    pub components: Vec<String>,
    /// JSON `match`.
    pub match_: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TuningEffect {
    pub skip_semantic: Vec<String>,
    pub scan_mode: String,
    /// "log": a strong detection of a matched request is recorded as LOG and let through.
    pub action: String,
    /// The key of a rule written before `action`: read, never written. `weakens_to_log` says what it means.
    pub weaken: Option<TuningWeaken>,
}

/// The effect of a rule of an earlier version: it lowered scores or moved a threshold.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TuningWeaken {
    pub sensitivity_delta: i64,
    pub score_multiplier: f64,
    pub threshold_delta: Option<TuningThresholdDelta>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TuningThresholdDelta {
    pub block: i64,
    pub log: i64,
}

impl TuningEffect {
    /// Whether the effect holds a strong detection back as LOG: `action` is "log", or the effect is a `weaken`
    /// of an earlier version that lowered scores (a multiplier above 0 and below 1) or raised the block
    /// threshold (a positive block delta). Any other `weaken` changed nothing a detection could show.
    pub fn holds_detections_as_log(&self) -> bool {
        self.action.trim().eq_ignore_ascii_case("log")
            || self.weaken.as_ref().is_some_and(|w| {
                (w.score_multiplier > 0.0 && w.score_multiplier < 1.0)
                    || w.threshold_delta.as_ref().is_some_and(|d| d.block > 0)
            })
    }
}

/// The merged result of every matching tuning rule for one request.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TuningPlan {
    pub matched_rule_ids: Vec<String>,
    pub skip_semantic_engines: BTreeSet<String>,
    pub skip_semantic_all: bool,
    /// `default`, `both` or `disabled`; empty when no rule named one.
    pub scan_mode: String,
    /// A strong detection of this request is recorded as LOG and let through.
    pub log_only: bool,
}

// ---- decoders (JSON) --------------------------------------------------------------------

pub fn decode_tuning_target(
    d: &mut DecodeTrace,
    v: &Value,
    t: &mut TuningTarget,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "engine.TuningTarget",
        "TuningTarget",
        &["components", "match"],
        |d, i, v| {
            match i {
                0 => json_decode::strings(d, v, &mut t.components)?,
                _ => json_decode::string(d, v, &mut t.match_),
            }
            Ok(())
        },
    )
}

fn decode_threshold_delta(
    d: &mut DecodeTrace,
    v: &Value,
    t: &mut TuningThresholdDelta,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "engine.TuningThresholdDlt",
        "TuningThresholdDlt",
        &["block", "log"],
        |d, i, v| {
            match i {
                0 => json_decode::int(d, v, &mut t.block),
                _ => json_decode::int(d, v, &mut t.log),
            }
            Ok(())
        },
    )
}

fn decode_weaken(
    d: &mut DecodeTrace,
    v: &Value,
    w: &mut TuningWeaken,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "engine.TuningWeaken",
        "TuningWeaken",
        &["sensitivity_delta", "score_multiplier", "threshold_delta"],
        |d, i, v| match i {
            0 => {
                json_decode::int(d, v, &mut w.sensitivity_delta);
                Ok(())
            }
            1 => {
                json_decode::float(d, v, &mut w.score_multiplier);
                Ok(())
            }
            _ => json_decode::optional(d, v, &mut w.threshold_delta, decode_threshold_delta),
        },
    )
}

pub fn decode_tuning_effect(
    d: &mut DecodeTrace,
    v: &Value,
    e: &mut TuningEffect,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "engine.TuningEffect",
        "TuningEffect",
        &["skip_semantic", "scan_mode", "action", "weaken"],
        |d, i, v| match i {
            0 => json_decode::strings(d, v, &mut e.skip_semantic),
            1 => {
                json_decode::string(d, v, &mut e.scan_mode);
                Ok(())
            }
            2 => {
                json_decode::string(d, v, &mut e.action);
                Ok(())
            }
            _ => json_decode::optional(d, v, &mut e.weaken, decode_weaken),
        },
    )
}

fn decode_tuning_scope(
    d: &mut DecodeTrace,
    v: &Value,
    s: &mut TuningScope,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "engine.TuningScope",
        "TuningScope",
        &["logic", "conditions"],
        |d, i, v| match i {
            0 => {
                json_decode::string(d, v, &mut s.logic);
                Ok(())
            }
            _ => json_decode::slice(
                d,
                v,
                &mut s.conditions,
                "[]engine.RuleCondition",
                decode_rule_condition,
            ),
        },
    )
}

pub fn decode_tuning_rule(
    d: &mut DecodeTrace,
    v: &Value,
    r: &mut TuningRule,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "engine.TuningRule",
        "TuningRule",
        &[
            "id",
            "name",
            "enabled",
            "priority",
            "created_at",
            "scope",
            "target",
            "engine",
            "effect",
        ],
        |d, i, v| {
            match i {
                0 => json_decode::string(d, v, &mut r.id),
                1 => json_decode::string(d, v, &mut r.name),
                2 => json_decode::boolean(d, v, &mut r.enabled),
                3 => json_decode::int(d, v, &mut r.priority),
                4 => json_decode::int_as(d, v, &mut r.created_at, "int64"),
                5 => decode_tuning_scope(d, v, &mut r.scope)?,
                6 => decode_tuning_target(d, v, &mut r.target)?,
                7 => json_decode::string(d, v, &mut r.engine),
                _ => decode_tuning_effect(d, v, &mut r.effect)?,
            }
            Ok(())
        },
    )
}
