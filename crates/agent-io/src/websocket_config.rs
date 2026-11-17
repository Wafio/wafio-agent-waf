//! Validation of the websocket rules JSON plus the control plane's JSON decoding rules that both it
//! and `ws_config` rely on: struct keys match case-insensitively, a repeated key decodes again into
//! the same field (a `*struct` merges), a type mismatch is remembered and decoding continues, `null`
//! leaves a bool or int unchanged and clears a pointer.

use wafio_domain::json_text::{self, Value, key_matches, type_mismatch_text};
use wafio_domain::text_helpers::{quote, trim_whitespace};

use crate::url_parse;

/// A decoded JSON object with raw member values; `None` = top-level `null`.
pub(crate) type RawMap = Option<Vec<(Vec<u8>, Value)>>;

/// Parses `data` as a JSON object: `None` for a
/// top-level `null`; members keyed exactly, the last duplicate wins.
pub(crate) fn parse_raw_map(data: &[u8]) -> Result<RawMap, String> {
    let v = json_text::parse(data).map_err(|e| e.to_string())?;
    raw_map_of(v)
}

fn raw_map_of(v: Value) -> Result<RawMap, String> {
    match v {
        Value::Null => Ok(None),
        Value::Object(members) => {
            let mut out: Vec<(Vec<u8>, Value)> = Vec::with_capacity(members.len());
            for (k, v) in members {
                match out.iter_mut().find(|(ok, _)| *ok == k) {
                    Some(slot) => slot.1 = v,
                    None => out.push((k, v)),
                }
            }
            Ok(Some(out))
        }
        other => Err(type_mismatch_text("", other.type_name(), "object")),
    }
}

pub(crate) fn map_get<'a>(m: &'a RawMap, key: &str) -> Option<&'a Value> {
    m.as_ref()?
        .iter()
        .find(|(k, _)| k == key.as_bytes())
        .map(|(_, v)| v)
}

/// Collects struct decoding errors: the first type error wins, decoding goes on.
#[derive(Default)]
pub(crate) struct Decoder {
    pub first_error: Option<String>,
}

impl Decoder {
    fn record_type_mismatch(&mut self, v: &Value, field: &str, ty: &str) {
        if self.first_error.is_none() {
            self.first_error = Some(type_mismatch_text(field, &v.kind_text(), ty));
        }
    }

    /// Members of an object in document order, each with the index of the
    /// first field it matches (exact name first, else case-insensitive).
    pub fn fields<'a>(
        &self,
        members: &'a [(Vec<u8>, Value)],
        names: &[&str],
    ) -> Vec<(usize, &'a Value)> {
        members
            .iter()
            .filter_map(|(k, v)| {
                let i = names
                    .iter()
                    .position(|n| k == n.as_bytes())
                    .or_else(|| names.iter().position(|n| key_matches(k, n)))?;
                Some((i, v))
            })
            .collect()
    }

    pub fn bool_into(&mut self, v: &Value, dst: &mut bool, field: &str) {
        match v {
            Value::Bool(b) => *dst = *b,
            Value::Null => {}
            _ => self.record_type_mismatch(v, field, "bool"),
        }
    }

    pub fn opt_bool_into(&mut self, v: &Value, dst: &mut Option<bool>, field: &str) {
        match v {
            Value::Null => *dst = None,
            Value::Bool(b) => *dst = Some(*b),
            _ => self.record_type_mismatch(v, field, "bool"),
        }
    }

    /// A 64-bit integer: the literal must parse as a base-10 i64, so `1.5` and `1e3` fail.
    pub fn int_into(&mut self, v: &Value, dst: &mut i64, field: &str) {
        match v {
            Value::Null => {}
            Value::Number(n) => match std::str::from_utf8(n)
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
            {
                Some(x) if !n.starts_with(b"+") => *dst = x,
                _ => self.record_type_mismatch(v, field, "int"),
            },
            _ => self.record_type_mismatch(v, field, "int"),
        }
    }

    pub fn strings_into(&mut self, v: &Value, dst: &mut Vec<String>, field: &str) {
        match v {
            Value::Null => dst.clear(),
            Value::Array(items) => {
                *dst = items
                    .iter()
                    .map(|it| match it {
                        Value::String(s) => String::from_utf8_lossy(s).into_owned(),
                        Value::Null => String::new(),
                        other => {
                            self.record_type_mismatch(other, field, "string");
                            String::new()
                        }
                    })
                    .collect();
            }
            _ => self.record_type_mismatch(v, field, "[]string"),
        }
    }
}

/// `origin_check` as both the validator and the agent decode it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OriginCheckRaw {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
}

/// `limits` as both the validator and the agent decode it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LimitsRaw {
    pub max_text_bytes: i64,
    pub max_binary_bytes: i64,
    pub max_msgs_per_min: i64,
}

pub(crate) fn decode_origin_check(d: &mut Decoder, v: &Value, dst: &mut Option<OriginCheckRaw>) {
    match v {
        Value::Null => *dst = None,
        Value::Object(m) => {
            let oc = dst.get_or_insert_default();
            for (i, fv) in d.fields(m, &["enabled", "allowed_origins"]) {
                match i {
                    0 => d.bool_into(fv, &mut oc.enabled, "origin_check.enabled"),
                    _ => {
                        d.strings_into(fv, &mut oc.allowed_origins, "origin_check.allowed_origins")
                    }
                }
            }
        }
        other => d.record_type_mismatch(other, "origin_check", "struct"),
    }
}

pub(crate) fn decode_limits(d: &mut Decoder, v: &Value, dst: &mut Option<LimitsRaw>) {
    match v {
        Value::Null => *dst = None,
        Value::Object(m) => {
            let l = dst.get_or_insert_default();
            for (i, fv) in d.fields(
                m,
                &["max_text_bytes", "max_binary_bytes", "max_messages_per_min"],
            ) {
                match i {
                    0 => d.int_into(fv, &mut l.max_text_bytes, "limits.max_text_bytes"),
                    1 => d.int_into(fv, &mut l.max_binary_bytes, "limits.max_binary_bytes"),
                    _ => d.int_into(fv, &mut l.max_msgs_per_min, "limits.max_messages_per_min"),
                }
            }
        }
        other => d.record_type_mismatch(other, "limits", "struct"),
    }
}

/// Checks the agent-only websocket section
/// before a control plane stores or distributes per-app rules_json.
pub fn check_websocket_rules(data: &[u8]) -> Result<(), String> {
    if trim_whitespace(data).is_empty() {
        return Ok(());
    }
    let rules = parse_raw_map(data).map_err(|e| format!("websocket: invalid rules_json: {e}"))?;
    let Some(raw) = map_get(&rules, "websocket") else {
        return Ok(());
    };
    let Value::Object(members) = raw else {
        return Err("websocket must be an object".into());
    };

    let mut d = Decoder::default();
    let (mut enabled, mut scan_bin, mut scan_srv) = (None, None, None);
    let mut origin_check: Option<OriginCheckRaw> = None;
    let mut limits: Option<LimitsRaw> = None;
    for (i, v) in d.fields(
        members,
        &[
            "enabled",
            "scan_binary_hashes",
            "scan_server_frames",
            "origin_check",
            "limits",
        ],
    ) {
        match i {
            0 => d.opt_bool_into(v, &mut enabled, "enabled"),
            1 => d.opt_bool_into(v, &mut scan_bin, "scan_binary_hashes"),
            2 => d.opt_bool_into(v, &mut scan_srv, "scan_server_frames"),
            3 => decode_origin_check(&mut d, v, &mut origin_check),
            _ => decode_limits(&mut d, v, &mut limits),
        }
    }
    if let Some(e) = d.first_error {
        return Err(format!("websocket: {e}"));
    }
    let fields = raw_map_of(raw.clone()).ok().flatten();
    reject_websocket_nulls(
        "websocket",
        &fields,
        &[
            "enabled",
            "scan_binary_hashes",
            "scan_server_frames",
            "origin_check",
            "limits",
        ],
    )?;
    let sub = |key: &str| map_get(&fields, key).and_then(|v| raw_map_of(v.clone()).ok().flatten());
    if let Some(oc) = &origin_check {
        reject_websocket_nulls(
            "websocket.origin_check",
            &sub("origin_check"),
            &["enabled", "allowed_origins"],
        )?;
        if oc.enabled && oc.allowed_origins.is_empty() {
            return Err(
                "websocket.origin_check.allowed_origins is required when origin check is enabled"
                    .into(),
            );
        }
        for origin in &oc.allowed_origins {
            if !valid_origin(origin) {
                return Err(format!(
                    "websocket.origin_check.allowed_origins contains invalid origin {}",
                    quote(origin.as_bytes())
                ));
            }
        }
    }
    if let Some(l) = &limits {
        reject_websocket_nulls(
            "websocket.limits",
            &sub("limits"),
            &["max_text_bytes", "max_binary_bytes", "max_messages_per_min"],
        )?;
        // With several negative limits, which one is named may differ;
        // the outcome does not.
        for (name, value) in [
            ("max_text_bytes", l.max_text_bytes),
            ("max_binary_bytes", l.max_binary_bytes),
            ("max_messages_per_min", l.max_msgs_per_min),
        ] {
            if value < 0 {
                return Err(format!("websocket.limits.{name} must be >= 0"));
            }
        }
    }
    Ok(())
}

fn valid_origin(origin: &str) -> bool {
    let Ok(u) = url_parse::parse(origin.as_bytes()) else {
        return false;
    };
    if (u.scheme != b"http" && u.scheme != b"https")
        || u.hostname().is_empty()
        || u.user.is_some()
        || !u.path.is_empty()
        || !u.raw_query.is_empty()
        || !u.fragment.is_empty()
        || trim_whitespace(origin.as_bytes()) != origin.as_bytes()
    {
        return false;
    }
    if u.host.ends_with(b":") {
        return false;
    }
    let port = u.port();
    if !port.is_empty() {
        // A base-10 integer in 1..65535.
        match std::str::from_utf8(port)
            .ok()
            .and_then(|p| p.parse::<i64>().ok())
        {
            Some(n) if (1..=65535).contains(&n) => {}
            _ => return false,
        }
    }
    true
}

fn reject_websocket_nulls(prefix: &str, fields: &RawMap, keys: &[&str]) -> Result<(), String> {
    for key in keys {
        if let Some(Value::Null) = map_get(fields, key) {
            return Err(format!("{prefix}.{key} must not be null"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_websocket_rules_cases() {
        for input in [
            r#"{"websocket":null}"#,
            r#"{"websocket":7}"#,
            r#"{"websocket":{"limits":{"max_text_bytes":-1}}}"#,
            r#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":[]}}}"#,
            r#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test/path"]}}}"#,
            r#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test:bad"]}}}"#,
            r#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test:70000"]}}}"#,
            r#"{"websocket":{"origin_check":{"enabled":null,"allowed_origins":["https://ok.test"]}}}"#,
            r#"{"websocket":{"origin_check":{"enabled":false,"allowed_origins":null}}}"#,
            r#"{"websocket":{"limits":{"max_text_bytes":null}}}"#,
            r#"{"websocket":{"limits":{"max_text_bytes":1.5}}}"#,
            r#"{"websocket":{"enabled":"yes"}}"#,
            r#"{"websocket":{"origin_check":{"allowed_origins":[" https://ok.test"]}}}"#,
            r#"{"websocket":{"origin_check":{"allowed_origins":["https://ok.test:"]}}}"#,
            r#"[]"#,
            r#"{"a":1} x"#,
        ] {
            assert!(
                check_websocket_rules(input.as_bytes()).is_err(),
                "{input}: want validation error"
            );
        }
        for input in [
            "{}",
            "  ",
            "null",
            r#"{"websocket":{"enabled":false}}"#,
            r#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test:443"]},"limits":{"max_text_bytes":65536}}}"#,
            r#"{"websocket":{"Enabled":null}}"#,
            r#"{"websocket":{"limits":{"max_text_bytes":-0}}}"#,
        ] {
            assert!(
                check_websocket_rules(input.as_bytes()).is_ok(),
                "{input}: unexpected validation error"
            );
        }
    }
}
