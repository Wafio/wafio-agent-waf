//! GUI rule types, decoding and evaluation, the script-rule result types. Script evaluation
//! itself is the agent's (`script_rules.rs` of `wafio-waf-agent`).

use std::sync::OnceLock;

use crate::custom_rules_v2::{DynamicJson, FormValue, MultipartPart, ParsedBody};
use crate::field_names::{FormField, follow_json_path, split_form_name};
use crate::ip_network;
use crate::json_decode::{self, DecodeTrace, JsonDecodeError, Value};
use crate::parsed_body::{
    join_values_in_key_order, json_node_values, json_pointer_value, read_form_pairs,
    resolve_pointer_nodes, scalar_text,
};
use crate::rule_regex::{RegexBudget, cached_rule_regex, is_regex_condition_operator};
use wafio_bytetext::strings;
use wafio_domain::text_helpers::eq_ignore_case;

/// One condition of a GUI rule.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RuleCondition {
    pub field: String,
    pub operator: String,
    pub value: String,
    pub negate: bool,
    pub case_sensitive: bool,
    pub transforms: Vec<String>,
    pub body_scope: String,
}

/// A visual condition rule evaluated pre-semantic.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CustomGuiRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: i64,
    pub created_at: i64,
    pub logic: String,
    pub conditions: Vec<RuleCondition>,
    pub action: String,
}

/// A script rule; the agent compiles its source and runs it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CustomScriptRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: i64,
    pub created_at: i64,
    pub script: String,
}

pub fn decode_rule_condition(
    d: &mut DecodeTrace,
    v: &Value,
    c: &mut RuleCondition,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "engine.RuleCondition",
        "RuleCondition",
        &[
            "field",
            "operator",
            "value",
            "negate",
            "case_sensitive",
            "transforms",
            "body_scope",
        ],
        |d, i, v| {
            match i {
                0 => json_decode::string(d, v, &mut c.field),
                1 => json_decode::string(d, v, &mut c.operator),
                2 => json_decode::string(d, v, &mut c.value),
                3 => json_decode::boolean(d, v, &mut c.negate),
                4 => json_decode::boolean(d, v, &mut c.case_sensitive),
                5 => json_decode::strings(d, v, &mut c.transforms)?,
                _ => json_decode::string(d, v, &mut c.body_scope),
            }
            Ok(())
        },
    )
}

pub fn decode_custom_gui_rule(
    d: &mut DecodeTrace,
    v: &Value,
    r: &mut CustomGuiRule,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "engine.CustomGUIRule",
        "CustomGUIRule",
        &[
            "id",
            "name",
            "enabled",
            "priority",
            "created_at",
            "logic",
            "conditions",
            "action",
        ],
        |d, i, v| {
            match i {
                0 => json_decode::string(d, v, &mut r.id),
                1 => json_decode::string(d, v, &mut r.name),
                2 => json_decode::boolean(d, v, &mut r.enabled),
                3 => json_decode::int(d, v, &mut r.priority),
                4 => json_decode::int_as(d, v, &mut r.created_at, "int64"),
                5 => json_decode::string(d, v, &mut r.logic),
                6 => json_decode::slice(
                    d,
                    v,
                    &mut r.conditions,
                    "[]engine.RuleCondition",
                    decode_rule_condition,
                )?,
                _ => json_decode::string(d, v, &mut r.action),
            }
            Ok(())
        },
    )
}

pub fn decode_custom_script_rule(
    d: &mut DecodeTrace,
    v: &Value,
    r: &mut CustomScriptRule,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "engine.CustomScriptRule",
        "CustomScriptRule",
        &["id", "name", "enabled", "priority", "created_at", "script"],
        |d, i, v| {
            match i {
                0 => json_decode::string(d, v, &mut r.id),
                1 => json_decode::string(d, v, &mut r.name),
                2 => json_decode::boolean(d, v, &mut r.enabled),
                3 => json_decode::int(d, v, &mut r.priority),
                4 => json_decode::int_as(d, v, &mut r.created_at, "int64"),
                _ => json_decode::string(d, v, &mut r.script),
            }
            Ok(())
        },
    )
}

/// Request + decision context for rule evaluation. Request data are byte strings.
#[derive(Clone, Debug, Default)]
pub struct RequestRuleContext {
    pub method: Vec<u8>,
    pub path: Vec<u8>,
    pub query: Vec<u8>,
    pub ip: Vec<u8>,
    pub country: Vec<u8>,
    pub ua: Vec<u8>,
    /// One entry per name; among equal-fold duplicates the first entry wins.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// Truncated to 4 KiB.
    pub body: Vec<u8>,
    pub host: Vec<u8>,
    pub cookies: Vec<(Vec<u8>, Vec<u8>)>,
    pub uri: Vec<u8>,
    pub path_extension: Vec<u8>,
    pub body_size: i64,
    pub body_truncated: bool,
    pub parsed: Option<ParsedBody>,
    /// Shared by both path readings (copies share the pointer). None = unlimited.
    pub regex_budget: Option<std::sync::Arc<std::sync::Mutex<RegexBudget>>>,
    pub score: f64,
    pub action: String,
    pub detected: Vec<String>,
}

/// Stable rule order: priority asc, created_at asc, id asc (stable sort of a copy).
pub fn sorted_by_priority<T: Clone>(rules: &[T], key: impl Fn(&T) -> (i64, i64, String)) -> Vec<T> {
    let mut v = rules.to_vec();
    v.sort_by_key(|r| key(r));
    v
}

/// Transform hook: engine-core owns the transforms (`apply_known_transforms`); the crate that
/// wires the pipeline installs it once. Without it a condition with transforms panics
/// rather than silently comparing the untransformed value.
pub static TRANSFORMS_HOOK: OnceLock<TransformsFn> = OnceLock::new();

/// Signature of `apply_known_transforms`.
pub type TransformsFn = fn(&[u8], &[String]) -> Vec<u8>;

/// The first matching enabled rule (action, id).
pub fn evaluate_gui_rules(rules: &[CustomGuiRule], ctx: &RequestRuleContext) -> (String, String) {
    for r in sorted_by_priority(rules, |r| (r.priority, r.created_at, r.id.clone())) {
        if r.enabled && gui_rule_matches(&r, ctx) {
            return (r.action.clone(), r.id.clone());
        }
    }
    (String::new(), String::new())
}

pub fn gui_rule_matches(r: &CustomGuiRule, ctx: &RequestRuleContext) -> bool {
    if r.conditions.is_empty() {
        return false;
    }
    let or = strings::to_lowercase(r.logic.as_bytes()) == b"or";
    for c in &r.conditions {
        let m = evaluate_condition(c, ctx);
        if or && m {
            return true;
        }
        if !or && !m {
            return false;
        }
    }
    !or
}

pub fn evaluate_condition(c: &RuleCondition, ctx: &RequestRuleContext) -> bool {
    let mut value = read_field_value(&c.field, &c.body_scope, ctx);
    if !c.transforms.is_empty() {
        let f = TRANSFORMS_HOOK
            .get()
            .expect("engine-rules: APPLY_TRANSFORMS_SAFE not installed");
        value = f(&value, &c.transforms);
    }
    if is_regex_condition_operator(&c.operator) {
        let e = cached_rule_regex(&c.value);
        let Some(re) = e.regex else { return false };
        let ok = match &ctx.regex_budget {
            None => true,
            Some(b) => b
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .charge(e.instruction_count, value.len()),
        };
        if !ok {
            return false;
        }
        return re.is_match(&value) != c.negate;
    }
    evaluate_operator(&c.operator, c.value.as_bytes(), &value, c.case_sensitive) != c.negate
}

fn lower(s: &[u8]) -> Vec<u8> {
    strings::to_lowercase(s)
}

pub fn evaluate_operator(op: &str, rule_val: &[u8], value: &[u8], case_sensitive: bool) -> bool {
    let (v, r) = if case_sensitive {
        (value.to_vec(), rule_val.to_vec())
    } else {
        (lower(value), lower(rule_val))
    };
    match op {
        "contains" => strings::contains(&v, &r),
        "not_contains" => !strings::contains(&v, &r),
        "starts_with" => v.starts_with(&r),
        "ends_with" => v.ends_with(&r),
        "equals" => {
            if case_sensitive {
                value == rule_val
            } else {
                eq_ignore_case(value, rule_val)
            }
        }
        "not_equals" => {
            if case_sensitive {
                value != rule_val
            } else {
                !eq_ignore_case(value, rule_val)
            }
        }
        "matches" | "regex" => {
            let e = cached_rule_regex(&String::from_utf8_lossy(rule_val));
            e.regex.is_some_and(|re| re.is_match(value))
        }
        "wildcard" => glob_match(&r, &v).unwrap_or(false),
        "contains_word" => contains_whole_word(&v, &r),
        "cidr" => ip_in_cidr(value, rule_val),
        "not_cidr" => !ip_in_cidr(value, rule_val),
        "in" | "not_in" => {
            let hit = strings::split(rule_val, b",").into_iter().any(|x| {
                let x = strings::trim_whitespace(x);
                if case_sensitive {
                    x == value
                } else {
                    eq_ignore_case(x, value)
                }
            });
            if op == "in" { hit } else { !hit }
        }
        "exists" => !value.is_empty(),
        "len_eq" | "len_gt" | "len_lt" => {
            let Ok(n) = wafio_bytetext::literal::parse_decimal(strings::trim_whitespace(rule_val))
            else {
                return false;
            };
            let l = wafio_bytetext::utf8::count_code_points(value) as i64;
            match op {
                "len_eq" => l == n,
                "len_gt" => l > n,
                _ => l < n,
            }
        }
        "num_gt" | "num_ge" | "num_lt" | "num_le" => {
            let p = |s: &[u8]| {
                crate::custom_rules_validate::parse_finite_number(&String::from_utf8_lossy(
                    strings::trim_whitespace(s),
                ))
            };
            let (Some(l), Some(r)) = (p(value), p(rule_val)) else {
                return false;
            };
            match op {
                "num_gt" => l > r,
                "num_ge" => l >= r,
                "num_lt" => l < r,
                _ => l <= r,
            }
        }
        _ => false,
    }
}

fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

pub fn contains_whole_word(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty()
        || !wafio_bytetext::utf8::to_code_points(needle)
            .iter()
            .all(|&r| r < 0x80 && is_word_byte(r as u8))
    {
        return false;
    }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        let Some(idx) = strings::find(&hay[i..], needle) else {
            return false;
        };
        let pos = i + idx;
        let end = pos + needle.len();
        if (pos == 0 || !is_word_byte(hay[pos - 1]))
            && (end == hay.len() || !is_word_byte(hay[end]))
        {
            return true;
        }
        i = pos + 1;
    }
    false
}

pub fn ip_in_cidr(ip: &[u8], cidr: &[u8]) -> bool {
    let Some(ip) = ip_network::parse_ip(&String::from_utf8_lossy(ip)) else {
        return false;
    };
    let Some((_, n)) = ip_network::parse_network_prefix(&String::from_utf8_lossy(cidr)) else {
        return false;
    };
    n.contains(&ip)
}

/// Glob match (Unix, '/' separator): Some(matched), None for a bad pattern.
pub fn glob_match(mut pattern: &[u8], mut name: &[u8]) -> Option<bool> {
    'pattern: while !pattern.is_empty() {
        let (star, chunk, rest) = split_glob_chunk(pattern);
        pattern = rest;
        if star && chunk.is_empty() {
            return Some(!name.contains(&b'/'));
        }
        let t = match_glob_chunk(chunk, name);
        if let Ok(Some(t)) = t
            && (t.is_empty() || !pattern.is_empty())
        {
            name = t;
            continue;
        }
        t.ok()?;
        if star {
            let mut i = 0;
            while i < name.len() && name[i] != b'/' {
                match match_glob_chunk(chunk, &name[i + 1..]) {
                    Ok(Some(t)) => {
                        if pattern.is_empty() && !t.is_empty() {
                            i += 1;
                            continue;
                        }
                        name = t;
                        continue 'pattern;
                    }
                    Ok(None) => {}
                    Err(()) => return None,
                }
                i += 1;
            }
        }
        return Some(false);
    }
    Some(name.is_empty())
}

/// Splits off the next chunk: (leading star, chunk up to the next unbracketed star, rest).
fn split_glob_chunk(mut pattern: &[u8]) -> (bool, &[u8], &[u8]) {
    let mut star = false;
    while pattern.first() == Some(&b'*') {
        pattern = &pattern[1..];
        star = true;
    }
    let mut inrange = false;
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'\\' if i + 1 < pattern.len() => i += 1,
            b'[' => inrange = true,
            b']' => inrange = false,
            b'*' if !inrange => return (star, &pattern[..i], &pattern[i..]),
            _ => {}
        }
        i += 1;
    }
    (star, pattern, &[])
}

/// Ok(Some(rest)) on a match, Ok(None) on a mismatch, Err on a bad pattern (the chunk is read to
/// its end even after a mismatch).
fn match_glob_chunk<'a>(mut chunk: &[u8], mut s: &'a [u8]) -> Result<Option<&'a [u8]>, ()> {
    use wafio_bytetext::utf8::decode_code_point;
    let mut failed = false;
    while !chunk.is_empty() {
        failed = failed || s.is_empty();
        match chunk[0] {
            b'[' => {
                let mut r = 0;
                if !failed {
                    let (rr, n) = decode_code_point(s);
                    r = rr;
                    s = &s[n..];
                }
                chunk = &chunk[1..];
                let mut negated = false;
                if chunk.first() == Some(&b'^') {
                    negated = true;
                    chunk = &chunk[1..];
                }
                let mut matched = false;
                let mut nrange = 0;
                loop {
                    if chunk.first() == Some(&b']') && nrange > 0 {
                        chunk = &chunk[1..];
                        break;
                    }
                    let (lo, rest) = read_glob_escape(chunk)?;
                    chunk = rest;
                    let mut hi = lo;
                    if chunk[0] == b'-' {
                        (hi, chunk) = read_glob_escape(&chunk[1..])?;
                    }
                    matched = matched || lo <= r && r <= hi;
                    nrange += 1;
                }
                failed = failed || matched == negated;
            }
            b'?' => {
                if !failed {
                    failed = s[0] == b'/';
                    s = &s[decode_code_point(s).1..];
                }
                chunk = &chunk[1..];
            }
            c => {
                let c = if c == b'\\' {
                    chunk = &chunk[1..];
                    *chunk.first().ok_or(())?
                } else {
                    c
                };
                if !failed {
                    failed = c != s[0];
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
        }
    }
    Ok((!failed).then_some(s))
}

/// One possibly escaped code point of a bracket expression.
fn read_glob_escape(mut chunk: &[u8]) -> Result<(wafio_bytetext::CodePoint, &[u8]), ()> {
    if chunk.is_empty() || chunk[0] == b'-' || chunk[0] == b']' {
        return Err(());
    }
    if chunk[0] == b'\\' {
        chunk = &chunk[1..];
        if chunk.is_empty() {
            return Err(());
        }
    }
    let (r, n) = wafio_bytetext::utf8::decode_code_point(chunk);
    let rest = &chunk[n..];
    if r == wafio_bytetext::utf8::REPLACEMENT_CODE_POINT && n == 1 || rest.is_empty() {
        return Err(());
    }
    Ok((r, rest))
}

fn header_lookup(list: &[(Vec<u8>, Vec<u8>)], name: &[u8]) -> Vec<u8> {
    list.iter()
        .find(|(k, _)| eq_ignore_case(k, name))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

pub fn read_field_value(field: &str, body_scope: &str, ctx: &RequestRuleContext) -> Vec<u8> {
    let (base, name, has_name) = match field.split_once(':') {
        Some((b, n)) => (b, n, true),
        None => (field, "", false),
    };
    let name_b = name.as_bytes();
    match lower(base.as_bytes()).as_slice() {
        b"path" => ctx.path.clone(),
        b"method" => ctx.method.clone(),
        b"ip" => ctx.ip.clone(),
        b"country" => ctx.country.clone(),
        b"user_agent" => ctx.ua.clone(),
        b"host" => ctx.host.clone(),
        b"uri" => ctx.uri.clone(),
        b"path_ext" => ctx.path_extension.clone(),
        b"body" => ctx.body.clone(),
        b"body_size" => ctx.body_size.to_string().into_bytes(),
        b"body_truncated" => ctx.body_truncated.to_string().into_bytes(),
        b"files_count" => ctx
            .parsed
            .as_ref()
            .map_or(b"0".to_vec(), |p| p.files_count.to_string().into_bytes()),
        b"json" => json_pointer_value(ctx.parsed.as_ref(), name, body_scope),
        b"header" if has_name => header_lookup(&ctx.headers, name_b),
        b"cookie" if has_name => header_lookup(&ctx.cookies, name_b),
        b"query" => {
            if !has_name {
                return ctx.query.clone();
            }
            strings::join(&form_values(&read_form_pairs(&ctx.query), name), b",")
        }
        b"form" => match &ctx.parsed {
            Some(p) if has_name => strings::join(&form_values(&p.form_pairs, name), b","),
            _ => Vec::new(),
        },
        b"multipart" => match &ctx.parsed {
            Some(p) if has_name => multipart_first_value(p, name),
            _ => Vec::new(),
        },
        b"param" if has_name => strings::join(&param_values(ctx, name), b"\n"),
        _ => Vec::new(),
    }
}

pub fn form_values(pairs: &[FormValue], field: &str) -> Vec<Vec<u8>> {
    let f = FormField::new(field);
    pairs
        .iter()
        .filter(|kv| f.matches(&kv.name, &split_form_name(&kv.name)))
        .map(|kv| kv.value.clone())
        .collect()
}

fn part_has_name(f: &FormField, part: &MultipartPart) -> bool {
    part.names.iter().any(|n| f.matches(n, &split_form_name(n)))
}

pub fn param_values(ctx: &RequestRuleContext, field: &str) -> Vec<Vec<u8>> {
    let mut vals = form_values(&read_form_pairs(&ctx.query), field);
    if let Some(p) = &ctx.parsed {
        vals.extend(form_values(&p.form_pairs, field));
        let f = FormField::new(field);
        for part in &p.multipart_parts {
            if part_has_name(&f, part) {
                vals.push(part.value.clone());
            }
        }
        if let Some(j) = &p.json {
            follow_json_path(j, field, &mut |v| collect_json_scalars(&mut vals, v));
        }
    }
    vals
}

/// Scalars of a node, map keys sorted.
pub fn collect_json_scalars(out: &mut Vec<Vec<u8>>, v: &DynamicJson) {
    match v {
        DynamicJson::Object(m) => {
            for x in m.values() {
                collect_json_scalars(out, x);
            }
        }
        DynamicJson::Array(a) => {
            for x in a {
                collect_json_scalars(out, x);
            }
        }
        _ => {
            if let Some(s) = scalar_text(v) {
                out.push(s.into_bytes());
            }
        }
    }
}

fn multipart_first_value(p: &ParsedBody, name: &str) -> Vec<u8> {
    match name {
        "filename" => join_values_in_key_order(&p.multipart_filenames, false).into_bytes(),
        "content_type" => join_values_in_key_order(&p.multipart_content_types, true).into_bytes(),
        _ => strings::join(&multipart_field_values(p, name), b","),
    }
}

fn multipart_field_values(p: &ParsedBody, name: &str) -> Vec<Vec<u8>> {
    let (field, filename) = match name.strip_prefix("filename:") {
        Some(f) => (f, true),
        None => (name, false),
    };
    let f = FormField::new(field);
    let mut vals = Vec::new();
    for part in &p.multipart_parts {
        if !part_has_name(&f, part) {
            continue;
        }
        if !filename {
            vals.push(part.value.clone());
        } else if !part.filename.is_empty() {
            vals.push(part.filename.clone());
        }
    }
    vals
}

/// Every value a field resolves to (script builtins `waf_values`).
pub fn all_field_values(field: &str, ctx: &RequestRuleContext) -> Vec<Vec<u8>> {
    let t = wafio_domain::text_helpers::trim_whitespace_str(field);
    let (base, name, has_name) = match t.split_once(':') {
        Some((b, n)) => (b, n, true),
        None => (t, "", false),
    };
    match lower(base.as_bytes()).as_slice() {
        b"query" if has_name => return form_values(&read_form_pairs(&ctx.query), name),
        b"form" => {
            return match &ctx.parsed {
                Some(p) if has_name => form_values(&p.form_pairs, name),
                _ => Vec::new(),
            };
        }
        b"multipart" => {
            if let Some(p) = &ctx.parsed
                && has_name
                && name != "filename"
                && name != "content_type"
            {
                return multipart_field_values(p, name);
            }
        }
        b"param" => {
            return if has_name {
                param_values(ctx, name)
            } else {
                Vec::new()
            };
        }
        b"json" => {
            if let Some(p) = &ctx.parsed
                && has_name
                && !name.is_empty()
            {
                return json_node_values(&resolve_pointer_nodes(p.json.as_ref(), name), "");
            }
        }
        _ => {}
    }
    let v = read_field_value(field, "", ctx);
    if v.is_empty() { Vec::new() } else { vec![v] }
}

// ---- script results ---------------------------------------------------------------------

pub const COVERAGE_FLAG_SCRIPT_TIMEOUT: &str = "script_timeout";
pub const COVERAGE_FLAG_SCRIPT_ERROR: &str = "script_error";
pub const COVERAGE_FLAG_REGEX_BUDGET: &str = "regex_budget";

/// The outcome of a request's script rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScriptResult {
    pub action: String,
    pub rule_id: String,
    pub incomplete: bool,
    pub incomplete_rule: String,
    pub incomplete_reason: String,
    pub content_incomplete: bool,
    pub coverage: String,
}

pub fn is_script_load_reason(reason: &str) -> bool {
    matches!(reason, "timeout" | "budget" | "busy" | "canceled")
}

impl ScriptResult {
    pub fn record_incomplete(&mut self, rule_id: &str, reason: &str) {
        if !self.incomplete {
            self.incomplete = true;
            self.incomplete_rule = rule_id.into();
            self.incomplete_reason = reason.into();
        }
        if !is_script_load_reason(reason) {
            self.content_incomplete = true;
        }
        self.merge_coverage(if reason == "error" {
            COVERAGE_FLAG_SCRIPT_ERROR
        } else {
            COVERAGE_FLAG_SCRIPT_TIMEOUT
        });
    }

    pub fn merge_coverage(&mut self, flags: &str) {
        for f in flags.split(',') {
            if f.is_empty() || self.coverage.split(',').any(|x| x == f) {
                continue;
            }
            if !self.coverage.is_empty() {
                self.coverage.push(',');
            }
            self.coverage.push_str(f);
        }
    }
}

pub fn merge_script_results(
    rp: &crate::forwarded_path::RequestPathReadings,
    primary: &ScriptResult,
    alternate: &ScriptResult,
) -> ScriptResult {
    let mut out = ScriptResult::default();
    (out.action, out.rule_id) = crate::path_rules::merge_script_actions(
        rp,
        &primary.action,
        &primary.rule_id,
        &alternate.action,
        &alternate.rule_id,
    );
    for r in [primary, alternate] {
        if r.incomplete && !out.incomplete {
            out.incomplete = true;
            out.incomplete_rule = r.incomplete_rule.clone();
            out.incomplete_reason = r.incomplete_reason.clone();
        }
        out.content_incomplete |= r.content_incomplete;
        out.merge_coverage(&r.coverage);
    }
    if out.incomplete && out.action == "allow" {
        out.action.clear();
        out.rule_id.clear();
    }
    out
}
