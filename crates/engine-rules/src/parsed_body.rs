//! The content-type-aware body parse custom rules read.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::custom_rules_v2::{DynamicJson, FormValue, ParsedBody};
use crate::field_names::unescape_form_leniently;
use crate::json_decode::{self, Value};
use wafio_domain::text_helpers::eq_ignore_case;

pub const BODY_PARSE_LIMIT_BYTES: usize = 64 * 1024;
pub const MULTIPART_PART_LIMIT: usize = 64;
pub const PART_VALUE_LIMIT_BYTES: usize = 64 * 1024;
pub const FILE_PREVIEW_LIMIT_BYTES: usize = 4 * 1024;

/// Multipart hook: multipart parsing needs a media-type parser and a multipart reader, which this
/// crate does not have. The pipeline crate installs it (it must fill multipart, multipart_parts,
/// multipart_filenames, multipart_content_types, files_count and parse_error).
pub static MULTIPART_PARSE_HOOK: OnceLock<MultipartParseFn> = OnceLock::new();

/// Signature of the multipart parse hook: (content type, raw body, result to fill).
pub type MultipartParseFn = fn(&[u8], &[u8], &mut ParsedBody);

pub fn parse_body_for_rules(content_type: &[u8], raw: &[u8]) -> ParsedBody {
    let mut p = ParsedBody {
        content_type: media_type_of(content_type),
        ..Default::default()
    };
    if raw.is_empty() {
        return p;
    }
    if raw.len() > BODY_PARSE_LIMIT_BYTES {
        p.parse_error = "body exceeds MaxBodyParseBytes".into();
        return p;
    }
    let ct = p.content_type.clone();
    if ct == "application/json" || ct == "text/json" || ct.ends_with("+json") {
        read_json_body(raw, &mut p);
    } else if ct == "application/x-www-form-urlencoded" {
        read_form_body(raw, &mut p);
    } else if ct.starts_with("multipart/") {
        let f = MULTIPART_PARSE_HOOK
            .get()
            .expect("engine-rules: PARSE_MULTIPART_BODY not installed");
        f(content_type, raw, &mut p);
    }
    p
}

fn media_type_of(ct: &[u8]) -> String {
    let ct = ct.split(|&c| c == b';').next().unwrap_or_default();
    String::from_utf8_lossy(&wafio_bytetext::strings::to_lowercase(
        wafio_bytetext::strings::trim_whitespace(ct),
    ))
    .into_owned()
}

/// A JSON value as a `DynamicJson`: numbers keep their literal.
pub fn to_dynamic_json(v: &Value) -> DynamicJson {
    match v {
        Value::Null => DynamicJson::Null,
        Value::Bool(b) => DynamicJson::Bool(*b),
        Value::Number(n) => DynamicJson::Number(String::from_utf8_lossy(n).into_owned()),
        Value::String(s) => DynamicJson::String(String::from_utf8_lossy(s).into_owned()),
        Value::Array(a) => DynamicJson::Array(a.iter().map(to_dynamic_json).collect()),
        Value::Object(m) => {
            let mut out = BTreeMap::new();
            for (k, v) in m {
                out.insert(String::from_utf8_lossy(k).into_owned(), to_dynamic_json(v));
            }
            DynamicJson::Object(out)
        }
    }
}

fn read_json_body(raw: &[u8], p: &mut ParsedBody) {
    let Ok(v) = json_decode::parse(raw) else {
        p.parse_error = "invalid json body".into();
        return;
    };
    let v = to_dynamic_json(&v);
    flatten_json_into("json", &v, &mut p.json_flat);
    p.json = Some(v);
}

fn flatten_json_into(prefix: &str, v: &DynamicJson, out: &mut BTreeMap<String, String>) {
    match v {
        DynamicJson::Object(m) => {
            for (k, c) in m {
                flatten_json_into(&format!("{prefix}.{k}"), c, out);
            }
        }
        DynamicJson::Array(a) => {
            for (i, c) in a.iter().enumerate() {
                flatten_json_into(&format!("{prefix}.{i}"), c, out);
            }
        }
        _ => {
            if let Some(s) = scalar_text(v) {
                out.insert(prefix.to_string(), s);
            }
        }
    }
}

fn read_form_body(raw: &[u8], p: &mut ParsedBody) {
    p.form_pairs = read_form_pairs(raw);
    for kv in &p.form_pairs {
        let k = String::from_utf8_lossy(&kv.name).into_owned();
        let v = String::from_utf8_lossy(&kv.value).into_owned();
        match p.form.get_mut(&k) {
            Some(prev) => {
                prev.push(',');
                prev.push_str(&v);
            }
            None => {
                p.form.insert(k, v);
            }
        }
    }
}

/// Every '&'-separated pair, leniently unescaped.
pub fn read_form_pairs(s: &[u8]) -> Vec<FormValue> {
    s.split(|&c| c == b'&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = match pair.iter().position(|&c| c == b'=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => (pair, &b""[..]),
            };
            FormValue {
                name: unescape_form_leniently(k),
                value: unescape_form_leniently(v),
            }
        })
        .collect()
}

pub fn append_map_entry(m: &mut BTreeMap<String, String>, key: &str, value: &str) {
    if let Some(prev) = m.get_mut(key)
        && !prev.is_empty()
    {
        prev.push(',');
        prev.push_str(value);
        return;
    }
    m.insert(key.to_string(), value.to_string());
}

pub fn scalar_text(v: &DynamicJson) -> Option<String> {
    match v {
        DynamicJson::String(s) => Some(s.clone()),
        DynamicJson::Bool(b) => Some(b.to_string()),
        DynamicJson::Number(n) => Some(n.clone()),
        _ => None,
    }
}

/// Every node a pointer names ("*" segments, keys
/// case-insensitive, sorted).
pub fn resolve_pointer_nodes<'a>(
    root: Option<&'a DynamicJson>,
    pointer: &str,
) -> Vec<Option<&'a DynamicJson>> {
    if pointer.is_empty() {
        return vec![root];
    }
    let Some(rest) = pointer.strip_prefix('/') else {
        return Vec::new();
    };
    let mut cur: Vec<Option<&DynamicJson>> = vec![root];
    for raw in rest.split('/') {
        let seg = raw.replace("~1", "/").replace("~0", "~");
        let mut next = Vec::new();
        for node in cur.iter().copied().flatten() {
            match node {
                DynamicJson::Object(m) => {
                    for (k, v) in m {
                        if raw == "*" || eq_ignore_case(k.as_bytes(), seg.as_bytes()) {
                            next.push(Some(v));
                        }
                    }
                }
                DynamicJson::Array(a) => {
                    if raw == "*" {
                        next.extend(a.iter().map(Some));
                    } else if let Ok(idx) = wafio_bytetext::literal::parse_decimal(seg.as_bytes())
                        && idx >= 0
                        && (idx as usize) < a.len()
                    {
                        next.push(Some(&a[idx as usize]));
                    }
                }
                _ => {}
            }
        }
        if next.is_empty() {
            return Vec::new();
        }
        cur = next;
    }
    cur
}

pub fn json_pointer_value(p: Option<&ParsedBody>, pointer: &str, body_scope: &str) -> Vec<u8> {
    let Some(p) = p else { return Vec::new() };
    if pointer.is_empty() {
        return join_values_in_key_order(&p.json_flat, false).into_bytes();
    }
    let nodes = resolve_pointer_nodes(p.json.as_ref(), pointer);
    if nodes.len() == 1 {
        return json_node_text(nodes[0], body_scope)
            .map(|s| s.0)
            .unwrap_or_default()
            .into_bytes();
    }
    json_node_values(&nodes, body_scope).join(&b"\n"[..])
}

pub fn json_node_values(nodes: &[Option<&DynamicJson>], body_scope: &str) -> Vec<Vec<u8>> {
    nodes
        .iter()
        .filter_map(|n| json_node_text(*n, body_scope))
        .filter(|(s, ok)| *ok && !s.is_empty())
        .map(|(s, _)| s.into_bytes())
        .collect()
}

fn json_node_text(node: Option<&DynamicJson>, body_scope: &str) -> Option<(String, bool)> {
    let (keys, vals): (Vec<String>, Vec<String>) = match node {
        Some(DynamicJson::Object(m)) => (
            m.keys().cloned().collect(),
            m.values().filter_map(scalar_text).collect(),
        ),
        Some(DynamicJson::Array(a)) => (
            (0..a.len()).map(|i| i.to_string()).collect(),
            a.iter().filter_map(scalar_text).collect(),
        ),
        Some(v) => return Some(scalar_text(v).map_or((String::new(), false), |s| (s, true))),
        None => return Some((String::new(), false)),
    };
    let scope = String::from_utf8_lossy(&wafio_bytetext::strings::to_lowercase(
        wafio_bytetext::strings::trim_whitespace(body_scope.as_bytes()),
    ))
    .into_owned();
    Some(match scope.as_str() {
        "key" => (keys.join("\n"), true),
        "value" => (vals.join("\n"), true),
        _ => ([keys, vals].concat().join("\n"), true),
    })
}

/// Values in key order, "\n"-joined.
pub fn join_values_in_key_order(m: &BTreeMap<String, String>, skip_empty: bool) -> String {
    m.values()
        .filter(|v| !(skip_empty && v.is_empty()))
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}
