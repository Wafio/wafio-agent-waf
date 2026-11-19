//! The WAF bundle types (`Bundle`, `BundleApp`, `UnblockEntry`) and their JSON decoding: keys matched
//! exactly then case-insensitively, a repeated key decoded again into the same field, type
//! errors reported after the whole decode, unknown keys ignored, and every raw message field
//! holding the input bytes verbatim (`null` included).

use std::collections::HashMap;

use wafio_engine_rules::json_decode::{self, DecodeTrace, JsonDecodeError, Value};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BundleApp {
    pub app_id: String,
    pub listen_host: String,
    pub listen_port: i64,
    pub aliases: Vec<String>,
    pub upstream: String,
    pub mode: String,
    pub body_limit: i64,
    /// Raw JSON; empty = absent.
    pub rules_json: Vec<u8>,
    pub proxy_config: Vec<u8>,
    pub fcgi_doc_root: String,
    pub fcgi_index: String,
    /// Keep FastCGI connections open between requests; the control plane sends the key only
    /// when it is on.
    pub fcgi_keep_conn: bool,
    pub custom_gui_rules: Vec<Vec<u8>>,
    pub custom_script_rules: Vec<Vec<u8>>,
    pub custom_tuning_rules: Vec<Vec<u8>>,
    /// Raw JSON of the maintenance object, present only while maintenance mode is on; empty = absent.
    pub maintenance: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnblockEntry {
    pub type_: String,
    pub scope: String,
    pub key: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Bundle {
    pub agent_id: String,
    pub project_id: String,
    pub generation: i64,
    pub apps: Vec<BundleApp>,
    pub rules_json: Vec<u8>,
    pub good_bot_cidrs: Vec<String>,
    pub unblock_entries: Vec<UnblockEntry>,
    pub management_only: bool,
}

/// Source span of every node of a parsed document, by node address.
struct Spans<'a> {
    src: &'a [u8],
    at: HashMap<*const Value, &'a [u8]>,
}

impl<'a> Spans<'a> {
    /// Walks `src` in step with `v` (both describe the same valid document).
    fn index(src: &'a [u8], v: &Value) -> Option<Spans<'a>> {
        let mut s = Spans {
            src,
            at: HashMap::new(),
        };
        let mut pos = 0;
        s.walk(v, &mut pos)?;
        Some(s)
    }

    fn ws(&self, pos: &mut usize) {
        while *pos < self.src.len() && matches!(self.src[*pos], b' ' | b'\t' | b'\n' | b'\r') {
            *pos += 1;
        }
    }

    fn expect(&self, pos: &mut usize, c: u8) -> Option<()> {
        self.ws(pos);
        (self.src.get(*pos) == Some(&c)).then(|| *pos += 1)
    }

    fn skip_string(&self, pos: &mut usize) -> Option<()> {
        self.ws(pos);
        (self.src.get(*pos) == Some(&b'"')).then_some(())?;
        *pos += 1;
        while *self.src.get(*pos)? != b'"' {
            *pos += if self.src[*pos] == b'\\' { 2 } else { 1 };
        }
        *pos += 1;
        Some(())
    }

    fn walk(&mut self, v: &Value, pos: &mut usize) -> Option<()> {
        self.ws(pos);
        let start = *pos;
        match v {
            Value::Object(members) => {
                self.expect(pos, b'{')?;
                for (i, (_, mv)) in members.iter().enumerate() {
                    if i > 0 {
                        self.expect(pos, b',')?;
                    }
                    self.skip_string(pos)?;
                    self.expect(pos, b':')?;
                    self.walk(mv, pos)?;
                }
                self.expect(pos, b'}')?;
            }
            Value::Array(items) => {
                self.expect(pos, b'[')?;
                for (i, iv) in items.iter().enumerate() {
                    if i > 0 {
                        self.expect(pos, b',')?;
                    }
                    self.walk(iv, pos)?;
                }
                self.expect(pos, b']')?;
            }
            Value::String(_) => self.skip_string(pos)?,
            Value::Null | Value::Bool(_) | Value::Number(_) => {
                while *pos < self.src.len()
                    && matches!(self.src[*pos], b'a'..=b'z' | b'0'..=b'9' | b'-' | b'+' | b'.' | b'E')
                {
                    *pos += 1;
                }
                (*pos > start).then_some(())?;
            }
        }
        self.at.insert(v as *const Value, &self.src[start..*pos]);
        Some(())
    }

    fn raw(&self, v: &Value) -> Vec<u8> {
        self.at
            .get(&(v as *const Value))
            .map(|s| s.to_vec())
            .unwrap_or_default()
    }
}

fn raw_slice(
    d: &mut DecodeTrace,
    sp: &Spans<'_>,
    v: &Value,
    out: &mut Vec<Vec<u8>>,
) -> Result<(), JsonDecodeError> {
    json_decode::slice(d, v, out, "[]object", |_, v, r| {
        *r = sp.raw(v);
        Ok(())
    })
}

const APP_FIELDS: [&str; 16] = [
    "app_id",
    "listen_host",
    "listen_port",
    "aliases",
    "upstream",
    "mode",
    "body_limit_bytes",
    "rules_json",
    "proxy_config",
    "fcgi_doc_root",
    "fcgi_index",
    "custom_gui_rules",
    "custom_script_rules",
    "custom_tuning_rules",
    "maintenance",
    "fcgi_keep_conn",
];

fn decode_app(
    d: &mut DecodeTrace,
    sp: &Spans<'_>,
    v: &Value,
    a: &mut BundleApp,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "agent.BundleApp",
        "BundleApp",
        &APP_FIELDS,
        |d, i, v| {
            match i {
                0 => json_decode::string(d, v, &mut a.app_id),
                1 => json_decode::string(d, v, &mut a.listen_host),
                2 => json_decode::int(d, v, &mut a.listen_port),
                3 => json_decode::strings(d, v, &mut a.aliases)?,
                4 => json_decode::string(d, v, &mut a.upstream),
                5 => json_decode::string(d, v, &mut a.mode),
                6 => json_decode::int(d, v, &mut a.body_limit),
                7 => a.rules_json = sp.raw(v),
                8 => a.proxy_config = sp.raw(v),
                9 => json_decode::string(d, v, &mut a.fcgi_doc_root),
                10 => json_decode::string(d, v, &mut a.fcgi_index),
                11 => raw_slice(d, sp, v, &mut a.custom_gui_rules)?,
                12 => raw_slice(d, sp, v, &mut a.custom_script_rules)?,
                13 => raw_slice(d, sp, v, &mut a.custom_tuning_rules)?,
                14 => a.maintenance = sp.raw(v),
                _ => json_decode::boolean(d, v, &mut a.fcgi_keep_conn),
            }
            Ok(())
        },
    )
}

fn decode_unblock(
    d: &mut DecodeTrace,
    v: &Value,
    u: &mut UnblockEntry,
) -> Result<(), JsonDecodeError> {
    json_decode::object(
        d,
        v,
        "agent.UnblockEntry",
        "UnblockEntry",
        &["type", "scope", "key"],
        |d, i, v| {
            match i {
                0 => json_decode::string(d, v, &mut u.type_),
                1 => json_decode::string(d, v, &mut u.scope),
                _ => json_decode::string(d, v, &mut u.key),
            }
            Ok(())
        },
    )
}

const BUNDLE_FIELDS: [&str; 8] = [
    "agent_id",
    "project_id",
    "generation",
    "apps",
    "rules_json",
    "good_bot_cidrs",
    "unblock_entries",
    "management_only",
];

/// Decodes a bundle from `raw`.
pub fn decode_bundle(raw: &[u8]) -> Result<Bundle, String> {
    let v = json_decode::parse(raw).map_err(|e| e.to_string())?;
    let sp = Spans::index(raw, &v).ok_or_else(|| "invalid JSON".to_string())?;
    let mut b = Bundle::default();
    json_decode::decode_value_into(&v, &mut b, |d, v, b| {
        json_decode::object(d, v, "agent.Bundle", "Bundle", &BUNDLE_FIELDS, |d, i, v| {
            match i {
                0 => json_decode::string(d, v, &mut b.agent_id),
                1 => json_decode::string(d, v, &mut b.project_id),
                2 => json_decode::int_as(d, v, &mut b.generation, "int64"),
                3 => json_decode::slice(d, v, &mut b.apps, "[]agent.BundleApp", |d, v, a| {
                    decode_app(d, &sp, v, a)
                })?,
                4 => b.rules_json = sp.raw(v),
                5 => json_decode::strings(d, v, &mut b.good_bot_cidrs)?,
                6 => json_decode::slice(
                    d,
                    v,
                    &mut b.unblock_entries,
                    "[]agent.UnblockEntry",
                    decode_unblock,
                )?,
                _ => json_decode::boolean(d, v, &mut b.management_only),
            }
            Ok(())
        })
    })
    .map_err(|e| e.to_string())?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_fields_keep_input_bytes() {
        let b = decode_bundle(
            br#"{"agent_id":"a1","Generation":7,"rules_json": { "thresholds" : {"block":150} } ,
               "apps":[{"app_id":"x","rules_json":null,"proxy_config":{ },"custom_gui_rules":[{"id":"r"}, null],
               "LISTEN_PORT":8080,"aliases":["A.example"]}],"unknown":[1,{"x":2}],"management_only":false}"#,
        )
        .unwrap();
        assert_eq!(b.agent_id, "a1");
        assert_eq!(b.generation, 7);
        assert_eq!(
            b.rules_json,
            br#"{ "thresholds" : {"block":150} }"#.to_vec()
        );
        let a = &b.apps[0];
        assert_eq!(a.rules_json, b"null".to_vec(), "RawMessage keeps null");
        assert_eq!(a.proxy_config, b"{ }".to_vec());
        assert_eq!(
            a.custom_gui_rules,
            vec![br#"{"id":"r"}"#.to_vec(), b"null".to_vec()]
        );
        assert_eq!(a.listen_port, 8080, "keys match case-insensitively");
        assert_eq!(a.aliases, vec!["A.example".to_string()]);
    }

    #[test]
    fn the_maintenance_object_is_kept_as_written() {
        let b = decode_bundle(
            br#"{"apps":[{"app_id":"x","maintenance":{ "enabled":true,"message":"Back soon","allow_ips":["10.0.0.1"] }},
               {"app_id":"y"},{"app_id":"z","Maintenance":null}]}"#,
        )
        .unwrap();
        assert_eq!(
            b.apps[0].maintenance,
            br#"{ "enabled":true,"message":"Back soon","allow_ips":["10.0.0.1"] }"#.to_vec()
        );
        assert!(b.apps[1].maintenance.is_empty(), "absent stays empty");
        assert_eq!(b.apps[2].maintenance, b"null".to_vec());
    }

    #[test]
    fn fcgi_keep_conn_is_read_and_defaults_to_off() {
        let b = decode_bundle(
            br#"{"apps":[{"app_id":"x","fcgi_keep_conn":true,"maintenance":{"enabled":true}},
               {"app_id":"y"},{"app_id":"z","fcgi_keep_conn":false}]}"#,
        )
        .unwrap();
        let on: Vec<bool> = b.apps.iter().map(|a| a.fcgi_keep_conn).collect();
        assert_eq!(on, [true, false, false]);
        assert_eq!(b.apps[0].maintenance, br#"{"enabled":true}"#.to_vec());
        assert!(b.apps[1].maintenance.is_empty());
    }

    #[test]
    fn repeated_keys_merge_into_one_value() {
        let b = decode_bundle(br#"{"apps":[{"app_id":"x","mode":"monitor"}],"apps":[{"upstream":"http://u"}],"rules_json":{"a":1},"rules_json":"s"}"#).unwrap();
        assert_eq!(b.apps.len(), 1);
        assert_eq!(
            b.apps[0].app_id, "x",
            "second decode merges into the existing element"
        );
        assert_eq!(b.apps[0].upstream, "http://u");
        assert_eq!(
            b.rules_json,
            br#""s""#.to_vec(),
            "RawMessage: last value wins"
        );
    }

    #[test]
    fn decode_error_texts() {
        assert_eq!(
            decode_bundle(br#"{"apps":[{"listen_port":"80"}]}"#).unwrap_err(),
            "apps.listen_port: expected an integer, got a string"
        );
        assert_eq!(
            decode_bundle(br#"{"generation":1.5}"#).unwrap_err(),
            "generation: expected an integer, got the number 1.5"
        );
        assert_eq!(
            decode_bundle(b"[]").unwrap_err(),
            "expected an object, got an array"
        );
        assert_eq!(
            decode_bundle(b"{").unwrap_err(),
            "unexpected end of JSON input"
        );
        assert_eq!(decode_bundle(b"null").unwrap(), Bundle::default());
    }
}
