//! The slice of struct decoding the control link needs: top-level object members matched to
//! field names case-insensitively, last occurrence wins, `null` leaves a scalar field unchanged,
//! and the decoder's error texts (syntax errors, type errors). Values stay raw so a bundle is
//! handed on verbatim.

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use std::fmt;
use wafio_engine_rules::json_decode::{JsonDecodeError, find_syntax_error};

/// A type error as its text prints it (`strukt`/`field` empty at top level).
fn type_error(strukt: &str, field: &str, value: &str, ty: &str) -> String {
    JsonDecodeError::Type {
        value: value.into(),
        type_name: ty.into(),
        struct_name: strukt.into(),
        field: field.into(),
    }
    .to_string()
}

/// The name of the kind of a valid JSON value starting with byte `b` (`null` aside).
fn kind(b: u8) -> &'static str {
    match b {
        b'{' => "object",
        b'[' => "array",
        b'"' => "string",
        b't' | b'f' => "bool",
        _ => "number",
    }
}

/// Top-level members of a JSON object in document order, for decoding into the struct named
/// `target_type`. `null` is an object with no members (decoding `null` into a struct is a no-op);
/// any other non-object is a type error. A document the scanner rejects reports the scanner's
/// text, as validity is checked first.
pub(crate) fn members<'a>(
    json: &'a [u8],
    target_type: &str,
) -> Result<Vec<(String, &'a RawValue)>, String> {
    if let Some(e) = find_syntax_error(json) {
        return Err(e);
    }
    let first = json
        .iter()
        .copied()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .unwrap_or(b'n');
    if !matches!(first, b'{' | b'n') {
        return Err(type_error("", "", kind(first), target_type));
    }
    // shortcut: valid JSON serde still refuses (nesting beyond 128, a lone surrogate escape,
    // invalid UTF-8) keeps serde's text; none occurs in a control-plane bundle.
    serde_json::from_slice::<Members<'_>>(json)
        .map(|m| m.0)
        .map_err(|e| e.to_string())
}

struct Members<'a>(Vec<(String, &'a RawValue)>);

impl<'de> Deserialize<'de> for Members<'de> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Members<'de>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(Members(Vec::new()))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(k) = a.next_key::<String>()? {
                    out.push((k, a.next_value::<&'de RawValue>()?));
                }
                Ok(Members(out))
            }
        }
        d.deserialize_any(V)
    }
}

/// Field match for an ASCII field name: exact, else simple case fold.
/// The only non-ASCII runes that fold onto ASCII letters are U+017F (ſ → S) and
/// U+212A (Kelvin → K).
pub(crate) fn key_matches(key: &str, field: &str) -> bool {
    let mut f = field.bytes();
    for c in key.chars() {
        let folded = match c {
            '\u{17F}' => 'S',
            '\u{212A}' => 'K',
            c => c.to_ascii_uppercase(),
        };
        match f.next() {
            Some(b) if folded.is_ascii() && folded as u8 == b.to_ascii_uppercase() => {}
            _ => return false,
        }
    }
    f.next().is_none()
}

fn is_null(raw: &RawValue) -> bool {
    raw.get() == "null"
}

/// First byte of a raw value (never empty).
fn lead(raw: &RawValue) -> u8 {
    raw.get().as_bytes()[0]
}

/// An integer field `strukt.field` of type `ty`, parsed from the literal as an integer (so `1.0`
/// and `1e2` fail, `-0` is 0); `null` keeps the previous value.
pub(crate) fn int64(
    raw: &RawValue,
    strukt: &str,
    field: &str,
    ty: &str,
) -> Result<Option<i64>, String> {
    if is_null(raw) {
        return Ok(None);
    }
    if kind(lead(raw)) != "number" {
        return Err(type_error(strukt, field, kind(lead(raw)), ty));
    }
    raw.get()
        .parse::<i64>()
        .map(Some)
        .map_err(|_| type_error(strukt, field, &format!("number {}", raw.get()), ty))
}

/// A bool field; `null` keeps the previous value.
pub(crate) fn boolean(raw: &RawValue, strukt: &str, field: &str) -> Result<Option<bool>, String> {
    match raw.get() {
        "null" => Ok(None),
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        _ => Err(type_error(strukt, field, kind(lead(raw)), "bool")),
    }
}

/// Length of a slice-of-struct field (`slice_ty` is the slice type name, `elem_ty` the element
/// type name): `null` is an empty slice; elements must be objects or `null` (their fields are the
/// full decoder's business).
pub(crate) fn struct_slice_len(
    raw: &RawValue,
    strukt: &str,
    field: &str,
    slice_ty: &str,
    elem_ty: &str,
) -> Result<usize, String> {
    if is_null(raw) {
        return Ok(0);
    }
    if lead(raw) != b'[' {
        return Err(type_error(strukt, field, kind(lead(raw)), slice_ty));
    }
    let items: Vec<&RawValue> = serde_json::from_str(raw.get()).map_err(|e| e.to_string())?;
    for it in &items {
        if !(lead(it) == b'{' || is_null(it)) {
            return Err(type_error(strukt, field, kind(lead(it)), elem_ty));
        }
    }
    Ok(items.len())
}

/// A time field: the raw literal is taken, so the quotes come off but no escape is resolved;
/// `null` keeps the previous value.
pub(crate) fn time_string(raw: &RawValue) -> Result<Option<&str>, String> {
    let s = raw.get();
    match s {
        "null" => Ok(None),
        _ if s.starts_with('"') => Ok(Some(&s[1..s.len() - 1])),
        _ => Err("Time.UnmarshalJSON: input is not a JSON string".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_matching_folds_case() {
        assert!(key_matches("generation", "generation"));
        assert!(key_matches("Generation", "generation"));
        assert!(key_matches("MANAGEMENT_ONLY", "management_only"));
        assert!(key_matches(
            "unbloc\u{212A}_entrie\u{17F}",
            "unblock_entries"
        ));
        assert!(!key_matches("generations", "generation"));
        assert!(!key_matches("generatio", "generation"));
        assert!(!key_matches("génération", "generation"));
    }

    #[test]
    fn members_last_wins_and_null() {
        let m = members(br#"{"generation":1,"Generation":2}"#, "agent.Bundle").unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(
            int64(m[1].1, "Bundle", "generation", "int64").unwrap(),
            Some(2)
        );
        assert!(members(b" null ", "agent.Bundle").unwrap().is_empty());
        let n = members(br#"{"g":-0,"h":1.0,"i":null}"#, "agent.Bundle").unwrap();
        assert_eq!(int64(n[0].1, "Bundle", "g", "int64").unwrap(), Some(0));
        assert!(int64(n[1].1, "Bundle", "h", "int64").is_err());
        assert_eq!(int64(n[2].1, "Bundle", "i", "int64").unwrap(), None);
    }

    /// The expected texts are the decoder's texts for the same documents.
    #[test]
    fn syntax_and_top_level_errors_use_decoder_texts() {
        for (doc, want) in [
            (&br#"{"apps":"#[..], "unexpected end of JSON input"),
            (b"", "unexpected end of JSON input"),
            (
                b"not json",
                "invalid character 'o' in literal null (expecting 'u')",
            ),
            (
                b"{\"a\":tru}",
                "invalid character '}' in literal true (expecting 'e')",
            ),
            (
                b"{\"a\":1,}",
                "invalid character '}' looking for beginning of object key string",
            ),
            (b"{\"a\" 1}", "invalid character '1' after object key"),
            (
                b"{\"a\":\"\\x\"}",
                "invalid character 'x' in string escape code",
            ),
            (
                b"{\"a\":01}",
                "invalid character '1' after object key:value pair",
            ),
            (b"{} x", "invalid character 'x' after top-level value"),
            (b"{\"a\":1", "unexpected end of JSON input"),
            (
                b"{\"a\":\"\x01\"}",
                "invalid character '\\x01' in string literal",
            ),
            (
                b"[1,2]",
                "json: cannot unmarshal array into Go value of type agent.Bundle",
            ),
            (
                b"\"x\"",
                "json: cannot unmarshal string into Go value of type agent.Bundle",
            ),
            (
                b"5",
                "json: cannot unmarshal number into Go value of type agent.Bundle",
            ),
            (
                b"true",
                "json: cannot unmarshal bool into Go value of type agent.Bundle",
            ),
        ] {
            assert_eq!(
                members(doc, "agent.Bundle").unwrap_err(),
                want,
                "{}",
                String::from_utf8_lossy(doc)
            );
        }
    }

    #[test]
    fn field_type_errors_use_decoder_texts() {
        fn field(doc: &str) -> &RawValue {
            members(doc.as_bytes(), "agent.Bundle").unwrap()[0].1
        }
        let int = |d: &str| int64(field(d), "Bundle", "generation", "int64").unwrap_err();
        assert_eq!(
            int(r#"{"generation":"3"}"#),
            "json: cannot unmarshal string into Go struct field Bundle.generation of type int64"
        );
        for lit in ["1.5", "1e2", "99999999999999999999"] {
            assert_eq!(
                int(&format!(r#"{{"generation":{lit}}}"#)),
                format!(
                    "json: cannot unmarshal number {lit} into Go struct field Bundle.generation of type int64"
                )
            );
        }
        assert_eq!(
            int64(
                field(r#"{"version":true}"#),
                "bundleCacheEnvelope",
                "version",
                "int"
            )
            .unwrap_err(),
            "json: cannot unmarshal bool into Go struct field bundleCacheEnvelope.version of type int"
        );
        let b = |d: &str| boolean(field(d), "Bundle", "management_only").unwrap_err();
        assert_eq!(
            b(r#"{"management_only":"yes"}"#),
            "json: cannot unmarshal string into Go struct field Bundle.management_only of type bool"
        );
        assert_eq!(
            b(r#"{"management_only":1}"#),
            "json: cannot unmarshal number into Go struct field Bundle.management_only of type bool"
        );
        let s = |d: &str| {
            struct_slice_len(
                field(d),
                "Bundle",
                "apps",
                "[]agent.BundleApp",
                "agent.BundleApp",
            )
        };
        for (doc, want) in [
            (
                r#"{"apps":[1]}"#,
                "number into Go struct field Bundle.apps of type agent.BundleApp",
            ),
            (
                r#"{"apps":[true]}"#,
                "bool into Go struct field Bundle.apps of type agent.BundleApp",
            ),
            (
                r#"{"apps":[[1]]}"#,
                "array into Go struct field Bundle.apps of type agent.BundleApp",
            ),
            (
                r#"{"apps":[{"a":1},"x"]}"#,
                "string into Go struct field Bundle.apps of type agent.BundleApp",
            ),
            (
                r#"{"apps":5}"#,
                "number into Go struct field Bundle.apps of type []agent.BundleApp",
            ),
            (
                r#"{"apps":{}}"#,
                "object into Go struct field Bundle.apps of type []agent.BundleApp",
            ),
        ] {
            assert_eq!(
                s(doc).unwrap_err(),
                format!("json: cannot unmarshal {want}"),
                "{doc}"
            );
        }
        assert_eq!(s(r#"{"apps":[null,{}]}"#), Ok(2));
        assert_eq!(s(r#"{"apps":null}"#), Ok(0));
        assert_eq!(
            time_string(field(r#"{"saved_at":5}"#)).unwrap_err(),
            "Time.UnmarshalJSON: input is not a JSON string"
        );
        assert_eq!(
            time_string(field(r#"{"saved_at":"2026\u002d11"}"#)),
            Ok(Some(r"2026\u002d11"))
        );
        assert_eq!(time_string(field(r#"{"saved_at":null}"#)), Ok(None));
    }
}
