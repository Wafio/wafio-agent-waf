//! The control plane's JSON decoding semantics over `wafio_domain::json_text::Value`, for the
//! hand-written decoders of the rules structs: syntax errors with the control plane's scanner
//! messages, struct keys matched exactly then case-insensitively, a repeated key decoded into the
//! same field (merge), type errors saved and decoding continued (first one reported, with its
//! `Struct.field` context), errors returned by a field's own decoder aborting the decode.

use std::collections::BTreeMap;
use std::fmt;

pub use wafio_domain::json_text::Value;
use wafio_domain::text_helpers::eq_ignore_case;

/// A JSON decode error; its message is the text the control plane's decoder prints.
#[derive(Clone, Debug, PartialEq)]
pub enum JsonDecodeError {
    /// A syntax error.
    Syntax(String),
    /// A value of the wrong type for its field.
    Type {
        value: String,
        type_name: String,
        struct_name: String,
        field: String,
    },
    /// Any other error (from a field's own decoder, validation).
    Message(String),
}

impl fmt::Display for JsonDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonDecodeError::Syntax(m) | JsonDecodeError::Message(m) => f.write_str(m),
            JsonDecodeError::Type {
                value,
                type_name: ty,
                struct_name: strukt,
                field,
            } => {
                if !strukt.is_empty() || !field.is_empty() {
                    write!(
                        f,
                        "json: cannot unmarshal {value} into Go struct field {strukt}.{field} of type {ty}"
                    )
                } else {
                    write!(
                        f,
                        "json: cannot unmarshal {value} into Go value of type {ty}"
                    )
                }
            }
        }
    }
}

impl JsonDecodeError {
    pub fn from_message(s: impl Into<String>) -> JsonDecodeError {
        JsonDecodeError::Message(s.into())
    }
    /// Prefixes the message: `prefix: <message>`.
    pub fn wrap(self, prefix: &str) -> JsonDecodeError {
        JsonDecodeError::Message(format!("{prefix}: {self}"))
    }
}

/// Decode state of one decode call.
#[derive(Default)]
pub struct DecodeTrace {
    saved: Option<JsonDecodeError>,
    struct_name: &'static str,
    fields: Vec<String>,
}

impl DecodeTrace {
    fn add_context(&self, err: JsonDecodeError) -> JsonDecodeError {
        if self.struct_name.is_empty() && self.fields.is_empty() {
            return err;
        }
        match err {
            JsonDecodeError::Type {
                value,
                type_name: ty,
                field,
                ..
            } => {
                let mut stack = self.fields.clone();
                if !field.is_empty() {
                    stack.push(field);
                }
                JsonDecodeError::Type {
                    value,
                    type_name: ty,
                    struct_name: self.struct_name.to_string(),
                    field: stack.join("."),
                }
            }
            e => e,
        }
    }

    /// Records a type mismatch; only the first one is kept.
    pub fn record_type_mismatch(&mut self, value: impl Into<String>, ty: &str) {
        if self.saved.is_none() {
            let e = JsonDecodeError::Type {
                value: value.into(),
                type_name: ty.to_string(),
                struct_name: String::new(),
                field: String::new(),
            };
            self.saved = Some(self.add_context(e));
        }
    }

    fn record_kind_mismatch(&mut self, v: &Value, ty: &str) {
        self.record_type_mismatch(v.type_name(), ty);
    }
}

/// Parses `data`, then decodes it into `x` with `decode`.
pub fn decode_into<T>(
    data: &[u8],
    x: &mut T,
    decode: impl FnOnce(&mut DecodeTrace, &Value, &mut T) -> Result<(), JsonDecodeError>,
) -> Result<(), JsonDecodeError> {
    let v = parse(data)?;
    decode_value_into(&v, x, decode)
}

/// Decodes an already parsed value into `x` with `decode`.
pub fn decode_value_into<T>(
    v: &Value,
    x: &mut T,
    decode: impl FnOnce(&mut DecodeTrace, &Value, &mut T) -> Result<(), JsonDecodeError>,
) -> Result<(), JsonDecodeError> {
    let mut d = DecodeTrace::default();
    if let Err(e) = decode(&mut d, v, x) {
        return Err(d.add_context(e));
    }
    match d.saved {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Parses a document, with the control plane's syntax error message on invalid input.
pub fn parse(data: &[u8]) -> Result<Value, JsonDecodeError> {
    if let Some(msg) = find_syntax_error(data) {
        return Err(JsonDecodeError::Syntax(msg));
    }
    wafio_domain::json_text::parse(data).map_err(|_| JsonDecodeError::Syntax("invalid JSON".into()))
}

// ---- syntax check and its error messages -----------------------------------------------

const NESTING_DEPTH_LIMIT: usize = 10000;

fn quote_byte_for_message(c: u8) -> String {
    match c {
        b'\'' => "'\\''".into(),
        b'"' => "'\"'".into(),
        _ => {
            let r = c as u32;
            let inner = match c {
                0x07 => "\\a".to_string(),
                0x08 => "\\b".to_string(),
                0x0C => "\\f".to_string(),
                b'\n' => "\\n".to_string(),
                b'\r' => "\\r".to_string(),
                b'\t' => "\\t".to_string(),
                0x0B => "\\v".to_string(),
                b'\\' => "\\\\".to_string(),
                c if c < 0x20 || c == 0x7f => format!("\\x{c:02x}"),
                c if c < 0x80 => (c as char).to_string(),
                // A byte of 0x80 or more is the code point U+0080..U+00FF; the non-printable ones are
                // escaped.
                _ if r < 0xA0 || r == 0xAD => format!("\\u{r:04x}"),
                _ => char::from_u32(r).unwrap().to_string(),
            };
            format!("'{inner}'")
        }
    }
}

struct SyntaxChecker<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
}

type CheckResult = Result<(), String>;

impl SyntaxChecker<'_> {
    fn eof() -> String {
        "unexpected end of JSON input".into()
    }
    fn bad(c: u8, ctx: &str) -> String {
        format!("invalid character {} {ctx}", quote_byte_for_message(c))
    }
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn push(&mut self, c: u8) -> CheckResult {
        self.depth += 1;
        if self.depth > NESTING_DEPTH_LIMIT {
            return Err(Self::bad(c, "exceeded max depth"));
        }
        Ok(())
    }
    fn value(&mut self) -> CheckResult {
        self.ws();
        let Some(c) = self.peek() else {
            return Err(Self::eof());
        };
        self.i += 1;
        match c {
            b'{' => {
                self.push(c)?;
                self.ws();
                match self.peek() {
                    None => return Err(Self::eof()),
                    Some(b'}') => {
                        self.i += 1;
                        self.depth -= 1;
                        return Ok(());
                    }
                    _ => {}
                }
                loop {
                    self.ws();
                    match self.peek() {
                        None => return Err(Self::eof()),
                        Some(b'"') => {
                            self.i += 1;
                            self.string()?
                        }
                        Some(c) => {
                            return Err(Self::bad(c, "looking for beginning of object key string"));
                        }
                    }
                    self.ws();
                    match self.peek() {
                        None => return Err(Self::eof()),
                        Some(b':') => self.i += 1,
                        Some(c) => return Err(Self::bad(c, "after object key")),
                    }
                    self.value()?;
                    self.ws();
                    match self.peek() {
                        None => return Err(Self::eof()),
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            self.depth -= 1;
                            return Ok(());
                        }
                        Some(c) => return Err(Self::bad(c, "after object key:value pair")),
                    }
                }
            }
            b'[' => {
                self.push(c)?;
                self.ws();
                match self.peek() {
                    None => return Err(Self::eof()),
                    Some(b']') => {
                        self.i += 1;
                        self.depth -= 1;
                        return Ok(());
                    }
                    _ => {}
                }
                loop {
                    self.value()?;
                    self.ws();
                    match self.peek() {
                        None => return Err(Self::eof()),
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            self.depth -= 1;
                            return Ok(());
                        }
                        Some(c) => return Err(Self::bad(c, "after array element")),
                    }
                }
            }
            b'"' => self.string(),
            b't' => self.lit(b"rue", "in literal true (expecting "),
            b'f' => self.lit(b"alse", "in literal false (expecting "),
            b'n' => self.lit(b"ull", "in literal null (expecting "),
            b'-' => {
                match self.peek() {
                    None => return Err(Self::eof()),
                    Some(b'0') => self.i += 1,
                    Some(b'1'..=b'9') => self.digits(),
                    Some(c) => return Err(Self::bad(c, "in numeric literal")),
                }
                self.number_tail()
            }
            b'0' => self.number_tail(),
            b'1'..=b'9' => {
                self.digits();
                self.number_tail()
            }
            c => Err(Self::bad(c, "looking for beginning of value")),
        }
    }
    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
    }
    fn number_tail(&mut self) -> CheckResult {
        if self.peek() == Some(b'.') {
            self.i += 1;
            match self.peek() {
                None => return Err(Self::eof()),
                Some(b'0'..=b'9') => self.digits(),
                Some(c) => return Err(Self::bad(c, "after decimal point in numeric literal")),
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            match self.peek() {
                None => return Err(Self::eof()),
                Some(b'0'..=b'9') => self.digits(),
                Some(c) => return Err(Self::bad(c, "in exponent of numeric literal")),
            }
        }
        Ok(())
    }
    fn lit(&mut self, rest: &[u8], ctx: &str) -> CheckResult {
        for &want in rest {
            match self.peek() {
                None => return Err(Self::eof()),
                Some(c) if c == want => self.i += 1,
                Some(c) => return Err(Self::bad(c, &format!("{ctx}'{}')", want as char))),
            }
        }
        Ok(())
    }
    fn string(&mut self) -> CheckResult {
        loop {
            let Some(c) = self.peek() else {
                return Err(Self::eof());
            };
            self.i += 1;
            match c {
                b'"' => return Ok(()),
                b'\\' => {
                    let Some(e) = self.peek() else {
                        return Err(Self::eof());
                    };
                    self.i += 1;
                    match e {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            for _ in 0..4 {
                                match self.peek() {
                                    None => return Err(Self::eof()),
                                    Some(h) if h.is_ascii_hexdigit() => self.i += 1,
                                    Some(h) => {
                                        return Err(Self::bad(
                                            h,
                                            "in \\u hexadecimal character escape",
                                        ));
                                    }
                                }
                            }
                        }
                        e => return Err(Self::bad(e, "in string escape code")),
                    }
                }
                c if c < 0x20 => return Err(Self::bad(c, "in string literal")),
                _ => {}
            }
        }
    }
}

/// None when data is one valid JSON value, else the control plane's syntax error message.
pub fn find_syntax_error(data: &[u8]) -> Option<String> {
    let mut c = SyntaxChecker {
        s: data,
        i: 0,
        depth: 0,
    };
    if let Err(e) = c.value() {
        return Some(e);
    }
    c.ws();
    c.peek()
        .map(|ch| SyntaxChecker::bad(ch, "after top-level value"))
}

// ---- value decoders ---------------------------------------------------------------------

fn key_str(k: &[u8]) -> String {
    String::from_utf8_lossy(k).into_owned()
}

/// Decodes a JSON object into a struct with the given JSON field names: `each(d, index,
/// value)` decodes one member into field `fields[index]`. `ty` is the type name an
/// error reports (`engine.PathBlockConfig`), `struct_name` its bare name.
pub fn object<'v>(
    d: &mut DecodeTrace,
    v: &'v Value,
    ty: &str,
    strukt: &'static str,
    fields: &[&str],
    mut each: impl FnMut(&mut DecodeTrace, usize, &'v Value) -> Result<(), JsonDecodeError>,
) -> Result<(), JsonDecodeError> {
    let members = match v {
        Value::Null => return Ok(()),
        Value::Object(m) => m,
        other => {
            d.record_kind_mismatch(other, ty);
            return Ok(());
        }
    };
    for (k, val) in members {
        let idx = fields
            .iter()
            .position(|f| f.as_bytes() == k.as_slice())
            .or_else(|| fields.iter().position(|f| eq_ignore_case(f.as_bytes(), k)));
        let Some(idx) = idx else { continue };
        let (os, ol) = (d.struct_name, d.fields.len());
        d.struct_name = strukt;
        d.fields.push(fields[idx].to_string());
        each(&mut *d, idx, val)?;
        d.fields.truncate(ol);
        d.struct_name = os;
    }
    Ok(())
}

pub fn string(d: &mut DecodeTrace, v: &Value, out: &mut String) {
    match v {
        Value::Null => {}
        Value::String(s) => *out = key_str(s),
        other => d.record_kind_mismatch(other, "string"),
    }
}

pub fn boolean(d: &mut DecodeTrace, v: &Value, out: &mut bool) {
    match v {
        Value::Null => {}
        Value::Bool(b) => *out = *b,
        other => d.record_kind_mismatch(other, "bool"),
    }
}

/// Parses a base-10 64-bit integer.
pub fn parse_int(s: &[u8]) -> Option<i64> {
    std::str::from_utf8(s).ok()?.parse::<i64>().ok()
}

/// An integer field: `ty` (`int` or `int64`) names it in errors.
pub fn int_as(d: &mut DecodeTrace, v: &Value, out: &mut i64, ty: &str) {
    match v {
        Value::Null => {}
        Value::Number(lit) => match parse_int(lit) {
            Some(n) => *out = n,
            None => d.record_type_mismatch(format!("number {}", key_str(lit)), ty),
        },
        other => d.record_kind_mismatch(other, ty),
    }
}

pub fn int(d: &mut DecodeTrace, v: &Value, out: &mut i64) {
    int_as(d, v, out, "int");
}

pub fn float(d: &mut DecodeTrace, v: &Value, out: &mut f64) {
    match v {
        Value::Null => {}
        Value::Number(lit) => match std::str::from_utf8(lit)
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|f| f.is_finite())
        {
            Some(f) => *out = f,
            None => d.record_type_mismatch(format!("number {}", key_str(lit)), "float64"),
        },
        other => d.record_kind_mismatch(other, "float64"),
    }
}

/// A pointer field: null sets None, anything else decodes into the existing value or a
/// new zero one (allocated even when the decode then fails).
pub fn optional<T: Default>(
    d: &mut DecodeTrace,
    v: &Value,
    out: &mut Option<T>,
    inner: impl FnOnce(&mut DecodeTrace, &Value, &mut T) -> Result<(), JsonDecodeError>,
) -> Result<(), JsonDecodeError> {
    if matches!(v, Value::Null) {
        *out = None;
        return Ok(());
    }
    inner(d, v, out.get_or_insert_with(T::default))
}

/// A slice field: null empties it, an array decodes element i into the existing element
/// i (or a new zero one) and truncates to the array length.
pub fn slice<T: Default>(
    d: &mut DecodeTrace,
    v: &Value,
    out: &mut Vec<T>,
    ty: &str,
    mut elem: impl FnMut(&mut DecodeTrace, &Value, &mut T) -> Result<(), JsonDecodeError>,
) -> Result<(), JsonDecodeError> {
    match v {
        Value::Null => out.clear(),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                if i >= out.len() {
                    out.push(T::default());
                }
                elem(&mut *d, item, &mut out[i])?;
            }
            out.truncate(items.len());
        }
        other => d.record_kind_mismatch(other, ty),
    }
    Ok(())
}

pub fn strings(
    d: &mut DecodeTrace,
    v: &Value,
    out: &mut Vec<String>,
) -> Result<(), JsonDecodeError> {
    slice(d, v, out, "[]string", |d, v, s| {
        string(d, v, s);
        Ok(())
    })
}

/// A map field with string keys: null empties it; each member decodes into a fresh zero T and
/// replaces the entry (last duplicate wins). Map keys never enter the error context.
pub fn map<T: Default>(
    d: &mut DecodeTrace,
    v: &Value,
    out: &mut BTreeMap<String, T>,
    ty: &str,
    mut elem: impl FnMut(&mut DecodeTrace, &Value, &mut T) -> Result<(), JsonDecodeError>,
) -> Result<(), JsonDecodeError> {
    match v {
        Value::Null => out.clear(),
        Value::Object(members) => {
            for (k, val) in members {
                let mut t = T::default();
                elem(&mut *d, val, &mut t)?;
                out.insert(key_str(k), t);
            }
        }
        other => d.record_kind_mismatch(other, ty),
    }
    Ok(())
}

/// Decodes an object into its raw members: Ok(None) for null, members last-wins in key order.
pub fn raw_map(v: &Value) -> Result<Option<BTreeMap<String, &Value>>, JsonDecodeError> {
    match v {
        Value::Null => Ok(None),
        Value::Object(members) => {
            let mut m = BTreeMap::new();
            for (k, val) in members {
                m.insert(key_str(k), val);
            }
            Ok(Some(m))
        }
        other => Err(JsonDecodeError::Type {
            value: other.type_name().into(),
            type_name: "map[string]json.RawMessage".into(),
            struct_name: String::new(),
            field: String::new(),
        }),
    }
}

pub fn is_null(v: &Value) -> bool {
    matches!(v, Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_messages_match_reference() {
        for (input, want) in [
            ("", "unexpected end of JSON input"),
            ("{", "unexpected end of JSON input"),
            ("x", "invalid character 'x' looking for beginning of value"),
            ("{\"a\" 1}", "invalid character '1' after object key"),
            (
                "{\"a\":1 \"b\"}",
                "invalid character '\"' after object key:value pair",
            ),
            ("[1 2]", "invalid character '2' after array element"),
            ("01", "invalid character '1' after top-level value"),
            ("tru", "unexpected end of JSON input"),
            (
                "trux",
                "invalid character 'x' in literal true (expecting 'e')",
            ),
            (
                "{,}",
                "invalid character ',' looking for beginning of object key string",
            ),
            ("\"\\x\"", "invalid character 'x' in string escape code"),
            (
                "1.x",
                "invalid character 'x' after decimal point in numeric literal",
            ),
            ("-x", "invalid character 'x' in numeric literal"),
            (
                "1ex",
                "invalid character 'x' in exponent of numeric literal",
            ),
            ("\"\x01\"", "invalid character '\\x01' in string literal"),
        ] {
            assert_eq!(
                find_syntax_error(input.as_bytes()).as_deref().unwrap_or(""),
                want,
                "{input:?}"
            );
        }
        assert_eq!(find_syntax_error(b"{\"a\":[1,true,null,\"x\"]}"), None);
    }

    #[test]
    fn struct_decode_matches_reference() {
        #[derive(Default)]
        struct S {
            a: i64,
            b: String,
        }
        let mut s = S::default();
        let err = decode_into(br#"{"A":1,"b":2,"B":"x"}"#, &mut s, |d, v, s| {
            object(d, v, "engine.S", "S", &["a", "b"], |d, i, v| {
                match i {
                    0 => int(d, v, &mut s.a),
                    _ => string(d, v, &mut s.b),
                }
                Ok(())
            })
        })
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "json: cannot unmarshal number into Go struct field S.b of type string"
        );
        assert_eq!((s.a, s.b.as_str()), (1, "x"));
    }
}
