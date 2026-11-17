//! The JSON helpers the domain needs: validation, string unquoting (invalid UTF-8 replaced), string
//! encoding, and an ordered document tree for hand-written struct decoders (struct keys
//! match case-insensitively, a repeated key merges into the same field).

use crate::text_helpers::{
    CodePoint, REPLACEMENT_CODE_POINT, decode_code_point, eq_ignore_case, push_code_point,
};

/// Nesting depth limit of the validator.
const NESTING_DEPTH_LIMIT: usize = 10000;

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

struct Validator<'a> {
    s: &'a [u8],
    i: usize,
}

impl Validator<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && is_ws(self.s[self.i]) {
            self.i += 1;
        }
    }

    fn lit(&mut self, w: &[u8]) -> bool {
        if self.s[self.i..].starts_with(w) {
            self.i += w.len();
            true
        } else {
            false
        }
    }

    fn digits(&mut self) -> usize {
        let st = self.i;
        while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
            self.i += 1;
        }
        self.i - st
    }

    fn number(&mut self) -> bool {
        if self.s.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        match self.s.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return false,
        }
        if self.s.get(self.i) == Some(&b'.') {
            self.i += 1;
            if self.digits() == 0 {
                return false;
            }
        }
        if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.s.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return false;
            }
        }
        true
    }

    fn string(&mut self) -> bool {
        self.i += 1;
        while self.i < self.s.len() {
            let c = self.s[self.i];
            match c {
                b'"' => {
                    self.i += 1;
                    return true;
                }
                b'\\' => {
                    self.i += 1;
                    match self.s.get(self.i) {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => self.i += 1,
                        Some(b'u') => {
                            self.i += 1;
                            for _ in 0..4 {
                                match self.s.get(self.i) {
                                    Some(h) if h.is_ascii_hexdigit() => self.i += 1,
                                    _ => return false,
                                }
                            }
                        }
                        _ => return false,
                    }
                }
                c if c < 0x20 => return false,
                _ => self.i += 1,
            }
        }
        false
    }

    /// Iterative value check (depth bounded by `NESTING_DEPTH_LIMIT`).
    fn value(&mut self) -> bool {
        // Stack of open containers: true = object.
        let mut stack: Vec<bool> = Vec::new();
        loop {
            self.ws();
            let Some(&c) = self.s.get(self.i) else {
                return false;
            };
            // Parse one value start.
            match c {
                b'{' | b'[' => {
                    self.i += 1;
                    stack.push(c == b'{');
                    if stack.len() > NESTING_DEPTH_LIMIT {
                        return false;
                    }
                    self.ws();
                    let close = if c == b'{' { b'}' } else { b']' };
                    if self.s.get(self.i) == Some(&close) {
                        self.i += 1;
                        stack.pop();
                    } else {
                        if c == b'{' && !self.key() {
                            return false;
                        }
                        continue;
                    }
                }
                b'"' => {
                    if !self.string() {
                        return false;
                    }
                }
                b't' => {
                    if !self.lit(b"true") {
                        return false;
                    }
                }
                b'f' => {
                    if !self.lit(b"false") {
                        return false;
                    }
                }
                b'n' => {
                    if !self.lit(b"null") {
                        return false;
                    }
                }
                b'-' | b'0'..=b'9' => {
                    if !self.number() {
                        return false;
                    }
                }
                _ => return false,
            }
            // After a complete value: close containers or take a comma.
            loop {
                let Some(&obj) = stack.last() else {
                    return true;
                };
                self.ws();
                match self.s.get(self.i) {
                    Some(b',') => {
                        self.i += 1;
                        if obj && !self.key() {
                            return false;
                        }
                        break;
                    }
                    Some(b'}') if obj => {
                        self.i += 1;
                        stack.pop();
                    }
                    Some(b']') if !obj => {
                        self.i += 1;
                        stack.pop();
                    }
                    _ => return false,
                }
            }
        }
    }

    /// An object key and its colon.
    fn key(&mut self) -> bool {
        self.ws();
        if self.s.get(self.i) != Some(&b'"') || !self.string() {
            return false;
        }
        self.ws();
        if self.s.get(self.i) != Some(&b':') {
            return false;
        }
        self.i += 1;
        true
    }
}

pub fn is_valid_json(data: &[u8]) -> bool {
    let mut v = Validator { s: data, i: 0 };
    if !v.value() {
        return false;
    }
    v.ws();
    v.i == data.len()
}

fn parse_hex4(s: &[u8]) -> Option<CodePoint> {
    if s.len() < 6 || s[0] != b'\\' || s[1] != b'u' {
        return None;
    }
    let h = std::str::from_utf8(&s[2..6]).ok()?;
    if !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    i32::from_str_radix(h, 16).ok()
}

/// Decodes a JSON string literal (quotes included): escapes decoded, invalid UTF-8 and lone
/// surrogates become U+FFFD. None for a malformed literal.
pub fn unquote_json_string(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 2 || raw[0] != b'"' || raw[raw.len() - 1] != b'"' {
        return None;
    }
    let s = &raw[1..raw.len() - 1];
    let mut b = Vec::with_capacity(s.len());
    let mut r = 0;
    while r < s.len() {
        let c = s[r];
        match c {
            b'\\' => {
                r += 1;
                let e = *s.get(r)?;
                match e {
                    b'"' | b'\\' | b'/' | b'\'' => {
                        b.push(e);
                        r += 1;
                    }
                    b'b' => (b.push(0x08), r += 1).1,
                    b'f' => (b.push(0x0C), r += 1).1,
                    b'n' => (b.push(b'\n'), r += 1).1,
                    b'r' => (b.push(b'\r'), r += 1).1,
                    b't' => (b.push(b'\t'), r += 1).1,
                    b'u' => {
                        r -= 1;
                        let mut rr = parse_hex4(&s[r..])?;
                        r += 6;
                        if (0xD800..0xE000).contains(&rr) {
                            let rr1 = parse_hex4(&s[r..]);
                            if let Some(rr1) = rr1
                                && (0xD800..0xDC00).contains(&rr)
                                && (0xDC00..0xE000).contains(&rr1)
                            {
                                r += 6;
                                push_code_point(
                                    &mut b,
                                    (((rr - 0xD800) << 10) | (rr1 - 0xDC00)) + 0x10000,
                                );
                                continue;
                            }
                            rr = REPLACEMENT_CODE_POINT;
                        }
                        push_code_point(&mut b, rr);
                    }
                    _ => return None,
                }
            }
            b'"' => return None,
            c if c < b' ' => return None,
            c if c < 0x80 => {
                b.push(c);
                r += 1;
            }
            _ => {
                let (rr, size) = decode_code_point(&s[r..]);
                r += size;
                push_code_point(&mut b, rr);
            }
        }
    }
    Some(b)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Appends `s` as a JSON string (HTML-escaped, invalid UTF-8
/// as `�`, U+2028/U+2029 escaped).
pub fn append_quoted_string(dst: &mut Vec<u8>, src: &[u8]) {
    dst.push(b'"');
    let mut start = 0;
    let mut i = 0;
    while i < src.len() {
        let b = src[i];
        if b < 0x80 {
            if b >= 0x20 && b != b'"' && b != b'\\' && b != b'<' && b != b'>' && b != b'&' {
                i += 1;
                continue;
            }
            dst.extend_from_slice(&src[start..i]);
            match b {
                b'\\' | b'"' => dst.extend_from_slice(&[b'\\', b]),
                0x08 => dst.extend_from_slice(b"\\b"),
                0x0C => dst.extend_from_slice(b"\\f"),
                b'\n' => dst.extend_from_slice(b"\\n"),
                b'\r' => dst.extend_from_slice(b"\\r"),
                b'\t' => dst.extend_from_slice(b"\\t"),
                _ => dst.extend_from_slice(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[usize::from(b >> 4)],
                    HEX[usize::from(b & 0xF)],
                ]),
            }
            i += 1;
            start = i;
            continue;
        }
        let (c, size) = decode_code_point(&src[i..]);
        if c == REPLACEMENT_CODE_POINT && size == 1 {
            dst.extend_from_slice(&src[start..i]);
            dst.extend_from_slice(b"\\ufffd");
            i += 1;
            start = i;
            continue;
        }
        if c == 0x2028 || c == 0x2029 {
            dst.extend_from_slice(&src[start..i]);
            dst.extend_from_slice(&[b'\\', b'u', b'2', b'0', b'2', HEX[(c & 0xF) as usize]]);
            i += size;
            start = i;
            continue;
        }
        i += size;
    }
    dst.extend_from_slice(&src[start..]);
    dst.push(b'"');
}

pub fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 2);
    append_quoted_string(&mut out, s);
    out
}

/// One JSON value of a document `valid` accepted, members in document order.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// The literal number text.
    Number(Vec<u8>),
    /// The decoded string.
    String(Vec<u8>),
    Array(Vec<Value>),
    Object(Vec<(Vec<u8>, Value)>),
}

/// The error for a document that is not valid JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonSyntaxError;

impl std::fmt::Display for JsonSyntaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // shortcut: the message does not name the offending character.
        f.write_str("invalid JSON")
    }
}

/// Parses a document after `valid` accepts it.
pub fn parse(data: &[u8]) -> Result<Value, JsonSyntaxError> {
    if !is_valid_json(data) {
        return Err(JsonSyntaxError);
    }
    let mut p = TreeParser { s: data, i: 0 };
    Ok(p.value())
}

struct TreeParser<'a> {
    s: &'a [u8],
    i: usize,
}

impl TreeParser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && is_ws(self.s[self.i]) {
            self.i += 1;
        }
    }

    fn string(&mut self) -> Vec<u8> {
        let st = self.i;
        self.i += 1;
        while self.s[self.i] != b'"' {
            self.i += if self.s[self.i] == b'\\' { 2 } else { 1 };
        }
        self.i += 1;
        unquote_json_string(&self.s[st..self.i]).unwrap_or_default()
    }

    // Recursion depth is bounded by `valid` (10000); callers keep documents small.
    fn value(&mut self) -> Value {
        self.ws();
        match self.s[self.i] {
            b'{' => {
                self.i += 1;
                let mut m = Vec::new();
                loop {
                    self.ws();
                    if self.s[self.i] == b'}' {
                        self.i += 1;
                        return Value::Object(m);
                    }
                    if self.s[self.i] == b',' {
                        self.i += 1;
                        self.ws();
                    }
                    let k = self.string();
                    self.ws();
                    self.i += 1; // ':'
                    let v = self.value();
                    m.push((k, v));
                }
            }
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                loop {
                    self.ws();
                    if self.s[self.i] == b']' {
                        self.i += 1;
                        return Value::Array(a);
                    }
                    if self.s[self.i] == b',' {
                        self.i += 1;
                    }
                    a.push(self.value());
                }
            }
            b'"' => Value::String(self.string()),
            b't' => {
                self.i += 4;
                Value::Bool(true)
            }
            b'f' => {
                self.i += 5;
                Value::Bool(false)
            }
            b'n' => {
                self.i += 4;
                Value::Null
            }
            _ => {
                let st = self.i;
                while self.i < self.s.len()
                    && matches!(
                        self.s[self.i],
                        b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
                    )
                {
                    self.i += 1;
                }
                Value::Number(self.s[st..self.i].to_vec())
            }
        }
    }
}

/// Struct-field key match: exact, else case-insensitive.
pub fn key_matches(key: &[u8], field: &str) -> bool {
    key == field.as_bytes() || eq_ignore_case(key, field.as_bytes())
}

impl Value {
    /// The type name that type-mismatch errors report for this value.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_matches_recorded_results() {
        for ok in [
            "{}",
            " [1,2] ",
            r#"{"a":"é","b":[true,false,null]}"#,
            "-0.5e+3",
        ] {
            assert!(is_valid_json(ok.as_bytes()), "{ok}");
        }
        assert!(is_valid_json(b"\"\xff\""));
        for bad in [
            "",
            "{",
            "[1,]",
            "01",
            "1.",
            "\"\x01\"",
            "{\"a\" 1}",
            r#""\x""#,
            "[1] x",
            "\u{feff}{}",
        ] {
            assert!(!is_valid_json(bad.as_bytes()), "{bad}");
        }
        let deep = "[".repeat(10001) + &"]".repeat(10001);
        assert!(!is_valid_json(deep.as_bytes()));
        let ok = "[".repeat(10000) + &"]".repeat(10000);
        assert!(is_valid_json(ok.as_bytes()));
    }

    #[test]
    fn unquote_matches_recorded_results() {
        assert_eq!(unquote_json_string(br#""a\nb""#).unwrap(), b"a\nb");
        assert_eq!(
            unquote_json_string(b"\"\\ud83d\\ude00\"").unwrap(),
            "\u{1F600}".as_bytes()
        );
        assert_eq!(
            unquote_json_string(b"\"\\ude00\\ud83d\"").unwrap(),
            "\u{FFFD}\u{FFFD}".as_bytes()
        );
        assert_eq!(
            unquote_json_string(br#""\ud83dx""#).unwrap(),
            "\u{FFFD}x".as_bytes()
        );
        assert_eq!(
            unquote_json_string(b"\"\xff\"").unwrap(),
            "\u{FFFD}".as_bytes()
        );
    }

    #[test]
    fn encode_string_matches_recorded_results() {
        let mut want = br#""\u003ca\u0026b\u003e\"\\\b\f\u0001"#.to_vec();
        want.extend_from_slice(b"\x7f\"");
        assert_eq!(encode_string(b"<a&b>\"\\\x08\x0c\x01\x7f"), want);
        let mut input = "\u{2028}".as_bytes().to_vec();
        input.push(0xff);
        assert_eq!(encode_string(&input), br#""\u2028\ufffd""#.to_vec());
    }
}
