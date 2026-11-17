//! The JSON behaviour field rules depend on: a decoder with exact numbers (decoding one value,
//! the input offset, a token stream), decoding into a generic value (objects are maps: a
//! repeated key keeps its last value) and serializing the decoded tree (map keys sorted
//! bytewise, HTML-escaped strings). String unquoting and escaping come from
//! `wafio_domain::json_text`.

use std::collections::BTreeMap;
use wafio_domain::json_text::{append_quoted_string, unquote_json_string};

/// A decoded JSON value (numbers keep their literal text).
#[derive(Clone, Debug, PartialEq)]
pub enum JValue {
    Null,
    Bool(bool),
    /// The literal text.
    Number(Vec<u8>),
    String(Vec<u8>),
    Array(Vec<JValue>),
    Object(BTreeMap<Vec<u8>, JValue>),
}

/// The decoder errors that matter to callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Syntax error.
    Syntax,
    /// Unexpected end of input.
    UnexpectedEof,
    /// End of input.
    Eof,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DecodeError::Syntax => "invalid character in JSON",
            DecodeError::UnexpectedEof => "unexpected EOF",
            DecodeError::Eof => "EOF",
        })
    }
}

const NESTING_DEPTH_LIMIT: usize = 10000;

fn is_json_whitespace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

/// Over a complete buffer: the end offset of the value that
/// starts at (or after whitespace from) `start`.
pub fn scan_value_end(buf: &[u8], start: usize) -> Result<usize, DecodeError> {
    scan_value_end_with_depth(buf, start).map(|(end, _)| end)
}

/// `scan_value_end` plus the deepest nesting of the value (iterative: nesting up to 10000
/// levels is accepted).
pub fn scan_value_end_with_depth(buf: &[u8], start: usize) -> Result<(usize, usize), DecodeError> {
    let mut sc = Scan {
        s: buf,
        i: start,
        max_depth: 0,
    };
    sc.ws();
    if sc.i == buf.len() {
        // The input ends before a value starts: not an end.
        return Err(if buf.iter().any(|&c| !is_json_whitespace(c)) {
            DecodeError::UnexpectedEof
        } else {
            DecodeError::Eof
        });
    }
    sc.value()?;
    Ok((sc.i, sc.max_depth))
}

struct Scan<'a> {
    s: &'a [u8],
    i: usize,
    max_depth: usize,
}

impl Scan<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && is_json_whitespace(self.s[self.i]) {
            self.i += 1;
        }
    }

    // The next byte, or the EOF error (an incomplete value at EOF is UnexpectedEOF:
    // the buffer always holds a non-space byte by then).
    fn peek(&self) -> Result<u8, DecodeError> {
        self.s
            .get(self.i)
            .copied()
            .ok_or(DecodeError::UnexpectedEof)
    }

    fn push(&mut self, stack: &mut Vec<u8>, c: u8) -> Result<(), DecodeError> {
        stack.push(c);
        self.i += 1;
        self.max_depth = self.max_depth.max(stack.len());
        if stack.len() > NESTING_DEPTH_LIMIT {
            return Err(DecodeError::Syntax);
        }
        self.ws();
        Ok(())
    }

    fn key(&mut self) -> Result<(), DecodeError> {
        if self.peek()? != b'"' {
            return Err(DecodeError::Syntax);
        }
        self.string()?;
        self.ws();
        if self.peek()? != b':' {
            return Err(DecodeError::Syntax);
        }
        self.i += 1;
        self.ws();
        Ok(())
    }

    fn value(&mut self) -> Result<(), DecodeError> {
        let mut stack: Vec<u8> = Vec::new();
        'value: loop {
            match self.peek()? {
                b'{' => {
                    self.push(&mut stack, b'{')?;
                    if self.peek()? != b'}' {
                        self.key()?;
                        continue 'value;
                    }
                }
                b'[' => {
                    self.push(&mut stack, b'[')?;
                    if self.peek()? != b']' {
                        continue 'value;
                    }
                }
                b'"' => self.string()?,
                b'-' | b'0'..=b'9' => self.number()?,
                b't' => self.literal(b"true")?,
                b'f' => self.literal(b"false")?,
                b'n' => self.literal(b"null")?,
                _ => return Err(DecodeError::Syntax),
            }
            // After a value (or at an empty container's closing byte).
            loop {
                let Some(&open) = stack.last() else {
                    return Ok(());
                };
                self.ws();
                match self.peek()? {
                    b',' => {
                        self.i += 1;
                        self.ws();
                        if open == b'{' {
                            self.key()?;
                        }
                        continue 'value;
                    }
                    c if (open == b'{' && c == b'}') || (open == b'[' && c == b']') => {
                        self.i += 1;
                        stack.pop();
                    }
                    _ => return Err(DecodeError::Syntax),
                }
            }
        }
    }

    fn string(&mut self) -> Result<(), DecodeError> {
        self.i += 1;
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return Ok(()),
                b'\\' => match self.peek()? {
                    b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => self.i += 1,
                    b'u' => {
                        self.i += 1;
                        for _ in 0..4 {
                            if !self.peek()?.is_ascii_hexdigit() {
                                return Err(DecodeError::Syntax);
                            }
                            self.i += 1;
                        }
                    }
                    _ => return Err(DecodeError::Syntax),
                },
                c if c < 0x20 => return Err(DecodeError::Syntax),
                _ => {}
            }
        }
    }

    fn literal(&mut self, lit: &[u8]) -> Result<(), DecodeError> {
        for &want in lit {
            if self.peek()? != want {
                return Err(DecodeError::Syntax);
            }
            self.i += 1;
        }
        Ok(())
    }

    // A number ends at the first byte that cannot continue it; at EOF it is complete
    // except after '-', '.', 'e', 'E', '+'/'-' of an exponent.
    fn number(&mut self) -> Result<(), DecodeError> {
        let at = |s: &Self| s.s.get(s.i).copied();
        if at(self) == Some(b'-') {
            self.i += 1;
        }
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => {
                while matches!(at(self), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(DecodeError::Syntax),
        }
        if at(self) == Some(b'.') {
            self.i += 1;
            if !self.peek()?.is_ascii_digit() {
                return Err(DecodeError::Syntax);
            }
            while matches!(at(self), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(at(self), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(at(self), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !self.peek()?.is_ascii_digit() {
                return Err(DecodeError::Syntax);
            }
            while matches!(at(self), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        Ok(())
    }
}

/// Builds the value of bytes `scan_value_end` accepted.
pub fn build(s: &[u8]) -> JValue {
    let mut b = Builder { s, i: 0 };
    b.value()
}

struct Builder<'a> {
    s: &'a [u8],
    i: usize,
}

impl Builder<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && is_json_whitespace(self.s[self.i]) {
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

    fn value(&mut self) -> JValue {
        self.ws();
        match self.s[self.i] {
            b'{' => {
                self.i += 1;
                let mut m = BTreeMap::new();
                loop {
                    self.ws();
                    match self.s[self.i] {
                        b'}' => {
                            self.i += 1;
                            return JValue::Object(m);
                        }
                        b',' => {
                            self.i += 1;
                            self.ws();
                        }
                        _ => {}
                    }
                    let k = self.string();
                    self.ws();
                    self.i += 1; // ':'
                    let v = self.value();
                    m.insert(k, v);
                }
            }
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                loop {
                    self.ws();
                    match self.s[self.i] {
                        b']' => {
                            self.i += 1;
                            return JValue::Array(a);
                        }
                        b',' => self.i += 1,
                        _ => {}
                    }
                    a.push(self.value());
                }
            }
            b'"' => JValue::String(self.string()),
            b't' => {
                self.i += 4;
                JValue::Bool(true)
            }
            b'f' => {
                self.i += 5;
                JValue::Bool(false)
            }
            b'n' => {
                self.i += 4;
                JValue::Null
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
                JValue::Number(self.s[st..self.i].to_vec())
            }
        }
    }
}

/// Decodes one value (numbers exact): the value and the offset after it.
pub fn decode_one(buf: &[u8]) -> Result<(JValue, usize), DecodeError> {
    let end = scan_value_end(buf, 0)?;
    Ok((build(&buf[..end]), end))
}

/// Serializes a decoded value.
pub fn serialize_sorted(v: &JValue) -> Vec<u8> {
    let mut out = Vec::new();
    append_value(&mut out, v);
    out
}

fn append_value(out: &mut Vec<u8>, v: &JValue) {
    match v {
        JValue::Null => out.extend_from_slice(b"null"),
        JValue::Bool(true) => out.extend_from_slice(b"true"),
        JValue::Bool(false) => out.extend_from_slice(b"false"),
        JValue::Number(n) if n.is_empty() => out.push(b'0'),
        JValue::Number(n) => out.extend_from_slice(n),
        JValue::String(s) => append_quoted_string(out, s),
        JValue::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                append_value(out, e);
            }
            out.push(b']');
        }
        JValue::Object(m) => {
            out.push(b'{');
            for (i, (k, e)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                append_quoted_string(out, k);
                out.push(b':');
                append_value(out, e);
            }
            out.push(b'}');
        }
    }
}

// Token decoder

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TokState {
    TopValue,
    ArrayStart,
    ArrayValue,
    ArrayComma,
    ObjectStart,
    ObjectKey,
    ObjectColon,
    ObjectValue,
    ObjectComma,
}

/// One token. Scalars other than strings carry nothing callers read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    Delim(u8),
    String(Vec<u8>),
    Scalar,
}

/// A token decoder (numbers exact) over a complete buffer.
pub struct TokenDecoder<'a> {
    buffer: &'a [u8],
    scan_offset: usize,
    state: TokState,
    stack: Vec<TokState>,
}

impl<'a> TokenDecoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        TokenDecoder {
            buffer: buf,
            scan_offset: 0,
            state: TokState::TopValue,
            stack: Vec::new(),
        }
    }

    /// Bytes consumed so far.
    pub fn consumed_offset(&self) -> usize {
        self.scan_offset
    }

    fn peek(&mut self) -> Result<u8, DecodeError> {
        while self.scan_offset < self.buffer.len() {
            let c = self.buffer[self.scan_offset];
            if !is_json_whitespace(c) {
                return Ok(c);
            }
            self.scan_offset += 1;
        }
        // Trailing spaces are never part of a later offset callers read.
        Err(DecodeError::Eof)
    }

    fn value_allowed(&self) -> bool {
        matches!(
            self.state,
            TokState::TopValue
                | TokState::ArrayStart
                | TokState::ArrayValue
                | TokState::ObjectValue
        )
    }

    fn finish_value(&mut self) {
        match self.state {
            TokState::ArrayStart | TokState::ArrayValue => self.state = TokState::ArrayComma,
            TokState::ObjectValue => self.state = TokState::ObjectComma,
            _ => {}
        }
    }

    // Decode of one scalar at scan_offset.
    fn decode_scalar(&mut self) -> Result<Vec<u8>, DecodeError> {
        let end = scan_value_end(self.buffer, self.scan_offset)?;
        let v = self.buffer[self.scan_offset..end].to_vec();
        self.scan_offset = end;
        self.finish_value();
        Ok(v)
    }

    pub fn token(&mut self) -> Result<Token, DecodeError> {
        loop {
            let c = self.peek()?;
            match c {
                b'[' | b'{' => {
                    if !self.value_allowed() {
                        return Err(DecodeError::Syntax);
                    }
                    self.scan_offset += 1;
                    self.stack.push(self.state);
                    self.state = if c == b'[' {
                        TokState::ArrayStart
                    } else {
                        TokState::ObjectStart
                    };
                    return Ok(Token::Delim(c));
                }
                b']' | b'}' => {
                    let ok = if c == b']' {
                        matches!(self.state, TokState::ArrayStart | TokState::ArrayComma)
                    } else {
                        matches!(self.state, TokState::ObjectStart | TokState::ObjectComma)
                    };
                    if !ok {
                        return Err(DecodeError::Syntax);
                    }
                    self.scan_offset += 1;
                    self.state = self.stack.pop().unwrap_or(TokState::TopValue);
                    self.finish_value();
                    return Ok(Token::Delim(c));
                }
                b':' => {
                    if self.state != TokState::ObjectColon {
                        return Err(DecodeError::Syntax);
                    }
                    self.scan_offset += 1;
                    self.state = TokState::ObjectValue;
                }
                b',' => match self.state {
                    TokState::ArrayComma => {
                        self.scan_offset += 1;
                        self.state = TokState::ArrayValue;
                    }
                    TokState::ObjectComma => {
                        self.scan_offset += 1;
                        self.state = TokState::ObjectKey;
                    }
                    _ => return Err(DecodeError::Syntax),
                },
                b'"' if matches!(self.state, TokState::ObjectStart | TokState::ObjectKey) => {
                    let old = self.state;
                    self.state = TokState::TopValue;
                    let r = self.decode_scalar();
                    self.state = old;
                    let raw = r?;
                    self.state = TokState::ObjectColon;
                    return Ok(Token::String(unquote_json_string(&raw).unwrap_or_default()));
                }
                _ => {
                    if !self.value_allowed() {
                        return Err(DecodeError::Syntax);
                    }
                    let raw = self.decode_scalar()?;
                    let lead = raw
                        .iter()
                        .position(|&c| !is_json_whitespace(c))
                        .unwrap_or(0);
                    return Ok(if raw.get(lead) == Some(&b'"') {
                        Token::String(unquote_json_string(&raw[lead..]).unwrap_or_default())
                    } else {
                        Token::Scalar
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_one_offsets_match_reference_decoder() {
        assert_eq!(decode_one(b"0123").unwrap().1, 1);
        assert_eq!(decode_one(b" 12x").unwrap().1, 3);
        assert_eq!(decode_one(b"{\"a\":1} tail").unwrap().1, 7);
        assert_eq!(decode_one(b"\"s\"rest").unwrap().1, 3);
        assert_eq!(decode_one(b"[1,2").unwrap_err(), DecodeError::UnexpectedEof);
        assert_eq!(decode_one(b"tru").unwrap_err(), DecodeError::UnexpectedEof);
        assert_eq!(decode_one(b"  ").unwrap_err(), DecodeError::Eof);
        assert_eq!(decode_one(b"[01]").unwrap_err(), DecodeError::Syntax);
        assert_eq!(decode_one(b"{\"a\" 1}").unwrap_err(), DecodeError::Syntax);
    }

    #[test]
    fn serialize_sorted_sorts_and_keeps_last_duplicate() {
        let (v, _) = decode_one(br#"{"b":1,"a":[true,null,"<x>"],"b":2.50}"#).unwrap();
        assert_eq!(
            serialize_sorted(&v),
            br#"{"a":[true,null,"\u003cx\u003e"],"b":2.50}"#
        );
    }

    #[test]
    fn depth_limit() {
        let deep = "[".repeat(10001);
        assert_eq!(
            decode_one(deep.as_bytes()).unwrap_err(),
            DecodeError::Syntax
        );
        let ok = "[".repeat(10000) + &"]".repeat(10000);
        assert_eq!(
            scan_value_end_with_depth(ok.as_bytes(), 0),
            Ok((20000, 10000))
        );
    }
}
