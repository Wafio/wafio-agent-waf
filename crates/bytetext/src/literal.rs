//! Number parsing and formatting, and string quoting and unquoting.

use crate::CodePoint;
use crate::unicode;
use crate::utf8::{self, REPLACEMENT_CODE_POINT, decode_code_point, push_code_point};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumberParseErrorKind {
    /// Invalid syntax.
    Syntax,
    /// Value out of range.
    Range,
    /// invalid base
    Base(i64),
    /// invalid bit size
    BitSize(i64),
}

/// A number parse error. `value` is returned alongside a range error (the clamped
/// limit); 0 otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NumberParseError {
    pub operation: &'static str,
    pub input: Vec<u8>,
    pub kind: NumberParseErrorKind,
    pub value: i128,
}

impl fmt::Display for NumberParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let err = match self.kind {
            NumberParseErrorKind::Syntax => "invalid syntax".to_string(),
            NumberParseErrorKind::Range => "value out of range".to_string(),
            NumberParseErrorKind::Base(b) => format!("invalid base {b}"),
            NumberParseErrorKind::BitSize(b) => format!("invalid bit size {b}"),
        };
        write!(
            f,
            "strconv.{}: parsing {}: {}",
            self.operation,
            String::from_utf8_lossy(&quote(&self.input)),
            err
        )
    }
}

impl std::error::Error for NumberParseError {}

fn build_number_parse_error(
    func: &'static str,
    num: &[u8],
    kind: NumberParseErrorKind,
    value: i128,
) -> NumberParseError {
    NumberParseError {
        operation: func,
        input: num.to_vec(),
        kind,
        value,
    }
}

fn lower(c: u8) -> u8 {
    c | (b'x' - b'X')
}

fn has_valid_underscores(s: &[u8]) -> bool {
    let mut saw = b'^';
    let mut i = 0;
    let mut s = s;
    if !s.is_empty() && (s[0] == b'-' || s[0] == b'+') {
        s = &s[1..];
    }
    let mut hex = false;
    if s.len() >= 2 && s[0] == b'0' && matches!(lower(s[1]), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = lower(s[1]) == b'x';
    }
    while i < s.len() {
        if s[i].is_ascii_digit() || (hex && (b'a'..=b'f').contains(&lower(s[i]))) {
            saw = b'0';
        } else if s[i] == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else {
            if saw == b'_' {
                return false;
            }
            saw = b'!';
        }
        i += 1;
    }
    saw != b'_'
}

/// bit_size 0 = 64.
pub fn parse_uint(s: &[u8], base: i64, bit_size: i64) -> Result<u64, NumberParseError> {
    parse_uint_fn("ParseUint", s, base, bit_size)
}

fn parse_uint_fn(
    func: &'static str,
    s0: &[u8],
    base: i64,
    bit_size: i64,
) -> Result<u64, NumberParseError> {
    if s0.is_empty() {
        return Err(build_number_parse_error(
            func,
            s0,
            NumberParseErrorKind::Syntax,
            0,
        ));
    }
    let base0 = base == 0;
    let mut s = s0;
    let mut base = base;
    if base == 0 {
        base = 10;
        if s[0] == b'0' {
            if s.len() >= 3 && lower(s[1]) == b'b' {
                base = 2;
                s = &s[2..];
            } else if s.len() >= 3 && lower(s[1]) == b'o' {
                base = 8;
                s = &s[2..];
            } else if s.len() >= 3 && lower(s[1]) == b'x' {
                base = 16;
                s = &s[2..];
            } else {
                base = 8;
                s = &s[1..];
            }
        }
    } else if !(2..=36).contains(&base) {
        return Err(build_number_parse_error(
            func,
            s0,
            NumberParseErrorKind::Base(base),
            0,
        ));
    }
    let bit_size = if bit_size == 0 {
        64
    } else if !(0..=64).contains(&bit_size) {
        return Err(build_number_parse_error(
            func,
            s0,
            NumberParseErrorKind::BitSize(bit_size),
            0,
        ));
    } else {
        bit_size
    };
    let cutoff = u64::MAX / base as u64 + 1;
    let max_val: u64 = if bit_size == 64 {
        u64::MAX
    } else {
        (1u64 << bit_size) - 1
    };
    let mut underscores = false;
    let mut n: u64 = 0;
    for &c in s {
        let d = if c == b'_' && base0 {
            underscores = true;
            continue;
        } else if c.is_ascii_digit() {
            c - b'0'
        } else if lower(c).is_ascii_lowercase() {
            lower(c) - b'a' + 10
        } else {
            return Err(build_number_parse_error(
                func,
                s0,
                NumberParseErrorKind::Syntax,
                0,
            ));
        };
        if d as i64 >= base {
            return Err(build_number_parse_error(
                func,
                s0,
                NumberParseErrorKind::Syntax,
                0,
            ));
        }
        if n >= cutoff {
            return Err(build_number_parse_error(
                func,
                s0,
                NumberParseErrorKind::Range,
                max_val as i128,
            ));
        }
        n *= base as u64;
        let n1 = n.wrapping_add(d as u64);
        if n1 < n || n1 > max_val {
            return Err(build_number_parse_error(
                func,
                s0,
                NumberParseErrorKind::Range,
                max_val as i128,
            ));
        }
        n = n1;
    }
    if underscores && !has_valid_underscores(s0) {
        return Err(build_number_parse_error(
            func,
            s0,
            NumberParseErrorKind::Syntax,
            0,
        ));
    }
    Ok(n)
}

/// bit_size 0 = 64.
pub fn parse_int(s: &[u8], base: i64, bit_size: i64) -> Result<i64, NumberParseError> {
    parse_int_fn("ParseInt", s, base, bit_size)
}

fn parse_int_fn(
    func: &'static str,
    s0: &[u8],
    base: i64,
    bit_size: i64,
) -> Result<i64, NumberParseError> {
    if s0.is_empty() {
        return Err(build_number_parse_error(
            func,
            s0,
            NumberParseErrorKind::Syntax,
            0,
        ));
    }
    let mut s = s0;
    let mut neg = false;
    if s[0] == b'+' {
        s = &s[1..];
    } else if s[0] == b'-' {
        neg = true;
        s = &s[1..];
    }
    let un = match parse_uint_fn(func, s, base, bit_size) {
        Ok(v) => v,
        Err(e) if e.kind == NumberParseErrorKind::Range => e.value as u64,
        Err(mut e) => {
            e.input = s0.to_vec();
            return Err(e);
        }
    };
    let bit_size = if bit_size == 0 { 64 } else { bit_size };
    let cutoff: u64 = 1u64 << (bit_size - 1);
    if !neg && un >= cutoff {
        return Err(build_number_parse_error(
            func,
            s0,
            NumberParseErrorKind::Range,
            (cutoff - 1) as i128,
        ));
    }
    if neg && un > cutoff {
        return Err(build_number_parse_error(
            func,
            s0,
            NumberParseErrorKind::Range,
            -(cutoff as i128),
        ));
    }
    let n = un as i64;
    Ok(if neg { n.wrapping_neg() } else { n })
}

/// Decimal integer as `i64`.
pub fn parse_decimal(s: &[u8]) -> Result<i64, NumberParseError> {
    if !s.is_empty() && s.len() < 19 {
        let s0 = s;
        let mut s = s;
        if s[0] == b'-' || s[0] == b'+' {
            s = &s[1..];
            if s.is_empty() {
                return Err(build_number_parse_error(
                    "Atoi",
                    s0,
                    NumberParseErrorKind::Syntax,
                    0,
                ));
            }
        }
        let mut n: i64 = 0;
        for &ch in s {
            let d = ch.wrapping_sub(b'0');
            if d > 9 {
                return Err(build_number_parse_error(
                    "Atoi",
                    s0,
                    NumberParseErrorKind::Syntax,
                    0,
                ));
            }
            n = n * 10 + d as i64;
        }
        return Ok(if s0[0] == b'-' { -n } else { n });
    }
    parse_int_fn("Atoi", s, 10, 0)
}

pub fn format_decimal(i: i64) -> Vec<u8> {
    i.to_string().into_bytes()
}

/// Base 2..=36, lower-case digits.
pub fn format_int(i: i64, base: u32) -> Vec<u8> {
    assert!(
        (2..=36).contains(&base),
        "strconv: illegal AppendInt/FormatInt base"
    );
    let neg = i < 0;
    let mut u = i.unsigned_abs();
    let mut buf = Vec::new();
    loop {
        let d = (u % base as u64) as u8;
        buf.push(if d < 10 { b'0' + d } else { b'a' + d - 10 });
        u /= base as u64;
        if u == 0 {
            break;
        }
    }
    if neg {
        buf.push(b'-');
    }
    buf.reverse();
    buf
}

/// Syntax error from unquoting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnquoteError;

impl fmt::Display for UnquoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid syntax")
    }
}

impl std::error::Error for UnquoteError {}

fn hex_digit_value(b: u8) -> Option<CodePoint> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as CodePoint),
        b'a'..=b'f' => Some((b - b'a' + 10) as CodePoint),
        b'A'..=b'F' => Some((b - b'A' + 10) as CodePoint),
        _ => None,
    }
}

/// (value, multibyte, tail).
pub fn read_quoted_char(s: &[u8], quote: u8) -> Result<(CodePoint, bool, &[u8]), UnquoteError> {
    if s.is_empty() {
        return Err(UnquoteError);
    }
    let c = s[0];
    if c == quote && (quote == b'\'' || quote == b'"') {
        return Err(UnquoteError);
    }
    if c >= 0x80 {
        let (r, size) = decode_code_point(s);
        return Ok((r, true, &s[size..]));
    }
    if c != b'\\' {
        return Ok((c as CodePoint, false, &s[1..]));
    }
    if s.len() <= 1 {
        return Err(UnquoteError);
    }
    let c = s[1];
    let mut s = &s[2..];
    let mut multibyte = false;
    let value: CodePoint = match c {
        b'a' => 0x07,
        b'b' => 0x08,
        b'f' => 0x0C,
        b'n' => b'\n' as CodePoint,
        b'r' => b'\r' as CodePoint,
        b't' => b'\t' as CodePoint,
        b'v' => 0x0B,
        b'x' | b'u' | b'U' => {
            let n = match c {
                b'x' => 2,
                b'u' => 4,
                _ => 8,
            };
            if s.len() < n {
                return Err(UnquoteError);
            }
            let mut v: CodePoint = 0;
            for &b in &s[..n] {
                v = (v << 4) | hex_digit_value(b).ok_or(UnquoteError)?;
            }
            s = &s[n..];
            if c != b'x' {
                if !utf8::is_valid_code_point(v) {
                    return Err(UnquoteError);
                }
                multibyte = true;
            }
            v
        }
        b'0'..=b'7' => {
            let mut v = (c - b'0') as CodePoint;
            if s.len() < 2 {
                return Err(UnquoteError);
            }
            for &b in &s[..2] {
                let x = b as CodePoint - b'0' as CodePoint;
                if !(0..=7).contains(&x) {
                    return Err(UnquoteError);
                }
                v = (v << 3) | x;
            }
            s = &s[2..];
            if v > 255 {
                return Err(UnquoteError);
            }
            v
        }
        b'\\' => b'\\' as CodePoint,
        b'\'' | b'"' => {
            if c != quote {
                return Err(UnquoteError);
            }
            c as CodePoint
        }
        _ => return Err(UnquoteError),
    };
    Ok((value, multibyte, s))
}

/// The unquoted leading string and the remainder: (out, rem).
fn unquote_inner(input: &[u8]) -> Result<(Vec<u8>, &[u8]), UnquoteError> {
    if input.len() < 2 {
        return Err(UnquoteError);
    }
    let quote = input[0];
    let Some(end) = input[1..].iter().position(|&c| c == quote) else {
        return Err(UnquoteError);
    };
    let end = end + 2;
    match quote {
        b'`' => {
            let body = &input[1..end - 1];
            let out: Vec<u8> = body.iter().copied().filter(|&c| c != b'\r').collect();
            Ok((out, &input[end..]))
        }
        b'"' | b'\'' => {
            let head = &input[..end];
            if !head.contains(&b'\\') && !head.contains(&b'\n') {
                let body = &input[1..end - 1];
                let valid = if quote == b'"' {
                    utf8::is_valid(body)
                } else {
                    let (r, n) = decode_code_point(body);
                    2 + n == end && (r != REPLACEMENT_CODE_POINT || n != 1)
                };
                if valid {
                    return Ok((body.to_vec(), &input[end..]));
                }
            }
            let mut buf = Vec::with_capacity(3 * end / 2);
            let mut rest = &input[1..];
            while !rest.is_empty() && rest[0] != quote {
                let first = rest[0];
                let r = read_quoted_char(rest, quote);
                if first == b'\n' {
                    return Err(UnquoteError);
                }
                let (r, multibyte, rem) = r?;
                rest = rem;
                if r < 0x80 || !multibyte {
                    buf.push(r as u8);
                } else {
                    push_code_point(&mut buf, r);
                }
                if quote == b'\'' {
                    break;
                }
            }
            if rest.first() != Some(&quote) {
                return Err(UnquoteError);
            }
            Ok((buf, &rest[1..]))
        }
        _ => Err(UnquoteError),
    }
}

pub fn unquote(s: &[u8]) -> Result<Vec<u8>, UnquoteError> {
    let (out, rem) = unquote_inner(s)?;
    if !rem.is_empty() {
        return Err(UnquoteError);
    }
    Ok(out)
}

const LOWER_HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn push_escaped_code_point(buf: &mut Vec<u8>, r: CodePoint, quote: u8, ascii_only: bool) {
    if r == quote as CodePoint || r == b'\\' as CodePoint {
        buf.push(b'\\');
        push_code_point(buf, r);
        return;
    }
    if ascii_only {
        if r < 0x80 && unicode::is_print(r) {
            buf.push(r as u8);
            return;
        }
    } else if unicode::is_print(r) {
        push_code_point(buf, r);
        return;
    }
    match r {
        0x07 => buf.extend_from_slice(b"\\a"),
        0x08 => buf.extend_from_slice(b"\\b"),
        0x0C => buf.extend_from_slice(b"\\f"),
        0x0A => buf.extend_from_slice(b"\\n"),
        0x0D => buf.extend_from_slice(b"\\r"),
        0x09 => buf.extend_from_slice(b"\\t"),
        0x0B => buf.extend_from_slice(b"\\v"),
        _ => {
            if r < b' ' as CodePoint || r == 0x7F {
                buf.extend_from_slice(&[
                    b'\\',
                    b'x',
                    LOWER_HEX_DIGITS[(r as u8 >> 4) as usize],
                    LOWER_HEX_DIGITS[(r as u8 & 0xF) as usize],
                ]);
            } else {
                let r = if utf8::is_valid_code_point(r) {
                    r
                } else {
                    0xFFFD
                };
                if r < 0x10000 {
                    buf.extend_from_slice(b"\\u");
                    for sh in (0..=12).rev().step_by(4) {
                        buf.push(LOWER_HEX_DIGITS[((r >> sh) & 0xF) as usize]);
                    }
                } else {
                    buf.extend_from_slice(b"\\U");
                    for sh in (0..=28).rev().step_by(4) {
                        buf.push(LOWER_HEX_DIGITS[((r >> sh) & 0xF) as usize]);
                    }
                }
            }
        }
    }
}

fn quote_with(s: &[u8], quote: u8, ascii_only: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(s.len() + 2);
    buf.push(quote);
    let mut i = 0;
    while i < s.len() {
        let (r, width) = if s[i] < 0x80 {
            (s[i] as CodePoint, 1)
        } else {
            decode_code_point(&s[i..])
        };
        if width == 1 && r == REPLACEMENT_CODE_POINT {
            buf.extend_from_slice(&[
                b'\\',
                b'x',
                LOWER_HEX_DIGITS[(s[i] >> 4) as usize],
                LOWER_HEX_DIGITS[(s[i] & 0xF) as usize],
            ]);
        } else {
            push_escaped_code_point(&mut buf, r, quote, ascii_only);
        }
        i += width;
    }
    buf.push(quote);
    buf
}

pub fn quote(s: &[u8]) -> Vec<u8> {
    quote_with(s, b'"', false)
}

pub fn quote_ascii_only(s: &[u8]) -> Vec<u8> {
    quote_with(s, b'"', true)
}

// Float parsing

/// Some(value) when parsing succeeds (a syntax error and a range error are both None).
/// Special values, `_` separators and hex floats are accepted.
pub fn parse_float(b: &[u8]) -> Option<f64> {
    if let Some((v, n)) = float_special(b) {
        return (n == b.len()).then_some(v);
    }
    let rf = read_float(b)?;
    if rf.n != b.len() {
        return None;
    }
    if rf.hex {
        return parse_hex_float(rf.mantissa, rf.exp, rf.neg, rf.trunc);
    }
    // Decimal: Rust rounds correctly; underscores were checked by read_float.
    let digits: String = b
        .iter()
        .filter(|&&c| c != b'_')
        .map(|&c| c as char)
        .collect();
    digits.parse::<f64>().ok().filter(|f| f.is_finite())
}

/// special: (value, bytes used) for a leading inf/infinity/nan (case ignored).
fn float_special(s: &[u8]) -> Option<(f64, usize)> {
    let prefix = |s: &[u8], p: &[u8]| {
        s.iter()
            .zip(p)
            .take_while(|(a, b)| a.to_ascii_lowercase() == **b)
            .count()
    };
    let (sign, nsign, rest) = match s.first()? {
        b'+' => (1.0, 1, &s[1..]),
        b'-' => (-1.0, 1, &s[1..]),
        b'i' | b'I' => (1.0, 0, s),
        b'n' | b'N' => return (prefix(s, b"nan") == 3).then_some((f64::NAN, 3)),
        _ => return None,
    };
    let mut n = prefix(rest, b"infinity");
    if 3 < n && n < 8 {
        n = 3;
    }
    (n == 3 || n == 8).then_some((sign * f64::INFINITY, nsign + n))
}

struct ReadFloat {
    mantissa: u64,
    exp: i64,
    neg: bool,
    trunc: bool,
    hex: bool,
    n: usize,
}

/// The longest float prefix, None when it is malformed.
fn read_float(s: &[u8]) -> Option<ReadFloat> {
    let lower = |c: u8| c | 0x20;
    let mut underscores = false;
    let mut i = 0;
    let mut neg = false;
    match s.first()? {
        b'+' => i += 1,
        b'-' => {
            i += 1;
            neg = true;
        }
        _ => {}
    }
    let (mut base, mut max_mant_digits, mut exp_char, mut hex) = (10u64, 19, b'e', false);
    if i + 2 < s.len() && s[i] == b'0' && lower(s[i + 1]) == b'x' {
        (base, max_mant_digits, exp_char, hex) = (16, 16, b'p', true);
        i += 2;
    }
    let (mut sawdot, mut sawdigits, mut trunc) = (false, false, false);
    let (mut nd, mut nd_mant, mut dp): (i64, i64, i64) = (0, 0, 0);
    let mut mantissa: u64 = 0;
    while i < s.len() {
        let c = s[i];
        if c == b'_' {
            underscores = true;
        } else if c == b'.' {
            if sawdot {
                break;
            }
            sawdot = true;
            dp = nd;
        } else if c.is_ascii_digit() {
            sawdigits = true;
            if c == b'0' && nd == 0 {
                dp -= 1;
            } else {
                nd += 1;
                if nd_mant < max_mant_digits {
                    mantissa = mantissa * base + (c - b'0') as u64;
                    nd_mant += 1;
                } else if c != b'0' {
                    trunc = true;
                }
            }
        } else if base == 16 && (b'a'..=b'f').contains(&lower(c)) {
            sawdigits = true;
            nd += 1;
            if nd_mant < max_mant_digits {
                mantissa = mantissa * 16 + (lower(c) - b'a' + 10) as u64;
                nd_mant += 1;
            } else {
                trunc = true;
            }
        } else {
            break;
        }
        i += 1;
    }
    if !sawdigits {
        return None;
    }
    if !sawdot {
        dp = nd;
    }
    if base == 16 {
        dp *= 4;
        nd_mant *= 4;
    }
    if i < s.len() && lower(s[i]) == exp_char {
        i += 1;
        let mut esign = 1;
        match s.get(i)? {
            b'+' => i += 1,
            b'-' => {
                i += 1;
                esign = -1;
            }
            _ => {}
        }
        if !s.get(i)?.is_ascii_digit() {
            return None;
        }
        let mut e: i64 = 0;
        while i < s.len() && (s[i].is_ascii_digit() || s[i] == b'_') {
            if s[i] == b'_' {
                underscores = true;
            } else if e < 10000 {
                e = e * 10 + (s[i] - b'0') as i64;
            }
            i += 1;
        }
        dp += e * esign;
    } else if base == 16 {
        return None;
    }
    let exp = if mantissa != 0 { dp - nd_mant } else { 0 };
    if underscores && !has_valid_underscores(&s[..i]) {
        return None;
    }
    Some(ReadFloat {
        mantissa,
        exp,
        neg,
        trunc,
        hex,
        n: i,
    })
}

/// Hex float to f64: None on overflow.
fn parse_hex_float(mut mantissa: u64, mut exp: i64, neg: bool, trunc: bool) -> Option<f64> {
    const MANTBITS: u32 = 52;
    const EXPBITS: u32 = 11;
    const BIAS: i64 = -1023;
    let max_exp = (1i64 << EXPBITS) + BIAS - 2;
    let min_exp = BIAS + 1;
    exp += MANTBITS as i64;
    while mantissa != 0 && mantissa >> (MANTBITS + 2) == 0 {
        mantissa <<= 1;
        exp -= 1;
    }
    if trunc {
        mantissa |= 1;
    }
    while mantissa >> (1 + MANTBITS + 2) != 0 {
        mantissa = mantissa >> 1 | mantissa & 1;
        exp += 1;
    }
    while mantissa > 1 && exp < min_exp - 2 {
        mantissa = mantissa >> 1 | mantissa & 1;
        exp += 1;
    }
    let mut round = mantissa & 3;
    mantissa >>= 2;
    round |= mantissa & 1;
    exp += 2;
    if round == 3 {
        mantissa += 1;
        if mantissa == 1 << (1 + MANTBITS) {
            mantissa >>= 1;
            exp += 1;
        }
    }
    if mantissa >> MANTBITS == 0 {
        exp = BIAS;
    }
    if exp > max_exp {
        return None;
    }
    let mut bits = mantissa & ((1 << MANTBITS) - 1);
    bits |= (((exp - BIAS) & ((1 << EXPBITS) - 1)) as u64) << MANTBITS;
    if neg {
        bits |= 1 << 63;
    }
    Some(f64::from_bits(bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_int_reference() {
        assert_eq!(parse_int(b"-42", 10, 64), Ok(-42));
        assert_eq!(parse_int(b"0x1F", 0, 64), Ok(31));
        assert_eq!(parse_int(b"0b101", 0, 64), Ok(5));
        assert_eq!(parse_int(b"0o17", 0, 64), Ok(15));
        assert_eq!(parse_int(b"017", 0, 64), Ok(15));
        assert_eq!(parse_int(b"0", 0, 64), Ok(0));
        assert_eq!(parse_int(b"1_000", 0, 64), Ok(1000));
        assert_eq!(
            parse_int(b"1_000", 10, 64).unwrap_err().kind,
            NumberParseErrorKind::Syntax
        );
        assert_eq!(
            parse_int(b"_1", 0, 64).unwrap_err().kind,
            NumberParseErrorKind::Syntax
        );
        assert_eq!(parse_int(b"7fffffff", 16, 32), Ok(0x7fffffff));
        let e = parse_int(b"80000000", 16, 32).unwrap_err();
        assert_eq!((e.kind, e.value), (NumberParseErrorKind::Range, 0x7fffffff));
        assert_eq!(parse_int(b"-80000000", 16, 32), Ok(-0x80000000));
        let e = parse_int(b"99999999999999999999x", 10, 64).unwrap_err();
        assert_eq!(e.kind, NumberParseErrorKind::Range);
        assert_eq!(
            parse_int(b"12", 1, 64).unwrap_err().kind,
            NumberParseErrorKind::Base(1)
        );
        assert_eq!(
            parse_int(b"ab", 10, 64).unwrap_err().to_string(),
            "strconv.ParseInt: parsing \"ab\": invalid syntax"
        );
        assert_eq!(
            parse_uint(b"-1", 10, 64).unwrap_err().kind,
            NumberParseErrorKind::Syntax
        );
        assert_eq!(parse_uint(b"ffff", 16, 16), Ok(0xffff));
        assert_eq!(parse_int(b"-9223372036854775808", 10, 64), Ok(i64::MIN));
    }

    #[test]
    fn parse_decimal_reference() {
        assert_eq!(parse_decimal(b"123"), Ok(123));
        assert_eq!(parse_decimal(b"+7"), Ok(7));
        assert_eq!(
            parse_decimal(b"-"),
            Err(build_number_parse_error(
                "Atoi",
                b"-",
                NumberParseErrorKind::Syntax,
                0
            ))
        );
        assert!(parse_decimal(b"").is_err());
        assert!(parse_decimal(b"1a").is_err());
        assert!(parse_decimal(b" 1").is_err());
        assert_eq!(parse_decimal(b"9223372036854775807"), Ok(i64::MAX));
        assert_eq!(
            parse_decimal(b"9223372036854775808").unwrap_err().kind,
            NumberParseErrorKind::Range
        );
        assert_eq!(
            parse_decimal(b"9223372036854775808").unwrap_err().operation,
            "Atoi"
        );
        assert_eq!(parse_decimal(b"0000000000000000000001"), Ok(1));
    }

    #[test]
    fn unquote_reference() {
        assert_eq!(unquote(br#""a\tb""#).unwrap(), b"a\tb");
        assert_eq!(
            unquote(br#""\x41\u00e9\101""#).unwrap(),
            "Aé".bytes().chain(*b"A").collect::<Vec<u8>>()
        );
        assert_eq!(unquote(b"`a\r\\nb`").unwrap(), b"a\\nb");
        assert_eq!(unquote(b"'a'").unwrap(), b"a");
        assert!(unquote(b"'ab'").is_err());
        assert!(unquote(b"\"a").is_err());
        assert!(unquote(b"\"a\"b").is_err());
        assert!(unquote(b"\"\\'\"").is_err());
        assert_eq!(unquote(b"\"\xff\"").unwrap(), "\u{FFFD}".as_bytes());
        assert_eq!(unquote(b"\"\\xff\"").unwrap(), b"\xff");
        assert!(unquote(b"\"a\nb\"").is_err());
        assert!(unquote(b"\"\\400\"").is_err());
    }

    #[test]
    fn quote_reference() {
        assert_eq!(quote(b"a\"b\\\n\x00\xff\x7f"), br#""a\"b\\\n\x00\xff\x7f""#);
        assert_eq!(
            quote("é\u{200b}\u{1F600}\u{a0}".as_bytes()),
            "\"é\\u200b\u{1F600}\\u00a0\"".as_bytes()
        );
        assert_eq!(quote_ascii_only("é".as_bytes()), br#""\u00e9""#);
        assert_eq!(format_int(-255, 16), b"-ff");
        assert_eq!(format_decimal(-3), b"-3");
    }
}
