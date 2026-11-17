//! The named text transformations of custom rule conditions.

use crate::base64::{STANDARD, STANDARD_NO_PAD};
use crate::{CodePoint, hex, literal, strings, unicode, utf8};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

pub type Transform = fn(&[u8]) -> Vec<u8>;

fn transform_lowercase(s: &[u8]) -> Vec<u8> {
    strings::to_lowercase(s)
}
fn transform_uppercase(s: &[u8]) -> Vec<u8> {
    strings::to_uppercase(s)
}
fn transform_trim(s: &[u8]) -> Vec<u8> {
    strings::trim_whitespace(s).to_vec()
}
fn transform_trim_left(s: &[u8]) -> Vec<u8> {
    strings::trim_start_by(s, unicode::is_space).to_vec()
}
fn transform_trim_right(s: &[u8]) -> Vec<u8> {
    strings::trim_end_by(s, unicode::is_space).to_vec()
}
fn transform_normalize_path(s: &[u8]) -> Vec<u8> {
    resolve_path_segments(s, false)
}
fn transform_normalize_path_windows(s: &[u8]) -> Vec<u8> {
    resolve_path_segments(s, true)
}
fn transform_length(s: &[u8]) -> Vec<u8> {
    literal::format_decimal(s.len() as i64)
}

/// The valid transform names with their functions, in name order.
pub const ALLOWED_TRANSFORMS: &[(&str, Transform)] = &[
    ("base64_decode", base64_decode),
    ("cmd_line", normalize_command_line),
    ("compress_whitespace", compress_whitespace),
    ("css_decode", css_decode),
    ("escape_seq_decode", decode_c_escapes),
    ("hex_decode", hex_decode),
    ("html_entity_decode", html_entity_decode),
    ("js_decode", js_decode),
    ("length", transform_length),
    ("lowercase", transform_lowercase),
    ("md5", md5_hex),
    ("normalize_path", transform_normalize_path),
    ("normalize_path_win", transform_normalize_path_windows),
    ("remove_comments_char", strip_comment_markers),
    ("remove_nulls", remove_nulls),
    ("remove_whitespace", remove_whitespace),
    ("replace_comments", replace_comments),
    ("replace_nulls", replace_nulls),
    ("sha1", sha1_hex),
    ("sha256", sha256_hex),
    ("sql_hex_decode", sql_hex_decode),
    ("trim", transform_trim),
    ("trim_left", transform_trim_left),
    ("trim_right", transform_trim_right),
    ("uppercase", transform_uppercase),
    ("url_decode", url_decode),
    ("url_decode_uni", decode_percent_escapes_with_unicode),
];

/// Looks a transform up by name (`ValidTransforms[name]`).
pub fn transform_by_name(name: &str) -> Option<Transform> {
    ALLOWED_TRANSFORMS
        .binary_search_by(|(n, _)| (*n).cmp(name))
        .ok()
        .map(|i| ALLOWED_TRANSFORMS[i].1)
}

/// Applies the named transforms in order; an unknown name aborts with `unknown transform "<name>"`.
pub fn apply_transform_chain<S: AsRef<str>>(input: &[u8], names: &[S]) -> Result<Vec<u8>, String> {
    let mut cur = input.to_vec();
    for name in names {
        let name = name.as_ref();
        let Some(t) = transform_by_name(name) else {
            return Err(format!(
                "unknown transform {}",
                String::from_utf8_lossy(&literal::quote(name.as_bytes()))
            ));
        };
        cur = t(&cur);
    }
    Ok(cur)
}

/// Applies the named transforms in order and skips unknown names.
pub fn apply_known_transforms<S: AsRef<str>>(input: &[u8], names: &[S]) -> Vec<u8> {
    let mut cur = input.to_vec();
    for name in names {
        if let Some(t) = transform_by_name(name.as_ref()) {
            cur = t(&cur);
        }
    }
    cur
}

pub fn parse_hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Whether `c` is a space, tab, line feed, carriage return, form feed or vertical tab.
pub fn is_whitespace_byte(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0C | 0x0B)
}

pub fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

pub fn is_word_code_point(r: CodePoint) -> bool {
    (0..128).contains(&r) && is_word_byte(r as u8)
}

/// Parses exactly `n` hex digits at the start of `s`.
pub fn parse_fixed_hex_digits(s: &[u8], n: usize) -> Option<i64> {
    if s.len() < n {
        return None;
    }
    let mut v: i64 = 0;
    for &c in &s[..n] {
        v = (v << 4) | parse_hex_digit(c)? as i64;
    }
    Some(v)
}

/// Whether `v` is in 0..=0x10FFFF and not a surrogate.
pub fn is_valid_code_point(v: i64) -> bool {
    if !(0..=0x10FFFF).contains(&v) {
        return false;
    }
    !(0xD800..=0xDFFF).contains(&v)
}

/// Decodes %XX; '+' is kept and invalid escapes stay verbatim.
pub fn url_decode(s: &[u8]) -> Vec<u8> {
    if !s.contains(&b'%') {
        return s.to_vec();
    }
    let mut b = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' && i + 3 <= s.len() {
            if let (Some(h1), Some(h2)) = (parse_hex_digit(s[i + 1]), parse_hex_digit(s[i + 2])) {
                b.push(h1 << 4 | h2);
                i += 3;
                continue;
            }
        }
        b.push(s[i]);
        i += 1;
    }
    b
}

/// Decodes `%uHHHH` escapes, then `%XX` escapes.
pub fn decode_percent_escapes_with_unicode(s: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' && i + 6 <= s.len() && (s[i + 1] == b'u' || s[i + 1] == b'U') {
            if let Some(v) = parse_fixed_hex_digits(&s[i + 2..], 4) {
                if is_valid_code_point(v) {
                    utf8::push_code_point(&mut b, v as CodePoint);
                    i += 6;
                    continue;
                }
            }
        }
        b.push(s[i]);
        i += 1;
    }
    url_decode(&b)
}

pub fn html_named_entity(name: &[u8]) -> Option<CodePoint> {
    Some(match name {
        b"amp" => '&' as CodePoint,
        b"lt" => '<' as CodePoint,
        b"gt" => '>' as CodePoint,
        b"quot" => '"' as CodePoint,
        b"apos" => '\'' as CodePoint,
        b"nbsp" => 0x00A0,
        b"copy" => 0x00A9,
        b"reg" => 0x00AE,
        b"trade" => 0x2122,
        b"hellip" => 0x2026,
        b"mdash" => 0x2014,
        b"ndash" => 0x2013,
        b"laquo" => 0x00AB,
        b"raquo" => 0x00BB,
        b"euro" => 0x20AC,
        b"pound" => 0x00A3,
        b"yen" => 0x00A5,
        b"cent" => 0x00A2,
        b"sect" => 0x00A7,
        b"para" => 0x00B6,
        b"middot" => 0x00B7,
        b"bull" => 0x2022,
        b"dagger" => 0x2020,
        b"deg" => 0x00B0,
        b"plusmn" => 0x00B1,
        b"frac12" => 0x00BD,
        b"times" => 0x00D7,
        b"divide" => 0x00F7,
        _ => return None,
    })
}

/// Decodes common named entities and numeric references (with ';').
pub fn html_entity_decode(s: &[u8]) -> Vec<u8> {
    if !s.contains(&b'&') {
        return s.to_vec();
    }
    let mut b = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'&' {
            b.push(s[i]);
            i += 1;
            continue;
        }
        let mut end: Option<usize> = None;
        let mut j = i + 1;
        while j < s.len() && j <= i + 10 {
            if s[j] == b';' {
                end = Some(j);
                break;
            }
            if s[j] == b'&' {
                break;
            }
            j += 1;
        }
        let Some(end) = end else {
            b.push(b'&');
            i += 1;
            continue;
        };
        let name = &s[i + 1..end];
        if let Some(r) = html_named_entity(name) {
            utf8::push_code_point(&mut b, r);
            i = end + 1;
            continue;
        }
        if name.len() > 1 && name[0] == b'#' {
            let v = if name[1] == b'x' || name[1] == b'X' {
                parse_fixed_hex_digits(&name[2..], name.len() - 2)
            } else {
                literal::parse_int(&name[1..], 10, 32)
                    .ok()
                    .filter(|&v| v >= 0)
            };
            if let Some(v) = v {
                if is_valid_code_point(v) {
                    utf8::push_code_point(&mut b, v as CodePoint);
                    i = end + 1;
                    continue;
                }
            }
        }
        b.push(b'&');
        i += 1;
    }
    b
}

/// Decodes \xHH, \uHHHH and the single-char escapes; unknown escapes drop the backslash.
pub fn js_decode(s: &[u8]) -> Vec<u8> {
    if !s.contains(&b'\\') {
        return s.to_vec();
    }
    let mut b = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' || i + 1 >= s.len() {
            b.push(s[i]);
            i += 1;
            continue;
        }
        let c = s[i + 1];
        match c {
            b'n' => b.push(b'\n'),
            b't' => b.push(b'\t'),
            b'r' => b.push(b'\r'),
            b'b' => b.push(0x08),
            b'f' => b.push(0x0C),
            b'v' => b.push(0x0B),
            b'0' => b.push(0),
            b'\\' | b'\'' | b'"' | b'/' => b.push(c),
            b'x' => {
                if i + 4 <= s.len() {
                    if let (Some(h1), Some(h2)) =
                        (parse_hex_digit(s[i + 2]), parse_hex_digit(s[i + 3]))
                    {
                        b.push(h1 << 4 | h2);
                        i += 4;
                        continue;
                    }
                }
                b.push(b'\\');
                i += 1;
                continue;
            }
            b'u' => {
                if let Some(v) = parse_fixed_hex_digits(&s[i + 2..], 4) {
                    if is_valid_code_point(v) {
                        utf8::push_code_point(&mut b, v as CodePoint);
                        i += 6;
                        continue;
                    }
                }
                b.push(b'\\');
                i += 1;
                continue;
            }
            _ => b.push(c),
        }
        i += 2;
    }
    b
}

/// Decodes \HHHHHH (1–6 hex digits, one following whitespace consumed) and \<char>.
pub fn css_decode(s: &[u8]) -> Vec<u8> {
    if !s.contains(&b'\\') {
        return s.to_vec();
    }
    let mut b = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' {
            b.push(s[i]);
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let mut v: i64 = 0;
        let mut digits = 0;
        while j < s.len() && digits < 6 {
            let Some(h) = parse_hex_digit(s[j]) else {
                break;
            };
            v = (v << 4) | h as i64;
            digits += 1;
            j += 1;
        }
        if digits > 0 {
            if j < s.len() && is_whitespace_byte(s[j]) {
                j += 1;
            }
            if is_valid_code_point(v) {
                utf8::push_code_point(&mut b, v as CodePoint);
            }
            i = j;
            continue;
        }
        if j < s.len() {
            b.push(s[j]);
            i += 2;
            continue;
        }
        b.push(b'\\');
        i += 1;
    }
    b
}

/// Decodes standard base64, padded or raw, of the trimmed input; returns s on failure.
pub fn base64_decode(s: &[u8]) -> Vec<u8> {
    let trimmed = strings::trim_whitespace(s);
    if trimmed.is_empty() {
        return s.to_vec();
    }
    if let Ok(out) = STANDARD.decode(trimmed) {
        return out;
    }
    if let Ok(out) = STANDARD_NO_PAD.decode(trimmed) {
        return out;
    }
    s.to_vec()
}

/// Decodes an even-length hex string; anything else is returned unchanged.
pub fn hex_decode(s: &[u8]) -> Vec<u8> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return s.to_vec();
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for p in s.chunks(2) {
        match (parse_hex_digit(p[0]), parse_hex_digit(p[1])) {
            (Some(h1), Some(h2)) => out.push(h1 << 4 | h2),
            _ => return s.to_vec(),
        }
    }
    out
}

/// Decodes "0x4142" to "AB"; anything else is returned unchanged.
pub fn sql_hex_decode(s: &[u8]) -> Vec<u8> {
    if s.len() < 4 || s[0] != b'0' || (s[1] != b'x' && s[1] != b'X') {
        return s.to_vec();
    }
    let payload = &s[2..];
    if !payload.len().is_multiple_of(2) {
        return s.to_vec();
    }
    let mut out = Vec::with_capacity(payload.len() / 2);
    for p in payload.chunks(2) {
        match (parse_hex_digit(p[0]), parse_hex_digit(p[1])) {
            (Some(h1), Some(h2)) => out.push(h1 << 4 | h2),
            _ => return s.to_vec(),
        }
    }
    out
}

/// Collapses duplicate slashes and resolves "." / ".." (the win variant
/// converts backslashes first).
pub fn resolve_path_segments(s: &[u8], win: bool) -> Vec<u8> {
    let src = if win {
        strings::replace_all(s, b"\\", b"/")
    } else {
        s.to_vec()
    };
    if src.is_empty() || !src.contains(&b'/') {
        return src;
    }
    let abs = src.starts_with(b"/");
    let trailing = src.len() > 1 && src.ends_with(b"/");
    let mut out: Vec<&[u8]> = Vec::new();
    for seg in src.split(|&c| c == b'/') {
        match seg {
            b"" | b"." => continue,
            b".." => {
                if !out.is_empty() && *out.last().expect("non-empty") != b".." {
                    out.pop();
                } else if !abs {
                    out.push(b"..");
                }
            }
            _ => out.push(seg),
        }
    }
    let mut res = strings::join(&out, b"/");
    if abs {
        res.insert(0, b'/');
    }
    if trailing && res != b"/" && !res.is_empty() {
        res.push(b'/');
    }
    res
}

pub fn compress_whitespace(s: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(s.len());
    let mut space = false;
    for &c in s {
        if is_whitespace_byte(c) {
            space = true;
            continue;
        }
        if space {
            b.push(b' ');
            space = false;
        }
        b.push(c);
    }
    if space {
        b.push(b' ');
    }
    b
}

pub fn remove_whitespace(s: &[u8]) -> Vec<u8> {
    s.iter()
        .copied()
        .filter(|&c| !is_whitespace_byte(c))
        .collect()
}

pub fn remove_nulls(s: &[u8]) -> Vec<u8> {
    s.iter().copied().filter(|&c| c != 0).collect()
}

pub fn replace_nulls(s: &[u8]) -> Vec<u8> {
    s.iter().map(|&c| if c == 0 { b' ' } else { c }).collect()
}

static COMMENT_MARKERS: LazyLock<strings::MultiReplacer> =
    LazyLock::new(|| strings::MultiReplacer::new(&[b"/*", b"", b"*/", b"", b"--", b"", b"#", b""]));

/// Removes the comment markers `/*`, `*/`, `--` and `#` and keeps the content.
pub fn strip_comment_markers(s: &[u8]) -> Vec<u8> {
    COMMENT_MARKERS.replace(s)
}

/// Replaces whole C-style comments with one space; unterminated ones are kept.
pub fn replace_comments(s: &[u8]) -> Vec<u8> {
    if !strings::contains(s, b"/*") {
        return s.to_vec();
    }
    let mut b = Vec::with_capacity(s.len());
    let mut s = s;
    while let Some(start) = strings::find(s, b"/*") {
        let Some(rel) = strings::find(&s[start + 2..], b"*/") else {
            break;
        };
        b.extend_from_slice(&s[..start]);
        b.push(b' ');
        s = &s[start + 2 + rel + 2..];
    }
    b.extend_from_slice(s);
    b
}

/// Removes backslashes and quotes and compresses whitespace.
pub fn normalize_command_line(s: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(s.len());
    let mut space = false;
    for &c in s {
        if c == b'\\' || c == b'"' || c == b'\'' {
            continue;
        }
        if is_whitespace_byte(c) {
            space = true;
        } else {
            if space {
                b.push(b' ');
                space = false;
            }
            b.push(c);
        }
    }
    if space {
        b.push(b' ');
    }
    b
}

/// Decodes C escapes, `\xHH`, `\uHHHH` and 1-3 digit octal; unknown escapes drop the backslash.
pub fn decode_c_escapes(s: &[u8]) -> Vec<u8> {
    if !s.contains(&b'\\') {
        return s.to_vec();
    }
    let mut b = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' {
            b.push(s[i]);
            i += 1;
            continue;
        }
        if i + 1 >= s.len() {
            b.push(b'\\');
            i += 1;
            continue;
        }
        let c = s[i + 1];
        match c {
            b'a' => b.push(0x07),
            b'b' => b.push(0x08),
            b'f' => b.push(0x0C),
            b'n' => b.push(b'\n'),
            b'r' => b.push(b'\r'),
            b't' => b.push(b'\t'),
            b'v' => b.push(0x0B),
            b'\\' | b'\'' | b'"' | b'?' => b.push(c),
            b'x' => {
                if i + 4 <= s.len() {
                    if let (Some(h1), Some(h2)) =
                        (parse_hex_digit(s[i + 2]), parse_hex_digit(s[i + 3]))
                    {
                        b.push(h1 << 4 | h2);
                        i += 4;
                        continue;
                    }
                }
                b.push(b'\\');
                i += 1;
                continue;
            }
            b'u' => {
                if let Some(v) = parse_fixed_hex_digits(&s[i + 2..], 4) {
                    if is_valid_code_point(v) {
                        utf8::push_code_point(&mut b, v as CodePoint);
                        i += 6;
                        continue;
                    }
                }
                b.push(b'\\');
                i += 1;
                continue;
            }
            b'0'..=b'7' => {
                let mut v = (c - b'0') as CodePoint;
                let mut j = i + 2;
                while j < s.len() && j < i + 4 && (b'0'..=b'7').contains(&s[j]) {
                    v = (v << 3) | (s[j] - b'0') as CodePoint;
                    j += 1;
                }
                utf8::push_code_point(&mut b, v);
                i = j;
                continue;
            }
            _ => b.push(c),
        }
        i += 2;
    }
    b
}

pub fn md5_hex(s: &[u8]) -> Vec<u8> {
    hex::encode(&crate::digest::md5(s))
}
pub fn sha1_hex(s: &[u8]) -> Vec<u8> {
    hex::encode(&crate::digest::sha1(s))
}
pub fn sha256_hex(s: &[u8]) -> Vec<u8> {
    hex::encode(&Sha256::digest(s))
}
