//! URL escaping and unescaping (query component and path segment), query parsing, and
//! `parse` (the subset the engines read, see [`Url`]).

pub use crate::url_parse::{Url, UrlParseError, parse};

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

/// Errors from unescaping and query parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UrlError {
    /// The bad escape, at most 3 bytes.
    Escape(Vec<u8>),
    /// "invalid semicolon separator in query"
    Semicolon,
    /// "number of URL query parameters exceeded limit"
    TooManyParams,
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UrlError::Escape(s) => {
                write!(
                    f,
                    "invalid URL escape {}",
                    String::from_utf8_lossy(&crate::literal::quote(s))
                )
            }
            UrlError::Semicolon => f.write_str("invalid semicolon separator in query"),
            UrlError::TooManyParams => f.write_str("number of URL query parameters exceeded limit"),
        }
    }
}

impl std::error::Error for UrlError {}

fn is_hex_digit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn hex_digit_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn unescape(s: &[u8], query: bool) -> Result<Vec<u8>, UrlError> {
    unescape_cow(s, query).map(Cow::into_owned)
}

/// `unescape`, borrowing `s` back when nothing decodes (no `%` escape and, for a query, no `+`).
fn unescape_cow(s: &[u8], query: bool) -> Result<Cow<'_, [u8]>, UrlError> {
    let mut n = 0;
    let mut has_plus = false;
    let mut i = 0;
    while let Some(k) = memchr::memchr2(b'%', b'+', &s[i..]) {
        i += k;
        if s[i] == b'%' {
            n += 1;
            if i + 2 >= s.len() || !is_hex_digit(s[i + 1]) || !is_hex_digit(s[i + 2]) {
                let e = &s[i..];
                return Err(UrlError::Escape(e[..e.len().min(3)].to_vec()));
            }
            i += 3;
        } else {
            has_plus = query;
            i += 1;
        }
    }
    if n == 0 && !has_plus {
        return Ok(Cow::Borrowed(s));
    }
    let mut t = Vec::with_capacity(s.len() - 2 * n);
    let mut i = 0;
    while let Some(k) = memchr::memchr2(b'%', b'+', &s[i..]) {
        t.extend_from_slice(&s[i..i + k]);
        i += k;
        if s[i] == b'%' {
            t.push(hex_digit_value(s[i + 1]) << 4 | hex_digit_value(s[i + 2]));
            i += 3;
        } else {
            t.push(if query { b' ' } else { b'+' });
            i += 1;
        }
    }
    t.extend_from_slice(&s[i..]);
    Ok(Cow::Owned(t))
}

/// Query component unescape, borrowing `s` back when nothing decodes.
pub fn unescape_query_component_cow(s: &[u8]) -> Result<Cow<'_, [u8]>, UrlError> {
    unescape_cow(s, true)
}

/// Path segment unescape, borrowing `s` back when nothing decodes.
pub fn unescape_path_segment_cow(s: &[u8]) -> Result<Cow<'_, [u8]>, UrlError> {
    unescape_cow(s, false)
}

/// `%XX` decoded, `+` → space; a malformed `%` is an error.
pub fn unescape_query_component(s: &[u8]) -> Result<Vec<u8>, UrlError> {
    unescape(s, true)
}

/// Like [`unescape_query_component`] but `+` stays `+`.
pub fn unescape_path_segment(s: &[u8]) -> Result<Vec<u8>, UrlError> {
    unescape(s, false)
}

// 1 = `escape` changes the byte.
const QUERY_ESCAPE_TABLE: &[u8; 256] = b"1111111111111111111111111111111111111111111110010000000000111111100000000000000000000000000111101000000000000000000000000001110111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
const PATH_ESCAPE_TABLE: &[u8; 256] = b"1111111111111111111111111111111111110101111010010000000000011011000000000000000000000000000111101000000000000000000000000001110111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

fn escape(s: &[u8], table: &[u8; 256], query: bool) -> Vec<u8> {
    const UPPER_HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut t = Vec::with_capacity(s.len());
    for &c in s {
        if c == b' ' && query {
            t.push(b'+');
        } else if table[c as usize] == b'1' {
            t.extend_from_slice(&[
                b'%',
                UPPER_HEX_DIGITS[(c >> 4) as usize],
                UPPER_HEX_DIGITS[(c & 15) as usize],
            ]);
        } else {
            t.push(c);
        }
    }
    t
}

pub fn escape_query_component(s: &[u8]) -> Vec<u8> {
    escape(s, QUERY_ESCAPE_TABLE, true)
}

pub fn escape_path_segment(s: &[u8]) -> Vec<u8> {
    escape(s, PATH_ESCAPE_TABLE, false)
}

/// Query parameters, ordered by key.
pub type QueryParams = BTreeMap<Vec<u8>, Vec<Vec<u8>>>;

/// The first value of key, or "".
pub fn first_query_value<'a>(v: &'a QueryParams, key: &[u8]) -> &'a [u8] {
    v.get(key)
        .and_then(|vs| vs.first())
        .map_or(&[], |x| x.as_slice())
}

/// Most query parameters one query may hold; more is an error.
pub const DEFAULT_MAX_QUERY_PARAMS: usize = 10000;

/// The values parsed and the error returned with them. Parsing continues after a bad pair:
/// the first escape error wins, a semicolon error replaces any earlier error.
pub fn parse_query(query: &[u8]) -> (QueryParams, Option<UrlError>) {
    let mut m = QueryParams::new();
    if crate::strings::count(query, b"&") + 1 > DEFAULT_MAX_QUERY_PARAMS {
        return (m, Some(UrlError::TooManyParams));
    }
    let mut err: Option<UrlError> = None;
    let mut query = query;
    while !query.is_empty() {
        let (key, rest, _) = crate::strings::cut(query, b"&");
        query = rest;
        if key.contains(&b';') {
            err = Some(UrlError::Semicolon);
            continue;
        }
        if key.is_empty() {
            continue;
        }
        let (key, value, _) = crate::strings::cut(key, b"=");
        let key = match unescape_query_component(key) {
            Ok(k) => k,
            Err(e) => {
                err.get_or_insert(e);
                continue;
            }
        };
        let value = match unescape_query_component(value) {
            Ok(v) => v,
            Err(e) => {
                err.get_or_insert(e);
                continue;
            }
        };
        m.entry(key).or_default().push(value);
    }
    (m, err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_cow_borrows_when_nothing_decodes() {
        assert!(matches!(
            unescape_query_component_cow(b"a=b&c"),
            Ok(Cow::Borrowed(_))
        ));
        assert!(matches!(
            unescape_path_segment_cow(b"a+b"),
            Ok(Cow::Borrowed(_))
        ));
        assert!(matches!(
            unescape_query_component_cow(b"a+b"),
            Ok(Cow::Owned(_))
        ));
        assert!(matches!(
            unescape_path_segment_cow(b"a%20b"),
            Ok(Cow::Owned(_))
        ));
        assert_eq!(
            unescape_query_component_cow(b"a+b%41").unwrap().as_ref(),
            b"a bA"
        );
        assert!(unescape_query_component_cow(b"%zz").is_err());
    }

    #[test]
    fn unescape_reference() {
        assert_eq!(unescape_query_component(b"a%20b+c").unwrap(), b"a b c");
        assert_eq!(unescape_path_segment(b"a%20b+c").unwrap(), b"a b+c");
        assert_eq!(
            unescape_query_component(b"%zz").unwrap_err(),
            UrlError::Escape(b"%zz".to_vec())
        );
        assert_eq!(
            unescape_query_component(b"ab%4").unwrap_err(),
            UrlError::Escape(b"%4".to_vec())
        );
        assert_eq!(
            unescape_query_component(b"%").unwrap_err().to_string(),
            "invalid URL escape \"%\""
        );
        assert_eq!(
            unescape_query_component(b"%2g%41").unwrap_err(),
            UrlError::Escape(b"%2g".to_vec())
        );
        assert_eq!(unescape_query_component(b"%ff%00").unwrap(), b"\xff\x00");
        assert_eq!(
            escape_query_component(b"a b&c=d/\xff~"),
            b"a+b%26c%3Dd%2F%FF~"
        );
        assert_eq!(escape_path_segment(b"a b/c+"), b"a%20b%2Fc+");
    }

    #[test]
    fn parse_query_reference() {
        let (v, e) = parse_query(b"a=1&b=2&a=3&&c&d=%zz&e=%41");
        assert_eq!(e, Some(UrlError::Escape(b"%zz".to_vec())));
        assert_eq!(v[&b"a"[..]], vec![b"1".to_vec(), b"3".to_vec()]);
        assert_eq!(v[&b"c"[..]], vec![b"".to_vec()]);
        assert_eq!(first_query_value(&v, b"e"), b"A");
        assert!(!v.contains_key(&b"d"[..]));
        let (v, e) = parse_query(b"x=%zz&a;b=1&y=2");
        assert_eq!(e, Some(UrlError::Semicolon));
        assert_eq!(first_query_value(&v, b"y"), b"2");
        let many = "a=1&".repeat(10000);
        let (v, e) = parse_query(many.as_bytes());
        assert_eq!(e, Some(UrlError::TooManyParams));
        assert!(v.is_empty());
    }
}
