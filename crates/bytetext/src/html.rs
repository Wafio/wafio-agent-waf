//! HTML entity unescaping (full HTML5 entity table) and escaping.

use crate::CodePoint;
use crate::html_entities::{ENTITIES, LONGEST_UNTERMINATED_ENTITY};
use crate::utf8::push_code_point;
use std::borrow::Cow;
use std::sync::LazyLock;

const WINDOWS_1252_REPLACEMENTS: [CodePoint; 32] = [
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039,
    0x0152, 0x008D, 0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
];

/// `ENTITIES[start..end]` are the names whose first byte is the index.
static BY_FIRST: LazyLock<[(u16, u16); 256]> = LazyLock::new(|| {
    let mut t = [(0u16, 0u16); 256];
    let mut i = 0;
    while i < ENTITIES.len() {
        let b = ENTITIES[i].0[0] as usize;
        let mut j = i;
        while j < ENTITIES.len() && ENTITIES[j].0[0] as usize == b {
            j += 1;
        }
        t[b] = (i as u16, j as u16);
        i = j;
    }
    t
});

/// The runes of a named entity (name without '&', with ';' when it has one).
pub fn lookup_entity(name: &[u8]) -> Option<(CodePoint, CodePoint)> {
    let &b = name.first()?;
    let (lo, hi) = BY_FIRST[b as usize];
    let part = &ENTITIES[lo as usize..hi as usize];
    part.binary_search_by(|e| e.0.cmp(name))
        .ok()
        .map(|i| (part[i].1 as CodePoint, part[i].2 as CodePoint))
}

/// What entity decoding does with `s`, which starts with '&': the number of bytes it
/// consumes, and the one or two runes that replace them (`None`: the bytes stay as they are).
fn decode_entity(s: &[u8]) -> (usize, Option<(CodePoint, CodePoint)>) {
    let mut i = 1usize;
    if s.len() <= 1 {
        return (1, None);
    }
    if s[i] == b'#' {
        if s.len() <= 3 {
            return (1, None);
        }
        i += 1;
        let mut c = s[i];
        let mut hex = false;
        if c == b'x' || c == b'X' {
            hex = true;
            i += 1;
        }
        let mut x: CodePoint = 0;
        while i < s.len() {
            c = s[i];
            i += 1;
            if hex {
                let d = match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    b'A'..=b'F' => Some(c - b'A' + 10),
                    _ => None,
                };
                if let Some(d) = d {
                    x = x.wrapping_mul(16).wrapping_add(d as CodePoint);
                    continue;
                }
            } else if c.is_ascii_digit() {
                x = x.wrapping_mul(10).wrapping_add((c - b'0') as CodePoint);
                continue;
            }
            if c != b';' {
                i -= 1;
            }
            break;
        }
        if i <= 3 {
            return (1, None);
        }
        if (0x80..=0x9F).contains(&x) {
            x = WINDOWS_1252_REPLACEMENTS[(x - 0x80) as usize];
        } else if x == 0 || (0xD800..=0xDFFF).contains(&x) || x > 0x10FFFF {
            x = 0xFFFD;
        }
        return (i, Some((x, 0)));
    }
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c.is_ascii_alphanumeric() {
            continue;
        }
        if c != b';' {
            i -= 1;
        }
        break;
    }
    let name = &s[1..i];
    if !name.is_empty() {
        if let Some(r) = lookup_entity(name) {
            return (i, Some(r));
        }
        let max_len = (name.len() - 1).min(LONGEST_UNTERMINATED_ENTITY);
        let mut j = max_len;
        while j > 1 {
            if let Some((a, 0)) = lookup_entity(&name[..j]) {
                return (j + 1, Some((a, 0)));
            }
            j -= 1;
        }
    }
    (i, None)
}

pub fn unescape(s: &[u8]) -> Vec<u8> {
    unescape_cow(s).into_owned()
}

/// Like [`unescape`], borrowing `s` back when no entity decodes (the result equals `s`).
pub fn unescape_cow(s: &[u8]) -> Cow<'_, [u8]> {
    let (mut pos, mut copied) = (0, 0);
    let mut out: Option<Vec<u8>> = None;
    while let Some(k) = memchr::memchr(b'&', &s[pos..]) {
        let at = pos + k;
        let (n, rep) = decode_entity(&s[at..]);
        if let Some((a, b)) = rep {
            let out = out.get_or_insert_with(|| Vec::with_capacity(s.len()));
            out.extend_from_slice(&s[copied..at]);
            push_code_point(out, a);
            if b != 0 {
                push_code_point(out, b);
            }
            copied = at + n;
        }
        pos = at + n;
    }
    match out {
        None => Cow::Borrowed(s),
        Some(mut out) => {
            out.extend_from_slice(&s[copied..]);
            Cow::Owned(out)
        }
    }
}

/// Escapes `<`, `>`, `&`, `'` and `"`.
pub fn escape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        match c {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'\'' => out.extend_from_slice(b"&#39;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&#34;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> String {
        String::from_utf8(unescape(s.as_bytes())).unwrap()
    }

    #[test]
    fn unescape_matches_reference() {
        assert_eq!(u("A\ttext\nstring"), "A\ttext\nstring");
        assert_eq!(u("&lt;&amp;&gt;&quot;"), "<&>\"");
        assert_eq!(u("&#39;&#x27;&#X27;"), "'''");
        assert_eq!(u("Delta = &Delta; "), "Delta = Δ ");
        assert_eq!(u("&notit;&notin;"), "¬it;∉");
        assert_eq!(u("&#9731; &#9731"), "☃ ☃");
        assert_eq!(u("&#x2603; &#x2603"), "☃ ☃");
        assert_eq!(u("&#x80;&#x9F;"), "€Ÿ");
        assert_eq!(u("&#0;&#xD800;&#x110000;"), "\u{FFFD}\u{FFFD}\u{FFFD}");
        assert_eq!(u("&"), "&");
        assert_eq!(u("&;"), "&;");
        assert_eq!(u("&#"), "&#");
        assert_eq!(u("&#x"), "&#x");
        assert_eq!(u("&#1"), "&#1"); // needs at least "&#.."
        assert_eq!(u("&#12"), "\u{c}");
        assert_eq!(u("&ampx"), "&x");
        assert_eq!(u("&nGt;"), "&nGt;"); // not in the entity table
        assert_eq!(u("&nGtv;"), "\u{226B}\u{338}");
        assert_eq!(u("&xyz;"), "&xyz;");
        assert_eq!(u("&lt"), "<");
        assert_eq!(u("&lt;x&gt"), "<x>");
        // int32 wrap-around of a long numeric reference.
        assert_eq!(u("&#99999999999;"), "\u{FFFD}");
        assert_eq!(unescape(b"a&\xffb"), b"a&\xffb");
    }

    #[test]
    fn cow_borrows_when_nothing_decodes() {
        for s in ["", "plain", "a=1&b=2&c", "&xyz;&nGt;&#1&", "&", "x&"] {
            assert!(
                matches!(unescape_cow(s.as_bytes()), Cow::Borrowed(_)),
                "{s:?}"
            );
        }
        for s in ["&lt;", "a&amp;b", "q=1&b=2&gt", "&#65;", "&xyz;&lt;&nGt;"] {
            assert!(matches!(unescape_cow(s.as_bytes()), Cow::Owned(_)), "{s:?}");
        }
        assert_eq!(unescape(b"&xyz;&lt;&nGt;"), b"&xyz;<&nGt;");
        assert_eq!(unescape(b"a=1&b=2&lt&c"), b"a=1&b=2<&c");
    }

    /// The first-byte index finds every entity of the table and nothing else.
    #[test]
    fn lookup_entity_finds_every_entity() {
        for e in ENTITIES.iter() {
            assert_eq!(
                lookup_entity(e.0),
                Some((e.1 as CodePoint, e.2 as CodePoint)),
                "{:?}",
                e.0
            );
        }
        for n in [&b""[..], b"x", b"zzzz", b"AElig2", b"\xff", b"lt;;", b"A"] {
            assert_eq!(
                lookup_entity(n),
                ENTITIES
                    .iter()
                    .find(|e| e.0 == n)
                    .map(|e| (e.1 as CodePoint, e.2 as CodePoint))
            );
        }
    }

    #[test]
    fn escape_reference() {
        assert_eq!(
            escape(b"<a href='x'>&\"</a>"),
            b"&lt;a href=&#39;x&#39;&gt;&amp;&#34;&lt;/a&gt;"
        );
    }
}
