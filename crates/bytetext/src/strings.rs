//! String functions over byte strings. Only the functions whose result depends on rune
//! decoding (invalid byte → U+FFFD of width 1) or Unicode tables live here; plain byte
//! operations (contains, has-prefix, index of a non-empty needle, …) are the same on
//! bytes and have helpers here only for convenience.

use crate::CodePoint;
use crate::unicode;
use crate::utf8::{
    self, REPLACEMENT_CODE_POINT, code_points, decode_code_point, decode_last_code_point,
    push_code_point,
};

fn is_ascii_space(c: u8) -> bool {
    matches!(c, b'\t' | b'\n' | 0x0B | 0x0C | b'\r' | b' ')
}

/// Each rune (an invalid byte reads as U+FFFD) replaced by `mapping(r)`;
/// a negative result drops the rune. An invalid byte is written as U+FFFD (EF BF BD).
pub fn map_chars(mapping: impl Fn(CodePoint) -> CodePoint, s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 4);
    for (_, c, _) in code_points(s) {
        let r = mapping(c);
        if r >= 0 {
            push_code_point(&mut out, r);
        }
    }
    out
}

/// `Map(mapping, s)` for a mapping that is the identity on ASCII except `ascii`: ASCII bytes
/// skip the rune decode and the table lookup.
fn map_ascii_fast(s: &[u8], ascii: fn(u8) -> u8, mapping: fn(CodePoint) -> CodePoint) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 4);
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c < 0x80 {
            out.push(ascii(c));
            i += 1;
            continue;
        }
        let (r, w) = decode_code_point(&s[i..]);
        push_code_point(&mut out, mapping(r));
        i += w;
    }
    out
}

pub fn to_lowercase(s: &[u8]) -> Vec<u8> {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    map_ascii_fast(s, |c| c.to_ascii_lowercase(), unicode::to_lowercase)
}

/// Lower-cases `s` with a one-pass ASCII path, borrowing `s` when it has no upper-case letter.
pub fn to_lowercase_cow(s: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let mut upper = false;
    for &c in s {
        if c >= 0x80 {
            return std::borrow::Cow::Owned(to_lowercase(s));
        }
        if c.is_ascii_uppercase() {
            upper = true;
        }
    }
    if !upper {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(s.to_ascii_lowercase())
}

pub fn to_uppercase(s: &[u8]) -> Vec<u8> {
    if s.is_ascii() {
        return s.to_ascii_uppercase();
    }
    map_ascii_fast(s, |c| c.to_ascii_uppercase(), unicode::to_uppercase)
}

/// Unicode simple case folding; invalid bytes each read as U+FFFD
/// (so two different invalid bytes are equal).
pub fn eq_ignore_case(s: &[u8], t: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() && i < t.len() {
        let (mut sr, mut tr) = (s[i], t[i]);
        if (sr | tr) >= 0x80 {
            return eq_ignore_case_unicode(&s[i..], &t[i..]);
        }
        i += 1;
        if tr == sr {
            continue;
        }
        if tr < sr {
            std::mem::swap(&mut tr, &mut sr);
        }
        if sr.is_ascii_uppercase() && tr == sr + 32 {
            continue;
        }
        return false;
    }
    s.len() == t.len()
}

fn eq_ignore_case_unicode(s: &[u8], mut t: &[u8]) -> bool {
    for (_, sr0, _) in code_points(s) {
        if t.is_empty() {
            return false;
        }
        let tr0;
        if t[0] < 0x80 {
            tr0 = t[0] as CodePoint;
            t = &t[1..];
        } else {
            let (r, size) = decode_code_point(t);
            tr0 = r;
            t = &t[size..];
        }
        let (mut sr, mut tr) = (sr0, tr0);
        if tr == sr {
            continue;
        }
        if tr < sr {
            std::mem::swap(&mut tr, &mut sr);
        }
        if tr < 0x80 {
            if (b'A' as CodePoint..=b'Z' as CodePoint).contains(&sr) && tr == sr + 32 {
                continue;
            }
            return false;
        }
        let mut r = unicode::next_case_fold_equivalent(sr);
        while r != sr && r < tr {
            r = unicode::next_case_fold_equivalent(r);
        }
        if r == tr {
            continue;
        }
        return false;
    }
    t.is_empty()
}

/// Subslices between runs of runes for which `f` holds.
pub fn split_fields_by(s: &[u8], f: impl Fn(CodePoint) -> bool) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, r, _) in code_points(s) {
        if f(r) {
            if let Some(st) = start.take() {
                out.push(&s[st..i]);
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(st) = start {
        out.push(&s[st..]);
    }
    out
}

/// Splits around runs of Unicode white space.
pub fn split_whitespace(s: &[u8]) -> Vec<&[u8]> {
    if s.is_ascii() {
        return s
            .split(|&c| is_ascii_space(c))
            .filter(|f| !f.is_empty())
            .collect();
    }
    split_fields_by(s, unicode::is_space)
}

/// The index of the first rune for which `f` equals `truth`.
fn find_by_truth(s: &[u8], f: &impl Fn(CodePoint) -> bool, truth: bool) -> Option<usize> {
    code_points(s)
        .find(|&(_, r, _)| f(r) == truth)
        .map(|(i, _, _)| i)
}

/// The index of the last rune for which `f` equals `truth`.
fn rfind_by_truth(s: &[u8], f: &impl Fn(CodePoint) -> bool, truth: bool) -> Option<usize> {
    let mut i = s.len();
    while i > 0 {
        let (r, size) = decode_last_code_point(&s[..i]);
        i -= size;
        if f(r) == truth {
            return Some(i);
        }
    }
    None
}

pub fn find_by(s: &[u8], f: impl Fn(CodePoint) -> bool) -> Option<usize> {
    find_by_truth(s, &f, true)
}

pub fn rfind_by(s: &[u8], f: impl Fn(CodePoint) -> bool) -> Option<usize> {
    rfind_by_truth(s, &f, true)
}

pub fn contains_by(s: &[u8], f: impl Fn(CodePoint) -> bool) -> bool {
    find_by(s, f).is_some()
}

pub fn trim_start_by(s: &[u8], f: impl Fn(CodePoint) -> bool) -> &[u8] {
    match find_by_truth(s, &f, false) {
        Some(i) => &s[i..],
        None => &s[s.len()..],
    }
}

/// Decodes backwards: a trailing invalid byte is U+FFFD.
pub fn trim_end_by(s: &[u8], f: impl Fn(CodePoint) -> bool) -> &[u8] {
    match rfind_by_truth(s, &f, false) {
        Some(i) => {
            let (_, w) = decode_code_point(&s[i..]);
            &s[..i + w.max(1)]
        }
        None => &s[..0],
    }
}

pub fn trim_by(s: &[u8], f: impl Fn(CodePoint) -> bool) -> &[u8] {
    trim_end_by(trim_start_by(s, &f), &f)
}

pub fn trim_whitespace(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() {
        let c = s[start];
        if c >= 0x80 {
            return trim_by(&s[start..], unicode::is_space);
        }
        if !is_ascii_space(c) {
            break;
        }
        start += 1;
    }
    let mut stop = s.len();
    while stop > start {
        let c = s[stop - 1];
        if c >= 0x80 {
            return trim_end_by(&s[start..stop], unicode::is_space);
        }
        if !is_ascii_space(c) {
            break;
        }
        stop -= 1;
    }
    &s[start..stop]
}

pub fn find_code_point(s: &[u8], r: CodePoint) -> Option<usize> {
    if (0..0x80).contains(&r) {
        return memchr::memchr(r as u8, s);
    }
    if r == REPLACEMENT_CODE_POINT {
        return code_points(s)
            .find(|&(_, c, _)| c == REPLACEMENT_CODE_POINT)
            .map(|(i, _, _)| i);
    }
    if !utf8::is_valid_code_point(r) {
        return None;
    }
    find(s, &utf8::encode_code_point(r))
}

pub fn contains_code_point(s: &[u8], r: CodePoint) -> bool {
    find_code_point(s, r).is_some()
}

pub fn find_any_of(s: &[u8], chars: &[u8]) -> Option<usize> {
    if chars.is_empty() {
        return None;
    }
    if chars.len() == 1 {
        let r = if chars[0] >= 0x80 {
            REPLACEMENT_CODE_POINT
        } else {
            chars[0] as CodePoint
        };
        return find_code_point(s, r);
    }
    if chars.is_ascii() {
        return match *chars {
            [a, b] => memchr::memchr2(a, b, s),
            [a, b, c] => memchr::memchr3(a, b, c, s),
            _ => {
                let mut set = [false; 256];
                for &c in chars {
                    set[c as usize] = true;
                }
                s.iter().position(|&c| set[c as usize])
            }
        };
    }
    code_points(s)
        .find(|&(_, c, _)| find_code_point(chars, c).is_some())
        .map(|(i, _, _)| i)
}

pub fn rfind_any_of(s: &[u8], chars: &[u8]) -> Option<usize> {
    if chars.is_empty() {
        return None;
    }
    if chars.is_ascii() {
        return s.iter().rposition(|c| chars.contains(c));
    }
    let mut i = s.len();
    while i > 0 {
        let (r, size) = decode_last_code_point(&s[..i]);
        i -= size;
        if find_code_point(chars, r).is_some() {
            return Some(i);
        }
    }
    None
}

pub fn contains_any_of(s: &[u8], chars: &[u8]) -> bool {
    find_any_of(s, chars).is_some()
}

/// Whether `r` is one of the runes of `cutset`; shared by the trim functions.
fn in_char_set(cutset: &[u8], r: CodePoint) -> bool {
    find_code_point(cutset, r).is_some()
}

/// The cutset is a set of runes.
pub fn trim_start_chars<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
    if s.is_empty() || cutset.is_empty() {
        return s;
    }
    if cutset.is_ascii() {
        let i = s
            .iter()
            .position(|c| !cutset.contains(c))
            .unwrap_or(s.len());
        return &s[i..];
    }
    let mut i = 0;
    while i < s.len() {
        let (r, w) = if s[i] < 0x80 {
            (s[i] as CodePoint, 1)
        } else {
            decode_code_point(&s[i..])
        };
        if !in_char_set(cutset, r) {
            break;
        }
        i += w;
    }
    &s[i..]
}

/// The cutset is a set of runes.
pub fn trim_end_chars<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
    if s.is_empty() || cutset.is_empty() {
        return s;
    }
    if cutset.is_ascii() {
        let i = s
            .iter()
            .rposition(|c| !cutset.contains(c))
            .map_or(0, |i| i + 1);
        return &s[..i];
    }
    let mut end = s.len();
    while end > 0 {
        let (r, w) = if s[end - 1] < 0x80 {
            (s[end - 1] as CodePoint, 1)
        } else {
            decode_last_code_point(&s[..end])
        };
        if !in_char_set(cutset, r) {
            break;
        }
        end -= w;
    }
    &s[..end]
}

pub fn trim_chars<'a>(s: &'a [u8], cutset: &[u8]) -> &'a [u8] {
    trim_start_chars(trim_end_chars(s, cutset), cutset)
}

pub fn trim_prefix<'a>(s: &'a [u8], prefix: &[u8]) -> &'a [u8] {
    s.strip_prefix(prefix).unwrap_or(s)
}

pub fn trim_suffix<'a>(s: &'a [u8], suffix: &[u8]) -> &'a [u8] {
    s.strip_suffix(suffix).unwrap_or(s)
}

/// Rough frequency rank of a byte in request data (lower = rarer); `index` searches for the
/// rarer end byte of its needle.
static BYTE_FREQUENCY_RANK: [u8; 256] = {
    let mut t = [0u8; 256];
    let common = b" etaoinsrhldcumfpgwybvkxjqz";
    let mut i = 0;
    while i < common.len() {
        let c = common[i];
        t[c as usize] = (200 - i * 3) as u8;
        if c.is_ascii_lowercase() {
            t[(c - 32) as usize] = (140 - i * 3) as u8; // upper case letters are rarer
        }
        i += 1;
    }
    let mut c = b'0';
    while c <= b'9' {
        t[c as usize] = 150;
        c += 1;
    }
    let punct = b"/.=&-_:%,;\"'()";
    let mut i = 0;
    while i < punct.len() {
        t[punct[i] as usize] = 120;
        i += 1;
    }
    t
};

/// Haystacks from this length on go straight to `memmem` (its searcher is built once per call,
/// which only pays off on longer input).
const INDEX_ANCHOR_MAX_HAY: usize = 256;
/// False hits of the anchor byte after which `index` hands the rest to `memmem`.
const INDEX_ANCHOR_MAX_FAILS: usize = 12;

/// Byte search (an empty needle is found at 0). Short haystacks, the common
/// case for request values, are searched through the rarer end byte of the needle with
/// `memchr` and a compare per hit; long ones and dense hits go to `memmem`. The result is
/// the first occurrence either way.
pub fn find(s: &[u8], sub: &[u8]) -> Option<usize> {
    let m = sub.len();
    if m == 0 {
        return Some(0);
    }
    if m > s.len() {
        return None;
    }
    if m == 1 {
        return memchr::memchr(sub[0], s);
    }
    if s.len() >= INDEX_ANCHOR_MAX_HAY {
        return memchr::memmem::find(s, sub);
    }
    let a = if BYTE_FREQUENCY_RANK[sub[m - 1] as usize] < BYTE_FREQUENCY_RANK[sub[0] as usize] {
        m - 1
    } else {
        0
    };
    let c = sub[a];
    let last = s.len() - m;
    let mut start = 0;
    let mut fails = 0;
    while start <= last {
        let st = start + memchr::memchr(c, &s[start + a..=last + a])?;
        if s[st..st + m] == *sub {
            return Some(st);
        }
        start = st + 1;
        fails += 1;
        if fails >= INDEX_ANCHOR_MAX_FAILS {
            return memchr::memmem::find(&s[start..], sub).map(|i| start + i);
        }
    }
    None
}

pub fn rfind(s: &[u8], sub: &[u8]) -> Option<usize> {
    if sub.is_empty() {
        return Some(s.len());
    }
    if sub.len() > s.len() {
        return None;
    }
    memchr::memmem::rfind(s, sub)
}

pub fn contains(s: &[u8], sub: &[u8]) -> bool {
    find(s, sub).is_some()
}

/// Non-overlapping; an empty needle counts runes + 1.
pub fn count(s: &[u8], sub: &[u8]) -> usize {
    if sub.is_empty() {
        return utf8::count_code_points(s) + 1;
    }
    // find_iter yields non-overlapping matches, left to right
    memchr::memmem::find_iter(s, sub).count()
}

pub fn cut<'a>(s: &'a [u8], sep: &[u8]) -> (&'a [u8], &'a [u8], bool) {
    match find(s, sep) {
        Some(i) => (&s[..i], &s[i + sep.len()..], true),
        None => (s, &s[s.len()..], false),
    }
}

/// Replaces up to `n` matches (n < 0: all). An empty `old` inserts `new` before every rune and
/// at the end.
pub fn replace(s: &[u8], old: &[u8], new: &[u8], n: isize) -> Vec<u8> {
    if old == new || n == 0 {
        return s.to_vec();
    }
    let m = count(s, old);
    if m == 0 {
        return s.to_vec();
    }
    let n = if n < 0 || (m as isize) < n {
        m
    } else {
        n as usize
    };
    let mut b = Vec::with_capacity(s.len() + n * new.len());
    let mut start = 0;
    for i in 0..n {
        let mut j = start;
        if old.is_empty() {
            if i > 0 {
                j += decode_code_point(&s[start..]).1;
            }
        } else {
            j += find(&s[start..], old).expect("counted");
        }
        b.extend_from_slice(&s[start..j]);
        b.extend_from_slice(new);
        start = j + old.len();
    }
    b.extend_from_slice(&s[start..]);
    b
}

pub fn replace_all(s: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    replace(s, old, new, -1)
}

/// At most n UTF-8 sequences (invalid bytes one each), n < 0 = all.
fn split_into_chars(mut s: &[u8], n: isize) -> Vec<&[u8]> {
    let l = utf8::count_code_points(s);
    let n = if n < 0 || n as usize > l {
        l
    } else {
        n as usize
    };
    let mut a = Vec::with_capacity(n);
    for _ in 0..n.saturating_sub(1) {
        let (_, size) = decode_code_point(s);
        a.push(&s[..size]);
        s = &s[size..];
    }
    if n > 0 {
        a.push(s);
    }
    a
}

pub fn splitn<'a>(s: &'a [u8], sep: &[u8], n: isize) -> Vec<&'a [u8]> {
    if n == 0 {
        return Vec::new();
    }
    if sep.is_empty() {
        return split_into_chars(s, n);
    }
    let n = if n < 0 { count(s, sep) as isize + 1 } else { n };
    let n = n.min(s.len() as isize + 1) as usize;
    let mut a = Vec::with_capacity(n);
    let mut s = s;
    while a.len() + 1 < n {
        match find(s, sep) {
            Some(m) => {
                a.push(&s[..m]);
                s = &s[m + sep.len()..];
            }
            None => break,
        }
    }
    a.push(s);
    a
}

pub fn split<'a>(s: &'a [u8], sep: &[u8]) -> Vec<&'a [u8]> {
    splitn(s, sep, -1)
}

/// Each run of invalid bytes becomes one `replacement`.
pub fn replace_invalid_utf8(s: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(s.len());
    let mut invalid = false;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c < 0x80 {
            i += 1;
            invalid = false;
            b.push(c);
            continue;
        }
        let (_, wid) = decode_code_point(&s[i..]);
        if wid == 1 {
            i += 1;
            if !invalid {
                invalid = true;
                b.extend_from_slice(replacement);
            }
            continue;
        }
        invalid = false;
        b.extend_from_slice(&s[i..i + wid]);
        i += wid;
    }
    b
}

pub fn repeat(s: &[u8], count: usize) -> Vec<u8> {
    s.repeat(count)
}

pub fn join<S: AsRef<[u8]>>(elems: &[S], sep: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, e) in elems.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(sep);
        }
        out.extend_from_slice(e.as_ref());
    }
    out
}

/// At each position the earliest (old, new) pair whose `old` matches wins; no match copies
/// one byte. Empty `old` strings are not supported.
#[derive(Clone, Debug)]
pub struct MultiReplacer {
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
    first: [bool; 256],
}

impl MultiReplacer {
    pub fn new(oldnew: &[&[u8]]) -> MultiReplacer {
        assert!(
            oldnew.len().is_multiple_of(2),
            "strings.NewReplacer: odd argument count"
        );
        let mut first = [false; 256];
        let mut pairs = Vec::new();
        for p in oldnew.chunks(2) {
            assert!(
                !p[0].is_empty(),
                "bytetext MultiReplacer: empty old string unsupported"
            );
            first[p[0][0] as usize] = true;
            pairs.push((p[0].to_vec(), p[1].to_vec()));
        }
        MultiReplacer { pairs, first }
    }

    pub fn replace(&self, s: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len());
        let mut i = 0;
        'outer: while i < s.len() {
            if self.first[s[i] as usize] {
                for (old, new) in &self.pairs {
                    if s[i..].starts_with(old) {
                        out.extend_from_slice(new);
                        i += old.len();
                        continue 'outer;
                    }
                }
            }
            out.push(s[i]);
            i += 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_lower_upper() {
        assert_eq!(to_lowercase(b"HeLLo"), b"hello");
        assert_eq!(to_lowercase("ÀÉ\u{212A}".as_bytes()), "àék".as_bytes());
        assert_eq!(to_lowercase(b"A\xffB"), b"a\xef\xbf\xbdb");
        assert_eq!(to_lowercase("İ".as_bytes()), b"i"); // U+0130 → 'i'
        assert_eq!(to_uppercase("ſ".as_bytes()), b"S");
        assert_eq!(to_lowercase(b"\xff"), "\u{FFFD}".as_bytes()); // non-ASCII path
        assert_eq!(to_lowercase("\u{FFFD}".as_bytes()), "\u{FFFD}".as_bytes());
    }

    #[test]
    fn eq_ignore_case_reference() {
        assert!(eq_ignore_case(b"Go", b"GO"));
        assert!(eq_ignore_case("k".as_bytes(), "\u{212A}".as_bytes()));
        assert!(eq_ignore_case("ſ".as_bytes(), b"S"));
        assert!(eq_ignore_case(b"\xff", b"\xfe"));
        assert!(eq_ignore_case(b"\xff", "\u{FFFD}".as_bytes()));
        assert!(!eq_ignore_case(b"a", b"ab"));
        assert!(!eq_ignore_case("ß".as_bytes(), b"ss"));
    }

    #[test]
    fn trim_and_fields() {
        assert_eq!(trim_whitespace(b" \t a b \n"), b"a b");
        assert_eq!(trim_whitespace("\u{3000}x\u{a0}".as_bytes()), b"x");
        assert_eq!(trim_whitespace(b"\xa0x\xa0"), b"\xa0x\xa0"); // raw 0xA0 is invalid UTF-8
        assert_eq!(trim_whitespace("x\u{85}".as_bytes()), b"x");
        assert_eq!(split_whitespace(b"  a  b\tc "), vec![&b"a"[..], b"b", b"c"]);
        assert_eq!(
            split_whitespace(b"a\xe2\x80\x83b\xffc"),
            vec![&b"a"[..], b"b\xffc"]
        );
        assert_eq!(trim_chars(b"'\"x\"'", b"'\"`"), b"x");
        assert_eq!(trim_start_chars("ééa".as_bytes(), "é".as_bytes()), b"a");
        assert_eq!(trim_end_chars(b"a\xff\xfe", "\u{FFFD}".as_bytes()), b"a");
    }

    #[test]
    fn index_any_and_count() {
        assert_eq!(find_any_of(b"abc", b"xc"), Some(2));
        assert_eq!(find_any_of(b"a\xffc", "\u{FFFD}".as_bytes()), Some(1));
        assert_eq!(find_any_of(b"a\xffc", b"\xfe"), Some(1)); // single non-ASCII byte reads as U+FFFD
        assert!(!contains_any_of(b"abc", b""));
        assert_eq!(count(b"cheese", b"e"), 3);
        assert_eq!(count("five€".as_bytes(), b""), 6);
        assert_eq!(replace(b"abc", b"", b"-", -1), b"-a-b-c-");
        assert_eq!(replace(b"aaa", b"a", b"b", 2), b"bba");
        assert_eq!(split(b"a,b,,c", b","), vec![&b"a"[..], b"b", b"", b"c"]);
        assert_eq!(split("a€".as_bytes(), b""), vec![&b"a"[..], "€".as_bytes()]);
        assert_eq!(splitn(b"a,b,c", b",", 2), vec![&b"a"[..], b"b,c"]);
        assert_eq!(replace_invalid_utf8(b"a\xff\xfeb\xff", b"?"), b"a?b?");
    }

    #[test]
    fn replacer_priority() {
        let r = MultiReplacer::new(&[b"/*", b"", b"*/", b"", b"--", b"", b"#", b""]);
        assert_eq!(r.replace(b"a/*b*/c--d#e/*/"), b"abcde/");
        let r = MultiReplacer::new(&[b"a", b"1", b"ab", b"2"]);
        assert_eq!(r.replace(b"ab"), b"1b");
    }
}
