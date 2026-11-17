//! UTF-8 decoding, encoding and validation over byte strings.

use crate::CodePoint;

pub const REPLACEMENT_CODE_POINT: CodePoint = 0xFFFD;
pub const ASCII_LIMIT: u8 = 0x80;
pub const MAX_CODE_POINT: CodePoint = 0x10FFFF;
pub const MAX_UTF8_LEN: usize = 4;
const SURROGATE_MIN: CodePoint = 0xD800;
const SURROGATE_MAX: CodePoint = 0xDFFF;

/// The first code point of `s` and its width. Empty → (U+FFFD, 0); an invalid
/// encoding → (U+FFFD, 1).
pub fn decode_code_point(s: &[u8]) -> (CodePoint, usize) {
    let n = s.len();
    if n == 0 {
        return (REPLACEMENT_CODE_POINT, 0);
    }
    let b0 = s[0];
    if b0 < 0x80 {
        return (b0 as CodePoint, 1);
    }
    // accept range for the second byte, and total width
    let (lo, hi, w) = match b0 {
        0xC2..=0xDF => (0x80, 0xBF, 2),
        0xE0 => (0xA0, 0xBF, 3),
        0xE1..=0xEC | 0xEE..=0xEF => (0x80, 0xBF, 3),
        0xED => (0x80, 0x9F, 3),
        0xF0 => (0x90, 0xBF, 4),
        0xF1..=0xF3 => (0x80, 0xBF, 4),
        0xF4 => (0x80, 0x8F, 4),
        _ => return (REPLACEMENT_CODE_POINT, 1),
    };
    if n < 2 || s[1] < lo || s[1] > hi {
        return (REPLACEMENT_CODE_POINT, 1);
    }
    if w == 2 {
        return (
            (((b0 & 0x1F) as CodePoint) << 6) | (s[1] & 0x3F) as CodePoint,
            2,
        );
    }
    if n < 3 || !(0x80..=0xBF).contains(&s[2]) {
        return (REPLACEMENT_CODE_POINT, 1);
    }
    if w == 3 {
        return (
            (((b0 & 0x0F) as CodePoint) << 12)
                | (((s[1] & 0x3F) as CodePoint) << 6)
                | (s[2] & 0x3F) as CodePoint,
            3,
        );
    }
    if n < 4 || !(0x80..=0xBF).contains(&s[3]) {
        return (REPLACEMENT_CODE_POINT, 1);
    }
    (
        (((b0 & 0x07) as CodePoint) << 18)
            | (((s[1] & 0x3F) as CodePoint) << 12)
            | (((s[2] & 0x3F) as CodePoint) << 6)
            | (s[3] & 0x3F) as CodePoint,
        4,
    )
}

pub fn decode_last_code_point(s: &[u8]) -> (CodePoint, usize) {
    let end = s.len();
    if end == 0 {
        return (REPLACEMENT_CODE_POINT, 0);
    }
    let last = s[end - 1];
    if last < 0x80 {
        return (last as CodePoint, 1);
    }
    // Back up to the start of a rune, at most MAX_UTF8_LEN bytes.
    let lim = end.saturating_sub(MAX_UTF8_LEN);
    let mut start = end - 1;
    while start > lim {
        start -= 1;
        if is_lead_byte(s[start]) {
            break;
        }
    }
    let (r, size) = decode_code_point(&s[start..end]);
    if start + size != end {
        return (REPLACEMENT_CODE_POINT, 1);
    }
    (r, size)
}

pub fn is_lead_byte(b: u8) -> bool {
    b & 0xC0 != 0x80
}

pub fn is_valid_code_point(r: CodePoint) -> bool {
    (0..SURROGATE_MIN).contains(&r) || (SURROGATE_MAX < r && r <= MAX_CODE_POINT)
}

/// -1 for an invalid code point.
pub fn encoded_len(r: CodePoint) -> isize {
    if r < 0 {
        -1
    } else if r < 0x80 {
        1
    } else if r < 0x800 {
        2
    } else if (SURROGATE_MIN..=SURROGATE_MAX).contains(&r) {
        -1
    } else if r < 0x10000 {
        3
    } else if r <= MAX_CODE_POINT {
        4
    } else {
        -1
    }
}

/// An invalid code point appends U+FFFD.
pub fn push_code_point(dst: &mut Vec<u8>, r: CodePoint) {
    let r = if is_valid_code_point(r) {
        r as u32
    } else {
        REPLACEMENT_CODE_POINT as u32
    };
    if r < 0x80 {
        dst.push(r as u8);
    } else if r < 0x800 {
        dst.extend_from_slice(&[0xC0 | (r >> 6) as u8, 0x80 | (r & 0x3F) as u8]);
    } else if r < 0x10000 {
        dst.extend_from_slice(&[
            0xE0 | (r >> 12) as u8,
            0x80 | ((r >> 6) & 0x3F) as u8,
            0x80 | (r & 0x3F) as u8,
        ]);
    } else {
        dst.extend_from_slice(&[
            0xF0 | (r >> 18) as u8,
            0x80 | ((r >> 12) & 0x3F) as u8,
            0x80 | ((r >> 6) & 0x3F) as u8,
            0x80 | (r & 0x3F) as u8,
        ]);
    }
}

/// Encodes into a fresh buffer.
pub fn encode_code_point(r: CodePoint) -> Vec<u8> {
    let mut v = Vec::with_capacity(4);
    push_code_point(&mut v, r);
    v
}

/// Invalid bytes count one each.
pub fn count_code_points(s: &[u8]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < s.len() {
        if s[i] < 0x80 {
            i += 1;
        } else {
            i += decode_code_point(&s[i..]).1;
        }
        n += 1;
    }
    n
}

pub fn is_valid(s: &[u8]) -> bool {
    std::str::from_utf8(s).is_ok()
}

pub fn has_complete_code_point(s: &[u8]) -> bool {
    if s.is_empty() {
        return false;
    }
    let (r, w) = decode_code_point(s);
    if w > 1 || r != REPLACEMENT_CODE_POINT {
        return true;
    }
    // invalid at width 1: a truncated prefix of a valid sequence is not full
    let need = match s[0] {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return true,
    };
    if s.len() >= need {
        return true;
    }
    // every present continuation byte must be acceptable for it to be a prefix
    let (lo, hi) = match s[0] {
        0xE0 => (0xA0, 0xBF),
        0xED => (0x80, 0x9F),
        0xF0 => (0x90, 0xBF),
        0xF4 => (0x80, 0x8F),
        _ => (0x80, 0xBF),
    };
    if s.len() > 1 && (s[1] < lo || s[1] > hi) {
        return true;
    }
    if s.len() > 2 && !(0x80..=0xBF).contains(&s[2]) {
        return true;
    }
    false
}

/// Yields (byte index, code point, width); an invalid byte is (U+FFFD, 1).
pub fn code_points(s: &[u8]) -> CodePoints<'_> {
    CodePoints { s, i: 0 }
}

pub struct CodePoints<'a> {
    s: &'a [u8],
    i: usize,
}

impl Iterator for CodePoints<'_> {
    type Item = (usize, CodePoint, usize);
    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.s.len() {
            return None;
        }
        let i = self.i;
        let c = self.s[i];
        let (r, w) = if c < 0x80 {
            (c as CodePoint, 1)
        } else {
            decode_code_point(&self.s[i..])
        };
        self.i += w;
        Some((i, r, w))
    }
}

pub fn to_code_points(s: &[u8]) -> Vec<CodePoint> {
    code_points(s).map(|(_, r, _)| r).collect()
}

pub fn from_code_points(rs: &[CodePoint]) -> Vec<u8> {
    let mut v = Vec::with_capacity(rs.len());
    for &r in rs {
        push_code_point(&mut v, r);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_matches_reference() {
        assert_eq!(decode_code_point(b""), (REPLACEMENT_CODE_POINT, 0));
        assert_eq!(decode_code_point(b"a"), ('a' as CodePoint, 1));
        assert_eq!(decode_code_point("é".as_bytes()), (0xE9, 2));
        assert_eq!(
            decode_code_point(b"\xed\xa0\x80"),
            (REPLACEMENT_CODE_POINT, 1)
        ); // surrogate
        assert_eq!(decode_code_point(b"\xc0\x80"), (REPLACEMENT_CODE_POINT, 1)); // overlong
        assert_eq!(decode_code_point(b"\xe2\x82"), (REPLACEMENT_CODE_POINT, 1)); // truncated
        assert_eq!(
            decode_code_point(b"\xf4\x90\x80\x80"),
            (REPLACEMENT_CODE_POINT, 1)
        ); // > MaxRune
        assert_eq!(decode_code_point("€".as_bytes()), (0x20AC, 3));
        assert_eq!(decode_code_point("😀".as_bytes()), (0x1F600, 4));
        assert_eq!(decode_last_code_point("a€".as_bytes()), (0x20AC, 3));
        assert_eq!(
            decode_last_code_point(b"a\xe2\x82"),
            (REPLACEMENT_CODE_POINT, 1)
        );
        assert_eq!(decode_last_code_point(b"\x80"), (REPLACEMENT_CODE_POINT, 1));
        assert_eq!(count_code_points(b"a\xffb\xe2\x82\xac"), 4);
        assert_eq!(encode_code_point(0xD800), "\u{FFFD}".as_bytes());
        assert_eq!(encode_code_point(-1), "\u{FFFD}".as_bytes());
        assert!(!has_complete_code_point(b"\xe2\x82"));
        assert!(has_complete_code_point(b"\xe2\x28"));
    }

    #[test]
    fn decode_agrees_with_std_on_every_two_and_three_byte_prefix() {
        for a in 0x80u32..=0xFF {
            for b in 0u32..=0xFF {
                let s = [a as u8, b as u8, 0x80, 0x80];
                let (r, w) = decode_code_point(&s);
                let std_w = match std::str::from_utf8(&s[..]) {
                    Ok(_) => 4,
                    Err(e) => e.valid_up_to(),
                };
                if std_w == 0 {
                    assert_eq!((r, w), (REPLACEMENT_CODE_POINT, 1), "{a:x} {b:x}");
                } else {
                    let ch = std::str::from_utf8(&s[..w])
                        .unwrap()
                        .chars()
                        .next()
                        .unwrap();
                    assert_eq!(r, ch as CodePoint);
                }
            }
        }
    }
}
