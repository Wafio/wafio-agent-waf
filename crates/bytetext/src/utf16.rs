//! UTF-16 surrogate handling.

use crate::CodePoint;

const REPLACEMENT: CodePoint = 0xFFFD;

pub fn is_surrogate(r: CodePoint) -> bool {
    (0xD800..0xE000).contains(&r)
}

/// The code point of a surrogate pair, else U+FFFD.
pub fn decode_surrogate_pair(r1: CodePoint, r2: CodePoint) -> CodePoint {
    if (0xD800..0xDC00).contains(&r1) && (0xDC00..0xE000).contains(&r2) {
        return ((r1 - 0xD800) << 10 | (r2 - 0xDC00)) + 0x10000;
    }
    REPLACEMENT
}

/// Lone surrogates become U+FFFD.
pub fn decode(s: &[u16]) -> Vec<CodePoint> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let r = s[i] as CodePoint;
        if !(0xD800..0xE000).contains(&r) {
            out.push(r);
        } else if (0xD800..0xDC00).contains(&r)
            && i + 1 < s.len()
            && (0xDC00..0xE000).contains(&(s[i + 1] as CodePoint))
        {
            out.push(decode_surrogate_pair(r, s[i + 1] as CodePoint));
            i += 1;
        } else {
            out.push(REPLACEMENT);
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_reference() {
        assert_eq!(
            decode(&[0x41, 0xD83D, 0xDE00, 0xD800, 0x42, 0xDC00]),
            vec![0x41, 0x1F600, 0xFFFD, 0x42, 0xFFFD]
        );
    }
}
