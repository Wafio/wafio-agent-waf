//! Hex encoding and decoding.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexDecodeError {
    /// A byte that is not a hex digit.
    InvalidByte(u8),
    /// Odd input length.
    Length,
}

impl fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Printable bytes also show the character.
            HexDecodeError::InvalidByte(b) if crate::unicode::is_print(*b as i32) => {
                write!(
                    f,
                    "encoding/hex: invalid byte: U+{:04X} '{}'",
                    b, *b as char
                )
            }
            HexDecodeError::InvalidByte(b) => write!(f, "encoding/hex: invalid byte: U+{:04X}", b),
            HexDecodeError::Length => f.write_str("encoding/hex: odd length hex string"),
        }
    }
}

impl std::error::Error for HexDecodeError {}

fn from_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Lower-case hex.
pub fn encode(src: &[u8]) -> Vec<u8> {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(src.len() * 2);
    for &b in src {
        out.push(H[(b >> 4) as usize]);
        out.push(H[(b & 15) as usize]);
    }
    out
}

/// Decodes as far as possible: the bytes decoded before the error come back with it.
pub fn decode_partial(src: &[u8]) -> (Vec<u8>, Option<HexDecodeError>) {
    let mut out = Vec::with_capacity(src.len() / 2);
    let mut j = 1;
    while j < src.len() {
        let (p, q) = (src[j - 1], src[j]);
        let Some(a) = from_hex(p) else {
            return (out, Some(HexDecodeError::InvalidByte(p)));
        };
        let Some(b) = from_hex(q) else {
            return (out, Some(HexDecodeError::InvalidByte(q)));
        };
        out.push(a << 4 | b);
        j += 2;
    }
    if src.len() % 2 == 1 {
        if from_hex(src[j - 1]).is_none() {
            return (out, Some(HexDecodeError::InvalidByte(src[j - 1])));
        }
        return (out, Some(HexDecodeError::Length));
    }
    (out, None)
}

pub fn decode(src: &[u8]) -> Result<Vec<u8>, HexDecodeError> {
    match decode_partial(src) {
        (d, None) => Ok(d),
        (_, Some(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_reference() {
        assert_eq!(encode(b"\x01\xab"), b"01ab");
        assert_eq!(decode(b"01AB").unwrap(), b"\x01\xab");
        assert_eq!(decode(b"0g"), Err(HexDecodeError::InvalidByte(b'g')));
        assert_eq!(decode(b"012"), Err(HexDecodeError::Length));
        assert_eq!(decode(b"01z"), Err(HexDecodeError::InvalidByte(b'z')));
        assert_eq!(
            decode_partial(b"0102zz"),
            (
                b"\x01\x02".to_vec(),
                Some(HexDecodeError::InvalidByte(b'z'))
            )
        );
        assert_eq!(
            HexDecodeError::InvalidByte(b'g').to_string(),
            "encoding/hex: invalid byte: U+0067 'g'"
        );
    }
}
