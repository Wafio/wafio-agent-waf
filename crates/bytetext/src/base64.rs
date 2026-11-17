//! Base64 (non-strict encodings: [`STANDARD`], [`URL_SAFE`], [`STANDARD_NO_PAD`],
//! [`URL_SAFE_NO_PAD`]). Decoding skips '\r' and '\n' anywhere.

use std::fmt;

pub struct Variant {
    alphabet: &'static [u8; 64],
    decode_map: [u8; 256],
    padded: bool,
}

const fn decode_map(alpha: &[u8; 64]) -> [u8; 256] {
    let mut m = [0xFFu8; 256];
    let mut i = 0;
    while i < 64 {
        m[alpha[i] as usize] = i as u8;
        i += 1;
    }
    m
}

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub static STANDARD: Variant = Variant {
    alphabet: STD,
    decode_map: decode_map(STD),
    padded: true,
};
pub static URL_SAFE: Variant = Variant {
    alphabet: URL,
    decode_map: decode_map(URL),
    padded: true,
};
pub static STANDARD_NO_PAD: Variant = Variant {
    alphabet: STD,
    decode_map: decode_map(STD),
    padded: false,
};
pub static URL_SAFE_NO_PAD: Variant = Variant {
    alphabet: URL,
    decode_map: decode_map(URL),
    padded: false,
};

/// Illegal base64 data at this input byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base64DecodeError(pub usize);

impl fmt::Display for Base64DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "illegal base64 data at input byte {}", self.0)
    }
}

impl std::error::Error for Base64DecodeError {}

impl Variant {
    pub fn encode(&self, src: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(src.len().div_ceil(3) * 4);
        for chunk in src.chunks(3) {
            let v = (chunk[0] as u32) << 16
                | (*chunk.get(1).unwrap_or(&0) as u32) << 8
                | *chunk.get(2).unwrap_or(&0) as u32;
            let n = chunk.len() + 1;
            for k in 0..4 {
                if k < n {
                    out.push(self.alphabet[((v >> (18 - 6 * k)) & 0x3F) as usize]);
                } else if self.padded {
                    out.push(b'=');
                }
            }
        }
        out
    }

    /// Decodes one quantum; appends to dst, returns the new source index and the error, if any.
    fn decode_quantum(
        &self,
        dst: &mut Vec<u8>,
        src: &[u8],
        mut si: usize,
    ) -> (usize, Option<Base64DecodeError>) {
        let mut dbuf = [0u8; 4];
        let mut dlen = 4;
        let mut err = None;
        let mut j = 0;
        while j < 4 {
            if src.len() == si {
                if j == 0 {
                    return (si, None);
                }
                if j == 1 || self.padded {
                    return (si, Some(Base64DecodeError(si - j)));
                }
                dlen = j;
                break;
            }
            let inb = src[si];
            si += 1;
            let out = self.decode_map[inb as usize];
            if out != 0xFF {
                dbuf[j] = out;
                j += 1;
                continue;
            }
            if inb == b'\n' || inb == b'\r' {
                continue;
            }
            if !self.padded || inb != b'=' {
                return (si, Some(Base64DecodeError(si - 1)));
            }
            match j {
                0 | 1 => return (si, Some(Base64DecodeError(si - 1))),
                2 => {
                    while si < src.len() && (src[si] == b'\n' || src[si] == b'\r') {
                        si += 1;
                    }
                    if si == src.len() {
                        return (si, Some(Base64DecodeError(src.len())));
                    }
                    if src[si] != b'=' {
                        return (si, Some(Base64DecodeError(si - 1)));
                    }
                    si += 1;
                }
                _ => {}
            }
            while si < src.len() && (src[si] == b'\n' || src[si] == b'\r') {
                si += 1;
            }
            if si < src.len() {
                err = Some(Base64DecodeError(si));
            }
            dlen = j;
            break;
        }
        let val = (dbuf[0] as u32) << 18
            | (dbuf[1] as u32) << 12
            | (dbuf[2] as u32) << 6
            | dbuf[3] as u32;
        let bytes = [(val >> 16) as u8, (val >> 8) as u8, val as u8];
        dst.extend_from_slice(&bytes[..dlen - 1]);
        (si, err)
    }

    /// Decodes as far as possible: the bytes decoded before an error come back with it.
    pub fn decode_partial(&self, src: &[u8]) -> (Vec<u8>, Option<Base64DecodeError>) {
        let mut dst = Vec::with_capacity(src.len() / 4 * 3 + 3);
        let mut si = 0;
        while si < src.len() {
            let (nsi, err) = self.decode_quantum(&mut dst, src, si);
            si = nsi;
            if err.is_some() {
                return (dst, err);
            }
        }
        (dst, None)
    }

    pub fn decode(&self, src: &[u8]) -> Result<Vec<u8>, Base64DecodeError> {
        match self.decode_partial(src) {
            (d, None) => Ok(d),
            (_, Some(e)) => Err(e),
        }
    }

    pub fn encoded_len(&self, n: usize) -> usize {
        if self.padded {
            n.div_ceil(3) * 4
        } else {
            (n * 8).div_ceil(6)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_reference() {
        assert_eq!(STANDARD.decode(b"aGVsbG8=").unwrap(), b"hello");
        assert_eq!(STANDARD.decode(b"aGVs\nbG8=\r\n").unwrap(), b"hello");
        assert_eq!(STANDARD.decode(b"aGVsbG8"), Err(Base64DecodeError(4)));
        assert_eq!(STANDARD_NO_PAD.decode(b"aGVsbG8").unwrap(), b"hello");
        assert_eq!(
            STANDARD_NO_PAD.decode(b"aGVsbG8="),
            Err(Base64DecodeError(7))
        );
        assert_eq!(STANDARD.decode(b"QQ=="), Ok(b"A".to_vec()));
        assert_eq!(STANDARD.decode(b"QR=="), Ok(b"A".to_vec())); // non-strict
        assert_eq!(STANDARD.decode(b"QQ="), Err(Base64DecodeError(3)));
        assert_eq!(
            STANDARD.decode_partial(b"QUJD QQ=="),
            (b"ABC".to_vec(), Some(Base64DecodeError(4)))
        );
        assert_eq!(
            STANDARD.decode_partial(b"QQ==x"),
            (b"A".to_vec(), Some(Base64DecodeError(4)))
        );
        assert_eq!(STANDARD.decode(b"Q"), Err(Base64DecodeError(0)));
        assert_eq!(URL_SAFE.decode(b"-_8=").unwrap(), [0xfb, 0xff]);
        assert_eq!(STANDARD.decode(b"").unwrap(), b"");
        assert_eq!(STANDARD.encode(b"hello"), b"aGVsbG8=");
        assert_eq!(URL_SAFE_NO_PAD.encode(&[0xfb, 0xff]), b"-_8");
    }
}
