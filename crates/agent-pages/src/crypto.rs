//! Crypto and encoding primitives: HMAC-SHA256, AES-256-GCM with a 12-byte nonce and
//! 16-byte tag, random bytes, hex and base64 (Std, RawStd, URL; newlines skipped, partial
//! output on error).
//!
//! AES-GCM is the `aes-gcm` crate (RustCrypto: AES-NI / ARMv8 instructions where the CPU has
//! them, a constant-time software path elsewhere).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use std::io::Read;

// Random bytes

/// Fills buf from the OS CSPRNG.
pub fn fill_random_bytes(buf: &mut [u8]) -> std::io::Result<()> {
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

// ── HMAC-SHA256 ─────────────────────────────────────────────────────────────

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HMAC-SHA256 over the concatenation of parts.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(ih);
    outer.finalize().into()
}

/// Constant-time comparison.
pub fn hmac_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// Hex

pub fn hex_encode(src: &[u8]) -> Vec<u8> {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(src.len() * 2);
    for &b in src {
        out.push(H[(b >> 4) as usize]);
        out.push(H[(b & 15) as usize]);
    }
    out
}

fn from_hex_char(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes hex, returning the error text on failure.
pub fn hex_decode(s: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 1;
    while i < s.len() {
        let a = from_hex_char(s[i - 1]).ok_or_else(|| invalid_hex_byte(s[i - 1]))?;
        let b = from_hex_char(s[i]).ok_or_else(|| invalid_hex_byte(s[i]))?;
        out.push(a << 4 | b);
        i += 2;
    }
    if s.len() % 2 == 1 {
        if from_hex_char(s[i - 1]).is_none() {
            return Err(invalid_hex_byte(s[i - 1]));
        }
        return Err("encoding/hex: odd length hex string".into());
    }
    Ok(out)
}

fn invalid_hex_byte(b: u8) -> String {
    format!("encoding/hex: invalid byte: {}", format_unicode_point(b))
}

// Formats a byte as U+0067 'g' (the quoted character only for printable ASCII).
fn format_unicode_point(b: u8) -> String {
    if (0x20..0x7f).contains(&b) {
        format!("U+{:04X} '{}'", b, b as char)
    } else {
        format!("U+{:04X}", b)
    }
}

// Base64

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Which base64 encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum B64 {
    Std,
    RawStd,
    Url,
}

impl B64 {
    fn alphabet(self) -> &'static [u8; 64] {
        if self == B64::Url { URL } else { STD }
    }
    fn padded(self) -> bool {
        self != B64::RawStd
    }
}

pub fn encode_base64(enc: B64, src: &[u8]) -> Vec<u8> {
    let a = enc.alphabet();
    let mut out = Vec::with_capacity(src.len().div_ceil(3) * 4);
    for c in src.chunks(3) {
        let v = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(a[(v >> 18) as usize & 63]);
        out.push(a[(v >> 12) as usize & 63]);
        if c.len() > 1 {
            out.push(a[(v >> 6) as usize & 63]);
        } else if enc.padded() {
            out.push(b'=');
        }
        if c.len() > 2 {
            out.push(a[v as usize & 63]);
        } else if enc.padded() {
            out.push(b'=');
        }
    }
    out
}

/// The bytes decoded before an error, and whether it succeeded.
pub fn decode_base64_partial(enc: B64, src: &[u8]) -> (Vec<u8>, bool) {
    let a = enc.alphabet();
    let mut map = [0xffu8; 256];
    for (i, &c) in a.iter().enumerate() {
        map[c as usize] = i as u8;
    }
    let mut dst = Vec::with_capacity(src.len() / 4 * 3 + 3);
    let mut si = 0;
    while si < src.len() {
        let (nsi, ok) = decode_quantum(enc.padded(), &map, &mut dst, src, si);
        if !ok {
            return (dst, false);
        }
        si = nsi;
    }
    (dst, true)
}

// Decodes one quantum: writes the quantum's bytes, returns (si, ok).
fn decode_quantum(
    padded: bool,
    map: &[u8; 256],
    dst: &mut Vec<u8>,
    src: &[u8],
    mut si: usize,
) -> (usize, bool) {
    let mut dbuf = [0u8; 4];
    let mut dlen = 4;
    let mut ok = true;
    let mut j = 0;
    while j < 4 {
        if src.len() == si {
            if j == 0 {
                return (si, true);
            }
            if j == 1 || padded {
                return (si, false);
            }
            dlen = j;
            break;
        }
        let c = src[si];
        si += 1;
        let out = map[c as usize];
        if out != 0xff {
            dbuf[j] = out;
            j += 1;
            continue;
        }
        if c == b'\n' || c == b'\r' {
            continue;
        }
        if !padded || c != b'=' {
            return (si, false);
        }
        match j {
            0 | 1 => return (si, false),
            2 => {
                while si < src.len() && (src[si] == b'\n' || src[si] == b'\r') {
                    si += 1;
                }
                if si == src.len() || src[si] != b'=' {
                    return (si, false);
                }
                si += 1;
            }
            _ => {}
        }
        while si < src.len() && (src[si] == b'\n' || src[si] == b'\r') {
            si += 1;
        }
        if si < src.len() {
            ok = false;
        }
        dlen = j;
        break;
    }
    let val =
        (dbuf[0] as u32) << 18 | (dbuf[1] as u32) << 12 | (dbuf[2] as u32) << 6 | dbuf[3] as u32;
    let b = [(val >> 16) as u8, (val >> 8) as u8, val as u8];
    dst.extend_from_slice(&b[..dlen - 1]);
    (si, ok)
}

// ── AES-256 + GCM ───────────────────────────────────────────────────────────

/// The error text of `Gcm::open` on a bad tag.
pub const AUTH_FAILED_MESSAGE: &str = "cipher: message authentication failed";

const GCM_NONCE: usize = 12;

/// AES-256-GCM for a 32-byte key: 12-byte nonce, 16-byte tag, no AAD.
pub struct Gcm(Aes256Gcm);

impl Gcm {
    pub fn new(key: &[u8; 32]) -> Gcm {
        Gcm(Aes256Gcm::new(key.into()))
    }

    pub fn required_nonce_len(&self) -> usize {
        GCM_NONCE
    }

    /// Seals `plaintext`: dst ‖ ciphertext ‖ tag.
    pub fn seal(&self, mut dst: Vec<u8>, nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        assert_eq!(
            nonce.len(),
            GCM_NONCE,
            "crypto/cipher: incorrect nonce length given to GCM"
        );
        dst.extend(
            self.0
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .expect("AES-GCM seal cannot fail for a 12-byte nonce"),
        );
        dst
    }

    pub fn open(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        assert_eq!(
            nonce.len(),
            GCM_NONCE,
            "crypto/cipher: incorrect nonce length given to GCM"
        );
        self.0
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| AUTH_FAILED_MESSAGE.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_nist_test_case_14() {
        // McGrew & Viega test case 14: 256-bit zero key, zero IV, one zero block.
        let g = Gcm::new(&[0u8; 32]);
        let out = g.seal(Vec::new(), &[0u8; 12], &[0u8; 16]);
        assert_eq!(
            hex_encode(&out),
            b"cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );
        assert_eq!(g.open(&[0u8; 12], &out).unwrap(), vec![0u8; 16]);
        let mut bad = out.clone();
        bad[0] ^= 1;
        assert!(g.open(&[0u8; 12], &bad).is_err());
    }

    #[test]
    fn hmac_rfc4231_case2() {
        let mac = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(
            hex_encode(&mac),
            b"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn base64_reference_cases() {
        assert_eq!(
            decode_base64_partial(B64::Std, b"YWJj"),
            (b"abc".to_vec(), true)
        );
        assert_eq!(
            decode_base64_partial(B64::Std, b"YW\r\nJj"),
            (b"abc".to_vec(), true)
        );
        assert_eq!(
            decode_base64_partial(B64::Std, b"YQ=="),
            (b"a".to_vec(), true)
        );
        assert!(!decode_base64_partial(B64::Std, b"YQ").1);
        assert_eq!(
            decode_base64_partial(B64::RawStd, b"YQ"),
            (b"a".to_vec(), true)
        );
        assert_eq!(
            decode_base64_partial(B64::Std, b"YWJjYQ"),
            (b"abc".to_vec(), false)
        );
        assert_eq!(
            decode_base64_partial(B64::Std, b"YQ==x"),
            (b"a".to_vec(), false)
        );
        assert_eq!(encode_base64(B64::Std, b"ab"), b"YWI=");
        assert_eq!(encode_base64(B64::RawStd, b"ab"), b"YWI");
    }
}
