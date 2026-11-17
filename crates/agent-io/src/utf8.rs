//! Request bytes are made valid UTF-8 where they cross into proto string fields (a marshal
//! failure tears the gRPC stream down). Each run of invalid bytes becomes one U+FFFD (not Rust's
//! per-sequence `from_utf8_lossy`).

use std::borrow::Cow;
use std::collections::HashMap;

use wafio_bytetext::strings::replace_invalid_utf8;

/// `s` unchanged (borrowed) when it is already valid.
pub fn repair_utf8(s: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(s) {
        Ok(v) => Cow::Borrowed(v),
        Err(_) => {
            let fixed = replace_invalid_utf8(s, "\u{FFFD}".as_bytes());
            Cow::Owned(String::from_utf8(fixed).expect("to_valid_utf8 yields valid UTF-8"))
        }
    }
}

/// Every element sanitized.
pub fn repair_utf8_list<S: AsRef<[u8]>>(input: &[S]) -> Vec<String> {
    input
        .iter()
        .map(|v| repair_utf8(v.as_ref()).into_owned())
        .collect()
}

/// Keys and values sanitized. Two keys that sanitize to
/// the same string collide onto one entry; which value survives depends on
/// map iteration order.
pub fn repair_utf8_map<K: AsRef<[u8]>, V: AsRef<[u8]>>(
    input: &HashMap<K, V>,
) -> HashMap<String, String> {
    input
        .iter()
        .map(|(k, v)| {
            (
                repair_utf8(k.as_ref()).into_owned(),
                repair_utf8(v.as_ref()).into_owned(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_valid_strings_alone() {
        for s in [
            "",
            "/index.php?id=1",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "harga: Rp1.000 — ✓ 日本語",
            "' OR 1=1--",
            "\u{FFFD}",
        ] {
            assert!(
                matches!(repair_utf8(s.as_bytes()), Cow::Borrowed(b) if b == s),
                "{s:?}"
            );
        }
    }

    #[test]
    fn replaces_invalid_bytes() {
        for input in [
            &b"/a\xffb"[..],
            b"\xc3",
            b"\xe2\x82",
            b"\xed\xa0\x80",
            b"\xf5\x80\x80\x80",
            b"\xc0\xaf",
        ] {
            let got = repair_utf8(input);
            assert!(std::str::from_utf8(got.as_bytes()).is_ok());
        }
        // one replacement per run of invalid bytes
        assert_eq!(repair_utf8(b"\xed\xa0\x80"), "\u{FFFD}");
        assert_eq!(repair_utf8(b"a\xff\xfeb"), "a\u{FFFD}b");
    }

    #[test]
    fn does_not_decode_overlong_slash() {
        assert!(!repair_utf8(b"\xc0\xaf").contains('/'));
    }

    #[test]
    fn preserves_surrounding_content() {
        let got = repair_utf8(b"/search?q=SELECT\xff FROM users");
        assert!(got.contains("/search?q=SELECT") && got.contains(" FROM users"));
    }

    #[test]
    fn slice_and_map() {
        let cats: Vec<Vec<u8>> = vec![b"sqli".to_vec(), b"x\xffss".to_vec()];
        let got = repair_utf8_list(&cats);
        assert_eq!(got[0], "sqli");
        assert_eq!(got[1], "x\u{FFFD}ss");
        let mut hdr: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        hdr.insert(b"X-Ok".to_vec(), b"fine".to_vec());
        hdr.insert(b"X-Bad\xff".to_vec(), b"v\xffal".to_vec());
        let m = repair_utf8_map(&hdr);
        assert_eq!(m["X-Ok"], "fine");
        assert_eq!(m["X-Bad\u{FFFD}"], "v\u{FFFD}al");
        let empty: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        assert!(repair_utf8_map(&empty).is_empty());
        assert!(repair_utf8_list::<Vec<u8>>(&[]).is_empty());
    }
}
