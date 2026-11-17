//! NFC/NFD/NFKC/NFKD over byte strings (Unicode 15.0.0 tables).
//!
//! The input is walked in lookup units:
//! - ASCII: 1 byte; 0x80–0xC1 and 0xF8–0xFF: 1 inert byte;
//! - a lead byte C2–DF / E0–EF / F0–F7 needs 2 / 3 / 4 bytes. When fewer bytes remain the
//!   lead is "invalid" (truncated): it is copied **and everything after it** unchanged;
//! - otherwise the unit ends at the first non-continuation byte (sizes 1, 2 or 3, inert), or
//!   spans the whole sequence. A whole sequence that is not a valid scalar (overlong,
//!   surrogate, > U+10FFFF, F5–F7 lead) or is a scalar unassigned in Unicode 15 has no
//!   normalization data: an inert starter, copied as is.
//!
//! Inert units are starters with ccc 0 that compose with nothing, so the text between them
//! normalizes independently; each such run of real characters goes through
//! `unicode-normalization` (stream-safe, then the form). The crate's tables are Unicode 18,
//! but normalization data of characters assigned in Unicode 15 is stable across versions,
//! and every character unassigned in Unicode 15 is treated as inert.

use crate::unicode;
use std::sync::LazyLock;
use unicode_normalization::{
    IsNormalized, UnicodeNormalization, is_nfc_stream_safe_quick, is_nfd_stream_safe_quick,
    is_nfkc_quick, is_nfkd_quick,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NormalizationForm {
    Nfc,
    Nfd,
    Nfkc,
    Nfkd,
}

/// The normalizer itself: stream-safe text, then the form.
fn apply_slow(form: NormalizationForm, s: &str, out: &mut Vec<u8>) {
    let it = s.chars().stream_safe();
    let r: String = match form {
        NormalizationForm::Nfc => it.nfc().collect(),
        NormalizationForm::Nfd => it.nfd().collect(),
        NormalizationForm::Nfkc => it.nfkc().collect(),
        NormalizationForm::Nfkd => it.nfkd().collect(),
    };
    out.extend_from_slice(r.as_bytes());
}

/// `apply_slow`, except that text the quick check proves already normalized and stream-safe
/// (so the normalizer would return it unchanged) is copied. The crate has a stream-safe quick
/// check for NFC and NFD only; a text in NFKC (NFKD) is in NFC (NFD) too, so the pair is used.
fn apply(form: NormalizationForm, s: &str, out: &mut Vec<u8>) {
    let c = s.chars();
    let normalized = match form {
        NormalizationForm::Nfc => is_nfc_stream_safe_quick(c) == IsNormalized::Yes,
        NormalizationForm::Nfd => is_nfd_stream_safe_quick(c) == IsNormalized::Yes,
        NormalizationForm::Nfkc => {
            is_nfkc_quick(c) == IsNormalized::Yes
                && is_nfc_stream_safe_quick(s.chars()) == IsNormalized::Yes
        }
        NormalizationForm::Nfkd => {
            is_nfkd_quick(c) == IsNormalized::Yes
                && is_nfd_stream_safe_quick(s.chars()) == IsNormalized::Yes
        }
    };
    if normalized {
        out.extend_from_slice(s.as_bytes());
    } else {
        apply_slow(form, s, out);
    }
}

/// Code points below this (ASCII, Latin-1, Latin Extended, IPA, spacing modifiers) never interact
/// with a neighbour under normalization: the first combining mark is U+0300 and none of them
/// composes with a starter, so a run of them normalizes character by character.
const SIMPLE_LIMIT: u32 = 0x300;

/// Per form, the normalization of every code point U+0080..SIMPLE_LIMIT on its own as UTF-8:
/// `data[off[i]..off[i + 1]]` for code point `0x80 + i`.
struct SimpleTable {
    off: Vec<u32>,
    data: Vec<u8>,
}

static SIMPLE: [LazyLock<SimpleTable>; 4] = [
    LazyLock::new(|| SimpleTable::new(NormalizationForm::Nfc)),
    LazyLock::new(|| SimpleTable::new(NormalizationForm::Nfd)),
    LazyLock::new(|| SimpleTable::new(NormalizationForm::Nfkc)),
    LazyLock::new(|| SimpleTable::new(NormalizationForm::Nfkd)),
];

impl SimpleTable {
    fn new(form: NormalizationForm) -> SimpleTable {
        let mut t = SimpleTable {
            off: vec![0],
            data: Vec::new(),
        };
        for r in 0x80..SIMPLE_LIMIT {
            let c = char::from_u32(r).expect("below the surrogates");
            let it = std::iter::once(c);
            let n: String = match form {
                NormalizationForm::Nfc => it.nfc().collect(),
                NormalizationForm::Nfd => it.nfd().collect(),
                NormalizationForm::Nfkc => it.nfkc().collect(),
                NormalizationForm::Nfkd => it.nfkd().collect(),
            };
            t.data.extend_from_slice(n.as_bytes());
            t.off.push(t.data.len() as u32);
        }
        t
    }
}

/// `apply` over a run of ASCII and U+0080..SIMPLE_LIMIT text (no byte of the run is >= 0xCC):
/// each character through the table, ASCII as it is.
fn apply_simple(form: NormalizationForm, run: &str, out: &mut Vec<u8>) {
    let t = &*SIMPLE[form as usize];
    let b = run.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c < 0x80 {
            // copy the ASCII stretch
            let j = b[i..]
                .iter()
                .position(|&x| x >= 0x80)
                .map_or(b.len(), |k| i + k);
            out.extend_from_slice(&b[i..j]);
            i = j;
            continue;
        }
        // a two-byte character C2..=CB, 80..=BF
        let r = (((c & 0x1F) as u32) << 6 | (b[i + 1] & 0x3F) as u32) - 0x80;
        out.extend_from_slice(&t.data[t.off[r as usize] as usize..t.off[r as usize + 1] as usize]);
        i += 2;
    }
}

/// `apply` over a run of valid text that is mostly ASCII without sending the ASCII through the
/// normalizer. An ASCII character is a starter that composes with nothing before it and
/// normalizes to itself, so the text splits before every ASCII byte; the one ASCII byte in front
/// of a non-ASCII stretch stays with it (a combining mark composes with it: `e` + U+0301).
/// The result equals `apply(run)`.
fn apply_run(form: NormalizationForm, run: &str, out: &mut Vec<u8>) {
    let b = run.as_bytes();
    if b.iter().all(|&x| x < 0xCC) {
        return apply_simple(form, run, out);
    }
    let (mut i, mut copied) = (0, 0);
    while i < b.len() {
        if b[i] < 0x80 {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < b.len() && b[j] >= 0x80 {
            j += 1;
        }
        let from = if i > copied { i - 1 } else { i };
        out.extend_from_slice(&b[copied..from]);
        apply(form, &run[from..j], out);
        copied = j;
        i = j;
    }
    out.extend_from_slice(&b[copied..]);
}

/// One lookup unit at the start of `s` (non-empty).
enum Unit {
    /// A valid scalar assigned in Unicode 15 (or ASCII) of this many bytes.
    Char(usize),
    /// Bytes that pass through as an inert starter.
    Inert(usize),
    /// A lead byte with fewer bytes left than it needs: the rest of the input is copied.
    Truncated,
}

fn is_cont(b: u8) -> bool {
    (0x80..0xC0).contains(&b)
}

/// The code points the Unicode 15 tables assign (letters, marks, numbers, punctuation,
/// symbols, separators and the assigned C subcategories: the C category as a whole also
/// covers unassigned code points), as a bit set: one lookup per character where the range
/// tables took a binary search in each of ten tables.
static ASSIGNED_15: LazyLock<Vec<u64>> = LazyLock::new(|| {
    let mut bits = vec![0u64; 0x110000 / 64];
    for table in [
        unicode::L,
        unicode::M,
        unicode::N,
        unicode::P,
        unicode::S,
        unicode::Z,
        unicode::CC,
        unicode::CF,
        unicode::CO,
        unicode::CS,
    ] {
        for &(lo, hi) in table {
            for r in lo..=hi.min(0x10FFFF) {
                bits[r as usize >> 6] |= 1 << (r & 63);
            }
        }
    }
    bits
});

/// Whether the Unicode 15 tables assign r.
fn assigned_unicode15(r: char) -> bool {
    let r = r as u32;
    ASSIGNED_15[r as usize >> 6] >> (r & 63) & 1 != 0
}

fn unit(s: &[u8]) -> Unit {
    let c0 = s[0];
    if c0 < 0x80 {
        return Unit::Char(1);
    }
    let need = match c0 {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => return Unit::Inert(1),
    };
    if s.len() < need {
        return Unit::Truncated;
    }
    if let Some(k) = (1..need).find(|&k| !is_cont(s[k])) {
        return Unit::Inert(k);
    }
    // The scalar value of a well-formed sequence; overlong forms, surrogates and values past
    // U+10FFFF are no scalars (what `str::from_utf8` rejects) and stay inert.
    let b = |k: usize| (s[k] & 0x3F) as u32;
    let (v, min) = match need {
        2 => (((c0 & 0x1F) as u32) << 6 | b(1), 0x80),
        3 => (((c0 & 0x0F) as u32) << 12 | b(1) << 6 | b(2), 0x800),
        _ => (
            ((c0 & 0x07) as u32) << 18 | b(1) << 12 | b(2) << 6 | b(3),
            0x10000,
        ),
    };
    match char::from_u32(v) {
        Some(c) if v >= min && assigned_unicode15(c) => Unit::Char(need),
        _ => Unit::Inert(need),
    }
}

impl NormalizationForm {
    pub fn normalize(self, s: &[u8]) -> Vec<u8> {
        if s.is_ascii() {
            return s.to_vec();
        }
        let mut out = Vec::with_capacity(s.len());
        let mut run: Option<usize> = None;
        let flush = |out: &mut Vec<u8>, run: &mut Option<usize>, end: usize| {
            if let Some(st) = run.take() {
                apply_run(
                    self,
                    std::str::from_utf8(&s[st..end]).expect("run of valid chars"),
                    out,
                );
            }
        };
        let mut i = 0;
        while i < s.len() {
            match unit(&s[i..]) {
                Unit::Char(n) => {
                    run.get_or_insert(i);
                    i += n;
                }
                Unit::Inert(n) => {
                    flush(&mut out, &mut run, i);
                    out.extend_from_slice(&s[i..i + n]);
                    i += n;
                }
                Unit::Truncated => {
                    flush(&mut out, &mut run, i);
                    out.extend_from_slice(&s[i..]);
                    return out;
                }
            }
        }
        flush(&mut out, &mut run, s.len());
        out
    }
}

pub const NFC: NormalizationForm = NormalizationForm::Nfc;
pub const NFD: NormalizationForm = NormalizationForm::Nfd;
pub const NFKC: NormalizationForm = NormalizationForm::Nfkc;
pub const NFKD: NormalizationForm = NormalizationForm::Nfkd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference_on_invalid_bytes() {
        assert_eq!(NFKC.normalize(b"a\xffb"), b"a\xffb");
        assert_eq!(NFKC.normalize("\u{ff21}".as_bytes()), b"A");
        assert_eq!(NFKC.normalize(b"\xff\xef\xbc\xa1"), b"\xffA");
        assert_eq!(
            NFKC.normalize("e\u{301}\u{ff}".as_bytes()),
            "é\u{ff}".as_bytes()
        );
        assert_eq!(
            NFKC.normalize(b"e\xcc\x81\xff\xcc\x81"),
            b"\xc3\xa9\xff\xcc\x81"
        );
        assert_eq!(
            NFKD.normalize(b"e\xcc\x81\xff\xcc\x81"),
            b"e\xcc\x81\xff\xcc\x81"
        );
        assert_eq!(NFKC.normalize(b"\xef\xac\x81\xc3"), b"fi\xc3");
        assert_eq!(NFKC.normalize(b"\xe2\x82"), b"\xe2\x82");
    }

    /// `apply` (quick check) and `apply_run` (ASCII split) equal the normalizer over the whole
    /// run, on random strings of ASCII, combining marks, Hangul jamo, Indic vowel signs,
    /// compatibility characters, and on a run of 40 combining marks (stream-safe text format).
    #[test]
    fn ascii_split_equals_whole_run() {
        const ALPHA: [&str; 24] = [
            "a", "e", "Z", " ", "0", "\u{301}", "\u{323}", "\u{328}", "\u{ff21}", "\u{fb01}",
            "\u{1100}", "\u{1161}", "\u{11a8}", "\u{ac00}", "\u{b47}", "\u{b3e}", "\u{9c7}",
            "\u{9be}", "\u{e9}", "\u{2126}", "\u{17f}", "\u{2160}", "\u{3099}", "\u{1e9b}",
        ];
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let long = format!("a{}b", "\u{301}".repeat(40));
        for form in [
            NormalizationForm::Nfc,
            NormalizationForm::Nfd,
            NormalizationForm::Nfkc,
            NormalizationForm::Nfkd,
        ] {
            let (mut whole, mut quick) = (Vec::new(), Vec::new());
            apply_slow(form, &long, &mut whole);
            apply(form, &long, &mut quick);
            assert_eq!(whole, quick, "{form:?} long mark run");
        }
        for _ in 0..40_000 {
            let n = (next() % 14) as usize;
            let run: String = (0..n)
                .map(|_| ALPHA[(next() % ALPHA.len() as u64) as usize])
                .collect();
            for form in [
                NormalizationForm::Nfc,
                NormalizationForm::Nfd,
                NormalizationForm::Nfkc,
                NormalizationForm::Nfkd,
            ] {
                let (mut whole, mut quick, mut split) = (Vec::new(), Vec::new(), Vec::new());
                apply_slow(form, &run, &mut whole);
                apply(form, &run, &mut quick);
                apply_run(form, &run, &mut split);
                assert_eq!(whole, quick, "{form:?} {run:?}");
                assert_eq!(whole, split, "{form:?} {run:?}");
            }
        }
    }

    #[test]
    fn truncated_lead_copies_the_rest() {
        // F0 needs 4 bytes, 3 remain: "\xf0Ä" is copied unchanged.
        assert_eq!(NFKD.normalize(b"x\xf0\xc3\x84"), b"x\xf0\xc3\x84");
        assert_eq!(
            NFKC.normalize("\u{17f}\u{e0}\u{17f}".as_bytes()),
            "s\u{e0}s".as_bytes()
        );
        assert_eq!(NFKC.normalize(b"\xc5\xbf\xf0\xc5\xbf"), b"s\xf0\xc5\xbf");
        // the unit grid decides: E0 80 is one inert unit, then F0 is truncated
        assert_eq!(
            NFKD.normalize(b"\xe0\x80\xf0\xc3\x84"),
            b"\xe0\x80\xf0\xc3\x84"
        );
        // overlong / surrogate / >10FFFF sequences are inert units
        assert_eq!(NFKC.normalize(b"\xe0\x80\x80\xc5\xbf"), b"\xe0\x80\x80s");
        assert_eq!(
            NFKC.normalize(b"\xed\xa0\x80\xef\xac\x81"),
            b"\xed\xa0\x80fi"
        );
    }

    /// `unit` equals the `from_utf8`-based reading it replaced, on every one-, two- and
    /// three-byte sequence and on four-byte sequences with a lead in F0..F7 and every second
    /// byte class.
    #[test]
    fn unit_matches_the_from_utf8_reading() {
        fn reference(s: &[u8]) -> Unit {
            let c0 = s[0];
            if c0 < 0x80 {
                return Unit::Char(1);
            }
            let need = match c0 {
                0xC2..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => return Unit::Inert(1),
            };
            if s.len() < need {
                return Unit::Truncated;
            }
            if let Some(k) = (1..need).find(|&k| !is_cont(s[k])) {
                return Unit::Inert(k);
            }
            match std::str::from_utf8(&s[..need]) {
                Ok(c) if assigned_unicode15(c.chars().next().unwrap()) => Unit::Char(need),
                _ => Unit::Inert(need),
            }
        }
        fn same(a: &Unit, b: &Unit) -> bool {
            match (a, b) {
                (Unit::Char(x), Unit::Char(y)) | (Unit::Inert(x), Unit::Inert(y)) => x == y,
                (Unit::Truncated, Unit::Truncated) => true,
                _ => false,
            }
        }
        let conts = [0x80u8, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0x41, 0xC0];
        for c0 in 0..=255u8 {
            for len in 1..=4usize {
                for &x in &conts {
                    for &y in &conts {
                        for &z in &conts {
                            let all = [c0, x, y, z];
                            let s = &all[..len];
                            assert!(same(&unit(s), &reference(s)), "{s:02X?}");
                        }
                    }
                }
            }
        }
        // every scalar value, encoded
        for r in 0..=0x10FFFFu32 {
            if let Some(c) = char::from_u32(r) {
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf).as_bytes();
                assert!(same(&unit(s), &reference(s)), "U+{r:04X}");
            }
        }
    }

    /// The per-character table path equals the normalizer over the whole run: every code point
    /// alone, and random runs of ASCII and U+0080..U+02FF, all four forms.
    #[test]
    fn simple_runs_equal_the_normalizer() {
        for form in [
            NormalizationForm::Nfc,
            NormalizationForm::Nfd,
            NormalizationForm::Nfkc,
            NormalizationForm::Nfkd,
        ] {
            for r in 0x80..SIMPLE_LIMIT {
                let c = char::from_u32(r).unwrap().to_string();
                let (mut whole, mut simple) = (Vec::new(), Vec::new());
                apply_slow(form, &c, &mut whole);
                apply_simple(form, &c, &mut simple);
                assert_eq!(whole, simple, "{form:?} U+{r:04X}");
            }
        }
        let mut seed = 0x1234_5678_9ABC_DEF1u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..30_000 {
            let n = (next() % 24) as usize;
            let run: String = (0..n)
                .map(|_| {
                    let r = if next() % 3 == 0 {
                        0x20 + (next() % 0x5F) as u32
                    } else {
                        0x80 + (next() % (SIMPLE_LIMIT as u64 - 0x80)) as u32
                    };
                    char::from_u32(r).unwrap()
                })
                .collect();
            for form in [
                NormalizationForm::Nfc,
                NormalizationForm::Nfd,
                NormalizationForm::Nfkc,
                NormalizationForm::Nfkd,
            ] {
                let (mut whole, mut simple) = (Vec::new(), Vec::new());
                apply_slow(form, &run, &mut whole);
                apply_simple(form, &run, &mut simple);
                assert_eq!(whole, simple, "{form:?} {run:?}");
            }
        }
    }

    /// The bit set equals a lookup in the ten tables for every code point.
    #[test]
    fn assigned_bits_equal_the_range_tables() {
        let tables = [
            unicode::L,
            unicode::M,
            unicode::N,
            unicode::P,
            unicode::S,
            unicode::Z,
            unicode::CC,
            unicode::CF,
            unicode::CO,
            unicode::CS,
        ];
        for r in 0..=0x10FFFFu32 {
            let Some(c) = char::from_u32(r) else { continue };
            assert_eq!(
                assigned_unicode15(c),
                unicode::in_any_table(r as i32, &tables),
                "U+{r:04X}"
            );
        }
    }

    #[test]
    fn unassigned_in_unicode15_is_inert() {
        // U+0558 and U+058C are unassigned in Unicode 15 but mapped by newer tables.
        assert_eq!(
            NFKC.normalize("f\u{558}x".as_bytes()),
            "f\u{558}x".as_bytes()
        );
        assert_eq!(NFKD.normalize("\u{58c}".as_bytes()), "\u{58c}".as_bytes());
    }
}
