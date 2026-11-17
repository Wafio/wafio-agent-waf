//! Unicode predicates and case mapping, from the Unicode 15.0.0 tables in `unicode_tables.rs`.

use crate::CodePoint;
use crate::unicode_tables as t;
use std::sync::LazyLock;

pub use crate::unicode_tables::UNICODE_VERSION;

pub const MAX_CODE_POINT: CodePoint = 0x10FFFF;
pub const REPLACEMENT_CODE_POINT: CodePoint = 0xFFFD;

/// A range table, flattened to inclusive ranges.
pub type Table = &'static [(u32, u32)];

pub fn table_contains(table: Table, r: CodePoint) -> bool {
    if r < 0 {
        return false;
    }
    let r = r as u32;
    table
        .binary_search_by(|&(lo, hi)| {
            if hi < r {
                std::cmp::Ordering::Less
            } else if lo > r {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

pub fn in_any_table(r: CodePoint, tables: &[Table]) -> bool {
    tables.iter().any(|t| table_contains(t, r))
}

pub static CC: Table = &t::CAT_CC;
pub static CF: Table = &t::CAT_CF;
pub static CO: Table = &t::CAT_CO;
pub static CS: Table = &t::CAT_CS;
pub static MN: Table = &t::CAT_MN;
pub static MC: Table = &t::CAT_MC;
pub static ME: Table = &t::CAT_ME;
pub static M: Table = &t::IS_MARK;
pub static ND: Table = &t::CAT_ND;
pub static N: Table = &t::IS_NUMBER;
pub static Z: Table = &t::CAT_Z;
pub static ZS: Table = &t::CAT_ZS;
pub static L: Table = &t::IS_LETTER;
pub static P: Table = &t::IS_PUNCT;
pub static S: Table = &t::IS_SYMBOL;

pub fn is_letter(r: CodePoint) -> bool {
    table_contains(&t::IS_LETTER, r)
}
pub fn is_upper(r: CodePoint) -> bool {
    table_contains(&t::IS_UPPER, r)
}
pub fn is_lower(r: CodePoint) -> bool {
    table_contains(&t::IS_LOWER, r)
}
pub fn is_digit(r: CodePoint) -> bool {
    if (0..=0x7F).contains(&r) {
        return (b'0' as CodePoint..=b'9' as CodePoint).contains(&r);
    }
    table_contains(&t::IS_DIGIT, r)
}
pub fn is_number(r: CodePoint) -> bool {
    table_contains(&t::IS_NUMBER, r)
}
pub fn is_mark(r: CodePoint) -> bool {
    table_contains(&t::IS_MARK, r)
}
pub fn is_punctuation(r: CodePoint) -> bool {
    table_contains(&t::IS_PUNCT, r)
}
pub fn is_symbol(r: CodePoint) -> bool {
    table_contains(&t::IS_SYMBOL, r)
}
/// '\t', '\n', '\v', '\f', '\r', ' ', U+0085, U+00A0 and White_Space.
pub fn is_space(r: CodePoint) -> bool {
    if (0..=0xFF).contains(&r) {
        return matches!(r, 0x09..=0x0D | 0x20 | 0x85 | 0xA0);
    }
    table_contains(&t::IS_SPACE, r)
}
/// Only the Latin-1 C0/C1 controls.
pub fn is_control(r: CodePoint) -> bool {
    table_contains(&t::IS_CONTROL, r)
}
pub fn is_print(r: CodePoint) -> bool {
    table_contains(&t::IS_PRINT, r)
}
pub fn is_graphic(r: CodePoint) -> bool {
    table_contains(&t::IS_GRAPHIC, r)
}

/// Kana, CJK ideographs and Yi syllables: no case mapping or fold orbit starts in this range
/// (`caseless_range_has_no_mappings`), so text in it skips the table search.
const CASELESS: std::ops::RangeInclusive<u32> = 0x3040..=0x9FFF;

/// A case table as two-stage direct lookup: the high bits of a rune pick a block of 128 mapped
/// runes (0 = the rune maps to itself); blocks with no mapping are all one shared block, so a
/// rune without a mapping costs two loads where the sorted table took a binary search.
struct CaseMap {
    stage1: Vec<u16>,
    blocks: Vec<[u32; 128]>,
}

impl CaseMap {
    fn new(table: &'static [(u32, u32)]) -> CaseMap {
        let top = table.last().map_or(0, |&(k, _)| k >> 7);
        let mut m = CaseMap {
            stage1: vec![0; top as usize + 1],
            blocks: vec![[0; 128]],
        };
        for &(k, v) in table {
            let hi = (k >> 7) as usize;
            if m.stage1[hi] == 0 {
                m.blocks.push([0; 128]);
                m.stage1[hi] = (m.blocks.len() - 1) as u16;
            }
            m.blocks[m.stage1[hi] as usize][(k & 127) as usize] = v;
        }
        m
    }

    fn get(&self, r: CodePoint) -> CodePoint {
        if r < 0 {
            return r;
        }
        let r = r as u32;
        let Some(&id) = self.stage1.get((r >> 7) as usize) else {
            return r as CodePoint;
        };
        match self.blocks[id as usize][(r & 127) as usize] {
            0 => r as CodePoint,
            m => m as CodePoint,
        }
    }
}

static LOWER_MAP: LazyLock<CaseMap> = LazyLock::new(|| CaseMap::new(&t::TO_LOWER));
static UPPER_MAP: LazyLock<CaseMap> = LazyLock::new(|| CaseMap::new(&t::TO_UPPER));
static FOLD_MAP: LazyLock<CaseMap> = LazyLock::new(|| CaseMap::new(&t::SIMPLE_FOLD));

fn map_lookup(map: &CaseMap, r: CodePoint) -> CodePoint {
    if r < 0 || CASELESS.contains(&(r as u32)) {
        return r;
    }
    map.get(r)
}

pub fn to_lowercase(r: CodePoint) -> CodePoint {
    if (0..0x80).contains(&r) {
        if (b'A' as CodePoint..=b'Z' as CodePoint).contains(&r) {
            return r + 32;
        }
        return r;
    }
    map_lookup(&LOWER_MAP, r)
}

pub fn to_uppercase(r: CodePoint) -> CodePoint {
    if (0..0x80).contains(&r) {
        if (b'a' as CodePoint..=b'z' as CodePoint).contains(&r) {
            return r - 32;
        }
        return r;
    }
    map_lookup(&UPPER_MAP, r)
}

/// The next code point of r's case-fold orbit (r itself when it has none).
pub fn next_case_fold_equivalent(r: CodePoint) -> CodePoint {
    if !(0..=MAX_CODE_POINT).contains(&r) {
        return r;
    }
    map_lookup(&FOLD_MAP, r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicates_match_reference() {
        assert!(is_space(0x85) && is_space(0xA0) && is_space(0x2028) && is_space(0x3000));
        assert!(!is_space(0x200B) && !is_space(0x180E));
        assert!(is_letter('é' as CodePoint) && !is_letter('1' as CodePoint));
        assert!(
            is_digit('٣' as CodePoint)
                && !is_digit('½' as CodePoint)
                && is_number('½' as CodePoint)
        );
        assert!(is_control(0x85) && !is_control(0x200B));
        assert!(is_print(' ' as CodePoint) && !is_print(0xA0) && !is_print(0x200B));
        assert!(is_graphic(0xA0));
        assert!(
            table_contains(CF, 0x200B) && table_contains(MN, 0x301) && table_contains(ME, 0x20DD)
        );
        assert!(!is_letter(-1) && !is_letter(0x110000));
    }

    #[test]
    fn caseless_range_has_no_mappings() {
        for table in [&t::TO_LOWER[..], &t::TO_UPPER[..], &t::SIMPLE_FOLD[..]] {
            assert!(table.iter().all(|&(k, _)| !CASELESS.contains(&k)));
        }
    }

    /// The two-stage case maps equal the sorted tables they were built from, for every rune.
    #[test]
    fn case_maps_equal_the_tables() {
        fn reference(table: &[(u32, u32)], r: CodePoint) -> CodePoint {
            match table.binary_search_by_key(&(r as u32), |&(k, _)| k) {
                Ok(i) => table[i].1 as CodePoint,
                Err(_) => r,
            }
        }
        for r in -2..0x110000 {
            assert_eq!(
                LOWER_MAP.get(r),
                if r < 0 { r } else { reference(&t::TO_LOWER, r) }
            );
            assert_eq!(
                UPPER_MAP.get(r),
                if r < 0 { r } else { reference(&t::TO_UPPER, r) }
            );
            assert_eq!(
                FOLD_MAP.get(r),
                if r < 0 {
                    r
                } else {
                    reference(&t::SIMPLE_FOLD, r)
                }
            );
        }
    }

    #[test]
    fn case_matches_reference() {
        assert_eq!(to_lowercase('K' as CodePoint), 'k' as CodePoint);
        assert_eq!(to_lowercase(0x212A), 'k' as CodePoint); // KELVIN SIGN
        assert_eq!(to_lowercase(0x130), 'i' as CodePoint); // İ
        assert_eq!(to_uppercase(0x17F), 'S' as CodePoint); // ſ
        assert_eq!(to_uppercase('ß' as CodePoint), 'ß' as CodePoint);
        assert_eq!(
            next_case_fold_equivalent('A' as CodePoint),
            'a' as CodePoint
        );
        assert_eq!(
            next_case_fold_equivalent('a' as CodePoint),
            'A' as CodePoint
        );
        assert_eq!(
            next_case_fold_equivalent('K' as CodePoint),
            'k' as CodePoint
        );
        assert_eq!(next_case_fold_equivalent('k' as CodePoint), 0x212A);
        assert_eq!(next_case_fold_equivalent(0x212A), 'K' as CodePoint);
        assert_eq!(
            next_case_fold_equivalent('1' as CodePoint),
            '1' as CodePoint
        );
        assert_eq!(next_case_fold_equivalent(-2), -2);
    }
}
