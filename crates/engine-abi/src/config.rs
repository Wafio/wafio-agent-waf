//! The scan configuration as a fixed row of 64-bit words. The agent turns a `SemanticConfig` into a row and
//! hands it over once; the library answers with a handle, and every scan names that handle. The row is also
//! what the agent compares to know whether it has handed a configuration over already.
//!
//! The words, in order (`f64` is stored as its bit pattern):
//!
//! | Words | Meaning |
//! |---|---|
//! | 0 | `engine_parse_work_budget` |
//! | 1 | presence bits, see [`presence`] |
//! | 2 | detectors switched off, one bit per key of [`KEYS`] |
//! | 3 | detectors that only log, one bit per key of [`KEYS`] |
//! | 4 | identity of the SSRF list (the agent's own number, ignored by the library), 0 for none |
//! | 5 to 28 | block threshold and soft threshold (evidence) of sql, xss, cmd, php, python, lfi, ssrf, java, nosql, ssti, xxe, deser |
//!
//! Word 2 and 3 carry only keys whose value is true. A key of a `disabled_engines` map that is not in
//! [`KEYS`] has no effect in any engine and is not carried.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use wafio_engine_api::{
    CmdPolicy, DeserPolicy, JavaPolicy, LfiPolicy, NosqlPolicy, PhpPolicy, PythonPolicy,
    SemanticConfig, SqlPolicy, SsrfConfig, SsrfPolicy, SstiPolicy, XssPolicy, XxePolicy,
};

/// The number of words in a row.
pub const WORDS: usize = 29;

/// A row.
pub type Words = [u64; WORDS];

/// The keys of the detector switches, bit by bit.
pub const KEYS: [&str; 20] = [
    "sql",
    "xss",
    "cmd",
    "php",
    "python",
    "lfi",
    "ssrf",
    "java",
    "nosql",
    "ssti",
    "xxe",
    "deser",
    "ldap",
    "proto_pollution",
    "jwt",
    "graphql",
    "header_injection",
    "open_redirect",
    "prompt_injection",
    "anomaly",
];

/// The bits of word 1.
pub mod presence {
    pub const SQL: u32 = 0;
    pub const XSS: u32 = 1;
    pub const CMD: u32 = 2;
    pub const PHP: u32 = 3;
    pub const PYTHON: u32 = 4;
    pub const LFI: u32 = 5;
    pub const SSRF: u32 = 6;
    pub const JAVA: u32 = 7;
    pub const NOSQL: u32 = 8;
    pub const SSTI: u32 = 9;
    pub const XXE: u32 = 10;
    pub const DESER: u32 = 11;
    pub const DISABLED_ENGINES: u32 = 12;
    pub const LOG_ONLY_ENGINES: u32 = 13;
    pub const SSRF_CONFIG: u32 = 14;
    /// Every bit a library of this interface version knows.
    pub const MASK: u64 = (1 << 15) - 1;
}

const W_PARSE_BUDGET: usize = 0;
const W_PRESENCE: usize = 1;
const W_DISABLED: usize = 2;
const W_LOG_ONLY: usize = 3;
const W_SSRF_ID: usize = 4;

fn key_mask<'a>(keys: impl Iterator<Item = &'a str>) -> u64 {
    keys.filter_map(|k| KEYS.iter().position(|x| *x == k))
        .fold(0, |m, i| m | (1 << i))
}

/// The row of a configuration. `ssrf_id` names the SSRF list in word 15 when the configuration has one.
/// `field_name` is not part of the row: it is handed over beside it.
pub fn encode(c: &SemanticConfig, ssrf_id: u64) -> Words {
    let mut w = [0u64; WORDS];
    let mut present = 0u64;
    let mut set = |bit: u32| present |= 1 << bit;
    w[W_PARSE_BUDGET] = c.engine_parse_work_budget as u64;

    macro_rules! pair {
        ($opt:expr, $bit:expr, $at:expr) => {
            if let Some(p) = $opt {
                set($bit);
                w[$at] = p.block_threshold.to_bits();
                w[$at + 1] = p.soft_threshold.to_bits();
            }
        };
    }
    pair!(c.sql_semantic_policy, presence::SQL, 5);
    pair!(c.xss_semantic_policy, presence::XSS, 7);
    pair!(c.cmd_semantic_policy, presence::CMD, 9);
    pair!(c.php_semantic_policy, presence::PHP, 11);
    pair!(c.python_semantic_policy, presence::PYTHON, 13);
    pair!(c.lfi_semantic_policy, presence::LFI, 15);
    pair!(c.ssrf_semantic_policy, presence::SSRF, 17);
    pair!(c.java_semantic_policy, presence::JAVA, 19);
    pair!(c.nosql_semantic_policy, presence::NOSQL, 21);
    pair!(c.ssti_semantic_policy, presence::SSTI, 23);
    pair!(c.xxe_semantic_policy, presence::XXE, 25);
    pair!(c.deser_semantic_policy, presence::DESER, 27);
    if let Some(m) = &c.disabled_engines {
        set(presence::DISABLED_ENGINES);
        w[W_DISABLED] = key_mask(m.iter().filter(|(_, on)| **on).map(|(k, _)| k.as_str()));
    }
    if let Some(s) = &c.log_only_engines {
        set(presence::LOG_ONLY_ENGINES);
        w[W_LOG_ONLY] = key_mask(s.iter().map(String::as_str));
    }
    if c.ssrf_config.is_some() {
        set(presence::SSRF_CONFIG);
        w[W_SSRF_ID] = ssrf_id;
    }
    w[W_PRESENCE] = present;
    w
}

/// The configuration a row stands for, with the SSRF list and the field name beside it. `None` when the row sets a
/// bit this version does not know, or names a key bit beyond [`KEYS`].
pub fn decode(
    w: &Words,
    field_name: &[u8],
    ssrf: Option<Arc<SsrfConfig>>,
) -> Option<SemanticConfig> {
    let present = w[W_PRESENCE];
    let key_bits = (1u64 << KEYS.len()) - 1;
    if present & !presence::MASK != 0
        || w[W_DISABLED] & !key_bits != 0
        || w[W_LOG_ONLY] & !key_bits != 0
    {
        return None;
    }
    let has = |bit: u32| present & (1 << bit) != 0;
    let f = |i: usize| f64::from_bits(w[i]);
    let mut c = SemanticConfig {
        engine_parse_work_budget: w[W_PARSE_BUDGET] as i64,
        field_name: field_name.to_vec(),
        ..Default::default()
    };
    macro_rules! pair {
        ($field:ident, $ty:ident, $bit:expr, $at:expr) => {
            if has($bit) {
                c.$field = Some($ty {
                    block_threshold: f($at),
                    soft_threshold: f($at + 1),
                });
            }
        };
    }
    pair!(sql_semantic_policy, SqlPolicy, presence::SQL, 5);
    pair!(xss_semantic_policy, XssPolicy, presence::XSS, 7);
    pair!(cmd_semantic_policy, CmdPolicy, presence::CMD, 9);
    pair!(php_semantic_policy, PhpPolicy, presence::PHP, 11);
    pair!(python_semantic_policy, PythonPolicy, presence::PYTHON, 13);
    pair!(lfi_semantic_policy, LfiPolicy, presence::LFI, 15);
    pair!(ssrf_semantic_policy, SsrfPolicy, presence::SSRF, 17);
    pair!(java_semantic_policy, JavaPolicy, presence::JAVA, 19);
    pair!(nosql_semantic_policy, NosqlPolicy, presence::NOSQL, 21);
    pair!(ssti_semantic_policy, SstiPolicy, presence::SSTI, 23);
    pair!(xxe_semantic_policy, XxePolicy, presence::XXE, 25);
    pair!(deser_semantic_policy, DeserPolicy, presence::DESER, 27);
    if has(presence::DISABLED_ENGINES) {
        c.disabled_engines = Some(
            keys_of(w[W_DISABLED])
                .map(|k| (k.to_string(), true))
                .collect::<HashMap<_, _>>(),
        );
    }
    if has(presence::LOG_ONLY_ENGINES) {
        c.log_only_engines = Some(
            keys_of(w[W_LOG_ONLY])
                .map(str::to_string)
                .collect::<HashSet<_>>(),
        );
    }
    if has(presence::SSRF_CONFIG) {
        c.ssrf_config = Some(ssrf.unwrap_or_default());
    }
    Some(c)
}

fn keys_of(mask: u64) -> impl Iterator<Item = &'static str> {
    KEYS.iter()
        .enumerate()
        .filter(move |(i, _)| mask & (1 << i) != 0)
        .map(|(_, k)| *k)
}
