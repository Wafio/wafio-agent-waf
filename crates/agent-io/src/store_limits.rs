//! The per-store entry cap of the L7 rate-limit and block stores, and their eviction samples.
//! The stores themselves live in the store crates, which call [`store_entry_cap`].

use std::sync::OnceLock;

use crate::metrics::{Label, Sample};

/// Caps each in-memory L7 rate-limit and block store of the WAF agent: a
/// positive entry count; unset or invalid = [`DEFAULT_STORE_CAP`]. Read once.
pub const STORE_CAP_ENV_VAR: &str = "WAFIO_WAF_STORE_MAX_ENTRIES";

/// `ratelimit.DefaultMaxEntries` / `blocklist.DefaultMaxEntries`.
pub const DEFAULT_STORE_CAP: i64 = 100_000;

/// Keeps a typo from shrinking the stores to uselessness.
const MIN_STORE_CAP: i64 = 1000;

/// The cap from the environment, read once per process.
pub fn store_entry_cap() -> i64 {
    static V: OnceLock<i64> = OnceLock::new();
    *V.get_or_init(|| {
        let raw = std::env::var_os(STORE_CAP_ENV_VAR).unwrap_or_default();
        parse_store_entry_cap(raw.as_encoded_bytes())
    })
}

pub fn parse_store_entry_cap(v: &[u8]) -> i64 {
    let stripped: Vec<u8> = v.iter().copied().filter(|&c| c != b'_').collect();
    let v = wafio_bytetext::strings::trim_whitespace(&stripped);
    if v.is_empty() {
        return DEFAULT_STORE_CAP;
    }
    // Optional sign, decimal digits, int64 range.
    let n = std::str::from_utf8(v)
        .ok()
        .and_then(|s| s.parse::<i64>().ok());
    match n {
        Some(n) if n >= MIN_STORE_CAP => {
            tracing::info!(
                "[waf-agent] rate-limit/block store cap {n} entries per store ({STORE_CAP_ENV_VAR})"
            );
            n
        }
        _ => {
            tracing::warn!(
                "[waf-agent] invalid {STORE_CAP_ENV_VAR}={} (want an integer ≥ {MIN_STORE_CAP}), using {DEFAULT_STORE_CAP}",
                wafio_domain::text_helpers::quote(v)
            );
            DEFAULT_STORE_CAP
        }
    }
}

/// Samples of a store's eviction counters by reason; capacity
/// excludes the capacity_locked part (an active entry evicted).
pub fn eviction_counter_samples(expired: u64, capacity: u64, capacity_locked: u64) -> Vec<Sample> {
    let reason = |v: &str| {
        vec![Label {
            name: "reason".into(),
            value: v.into(),
        }]
    };
    vec![
        Sample {
            labels: reason("capacity"),
            value: capacity.wrapping_sub(capacity_locked) as f64,
        },
        Sample {
            labels: reason("capacity_locked"),
            value: capacity_locked as f64,
        },
        Sample {
            labels: reason("expired"),
            value: expired as f64,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_store_entry_cap_cases() {
        for (input, want) in [
            ("", DEFAULT_STORE_CAP),
            ("250000", 250_000),
            ("250_000", 250_000),
            (" 5000 ", 5000),
            ("999", DEFAULT_STORE_CAP),
            ("0", DEFAULT_STORE_CAP),
            ("-1", DEFAULT_STORE_CAP),
            ("lots", DEFAULT_STORE_CAP),
            ("1e6", DEFAULT_STORE_CAP),
            ("10000000", 10_000_000),
            ("+2000", 2000),
        ] {
            assert_eq!(parse_store_entry_cap(input.as_bytes()), want, "{input:?}");
        }
    }

    #[test]
    fn eviction_counter_samples_split_locked() {
        let s = eviction_counter_samples(4, 10, 3);
        assert_eq!(
            s.iter().map(|x| x.value).collect::<Vec<_>>(),
            vec![7.0, 3.0, 4.0]
        );
        assert_eq!(s[1].labels[0].value, "capacity_locked");
    }
}
