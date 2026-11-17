//! The process-wide in-flight decode memory budget. A reservation that does not fit is
//! never waited for: decoding is skipped and the body is marked `decompress_budget`.

use std::sync::Once;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use wafio_domain::text_helpers::{to_lowercase, trim_whitespace};

/// The process-wide budget when neither the env nor
/// `set_inflight_decode_bytes` sets one.
pub const DEFAULT_INFLIGHT_DECODE_BYTES: i64 = 64 << 20;

/// Overrides the budget: a byte count, optionally with a KiB/MiB/GiB (or
/// K/M/G) suffix; "0" disables it. Read once, at the first decode.
pub const INFLIGHT_DECODE_BYTES_ENV: &str = "WAFIO_BODY_DECODE_BUDGET_BYTES";

pub(crate) struct ByteBudget {
    /// Bytes; 0 = unlimited.
    pub(crate) capacity: AtomicI64,
    /// Bytes currently reserved.
    pub(crate) in_use: AtomicI64,
    pub(crate) skips: AtomicU64,
}

static INFLIGHT_BUDGET: ByteBudget = ByteBudget {
    capacity: AtomicI64::new(0),
    in_use: AtomicI64::new(0),
    skips: AtomicU64::new(0),
};
static INFLIGHT_BUDGET_INIT: Once = Once::new();

pub(crate) fn shared_budget() -> &'static ByteBudget {
    INFLIGHT_BUDGET_INIT.call_once(|| {
        let v = std::env::var_os(INFLIGHT_DECODE_BYTES_ENV)
            .map(|v| v.into_encoded_bytes())
            .unwrap_or_default();
        INFLIGHT_BUDGET
            .capacity
            .store(parse_budget_env(&v), Ordering::SeqCst);
    });
    &INFLIGHT_BUDGET
}

/// Parses the env value; unset or invalid means the default.
pub(crate) fn parse_budget_env(v: &[u8]) -> i64 {
    let v = trim_whitespace(v);
    if v.is_empty() {
        return DEFAULT_INFLIGHT_DECODE_BYTES;
    }
    let Some(n) = parse_size_with_suffix(v) else {
        tracing::warn!(
            "[bodyinspect] invalid {INFLIGHT_DECODE_BYTES_ENV}={:?}, using the default {DEFAULT_INFLIGHT_DECODE_BYTES} bytes",
            String::from_utf8_lossy(v)
        );
        return DEFAULT_INFLIGHT_DECODE_BYTES;
    };
    if n == 0 {
        tracing::info!(
            "[bodyinspect] {INFLIGHT_DECODE_BYTES_ENV}=0: process-wide decode memory budget disabled"
        );
    } else {
        tracing::info!(
            "[bodyinspect] decode memory budget {n} bytes ({INFLIGHT_DECODE_BYTES_ENV})"
        );
    }
    n
}

/// Parses "123", "64MiB", "64M", "512KiB", "1GiB" (binary units,
/// case-insensitive). Negative values and overflow are rejected.
pub(crate) fn parse_size_with_suffix(v: &[u8]) -> Option<i64> {
    let lowered = to_lowercase(trim_whitespace(v));
    let mut s: &[u8] = &lowered;
    let mut shift = 0u32;
    for (suffix, sh) in [
        ("kib", 10),
        ("mib", 20),
        ("gib", 30),
        ("k", 10),
        ("m", 20),
        ("g", 30),
        ("b", 0),
    ] {
        if let Some(rest) = s.strip_suffix(suffix.as_bytes()) {
            s = trim_whitespace(rest);
            shift = sh;
            break;
        }
    }
    let n = wafio_bytetext::literal::parse_int(s, 10, 64).ok()?;
    if n < 0 || n > (1i64 << 62) >> shift {
        return None;
    }
    Some(n << shift)
}

/// Sets the process-wide in-flight decode budget in bytes: > 0 caps it, 0
/// disables it, < 0 restores the default. Overrides the env.
pub fn set_inflight_decode_bytes(bytes: i64) {
    let b = shared_budget();
    b.capacity.store(
        if bytes < 0 {
            DEFAULT_INFLIGHT_DECODE_BYTES
        } else {
            bytes
        },
        Ordering::SeqCst,
    );
}

/// The current process-wide budget (0 = unlimited).
pub fn inflight_decode_bytes_limit() -> i64 {
    shared_budget().capacity.load(Ordering::SeqCst)
}

/// Bytes currently reserved by in-flight decodes.
pub fn inflight_decode_bytes_used() -> i64 {
    shared_budget().in_use.load(Ordering::SeqCst)
}

/// Decodes skipped because the budget was exhausted since process start.
pub fn skipped_decode_count() -> u64 {
    shared_budget().skips.load(Ordering::SeqCst)
}

impl ByteBudget {
    /// Reserves n bytes without waiting; false when it would exceed the
    /// capacity. Without a capacity it always succeeds and still tracks use.
    pub(crate) fn try_acquire(&self, n: i64) -> bool {
        if n <= 0 {
            return true;
        }
        loop {
            let limit = self.capacity.load(Ordering::SeqCst);
            let cur = self.in_use.load(Ordering::SeqCst);
            if limit > 0 && cur + n > limit {
                return false;
            }
            if self
                .in_use
                .compare_exchange(cur, cur + n, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Returns a reservation made by a successful try_acquire(n).
    pub(crate) fn release(&self, n: i64) {
        if n > 0 {
            self.in_use.fetch_sub(n, Ordering::SeqCst);
        }
    }
}
