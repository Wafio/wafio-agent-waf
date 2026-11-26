//! The agent-side counters the request path feeds: the analyze latency histogram,
//! partial-coverage flags, recovered agent panics, maintenance answers. Process-wide; the binary
//! registers them (`wafio_waf_analyze_duration_seconds`, `wafio_waf_partial_coverage_flags`,
//! `wafio_waf_agent_panics`, `wafio_waf_maintenance_responses`) and reads the heartbeat summary.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use wafio_agent_io::metrics::{ANALYZE_LATENCY_BOUNDS, Histogram};

/// The window of the latency histogram.
pub const ANALYZE_LATENCY_WINDOW: Duration = Duration::from_secs(300);

/// Latency of every Analyze call of the inline proxy.
pub static ANALYZE_LATENCY_HISTOGRAM: LazyLock<Arc<Histogram>> = LazyLock::new(|| {
    Arc::new(Histogram::new(
        &ANALYZE_LATENCY_BOUNDS,
        ANALYZE_LATENCY_WINDOW,
        5,
    ))
});

/// Panics recovered outside Analyze and the engines.
pub static PANIC_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn count_agent_panic() {
    PANIC_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Requests answered with the maintenance page.
pub static MAINTENANCE_RESPONSES: AtomicU64 = AtomicU64::new(0);

/// Answers sent compressed, by encoding.
pub static COMPRESSED_GZIP: AtomicU64 = AtomicU64::new(0);
pub static COMPRESSED_BROTLI: AtomicU64 = AtomicU64::new(0);
/// Bytes of the compressed answers before compression and as sent.
pub static COMPRESSION_BYTES_IN: AtomicU64 = AtomicU64::new(0);
pub static COMPRESSION_BYTES_OUT: AtomicU64 = AtomicU64::new(0);

/// Why an answer that could have been compressed was not: it came in pieces, it was over the
/// largest size, no compression slot was free, or the compressed form was not smaller.
pub const COMPRESSION_SKIP_REASONS: [&str; 4] = ["streamed", "too_large", "busy", "grew"];
pub(crate) const SKIP_STREAMED: usize = 0;
pub(crate) const SKIP_TOO_LARGE: usize = 1;
pub(crate) const SKIP_BUSY: usize = 2;
pub(crate) const SKIP_GREW: usize = 3;
pub static COMPRESSION_SKIPPED: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

pub(crate) fn count_compression_skipped(reason: usize) {
    COMPRESSION_SKIPPED[reason].fetch_add(1, Ordering::Relaxed);
}

/// The statuses a folder of static files answers, one counter each: the file (`200`), a part of it
/// (`206`), not modified (`304`), the directory's slash (`308`), a range outside the file (`416`)
/// and, for an app that answers its own misses, `404`, `405` and `503` (the disk is busy).
pub const STATIC_STATUSES: [u16; 8] = [200, 206, 304, 308, 404, 405, 416, 503];
pub static STATIC_RESPONSES: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
/// Looks and reads of a folder that were not made because every disk slot was taken, or that did
/// not return in time (a disk that does not answer).
pub static STATIC_UNAVAILABLE: AtomicU64 = AtomicU64::new(0);
/// Bytes of the bodies of those answers, as sent.
pub static STATIC_BYTES: AtomicU64 = AtomicU64::new(0);

/// Counts a static answer of `status` with `bytes` of body already in hand; a body that is read
/// from a file as it is sent is counted by [`count_static_bytes`].
pub(crate) fn count_static(status: u16, bytes: u64) {
    if let Some(i) = STATIC_STATUSES.iter().position(|&s| s == status) {
        STATIC_RESPONSES[i].fetch_add(1, Ordering::Relaxed);
    }
    count_static_bytes(bytes);
}

pub(crate) fn count_static_bytes(bytes: u64) {
    STATIC_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

pub(crate) fn count_static_unavailable() {
    STATIC_UNAVAILABLE.fetch_add(1, Ordering::Relaxed);
}

/// Copies of the response cache that failed their check when read (a size, a check sum or a key
/// that differs) and were deleted.
pub static CACHE_CORRUPT_FILES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn count_cache_corrupt() {
    CACHE_CORRUPT_FILES.fetch_add(1, Ordering::Relaxed);
}

/// Most distinct coverage flags kept as labels; the rest count as "other".
const COVERAGE_LABEL_CAP: usize = 32;

static COVERAGE_COUNTS: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

/// Counts each comma-separated flag of `coverage`.
pub fn count_coverage_flags(coverage: &str) {
    if coverage.is_empty() {
        return;
    }
    let mut m = COVERAGE_COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    for f in coverage.split(',') {
        let f = f.trim();
        if f.is_empty() {
            continue;
        }
        let key = if m.contains_key(f) || m.len() < COVERAGE_LABEL_CAP {
            f
        } else {
            "other"
        };
        *m.entry(key.to_string()).or_default() += 1;
    }
}

/// `wafio_waf_partial_coverage_flags` samples, sorted by flag.
pub fn coverage_flag_samples() -> Vec<(String, u64)> {
    COVERAGE_COUNTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect()
}

/// p50, p95, p99 over the heartbeat window and the sample count.
pub fn latency_percentiles() -> (Duration, Duration, Duration, u64) {
    let (q, n) = ANALYZE_LATENCY_HISTOGRAM.quantiles(&[0.5, 0.95, 0.99]);
    (q[0], q[1], q[2], n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_flags_are_counted_and_capped() {
        count_coverage_flags(" query_cap, value_truncated ,");
        let s = coverage_flag_samples();
        assert!(s.iter().any(|(k, v)| k == "query_cap" && *v >= 1));
        for i in 0..40 {
            count_coverage_flags(&format!("zz_flag_{i}"));
        }
        assert!(coverage_flag_samples().len() <= COVERAGE_LABEL_CAP + 1);
    }
}
