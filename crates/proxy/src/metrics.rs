//! The agent-side counters the request path feeds: the analyze latency histogram,
//! partial-coverage flags, recovered agent panics. Process-wide; the binary registers them
//! (`wafio_waf_analyze_duration_seconds`, `wafio_waf_partial_coverage_flags`,
//! `wafio_waf_agent_panics`) and reads the heartbeat summary.

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
