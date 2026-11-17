//! Reconnect backoff, jitter and keepalive.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// ± fraction applied to every reconnect wait.
pub const RECONNECT_JITTER: f64 = 0.20;

/// Reconnect backoff bounds. A stream that stayed up for `RECONNECT_HEALTHY_AFTER`
/// counts as healthy: the next wait starts again at the minimum.
pub const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(1);
pub const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);
pub const RECONNECT_HEALTHY_AFTER: Duration = Duration::from_secs(60);

/// Client keepalive: ping every 30 s while a stream is open, 10 s timeout.
pub const GRPC_CLIENT_KEEPALIVE_TIME: Duration = Duration::from_secs(30);
pub const GRPC_CLIENT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// The wait between stream attempts.
#[derive(Debug, Default)]
pub struct ReconnectBackoff {
    next: Duration,
}

impl ReconnectBackoff {
    /// The wait (before jitter) after a stream that lived for `lived`; advances the backoff.
    pub fn delay(&mut self, lived: Duration) -> Duration {
        if self.next.is_zero() || lived >= RECONNECT_HEALTHY_AFTER {
            self.next = RECONNECT_BACKOFF_MIN;
        }
        let d = self.next;
        self.next = (self.next * 2).min(RECONNECT_BACKOFF_MAX);
        d
    }
}

/// `d` scaled by a random factor in [1-RECONNECT_JITTER, 1+RECONNECT_JITTER].
pub fn jitter(d: Duration) -> Duration {
    if d.is_zero() {
        return d;
    }
    let f = 1.0 - RECONNECT_JITTER + random_f64() * 2.0 * RECONNECT_JITTER;
    Duration::from_nanos((d.as_nanos() as f64 * f) as u64)
}

/// Random bits for timing spread and temp names, not security: std's randomly keyed
/// SipHash over a counter.
pub(crate) fn random_u64() -> u64 {
    static STATE: std::sync::LazyLock<RandomState> = std::sync::LazyLock::new(RandomState::new);
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    STATE.hash_one(COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn random_f64() -> f64 {
    (random_u64() >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // Reconnect waits are spread ±20 %.
    #[test]
    fn jitter_stays_within_twenty_percent_and_varies() {
        let d = Duration::from_secs(10);
        let (lo, hi) = (Duration::from_secs(8), Duration::from_secs(12));
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let got = jitter(d);
            assert!(got >= lo && got <= hi, "jitter({d:?}) = {got:?}");
            seen.insert(got);
        }
        assert!(seen.len() >= 10, "only {} distinct values", seen.len());
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }

    // Doubles while streams fail fast, starts over after a healthy stream.
    #[test]
    fn reconnect_backoff_resets_after_healthy_stream() {
        let mut b = ReconnectBackoff::default();
        for (i, w) in [1, 2, 4, 8, 16, 30, 30].into_iter().enumerate() {
            assert_eq!(
                b.delay(Duration::from_secs(1)),
                Duration::from_secs(w),
                "fast failure {i}"
            );
        }
        assert_eq!(b.delay(RECONNECT_HEALTHY_AFTER), RECONNECT_BACKOFF_MIN);
        assert_eq!(b.delay(Duration::ZERO), Duration::from_secs(2));
    }
}
