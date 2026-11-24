//! What the edge parts of an app (compression now) count, over the last hour in one-minute
//! buckets: the control plane shows the sum of the buckets still inside the hour, never a total
//! since start. The counters belong to the process, not to a route, so a bundle apply keeps them.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

const MINUTES: u64 = 60;

/// `N` counters kept per minute for the last hour. The caller passes the time (unix seconds), so
/// a test can move it.
pub(crate) struct Hourly<const N: usize> {
    slots: Mutex<[(u64, [u64; N]); MINUTES as usize]>,
}

impl<const N: usize> Default for Hourly<N> {
    fn default() -> Self {
        Hourly {
            slots: Mutex::new([(0, [0; N]); MINUTES as usize]),
        }
    }
}

impl<const N: usize> Hourly<N> {
    /// Adds `n` to counter `counter` in the minute of `now`.
    pub fn add(&self, now: u64, counter: usize, n: u64) {
        let minute = now / 60;
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = &mut slots[(minute % MINUTES) as usize];
        if slot.0 != minute {
            *slot = (minute, [0; N]);
        }
        slot.1[counter] = slot.1[counter].saturating_add(n);
    }

    /// Each counter summed over the minute of `now` and the 59 before it.
    pub fn sums(&self, now: u64) -> [u64; N] {
        let minute = now / 60;
        let slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let mut sums = [0u64; N];
        for (stamp, counts) in slots.iter() {
            if *stamp <= minute && minute - *stamp < MINUTES {
                for (sum, count) in sums.iter_mut().zip(counts) {
                    *sum = sum.saturating_add(*count);
                }
            }
        }
        sums
    }
}

/// What the compression of one app did over the last hour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompressionCounters {
    /// Answers sent compressed.
    pub responses: u64,
    /// Answers that would have been compressed but came without a length, in pieces.
    pub skipped_streamed: u64,
    /// The size of the answers before compression minus what was sent.
    pub bytes_saved: u64,
}

const RESPONSES: usize = 0;
const SKIPPED_STREAMED: usize = 1;
const BYTES_SAVED: usize = 2;

/// The counters of one app.
#[derive(Default)]
pub(crate) struct AppEdgeStats {
    compression: Hourly<3>,
}

impl AppEdgeStats {
    pub fn compressed(&self, now: u64, saved: u64) {
        self.compression.add(now, RESPONSES, 1);
        self.compression.add(now, BYTES_SAVED, saved);
    }

    pub fn compression_streamed(&self, now: u64) {
        self.compression.add(now, SKIPPED_STREAMED, 1);
    }

    pub fn compression_counters(&self, now: u64) -> CompressionCounters {
        let [responses, skipped_streamed, bytes_saved] = self.compression.sums(now);
        CompressionCounters {
            responses,
            skipped_streamed,
            bytes_saved,
        }
    }
}

/// The counters of every app, by app id.
#[derive(Default)]
pub(crate) struct EdgeStats {
    apps: RwLock<HashMap<String, Arc<AppEdgeStats>>>,
}

impl EdgeStats {
    /// The counters of `app_id`, made on first use.
    pub fn app(&self, app_id: &str) -> Arc<AppEdgeStats> {
        if let Some(stats) = self.get(app_id) {
            return stats;
        }
        let mut apps = self.apps.write().unwrap_or_else(PoisonError::into_inner);
        apps.entry(app_id.to_owned()).or_default().clone()
    }

    pub fn get(&self, app_id: &str) -> Option<Arc<AppEdgeStats>> {
        let apps = self.apps.read().unwrap_or_else(PoisonError::into_inner);
        apps.get(app_id).cloned()
    }

    /// Forgets the apps that are not in `keep` (a bundle dropped them).
    pub fn retain(&self, keep: &HashSet<&str>) {
        let mut apps = self.apps.write().unwrap_or_else(PoisonError::into_inner);
        apps.retain(|id, _| keep.contains(id.as_str()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_cover_the_last_sixty_minutes_and_not_the_one_before() {
        let h = Hourly::<2>::default();
        let t0 = 1_000_000 * 60;
        h.add(t0, 0, 5);
        h.add(t0 + 59, 0, 1);
        h.add(t0 + 59, 1, 7);
        assert_eq!(h.sums(t0 + 59), [6, 7], "one minute holds both");
        assert_eq!(h.sums(t0 + 59 * 60), [6, 7], "still inside the hour");
        assert_eq!(h.sums(t0 + 60 * 60), [0, 0], "the first minute is out");
        h.add(t0 + 60, 0, 2);
        assert_eq!(h.sums(t0 + 59 * 60 + 60), [2, 0], "second minute only");
    }

    #[test]
    fn a_slot_is_reused_by_the_minute_an_hour_later_and_starts_from_zero() {
        let h = Hourly::<1>::default();
        let t0 = 5_000 * 60;
        h.add(t0, 0, 9);
        h.add(t0 + 3600, 0, 1);
        assert_eq!(h.sums(t0 + 3600), [1]);
        assert_eq!(h.sums(t0 + 3600 + 59 * 60), [1]);
        assert_eq!(h.sums(t0 + 3600 + 60 * 60), [0]);
    }

    #[test]
    fn sums_ignore_a_minute_in_the_future_and_saturate() {
        let h = Hourly::<1>::default();
        h.add(10_000 * 60, 0, 3);
        assert_eq!(h.sums(9_999 * 60), [0], "a clock that went back");
        h.add(20_000 * 60, 0, u64::MAX);
        h.add(20_000 * 60, 0, 5);
        assert_eq!(h.sums(20_000 * 60), [u64::MAX]);
    }

    #[test]
    fn the_registry_keeps_an_app_across_calls_and_forgets_the_dropped_ones() {
        let stats = EdgeStats::default();
        let t = 123_456 * 60;
        stats.app("a").compressed(t, 40);
        stats.app("a").compressed(t, 10);
        stats.app("a").compression_streamed(t);
        stats.app("b").compressed(t, 1);
        assert_eq!(
            stats.get("a").unwrap().compression_counters(t),
            CompressionCounters {
                responses: 2,
                skipped_streamed: 1,
                bytes_saved: 50
            }
        );
        stats.retain(&HashSet::from(["b"]));
        assert!(stats.get("a").is_none());
        assert_eq!(stats.get("b").unwrap().compression_counters(t).responses, 1);
    }
}
