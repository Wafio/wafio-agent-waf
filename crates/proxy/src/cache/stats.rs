//! What the cache of one app counts: each counter over the last hour in one-minute buckets (what
//! `EdgeStatus` carries) and since the agent started (what the metrics carry).

use std::sync::atomic::{AtomicU64, Ordering};

use crate::edge_stats::Hourly;

/// A thing the cache counts. The order is the order of the buckets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Count {
    HitMemory,
    HitDisk,
    Miss,
    Bypass,
    Stale,
    Stored,
    SkippedNoLifetime,
    SkippedPrivate,
    SkippedTooLarge,
    SkippedStreamed,
    SkippedDiskFull,
    Evictions,
    Corrupt,
}

const KINDS: usize = 13;

/// What an app's cache did over the last hour, and what it holds now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheCounters {
    /// Every answer that carried an `X-Cache`: hits, misses, bypasses and stale answers.
    pub requests: u64,
    pub hits_memory: u64,
    pub hits_disk: u64,
    pub misses: u64,
    pub bypass: u64,
    pub stale: u64,
    pub stored: u64,
    pub skipped_no_lifetime: u64,
    pub skipped_private: u64,
    pub skipped_too_large: u64,
    pub skipped_streamed: u64,
    pub skipped_disk_full: u64,
    pub evictions: u64,
    pub corrupt: u64,
    /// Gauges: bytes of copies on disk, bytes held in memory, copies.
    pub disk_bytes: u64,
    pub memory_bytes: u64,
    pub objects: u64,
}

/// What an app's cache counted since the agent started, for the metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheTotals {
    pub hits_memory: u64,
    pub hits_disk: u64,
    pub misses: u64,
    pub bypass: u64,
    pub stale: u64,
    pub evictions: u64,
}

#[derive(Default)]
pub(crate) struct Counters {
    hourly: Hourly<KINDS>,
    totals: [AtomicU64; KINDS],
}

impl Counters {
    pub fn add(&self, what: Count, n: u64) {
        if n > 0 {
            self.hourly.add(super::store::now(), what as usize, n);
            self.totals[what as usize].fetch_add(n, Ordering::Relaxed);
        }
    }

    pub fn hour(&self, now: u64) -> CacheCounters {
        let s = self.hourly.sums(now);
        let at = |what: Count| s[what as usize];
        CacheCounters {
            requests: at(Count::HitMemory)
                .saturating_add(at(Count::HitDisk))
                .saturating_add(at(Count::Miss))
                .saturating_add(at(Count::Bypass))
                .saturating_add(at(Count::Stale)),
            hits_memory: at(Count::HitMemory),
            hits_disk: at(Count::HitDisk),
            misses: at(Count::Miss),
            bypass: at(Count::Bypass),
            stale: at(Count::Stale),
            stored: at(Count::Stored),
            skipped_no_lifetime: at(Count::SkippedNoLifetime),
            skipped_private: at(Count::SkippedPrivate),
            skipped_too_large: at(Count::SkippedTooLarge),
            skipped_streamed: at(Count::SkippedStreamed),
            skipped_disk_full: at(Count::SkippedDiskFull),
            evictions: at(Count::Evictions),
            corrupt: at(Count::Corrupt),
            ..CacheCounters::default()
        }
    }

    pub fn totals(&self) -> CacheTotals {
        let at = |what: Count| self.totals[what as usize].load(Ordering::Relaxed);
        CacheTotals {
            hits_memory: at(Count::HitMemory),
            hits_disk: at(Count::HitDisk),
            misses: at(Count::Miss),
            bypass: at(Count::Bypass),
            stale: at(Count::Stale),
            evictions: at(Count::Evictions),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_the_answers_that_carried_an_x_cache() {
        let c = Counters::default();
        for (what, n) in [
            (Count::HitMemory, 2),
            (Count::HitDisk, 3),
            (Count::Miss, 4),
            (Count::Bypass, 5),
            (Count::Stale, 6),
            (Count::Stored, 7),
            (Count::Corrupt, 1),
        ] {
            c.add(what, n);
        }
        let hour = c.hour(super::super::store::now());
        assert_eq!(hour.requests, 20, "a store is not a request");
        assert_eq!((hour.hits_memory, hour.hits_disk, hour.stored), (2, 3, 7));
        assert_eq!(
            (hour.disk_bytes, hour.objects),
            (0, 0),
            "gauges are the store's"
        );
        assert_eq!(c.totals().stale, 6);
        c.add(Count::Evictions, 0);
        assert_eq!(c.totals().evictions, 0);
    }
}
