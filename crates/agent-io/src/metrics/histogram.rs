//! A lock-free latency histogram with
//! cumulative buckets for the exposition and a sliding window of per-interval
//! slots for heartbeat p50/p95/p99.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Analyze-latency bucket upper bounds in seconds.
pub const ANALYZE_LATENCY_BOUNDS: [f64; 11] = [
    0.00025, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0,
];

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Observe costs a few atomic adds; a slot rollover resets
/// that slot with plain stores, so an observation racing it can be lost.
pub struct Histogram {
    bounds: Vec<f64>,
    buckets: Vec<AtomicU64>,
    count: AtomicU64,
    sum_nanos: AtomicU64,
    slot_nanos: i64, // ns
    slots: Vec<WindowSlot>,
    /// Unix nanoseconds (replaceable in tests).
    now: Clock,
}

struct WindowSlot {
    epoch: AtomicI64,
    buckets: Vec<AtomicU64>,
}

fn unix_nanos() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(e) => -(e.duration().as_nanos() as i64),
    }
}

fn zeroed(n: usize) -> Vec<AtomicU64> {
    (0..n).map(|_| AtomicU64::new(0)).collect()
}

impl Histogram {
    /// Ascending bounds (seconds); `window`/`slots`
    /// configure the sliding window, a zero window disables it.
    pub fn new(bounds: &[f64], window: Duration, slots: usize) -> Histogram {
        let mut b = bounds.to_vec();
        b.sort_by(|x, y| x.total_cmp(y));
        let n = b.len();
        let mut h = Histogram {
            bounds: b,
            buckets: zeroed(n + 1),
            count: AtomicU64::new(0),
            sum_nanos: AtomicU64::new(0),
            slot_nanos: 0,
            slots: Vec::new(),
            now: Box::new(unix_nanos),
        };
        let window_ns = window.as_nanos() as i64;
        if window_ns > 0 && slots > 0 {
            h.slot_nanos = window_ns / slots as i64;
            if h.slot_nanos <= 0 {
                h.slot_nanos = window_ns;
            }
            // One spare slot so the slot being filled never overlaps the oldest one.
            h.slots = (0..slots + 1)
                .map(|_| WindowSlot {
                    epoch: AtomicI64::new(-1),
                    buckets: zeroed(n + 1),
                })
                .collect();
        }
        h
    }

    /// Replaces the clock (Unix nanoseconds); tests only.
    pub fn set_clock(&mut self, now: impl Fn() -> i64 + Send + Sync + 'static) {
        self.now = Box::new(now);
    }

    /// The finite bounds, ascending.
    pub fn bounds(&self) -> &[f64] {
        &self.bounds
    }

    fn bucket_for(&self, sec: f64) -> usize {
        self.bounds.partition_point(|&b| b < sec) // first bound >= sec; len = +Inf
    }

    /// Records one duration.
    pub fn observe(&self, d: Duration) {
        let i = self.bucket_for(d.as_secs_f64());
        self.buckets[i].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_nanos
            .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
        if self.slots.is_empty() {
            return;
        }
        let epoch = (self.now)() / self.slot_nanos;
        let s = &self.slots[(epoch % self.slots.len() as i64) as usize];
        let cur = s.epoch.load(Ordering::Acquire);
        if cur != epoch
            && s.epoch
                .compare_exchange(cur, epoch, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            for b in &s.buckets {
                b.store(0, Ordering::Relaxed);
            }
        }
        s.buckets[i].fetch_add(1, Ordering::Relaxed);
    }

    /// Cumulative bucket counts (one per finite bound), the
    /// total count and the sum in seconds.
    pub fn snapshot(&self) -> (Vec<u64>, u64, f64) {
        let mut cumulative = Vec::with_capacity(self.bounds.len());
        let mut run = 0u64;
        for b in &self.buckets[..self.bounds.len()] {
            run = run.wrapping_add(b.load(Ordering::Relaxed));
            cumulative.push(run);
        }
        let count = run.wrapping_add(self.buckets[self.bounds.len()].load(Ordering::Relaxed));
        let sum = Duration::from_nanos(self.sum_nanos.load(Ordering::Relaxed)).as_secs_f64();
        (cumulative, count, sum)
    }

    /// The quantiles (0..1) over the sliding window and the
    /// number of observations in it; all 0 with none.
    pub fn quantiles(&self, qs: &[f64]) -> (Vec<Duration>, u64) {
        let mut vals = vec![Duration::ZERO; qs.len()];
        if self.slots.is_empty() {
            return (vals, 0);
        }
        let mut counts = vec![0u64; self.bounds.len() + 1];
        let now_epoch = (self.now)() / self.slot_nanos;
        let oldest = now_epoch - (self.slots.len() as i64 - 1) + 1; // window = len(slots)-1 slots
        for s in &self.slots {
            let e = s.epoch.load(Ordering::Acquire);
            if e < oldest || e > now_epoch {
                continue;
            }
            for (j, c) in counts.iter_mut().enumerate() {
                *c = c.wrapping_add(s.buckets[j].load(Ordering::Relaxed));
            }
        }
        let n = counts.iter().fold(0u64, |a, c| a.wrapping_add(*c));
        if n == 0 {
            return (vals, 0);
        }
        for (qi, q) in qs.iter().enumerate() {
            let secs = estimate_quantile(*q, &self.bounds, &counts, n);
            // The nanosecond count truncates toward zero.
            vals[qi] = Duration::from_nanos((secs * 1e9) as i64 as u64);
        }
        (vals, n)
    }
}

fn estimate_quantile(q: f64, bounds: &[f64], counts: &[u64], n: u64) -> f64 {
    let q = q.clamp(0.0, 1.0);
    let rank = q * n as f64;
    let mut cum = 0.0;
    for (i, &c) in counts.iter().enumerate() {
        let prev = cum;
        cum += c as f64;
        if cum < rank || c == 0 {
            continue;
        }
        if i == bounds.len() {
            return bounds.last().copied().unwrap_or(0.0);
        }
        let lower = if i > 0 { bounds[i - 1] } else { 0.0 };
        return lower + (bounds[i] - lower) * ((rank - prev) / c as f64);
    }
    bounds.last().copied().unwrap_or(0.0)
}

/// Whole microseconds.
pub fn micros(d: Duration) -> u64 {
    (d.as_nanos() / 1000) as u64
}
