//! The in-memory rate limit store: fixed-window counters for L7 flood, per-path rate limits and login
//! protection.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use wafio_lru::{Cache, shorten_key};

pub trait RateLimitStore: Send + Sync {
    /// Fixed window: false when the count exceeds `max_requests` in `window_sec`.
    fn allow(&self, scope: &[u8], key: &[u8], max_requests: i64, window_sec: i64) -> bool;
    /// Like `allow`, plus a lockout of `lockout_sec` once the limit is exceeded.
    fn allow_login(
        &self,
        scope: &[u8],
        key: &[u8],
        max_attempts: i64,
        window_sec: i64,
        lockout_sec: i64,
    ) -> bool;
    /// Clears the state of one scope+key.
    fn unblock(&self, scope: &[u8], key: &[u8]);
}

/// Per-store bucket cap when none is configured (WAFIO_WAF_STORE_MAX_ENTRIES).
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

static EXPIRED_TOTAL: AtomicU64 = AtomicU64::new(0);
static CAPACITY_TOTAL: AtomicU64 = AtomicU64::new(0);
static CAPACITY_LOCKED_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn expired_evicted_total() -> u64 {
    EXPIRED_TOTAL.load(Ordering::Relaxed)
}
pub fn capacity_evicted_total() -> u64 {
    CAPACITY_TOTAL.load(Ordering::Relaxed)
}
pub fn capacity_locked_evicted_total() -> u64 {
    CAPACITY_LOCKED_TOTAL.load(Ordering::Relaxed)
}

const SCOPE_SEP: u8 = 0;

/// Window and lockout ends; None = not set.
#[derive(Default)]
struct Bucket {
    count: i64,
    window_end: Option<Instant>,
    locked_until: Option<Instant>,
}

fn after(now: Instant, t: Option<Instant>) -> bool {
    t.is_none_or(|t| now > t)
}

fn locked(now: Instant, b: &Bucket) -> bool {
    b.locked_until.is_some_and(|l| now < l)
}

fn secs(n: i64) -> Duration {
    Duration::from_secs(n.max(0) as u64)
}

/// In-memory RateLimitStore: one fixed-window counter per scope+key, at most
/// `capacity` buckets, least recently used evicted first (an active login
/// lockout is passed over when a nearby entry can go instead).
pub struct MemoryStore {
    data: Cache<Bucket>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Hashes an over-long scope base, keeping the identifier suffix after the
/// last NUL ("\0ip", "\0f", "\0ua") verbatim so `clear_login_scope` still finds it.
fn compact_scope(scope: &[u8]) -> Vec<u8> {
    match scope.iter().rposition(|&c| c == 0) {
        Some(i) => [shorten_key(&scope[..i]).as_slice(), &scope[i..]].concat(),
        None => shorten_key(scope),
    }
}

fn store_key(scope: &[u8], key: &[u8]) -> Vec<u8> {
    let mut k = compact_scope(scope);
    k.push(SCOPE_SEP);
    k.extend_from_slice(&shorten_key(key));
    k
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_MAX_ENTRIES)
    }

    /// A store holding at most `max_entries` buckets (< 1 = default).
    pub fn with_cap(max_entries: usize) -> Self {
        let max_entries = if max_entries < 1 {
            DEFAULT_MAX_ENTRIES
        } else {
            max_entries
        };
        let mut c = Cache::new(max_entries);
        c.set_pin_hook(|b: &Bucket| locked(Instant::now(), b));
        c.set_evict_hook(|protected| {
            CAPACITY_TOTAL.fetch_add(1, Ordering::Relaxed);
            if protected {
                CAPACITY_LOCKED_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
        });
        MemoryStore { data: c }
    }

    /// Deletes every bucket of a login protection scope (all identifiers).
    pub fn clear_login_scope(&self, base_scope: &[u8]) {
        let mut prefix = shorten_key(base_scope);
        prefix.push(SCOPE_SEP);
        self.data.remove_matching(|k, _| k.starts_with(&prefix));
    }

    /// Purges buckets whose window passed and whose lockout is over.
    pub fn cleanup_expired(&self, now: Instant) -> usize {
        let evicted = self
            .data
            .remove_matching(|_, b| !locked(now, b) && after(now, b.window_end));
        EXPIRED_TOTAL.fetch_add(evicted as u64, Ordering::Relaxed);
        evicted
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }
}

impl RateLimitStore for MemoryStore {
    fn allow(&self, scope: &[u8], key: &[u8], max_requests: i64, window_sec: i64) -> bool {
        if max_requests < 1 || window_sec < 1 {
            return true;
        }
        let mut allowed = true;
        self.data.update(&store_key(scope, key), |b, _| {
            let now = Instant::now();
            if after(now, b.window_end) {
                b.count = 0;
                b.window_end = Some(now + secs(window_sec));
            }
            b.count += 1;
            allowed = b.count <= max_requests;
        });
        allowed
    }

    fn allow_login(
        &self,
        scope: &[u8],
        key: &[u8],
        max_attempts: i64,
        window_sec: i64,
        lockout_sec: i64,
    ) -> bool {
        if max_attempts < 1 || window_sec < 1 {
            return true;
        }
        let mut allowed = true;
        self.data.update(&store_key(scope, key), |b, _| {
            let now = Instant::now();
            if locked(now, b) {
                allowed = false;
                return;
            }
            if after(now, b.window_end) {
                b.count = 0;
                b.locked_until = None;
                b.window_end = Some(now + secs(window_sec));
            }
            b.count += 1;
            if b.count > max_attempts {
                if lockout_sec > 0 {
                    b.locked_until = Some(now + secs(lockout_sec));
                }
                allowed = false;
            }
        });
        allowed
    }

    fn unblock(&self, scope: &[u8], key: &[u8]) {
        self.data.remove(&store_key(scope, key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window() {
        let s = MemoryStore::new();
        for _ in 0..3 {
            assert!(s.allow(b"p", b"ip", 3, 60));
        }
        assert!(!s.allow(b"p", b"ip", 3, 60));
        assert!(s.allow(b"p", b"other", 3, 60));
        assert!(s.allow(b"p", b"ip", 0, 60), "disabled limit always allows");
        s.unblock(b"p", b"ip");
        assert!(s.allow(b"p", b"ip", 3, 60));
    }

    #[test]
    fn login_lockout_and_clear_scope() {
        let s = MemoryStore::new();
        assert!(s.allow_login(b"scope\x00ip", b"1.2.3.4", 2, 60, 300));
        assert!(s.allow_login(b"scope\x00ip", b"1.2.3.4", 2, 60, 300));
        assert!(!s.allow_login(b"scope\x00ip", b"1.2.3.4", 2, 60, 300));
        assert!(
            !s.allow_login(b"scope\x00ip", b"1.2.3.4", 2, 60, 300),
            "locked out"
        );
        s.clear_login_scope(b"scope");
        assert!(s.allow_login(b"scope\x00ip", b"1.2.3.4", 2, 60, 300));
    }

    // A hashed long scope is still cleared by `clear_login_scope`.
    #[test]
    fn long_scope_clear() {
        let s = MemoryStore::new();
        let base = vec![b's'; 300];
        let scope = [base.as_slice(), b"\x00f"].concat();
        assert!(s.allow_login(&scope, b"user", 1, 60, 300));
        assert!(!s.allow_login(&scope, b"user", 1, 60, 300));
        s.clear_login_scope(&base);
        assert!(s.allow_login(&scope, b"user", 1, 60, 300));
    }

    #[test]
    fn cap_and_locked_survive() {
        let s = MemoryStore::with_cap(1000);
        assert!(s.allow_login(b"l\x00ip", b"victim", 1, 60, 3600));
        assert!(!s.allow_login(b"l\x00ip", b"victim", 1, 60, 3600));
        for i in 0..20_000 {
            s.allow(b"flood", format!("k{i}").as_bytes(), 10, 60);
        }
        assert!(s.len() <= 1000);
        assert!(
            !s.allow_login(b"l\x00ip", b"victim", 1, 60, 3600),
            "lockout kept"
        );
    }

    #[test]
    fn cleanup() {
        let s = MemoryStore::new();
        s.allow(b"p", b"a", 10, 1);
        assert_eq!(s.cleanup_expired(Instant::now()), 0);
        assert_eq!(
            s.cleanup_expired(Instant::now() + Duration::from_secs(2)),
            1
        );
        assert!(s.is_empty());
    }
}
