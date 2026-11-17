//! The bounded in-memory block store.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use wafio_lru::{Cache, shorten_key};

pub trait BlockStore: Send + Sync {
    /// End of the current block window for key, when key is in one. An expired
    /// window may be cleared.
    fn block_until(&self, key: &[u8]) -> Option<SystemTime>;
    /// Increments the block count for key.
    fn record_block(&self, key: &[u8]);
    /// Current block count for key.
    fn block_count(&self, key: &[u8]) -> i64;
    /// Sets the block window end for key.
    fn set_block_until(&self, key: &[u8], until: SystemTime);
    /// Removes the block state for key.
    fn clear_block(&self, key: &[u8]);
}

/// Per-store record cap when none is configured (WAFIO_WAF_STORE_MAX_ENTRIES).
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

static EXPIRED_TOTAL: AtomicU64 = AtomicU64::new(0);
static CAPACITY_TOTAL: AtomicU64 = AtomicU64::new(0);
static CAPACITY_LOCKED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Process-wide number of expired records removed.
pub fn expired_evicted_total() -> u64 {
    EXPIRED_TOTAL.load(Ordering::Relaxed)
}
/// Process-wide number of records evicted because a store was full.
pub fn capacity_evicted_total() -> u64 {
    CAPACITY_TOTAL.load(Ordering::Relaxed)
}
/// Capacity evictions that removed a still-active block (part of the above).
pub fn capacity_locked_evicted_total() -> u64 {
    CAPACITY_LOCKED_TOTAL.load(Ordering::Relaxed)
}

#[derive(Default)]
struct Record {
    count: i64,
    /// None = not set.
    block_until: Option<SystemTime>,
}

/// In-memory BlockStore, at most `capacity` records, least recently used
/// evicted first (an active block window is passed over when a nearby entry
/// can go instead). Keys over `wafio_lru::MAX_VERBATIM_KEY_LEN` bytes are stored as a
/// SHA-256 digest.
pub struct MemoryStore {
    data: Cache<Record>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// A store capped at DEFAULT_MAX_ENTRIES.
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_MAX_ENTRIES)
    }

    /// A store holding at most `max_entries` records (< 1 = default).
    pub fn with_cap(max_entries: usize) -> Self {
        let max_entries = if max_entries < 1 {
            DEFAULT_MAX_ENTRIES
        } else {
            max_entries
        };
        let mut c = Cache::new(max_entries);
        c.set_pin_hook(|r: &Record| r.block_until.is_some_and(|u| SystemTime::now() < u));
        c.set_evict_hook(|protected| {
            CAPACITY_TOTAL.fetch_add(1, Ordering::Relaxed);
            if protected {
                CAPACITY_LOCKED_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
        });
        MemoryStore { data: c }
    }

    /// Purges idle records (no window, count 0) and records whose block window
    /// has passed; returns how many were removed.
    pub fn cleanup_expired(&self, now: SystemTime) -> usize {
        let evicted = self.data.remove_matching(|_, r| match r.block_until {
            Some(u) if now < u => false,
            None => r.count == 0,
            Some(u) => now > u,
        });
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

impl BlockStore for MemoryStore {
    fn block_until(&self, key: &[u8]) -> Option<SystemTime> {
        let mut out = None;
        self.data.get(
            &shorten_key(key),
            Some(&mut |r: &mut Record| {
                let Some(u) = r.block_until else { return };
                if SystemTime::now() < u {
                    out = Some(u);
                    return;
                }
                // Expired: clear the window and reset the count (fresh N blocks).
                r.block_until = None;
                r.count = 0;
            }),
        );
        out
    }

    fn record_block(&self, key: &[u8]) {
        self.data.update(&shorten_key(key), |r, _| r.count += 1);
    }

    fn block_count(&self, key: &[u8]) -> i64 {
        let mut n = 0;
        self.data
            .get(&shorten_key(key), Some(&mut |r: &mut Record| n = r.count));
        n
    }

    fn set_block_until(&self, key: &[u8], until: SystemTime) {
        self.data
            .update(&shorten_key(key), |r, _| r.block_until = Some(until));
    }

    fn clear_block(&self, key: &[u8]) {
        self.data.remove(&shorten_key(key));
    }
}

/// Prefixes every key with `project_id + ":"`.
pub fn scope_store_to_project(store: Arc<dyn BlockStore>, project_id: &str) -> Arc<dyn BlockStore> {
    Arc::new(ScopedStore {
        store,
        prefix: format!("{project_id}:").into_bytes(),
    })
}

struct ScopedStore {
    store: Arc<dyn BlockStore>,
    prefix: Vec<u8>,
}

impl ScopedStore {
    fn key(&self, k: &[u8]) -> Vec<u8> {
        [self.prefix.as_slice(), k].concat()
    }
}

impl BlockStore for ScopedStore {
    fn block_until(&self, key: &[u8]) -> Option<SystemTime> {
        self.store.block_until(&self.key(key))
    }
    fn record_block(&self, key: &[u8]) {
        self.store.record_block(&self.key(key))
    }
    fn block_count(&self, key: &[u8]) -> i64 {
        self.store.block_count(&self.key(key))
    }
    fn set_block_until(&self, key: &[u8], until: SystemTime) {
        self.store.set_block_until(&self.key(key), until)
    }
    fn clear_block(&self, key: &[u8]) {
        self.store.clear_block(&self.key(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn cap_bounds_entries() {
        let s = MemoryStore::with_cap(1000);
        for i in 0..5000 {
            s.record_block(format!("client-{i}").as_bytes());
        }
        assert!(s.len() <= 1000, "len {}", s.len());
        assert_eq!(s.capacity(), 1000);
    }

    // An active block survives a key spray.
    #[test]
    fn active_block_survives_spray() {
        let s = MemoryStore::with_cap(1000);
        let until = SystemTime::now() + Duration::from_secs(3600);
        s.set_block_until(b"attacker", until);
        for i in 0..20_000 {
            s.record_block(format!("spray-{i}").as_bytes());
        }
        assert_eq!(s.block_until(b"attacker"), Some(until));
    }

    #[test]
    fn long_keys_compacted() {
        let s = MemoryStore::new();
        let long = vec![b'k'; 4096];
        s.record_block(&long);
        s.record_block(&long);
        assert_eq!(s.block_count(&long), 2);
    }

    #[test]
    fn cleanup_and_expiry() {
        let s = MemoryStore::new();
        s.record_block(b"counted");
        s.set_block_until(b"expired", SystemTime::now() - Duration::from_secs(1));
        s.set_block_until(b"active", SystemTime::now() + Duration::from_secs(3600));
        s.data.update(b"idle", |_, _| {});
        assert_eq!(s.cleanup_expired(SystemTime::now()), 2);
        assert_eq!(s.len(), 2);
        assert_eq!(s.block_count(b"counted"), 1);
        assert!(s.block_until(b"active").is_some());
    }

    #[test]
    fn expired_window_resets_count() {
        let s = MemoryStore::new();
        s.record_block(b"k");
        s.record_block(b"k");
        s.set_block_until(b"k", SystemTime::now() - Duration::from_secs(1));
        assert_eq!(s.block_until(b"k"), None);
        assert_eq!(s.block_count(b"k"), 0);
    }

    #[test]
    fn scoped() {
        let base: Arc<dyn BlockStore> = Arc::new(MemoryStore::new());
        let a = scope_store_to_project(base.clone(), "p1");
        a.record_block(b"ip");
        assert_eq!(base.block_count(b"p1:ip"), 1);
        a.clear_block(b"ip");
        assert_eq!(base.block_count(b"p1:ip"), 0);
    }
}
