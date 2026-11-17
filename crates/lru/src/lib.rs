//! A bounded, sharded LRU map for the WAF agent's in-memory rate-limit and block stores. Every operation is
//! O(1) under one shard mutex (key hash → shard); the entry count never exceeds the configured capacity
//! (split evenly over the shards, so a shard can start evicting slightly before the whole cache is full).
//! Keys are byte strings; values live inline in the list node and are handed to callbacks by reference
//! while the shard lock is held.
//!
//! Each shard keeps two recency lists: entries the pin hook protects (an
//! active lockout or block) and all others. A full shard evicts the least
//! recently used unprotected entry; a protected one goes only when the shard
//! holds nothing else, so a spray of fresh keys — or of decoy lockouts next to
//! plain keys — cannot push an active lockout out.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

/// Bounds lock contention; small caches use fewer shards so the capacity
/// split stays exact.
const SHARD_COUNT_LIMIT: usize = 16;

/// How many protected-list tail entries an eviction inspects for one whose
/// protection has lapsed before evicting a protected entry.
const PINNED_SCAN_DEPTH: usize = 8;

const NIL: usize = usize::MAX;

struct Node<V> {
    key: Box<[u8]>,
    value: V,
    prev: usize,
    next: usize,
    /// On the protected list.
    pinned: bool,
}

#[derive(Clone, Copy)]
struct List {
    head: usize, // most recently used
    tail: usize,
}

const EMPTY: List = List {
    head: NIL,
    tail: NIL,
};

struct Shard<V> {
    index: HashMap<Box<[u8]>, usize>,
    slab: Vec<Option<Node<V>>>,
    free: Vec<usize>,
    lists: [List; 2], // [0] unprotected, [1] protected
    capacity: usize,
}

type PinHook<V> = Box<dyn Fn(&V) -> bool + Send + Sync>;
type EvictHook = Box<dyn Fn(bool) + Send + Sync>;

/// Sharded LRU map.
pub struct Cache<V> {
    seed: RandomState,
    shards: Vec<Mutex<Shard<V>>>,
    capacity: usize,
    evictions: AtomicU64,
    /// Marks entries eviction spares while any unprotected entry is left in
    /// the shard (e.g. an active lockout). Re-evaluated after every
    /// update/get callback. Called with the shard lock held.
    pin_hook: Option<PinHook<V>>,
    /// Called once per capacity eviction; `protected` reports that a
    /// still-protected entry had to go. Called with the shard lock held.
    evict_hook: Option<EvictHook>,
}

impl<V: Default> Cache<V> {
    /// A cache holding at most `capacity` entries (capacity < 1 is treated as 1).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let n = SHARD_COUNT_LIMIT.min(capacity);
        let shards = (0..n)
            .map(|i| {
                let mut sc = capacity / n;
                if i < capacity % n {
                    sc += 1;
                }
                Mutex::new(Shard::new(sc))
            })
            .collect();
        Self::from_shards(shards, capacity)
    }

    fn from_shards(shards: Vec<Mutex<Shard<V>>>, capacity: usize) -> Self {
        Cache {
            seed: RandomState::new(),
            shards,
            capacity,
            evictions: AtomicU64::new(0),
            pin_hook: None,
            evict_hook: None,
        }
    }

    /// Sets the pin hook. Set before sharing the cache.
    pub fn set_pin_hook(&mut self, f: impl Fn(&V) -> bool + Send + Sync + 'static) {
        self.pin_hook = Some(Box::new(f));
    }

    /// Sets the evict hook. Keep it to an atomic add.
    pub fn set_evict_hook(&mut self, f: impl Fn(bool) + Send + Sync + 'static) {
        self.evict_hook = Some(Box::new(f));
    }

    /// The configured entry cap.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Entries removed to make room (capacity evictions only; remove and
    /// remove_matching removals are not counted).
    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    fn select_shard(&self, key: &[u8]) -> &Mutex<Shard<V>> {
        if self.shards.len() == 1 {
            return &self.shards[0];
        }
        let h = self.seed.hash_one(key);
        &self.shards[(h % self.shards.len() as u64) as usize]
    }

    fn is_pinned(&self, v: &V) -> bool {
        self.pin_hook.as_ref().is_some_and(|f| f(v))
    }

    /// Runs `f` on the entry for `key`, creating a default value when absent
    /// (`created` = true), and marks it most recently used. `f` runs under the
    /// shard lock and must not call back into the cache.
    pub fn update(&self, key: &[u8], f: impl FnOnce(&mut V, bool)) {
        let mut s = self
            .select_shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(&i) = s.index.get(key) {
            f(&mut s.node_mut(i).value, false);
            self.touch(&mut s, i);
            return;
        }
        if s.index.len() >= s.capacity {
            let protected = self.evict_victim(&mut s);
            self.evictions.fetch_add(1, Ordering::Relaxed);
            if let Some(cb) = &self.evict_hook {
                cb(protected);
            }
        }
        let mut val = V::default();
        f(&mut val, true);
        let pinned = self.is_pinned(&val);
        let key: Box<[u8]> = key.into();
        let i = s.alloc(Node {
            key: key.clone(),
            value: val,
            prev: NIL,
            next: NIL,
            pinned,
        });
        s.index.insert(key, i);
        s.push_front(i);
    }

    /// Runs `f` on the entry for `key` when present (marking it most recently
    /// used) and reports whether it was. `f` runs under the shard lock.
    pub fn get(&self, key: &[u8], f: Option<&mut dyn FnMut(&mut V)>) -> bool {
        let mut s = self
            .select_shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(&i) = s.index.get(key) else {
            return false;
        };
        if let Some(f) = f {
            f(&mut s.node_mut(i).value);
        }
        self.touch(&mut s, i);
        true
    }

    /// Removes `key`.
    pub fn remove(&self, key: &[u8]) {
        let mut s = self
            .select_shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(i) = s.index.remove(key) {
            s.unlink(i);
            s.release(i);
        }
    }

    /// Removes every entry for which `del` returns true and returns how many
    /// were removed. Walks each shard under its lock (O(n); meant for the
    /// periodic cleaner and operator actions, not the request path).
    pub fn remove_matching(&self, mut del: impl FnMut(&[u8], &mut V) -> bool) -> usize {
        let mut removed = 0;
        for sh in &self.shards {
            let mut s = sh.lock().unwrap_or_else(|e| e.into_inner());
            let idx: Vec<usize> = s.index.values().copied().collect();
            for i in idx {
                let n = s.node_mut(i);
                let (key, val) = (&n.key, &mut n.value);
                if del(key, val) {
                    let key = n.key.clone();
                    s.unlink(i);
                    s.index.remove(&key);
                    s.release(i);
                    removed += 1;
                }
            }
        }
        removed
    }

    /// The current entry count.
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).index.len())
            .sum()
    }

    /// Reports whether the cache holds no entry.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Moves node `i` to the front of the list its current protection selects.
    fn touch(&self, s: &mut Shard<V>, i: usize) {
        s.unlink(i);
        let pinned = self.is_pinned(&s.node(i).value);
        s.node_mut(i).pinned = pinned;
        s.push_front(i);
    }

    /// Removes one entry from a full shard: the unprotected LRU entry, else a
    /// protected-list entry whose protection has lapsed (within PINNED_SCAN_DEPTH of
    /// the tail), else the protected LRU entry. Reports whether a
    /// still-protected entry was evicted.
    fn evict_victim(&self, s: &mut Shard<V>) -> bool {
        let mut victim = s.lists[0].tail;
        let mut protected = false;
        if victim == NIL {
            victim = s.lists[1].tail;
            protected = true;
            let (mut n, mut k) = (s.lists[1].tail, 0);
            while n != NIL && k < PINNED_SCAN_DEPTH {
                if !self.is_pinned(&s.node(n).value) {
                    victim = n;
                    protected = false;
                    break;
                }
                n = s.node(n).prev;
                k += 1;
            }
        }
        if victim == NIL {
            return false;
        }
        s.unlink(victim);
        let key = s.node(victim).key.clone();
        s.index.remove(&key);
        s.release(victim);
        protected
    }
}

impl<V> Shard<V> {
    fn new(capacity: usize) -> Self {
        Shard {
            index: HashMap::new(),
            slab: Vec::new(),
            free: Vec::new(),
            lists: [EMPTY; 2],
            capacity,
        }
    }

    fn node(&self, i: usize) -> &Node<V> {
        self.slab[i].as_ref().expect("live lru node")
    }

    fn node_mut(&mut self, i: usize) -> &mut Node<V> {
        self.slab[i].as_mut().expect("live lru node")
    }

    fn alloc(&mut self, n: Node<V>) -> usize {
        if let Some(i) = self.free.pop() {
            self.slab[i] = Some(n);
            i
        } else {
            self.slab.push(Some(n));
            self.slab.len() - 1
        }
    }

    fn release(&mut self, i: usize) {
        self.slab[i] = None;
        self.free.push(i);
    }

    fn list_of(&self, i: usize) -> usize {
        usize::from(self.node(i).pinned)
    }

    fn push_front(&mut self, i: usize) {
        let l = self.list_of(i);
        let head = self.lists[l].head;
        {
            let n = self.node_mut(i);
            n.prev = NIL;
            n.next = head;
        }
        if head != NIL {
            self.node_mut(head).prev = i;
        }
        self.lists[l].head = i;
        if self.lists[l].tail == NIL {
            self.lists[l].tail = i;
        }
    }

    fn unlink(&mut self, i: usize) {
        let l = self.list_of(i);
        let (prev, next) = {
            let n = self.node(i);
            (n.prev, n.next)
        };
        if prev != NIL {
            self.node_mut(prev).next = next;
        } else if self.lists[l].head == i {
            self.lists[l].head = next;
        }
        if next != NIL {
            self.node_mut(next).prev = prev;
        } else if self.lists[l].tail == i {
            self.lists[l].tail = prev;
        }
        let n = self.node_mut(i);
        n.prev = NIL;
        n.next = NIL;
    }
}

/// The longest key kept verbatim by [`shorten_key`].
pub const MAX_VERBATIM_KEY_LEN: usize = 128;

/// Marks a [`shorten_key`] digest. A raw key starting with it is hashed too,
/// so a verbatim key can never equal another key's digest.
const DIGEST_KEY_PREFIX: &[u8] = b"\x01sha256:";

/// Returns `s` unchanged when it is at most MAX_VERBATIM_KEY_LEN bytes, else a
/// fixed-size SHA-256 digest of it, so attacker-sized keys (user agents,
/// header values, URIs) cost bounded memory per entry.
pub fn shorten_key(s: &[u8]) -> Vec<u8> {
    if s.len() <= MAX_VERBATIM_KEY_LEN && !s.starts_with(DIGEST_KEY_PREFIX) {
        return s.to_vec();
    }
    let sum = Sha256::digest(s);
    let mut out = Vec::with_capacity(DIGEST_KEY_PREFIX.len() + 64);
    out.extend_from_slice(DIGEST_KEY_PREFIX);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in sum {
        out.push(HEX[usize::from(b >> 4)]);
        out.push(HEX[usize::from(b & 15)]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn one_shard<V: Default>(capacity: usize) -> Cache<V> {
        // new(3) would make 3 one-entry shards; order checks need one shard.
        Cache::from_shards(vec![Mutex::new(Shard::new(capacity))], capacity)
    }

    #[test]
    fn cache_capacity_and_lru_order() {
        let c = one_shard::<i32>(3);
        for k in ["a", "b", "c"] {
            c.update(k.as_bytes(), |v, created| {
                assert!(created, "{k}: want created");
                *v = 1;
            });
        }
        c.get(b"a", None); // a is now most recently used; b is the LRU entry
        c.update(b"d", |_, _| {});
        assert!(
            !c.get(b"b", None),
            "least recently used entry b must be evicted"
        );
        for k in ["a", "c", "d"] {
            assert!(c.get(k.as_bytes(), None), "{k} evicted too early");
        }
        assert_eq!((c.len(), c.evictions()), (3, 1));
    }

    #[test]
    fn cache_pinned_passed_over() {
        let mut c = one_shard::<bool>(2);
        c.set_pin_hook(|v| *v);
        c.update(b"locked", |v, _| *v = true);
        c.update(b"idle", |_, _| {});
        c.update(b"new", |_, _| {});
        assert!(
            c.get(b"locked", None) && !c.get(b"idle", None),
            "a pinned tail entry must be passed over for an unpinned one"
        );
        // All pinned: the tail goes anyway, the cap holds.
        c.update(b"new", |v, _| *v = true);
        c.update(b"third", |_, _| {});
        assert_eq!(
            c.len(),
            2,
            "cap 2 must hold even when every entry is pinned"
        );
    }

    #[test]
    fn cache_cap_holds_under_many_keys() {
        let n: usize = if cfg!(debug_assertions) {
            100_000
        } else {
            1_000_000
        };
        const CAPACITY: usize = 1000;
        let c = Arc::new(Cache::<i32>::new(CAPACITY));
        let workers: Vec<_> = (0..4)
            .map(|w| {
                let c = Arc::clone(&c);
                std::thread::spawn(move || {
                    let mut i = w;
                    while i < n {
                        c.update(i.to_string().as_bytes(), |v, _| *v += 1);
                        i += 4;
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        assert_eq!(c.len(), CAPACITY);
        assert_eq!(c.evictions(), (n - CAPACITY) as u64);
    }

    #[test]
    fn cache_remove_matching() {
        let c = Cache::<i32>::new(10_000); // per-shard caps: keep far above the key count
        for i in 0..50 {
            c.update(format!("k{i}").as_bytes(), |v, _| *v = i);
        }
        assert_eq!(c.remove_matching(|_, v| *v % 2 == 0), 25);
        assert_eq!((c.len(), c.evictions()), (25, 0));
        c.remove(b"k1");
        assert!(!c.get(b"k1", None), "deleted key still present");
    }

    #[test]
    fn cache_on_evict_reports_protected() {
        let hits = Arc::new(AtomicU64::new(0));
        let mut c = one_shard::<bool>(1);
        c.set_pin_hook(|v| *v);
        let h = Arc::clone(&hits);
        c.set_evict_hook(move |protected| {
            if protected {
                h.fetch_add(1, Ordering::Relaxed);
            }
        });
        c.update(b"a", |v, _| *v = true);
        c.update(b"b", |_, _| {});
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        assert!(c.get(b"b", None));
    }

    #[test]
    fn shorten_key_rules() {
        let short = vec![b'a'; MAX_VERBATIM_KEY_LEN];
        assert_eq!(
            shorten_key(&short),
            short,
            "a key of MAX_KEY_LEN bytes must be kept verbatim"
        );
        let long = vec![b'a'; 64 * 1024];
        let h = shorten_key(&long);
        let mut longer = long.clone();
        longer.push(b'b');
        assert!(
            h.len() <= MAX_VERBATIM_KEY_LEN && h == shorten_key(&long) && h != shorten_key(&longer)
        );
        assert_ne!(
            shorten_key(&h),
            h,
            "a raw key shaped like a digest must be hashed"
        );
        // Digest text is "\x01sha256:" + 64 lowercase hex digits.
        assert_eq!(h.len(), DIGEST_KEY_PREFIX.len() + 64);
        assert!(
            h[DIGEST_KEY_PREFIX.len()..]
                .iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        );
    }
}
