//! A segmented LRU over keys that have a size in bytes. A new key enters the probation segment;
//! a key that is touched again moves to the protected segment, which may hold four fifths of the
//! capacity and gives its oldest key back to probation when it grows past that. The victim is the
//! oldest key of probation, so a crawl that touches every key once only cycles probation and the
//! keys that were asked for twice stay.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

#[derive(Clone, Copy)]
struct Item {
    size: u64,
    tick: u64,
    protected: bool,
}

pub(crate) struct Slru<K: Copy + Eq + Hash> {
    items: HashMap<K, Item>,
    probation: BTreeMap<u64, K>,
    protected: BTreeMap<u64, K>,
    tick: u64,
    bytes: u64,
    protected_bytes: u64,
}

impl<K: Copy + Eq + Hash> Default for Slru<K> {
    fn default() -> Self {
        Slru {
            items: HashMap::new(),
            probation: BTreeMap::new(),
            protected: BTreeMap::new(),
            tick: 0,
            bytes: 0,
            protected_bytes: 0,
        }
    }
}

impl<K: Copy + Eq + Hash> Slru<K> {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// The sum of the sizes of the keys held.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    #[cfg(test)]
    pub fn contains(&self, key: &K) -> bool {
        self.items.contains_key(key)
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Puts `key` in probation as the newest, replacing a key of the same name (whichever segment
    /// it was in).
    pub fn insert(&mut self, key: K, size: u64) {
        self.remove(&key);
        let tick = self.next_tick();
        self.probation.insert(tick, key);
        self.items.insert(
            key,
            Item {
                size,
                tick,
                protected: false,
            },
        );
        self.bytes += size;
    }

    /// A touch of `key`. A key in probation moves to protected when `promote` is set, else it
    /// becomes the newest of probation; a protected key becomes the newest of protected. `cap` is
    /// the capacity the protected segment is a share of. Returns false for a key not held.
    pub fn touch(&mut self, key: &K, promote: bool, cap: u64) -> bool {
        let Some(item) = self.items.get(key).copied() else {
            return false;
        };
        let tick = self.next_tick();
        let protected = if item.protected {
            self.protected.remove(&item.tick);
            self.protected.insert(tick, *key);
            true
        } else if promote {
            self.probation.remove(&item.tick);
            self.protected.insert(tick, *key);
            self.protected_bytes += item.size;
            true
        } else {
            self.probation.remove(&item.tick);
            self.probation.insert(tick, *key);
            false
        };
        self.items.insert(
            *key,
            Item {
                tick,
                protected,
                ..item
            },
        );
        self.demote(cap);
        true
    }

    /// Gives the oldest protected keys back to probation while the segment holds more than four
    /// fifths of `cap`.
    fn demote(&mut self, cap: u64) {
        let room = cap - cap / 5;
        while self.protected_bytes > room {
            // A key that fills the whole segment alone goes too, so the loop ends.
            let Some((_, key)) = self.protected.pop_first() else {
                break;
            };
            let tick = self.next_tick();
            let item = self.items.get_mut(&key).expect("a protected key is held");
            item.protected = false;
            item.tick = tick;
            self.protected_bytes -= item.size;
            self.probation.insert(tick, key);
        }
    }

    pub fn remove(&mut self, key: &K) -> Option<u64> {
        let item = self.items.remove(key)?;
        if item.protected {
            self.protected.remove(&item.tick);
            self.protected_bytes -= item.size;
        } else {
            self.probation.remove(&item.tick);
        }
        self.bytes -= item.size;
        Some(item.size)
    }

    /// The key to evict first: the oldest of probation, else the oldest of protected.
    pub fn victim(&self) -> Option<K> {
        self.probation
            .first_key_value()
            .or_else(|| self.protected.first_key_value())
            .map(|(_, key)| *key)
    }

    /// Every key held, oldest first within each segment (probation first).
    #[cfg(test)]
    pub fn order(&self) -> Vec<K> {
        self.probation
            .values()
            .chain(self.protected.values())
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_crawl_cycles_probation_and_leaves_the_keys_asked_for_twice() {
        let mut s = Slru::<u32>::default();
        let cap = 10;
        for k in 0..4 {
            s.insert(k, 1);
        }
        // 0 and 1 are asked for again: they are protected.
        s.touch(&0, true, cap);
        s.touch(&1, true, cap);
        // A crawl of new keys: each insert evicts the victim to stay within the capacity.
        for k in 100..140 {
            s.insert(k, 1);
            while s.bytes() > cap {
                let v = s.victim().unwrap();
                s.remove(&v);
            }
        }
        assert!(s.contains(&0) && s.contains(&1), "protected survive");
        assert!(!s.contains(&2) && !s.contains(&3), "probation was cycled");
        assert_eq!(s.bytes(), cap);
    }

    #[test]
    fn the_victim_is_the_oldest_of_probation_then_the_oldest_of_protected() {
        let mut s = Slru::<u32>::default();
        s.insert(1, 1);
        s.insert(2, 1);
        s.insert(3, 1);
        s.touch(&2, true, 100);
        assert_eq!(s.victim(), Some(1));
        // A touch that does not promote makes the key the newest of probation.
        s.touch(&1, false, 100);
        assert_eq!(s.victim(), Some(3));
        s.remove(&3);
        s.remove(&1);
        assert_eq!(s.victim(), Some(2), "only protected is left");
        s.remove(&2);
        assert_eq!(s.victim(), None);
        assert_eq!((s.len(), s.bytes()), (0, 0));
    }

    #[test]
    fn protected_holds_four_fifths_and_gives_its_oldest_back() {
        let mut s = Slru::<u32>::default();
        let cap = 10;
        for k in 0..10 {
            s.insert(k, 1);
        }
        for k in 0..10 {
            s.touch(&k, true, cap);
        }
        // Eight bytes protected, the two oldest back in probation.
        assert_eq!(s.order()[..2], [0, 1]);
        assert_eq!(s.victim(), Some(0));
        assert_eq!(s.order().len(), 10);
        s.touch(&5, true, cap);
        assert_eq!(s.order().len(), 10, "no key is lost");
    }

    #[test]
    fn inserting_a_key_again_replaces_it_and_its_size() {
        let mut s = Slru::<u32>::default();
        s.insert(1, 5);
        s.touch(&1, true, 100);
        s.insert(1, 7);
        assert_eq!((s.len(), s.bytes()), (1, 7));
        assert_eq!(s.victim(), Some(1));
        assert_eq!(s.remove(&1), Some(7));
        assert_eq!(s.remove(&1), None);
        assert!(!s.touch(&1, true, 100));
    }

    #[test]
    fn a_key_bigger_than_the_protected_share_does_not_hang_the_demotion() {
        let mut s = Slru::<u32>::default();
        s.insert(1, 50);
        s.touch(&1, true, 10);
        assert_eq!(s.len(), 1);
        assert_eq!(s.victim(), Some(1));
    }
}
