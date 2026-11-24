//! The in-memory index of one app's stored answers: what is on disk (by the SHA-256 that names the
//! file), which `Vary` names each primary key leads to, the copies that are also held in memory,
//! and the two segmented LRUs (disk and memory) that decide what goes when a limit is passed.

use std::collections::HashMap;
use std::sync::Arc;

use super::format::{Loaded, Times};
use super::key::{FileId, PrimaryId};
use super::slru::Slru;

/// The most entries an app's index holds; the oldest go past it.
pub(crate) const MAX_ENTRIES: usize = 200_000;
/// The biggest copy the memory tier holds.
pub(crate) const MEMORY_COPY_MAX: u64 = 256 << 10;

pub(crate) struct Entry {
    primary: PrimaryId,
    pub size: u64,
    pub times: Times,
    pub hits: u32,
    mem: Option<Arc<Loaded>>,
}

/// A primary key: the `Vary` names its latest answer has, and the files of its variants.
struct Primary {
    names: Vec<Vec<u8>>,
    ids: Vec<FileId>,
}

/// An entry a request found.
pub(crate) struct Found {
    pub id: FileId,
    /// The whole key (primary and variant), which the file must hold.
    pub key: Vec<u8>,
    pub size: u64,
    /// The hits of the entry, this one included.
    pub hits: u32,
    pub mem: Option<Arc<Loaded>>,
}

pub(crate) struct Index {
    entries: HashMap<FileId, Entry>,
    primaries: HashMap<PrimaryId, Primary>,
    disk: Slru<FileId>,
    mem: Slru<FileId>,
    disk_limit: u64,
    mem_limit: u64,
}

impl Default for Index {
    /// No limit on disk until the settings are applied: what a scan finds stays until they are.
    fn default() -> Index {
        Index {
            entries: HashMap::new(),
            primaries: HashMap::new(),
            disk: Slru::default(),
            mem: Slru::default(),
            disk_limit: u64::MAX,
            mem_limit: 0,
        }
    }
}

impl Index {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn disk_bytes(&self) -> u64 {
        self.disk.bytes()
    }

    pub fn memory_bytes(&self) -> u64 {
        self.mem.bytes()
    }

    #[cfg(test)]
    pub fn contains(&self, id: &FileId) -> bool {
        self.entries.contains_key(id)
    }

    /// The `Vary` names of a primary key, when it has an entry.
    #[cfg(test)]
    pub fn names(&self, primary: &PrimaryId) -> Option<&[Vec<u8>]> {
        self.primaries.get(primary).map(|p| p.names.as_slice())
    }

    /// Forgets everything but the limits.
    pub fn clear(&mut self) {
        let (disk_limit, mem_limit) = (self.disk_limit, self.mem_limit);
        *self = Index {
            disk_limit,
            mem_limit,
            ..Index::default()
        };
    }

    /// Changes the limits. The files of the entries that no longer fit are returned, oldest
    /// first; a memory copy that no longer fits is just dropped.
    pub fn set_limits(&mut self, disk: u64, mem: u64) -> Vec<FileId> {
        self.disk_limit = disk;
        self.mem_limit = mem;
        self.trim_memory();
        self.trim_disk()
    }

    /// Looks the key up. `variant_of` builds the variant from the names the primary key leads to.
    /// An entry that is still fresh at `now` counts a hit and moves in the LRUs; an entry that is
    /// not is returned as it is, for the caller to treat as a miss.
    pub fn find(
        &mut self,
        primary_id: &PrimaryId,
        primary: &[u8],
        variant_of: impl FnOnce(&[Vec<u8>]) -> Vec<u8>,
        now: u64,
    ) -> Option<(Found, bool)> {
        let names = &self.primaries.get(primary_id)?.names;
        let mut key = primary.to_vec();
        key.extend_from_slice(&variant_of(names));
        let id = super::key::file_id(&key, b"");
        let entry = self.entries.get_mut(&id)?;
        let fresh = now < entry.times.fresh_until;
        if fresh {
            entry.hits = entry.hits.saturating_add(1);
            let promote = entry.hits >= 2;
            let in_memory = entry.mem.is_some();
            self.disk.touch(&id, promote, self.disk_limit);
            if in_memory {
                self.mem.touch(&id, true, self.mem_limit);
            }
        }
        let entry = &self.entries[&id];
        Some((
            Found {
                id,
                key,
                size: entry.size,
                hits: entry.hits,
                mem: entry.mem.clone(),
            },
            fresh,
        ))
    }

    /// Adds the file of `id`, which holds the answer with these `names` to the primary key. A
    /// primary key whose answer now varies by other names loses its other files, which no request
    /// can reach any more. The files to delete are returned: those, and the entries pushed out by
    /// the limits (the new entry may be one when it alone does not fit).
    pub fn insert(
        &mut self,
        id: FileId,
        primary: PrimaryId,
        names: Vec<Vec<u8>>,
        size: u64,
        times: Times,
    ) -> Vec<FileId> {
        let mut gone = Vec::new();
        self.remove(&id);
        if self
            .primaries
            .get(&primary)
            .is_some_and(|p| p.names != names)
        {
            for old in self
                .primaries
                .remove(&primary)
                .map(|p| p.ids)
                .unwrap_or_default()
            {
                if self.remove_entry(&old) {
                    gone.push(old);
                }
            }
        }
        self.primaries
            .entry(primary)
            .or_insert_with(|| Primary {
                names,
                ids: Vec::new(),
            })
            .ids
            .push(id);
        self.entries.insert(
            id,
            Entry {
                primary,
                size,
                times,
                hits: 0,
                mem: None,
            },
        );
        self.disk.insert(id, size);
        gone.extend(self.trim_disk());
        gone
    }

    /// Deletes entries, the victim of the disk LRU first, until both limits hold. The entry just
    /// stored is the newest of probation, so it goes only when nothing in probation is older: a
    /// copy bigger than what the protected segment leaves does not push the protected copies out.
    fn trim_disk(&mut self) -> Vec<FileId> {
        let mut gone = Vec::new();
        while self.disk.bytes() > self.disk_limit || self.entries.len() > MAX_ENTRIES {
            let Some(victim) = self.disk.victim() else {
                break;
            };
            self.remove(&victim);
            gone.push(victim);
        }
        gone
    }

    fn trim_memory(&mut self) {
        while self.mem.bytes() > self.mem_limit {
            let Some(victim) = self.mem.victim() else {
                break;
            };
            self.mem.remove(&victim);
            if let Some(e) = self.entries.get_mut(&victim) {
                e.mem = None;
            }
        }
    }

    /// Removes the entry of `id` and the memory copy of it. Returns whether there was one.
    pub fn remove(&mut self, id: &FileId) -> bool {
        let Some(primary) = self.entries.get(id).map(|e| e.primary) else {
            return false;
        };
        if let Some(p) = self.primaries.get_mut(&primary) {
            p.ids.retain(|i| i != id);
            if p.ids.is_empty() {
                self.primaries.remove(&primary);
            }
        }
        self.remove_entry(id)
    }

    /// The entry and its place in both LRUs, not its primary key.
    fn remove_entry(&mut self, id: &FileId) -> bool {
        self.mem.remove(id);
        self.disk.remove(id);
        self.entries.remove(id).is_some()
    }

    /// Removes every entry of these primary keys (every variant of a URL in a bucket). Returns the
    /// files.
    pub fn drop_primaries(&mut self, primaries: &[PrimaryId]) -> Vec<FileId> {
        let mut gone = Vec::new();
        for primary in primaries {
            for id in self
                .primaries
                .remove(primary)
                .map(|p| p.ids)
                .unwrap_or_default()
            {
                if self.remove_entry(&id) {
                    gone.push(id);
                }
            }
        }
        gone
    }

    /// Gives the entry of `id` a copy in memory, when it is still the file that was read, the copy
    /// is small enough and memory has room; what that pushes out loses its copy.
    pub fn admit_memory(&mut self, id: &FileId, loaded: Arc<Loaded>) {
        let Some(entry) = self.entries.get_mut(id) else {
            return;
        };
        if self.mem_limit == 0
            || loaded.size > MEMORY_COPY_MAX
            || loaded.size > self.mem_limit
            || loaded.times != entry.times
            || loaded.size != entry.size
        {
            return;
        }
        entry.mem = Some(loaded);
        let size = entry.size;
        self.mem.insert(*id, size);
        self.trim_memory();
    }

    /// The entries that are past their lifetime and the window their answer allows beyond it
    /// (`window_for` gives the larger of that and the app's own setting).
    pub fn past_window(&self, now: u64, setting_s: u64) -> Vec<FileId> {
        self.entries
            .iter()
            .filter(|(_, e)| {
                let window = u64::from(e.times.stale_window).max(setting_s);
                now >= e.times.fresh_until.saturating_add(window)
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Whether the entry of `id` holds a memory copy.
    #[cfg(test)]
    pub fn in_memory(&self, id: &FileId) -> bool {
        self.entries.get(id).is_some_and(|e| e.mem.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::format::StoredHead;
    use crate::cache::key::{file_id, primary_id};

    const T: Times = Times {
        stored_at: 100,
        fresh_until: 200,
        initial_age: 0,
        stale_window: 0,
    };

    fn id(n: u32) -> FileId {
        file_id(&n.to_le_bytes(), b"")
    }

    fn primary(n: u32) -> PrimaryId {
        primary_id(&n.to_le_bytes())
    }

    fn loaded(size: u64) -> Arc<Loaded> {
        Arc::new(Loaded {
            times: T,
            head: StoredHead::default(),
            body: Vec::new(),
            size,
        })
    }

    /// An entry of `size` bytes of its own primary key, whose key is the 4 bytes of `n`.
    fn put(ix: &mut Index, n: u32, size: u64) -> Vec<FileId> {
        ix.insert(id(n), primary(n), Vec::new(), size, T)
    }

    #[test]
    fn an_entry_is_found_by_its_key_and_counts_its_hits_while_fresh() {
        let mut ix = Index::default();
        put(&mut ix, 1, 10);
        let key = |_: &[Vec<u8>]| Vec::new();
        // The key of the entry is the primary bytes; here the primary bytes are the 4 bytes of 1.
        let (found, fresh) = ix.find(&primary(1), &1u32.to_le_bytes(), key, 150).unwrap();
        assert!(fresh);
        assert_eq!((found.id, found.hits, found.size), (id(1), 1, 10));
        let (found, _) = ix.find(&primary(1), &1u32.to_le_bytes(), key, 199).unwrap();
        assert_eq!(found.hits, 2);
        // Past its lifetime it is returned as not fresh and no hit is counted.
        let (found, fresh) = ix.find(&primary(1), &1u32.to_le_bytes(), key, 200).unwrap();
        assert!(!fresh);
        assert_eq!(found.hits, 2);
        assert!(
            ix.find(&primary(2), &2u32.to_le_bytes(), key, 150)
                .is_none()
        );
    }

    #[test]
    fn the_variant_is_built_from_the_names_of_the_answer_and_picks_the_file() {
        let mut ix = Index::default();
        let names = vec![b"accept-language".to_vec()];
        let p = primary(9);
        let key_for = |lang: &str| {
            let mut k = 9u32.to_le_bytes().to_vec();
            k.extend_from_slice(lang.as_bytes());
            k
        };
        for lang in ["id", "en"] {
            let k = key_for(lang);
            ix.insert(file_id(&k, b""), p, names.clone(), 5, T);
        }
        assert_eq!(ix.len(), 2);
        let ask = |ix: &mut Index, lang: &'static str| {
            ix.find(
                &p,
                &9u32.to_le_bytes(),
                |n| {
                    assert_eq!(n, names.as_slice());
                    lang.as_bytes().to_vec()
                },
                150,
            )
        };
        assert_eq!(
            ask(&mut ix, "id").unwrap().0.id,
            file_id(&key_for("id"), b"")
        );
        assert_eq!(
            ask(&mut ix, "en").unwrap().0.id,
            file_id(&key_for("en"), b"")
        );
        assert!(ask(&mut ix, "fr").is_none());
        // The answer now varies by other names: the old variants are unreachable and go.
        let k = key_for("x");
        let gone = ix.insert(file_id(&k, b""), p, vec![b"user-agent".to_vec()], 5, T);
        assert_eq!(gone.len(), 2);
        assert_eq!(ix.len(), 1);
        assert_eq!(ix.names(&p), Some(&[b"user-agent".to_vec()][..]));
    }

    #[test]
    fn a_crawl_of_unique_urls_stays_within_the_limit_and_keeps_what_was_asked_twice() {
        let mut ix = Index::default();
        ix.set_limits(100, 0);
        for n in 0..5 {
            put(&mut ix, n, 10);
        }
        for n in 0..2 {
            for _ in 0..2 {
                ix.find(&primary(n), &n.to_le_bytes(), |_| Vec::new(), 150);
            }
        }
        let mut deleted = 0;
        for n in 100..1100 {
            deleted += put(&mut ix, n, 10).len();
            assert!(ix.disk_bytes() <= 100, "within the limit after each store");
        }
        assert!(
            ix.contains(&id(0)) && ix.contains(&id(1)),
            "asked twice: kept"
        );
        assert!(!ix.contains(&id(2)), "asked never: cycled out");
        assert!(
            deleted >= 1000 - 5,
            "every eviction is returned for its file"
        );
        // No entry holds a primary key that has no entry.
        assert_eq!(ix.primaries.len(), ix.len());
    }

    #[test]
    fn the_entry_just_stored_is_not_the_one_evicted_while_older_ones_can_go() {
        let mut ix = Index::default();
        ix.set_limits(25, 0);
        put(&mut ix, 1, 10);
        put(&mut ix, 2, 10);
        let gone = put(&mut ix, 3, 10);
        assert_eq!(gone, vec![id(1)]);
        assert!(ix.contains(&id(3)));
        // One that alone is bigger than the limit is not kept.
        let gone = put(&mut ix, 4, 30);
        assert!(gone.contains(&id(4)), "{gone:?}");
        assert!(!ix.contains(&id(4)));
        assert!(ix.disk_bytes() <= 25);
    }

    #[test]
    fn lowering_the_limits_returns_the_files_to_delete_and_drops_memory_copies() {
        let mut ix = Index::default();
        ix.set_limits(1000, 1000);
        for n in 0..4 {
            put(&mut ix, n, 100);
        }
        ix.admit_memory(&id(0), loaded(100));
        assert!(ix.in_memory(&id(0)));
        let gone = ix.set_limits(250, 50);
        assert_eq!(gone.len(), 2);
        assert!(!ix.in_memory(&id(0)), "a copy that does not fit is dropped");
        assert_eq!(ix.memory_bytes(), 0);
        assert!(ix.disk_bytes() <= 250);
    }

    #[test]
    fn the_memory_tier_takes_small_copies_that_still_match_and_evicts_the_oldest() {
        let mut ix = Index::default();
        ix.set_limits(u64::MAX, 300);
        for n in 0..4 {
            put(&mut ix, n, 100);
        }
        for n in 0..4 {
            ix.admit_memory(&id(n), loaded(100));
        }
        assert_eq!(ix.memory_bytes(), 300);
        assert!(!ix.in_memory(&id(0)) && ix.in_memory(&id(3)));
        // Too big for the tier, a size that no longer matches, and a file that is gone.
        put(&mut ix, 10, MEMORY_COPY_MAX + 1);
        ix.admit_memory(&id(10), loaded(MEMORY_COPY_MAX + 1));
        assert!(!ix.in_memory(&id(10)));
        ix.admit_memory(&id(1), loaded(99));
        ix.admit_memory(&id(77), loaded(10));
        assert_eq!(ix.memory_bytes(), 300);
        // Memory 0 holds nothing.
        ix.set_limits(u64::MAX, 0);
        ix.admit_memory(&id(2), loaded(100));
        assert_eq!(ix.memory_bytes(), 0);
    }

    #[test]
    fn dropping_a_primary_removes_every_variant_in_both_tiers() {
        let mut ix = Index::default();
        ix.set_limits(u64::MAX, 1000);
        let p = primary(5);
        let (a, b) = (id(50), id(51));
        ix.insert(a, p, vec![b"accept".to_vec()], 10, T);
        ix.insert(b, p, vec![b"accept".to_vec()], 10, T);
        ix.admit_memory(&a, loaded(10));
        put(&mut ix, 6, 10);
        let mut gone = ix.drop_primaries(&[p]);
        gone.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(gone, want);
        assert_eq!((ix.len(), ix.memory_bytes(), ix.disk_bytes()), (1, 0, 10));
        assert!(ix.names(&p).is_none());
        assert!(ix.drop_primaries(&[p]).is_empty());
    }

    #[test]
    fn at_most_two_hundred_thousand_entries_the_oldest_go_first() {
        let mut ix = Index::default();
        for n in 0..(MAX_ENTRIES as u32 + 3) {
            put(&mut ix, n, 1);
        }
        assert_eq!(ix.len(), MAX_ENTRIES);
        assert!(!ix.contains(&id(0)) && !ix.contains(&id(2)));
        assert!(ix.contains(&id(3)));
    }

    #[test]
    fn what_is_past_its_window_is_found_by_the_larger_of_the_two_windows() {
        let mut ix = Index::default();
        let own = Times {
            stale_window: 50,
            ..T
        };
        ix.insert(id(1), primary(1), Vec::new(), 1, T);
        ix.insert(id(2), primary(2), Vec::new(), 1, own);
        // fresh_until is 200: with a setting of 10 the first is past at 210, the second at 250.
        assert!(ix.past_window(209, 10).is_empty());
        assert_eq!(ix.past_window(210, 10), vec![id(1)]);
        let mut both = ix.past_window(250, 10);
        both.sort();
        let mut want = vec![id(1), id(2)];
        want.sort();
        assert_eq!(both, want);
        ix.clear();
        assert_eq!(ix.len(), 0);
    }
}
