//! Scan configurations that the library holds, by handle. A configuration is handed over once and then named by its
//! handle; this module decides whether a `SemanticConfig` of a request has been handed over already.
//!
//! The agent builds a configuration for each request (the application's, with the path override and the tuning skips
//! applied), so identity cannot be a pointer: it is the row of words of `wafio_engine_abi::config`, which is also what
//! the library receives. A thread keeps the last few rows it used and finds its handle there without a lock; the rest
//! sit in a table shared by all threads, which holds at most [`SHARED_CAPACITY`] and drops the oldest first. A handle is
//! freed when the last holder lets go, so a thread that still uses an evicted one is safe.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};

use wafio_engine_abi::FreeHandleFn;
use wafio_engine_abi::config::Words;
use wafio_engine_api::SsrfConfig;

/// Rows per thread. A power of two: the slot is the low bits of the hash.
const SLOTS: usize = 8;
/// Rows in the shared table.
pub const SHARED_CAPACITY: usize = 256;

/// An SSRF list in the library. It keeps the agent's list alive so that the address the row names is not reused.
pub struct SsrfHandle {
    pub handle: u64,
    pub free: FreeHandleFn,
    pub _keep: Arc<SsrfConfig>,
}

impl Drop for SsrfHandle {
    fn drop(&mut self) {
        // SAFETY: `handle` came from `wafio_engine_ssrf_new` of this library and is freed once, here.
        unsafe { (self.free)(self.handle) }
    }
}

/// A configuration in the library.
pub struct Entry {
    pub handle: u64,
    free: FreeHandleFn,
    _ssrf: Option<Arc<SsrfHandle>>,
}

impl Entry {
    pub fn new(handle: u64, free: FreeHandleFn, ssrf: Option<Arc<SsrfHandle>>) -> Entry {
        Entry {
            handle,
            free,
            _ssrf: ssrf,
        }
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        // SAFETY: `handle` came from `wafio_engine_config_new` of this library and is freed once, here.
        unsafe { (self.free)(self.handle) }
    }
}

/// The table shared by the threads, and the registry of SSRF lists.
#[derive(Default)]
pub struct Shared {
    rows: Mutex<Rows>,
    ssrf: Mutex<HashMap<usize, Weak<SsrfHandle>>>,
}

#[derive(Default)]
struct Rows {
    by_row: HashMap<Words, Arc<Entry>>,
    oldest_first: VecDeque<Words>,
}

impl Shared {
    pub fn get(&self, row: &Words) -> Option<Arc<Entry>> {
        self.rows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .by_row
            .get(row)
            .cloned()
    }

    pub fn insert(&self, row: Words, entry: Arc<Entry>) -> Arc<Entry> {
        let mut rows = self.rows.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(have) = rows.by_row.get(&row) {
            return have.clone();
        }
        rows.oldest_first.push_back(row);
        rows.by_row.insert(row, entry.clone());
        while rows.oldest_first.len() > SHARED_CAPACITY {
            if let Some(old) = rows.oldest_first.pop_front() {
                rows.by_row.remove(&old);
            }
        }
        entry
    }

    pub fn ssrf(&self, key: usize) -> Option<Arc<SsrfHandle>> {
        self.ssrf
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)?
            .upgrade()
    }

    pub fn insert_ssrf(&self, key: usize, handle: Arc<SsrfHandle>) -> Arc<SsrfHandle> {
        let mut m = self.ssrf.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(have) = m.get(&key).and_then(Weak::upgrade) {
            return have;
        }
        m.retain(|_, w| w.strong_count() > 0);
        m.insert(key, Arc::downgrade(&handle));
        handle
    }
}

struct Slot {
    owner: usize,
    row: Words,
    entry: Arc<Entry>,
}

thread_local! {
    static LOCAL: RefCell<[Option<Slot>; SLOTS]> = const { RefCell::new([const { None }; SLOTS]) };
}

/// A fast hash of a row: it only picks the slot, equality of the row decides.
fn slot_of(row: &Words) -> usize {
    let mut h = 0u64;
    for w in row {
        h = (h.rotate_left(5) ^ w).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    (h >> 32) as usize & (SLOTS - 1)
}

/// Runs `f` with the entry of `row` from this thread's slots, or fetches it with `miss` and keeps it. `owner` names the
/// engine, so rows of two libraries never meet.
pub fn with_local<R, E>(
    owner: usize,
    row: &Words,
    miss: impl FnOnce() -> Result<Arc<Entry>, E>,
    f: impl FnOnce(&Entry) -> R,
) -> Result<R, E> {
    let at = slot_of(row);
    LOCAL.with(|cell| {
        let mut slots = cell.borrow_mut();
        if let Some(s) = &slots[at]
            && s.owner == owner
            && s.row == *row
        {
            return Ok(f(&s.entry));
        }
        let entry = miss()?;
        let slot = slots[at].insert(Slot {
            owner,
            row: *row,
            entry,
        });
        Ok(f(&slot.entry))
    })
}
