//! The cache directory and the apps' stores in it.
//!
//! `<dir>/<app id>/<2 hex>/<64 hex>` holds the files of an app (`format`), `<dir>/<app id>/tmp/`
//! the ones being written, `<dir>/cache.lock` the lock that makes one process the writer. Only the
//! holder of the lock stores, evicts and deletes; a reload's successor that does not hold it serves
//! what it reads. Every process builds the in-memory index (`index`) from the headers of the files
//! at start, in the background, and nothing is stored until that is done and, for the holder, the
//! clean that follows it. All of this blocks and runs under `spawn_blocking`.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use tokio::sync::Semaphore;

use super::control::vary_names;
use super::fills::Fills;
use super::format::{self, Loaded, ReadError, TMP_DIR, Times};
use super::host::{CacheRefusal, CacheRefusalCode, HostFacts, check_dir};
use super::index::{Found, Index, MAX_ENTRIES};
use super::key::{FileId, PrimaryId, from_hex, primary_id};
use super::purge::{Matcher, PurgeScope};
use super::stats::{CacheCounters, CacheTotals, Count, Counters};

/// What may be read from disk or written to it at once, in bytes of files.
pub(crate) const IN_FLIGHT_MAX: usize = 256 << 20;
const LOCK_FILE: &str = "cache.lock";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn now() -> u64 {
    u64::try_from(crate::decision::now_unix()).unwrap_or(0)
}

/// Whether `id` can name the directory of an app: 1 to 64 of letters, digits, `-` and `_`.
pub fn valid_app_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// What the stores of all the apps share.
pub(crate) struct HostState {
    holder: AtomicBool,
    ready: AtomicBool,
    cleaned: AtomicBool,
    /// The file system is nearly full (free space under 5 %): nothing is stored until a check
    /// finds room again.
    disk_full: AtomicBool,
    /// Tests: every write fails as if the file system were full.
    fail_writes: AtomicBool,
    /// Tests: free bytes and size of the file system, in place of what `statvfs` says.
    pretend_free: Mutex<Option<(u64, u64)>>,
    /// Answers that are being written behind the visitor's back.
    stores: AtomicUsize,
    pub budget: Arc<Semaphore>,
}

/// An answer that is being stored: the host counts it until this is dropped.
pub(crate) struct Storing(Arc<HostState>);

impl Drop for Storing {
    fn drop(&mut self) {
        self.0.stores.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The most primary keys a process that cannot delete files remembers a write for. Past it the
/// notes are replaced by one time, which ends every copy stored up to then.
const DROPPED_MAX: usize = 4096;

/// What a process that cannot delete files knows has ended: a write to a URL ends its copies, but
/// the files of them stay on disk while another process holds the lock, and a process that later
/// reads the directory again would take them for live. The copies are told by primary key and
/// the second of the write: a file stored in that second or before is one the write ended; one
/// stored after is newer than the write.
#[derive(Default)]
struct Dropped {
    primaries: HashMap<PrimaryId, u64>,
    /// Every copy stored at or before this second has ended: the notes outgrew [`DROPPED_MAX`].
    floor: Option<u64>,
}

impl Dropped {
    fn record(&mut self, primaries: &[PrimaryId], at: u64) {
        for primary in primaries {
            let newest = self.primaries.entry(*primary).or_insert(at);
            *newest = (*newest).max(at);
        }
        if self.primaries.len() > DROPPED_MAX {
            self.primaries.clear();
            self.floor = Some(self.floor.map_or(at, |f| f.max(at)));
        }
    }

    fn ended(&self, primary: &PrimaryId, stored_at: u64) -> bool {
        self.floor.is_some_and(|f| stored_at <= f)
            || self
                .primaries
                .get(primary)
                .is_some_and(|&at| stored_at <= at)
    }

    fn clear(&mut self) {
        self.primaries.clear();
        self.floor = None;
    }
}

/// An answer to put on disk.
pub(crate) struct Store {
    /// The purge count of the app when the fetch of this answer began: a purge since then drops
    /// the answer.
    pub purge_gen: u64,
    pub id: FileId,
    pub primary: PrimaryId,
    pub key: Vec<u8>,
    pub primary_len: usize,
    pub names: Vec<Vec<u8>>,
    pub head: Vec<u8>,
    pub body: Bytes,
    pub times: Times,
}

/// Why an answer was not put on disk.
#[derive(Debug)]
pub(crate) enum Skip {
    /// This process is not the writer yet, or any more.
    NotWriter,
    /// A purge began after the answer was asked for.
    Purged,
    /// The file system is full or nearly so.
    DiskFull,
    Disk(io::Error),
}

/// Whether a write failed for want of room.
fn no_space(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(nix::libc::ENOSPC | nix::libc::EDQUOT)
    )
}

/// Why a purge was not done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PurgeError {
    /// The app has no cache here.
    CacheOff,
    /// This process does not write (a reload's successor, or still reading the directory): try
    /// again later.
    Busy,
    /// An address that is not a path or an absolute `http://` or `https://` URL.
    Invalid,
}

/// One app's files and index.
pub(crate) struct AppCache {
    pub id: String,
    dir: PathBuf,
    host: Arc<HostState>,
    /// Lock order: the index first, then this.
    index: Mutex<Index>,
    dropped: Mutex<Dropped>,
    /// `stale_if_error_s` of the settings in force: the window kept past an answer's life when
    /// the answer names none of its own.
    stale_s: AtomicU32,
    /// Raised by every purge; an answer fetched before the raise is not stored.
    purges: AtomicU64,
    fills: Arc<Fills>,
    counts: Counters,
}

impl AppCache {
    fn new(id: &str, root: &Path, host: Arc<HostState>) -> AppCache {
        AppCache {
            id: id.to_owned(),
            dir: root.join(id),
            host,
            index: Mutex::new(Index::default()),
            dropped: Mutex::new(Dropped::default()),
            stale_s: AtomicU32::new(0),
            purges: AtomicU64::new(0),
            fills: Arc::default(),
            counts: Counters::default(),
        }
    }

    pub fn index(&self) -> MutexGuard<'_, Index> {
        lock(&self.index)
    }

    pub fn fills(&self) -> &Arc<Fills> {
        &self.fills
    }

    pub fn count(&self, what: Count) {
        self.counts.add(what, 1);
    }

    /// What was counted over the last hour at second `now`, for the tests of the cache.
    #[cfg(test)]
    pub fn hour(&self, now: u64) -> CacheCounters {
        self.counts.hour(now)
    }

    /// The `stale_if_error_s` of the settings in force.
    pub fn stale_if_error_s(&self) -> u32 {
        self.stale_s.load(Ordering::Relaxed)
    }

    /// The purge count now: what a fetch that begins now carries.
    pub fn purge_count(&self) -> u64 {
        self.purges.load(Ordering::Acquire)
    }

    /// Adds what the limits pushed out of the index since the last look to the counters. The
    /// caller holds the index.
    fn account_evictions(&self, index: &mut Index) {
        self.counts.add(Count::Evictions, index.take_evicted());
    }

    /// Whether this process may write now: it holds the lock, the index is built and the clean
    /// after the lock was taken is done.
    pub fn can_store(&self) -> bool {
        self.host.holder.load(Ordering::Acquire)
            && self.host.ready.load(Ordering::Acquire)
            && self.host.cleaned.load(Ordering::Acquire)
    }

    pub fn budget(&self) -> &Arc<Semaphore> {
        &self.host.budget
    }

    /// Counts an answer as being stored until the guard is dropped.
    pub fn storing(&self) -> Storing {
        self.host.stores.fetch_add(1, Ordering::AcqRel);
        Storing(self.host.clone())
    }

    /// Reads and checks the file of an entry. A file that is not what the index says (a size, a
    /// check sum or a key that differs, a link in its place) is removed, from the index and from
    /// the disk, and is reported as `Corrupt`; one that is gone is dropped from the index. A store
    /// that put a newer file in place since `found` was taken is not damage: the entry is left, and
    /// the read is `Replaced`. The body goes into `body` (`format::read`).
    pub fn read(&self, found: &Found, body: Vec<u8>) -> Result<Loaded, ReadError> {
        let path = format::path_of(&self.dir, &found.id);
        let read = format::read(&path, found.size, &found.key, body);
        match read {
            Err(ReadError::Corrupt) if self.forget(&found.id, found.size, found.times) => {
                self.counts.add(Count::Corrupt, 1);
                crate::metrics::count_cache_corrupt();
                read
            }
            Err(ReadError::Missing) if self.forget(&found.id, found.size, found.times) => read,
            Err(ReadError::Corrupt | ReadError::Missing) => Err(ReadError::Replaced),
            _ => read,
        }
    }

    /// Puts an answer on disk and in the index; what the limits push out is deleted. A full file
    /// system is a skip, never an error: free space under 5 % stops stores (`DiskFull`), and so
    /// does a write that fails for want of room. The file takes its name while the index is held,
    /// so a reader that opens the new file finds the new entry when it asks.
    pub fn store(&self, s: Store) -> Result<(), Skip> {
        if !self.can_store() {
            return Err(Skip::NotWriter);
        }
        if s.purge_gen != self.purge_count() {
            return Err(Skip::Purged);
        }
        if self.host.disk_full.load(Ordering::Acquire) {
            self.counts.add(Count::SkippedDiskFull, 1);
            return Err(Skip::DiskFull);
        }
        let written = if self.host.fail_writes.load(Ordering::Relaxed) {
            Err(io::Error::from_raw_os_error(nix::libc::ENOSPC))
        } else {
            format::write_temp(
                &self.dir,
                &s.id,
                s.primary_len,
                &s.key,
                &s.head,
                &s.body,
                s.times,
            )
        };
        let skip = |e: io::Error| {
            if no_space(&e) {
                self.counts.add(Count::SkippedDiskFull, 1);
                Skip::DiskFull
            } else {
                Skip::Disk(e)
            }
        };
        let written = written.map_err(skip)?;
        let size = written.size();
        let mut index = self.index();
        // A purge raises the count before it takes the index, so one that comes after this check
        // finds the entry and drops it.
        if s.purge_gen != self.purge_count() {
            drop(index);
            written.discard();
            return Err(Skip::Purged);
        }
        written.place().map_err(skip)?;
        let gone = index.insert(
            s.id,
            s.primary,
            &s.key[..s.primary_len],
            s.names,
            size,
            s.times,
        );
        self.account_evictions(&mut index);
        drop(index);
        if !gone.contains(&s.id) {
            self.counts.add(Count::Stored, 1);
        }
        self.delete_files(&gone);
        Ok(())
    }

    /// Removes what `matcher` names and ends every fetch that began before: the purge count is
    /// raised before the index is taken. The files go before this returns.
    fn purge(&self, matcher: &Matcher) {
        self.purges.fetch_add(1, Ordering::AcqRel);
        self.fills.clear_marks();
        let gone = self.index().purge(matcher);
        self.delete_files(&gone);
    }

    /// Forgets an entry and deletes its file: its copy is no longer to be kept. Only the entry
    /// with this `size` and these `times`, the one that was read: a store may have put a newer one
    /// in its place since, which stays. The file goes while the index is held, so a store that
    /// puts a new file under the name comes after. Returns whether the entry went.
    pub fn forget(&self, id: &FileId, size: u64, times: Times) -> bool {
        let mut index = self.index();
        if !index.holds(id, size, times) {
            return false;
        }
        index.remove(id);
        self.delete_files(std::slice::from_ref(id));
        true
    }

    /// Removes the files of entries that are no longer in the index, when this process may delete.
    pub fn delete_files(&self, ids: &[FileId]) {
        if self.host.holder.load(Ordering::Acquire) {
            for id in ids {
                format::remove(&self.dir, id);
            }
        }
    }

    /// Drops every entry of these primary keys now and returns their files, which the caller
    /// deletes. `at` is the second of the write that ended them. A process that cannot be sure its
    /// deletes reach the disk (it does not hold the lock, or has not read the directory yet) notes
    /// the write too, so the files that are left are not taken for live when it reads the directory
    /// again.
    pub fn drop_primaries(&self, primaries: &[PrimaryId], at: u64) -> Vec<FileId> {
        let mut index = self.index();
        let gone = index.drop_primaries(primaries);
        if !(self.host.holder.load(Ordering::Acquire) && self.host.ready.load(Ordering::Acquire)) {
            lock(&self.dropped).record(primaries, at);
        }
        drop(index);
        gone
    }

    /// Entries, bytes on disk and bytes in memory.
    pub fn usage(&self) -> (usize, u64, u64) {
        let ix = self.index();
        (ix.len(), ix.disk_bytes(), ix.memory_bytes())
    }
}

/// What an app's cache counted since the agent started and what it holds now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppMetrics {
    pub app_id: String,
    pub totals: CacheTotals,
    pub objects: u64,
    pub disk_bytes: u64,
    pub memory_bytes: u64,
}

/// The settings of an app the store needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheLimits {
    pub app_id: String,
    pub disk_bytes: u64,
    pub memory_bytes: u64,
    pub stale_if_error_s: u32,
}

/// An entry the scan found.
struct Scanned {
    id: FileId,
    primary: PrimaryId,
    /// The bytes of the primary key, for the address a purge compares with.
    primary_key: Vec<u8>,
    names: Vec<Vec<u8>>,
    size: u64,
    times: Times,
}

#[derive(Default)]
struct Scan {
    apps: HashMap<String, Vec<Scanned>>,
    /// What is in the directory and is not an answer: the temporary files, names that are not the
    /// agent's, files that fail their header. Removed by the holder.
    junk: Vec<PathBuf>,
}

fn is_shard(name: &str) -> bool {
    name.len() == 2 && name.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

fn scan(root: &Path) -> Scan {
    let mut out = Scan::default();
    let Ok(apps) = std::fs::read_dir(root) else {
        return out;
    };
    for app in apps.flatten() {
        let path = app.path();
        let (name, kind) = (app.file_name(), app.file_type());
        let Some(name) = name.to_str().map(str::to_owned) else {
            out.junk.push(path);
            continue;
        };
        if name == LOCK_FILE && kind.as_ref().is_ok_and(|t| t.is_file()) {
            continue;
        }
        if !valid_app_id(&name) || !kind.is_ok_and(|t| t.is_dir()) {
            out.junk.push(path);
            continue;
        }
        let entries = scan_app(&path, &mut out.junk);
        out.apps.insert(name, entries);
    }
    out
}

fn scan_app(dir: &Path, junk: &mut Vec<PathBuf>) -> Vec<Scanned> {
    let mut found = Vec::new();
    let Ok(children) = std::fs::read_dir(dir) else {
        return found;
    };
    for child in children.flatten() {
        let path = child.path();
        let name = child.file_name().to_str().map(str::to_owned);
        let is_dir = child.file_type().is_ok_and(|t| t.is_dir());
        match name {
            Some(n) if n == TMP_DIR && is_dir => {
                if let Ok(files) = std::fs::read_dir(&path) {
                    junk.extend(files.flatten().map(|f| f.path()));
                }
            }
            Some(n) if is_shard(&n) && is_dir => scan_shard(&n, &path, &mut found, junk),
            _ => junk.push(path),
        }
    }
    found
}

fn scan_shard(shard: &str, dir: &Path, found: &mut Vec<Scanned>, junk: &mut Vec<PathBuf>) {
    let Ok(files) = std::fs::read_dir(dir) else {
        return;
    };
    for file in files.flatten() {
        let path = file.path();
        let id = file
            .file_name()
            .to_str()
            .filter(|n| n.starts_with(shard))
            .and_then(from_hex);
        let (Some(id), true) = (id, file.file_type().is_ok_and(|t| t.is_file())) else {
            junk.push(path);
            continue;
        };
        let summary = match format::read_summary(&path) {
            Ok(s) => s,
            Err(ReadError::Corrupt) => {
                junk.push(path);
                continue;
            }
            Err(_) => continue,
        };
        // The name is the hash of the key the file holds, and the key holds its primary part.
        let names = vary_names(
            summary
                .head
                .lines
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(b"vary"))
                .map(|(_, v)| v.as_slice()),
        );
        let (true, Ok(names)) = (
            super::key::file_id(&summary.key, b"") == id
                && summary.primary_len <= summary.key.len(),
            names,
        ) else {
            junk.push(path);
            continue;
        };
        if found.len() >= MAX_ENTRIES {
            junk.push(path);
            continue;
        }
        found.push(Scanned {
            id,
            primary: primary_id(&summary.key[..summary.primary_len]),
            primary_key: summary.key[..summary.primary_len].to_vec(),
            names,
            size: summary.size,
            times: summary.times,
        });
    }
}

/// The cache directory and the stores of the apps in it. One for the process.
pub struct CacheHost {
    dir: PathBuf,
    state: Arc<HostState>,
    lock: Mutex<Option<Flock<std::fs::File>>>,
    apps: Mutex<HashMap<String, Arc<AppCache>>>,
    /// The apps with the cache on in the newest bundle; `None` before the first.
    live: Mutex<Option<HashSet<String>>>,
    junk: Mutex<Vec<PathBuf>>,
    maintaining: Mutex<()>,
    /// Whether the last lock attempt failed for a reason other than another holder, so it is said
    /// once.
    complained: AtomicBool,
}

impl CacheHost {
    /// Opens the directory the unit made: checks it (`CacheRefusalCode::DirUnusable` says why not),
    /// tries to take the lock and starts building the index from what is on disk. The index is
    /// built on the runtime's blocking pool when there is a runtime, else here.
    pub fn open(dir: &Path, uid: u32) -> Result<Arc<CacheHost>, CacheRefusal> {
        check_dir(dir, uid).map_err(|why| CacheRefusal::new(CacheRefusalCode::DirUnusable, why))?;
        let host = Arc::new(CacheHost {
            dir: dir.to_owned(),
            state: Arc::new(HostState {
                holder: AtomicBool::new(false),
                ready: AtomicBool::new(false),
                cleaned: AtomicBool::new(false),
                disk_full: AtomicBool::new(false),
                fail_writes: AtomicBool::new(false),
                pretend_free: Mutex::new(None),
                stores: AtomicUsize::new(0),
                budget: Arc::new(Semaphore::new(IN_FLIGHT_MAX)),
            }),
            lock: Mutex::new(None),
            apps: Mutex::new(HashMap::new()),
            live: Mutex::new(None),
            junk: Mutex::new(Vec::new()),
            maintaining: Mutex::new(()),
            complained: AtomicBool::new(false),
        });
        host.try_lock();
        let worker = host.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn_blocking(move || worker.rescan());
            }
            Err(_) => worker.rescan(),
        }
        Ok(host)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether this process is the one that writes.
    pub fn holds_lock(&self) -> bool {
        self.state.holder.load(Ordering::Acquire)
    }

    /// Whether the index is built from the disk.
    pub fn is_ready(&self) -> bool {
        self.state.ready.load(Ordering::Acquire)
    }

    /// Whether answers are being stored: the lock is held, the index is built and the clean is
    /// done. That needs a bundle: the clean waits for the first one.
    pub fn is_writable(&self) -> bool {
        self.state.holder.load(Ordering::Acquire)
            && self.state.ready.load(Ordering::Acquire)
            && self.state.cleaned.load(Ordering::Acquire)
    }

    fn try_lock(&self) -> bool {
        let mut held = lock(&self.lock);
        if held.is_some() {
            return true;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(self.dir.join(LOCK_FILE));
        let file = match file {
            Ok(f) => f,
            Err(e) => {
                self.complain(format_args!("cannot open ({})", e.kind()));
                return false;
            }
        };
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(l) => {
                *held = Some(l);
                self.state.holder.store(true, Ordering::Release);
                true
            }
            Err((_, Errno::EAGAIN)) => false,
            Err((_, e)) => {
                self.complain(format_args!("{e}"));
                false
            }
        }
    }

    fn complain(&self, what: std::fmt::Arguments<'_>) {
        if !self.complained.swap(true, Ordering::Relaxed) {
            tracing::warn!("[cache] cache directory lock: {what}");
        }
    }

    /// Takes the lock if the process that held it let go. The files are read again first, as what
    /// the old process stored after this one started counts, then cleaned, before anything is
    /// stored. Blocks. Returns whether this process is the writer.
    pub fn take_over(self: &Arc<Self>) -> bool {
        if self.holds_lock() {
            return true;
        }
        if !self.try_lock() {
            return false;
        }
        self.state.ready.store(false, Ordering::Release);
        self.state.cleaned.store(false, Ordering::Release);
        self.rescan();
        true
    }

    /// Lets go of the lock, for the process that takes over. Nothing is stored or deleted after.
    pub fn release(&self) {
        self.state.holder.store(false, Ordering::Release);
        self.state.cleaned.store(false, Ordering::Release);
        *lock(&self.lock) = None;
    }

    /// The store of an app, made when it is not there. `None` for an id that cannot name a
    /// directory.
    pub(crate) fn app(&self, id: &str) -> Option<Arc<AppCache>> {
        if !valid_app_id(id) {
            return None;
        }
        let mut apps = lock(&self.apps);
        Some(
            apps.entry(id.to_owned())
                .or_insert_with(|| Arc::new(AppCache::new(id, &self.dir, self.state.clone())))
                .clone(),
        )
    }

    /// Builds every app's index from the disk and replaces what the stores hold, then cleans.
    fn rescan(&self) {
        let scanned = scan(&self.dir);
        let mut doomed: Vec<(Arc<AppCache>, Vec<FileId>)> = Vec::new();
        let names: HashSet<String> = scanned.apps.keys().cloned().collect();
        for (name, entries) in scanned.apps {
            let Some(app) = self.app(&name) else { continue };
            let mut gone = Vec::new();
            {
                let mut ix = app.index();
                let mut dropped = lock(&app.dropped);
                ix.clear();
                for e in entries {
                    // A write ended this copy while this process could not delete its file.
                    if dropped.ended(&e.primary, e.times.stored_at) {
                        gone.push(e.id);
                        continue;
                    }
                    gone.extend(ix.insert(
                        e.id,
                        e.primary,
                        &e.primary_key,
                        e.names,
                        e.size,
                        e.times,
                    ));
                }
                app.account_evictions(&mut ix);
                // The writer deletes those files below; a process that cannot keeps its notes for
                // the day it takes the lock.
                if self.holds_lock() {
                    dropped.clear();
                }
            }
            doomed.push((app, gone));
        }
        for app in lock(&self.apps).values() {
            if !names.contains(&app.id) {
                app.index().clear();
            }
        }
        *lock(&self.junk) = scanned.junk;
        self.state.ready.store(true, Ordering::Release);
        for (app, gone) in doomed {
            app.delete_files(&gone);
        }
        self.maintain();
    }

    /// Applies the settings of the apps that have the cache on: their limits, and the apps that
    /// have it off or are gone are forgotten. Deletes what the new limits push out, when this
    /// process is the writer, then cleans in the background.
    pub fn commit(self: &Arc<Self>, apps: &[CacheLimits]) {
        let live: HashSet<String> = apps.iter().map(|a| a.app_id.clone()).collect();
        for limits in apps {
            let Some(app) = self.app(&limits.app_id) else {
                continue;
            };
            app.stale_s
                .store(limits.stale_if_error_s, Ordering::Relaxed);
            let gone = {
                let mut index = app.index();
                let gone = index.set_limits(limits.disk_bytes, limits.memory_bytes);
                app.account_evictions(&mut index);
                gone
            };
            app.delete_files(&gone);
        }
        lock(&self.apps).retain(|id, _| live.contains(id));
        *lock(&self.live) = Some(live);
        let worker = self.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn_blocking(move || worker.maintain());
            }
            Err(_) => worker.maintain(),
        }
    }

    /// The clean of the writer: the temporary files and unknown names the scan found, the
    /// directories of apps that do not have the cache on, the answers past their stale window.
    /// It waits for the first bundle (which says which apps are live), and ends with the writer
    /// allowed to store.
    fn maintain(&self) {
        let _one = lock(&self.maintaining);
        if !self.holds_lock() || !self.is_ready() {
            return;
        }
        let Some(live) = lock(&self.live).clone() else {
            return;
        };
        for path in std::mem::take(&mut *lock(&self.junk)) {
            remove_path(&path);
        }
        if let Ok(children) = std::fs::read_dir(&self.dir) {
            for child in children.flatten() {
                let name = child.file_name();
                let Some(name) = name.to_str() else { continue };
                if valid_app_id(name)
                    && !live.contains(name)
                    && child.file_type().is_ok_and(|t| t.is_dir())
                {
                    remove_path(&child.path());
                }
            }
        }
        let apps: Vec<Arc<AppCache>> = lock(&self.apps)
            .values()
            .filter(|a| live.contains(&a.id))
            .cloned()
            .collect();
        let now = now();
        for app in apps {
            let stale = u64::from(app.stale_s.load(Ordering::Relaxed));
            let mut gone = Vec::new();
            {
                let mut ix = app.index();
                for id in ix.past_window(now, stale) {
                    ix.remove(&id);
                    gone.push(id);
                }
            }
            app.delete_files(&gone);
        }
        self.state.cleaned.store(true, Ordering::Release);
    }

    /// Waits up to `wait` for the index to be built, and returns what the cache holds on disk, in
    /// bytes; `None` when the index is not built by then.
    pub fn disk_in_use(&self, wait: Duration) -> Option<u64> {
        let until = Instant::now() + wait;
        while !self.is_ready() {
            if Instant::now() >= until {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Some(
            lock(&self.apps)
                .values()
                .map(|a| a.usage().1)
                .fold(0u64, u64::saturating_add),
        )
    }

    /// What the host has for the cache directory.
    pub fn host_facts(&self) -> io::Result<HostFacts> {
        HostFacts::read(&self.dir)
    }

    /// Removes the copies `scope` names from `app_id`, in both tiers, and ends the fetches that
    /// began before. Once this returns the index holds none of them and their files are gone.
    /// Blocks. A process that does not write (a reload's successor, or one that has not read the
    /// directory yet) cannot delete files and says `Busy`.
    pub fn purge(&self, app_id: &str, scope: PurgeScope<'_>) -> Result<(), PurgeError> {
        let matcher = Matcher::new(scope).ok_or(PurgeError::Invalid)?;
        let app = lock(&self.apps)
            .get(app_id)
            .cloned()
            .ok_or(PurgeError::CacheOff)?;
        if !(self.holds_lock() && self.is_ready()) {
            return Err(PurgeError::Busy);
        }
        app.purge(&matcher);
        Ok(())
    }

    /// What the cache of `app_id` counted over the last hour and holds now; `None` for an app the
    /// store does not know.
    pub fn counters(&self, app_id: &str) -> Option<CacheCounters> {
        let app = lock(&self.apps).get(app_id).cloned()?;
        let (objects, disk, memory) = app.usage();
        Some(CacheCounters {
            disk_bytes: disk,
            memory_bytes: memory,
            objects: objects as u64,
            ..app.counts.hour(now())
        })
    }

    /// What each app's cache counted since the agent started and holds now, by app id, for the
    /// metrics.
    pub fn metrics(&self) -> Vec<AppMetrics> {
        let mut apps: Vec<AppMetrics> = lock(&self.apps)
            .values()
            .map(|app| {
                let (objects, disk_bytes, memory_bytes) = app.usage();
                AppMetrics {
                    app_id: app.id.clone(),
                    totals: app.counts.totals(),
                    objects: objects as u64,
                    disk_bytes,
                    memory_bytes,
                }
            })
            .collect();
        apps.sort_by(|a, b| a.app_id.cmp(&b.app_id));
        apps
    }

    /// Looks at the free space of the file system under the cache directory. Under 5 % of it, no
    /// copy is stored until a later look finds room, and the writer pushes out the copies the
    /// apps use least until that much is free again. Run it every minute. Blocks.
    pub fn check_disk(&self) {
        let pretend = *lock(&self.state.pretend_free);
        let (free, size) = match pretend {
            Some(pair) => pair,
            None => match HostFacts::read(&self.dir) {
                Ok(f) => (f.free_bytes, f.fs_bytes),
                Err(e) => {
                    tracing::warn!("[cache] free space could not be read: {e}");
                    return;
                }
            },
        };
        let floor = size / 20;
        let full = free < floor;
        if self.state.disk_full.swap(full, Ordering::AcqRel) != full {
            if full {
                tracing::warn!(
                    "[cache] the file system has under 5 % free: no copy is stored until it has room"
                );
            } else {
                tracing::info!("[cache] the file system has room again: copies are stored");
            }
        }
        if !full || !self.holds_lock() || !self.is_ready() {
            return;
        }
        let mut need = floor - free;
        let mut doomed: Vec<(Arc<AppCache>, Vec<FileId>)> = lock(&self.apps)
            .values()
            .map(|app| (app.clone(), Vec::new()))
            .collect();
        doomed.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        // One copy at a time from each app in turn, so no app loses all of its own first.
        while need > 0 {
            let mut freed_any = false;
            for (app, gone) in &mut doomed {
                if need == 0 {
                    break;
                }
                let victim = {
                    let mut index = app.index();
                    let victim = index.evict_one();
                    app.account_evictions(&mut index);
                    victim
                };
                if let Some((id, size)) = victim {
                    gone.push(id);
                    need = need.saturating_sub(size.max(1));
                    freed_any = true;
                }
            }
            if !freed_any {
                break;
            }
        }
        for (app, gone) in doomed {
            app.delete_files(&gone);
        }
    }

    /// Tests: what the free space check sees (free bytes, size of the file system) in place of
    /// the file system, or `None` for the file system again.
    #[doc(hidden)]
    pub fn pretend_free_space(&self, pair: Option<(u64, u64)>) {
        *lock(&self.state.pretend_free) = pair;
    }

    /// Tests: every write fails as if the file system were full.
    #[doc(hidden)]
    pub fn fail_writes_for_want_of_room(&self, on: bool) {
        self.state.fail_writes.store(on, Ordering::Relaxed);
    }

    /// Entries, bytes on disk and bytes in memory of an app; `None` for one the store does not
    /// know.
    #[doc(hidden)]
    pub fn usage(&self, app_id: &str) -> Option<(usize, u64, u64)> {
        lock(&self.apps).get(app_id).map(|a| a.usage())
    }

    /// How many answers are being written behind the visitors who got them, for a test.
    #[doc(hidden)]
    pub fn stores_in_flight(&self) -> usize {
        self.state.stores.load(Ordering::Acquire)
    }

    /// Waits until answers are stored, for a test.
    #[doc(hidden)]
    pub fn wait_writable(&self, wait: Duration) -> bool {
        let until = Instant::now() + wait;
        while !self.is_writable() {
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }
}

fn remove_path(path: &Path) {
    // `symlink_metadata`: a link is removed itself, never followed.
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => {
            let _ = std::fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(path);
        }
        Err(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::format::StoredHead;
    use crate::cache::key::{file_id, hex};
    use std::sync::atomic::AtomicU64;

    pub(crate) struct Dir(pub PathBuf);

    impl Dir {
        pub fn new() -> Dir {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "wafio-cache-store-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Dir(dir.canonicalize().unwrap())
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn uid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    const FRESH: Times = Times {
        stored_at: 1,
        fresh_until: u64::MAX / 2,
        initial_age: 0,
        stale_window: 0,
    };

    fn head() -> Vec<u8> {
        StoredHead {
            status: 200,
            http10: false,
            reason: b"OK".to_vec(),
            lines: vec![(b"Content-Type".to_vec(), b"text/plain".to_vec())],
        }
        .encode()
        .unwrap()
    }

    /// An answer under the primary key `name`.
    fn answer(name: &str, body: &[u8], times: Times) -> Store {
        let key = name.as_bytes().to_vec();
        Store {
            purge_gen: 0,
            id: file_id(&key, b""),
            primary: primary_id(&key),
            primary_len: key.len(),
            key,
            names: Vec::new(),
            head: head(),
            body: Bytes::copy_from_slice(body),
            times,
        }
    }

    fn limits(app: &str, disk: u64) -> CacheLimits {
        CacheLimits {
            app_id: app.into(),
            disk_bytes: disk,
            memory_bytes: 1 << 20,
            stale_if_error_s: 0,
        }
    }

    /// A host in a fresh directory with the apps live, writable.
    fn writable(dir: &Dir, apps: &[CacheLimits]) -> Arc<CacheHost> {
        let host = CacheHost::open(&dir.0, uid()).unwrap();
        host.commit(apps);
        assert!(host.wait_writable(Duration::from_secs(5)));
        host
    }

    #[test]
    fn app_ids_that_can_name_a_directory() {
        for ok in ["a", "shop", "7f3a-91_b", &"a".repeat(64)] {
            assert!(valid_app_id(ok), "{ok}");
        }
        for bad in [
            "",
            "..",
            "a/b",
            "a.b",
            ".hidden",
            "a b",
            "é",
            "tmp\0",
            &"a".repeat(65),
        ] {
            assert!(!valid_app_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_stored_answer_is_read_back_and_survives_a_restart() {
        let dir = Dir::new();
        let host = writable(&dir, &[limits("shop", 1 << 20)]);
        let app = host.app("shop").unwrap();
        app.store(answer("one", b"hello", FRESH)).unwrap();
        let (found, fresh) = app
            .index()
            .find(&primary_id(b"one"), b"one", |_| Vec::new(), 10)
            .unwrap();
        assert!(fresh);
        let loaded = app.read(&found, Vec::new()).unwrap();
        assert_eq!(loaded.body, b"hello");
        assert_eq!(host.usage("shop").unwrap().0, 1);
        host.release();
        drop(app);
        drop(host);
        // Another process: the same directory, the same index, hits without a store.
        let again = CacheHost::open(&dir.0, uid()).unwrap();
        again.commit(&[limits("shop", 1 << 20)]);
        assert!(again.is_ready() && again.wait_writable(Duration::from_secs(5)));
        let app = again.app("shop").unwrap();
        let (found, _) = app
            .index()
            .find(&primary_id(b"one"), b"one", |_| Vec::new(), 10)
            .unwrap();
        assert_eq!(app.read(&found, Vec::new()).unwrap().body, b"hello");
    }

    #[test]
    fn only_one_process_writes_and_the_successor_takes_over_when_the_lock_is_free() {
        let dir = Dir::new();
        let first = CacheHost::open(&dir.0, uid()).unwrap();
        first.commit(&[limits("shop", 1 << 20)]);
        assert!(first.wait_writable(Duration::from_secs(5)));
        let second = CacheHost::open(&dir.0, uid()).unwrap();
        second.commit(&[limits("shop", 1 << 20)]);
        assert!(!second.holds_lock());
        assert!(second.is_ready(), "a reader builds its index too");
        let (a, b) = (first.app("shop").unwrap(), second.app("shop").unwrap());
        a.store(answer("one", b"1", FRESH)).unwrap();
        // The reader stores, evicts and deletes nothing.
        assert!(matches!(
            b.store(answer("two", b"2", FRESH)),
            Err(Skip::NotWriter)
        ));
        assert!(!format::path_of(&dir.0.join("shop"), &answer("two", b"", FRESH).id).exists());
        assert!(!second.take_over(), "the lock is held");
        // The first lets go; the second reads what the first stored after the second started.
        first.release();
        assert!(second.take_over());
        assert!(second.is_writable());
        let found = b
            .index()
            .find(&primary_id(b"one"), b"one", |_| Vec::new(), 10);
        assert!(found.is_some(), "a file stored after the start counts");
        assert!(matches!(
            a.store(answer("three", b"3", FRESH)),
            Err(Skip::NotWriter)
        ));
        b.store(answer("two", b"2", FRESH)).unwrap();
    }

    fn has(app: &AppCache, name: &str) -> bool {
        app.index()
            .find(
                &primary_id(name.as_bytes()),
                name.as_bytes(),
                |_| Vec::new(),
                200,
            )
            .is_some()
    }

    #[test]
    fn a_write_answered_without_the_lock_is_not_undone_when_the_lock_is_taken() {
        let dir = Dir::new();
        let first = CacheHost::open(&dir.0, uid()).unwrap();
        first.commit(&[limits("shop", 1 << 20)]);
        assert!(first.wait_writable(Duration::from_secs(5)));
        let second = CacheHost::open(&dir.0, uid()).unwrap();
        second.commit(&[limits("shop", 1 << 20)]);
        assert!(!second.holds_lock() && second.is_ready());
        let (a, b) = (first.app("shop").unwrap(), second.app("shop").unwrap());
        let at = |stored_at| Times { stored_at, ..FRESH };
        // The first stores after the second built its index, so the second's index holds neither.
        a.store(answer("one", b"1", at(100))).unwrap();
        a.store(answer("two", b"2", at(100))).unwrap();
        // A write at second 150 to the URL of "one": nothing to drop here, and the files stay.
        assert!(b.drop_primaries(&[primary_id(b"one")], 150).is_empty());
        let file = |name: &str| format::path_of(&dir.0.join("shop"), &answer(name, b"", FRESH).id);
        assert!(file("one").exists());
        first.release();
        assert!(second.take_over());
        assert!(!has(&b, "one"), "the write ended it");
        assert!(!file("one").exists(), "and its file went with it");
        assert!(has(&b, "two") && file("two").exists());
        assert!(
            lock(&b.dropped).primaries.is_empty(),
            "the files are gone, so is the note"
        );
        // A copy stored after the write is newer than it.
        b.store(answer("one", b"3", at(151))).unwrap();
        assert!(has(&b, "one"));
        // The writer deletes its drops at once and keeps no note.
        assert_eq!(b.drop_primaries(&[primary_id(b"two")], 160).len(), 1);
        assert!(lock(&b.dropped).primaries.is_empty());
        assert!(!has(&b, "two"));
    }

    #[test]
    fn a_process_that_cannot_delete_keeps_its_notes_for_the_day_it_can() {
        let dir = Dir::new();
        let first = CacheHost::open(&dir.0, uid()).unwrap();
        first.commit(&[limits("shop", 1 << 20)]);
        assert!(first.wait_writable(Duration::from_secs(5)));
        let second = CacheHost::open(&dir.0, uid()).unwrap();
        second.commit(&[limits("shop", 1 << 20)]);
        let (a, b) = (first.app("shop").unwrap(), second.app("shop").unwrap());
        a.store(answer(
            "one",
            b"1",
            Times {
                stored_at: 100,
                ..FRESH
            },
        ))
        .unwrap();
        b.drop_primaries(&[primary_id(b"one")], 150);
        // The lock is still the first's: reading the directory again hides the copy and deletes
        // nothing, and the note stays.
        second.rescan();
        assert!(!has(&b, "one"));
        assert!(format::path_of(&dir.0.join("shop"), &answer("one", b"", FRESH).id).exists());
        assert_eq!(lock(&b.dropped).primaries.len(), 1);
        first.release();
        assert!(second.take_over());
        assert!(!format::path_of(&dir.0.join("shop"), &answer("one", b"", FRESH).id).exists());
    }

    #[test]
    fn the_notes_of_writes_are_bounded_and_past_the_bound_end_everything_stored_before_the_last() {
        let mut d = Dropped::default();
        let (a, b) = (primary_id(b"a"), primary_id(b"b"));
        d.record(&[a], 10);
        assert!(
            d.ended(&a, 9) && d.ended(&a, 10),
            "the second of the write counts"
        );
        assert!(!d.ended(&a, 11), "a later copy is newer");
        assert!(!d.ended(&b, 5), "another URL is not named");
        d.record(&[a], 4);
        assert!(d.ended(&a, 10), "an older write does not lower the note");
        d.clear();
        for n in 0..DROPPED_MAX as u32 {
            d.record(&[primary_id(&n.to_le_bytes())], 20);
        }
        assert_eq!(d.primaries.len(), DROPPED_MAX);
        assert!(!d.ended(&b, 20), "up to the bound each URL is named");
        d.record(&[primary_id(b"one more")], 30);
        assert!(d.primaries.is_empty(), "past it the notes were replaced");
        assert!(d.ended(&b, 30) && !d.ended(&b, 31));
        d.clear();
        assert!(!d.ended(&a, 1) && !d.ended(&b, 1));
    }

    #[test]
    fn the_clean_removes_temporary_files_unknown_names_and_the_directories_of_apps_that_are_off() {
        let dir = Dir::new();
        {
            let host = writable(&dir, &[limits("keep", 1 << 20), limits("gone", 1 << 20)]);
            host.app("keep")
                .unwrap()
                .store(answer("a", b"x", FRESH))
                .unwrap();
            host.app("gone")
                .unwrap()
                .store(answer("a", b"x", FRESH))
                .unwrap();
            host.release();
        }
        let keep = dir.0.join("keep");
        let id = hex(&answer("a", b"", FRESH).id);
        std::fs::write(keep.join("tmp").join("1234-0"), b"torn").unwrap();
        std::fs::write(keep.join("notes.txt"), b"x").unwrap();
        std::fs::create_dir(keep.join("zz")).unwrap();
        std::fs::write(keep.join(&id[..2]).join("short"), b"x").unwrap();
        std::fs::write(dir.0.join("stray"), b"x").unwrap();
        std::fs::create_dir(dir.0.join("not a valid id")).unwrap();
        std::os::unix::fs::symlink("/", dir.0.join("link")).unwrap();
        let host = CacheHost::open(&dir.0, uid()).unwrap();
        // Before the first bundle nothing is cleaned, and nothing is stored.
        assert!(!host.wait_writable(Duration::from_millis(200)));
        assert!(dir.0.join("stray").exists() && dir.0.join("gone").exists());
        host.commit(&[limits("keep", 1 << 20)]);
        assert!(host.wait_writable(Duration::from_secs(5)));
        let names = |p: &Path| {
            let mut v: Vec<String> = std::fs::read_dir(p)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            v.sort();
            v
        };
        assert_eq!(names(&dir.0), ["cache.lock", "keep"], "the rest is gone");
        let mut want = vec!["tmp".to_string(), id[..2].to_string()];
        want.sort();
        assert_eq!(names(&keep), want);
        assert!(names(&keep.join("tmp")).is_empty());
        assert_eq!(
            names(&keep.join(&id[..2])),
            std::slice::from_ref(&id),
            "the answer stays alone in its folder"
        );
        // What the clean kept is still served.
        let app = host.app("keep").unwrap();
        assert!(
            app.index()
                .find(&primary_id(b"a"), b"a", |_| Vec::new(), 10)
                .is_some()
        );
        // The link was removed, not followed: the root of the file system is as it was.
        assert!(Path::new("/etc").exists());
    }

    #[test]
    fn a_reader_cleans_nothing() {
        let dir = Dir::new();
        let writer = CacheHost::open(&dir.0, uid()).unwrap();
        let reader = CacheHost::open(&dir.0, uid()).unwrap();
        std::fs::write(dir.0.join("stray"), b"x").unwrap();
        reader.commit(&[limits("shop", 1 << 20)]);
        assert!(!reader.holds_lock());
        std::thread::sleep(Duration::from_millis(100));
        assert!(dir.0.join("stray").exists(), "the reader deleted nothing");
        drop(writer);
    }

    #[test]
    fn what_is_past_its_stale_window_goes_at_the_clean_and_the_quota_is_kept() {
        let dir = Dir::new();
        {
            let host = writable(&dir, &[limits("shop", 1 << 20)]);
            let app = host.app("shop").unwrap();
            let old = Times {
                stored_at: 1,
                fresh_until: 10,
                initial_age: 0,
                stale_window: 0,
            };
            app.store(answer("old", b"x", old)).unwrap();
            app.store(answer("new", b"x", FRESH)).unwrap();
            host.release();
        }
        // The old one is past its life and the setting's window: gone at the clean.
        let host = CacheHost::open(&dir.0, uid()).unwrap();
        host.commit(&[limits("shop", 1 << 20)]);
        assert!(host.wait_writable(Duration::from_secs(5)));
        let app = host.app("shop").unwrap();
        assert_eq!(app.usage().0, 1);
        assert!(!format::path_of(&dir.0.join("shop"), &answer("old", b"", FRESH).id).exists());
        // A smaller quota evicts, and the files of what it evicts go.
        for n in 0..10 {
            app.store(answer(&format!("k{n}"), &[0u8; 1000], FRESH))
                .unwrap();
        }
        host.commit(&[limits("shop", 3000)]);
        let (entries, disk, _) = app.usage();
        assert!(disk <= 3000 && entries <= 3, "{entries} {disk}");
        let on_disk: usize = std::fs::read_dir(dir.0.join("shop"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name() != "tmp")
            .map(|shard| std::fs::read_dir(shard.path()).unwrap().count())
            .sum();
        assert_eq!(on_disk, entries, "no file outlives its entry");
    }

    #[test]
    fn a_file_that_fails_its_check_is_dropped_deleted_and_never_served() {
        let dir = Dir::new();
        let host = writable(&dir, &[limits("shop", 1 << 20)]);
        let app = host.app("shop").unwrap();
        app.store(answer("one", b"a body of some length", FRESH))
            .unwrap();
        let path = format::path_of(&dir.0.join("shop"), &answer("one", b"", FRESH).id);
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let (found, _) = app
            .index()
            .find(&primary_id(b"one"), b"one", |_| Vec::new(), 10)
            .unwrap();
        assert_eq!(app.read(&found, Vec::new()).err(), Some(ReadError::Corrupt));
        assert!(!path.exists(), "the corrupt file is deleted");
        assert!(
            app.index()
                .find(&primary_id(b"one"), b"one", |_| Vec::new(), 10)
                .is_none()
        );
        // A file that is gone is dropped from the index quietly.
        app.store(answer("two", b"x", FRESH)).unwrap();
        let (found, _) = app
            .index()
            .find(&primary_id(b"two"), b"two", |_| Vec::new(), 10)
            .unwrap();
        std::fs::remove_file(format::path_of(&dir.0.join("shop"), &found.id)).unwrap();
        assert_eq!(app.read(&found, Vec::new()).err(), Some(ReadError::Missing));
        assert_eq!(app.usage().0, 0);
    }

    #[test]
    fn a_scan_ignores_a_file_that_is_not_the_one_its_name_says() {
        let dir = Dir::new();
        {
            let host = writable(&dir, &[limits("shop", 1 << 20)]);
            let app = host.app("shop").unwrap();
            app.store(answer("one", b"x", FRESH)).unwrap();
            app.store(answer("two", b"y", FRESH)).unwrap();
            host.release();
        }
        // The files of two keys swapped between their names.
        let shop = dir.0.join("shop");
        let (one, two) = (
            format::path_of(&shop, &answer("one", b"", FRESH).id),
            format::path_of(&shop, &answer("two", b"", FRESH).id),
        );
        let tmp = shop.join("swap");
        std::fs::rename(&one, &tmp).unwrap();
        std::fs::rename(&two, &one).unwrap();
        std::fs::rename(&tmp, &two).unwrap();
        let host = CacheHost::open(&dir.0, uid()).unwrap();
        host.commit(&[limits("shop", 1 << 20)]);
        assert!(host.wait_writable(Duration::from_secs(5)));
        assert_eq!(host.usage("shop").unwrap().0, 0, "neither is believed");
    }

    #[test]
    fn the_disk_in_use_waits_for_the_index_and_adds_up_the_apps() {
        let dir = Dir::new();
        let host = writable(&dir, &[limits("a", 1 << 20), limits("b", 1 << 20)]);
        host.app("a")
            .unwrap()
            .store(answer("x", &[0; 100], FRESH))
            .unwrap();
        host.app("b")
            .unwrap()
            .store(answer("x", &[0; 200], FRESH))
            .unwrap();
        let used = host.disk_in_use(Duration::from_secs(1)).unwrap();
        assert!((300..1000).contains(&used), "{used}");
        assert!(host.host_facts().unwrap().fs_bytes > 0);
    }

    #[test]
    fn an_answer_that_was_asked_for_before_a_purge_is_not_stored_and_leaves_no_file() {
        let dir = Dir::new();
        let host = writable(&dir, &[limits("shop", 1 << 20)]);
        let app = host.app("shop").unwrap();
        let begun = app.purge_count();
        app.store(Store {
            purge_gen: begun,
            ..answer("kept", b"1", FRESH)
        })
        .unwrap();
        host.purge("shop", PurgeScope::Url("/nothing")).unwrap();
        assert_eq!(app.purge_count(), begun + 1, "every purge raises the count");
        let late = Store {
            purge_gen: begun,
            ..answer("late", b"2", FRESH)
        };
        let path = format::path_of(&dir.0.join("shop"), &late.id);
        assert!(matches!(app.store(late), Err(Skip::Purged)));
        assert!(!path.exists() && !has(&app, "late"));
        // One asked for after it is kept.
        app.store(Store {
            purge_gen: app.purge_count(),
            ..answer("after", b"3", FRESH)
        })
        .unwrap();
        assert!(has(&app, "after"));
    }

    #[test]
    fn a_purge_names_what_it_removes_and_says_why_it_cannot() {
        let dir = Dir::new();
        let host = writable(&dir, &[limits("shop", 1 << 20)]);
        let app = host.app("shop").unwrap();
        for name in ["one", "two"] {
            app.store(answer(name, b"x", FRESH)).unwrap();
        }
        assert_eq!(
            host.purge("nope", PurgeScope::App),
            Err(PurgeError::CacheOff)
        );
        assert_eq!(
            host.purge("shop", PurgeScope::Url("a")),
            Err(PurgeError::Invalid)
        );
        assert_eq!(
            host.usage("shop").unwrap().0,
            2,
            "nothing went for a refusal"
        );
        assert_eq!(host.purge("shop", PurgeScope::App), Ok(()));
        assert_eq!(host.usage("shop").unwrap().0, 0);
        assert!(
            std::fs::read_dir(dir.0.join("shop"))
                .unwrap()
                .flatten()
                .filter(|e| e.file_name() != "tmp")
                .all(|shard| std::fs::read_dir(shard.path()).unwrap().count() == 0),
            "the files went with the entries"
        );
        // A process that does not hold the lock cannot delete, so it says to try again.
        let reader = CacheHost::open(&dir.0, uid()).unwrap();
        reader.commit(&[limits("shop", 1 << 20)]);
        assert_eq!(reader.purge("shop", PurgeScope::App), Err(PurgeError::Busy));
    }

    #[test]
    fn a_full_file_system_and_a_write_without_room_are_skips_and_are_counted() {
        let dir = Dir::new();
        let host = writable(&dir, &[limits("shop", 1 << 20)]);
        let app = host.app("shop").unwrap();
        host.fail_writes_for_want_of_room(true);
        assert!(matches!(
            app.store(answer("a", b"x", FRESH)),
            Err(Skip::DiskFull)
        ));
        assert!(!has(&app, "a"));
        host.fail_writes_for_want_of_room(false);
        // Under 5 % free the check stops the stores; room again lets them go on.
        host.pretend_free_space(Some((4, 100)));
        host.check_disk();
        assert!(matches!(
            app.store(answer("b", b"x", FRESH)),
            Err(Skip::DiskFull)
        ));
        host.pretend_free_space(Some((5, 100)));
        host.check_disk();
        app.store(answer("c", b"x", FRESH)).unwrap();
        let hour = app.hour(now());
        assert_eq!((hour.skipped_disk_full, hour.stored), (2, 1));
        // Another error of the disk is an error, not a skip.
        assert!(no_space(&io::Error::from_raw_os_error(nix::libc::EDQUOT)));
        assert!(!no_space(&io::Error::from_raw_os_error(nix::libc::EACCES)));
    }

    #[test]
    fn a_nearly_full_file_system_loses_the_least_used_copies_of_every_app_in_turn() {
        let dir = Dir::new();
        let host = writable(&dir, &[limits("a", 1 << 20), limits("b", 1 << 20)]);
        let (a, b) = (host.app("a").unwrap(), host.app("b").unwrap());
        let body = [0u8; 1000];
        for n in 0..4 {
            a.store(answer(&format!("a{n}"), &body, FRESH)).unwrap();
        }
        b.store(answer("b0", &body, FRESH)).unwrap();
        let each = host.usage("b").unwrap().1;
        // The floor is the size of three files and nothing is free: three go, one from each app in
        // turn, so the app with more of them keeps more.
        host.pretend_free_space(Some((0, each * 20 * 3)));
        host.check_disk();
        let left = host.usage("a").unwrap().0 + host.usage("b").unwrap().0;
        assert_eq!(left, 2, "five files, three of them freed");
        assert!(host.usage("b").unwrap().0 == 0 || host.usage("a").unwrap().0 == 1);
        assert_eq!(a.hour(now()).evictions + b.hour(now()).evictions, 3);
        let on_disk = |app: &str| -> usize {
            std::fs::read_dir(dir.0.join(app))
                .unwrap()
                .flatten()
                .filter(|e| e.file_name() != "tmp")
                .map(|shard| std::fs::read_dir(shard.path()).unwrap().count())
                .sum()
        };
        assert_eq!(
            on_disk("a") + on_disk("b"),
            left,
            "no file outlives its entry"
        );
        // A process that does not hold the lock stops stores but deletes nothing.
        let reader = CacheHost::open(&dir.0, uid()).unwrap();
        reader.commit(&[limits("a", 1 << 20), limits("b", 1 << 20)]);
        reader.pretend_free_space(Some((0, 1000)));
        reader.check_disk();
        assert_eq!(on_disk("a") + on_disk("b"), left);
        // Free space that cannot be read changes nothing.
        reader.pretend_free_space(None);
        reader.check_disk();
    }

    #[test]
    fn the_counters_and_the_gauges_of_an_app_are_what_it_did_and_holds() {
        let dir = Dir::new();
        let host = writable(&dir, &[limits("shop", 1 << 20)]);
        let app = host.app("shop").unwrap();
        app.store(answer("a", b"12345", FRESH)).unwrap();
        app.count(Count::HitDisk);
        app.count(Count::HitDisk);
        app.count(Count::Miss);
        let c = host.counters("shop").unwrap();
        assert_eq!((c.stored, c.hits_disk, c.misses, c.requests), (1, 2, 1, 3));
        assert_eq!((c.objects, c.disk_bytes > 0, c.memory_bytes), (1, true, 0));
        assert!(host.counters("nope").is_none());
        let m = host.metrics();
        assert_eq!(m.len(), 1);
        assert_eq!(
            (m[0].app_id.as_str(), m[0].objects, m[0].totals.hits_disk),
            ("shop", 1, 2)
        );
        // A file that fails its check is counted as corrupt, here and for the process.
        let path = format::path_of(&dir.0.join("shop"), &answer("a", b"", FRESH).id);
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let (found, _) = app
            .index()
            .find(&primary_id(b"a"), b"a", |_| Vec::new(), 10)
            .unwrap();
        let before = crate::metrics::CACHE_CORRUPT_FILES.load(Ordering::Relaxed);
        assert!(app.read(&found, Vec::new()).is_err());
        assert_eq!(host.counters("shop").unwrap().corrupt, 1);
        assert!(crate::metrics::CACHE_CORRUPT_FILES.load(Ordering::Relaxed) > before);
        // An entry that is forgotten takes its file, but only the entry that was read: one a
        // store put in its place since stays.
        app.store(answer("b", b"x", FRESH)).unwrap();
        let b = answer("b", b"", FRESH).id;
        let (read, _) = app
            .index()
            .find(&primary_id(b"b"), b"b", |_| Vec::new(), 10)
            .unwrap();
        let newer = Times {
            stored_at: 2,
            ..FRESH
        };
        app.store(answer("b", b"y", newer)).unwrap();
        assert!(!app.forget(&b, read.size, read.times));
        assert!(has(&app, "b") && format::path_of(&dir.0.join("shop"), &b).exists());
        assert!(app.forget(&b, read.size, newer));
        assert!(!has(&app, "b") && !format::path_of(&dir.0.join("shop"), &b).exists());
    }

    #[test]
    fn a_reader_of_an_older_entry_than_the_file_finds_no_damage_and_the_new_entry_stays() {
        let dir = Dir::new();
        let host = writable(&dir, &[limits("shop", 1 << 20)]);
        let app = host.app("shop").unwrap();
        app.store(answer("one", b"short", FRESH)).unwrap();
        let (found, _) = app
            .index()
            .find(&primary_id(b"one"), b"one", |_| Vec::new(), 10)
            .unwrap();
        // A refresh stores a longer answer under the same name before this reader opens the file.
        let newer = Times {
            stored_at: 2,
            ..FRESH
        };
        app.store(answer("one", b"a much longer answer than before", newer))
            .unwrap();
        assert_eq!(
            app.read(&found, Vec::new()).err(),
            Some(ReadError::Replaced)
        );
        let corrupt = host.counters("shop").unwrap().corrupt;
        assert_eq!(corrupt, 0, "nothing was damaged");
        let path = format::path_of(&dir.0.join("shop"), &found.id);
        assert!(path.exists(), "the new file is not deleted");
        let (now, _) = app
            .index()
            .find(&primary_id(b"one"), b"one", |_| Vec::new(), 10)
            .expect("the new entry stays");
        assert_eq!(
            app.read(&now, Vec::new()).unwrap().body,
            b"a much longer answer than before"
        );
        // Replaced again: the reader that holds the second entry is told the same.
        let third = Times {
            stored_at: 3,
            ..FRESH
        };
        app.store(answer("one", b"third", third)).unwrap();
        assert_eq!(app.read(&now, Vec::new()).err(), Some(ReadError::Replaced));
        assert!(has(&app, "one"));
        assert_eq!(host.counters("shop").unwrap().corrupt, 0);
    }

    #[test]
    fn readers_of_a_key_that_is_stored_again_and_again_never_meet_damage() {
        let dir = Dir::new();
        let host = writable(&dir, &[limits("shop", 1 << 20)]);
        let app = host.app("shop").unwrap();
        app.store(answer("hot", &[1u8; 100], FRESH)).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let (app, done) = (app.clone(), done.clone());
                std::thread::spawn(move || {
                    let mut reads = 0u32;
                    while !done.load(Ordering::Acquire) {
                        let Some((found, _)) =
                            app.index()
                                .find(&primary_id(b"hot"), b"hot", |_| Vec::new(), 10)
                        else {
                            panic!("the entry is never out of the index");
                        };
                        match app.read(&found, Vec::new()) {
                            Ok(_) => reads += 1,
                            Err(ReadError::Replaced) => {}
                            Err(e) => panic!("a replaced file was taken for {e:?}"),
                        }
                    }
                    reads
                })
            })
            .collect();
        // Every store changes the length of the file under the same name.
        for i in 0..1500u64 {
            let times = Times {
                stored_at: i + 2,
                ..FRESH
            };
            let body = vec![0u8; 50 + (i as usize % 7) * 90];
            app.store(answer("hot", &body, times)).unwrap();
        }
        done.store(true, Ordering::Release);
        let reads: u32 = readers.into_iter().map(|r| r.join().unwrap()).sum();
        assert!(reads > 0);
        assert_eq!(host.counters("shop").unwrap().corrupt, 0);
    }

    #[test]
    fn a_directory_that_cannot_be_used_is_refused_with_the_reason() {
        let err = CacheHost::open(Path::new("/no/such/dir"), uid())
            .err()
            .unwrap();
        assert_eq!(err.code, CacheRefusalCode::DirUnusable);
        let dir = Dir::new();
        let err = CacheHost::open(&dir.0, uid().wrapping_add(1))
            .err()
            .unwrap();
        assert!(err.detail.contains("owned by user"), "{}", err.detail);
    }
}
