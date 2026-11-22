//! The last applied live bundle is kept in `<state dir>/last-bundle.json` (temp file + fsync +
//! rename, mode 0600) and applied at start before the stream connects, so a restart while the
//! control plane is unreachable still serves the apps. The write runs on a thread of its own after
//! the bundle is acked, because an fsync on a busy disk can take seconds and the stream must go
//! on with the commands behind the bundle. The heartbeat reports where the configuration in force
//! came from (`live` | `cache` | `cache_stale`). The envelope is the format earlier agent versions
//! wrote and read, in both directions.

use crate::bundle_puller::{BundleError, BundleProbe};
use crate::grpc_reconnect::random_u64;
use crate::grpc_stream::ControlLink;
use crate::json_members;
use crate::timestamp::{Timestamp, duration_nanos, round_nanos, whole_seconds_text};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime};
use tracing::info;

/// The file inside the state directory.
pub const BUNDLE_CACHE_FILE_NAME: &str = "last-bundle.json";
/// When a cached bundle is reported stale.
pub const DEFAULT_BUNDLE_CACHE_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
const BUNDLE_CACHE_VERSION: i64 = 1;
/// Caps how much is read back at startup.
const MAX_BUNDLE_CACHE_BYTES: u64 = 64 << 20;

pub const BUNDLE_SOURCE_LIVE: &str = "live";
pub const BUNDLE_SOURCE_CACHE: &str = "cache";
pub const BUNDLE_SOURCE_CACHE_STALE: &str = "cache_stale";

/// The name of the cache envelope type, as its decode errors print it.
const ENVELOPE: &str = "bundleCacheEnvelope";

/// How a bundle reaches the disk, with the arguments of [`save_bundle_cache`]. The agent uses that
/// function; a test passes its own to hold a write back or to make it fail.
pub type CacheWrite =
    Arc<dyn Fn(&Path, &[u8], i64, SystemTime) -> Result<(), String> + Send + Sync>;

/// A cache file that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedBundle {
    /// The bundle JSON as applied (generation embedded), verbatim from the file.
    pub bundle: Vec<u8>,
    pub generation: i64,
    pub saved_at: Timestamp,
}

/// How starting from the cached bundle ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheStart {
    /// No cached bundle, an unusable one, or one the sink refused.
    NotApplied,
    /// The cached bundle is in force.
    Applied,
    /// The sink could not bind an address the bundle names. [`ControlLink::start`] applies this
    /// bundle again every minute, until it binds or a live bundle arrives.
    Bind(CachedBundle),
}

#[derive(Debug)]
pub enum CacheReadError {
    /// No cache file: quietly "no cache".
    NotFound,
    Invalid(String),
}

impl std::fmt::Display for CacheReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheReadError::NotFound => f.write_str("no cache file"),
            CacheReadError::Invalid(m) => f.write_str(m),
        }
    }
}

/// Atomically replace `dir/last-bundle.json` with `bundle` saved at `now`. The embedded
/// generation is set to `generation` (the message's generation replaces the embedded one).
pub fn save_bundle_cache(
    dir: &Path,
    bundle: &[u8],
    generation: i64,
    now: SystemTime,
) -> Result<(), String> {
    let raw = BundleProbe::with_generation(bundle, generation)
        .map_err(|e| format!("encode bundle: {e}"))?;
    let mut env = format!(
        "{{\"version\":{BUNDLE_CACHE_VERSION},\"saved_at\":\"{}\",\"generation\":{generation},\"bundle\":",
        Timestamp::from_system(now).format_rfc3339_nano()
    )
    .into_bytes();
    env.extend_from_slice(&raw);
    env.push(b'}');

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("create state dir: {e}"))?;
    let (mut tmp, tmp_name) =
        create_temp(dir, ".last-bundle-", ".tmp").map_err(|e| format!("create temp: {e}"))?;
    let mut cleanup = TempGuard::new(&tmp_name);
    tmp.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod temp: {e}"))?;
    tmp.write_all(&env)
        .map_err(|e| format!("write temp: {e}"))?;
    tmp.sync_all().map_err(|e| format!("fsync temp: {e}"))?;
    drop(tmp);
    std::fs::rename(&tmp_name, dir.join(BUNDLE_CACHE_FILE_NAME))
        .map_err(|e| format!("rename: {e}"))?;
    cleanup.keep();
    // Persist the rename itself; best effort.
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// One bundle that waits to be written.
struct PendingWrite {
    /// Its place in the order of queuing, from 1.
    ticket: u64,
    dir: PathBuf,
    bundle: Vec<u8>,
    generation: i64,
    /// When the bundle was applied, not when the disk got to it: the stale check reads it.
    saved_at: SystemTime,
}

#[derive(Default)]
struct WriterState {
    /// The newest bundle that no write has taken yet.
    pending: Option<PendingWrite>,
    /// The writer thread lives: it has a write to do or is doing one.
    busy: bool,
    /// How many bundles were queued; the newest holds this number as its ticket.
    queued: u64,
    /// Every bundle up to this ticket is written, replaced, or failed.
    done: u64,
}

struct WriterShared {
    state: Mutex<WriterState>,
    /// The writer moved `done` up.
    advanced: Condvar,
    write: CacheWrite,
}

/// Writes the bundle cache off the stream task. A single thread does the writes one after the
/// other, and it keeps only the newest bundle that waits: a bundle that arrives while a write runs
/// replaces the one that waits, so an older bundle never lands on the disk over a newer one and a
/// slow disk costs one write, not one per bundle. The thread exists only while there is something
/// to write.
#[derive(Clone)]
pub(crate) struct CacheWriter(Arc<WriterShared>);

impl CacheWriter {
    pub(crate) fn new(write: CacheWrite) -> CacheWriter {
        CacheWriter(Arc::new(WriterShared {
            state: Mutex::new(WriterState::default()),
            advanced: Condvar::new(),
            write,
        }))
    }

    /// Queues `bundle` and returns at once.
    pub(crate) fn submit(
        &self,
        dir: PathBuf,
        bundle: Vec<u8>,
        generation: i64,
        saved_at: SystemTime,
    ) {
        let mut state = self.0.state.lock().unwrap();
        state.queued += 1;
        let ticket = state.queued;
        state.pending = Some(PendingWrite {
            ticket,
            dir,
            bundle,
            generation,
            saved_at,
        });
        if state.busy {
            return;
        }
        let shared = self.0.clone();
        match std::thread::Builder::new()
            .name("bundle-cache".into())
            .spawn(move || write_pending(&shared))
        {
            Ok(_) => state.busy = true,
            Err(e) => {
                state.pending = None;
                state.done = ticket;
                self.0.advanced.notify_all();
                info!("[waf-bundle] cache write failed (bundle still applied): start writer: {e}");
            }
        }
    }

    /// Blocks until every bundle queued before the call is written, replaced, or failed. A bundle
    /// queued while it waits does not hold it, so a steady stream of bundles cannot stall a reload.
    pub(crate) fn finish(&self) {
        let mut state = self.0.state.lock().unwrap();
        let upto = state.queued;
        while state.done < upto {
            state = self.0.advanced.wait(state).unwrap();
        }
    }
}

/// The writer thread: takes the waiting bundle until none is left. A failed write is logged and
/// the next bundle writes again.
fn write_pending(shared: &WriterShared) {
    let mut state = shared.state.lock().unwrap();
    while let Some(w) = state.pending.take() {
        drop(state);
        let res = catch_unwind(AssertUnwindSafe(|| {
            (shared.write)(&w.dir, &w.bundle, w.generation, w.saved_at)
        }))
        .unwrap_or_else(|_| Err("the write panicked".into()));
        if let Err(e) = res {
            info!("[waf-bundle] cache write failed (bundle still applied): {e}");
        }
        state = shared.state.lock().unwrap();
        // The bundle taken was the newest queued, so its ticket covers the ones it replaced.
        state.done = w.ticket;
        shared.advanced.notify_all();
    }
    state.busy = false;
}

/// A new file `<prefix><random><suffix>` in `dir`, created exclusively (so never through a link)
/// with mode 0600 from the first moment: no other user can read it before anything is written.
pub fn create_temp(dir: &Path, prefix: &str, suffix: &str) -> std::io::Result<(File, PathBuf)> {
    for _ in 0..10_000 {
        let name = dir.join(format!("{prefix}{}{suffix}", random_u64() as u32));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&name)
        {
            Ok(f) => return Ok((f, name)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        ErrorKind::AlreadyExists,
        "too many temp file collisions",
    ))
}

/// Removes a temporary file when it drops, on every path out of the write that made it (an error
/// or a panic), unless `keep` says it was renamed into place.
#[must_use = "the temporary file is removed when the guard drops"]
pub struct TempGuard {
    path: PathBuf,
    keep: bool,
}

impl TempGuard {
    pub fn new(path: &Path) -> TempGuard {
        TempGuard {
            path: path.to_owned(),
            keep: false,
        }
    }

    /// The file is where it belongs now: leave it.
    pub fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Load and validate `dir/last-bundle.json`. `check` is the full bundle decode
/// ([`crate::BundleSink::check`]).
pub fn load_bundle_cache(
    dir: &Path,
    check: &dyn Fn(&[u8]) -> Result<(), String>,
) -> Result<CachedBundle, CacheReadError> {
    use CacheReadError::Invalid;
    let f = match File::open(dir.join(BUNDLE_CACHE_FILE_NAME)) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(CacheReadError::NotFound),
        Err(e) => return Err(Invalid(e.to_string())),
    };
    let mut data = Vec::new();
    f.take(MAX_BUNDLE_CACHE_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|e| Invalid(format!("read cache: {e}")))?;
    if data.len() as u64 > MAX_BUNDLE_CACHE_BYTES {
        return Err(Invalid("cache file exceeds size limit".into()));
    }
    let (mut version, mut saved_at, mut generation, mut bundle) =
        (0i64, Timestamp::ZERO, 0i64, Vec::new());
    let decode = |e: String| Invalid(format!("decode cache envelope: {e}"));
    for (k, v) in json_members::members(&data, "agent.bundleCacheEnvelope").map_err(decode)? {
        if json_members::key_matches(&k, "version") {
            if let Some(x) = json_members::int64(v, ENVELOPE, "version", "int").map_err(decode)? {
                version = x;
            }
        } else if json_members::key_matches(&k, "saved_at") {
            if let Some(s) = json_members::time_string(v).map_err(decode)? {
                saved_at = Timestamp::parse_rfc3339(s).map_err(decode)?;
            }
        } else if json_members::key_matches(&k, "generation") {
            if let Some(x) =
                json_members::int64(v, ENVELOPE, "generation", "int64").map_err(decode)?
            {
                generation = x;
            }
        } else if json_members::key_matches(&k, "bundle") {
            bundle = v.get().as_bytes().to_vec(); // "null" included
        }
    }
    if version != BUNDLE_CACHE_VERSION {
        return Err(Invalid(format!("unsupported cache version {version}")));
    }
    if bundle.is_empty() || saved_at.is_zero() {
        return Err(Invalid("cache envelope incomplete".into()));
    }
    // The full decode first: its error is the decoder's, the probe reads four fields.
    check(&bundle).map_err(|e| Invalid(format!("decode cached bundle: {e}")))?;
    let probe =
        BundleProbe::parse(&bundle).map_err(|e| Invalid(format!("decode cached bundle: {e}")))?;
    if probe.management_only || probe.unblock_entries > 0 {
        return Err(Invalid("cached bundle is a management command".into()));
    }
    if probe.generation != generation {
        return Err(Invalid("cached bundle generation mismatch".into()));
    }
    Ok(CachedBundle {
        bundle,
        generation,
        saved_at,
    })
}

impl ControlLink {
    fn bundle_cache_config(&self) -> (String, Duration) {
        let cfg = self.config();
        let max_age = if cfg.bundle_cache_max_age.is_zero() {
            DEFAULT_BUNDLE_CACHE_MAX_AGE
        } else {
            cfg.bundle_cache_max_age
        };
        (cfg.state_dir, max_age)
    }

    /// Provenance of the configuration in force: ("", 0) before any bundle.
    pub fn bundle_status(&self) -> (String, i64) {
        self.bundle_state.lock().unwrap().clone()
    }

    pub(crate) fn set_bundle_status(&self, source: &str, generation: i64) {
        *self.bundle_state.lock().unwrap() = (source.to_string(), generation);
    }

    /// A readable cached bundle exists, so startup may tolerate an unreachable control
    /// plane.
    pub fn is_cached_bundle_usable(&self) -> bool {
        let (dir, _) = self.bundle_cache_config();
        !dir.is_empty() && load_bundle_cache(Path::new(&dir), &|b| self.sink().check(b)).is_ok()
    }

    /// Hands the applied bundle to the cache writer and returns at once, so the ack does not wait
    /// for the disk. A failed write is logged, never fatal.
    pub(crate) fn queue_applied_bundle(&self, bundle: &[u8], generation: i64) {
        let (dir, _) = self.bundle_cache_config();
        if dir.is_empty() {
            return;
        }
        self.cache_writer.submit(
            PathBuf::from(&dir),
            bundle.to_vec(),
            generation,
            SystemTime::now(),
        );
    }

    /// Returns once every bundle queued before the call is on the disk (or one that replaced it is),
    /// or its write failed; later bundles do not hold it. The agent calls it before it starts a
    /// successor and before it ends, since both read the cache next.
    pub async fn finish_cache_write(&self) {
        let writer = self.cache_writer.clone();
        let _ = tokio::task::spawn_blocking(move || writer.finish()).await;
    }

    /// [`ControlLink::finish_cache_write`] for a caller with no runtime left: an apply still running
    /// when the runtime drops finishes during the drop and queues its write after the last async wait.
    pub fn finish_cache_write_blocking(&self) {
        self.cache_writer.finish();
    }

    /// Apply the cached bundle, if any, through the sink. Run before the stream starts so a live
    /// bundle always wins ([`ControlLink::start`] does). Blocking.
    pub fn install_cached_bundle(&self) -> CacheStart {
        let (dir, _) = self.bundle_cache_config();
        if dir.is_empty() {
            return CacheStart::NotApplied;
        }
        let c = match load_bundle_cache(Path::new(&dir), &|b| self.sink().check(b)) {
            Ok(c) => c,
            Err(CacheReadError::NotFound) => return CacheStart::NotApplied,
            Err(e) => {
                info!(
                    "[waf-bundle] ignoring cached bundle {}: {e}",
                    Path::new(&dir).join(BUNDLE_CACHE_FILE_NAME).display()
                );
                return CacheStart::NotApplied;
            }
        };
        match self.apply_cached_bundle(&c) {
            Ok(()) => CacheStart::Applied,
            Err(BundleError::Bind(e)) => {
                info!(
                    "[waf-bundle] cached bundle generation {} not applied: {e} (retrying)",
                    c.generation
                );
                CacheStart::Bind(c)
            }
            Err(e) => {
                info!(
                    "[waf-bundle] cached bundle generation {} not applied: {e}",
                    c.generation
                );
                CacheStart::NotApplied
            }
        }
    }

    /// Hands a cached bundle to the sink and, once it is in force, records where the configuration
    /// came from.
    pub(crate) fn apply_cached_bundle(&self, c: &CachedBundle) -> Result<(), BundleError> {
        let (_, max_age) = self.bundle_cache_config();
        let probe = BundleProbe::parse(&c.bundle).unwrap_or_default();
        self.hand_bundle_to_sink(&c.bundle, c.generation, &probe)?;
        let age = c.saved_at.nanos_until(SystemTime::now());
        let max = duration_nanos(max_age);
        let source = if age > max {
            info!(
                "[waf-bundle] WARNING: cached bundle generation {} is {} old (max {}); serving it until the control plane is reachable",
                c.generation,
                whole_seconds_text(round_nanos(age, 60_000_000_000)),
                whole_seconds_text(max)
            );
            BUNDLE_SOURCE_CACHE_STALE
        } else {
            info!(
                "[waf-bundle] started from cached bundle generation {} (saved {} ago)",
                c.generation,
                whole_seconds_text(round_nanos(age, 1_000_000_000))
            );
            BUNDLE_SOURCE_CACHE
        };
        self.set_bundle_status(source, c.generation);
        *self.last_gen.lock().unwrap() = c.generation;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(_: &[u8]) -> Result<(), String> {
        Ok(())
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "wafio-cache-{tag}-{}-{}",
            std::process::id(),
            random_u64()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn bundle(generation: i64) -> Vec<u8> {
        format!(r#"{{"agent_id":"a","generation":{generation},"apps":[]}}"#).into_bytes()
    }

    /// A cache write that a test holds back: it notes the generation it was asked to write, waits
    /// until the test lets it go, and then writes the file as the agent does.
    #[derive(Default)]
    struct Held {
        started: Mutex<Vec<i64>>,
        open: Mutex<bool>,
        opened: Condvar,
    }

    impl Held {
        fn writer(self: &Arc<Self>) -> CacheWrite {
            let held = self.clone();
            Arc::new(
                move |dir: &Path, bundle: &[u8], generation: i64, now: SystemTime| {
                    held.started.lock().unwrap().push(generation);
                    let mut open = held.open.lock().unwrap();
                    while !*open {
                        let (guard, wait) = held
                            .opened
                            .wait_timeout(open, Duration::from_secs(30))
                            .unwrap();
                        open = guard;
                        if wait.timed_out() {
                            return Err("the test never let the write go".into());
                        }
                    }
                    drop(open);
                    save_bundle_cache(dir, bundle, generation, now)
                },
            )
        }

        fn let_go(&self) {
            *self.open.lock().unwrap() = true;
            self.opened.notify_all();
        }

        /// Waits until `n` writes have started.
        fn wait_started(&self, n: usize) {
            let end = std::time::Instant::now() + Duration::from_secs(30);
            while self.started.lock().unwrap().len() < n {
                assert!(std::time::Instant::now() < end, "{n} writes did not start");
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn started(&self) -> Vec<i64> {
            self.started.lock().unwrap().clone()
        }
    }

    // The bundle that waits for a write that runs is replaced by a newer one: the older one is never
    // written, so it cannot land on the disk over the newer one.
    #[test]
    fn a_bundle_that_arrives_during_a_write_replaces_the_one_that_waits() {
        let dir = tmpdir("newest");
        let held = Arc::new(Held::default());
        let writer = CacheWriter::new(held.writer());
        let at = SystemTime::now();
        writer.submit(dir.clone(), bundle(1), 1, at);
        held.wait_started(1);
        writer.submit(dir.clone(), bundle(2), 2, at);
        writer.submit(dir.clone(), bundle(3), 3, at);
        held.let_go();
        writer.finish();
        assert_eq!(held.started(), [1, 3], "generation 2 was never written");
        assert_eq!(load_bundle_cache(&dir, &ok).unwrap().generation, 3);
        std::fs::remove_dir_all(dir).unwrap();
    }

    // Real writes, one after the other as fast as they come: whatever the writer takes, the last
    // bundle is the one on the disk.
    #[test]
    fn a_burst_of_bundles_leaves_the_last_one_on_disk() {
        let dir = tmpdir("burst");
        let writer = CacheWriter::new(Arc::new(save_bundle_cache));
        for generation in 1..=300 {
            writer.submit(
                dir.clone(),
                bundle(generation),
                generation,
                SystemTime::now(),
            );
        }
        writer.finish();
        assert_eq!(load_bundle_cache(&dir, &ok).unwrap().generation, 300);
        std::fs::remove_dir_all(dir).unwrap();
    }

    // `finish` does not return while a write runs or waits: when it does, the file is there.
    #[test]
    fn finish_returns_only_once_the_write_is_on_the_disk() {
        let dir = tmpdir("finish");
        let held = Arc::new(Held::default());
        let writer = CacheWriter::new(held.writer());
        writer.submit(dir.clone(), bundle(1), 1, SystemTime::now());
        held.wait_started(1);
        writer.submit(dir.clone(), bundle(2), 2, SystemTime::now());
        let h = held.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            h.let_go();
        });
        writer.finish();
        assert_eq!(
            load_bundle_cache(&dir, &ok).unwrap().generation,
            2,
            "finish waited for the write that runs and the one behind it"
        );
        // With nothing left it returns at once.
        writer.finish();
        std::fs::remove_dir_all(dir).unwrap();
    }

    // A bundle queued after the call must not hold `finish`. The feeder queues faster than a write
    // ends, so the writer never runs out of work.
    #[test]
    fn finish_does_not_wait_for_bundles_that_arrive_after_the_call() {
        let dir = tmpdir("keeps-coming");
        let writer = CacheWriter::new(Arc::new(
            |dir: &Path, bundle: &[u8], generation: i64, now: SystemTime| {
                std::thread::sleep(Duration::from_millis(20));
                save_bundle_cache(dir, bundle, generation, now)
            },
        ));
        writer.submit(dir.clone(), bundle(1), 1, SystemTime::now());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let feeder = {
            let (writer, dir, stop) = (writer.clone(), dir.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut generation = 2;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    writer.submit(
                        dir.clone(),
                        bundle(generation),
                        generation,
                        SystemTime::now(),
                    );
                    generation += 1;
                    std::thread::sleep(Duration::from_millis(5));
                }
                generation - 1
            })
        };
        let (done, returned) = std::sync::mpsc::channel();
        let waiting = writer.clone();
        std::thread::spawn(move || {
            waiting.finish();
            let _ = done.send(());
        });
        let returned = returned.recv_timeout(Duration::from_secs(10));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let last = feeder.join().unwrap();
        assert!(
            returned.is_ok(),
            "finish kept waiting for bundles that arrived after the call"
        );
        assert!(load_bundle_cache(&dir, &ok).is_ok());
        writer.finish();
        assert_eq!(load_bundle_cache(&dir, &ok).unwrap().generation, last);
        std::fs::remove_dir_all(dir).unwrap();
    }

    // A write that fails, or panics, costs that bundle only: the writer takes the next one.
    #[test]
    fn a_failed_write_leaves_the_writer_ready_for_the_next_bundle() {
        let dir = tmpdir("fails");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n = calls.clone();
        let writer = CacheWriter::new(Arc::new(
            move |dir: &Path, bundle: &[u8], generation: i64, now: SystemTime| match n
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            {
                0 => Err("disk full".into()),
                1 => panic!("write panicked"),
                _ => save_bundle_cache(dir, bundle, generation, now),
            },
        ));
        for generation in 1..=2 {
            writer.submit(
                dir.clone(),
                bundle(generation),
                generation,
                SystemTime::now(),
            );
            writer.finish();
            assert!(
                matches!(load_bundle_cache(&dir, &ok), Err(CacheReadError::NotFound)),
                "nothing was written for generation {generation}"
            );
        }
        writer.submit(dir.clone(), bundle(3), 3, SystemTime::now());
        writer.finish();
        assert_eq!(load_bundle_cache(&dir, &ok).unwrap().generation, 3);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        std::fs::remove_dir_all(dir).unwrap();
    }

    // The process can end after the ack and before the write: what is on the disk then is the
    // earlier cache, whole, and nothing else.
    #[test]
    fn the_earlier_cache_stays_readable_while_a_write_is_pending() {
        let dir = tmpdir("pending");
        save_bundle_cache(&dir, &bundle(1), 1, SystemTime::now()).unwrap();
        let held = Arc::new(Held::default());
        let writer = CacheWriter::new(held.writer());
        writer.submit(dir.clone(), bundle(2), 2, SystemTime::now());
        held.wait_started(1);
        assert_eq!(load_bundle_cache(&dir, &ok).unwrap().generation, 1);
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [BUNDLE_CACHE_FILE_NAME]);
        held.let_go();
        writer.finish();
        assert_eq!(load_bundle_cache(&dir, &ok).unwrap().generation, 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn round_trip_mode_and_no_leftovers() {
        let dir = tmpdir("rt");
        let raw = br#"{"agent_id":"a","generation":1,"apps":[{"app_id":"x"}],"rules_json":{"thresholds":{"block":150}}}"#;
        save_bundle_cache(&dir, raw, 42, SystemTime::now()).unwrap();
        let path = dir.join(BUNDLE_CACHE_FILE_NAME);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name() != BUNDLE_CACHE_FILE_NAME)
            .collect();
        assert!(left.is_empty(), "{left:?}");
        let c = load_bundle_cache(&dir, &ok).unwrap();
        assert_eq!(c.generation, 42);
        assert_eq!(BundleProbe::parse(&c.bundle).unwrap().generation, 42);
        assert!(
            String::from_utf8_lossy(&c.bundle)
                .contains(r#""rules_json":{"thresholds":{"block":150}}"#)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn envelope_bytes_match_recorded_layout() {
        let dir = tmpdir("bytes");
        let t = Timestamp::parse_rfc3339("2026-11-12T10:00:00.1234Z").unwrap();
        let now = std::time::UNIX_EPOCH + Duration::new(t.unix as u64, t.nanos);
        save_bundle_cache(
            &dir,
            br#"{"agent_id":"a","generation":7,"apps":null}"#,
            7,
            now,
        )
        .unwrap();
        let got = std::fs::read_to_string(dir.join(BUNDLE_CACHE_FILE_NAME)).unwrap();
        assert_eq!(
            got,
            r#"{"version":1,"saved_at":"2026-11-12T10:00:00.1234Z","generation":7,"bundle":{"agent_id":"a","generation":7,"apps":null}}"#
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    // Corrupt, truncated, foreign or management-only caches are ignored.
    #[test]
    fn corrupt_cached_bundle_ignored() {
        let dir = tmpdir("corrupt");
        let path = dir.join(BUNDLE_CACHE_FILE_NAME);
        let valid = |b: &str, g: i64| {
            format!(
                r#"{{"version":1,"saved_at":"2026-09-28T00:00:00Z","generation":{g},"bundle":{b}}}"#
            )
        };
        let cases = [
            ("garbage", "not json at all".to_string()),
            ("truncated", valid(r#"{"generation":3,"apps":[]}"#, 3)[..30].to_string()),
            ("empty", String::new()),
            ("wrong version", r#"{"version":99,"saved_at":"2026-09-28T00:00:00Z","generation":3,"bundle":{"generation":3}}"#.into()),
            ("no bundle", r#"{"version":1,"saved_at":"2026-09-28T00:00:00Z","generation":3}"#.into()),
            ("no timestamp", r#"{"version":1,"generation":3,"bundle":{"generation":3}}"#.into()),
            ("zero timestamp", valid(r#"{"generation":3}"#, 3).replace("2026-09-28", "0001-01-01")),
            ("bundle not object", valid("[1,2,3]", 3)),
            ("generation mismatch", valid(r#"{"generation":4,"apps":[]}"#, 3)),
            ("management only", valid(r#"{"generation":3,"management_only":true}"#, 3)),
            ("unblock entries", valid(r#"{"generation":3,"unblock_entries":[{"type":"blockpolicy","key":"1.2.3.4"}]}"#, 3)),
        ];
        for (name, content) in cases {
            std::fs::write(&path, content).unwrap();
            assert!(
                matches!(
                    load_bundle_cache(&dir, &ok),
                    Err(CacheReadError::Invalid(_))
                ),
                "{name}"
            );
        }
        std::fs::write(&path, valid(r#"{"generation":3}"#, 3)).unwrap();
        assert!(
            load_bundle_cache(&dir, &|_| Err("bad app".into())).is_err(),
            "full decode check"
        );
        assert!(load_bundle_cache(&dir, &ok).is_ok());
        // Fields match case-insensitively, `null` keeps a value.
        std::fs::write(&path, r#"{"VERSION":1,"Saved_At":"2026-09-28T07:00:00+07:00","generation":3,"generation":null,"Bundle":{"Generation":3}}"#).unwrap();
        let c = load_bundle_cache(&dir, &ok).unwrap();
        assert_eq!(
            (c.generation, c.saved_at.format_rfc3339()),
            (3, "2026-09-28T00:00:00Z".to_string())
        );
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            load_bundle_cache(&dir, &ok),
            Err(CacheReadError::NotFound)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// What the log line "ignoring cached bundle …" says: the decode texts for the envelope and
    /// the bundle.
    #[test]
    fn cache_errors_carry_decode_texts() {
        let dir = tmpdir("texts");
        let path = dir.join(BUNDLE_CACHE_FILE_NAME);
        let env = |bundle: &str| {
            format!(
                r#"{{"version":1,"saved_at":"2026-09-28T00:00:00Z","generation":3,"bundle":{bundle}}}"#
            )
        };
        for (content, want) in [
            (
                r#"{"version":"1"}"#.to_string(),
                "decode cache envelope: version: expected an integer, got a string",
            ),
            (
                "[1]".into(),
                "decode cache envelope: expected an object, got an array",
            ),
            (
                r#"{"generation":1.5}"#.into(),
                "decode cache envelope: generation: expected an integer, got the number 1.5",
            ),
            (
                r#"{"saved_at":5}"#.into(),
                "decode cache envelope: expected a string with a timestamp",
            ),
            (
                "{\"version\":1".into(),
                "decode cache envelope: unexpected end of JSON input",
            ),
            (
                env(r#"{"generation":"3"}"#),
                "decode cached bundle: generation: expected an integer, got a string",
            ),
            (
                env("[1]"),
                "decode cached bundle: expected an object, got an array",
            ),
        ] {
            std::fs::write(&path, &content).unwrap();
            let e = load_bundle_cache(&dir, &ok).unwrap_err();
            assert_eq!(e.to_string(), want, "{content}");
        }
        // The full decode runs first: its error wins over the probe's.
        std::fs::write(&path, env(r#"{"generation":"3"}"#)).unwrap();
        let e = load_bundle_cache(&dir, &|_| Err("first error".into())).unwrap_err();
        assert_eq!(e.to_string(), "decode cached bundle: first error");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A cache file written by the previous agent.
    #[test]
    fn reads_cache_written_by_the_previous_agent() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go-cache");
        let c = load_bundle_cache(&dir, &ok).unwrap();
        assert_eq!(c.generation, 42);
        assert_eq!(
            c.saved_at.format_rfc3339_nano(),
            "2026-11-12T10:00:00.123456789Z"
        );
        let p = BundleProbe::parse(&c.bundle).unwrap();
        assert_eq!((p.generation, p.apps, p.management_only), (42, 2, false));
        // Rewriting it gives the same bytes.
        let out = tmpdir("go");
        let now = std::time::UNIX_EPOCH + Duration::new(c.saved_at.unix as u64, c.saved_at.nanos);
        save_bundle_cache(&out, &c.bundle, c.generation, now).unwrap();
        assert_eq!(
            std::fs::read(out.join(BUNDLE_CACHE_FILE_NAME)).unwrap(),
            std::fs::read(dir.join(BUNDLE_CACHE_FILE_NAME)).unwrap()
        );
        std::fs::remove_dir_all(out).unwrap();
    }
}
