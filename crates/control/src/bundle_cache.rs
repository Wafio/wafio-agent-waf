//! The last applied live bundle is kept in `<state dir>/last-bundle.json` (temp file + fsync +
//! rename, mode 0600) and applied at start before the stream connects, so a restart while the
//! control plane is unreachable still serves the apps. The heartbeat reports where the
//! configuration in force came from (`live` | `cache` | `cache_stale`). The envelope is the
//! format earlier agent versions wrote and read, in both directions.

use crate::bundle_puller::BundleProbe;
use crate::grpc_reconnect::random_u64;
use crate::grpc_stream::ControlLink;
use crate::json_members;
use crate::timestamp::{Timestamp, duration_nanos, round_nanos, whole_seconds_text};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
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

/// A cache file that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedBundle {
    /// The bundle JSON as applied (generation embedded), verbatim from the file.
    pub bundle: Vec<u8>,
    pub generation: i64,
    pub saved_at: Timestamp,
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
    let (mut tmp, tmp_name) = create_temp(dir).map_err(|e| format!("create temp: {e}"))?;
    struct Cleanup<'a>(&'a Path, bool);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            if !self.1 {
                let _ = std::fs::remove_file(self.0);
            }
        }
    }
    let mut cleanup = Cleanup(&tmp_name, false);
    tmp.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod temp: {e}"))?;
    tmp.write_all(&env)
        .map_err(|e| format!("write temp: {e}"))?;
    tmp.sync_all().map_err(|e| format!("fsync temp: {e}"))?;
    drop(tmp);
    std::fs::rename(&tmp_name, dir.join(BUNDLE_CACHE_FILE_NAME))
        .map_err(|e| format!("rename: {e}"))?;
    cleanup.1 = true;
    // Persist the rename itself; best effort.
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// A new temporary file `.last-bundle-*.tmp` in `dir`, created exclusively with mode 0600.
fn create_temp(dir: &Path) -> std::io::Result<(File, std::path::PathBuf)> {
    for _ in 0..10_000 {
        let name = dir.join(format!(".last-bundle-{}.tmp", random_u64() as u32));
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

    /// Persists the applied bundle: failure is logged, never fatal.
    pub(crate) fn save_applied_bundle(&self, bundle: &[u8], generation: i64) {
        let (dir, _) = self.bundle_cache_config();
        if dir.is_empty() {
            return;
        }
        if let Err(e) = save_bundle_cache(Path::new(&dir), bundle, generation, SystemTime::now()) {
            info!("[waf-bundle] cache write failed (bundle still applied): {e}");
        }
    }

    /// Apply the cached bundle, if any, through the sink; true when one was applied. Run before
    /// the stream starts so a live bundle always wins ([`ControlLink::start`] does). Blocking.
    pub fn install_cached_bundle(&self) -> bool {
        let (dir, max_age) = self.bundle_cache_config();
        if dir.is_empty() {
            return false;
        }
        let c = match load_bundle_cache(Path::new(&dir), &|b| self.sink().check(b)) {
            Ok(c) => c,
            Err(CacheReadError::NotFound) => return false,
            Err(e) => {
                info!(
                    "[waf-bundle] ignoring cached bundle {}: {e}",
                    Path::new(&dir).join(BUNDLE_CACHE_FILE_NAME).display()
                );
                return false;
            }
        };
        let probe = BundleProbe::parse(&c.bundle).unwrap_or_default();
        if let Err(e) = self.hand_bundle_to_sink(&c.bundle, c.generation, &probe) {
            info!(
                "[waf-bundle] cached bundle generation {} not applied: {e}",
                c.generation
            );
            return false;
        }
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
        true
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
