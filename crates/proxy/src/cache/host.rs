//! What the host allows the cache: free space under the cache directory and memory, the
//! refusals the agent reports when settings ask for more, and the checks of the directory itself.

use std::fs::Permissions;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Why the cache of an app, or all of them, is not applied. `as_str` is the code of
/// `EdgeFeatureState`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheRefusalCode {
    /// A setting that is not valid, or an app id that cannot name a directory.
    Invalid,
    /// The cache directory cannot be used: the cache stays off.
    DirUnusable,
    DiskTooSmall,
    MemoryTooSmall,
}

impl CacheRefusalCode {
    pub fn as_str(self) -> &'static str {
        match self {
            CacheRefusalCode::Invalid => "invalid",
            CacheRefusalCode::DirUnusable => "cache_dir_unusable",
            CacheRefusalCode::DiskTooSmall => "disk_too_small",
            CacheRefusalCode::MemoryTooSmall => "memory_too_small",
        }
    }
}

/// A refusal and what the control plane shows with it. For `DiskTooSmall` the detail is
/// `"<allowed bytes> <asked bytes>"`, for `MemoryTooSmall` `"<the host's memory in bytes>"`: decimal
/// digits, no unit. For `Invalid` the name of the setting, and for `DirUnusable` the reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheRefusal {
    pub code: CacheRefusalCode,
    pub detail: String,
}

impl CacheRefusal {
    pub(crate) fn new(code: CacheRefusalCode, detail: impl Into<String>) -> CacheRefusal {
        let mut detail: String = detail.into();
        // The control plane shows at most 256 bytes and no control character.
        detail = detail
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect();
        while detail.len() > 256 {
            detail.pop();
        }
        CacheRefusal { code, detail }
    }
}

/// What the host has, as the checks of an apply read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostFacts {
    /// Bytes the file system under the cache directory has free for this user.
    pub free_bytes: u64,
    /// The size of that file system.
    pub fs_bytes: u64,
    /// The host's memory, or the limit of the cgroup the agent runs in when that is lower.
    pub memory_bytes: u64,
}

/// The most digits a number in a detail has.
const DETAIL_NUMBER_MAX: u64 = 999_999_999_999_999;

impl HostFacts {
    /// Reads the host: `statvfs` of the directory, `/proc/meminfo` and the cgroup's `memory.max`.
    #[allow(clippy::useless_conversion)] // the statvfs counts are u64 on this target, other widths elsewhere
    pub fn read(dir: &Path) -> std::io::Result<HostFacts> {
        let stat = nix::sys::statvfs::statvfs(dir).map_err(std::io::Error::from)?;
        let unit = u64::from(stat.fragment_size());
        let facts = HostFacts {
            free_bytes: u64::from(stat.blocks_available()).saturating_mul(unit),
            fs_bytes: u64::from(stat.blocks()).saturating_mul(unit),
            memory_bytes: host_memory().unwrap_or(0),
        };
        Ok(facts)
    }

    /// Checks the sums of the settings against the host. `in_use` is what the cache already holds
    /// on disk (it can be evicted, so it counts as free). The disk may be filled to 95 % of the
    /// file system; memory for the hot copies may be a quarter of the host's.
    pub fn check(
        &self,
        in_use: u64,
        disk_total: u64,
        memory_total: u64,
    ) -> Result<(), CacheRefusal> {
        let allowed = self
            .free_bytes
            .saturating_add(in_use)
            .saturating_sub(self.fs_bytes / 20);
        if disk_total > allowed {
            return Err(CacheRefusal::new(
                CacheRefusalCode::DiskTooSmall,
                format!(
                    "{} {}",
                    allowed.min(DETAIL_NUMBER_MAX),
                    disk_total.min(DETAIL_NUMBER_MAX)
                ),
            ));
        }
        if self.memory_bytes > 0 && memory_total > self.memory_bytes / 4 {
            return Err(CacheRefusal::new(
                CacheRefusalCode::MemoryTooSmall,
                self.memory_bytes.min(DETAIL_NUMBER_MAX).to_string(),
            ));
        }
        Ok(())
    }
}

/// `MemTotal` of `/proc/meminfo`, lowered to the `memory.max` of the agent's cgroup (v2) when that
/// is a number.
fn host_memory() -> Option<u64> {
    let total = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            let line = s.lines().find(|l| l.starts_with("MemTotal:"))?;
            let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
            kib.checked_mul(1024)
        })?;
    Some(cgroup_memory_max().map_or(total, |max| max.min(total)))
}

fn cgroup_memory_max() -> Option<u64> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    [format!("/sys/fs/cgroup{path}"), "/sys/fs/cgroup".into()]
        .iter()
        .find_map(|base| std::fs::read_to_string(format!("{base}/memory.max")).ok())
        .and_then(|s| s.trim().parse().ok())
}

/// The folder of the unit's state, which the host agent keeps every open of in its trace ring.
const STATE_DIR: &str = "/var/lib/wafio-waf-agent";

/// Whether `path` is the canonical, absolute form of itself: no empty, `.` or `..` segment and no
/// trailing `/`. The host agent sheds the opens of the cache directory only for a path like that.
fn canonical_absolute(path: &Path) -> bool {
    path.to_str().is_some_and(|text| {
        text.len() > 1
            && text.starts_with('/')
            && text[1..]
                .split('/')
                .all(|segment| !matches!(segment, "" | "." | ".."))
    })
}

fn under(path: &Path, base: &str) -> bool {
    path.starts_with(base)
}

/// Checks the cache directory: a canonical absolute path, not the state folder or below it, a real
/// directory (not a link) owned by `uid`. Group and other bits are cleared. The directory is made
/// by the unit, not by the agent.
pub(crate) fn check_dir(path: &Path, uid: u32) -> Result<(), String> {
    let shown = path.display();
    if !canonical_absolute(path) {
        return Err(format!("{shown}: not a canonical absolute path"));
    }
    if under(path, STATE_DIR) {
        return Err(format!("{shown}: below the state directory {STATE_DIR}"));
    }
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("{shown}: cannot stat ({})", e.kind()))?;
    if !meta.is_dir() {
        return Err(format!("{shown}: not a directory"));
    }
    if meta.uid() != uid {
        return Err(format!(
            "{shown}: owned by user {}, not by user {uid}",
            meta.uid()
        ));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        std::fs::set_permissions(path, Permissions::from_mode(mode & !0o077)).map_err(|e| {
            format!(
                "{shown}: cannot clear group and other access ({})",
                e.kind()
            )
        })?;
        tracing::info!(
            "[cache] directory {shown}: group and other access cleared (mode was {mode:04o})"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn facts(free: u64, fs: u64, memory: u64) -> HostFacts {
        HostFacts {
            free_bytes: free,
            fs_bytes: fs,
            memory_bytes: memory,
        }
    }

    #[test]
    fn the_disk_sum_may_fill_the_file_system_to_ninety_five_percent() {
        // 100 GiB file system, 10 GiB free: 5 GiB stay free, so 5 GiB may be asked for.
        let f = facts(10 * GIB, 100 * GIB, 64 * GIB);
        assert!(f.check(0, 5 * GIB, 0).is_ok());
        let refused = f.check(0, 5 * GIB + 1, 0).unwrap_err();
        assert_eq!(refused.code, CacheRefusalCode::DiskTooSmall);
        assert_eq!(refused.detail, format!("{} {}", 5 * GIB, 5 * GIB + 1));
        // What the cache holds already counts as free: it can be evicted.
        assert!(f.check(3 * GIB, 8 * GIB, 0).is_ok());
        assert!(f.check(3 * GIB, 8 * GIB + 1, 0).is_err());
        // Already past the line: nothing may be asked for.
        let full = facts(GIB, 100 * GIB, 64 * GIB);
        assert_eq!(full.check(0, 1, 0).unwrap_err().detail, "0 1");
    }

    #[test]
    fn the_memory_sum_may_be_a_quarter_of_the_hosts() {
        let f = facts(100 * GIB, 100 * GIB, 8 * GIB);
        assert!(f.check(0, 0, 2 * GIB).is_ok());
        let refused = f.check(0, 0, 2 * GIB + 1).unwrap_err();
        assert_eq!(refused.code, CacheRefusalCode::MemoryTooSmall);
        assert_eq!(refused.detail, (8 * GIB).to_string());
        // A host whose memory could not be read is not a reason to refuse.
        assert!(
            facts(100 * GIB, 100 * GIB, 0)
                .check(0, 0, 100 * GIB)
                .is_ok()
        );
    }

    #[test]
    fn the_numbers_of_a_detail_have_at_most_fifteen_digits() {
        let f = facts(u64::MAX / 2, u64::MAX / 2, u64::MAX);
        let refused = f.check(0, u64::MAX, 0).unwrap_err();
        let (allowed, asked) = refused.detail.split_once(' ').unwrap();
        assert!(
            allowed.len() <= 15 && asked.len() <= 15,
            "{}",
            refused.detail
        );
        let refused = f.check(0, 0, u64::MAX).unwrap_err();
        assert!(refused.detail.len() <= 15);
    }

    #[test]
    fn a_detail_is_cut_and_cleaned_for_the_control_plane() {
        let r = CacheRefusal::new(
            CacheRefusalCode::DirUnusable,
            format!("a\u{7}b{}", "x".repeat(400)),
        );
        assert_eq!(r.detail.len(), 256);
        assert!(r.detail.starts_with("a?b"));
        for (code, text) in [
            (CacheRefusalCode::Invalid, "invalid"),
            (CacheRefusalCode::DirUnusable, "cache_dir_unusable"),
            (CacheRefusalCode::DiskTooSmall, "disk_too_small"),
            (CacheRefusalCode::MemoryTooSmall, "memory_too_small"),
        ] {
            assert_eq!(code.as_str(), text);
        }
    }

    #[test]
    fn the_host_is_read_from_the_system() {
        let dir = std::env::temp_dir();
        let f = HostFacts::read(&dir).unwrap();
        assert!(f.fs_bytes > 0 && f.free_bytes <= f.fs_bytes);
        assert!(f.memory_bytes > 0);
        assert!(HostFacts::read(Path::new("/no/such/dir")).is_err());
    }

    #[test]
    fn only_a_canonical_absolute_path_below_no_state_folder_is_a_cache_directory() {
        let uid = nix::unistd::geteuid().as_raw();
        for bad in [
            "relative/dir",
            "/",
            "/var/cache//wafio-waf",
            "/var/cache/./wafio-waf",
            "/var/cache/wafio-waf/../x",
            "/var/cache/wafio-waf/",
        ] {
            let err = check_dir(Path::new(bad), uid).unwrap_err();
            assert!(err.contains("canonical absolute"), "{bad}: {err}");
        }
        for bad in [
            "/var/lib/wafio-waf-agent",
            "/var/lib/wafio-waf-agent/cache",
            "/var/lib/wafio-waf-agent/tls/x",
        ] {
            let err = check_dir(Path::new(bad), uid).unwrap_err();
            assert!(err.contains("state directory"), "{bad}: {err}");
        }
        // Look-alikes of the state folder are fine as paths (they fail later, as missing).
        let err = check_dir(Path::new("/var/lib/wafio-waf-agent2"), uid).unwrap_err();
        assert!(err.contains("cannot stat"), "{err}");
    }

    #[test]
    fn a_directory_must_be_a_real_directory_of_the_user_and_is_made_private() {
        let base = std::env::temp_dir().join(format!("wafio-cache-host-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let base = base.canonicalize().unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        let dir = base.join("cache");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, Permissions::from_mode(0o755)).unwrap();
        check_dir(&dir, uid).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        // Another owner, a file, a link and a missing directory.
        assert!(
            check_dir(&dir, uid.wrapping_add(1))
                .unwrap_err()
                .contains("owned by user")
        );
        let file = base.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(
            check_dir(&file, uid)
                .unwrap_err()
                .contains("not a directory")
        );
        let link = base.join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(
            check_dir(&link, uid)
                .unwrap_err()
                .contains("not a directory")
        );
        assert!(
            check_dir(&base.join("missing"), uid)
                .unwrap_err()
                .contains("cannot stat")
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
