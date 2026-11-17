//! The agent's side of the security data hooks (malware snapshot install and security data fetch).

use std::path::Path;
use std::sync::Mutex;

use wafio_control::{FetchResult, MAX_MALWARE_SNAPSHOT_BYTES, SecurityData};

/// Lexically cleans a Unix path.
pub fn normalize_path(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|l| *l != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            s => out.push(s),
        }
    }
    let joined = out.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

pub fn final_component(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let t = p.trim_end_matches('/');
    if t.is_empty() {
        return "/".into();
    }
    t.rsplit('/').next().unwrap_or(t).to_string()
}

pub fn parent_directory(p: &str) -> String {
    let i = p.rfind('/').map_or(0, |i| i + 1);
    normalize_path(&p[..i])
}

/// The security-data directory that a deprecated `--crs-default-dir` value implies. Version 1 installs wrote
/// `<base>/crs`, `<base>/crs/coreruleset` or `<base>/crs/coreruleset/rules`: this strips `rules`, `coreruleset`, `crs`.
pub fn security_data_dir_from_legacy_setting(d: &str) -> String {
    let mut d = normalize_path(d);
    if final_component(&d) == "rules" {
        d = parent_directory(&d);
    }
    if final_component(&d) == "crs" {
        return parent_directory(&d);
    }
    parent_directory(&parent_directory(&d))
}

/// The agent's [`SecurityData`]: malware snapshots from the control plane and on-demand
/// downloads (`FetchSecurityData`).
pub struct AgentSecurityData;

static MALWARE_SNAPSHOT_LOCK: Mutex<()> = Mutex::new(());

impl SecurityData for AgentSecurityData {
    fn replace_malware_snapshot(&self, dir: &Path, data: Vec<u8>) -> Result<(), String> {
        replace_malware_snapshot(dir, &data)?;
        // The installed file replaces the default engine's snapshot; a
        // file that fails there keeps the last good one and the error is the sync's.
        let path = dir.join("malware").join("malware_hashes.txt");
        wafio_malware::reload_default_engine(&[&path.to_string_lossy()])
    }

    fn download_components(&self, dir: &Path, only: &[String], force: bool) -> Vec<FetchResult> {
        let cfg = crate::setup::FetchOptions {
            dir: dir.to_string_lossy().into_owned(),
            only: only.to_vec(),
            force,
            ..Default::default()
        };
        crate::setup::download_components(&cfg)
            .into_iter()
            .map(|r| FetchResult {
                component: r.component,
                error: r.error,
            })
            .collect()
    }
}

/// Validates the whole corpus, keeps the old file as
/// `.previous`, replaces atomically. Never replaces the last good data on a bad snapshot.
pub fn replace_malware_snapshot(dir: &Path, data: &[u8]) -> Result<(), String> {
    let _g = MALWARE_SNAPSHOT_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if data.is_empty() || data.len() > MAX_MALWARE_SNAPSHOT_BYTES {
        return Err("incomplete or oversized malware snapshot".into());
    }
    // bloom.NewMalwareHashEngine(1024, .0001).LoadFromTextReader: every record validated first.
    match wafio_malware::HashMatcher::new(1024, 0.0001).load_text(&mut &data[..]) {
        Ok(n) if n > 0 => {}
        _ => return Err("invalid malware snapshot".into()),
    }
    let dir = dir.join("malware");
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let path = dir.join("malware_hashes.txt");
    let old = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("open {}: {e}", path.display())),
    };
    if old == data {
        return Ok(());
    }
    if !old.is_empty() {
        crate::setup::write_atomic(&dir.join("malware_hashes.txt.previous"), &old)?;
    }
    crate::setup::write_atomic(&path, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_setting_values_of_earlier_installs_give_the_data_directory() {
        for legacy in [
            "/etc/wafio/security-data/crs",
            "/etc/wafio/security-data/crs/",
            "/etc/wafio/security-data/crs/coreruleset",
            "/etc/wafio/security-data/crs/coreruleset/",
            "/etc/wafio/security-data/crs/coreruleset/rules",
            "/etc/wafio/security-data/crs/coreruleset/rules/",
        ] {
            assert_eq!(
                security_data_dir_from_legacy_setting(legacy),
                "/etc/wafio/security-data",
                "{legacy}"
            );
        }
        assert_eq!(
            security_data_dir_from_legacy_setting("/srv/waf/data/crs"),
            "/srv/waf/data"
        );
    }

    #[test]
    fn path_helpers_follow_posix_rules() {
        for (p, c, b, d) in [
            ("", ".", ".", "."),
            ("/", "/", "/", "/"),
            ("a/b/../c/./d/", "a/c/d", "d", "a/c/d"),
            ("/../x", "/x", "x", "/"),
            ("../../x", "../../x", "x", "../.."),
            ("x//y", "x/y", "y", "x"),
        ] {
            assert_eq!(normalize_path(p), c, "clean {p:?}");
            assert_eq!(final_component(p), b, "base {p:?}");
            assert_eq!(parent_directory(p), d, "dir {p:?}");
        }
    }

    #[test]
    fn malware_snapshot_replace_keeps_previous_and_refuses_garbage() {
        let d = std::env::temp_dir().join(format!("wafio-malware-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let one = format!("{} Test.One\n", "ab".repeat(32));
        let two = format!(
            "# Updated: 2026-01-01T00:00:00Z\n{} Test.Two\n",
            "cd".repeat(32)
        );
        replace_malware_snapshot(&d, one.as_bytes()).unwrap();
        replace_malware_snapshot(&d, two.as_bytes()).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.join("malware/malware_hashes.txt")).unwrap(),
            two
        );
        assert_eq!(
            std::fs::read_to_string(d.join("malware/malware_hashes.txt.previous")).unwrap(),
            one
        );
        for bad in [
            &b""[..],
            b"# only a comment\n",
            b"nothex Label\n",
            b"# Updated: 2999-01-01T00:00:00Z\n",
        ] {
            assert!(
                replace_malware_snapshot(&d, bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(
            std::fs::read_to_string(d.join("malware/malware_hashes.txt")).unwrap(),
            two,
            "last good kept"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
