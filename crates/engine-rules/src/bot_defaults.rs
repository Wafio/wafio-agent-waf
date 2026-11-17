//! The default bot lists: the UA patterns, the JA3 and the JA4 fingerprints from the security data. Each list
//! comes from a file named by an environment variable, else from the working directory, else from next to the
//! executable; a missing file is an empty list. The JA4 lists fall back to the seeds an engine ships.

use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};
use wafio_bytetext::strings::{to_lowercase_cow as to_lowercase, trim_whitespace};

/// Reads the first candidate that opens: $env, CWD/<rel>, <exe dir>/<rel>.
fn read_first(env: &str, rel: &[&str]) -> Option<Vec<u8>> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var(env)
        && !p.is_empty()
    {
        candidates.push(PathBuf::from(p));
    }
    candidates.push(rel.iter().collect());
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let mut p = dir.to_path_buf();
        p.extend(rel);
        candidates.push(p);
    }
    candidates.into_iter().find_map(|p| std::fs::read(p).ok())
}

/// Reads a fingerprint list (first token per line, lower-cased, deduped);
/// None when no candidate file opens.
// shortcut: there is no limit on line length.
fn load_fingerprint_file(env: &str, rel: &[&str]) -> Option<Vec<String>> {
    let data = read_first(env, rel)?;
    let mut out: Vec<String> = Vec::new();
    for line in data.split(|&c| c == b'\n') {
        let line = trim_whitespace(line.strip_suffix(b"\r").unwrap_or(line));
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let mut hash = line;
        if let Some(idx) = line.iter().position(|&c| c == b' ' || c == b'\t')
            && idx > 0
        {
            hash = &line[..idx];
        }
        let hash = String::from_utf8_lossy(trim_whitespace(&to_lowercase(hash))).into_owned();
        if hash.is_empty() || out.contains(&hash) {
            continue;
        }
        out.push(hash);
    }
    Some(out)
}

fn load_bad_bot_ua_blocklist() -> Vec<String> {
    let Some(data) = read_first(
        "WAFIO_UA_BAD_BOT_FILE",
        &["security-data", "user-agents", "bot.txt"],
    ) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for line in data.split(|&c| c == b'\n') {
        let line = trim_whitespace(line.strip_suffix(b"\r").unwrap_or(line));
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let s = String::from_utf8_lossy(line).into_owned();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

static UA_LIST: RwLock<Option<Vec<String>>> = RwLock::new(None);

pub fn default_bad_bot_ua_blocklist() -> Vec<String> {
    if let Some(l) = UA_LIST.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        return l.clone();
    }
    UA_LIST
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(load_bad_bot_ua_blocklist)
        .clone()
}

static JA3_LIST: OnceLock<Vec<String>> = OnceLock::new();

/// The default JA3 blocklist (loaded once, empty when no file opens).
pub fn default_ja3_blocklist() -> Vec<String> {
    JA3_LIST
        .get_or_init(|| {
            load_fingerprint_file(
                "WAFIO_JA3_BLACKLIST_FILE",
                &["security-data", "ja3", "ja3.txt"],
            )
            .unwrap_or_default()
        })
        .clone()
}

/// What the two JA4 files hold; `None` when a file is missing or empty.
type Ja4Files = (Option<Vec<String>>, Option<Vec<String>>);

fn load_ja4_files() -> Ja4Files {
    let read = |env: &str, name: &str| {
        load_fingerprint_file(env, &["security-data", "ja4", name]).filter(|v| !v.is_empty())
    };
    (
        read("WAFIO_JA4_BLACKLIST_FILE", "ja4.txt"),
        read("WAFIO_JA4_ALLOWLIST_FILE", "ja4_allowlist.txt"),
    )
}

static JA4_FILES: RwLock<Option<Ja4Files>> = RwLock::new(None);

fn ja4_files() -> Ja4Files {
    if let Some(l) = JA4_FILES.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        return l.clone();
    }
    let mut g = JA4_FILES.write().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(load_ja4_files).clone()
}

fn or_seeds(file: Option<Vec<String>>, seeds: &[&str]) -> Vec<String> {
    file.unwrap_or_else(|| seeds.iter().map(|s| s.to_string()).collect())
}

/// The default JA4 blocklist: the file, else `seeds`.
pub fn default_ja4_blocklist(seeds: &[&str]) -> Vec<String> {
    or_seeds(ja4_files().0, seeds)
}

/// The default JA4 allowlist: the file, else `seeds`.
pub fn default_ja4_allowlist(seeds: &[&str]) -> Vec<String> {
    or_seeds(ja4_files().1, seeds)
}
