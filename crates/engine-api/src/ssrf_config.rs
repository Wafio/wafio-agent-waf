//! The SSRF host/suffix blocklist (built-in list extension).

use std::collections::HashSet;
use std::sync::Arc;
use wafio_bytetext::strings;

/// Extra hostnames and suffixes merged with the built-in SSRF blocklist. Built once, then
/// read-only (the agent only builds new ones).
#[derive(Clone, Debug, Default)]
pub struct SsrfBlocklist {
    pub hosts: HashSet<Vec<u8>>,
    pub suffixes: Vec<Vec<u8>>,
}

/// Optional SSRF tuning (blocklist only).
#[derive(Clone, Debug, Default)]
pub struct SsrfConfig {
    /// None = built-in only.
    pub blocklist: Option<Arc<SsrfBlocklist>>,
}

impl SsrfBlocklist {
    pub fn new() -> SsrfBlocklist {
        SsrfBlocklist::default()
    }

    /// Adds a host, lower-cased and trimmed; empty is ignored.
    pub fn add_host(&mut self, host: &[u8]) {
        let host = strings::to_lowercase(strings::trim_whitespace(host));
        if host.is_empty() {
            return;
        }
        self.hosts.insert(host);
    }

    /// Adds a suffix, lower-cased, trimmed and deduplicated; empty is ignored.
    pub fn add_suffix(&mut self, suffix: &[u8]) {
        let suffix = strings::to_lowercase(strings::trim_whitespace(suffix));
        if suffix.is_empty() || self.suffixes.contains(&suffix) {
            return;
        }
        self.suffixes.push(suffix);
    }
}

fn add_line(bl: &mut SsrfBlocklist, line: &[u8]) {
    let line = strings::trim_whitespace(line);
    if line.is_empty() || line.starts_with(b"#") {
        return;
    }
    let line = strings::to_lowercase(line);
    if line.starts_with(b".") {
        bl.add_suffix(&line);
    } else {
        bl.add_host(&line);
    }
}

/// Reads an SSRF blocklist file: one host or `.suffix` per line, `#` comments.
pub fn read_ssrf_blocklist_file(path: &std::path::Path) -> std::io::Result<SsrfBlocklist> {
    let data = std::fs::read(path)?;
    let mut bl = SsrfBlocklist::new();
    // Lines: split on '\n', drop one trailing '\r'
    for line in data.split(|&c| c == b'\n') {
        add_line(&mut bl, line.strip_suffix(b"\r").unwrap_or(line));
    }
    Ok(bl)
}

pub fn parse_ssrf_blocklist_lines<S: AsRef<[u8]>>(lines: &[S]) -> SsrfBlocklist {
    let mut bl = SsrfBlocklist::new();
    for line in lines {
        add_line(&mut bl, line.as_ref());
    }
    bl
}
