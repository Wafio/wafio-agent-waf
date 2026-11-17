//! `ContentScanConfig`, its defaults and validation (`prepare`). The upload scan itself (upload
//! extraction and the Bloom malware database) is not implemented in this module.

use std::collections::BTreeSet;

use crate::json_decode::{self, DecodeTrace, JsonDecodeError, Value};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ContentScanConfig {
    pub on_incomplete: String,
    pub enabled: bool,
    pub mode: String,
    pub max_scan_size_bytes: i64,
    pub scan_multipart: bool,
    pub scan_raw_body: bool,
    pub custom_blocklist_hashes: Vec<String>,
    pub custom_allowlist_hashes: Vec<String>,
    pub allow_hashes: BTreeSet<[u8; 32]>,
    pub block_hashes: BTreeSet<[u8; 32]>,
}

pub fn standard_content_scan_config() -> ContentScanConfig {
    ContentScanConfig {
        enabled: true,
        mode: "block".into(),
        max_scan_size_bytes: 10 * 1024 * 1024,
        scan_multipart: true,
        scan_raw_body: false,
        ..Default::default()
    }
}

pub fn decode_content_scan_config(
    d: &mut DecodeTrace,
    v: &Value,
    c: &mut ContentScanConfig,
) -> Result<(), JsonDecodeError> {
    const F: [&str; 8] = [
        "on_incomplete",
        "enabled",
        "mode",
        "max_scan_size_bytes",
        "scan_multipart",
        "scan_raw_body",
        "custom_blocklist_hashes",
        "custom_allowlist_hashes",
    ];
    json_decode::object(
        d,
        v,
        "engine.ContentScanConfig",
        "ContentScanConfig",
        &F,
        |d, i, v| {
            match i {
                0 => json_decode::string(d, v, &mut c.on_incomplete),
                1 => json_decode::boolean(d, v, &mut c.enabled),
                2 => json_decode::string(d, v, &mut c.mode),
                3 => json_decode::int(d, v, &mut c.max_scan_size_bytes),
                4 => json_decode::boolean(d, v, &mut c.scan_multipart),
                5 => json_decode::boolean(d, v, &mut c.scan_raw_body),
                6 => json_decode::strings(d, v, &mut c.custom_blocklist_hashes)?,
                _ => json_decode::strings(d, v, &mut c.custom_allowlist_hashes)?,
            }
            Ok(())
        },
    )
}

impl ContentScanConfig {
    /// prepare: validates and compiles the hash lists.
    pub fn prepare(&mut self) -> Result<(), String> {
        if !self.mode.is_empty()
            && self.mode != "block"
            && self.mode != "log"
            && self.mode != "disabled"
        {
            return Err("content_scan.mode must be block, log or disabled".into());
        }
        if !self.on_incomplete.is_empty()
            && self.on_incomplete != "allow"
            && self.on_incomplete != "log"
            && self.on_incomplete != "block"
        {
            return Err("content_scan.on_incomplete must be allow, log or block".into());
        }
        if self.max_scan_size_bytes < 0 || self.max_scan_size_bytes > 100 * 1024 * 1024 {
            return Err("content_scan.max_scan_size_bytes must be between 0 and 104857600".into());
        }
        fn compile(hashes: &[String]) -> Result<BTreeSet<[u8; 32]>, String> {
            if hashes.len() > 10000 {
                return Err("content_scan hash list exceeds 10000 entries".into());
            }
            let mut out = BTreeSet::new();
            for h in hashes {
                let t = wafio_domain::text_helpers::trim_whitespace_str(h);
                let bytes = decode_hex(t)
                    .filter(|b| b.len() == 32)
                    .ok_or("content_scan requires 64-character SHA-256 hex hashes")?;
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                out.insert(k);
            }
            Ok(out)
        }
        self.allow_hashes = compile(&self.custom_allowlist_hashes)?;
        self.block_hashes = compile(&self.custom_blocklist_hashes)?;
        Ok(())
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let v = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    b.chunks(2)
        .map(|p| Some(v(p[0])? << 4 | v(p[1])?))
        .collect()
}

/// Caps attacker-controlled metadata at 256 bytes.
pub fn content_scan_reason_label(value: &[u8]) -> &[u8] {
    &value[..value.len().min(256)]
}
