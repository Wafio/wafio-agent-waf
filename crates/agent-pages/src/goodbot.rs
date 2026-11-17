//! Official Googlebot / Bingbot IPv4 ranges, sorted by start (not merged: the binary search
//! runs over the raw ranges). Fetching every 24 h is the caller's: it downloads each source
//! (2 MiB cap) and calls `parse_bot_ip_ranges`, then `VerifiedBotChecker::refresh`; a bundle
//! push calls `load_ranges_from_cidrs`.

use crate::iprep::{
    AddressRange, contains_in_sorted_ranges, parse_dotted_quad, parse_network_prefix,
    to_ipv4_octets,
};
use std::sync::{Arc, RwLock};
use wafio_domain::json_text::{Value, key_matches, parse, type_mismatch_text};

pub struct BotRangeSource {
    pub name: &'static str,
    pub url: &'static str,
}

pub const BOT_RANGE_SOURCES: [BotRangeSource; 2] = [
    BotRangeSource {
        name: "Googlebot",
        url: "https://developers.google.com/search/apis/ipranges/googlebot.json",
    },
    BotRangeSource {
        name: "Bingbot",
        url: "https://www.bing.com/toolbox/bingbot.json",
    },
];

/// Response body cap of a source download (2 MiB).
pub const GOOD_BOT_BODY_LIMIT: usize = 2 << 20;

/// Checks IPs against an atomically swapped range list.
#[derive(Default)]
pub struct VerifiedBotChecker {
    db: RwLock<Arc<Vec<AddressRange>>>,
}

// CIDR → range (host bits from the mask; 1<<32 wraps to 0).
fn cidr_to_range(cidr: &[u8]) -> Option<AddressRange> {
    let (ip16, mask) = parse_network_prefix(cidr)?;
    let ip4 = to_ipv4_octets(&ip16, &mask)?;
    let ones: u32 = mask.iter().map(|b| b.count_ones()).sum();
    let bits = (mask.len() * 8) as u32;
    let host_bits = bits - ones;
    let start = u32::from_be_bytes(ip4);
    let end = start | 1u32.checked_shl(host_bits).unwrap_or(0).wrapping_sub(1);
    Some(AddressRange { start, end })
}

impl VerifiedBotChecker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the ranges unless none parse. Returns the log line.
    pub fn load_ranges_from_cidrs<S: AsRef<[u8]>>(&self, cidrs: &[S]) -> Option<String> {
        let ranges = ranges_from_cidrs(cidrs);
        if ranges.is_empty() {
            return None;
        }
        let n = ranges.len();
        *self.db.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(ranges);
        Some(format!(
            "[goodbot] loaded {n} IPv4 ranges from control plane bundle"
        ))
    }

    /// Publishes the merged ranges of the sources that loaded; keeps the
    /// previous DB when none did.
    pub fn refresh(&self, per_source: Vec<Vec<AddressRange>>) {
        let mut all: Vec<AddressRange> = per_source.into_iter().flatten().collect();
        if all.is_empty() {
            return;
        }
        all.sort_by_key(|r| r.start);
        *self.db.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(all);
    }

    /// Dotted IPv4 only (no port stripping, unlike iprep).
    pub fn is_verified_bot_address(&self, client_ip: &[u8]) -> bool {
        let Some(addr) = parse_dotted_quad(client_ip) else {
            return false;
        };
        let db = self.db.read().unwrap_or_else(|e| e.into_inner()).clone();
        contains_in_sorted_ranges(&db, addr)
    }
}

/// The ranges `load_ranges_from_cidrs` installs: IPv4 (or v4-mapped) CIDRs, sorted by start,
/// not merged. The sort is stable: ranges with the same start keep their input order.
pub fn ranges_from_cidrs<S: AsRef<[u8]>>(cidrs: &[S]) -> Vec<AddressRange> {
    let mut ranges: Vec<AddressRange> = cidrs
        .iter()
        .filter_map(|c| cidr_to_range(c.as_ref()))
        .collect();
    ranges.sort_by_key(|r| r.start);
    ranges
}

/// After the download: `{"prefixes":[{"ipv4Prefix":…},…]}` → IPv4 ranges.
/// Err is the JSON decode failure (the source is skipped).
pub fn parse_bot_ip_ranges(body: &[u8]) -> Result<Vec<AddressRange>, String> {
    let doc = parse(body).map_err(|e| e.to_string())?;
    let mut ranges = Vec::new();
    // Wrong types are errors, null keeps zero values.
    let Value::Object(top) = &doc else {
        return if doc == Value::Null {
            Ok(ranges)
        } else {
            Err(type_mismatch_text("", doc.type_name(), "object"))
        };
    };
    let mut prefixes: Option<&Vec<Value>> = None;
    for (k, v) in top {
        if key_matches(k, "prefixes") {
            match v {
                Value::Array(a) => prefixes = Some(a),
                Value::Null => prefixes = None,
                other => {
                    return Err(type_mismatch_text(
                        "prefixes",
                        other.type_name(),
                        "[]object",
                    ));
                }
            }
        }
    }
    let mut err = None;
    for p in prefixes.into_iter().flatten() {
        let mut v4: &[u8] = b"";
        match p {
            Value::Object(fields) => {
                for (k, v) in fields {
                    if key_matches(k, "ipv4Prefix") || key_matches(k, "ipv6Prefix") {
                        match v {
                            Value::String(s) if key_matches(k, "ipv4Prefix") => v4 = s,
                            Value::String(_) | Value::Null => {}
                            _ => {
                                let name = if key_matches(k, "ipv4Prefix") {
                                    "prefixes.ipv4Prefix"
                                } else {
                                    "prefixes.ipv6Prefix"
                                };
                                err = Some(type_mismatch_text(name, &v.kind_text(), "string"));
                            }
                        }
                    }
                }
            }
            Value::Null => {}
            other => {
                err = Some(type_mismatch_text("prefixes", &other.kind_text(), "object"));
            }
        }
        if v4.is_empty() {
            continue;
        }
        if let Some(r) = cidr_to_range(v4) {
            ranges.push(r);
        }
    }
    match err {
        Some(e) => Err(e),
        None => Ok(ranges),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_from_json_and_bundle() {
        let r = parse_bot_ip_ranges(br#"{"creationTime":"x","prefixes":[{"ipv6Prefix":"2001:4860::/32"},{"ipv4Prefix":"66.249.64.0/27"},{"IPV4PREFIX":"1.2.3.4/32"}]}"#).unwrap();
        assert_eq!(
            r,
            vec![
                AddressRange {
                    start: 0x42F94000,
                    end: 0x42F9401F
                },
                AddressRange {
                    start: 0x01020304,
                    end: 0x01020304
                }
            ]
        );
        let c = VerifiedBotChecker::new();
        assert!(!c.is_verified_bot_address(b"66.249.64.1"));
        c.refresh(vec![r]);
        assert!(c.is_verified_bot_address(b"66.249.64.31"));
        assert!(!c.is_verified_bot_address(b"66.249.64.32"));
        assert!(
            c.load_ranges_from_cidrs(&["bad", "::ffff:0:0/96"])
                .is_some()
        );
        assert!(c.is_verified_bot_address(b"9.9.9.9")); // /96 mapped: 1<<32 wraps, whole IPv4 space
        assert!(c.load_ranges_from_cidrs(&["nope"]).is_none());
        assert!(c.is_verified_bot_address(b"9.9.9.9"));
    }
}
