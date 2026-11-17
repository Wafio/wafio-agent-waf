//! FireHOL level 1 (block) / level 2 (challenge) netsets as sorted, merged IPv4 ranges;
//! public IPv4 only. Loading (local files or download every 24 h) is the caller's: it reads
//! the netset text and calls `ReputationLists::load`, keeping the previous DB on error.

use std::sync::{Arc, RwLock};
use wafio_domain::ip_address::parse_ip_address;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReputationLevel {
    Clean = 0,
    Challenge = 1,
    Block = 2,
}

pub const FIREHOL_LEVEL1_LIST_URL: &str =
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset";
pub const FIREHOL_LEVEL2_LIST_URL: &str =
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset";
/// User-Agent of the netset download.
pub const IPREP_USER_AGENT: &str = "wafio-iprep/1.0";

/// Inclusive IPv4 range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ReputationLists {
    pub block: Vec<AddressRange>,
    pub challenge: Vec<AddressRange>,
}

/// The DB swapped whole on reload. `None` until the first load.
#[derive(Default)]
pub struct ReputationChecker {
    db: RwLock<Option<Arc<ReputationLists>>>,
}

impl ReputationChecker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&self, ip: &[u8]) -> ReputationLevel {
        let ip = strip_port(ip);
        let Some(n) = parse_dotted_quad(ip) else {
            return ReputationLevel::Clean;
        };
        if is_non_routable_ipv4(n) {
            return ReputationLevel::Clean;
        }
        let Some(db) = self.db.read().unwrap_or_else(|e| e.into_inner()).clone() else {
            return ReputationLevel::Clean;
        };
        if contains_in_sorted_ranges(&db.block, n) {
            return ReputationLevel::Block;
        }
        if contains_in_sorted_ranges(&db.challenge, n) {
            return ReputationLevel::Challenge;
        }
        ReputationLevel::Clean
    }

    /// The current DB (for `load`'s keep-previous rule).
    pub fn current(&self) -> Option<Arc<ReputationLists>> {
        self.db.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// `load` with each list as a plain result: an error carries no partial ranges. Use
    /// `load_partial` with `parse_netset_partial` to keep the partial ranges of a failed first load.
    pub fn load(
        &self,
        level1: Result<Vec<AddressRange>, String>,
        level2: Result<Vec<AddressRange>, String>,
        local_files: bool,
    ) -> String {
        let split = |r: Result<Vec<AddressRange>, String>| match r {
            Ok(v) => (v, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        self.load_partial(split(level1), split(level2), local_files)
    }

    /// level1/level2 are what reading or fetching a netset returns, the ranges
    /// with the error (`parse_netset_partial`). Both failed → keep the DB; one failed →
    /// that list from the previous DB, or its partial ranges on the first load.
    /// Returns the log line.
    pub fn load_partial(
        &self,
        level1: (Vec<AddressRange>, Option<String>),
        level2: (Vec<AddressRange>, Option<String>),
        local_files: bool,
    ) -> String {
        let ((mut block, err1), (mut challenge, err2)) = (level1, level2);
        if let (Some(e1), Some(e2)) = (&err1, &err2) {
            return format!("[iprep] load failed (level1: {e1}, level2: {e2}) — using cached data");
        }
        let prev = self.current();
        if let Some(e) = err1 {
            tracing::warn!("[iprep] level1 load failed: {e} — using cached data for that list");
            if let Some(p) = &prev {
                block = p.block.clone();
            }
        }
        if let Some(e) = err2 {
            tracing::warn!("[iprep] level2 load failed: {e} — using cached data for that list");
            if let Some(p) = &prev {
                challenge = p.challenge.clone();
            }
        }
        let msg = format!(
            "[iprep] loaded ({}): {} block ranges (level1), {} challenge ranges (level2)",
            if local_files {
                "local files"
            } else {
                "downloaded"
            },
            block.len(),
            challenge.len()
        );
        *self.db.write().unwrap_or_else(|e| e.into_inner()) =
            Some(Arc::new(ReputationLists { block, challenge }));
        msg
    }

    /// Installs a DB directly (tests, fakes).
    pub fn store(&self, db: ReputationLists) {
        *self.db.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(db));
    }
}

/// Drops ":port" when the string has exactly one colon.
pub fn strip_port(ip: &[u8]) -> &[u8] {
    if let Some(i) = ip.iter().rposition(|&c| c == b':')
        && ip.iter().position(|&c| c == b':') == Some(i)
    {
        return &ip[..i];
    }
    ip
}

/// Private or loopback: 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10.
pub fn is_non_routable_ipv4(n: u32) -> bool {
    n >> 24 == 127
        || n >> 24 == 10
        || (n >> 20) & 0xFFF == 0xAC1
        || n >> 16 == 0xC0A8
        || n >> 16 == 0xA9FE
        || (n >> 22) == 0x191
}

/// Dotted decimal only (leading zeros accepted, no trailing bytes).
pub fn parse_dotted_quad(mut s: &[u8]) -> Option<u32> {
    let mut result: u32 = 0;
    for i in 0..4 {
        if s.is_empty() {
            return None;
        }
        let mut octet: u32 = 0;
        let mut j = 0;
        while j < s.len() && s[j].is_ascii_digit() {
            octet = octet * 10 + (s[j] - b'0') as u32;
            j += 1;
            if octet > 255 {
                return None;
            }
        }
        if j == 0 {
            return None;
        }
        result = (result << 8) | octet;
        s = &s[j..];
        if i < 3 {
            if s.first() != Some(&b'.') {
                return None;
            }
            s = &s[1..];
        }
    }
    s.is_empty().then_some(result)
}

/// `parse_netset_partial` as a plain result (the ranges parsed before an error are dropped).
pub fn parse_ip_list(text: &[u8]) -> Result<Vec<AddressRange>, String> {
    match parse_netset_partial(text, None) {
        (r, None) => Ok(r),
        (_, Some(e)) => Err(e),
    }
}

/// One CIDR or IP per line, '#' comments, sorted and merged. `text` is what
/// was read and `read_err` the error the read ended with (None = EOF). Lines split like a
/// line scanner; on an error (`read_err`, or a line of 64 KiB or more) the ranges parsed so
/// far come back, unsorted and unmerged, with the error.
pub fn parse_netset_partial(
    text: &[u8],
    read_err: Option<String>,
) -> (Vec<AddressRange>, Option<String>) {
    let mut ranges = Vec::new();
    for line in text.split(|&c| c == b'\n') {
        if line.len() >= 64 * 1024 {
            return (ranges, Some("bufio.Scanner: token too long".into()));
        }
        let line = wafio_bytetext::strings::trim_whitespace(line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        if let Some(r) = cidr_bounds(line) {
            ranges.push(r);
        }
    }
    if read_err.is_some() {
        return (ranges, read_err);
    }
    ranges.sort_by_key(|r| r.start);
    (coalesce_ranges(ranges), None)
}

/// Parses a CIDR (address without zone, decimal prefix ≤ bit length):
/// the 16-byte network and the mask (4 bytes for IPv4, 16 for IPv6).
pub fn parse_network_prefix(s: &[u8]) -> Option<([u8; 16], Vec<u8>)> {
    let (addr, mask, found) = wafio_bytetext::strings::cut(s, b"/");
    if !found {
        return None;
    }
    let a = parse_ip_address(addr).ok()?;
    if !a.zone().is_empty() {
        return None;
    }
    let bits = a.bit_length() as usize;
    let mut n: usize = 0;
    let mut i = 0;
    while i < mask.len() && mask[i].is_ascii_digit() {
        n = n * 10 + (mask[i] - b'0') as usize;
        if n >= 0xFFFFFF {
            return None;
        }
        i += 1;
    }
    if i == 0 || i != mask.len() || n > bits {
        return None;
    }
    let mut m = vec![0u8; bits / 8];
    for (k, b) in m.iter_mut().enumerate() {
        let ones = n.saturating_sub(k * 8).min(8);
        *b = if ones == 0 { 0 } else { 0xFFu8 << (8 - ones) };
    }
    let mut ip16 = match a.to_std()? {
        std::net::IpAddr::V4(v) => v.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(v) => v.octets(),
    };
    let off = 16 - m.len();
    for (k, b) in m.iter().enumerate() {
        ip16[off + k] &= b;
    }
    Some((ip16, m))
}

/// The 4 IPv4 octets of the network `parse_network_prefix` returns (IPv4, or IPv4-mapped IPv6).
pub fn to_ipv4_octets(ip16: &[u8; 16], mask: &[u8]) -> Option<[u8; 4]> {
    if mask.len() == 4
        || (ip16[..10].iter().all(|&b| b == 0) && ip16[10] == 0xff && ip16[11] == 0xff)
    {
        return Some([ip16[12], ip16[13], ip16[14], ip16[15]]);
    }
    None
}

/// CIDR or bare IP (as /32); IPv4 (or v4-mapped) only.
pub fn cidr_bounds(s: &[u8]) -> Option<AddressRange> {
    let with_bits;
    let s = if s.contains(&b'/') {
        s
    } else {
        with_bits = [s, b"/32"].concat();
        &with_bits
    };
    let (ip16, mask) = parse_network_prefix(s)?;
    let v4 = to_ipv4_octets(&ip16, &mask)?;
    let m = if mask.len() == 16 {
        &mask[12..]
    } else {
        &mask[..]
    };
    let start = u32::from_be_bytes(v4);
    let broadcast = start | !u32::from_be_bytes([m[0], m[1], m[2], m[3]]);
    Some(AddressRange {
        start,
        end: broadcast,
    })
}

/// Merges sorted ranges (overlapping or adjacent).
pub fn coalesce_ranges(input: Vec<AddressRange>) -> Vec<AddressRange> {
    let mut out: Vec<AddressRange> = Vec::with_capacity(input.len());
    for r in input {
        if let Some(last) = out.last_mut()
            && r.start <= last.end.wrapping_add(1)
        {
            if r.end > last.end {
                last.end = r.end;
            }
            continue;
        }
        out.push(r);
    }
    out
}

/// Binary search.
pub fn contains_in_sorted_ranges(ranges: &[AddressRange], ip: u32) -> bool {
    let (mut lo, mut hi) = (0isize, ranges.len() as isize - 1);
    while lo <= hi {
        let mid = ((lo + hi) >> 1) as usize;
        if ip < ranges[mid].start {
            hi = mid as isize - 1;
        } else if ip > ranges[mid].end {
            lo = mid as isize + 1;
        } else {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netset_parse_merge_and_check() {
        let r =
            parse_ip_list(b"# c\n1.2.3.0/24\n1.2.4.0/24\r\n5.6.7.8\n::1/128\n10.0.0.0/8\nbad\n")
                .unwrap();
        assert_eq!(
            r,
            vec![
                AddressRange {
                    start: 0x01020300,
                    end: 0x010204FF
                },
                AddressRange {
                    start: 0x05060708,
                    end: 0x05060708
                },
                AddressRange {
                    start: 0x0A000000,
                    end: 0x0AFFFFFF
                },
            ]
        );
        let c = ReputationChecker::new();
        assert_eq!(c.check(b"1.2.3.4"), ReputationLevel::Clean);
        c.store(ReputationLists {
            block: r.clone(),
            challenge: vec![AddressRange {
                start: 0x08080808,
                end: 0x08080808,
            }],
        });
        assert_eq!(c.check(b"1.2.4.200:443"), ReputationLevel::Block);
        assert_eq!(c.check(b"8.8.8.8"), ReputationLevel::Challenge);
        assert_eq!(c.check(b"10.1.1.1"), ReputationLevel::Clean); // private short-circuit
        assert_eq!(c.check(b"::ffff:1.2.3.4"), ReputationLevel::Clean); // not dotted IPv4
    }

    // On the first load a list whose read failed keeps the ranges `parse_netset_partial`
    // returned before the error (unsorted, unmerged).
    #[test]
    fn first_load_keeps_partial_ranges_of_a_failed_list() {
        let l1 = [
            b"9.9.9.9\n1.1.1.0/24\n".as_slice(),
            &[b'x'; 70000],
            b"\n8.8.8.8\n",
        ]
        .concat();
        let (r1, e1) = parse_netset_partial(&l1, None);
        assert_eq!(
            (r1.clone(), e1.is_some()),
            (
                vec![
                    AddressRange {
                        start: 0x09090909,
                        end: 0x09090909
                    },
                    AddressRange {
                        start: 0x01010100,
                        end: 0x010101FF
                    }
                ],
                true
            )
        );
        assert!(parse_ip_list(&l1).is_err());
        let c = ReputationChecker::new();
        c.load_partial((r1, e1), parse_netset_partial(b"5.6.7.8\n", None), true);
        assert_eq!(c.check(b"9.9.9.9"), ReputationLevel::Block);
        assert_eq!(c.check(b"5.6.7.8"), ReputationLevel::Challenge);
        assert_eq!(c.check(b"8.8.8.8"), ReputationLevel::Clean);
        assert_eq!(c.check(b"1.1.1.5"), ReputationLevel::Clean); // unsorted: the binary search misses it
        // Both failed: the DB stays as it was.
        c.load_partial(
            (
                vec![AddressRange {
                    start: 0x02020202,
                    end: 0x02020202,
                }],
                Some("read: reset".into()),
            ),
            parse_netset_partial(b"6.6.6.6", Some("read: reset".into())),
            true,
        );
        assert_eq!(
            (
                c.check(b"9.9.9.9"),
                c.check(b"5.6.7.8"),
                c.check(b"6.6.6.6")
            ),
            (
                ReputationLevel::Block,
                ReputationLevel::Challenge,
                ReputationLevel::Clean
            )
        );
        // With a previous DB a failed list comes from it, not from its partial ranges.
        c.load_partial(
            (
                vec![AddressRange {
                    start: 0x02020202,
                    end: 0x02020202,
                }],
                Some("read: reset".into()),
            ),
            (vec![], None),
            true,
        );
        assert_eq!(
            (
                c.check(b"9.9.9.9"),
                c.check(b"2.2.2.2"),
                c.check(b"5.6.7.8")
            ),
            (
                ReputationLevel::Block,
                ReputationLevel::Clean,
                ReputationLevel::Clean
            )
        );
        // A read error still parses the partial last line, as a line scanner does at EOF.
        assert_eq!(
            parse_netset_partial(b"1.2.3.4\n5.6.7.8", Some("e".into()))
                .0
                .len(),
            2
        );
    }

    #[test]
    fn parse_dotted_quad_cases() {
        assert_eq!(parse_dotted_quad(b"001.2.3.4"), Some(0x01020304));
        assert_eq!(parse_dotted_quad(b"1.2.3.4 "), None);
        assert_eq!(parse_dotted_quad(b"1.2.3.256"), None);
        assert_eq!(parse_dotted_quad(b"1.2.3"), None);
    }

    #[test]
    fn mapped_and_edge_cidrs() {
        assert_eq!(
            cidr_bounds(b"::ffff:1.2.3.0/120"),
            Some(AddressRange {
                start: 0x01020300,
                end: 0x010203FF
            })
        );
        assert_eq!(
            cidr_bounds(b"0.0.0.0/0"),
            Some(AddressRange {
                start: 0,
                end: u32::MAX
            })
        );
        assert_eq!(cidr_bounds(b"1.2.3.4/33"), None);
        assert_eq!(cidr_bounds(b"01.2.3.4/32"), None); // netip rejects leading zeros
        assert_eq!(
            coalesce_ranges(vec![
                AddressRange {
                    start: 0,
                    end: u32::MAX
                },
                AddressRange { start: 0, end: 5 }
            ])
            .len(),
            1
        );
    }
}
