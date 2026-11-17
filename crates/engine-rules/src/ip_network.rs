//! IP and network helpers the rules config and custom rules need: address and CIDR parsing,
//! network containment, address equality, host and port splitting, client IP, IP lists and country
//! code validation.

use wafio_domain::ip_address;
use wafio_domain::text_helpers::trim_whitespace_str;

/// An IP address: 16 bytes from `parse_ip`, 4 or 16 bytes after masking.
pub type IpBytes = Vec<u8>;

/// Parses an address without a zone, as 16 bytes.
pub fn parse_ip(s: &str) -> Option<IpBytes> {
    let a = ip_address::parse_ip_address(s.as_bytes()).ok()?;
    if !a.zone().is_empty() {
        return None;
    }
    Some(as16(&a).to_vec())
}

fn as16(a: &ip_address::IpAddress) -> [u8; 16] {
    match a.to_std() {
        Some(std::net::IpAddr::V4(v4)) => v4.to_ipv6_mapped().octets(),
        Some(std::net::IpAddr::V6(v6)) => v6.octets(),
        None => [0; 16],
    }
}

const V4_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

pub fn to_ipv4_octets(ip: &[u8]) -> Option<Vec<u8>> {
    if ip.len() == 4 {
        return Some(ip.to_vec());
    }
    if ip.len() == 16 && ip[..12] == V4_PREFIX {
        return Some(ip[12..].to_vec());
    }
    None
}

fn prefix_mask(ones: usize, bits: usize) -> Vec<u8> {
    let mut m = vec![0u8; bits / 8];
    let mut n = ones;
    for b in m.iter_mut() {
        if n >= 8 {
            *b = 0xff;
            n -= 8;
            continue;
        }
        *b = !(0xffu8 >> n);
        n = 0;
    }
    m
}

fn apply_mask(ip: &[u8], mask: &[u8]) -> Option<Vec<u8>> {
    let mut ip = ip.to_vec();
    if mask.len() == 16 && ip.len() == 4 && mask[..12].iter().all(|&b| b == 0xff) {
        // the last 4 mask bytes
        return Some(ip.iter().zip(&mask[12..]).map(|(a, b)| a & b).collect());
    }
    if mask.len() == 4 && ip.len() == 16 && ip[..12] == V4_PREFIX {
        ip = ip[12..].to_vec();
    }
    if ip.len() != mask.len() {
        return None;
    }
    Some(ip.iter().zip(mask).map(|(a, b)| a & b).collect())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpNetwork {
    pub ip: IpBytes,
    pub mask: Vec<u8>,
}

impl IpNetwork {
    pub fn contains(&self, ip: &[u8]) -> bool {
        let Some((nn, m)) = network_address_and_mask(self) else {
            return false;
        };
        let ip = to_ipv4_octets(ip).unwrap_or_else(|| ip.to_vec());
        if ip.len() != nn.len() {
            return false;
        }
        (0..ip.len()).all(|i| nn[i] & m[i] == ip[i] & m[i])
    }
}

fn network_address_and_mask(n: &IpNetwork) -> Option<(Vec<u8>, Vec<u8>)> {
    let ip = match to_ipv4_octets(&n.ip) {
        Some(v4) => v4,
        None => {
            if n.ip.len() != 16 {
                return None;
            }
            n.ip.clone()
        }
    };
    let mut m = n.mask.clone();
    match m.len() {
        4 => {
            if ip.len() != 4 {
                return None;
            }
        }
        16 => {
            if ip.len() == 4 {
                m = m[12..].to_vec();
            }
        }
        _ => return None,
    }
    Some((ip, m))
}

/// Returns Some((ip, net)) or None for a parse error.
pub fn parse_network_prefix(s: &str) -> Option<(IpBytes, IpNetwork)> {
    let (addr, mask) = s.split_once('/')?;
    let a = ip_address::parse_ip_address(addr.as_bytes()).ok()?;
    if !a.zone().is_empty() {
        return None;
    }
    let bits = if a.is_ipv4() { 32 } else { 128 };
    // the prefix length: decimal digits only
    let mb = mask.as_bytes();
    let mut n: usize = 0;
    let mut i = 0;
    while i < mb.len() && mb[i].is_ascii_digit() {
        n = n * 10 + usize::from(mb[i] - b'0');
        if n >= 0xFFFFFF {
            return None;
        }
        i += 1;
    }
    if i == 0 || i != mb.len() || n > bits {
        return None;
    }
    let m = prefix_mask(n, bits);
    let a16 = as16(&a).to_vec();
    let masked = apply_mask(&a16, &m)?;
    Some((
        a16,
        IpNetwork {
            ip: masked,
            mask: m,
        },
    ))
}

pub fn ip_bytes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() == b.len() {
        return a == b;
    }
    if a.len() == 4 && b.len() == 16 {
        return b[..12] == V4_PREFIX && b[12..] == *a;
    }
    if a.len() == 16 && b.len() == 4 {
        return a[..12] == V4_PREFIX && a[12..] == *b;
    }
    false
}

/// The host part of `host:port` (None on error).
pub fn host_from_host_port(hostport: &str) -> Option<&str> {
    let i = hostport.rfind(':')?;
    let (host, j, k);
    if hostport.starts_with('[') {
        let end = hostport.find(']')?;
        if end + 1 != i {
            return None; // missing port or too many colons
        }
        host = &hostport[1..end];
        (j, k) = (1, end + 1);
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return None;
        }
        (j, k) = (0, 0);
    }
    if hostport[j..].contains('[') || hostport[k..].contains(']') {
        return None;
    }
    Some(host)
}

pub fn parse_client_ip(remote_addr: &str) -> String {
    let remote_addr = trim_whitespace_str(remote_addr);
    if remote_addr.is_empty() {
        return String::new();
    }
    match host_from_host_port(remote_addr) {
        Some(h) => h.to_string(),
        None => remote_addr.to_string(),
    }
}

pub fn ip_in_list(ip_str: &str, list: &[String]) -> bool {
    if list.is_empty() {
        return false;
    }
    let Some(ip) = parse_ip(ip_str) else {
        return false;
    };
    for s in list {
        let s = trim_whitespace_str(s);
        if s.is_empty() {
            continue;
        }
        if s.contains('/') {
            if let Some((_, n)) = parse_network_prefix(s)
                && n.contains(&ip)
            {
                return true;
            }
        } else if let Some(other) = parse_ip(s)
            && ip_bytes_equal(&ip, &other)
        {
            return true;
        }
    }
    false
}

const COUNTRY_CODES: [&str; 195] = [
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AR", "AT", "AU", "AW", "AZ", "BA", "BB", "BD",
    "BE", "BF", "BG", "BH", "BI", "BJ", "BN", "BO", "BR", "BS", "BT", "BW", "BY", "BZ", "CA", "CD",
    "CF", "CG", "CH", "CI", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CY", "CZ", "DE", "DJ", "DK",
    "DM", "DO", "DZ", "EC", "EE", "EG", "ER", "ES", "ET", "FI", "FJ", "FR", "GA", "GB", "GD", "GE",
    "GH", "GM", "GN", "GQ", "GR", "GT", "GW", "GY", "HK", "HN", "HR", "HT", "HU", "ID", "IE", "IL",
    "IN", "IQ", "IR", "IS", "IT", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR",
    "KW", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD",
    "ME", "MG", "MK", "ML", "MM", "MN", "MO", "MR", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NE", "NG", "NI", "NL", "NO", "NP", "NZ", "OM", "PA", "PE", "PG", "PH", "PK", "PL", "PR", "PS",
    "PT", "PY", "QA", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SI", "SK", "SL",
    "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SY", "SZ", "TD", "TG", "TH", "TJ", "TL", "TM", "TN",
    "TO", "TR", "TT", "TW", "TZ", "UA", "UG", "US", "UY", "UZ", "VA", "VE", "VN", "VU", "WS", "YE",
    "ZA", "ZM", "ZW",
];

/// Exactly 2 bytes, upper-cased (ASCII is enough for a 2-byte code that can match) and in
/// the country table.
pub fn is_valid_country_code(code: &str) -> bool {
    if code.len() != 2 {
        return false;
    }
    let upper = trim_whitespace_str(code).to_ascii_uppercase();
    COUNTRY_CODES.contains(&upper.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_in_cidr_matches_reference() {
        let (_, n) = parse_network_prefix("10.0.0.0/8").unwrap();
        assert!(n.contains(&parse_ip("10.1.2.3").unwrap()));
        assert!(!n.contains(&parse_ip("11.1.2.3").unwrap()));
        assert!(!n.contains(&parse_ip("::1").unwrap()));
        assert!(parse_network_prefix("10.0.0.0/33").is_none());
        assert!(parse_network_prefix("10.0.0.0").is_none());
        assert!(parse_ip("fe80::1%eth0").is_none());
        assert!(ip_in_list("1.2.3.4", &["1.2.3.4".into()]));
        assert_eq!(parse_client_ip("1.2.3.4:80"), "1.2.3.4");
        assert_eq!(parse_client_ip("[::1]:80"), "::1");
        assert!(is_valid_country_code("id") && !is_valid_country_code(" I"));
    }
}
