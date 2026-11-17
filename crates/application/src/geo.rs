//! The geo helpers the pipeline calls: client IP parsing, IP list matching and the no-op lookup, with the
//! host:port and IP parsing they rely on (list matching goes through engine-rules `ip_network`). No crate
//! owns them, so they live here.

use std::net::{IpAddr, Ipv4Addr};

use wafio_bytetext::strings::trim_whitespace;
use wafio_domain::ip_address;
use wafio_engine_rules::ip_network;

pub trait GeoLookup: Send + Sync {
    /// Country code of `ip` ("" = unknown).
    fn country(&self, ip: &[u8]) -> Result<Vec<u8>, String>;
}

/// Always unknown (no GeoIP database).
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledGeoLookup;

impl GeoLookup for DisabledGeoLookup {
    fn country(&self, _ip: &[u8]) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
}

/// Splits `host:port` and returns the host only (errors as None).
pub fn host_from_host_port(hostport: &[u8]) -> Option<&[u8]> {
    let i = hostport.iter().rposition(|&c| c == b':')?;
    let (host, j, k);
    if hostport[0] == b'[' {
        let end = hostport.iter().position(|&c| c == b']')?;
        if end + 1 == hostport.len() || end + 1 != i {
            return None;
        }
        host = &hostport[1..end];
        (j, k) = (1, end + 1);
    } else {
        host = &hostport[..i];
        if host.contains(&b':') {
            return None;
        }
        (j, k) = (0, 0);
    }
    if hostport[j..].contains(&b'[') || hostport[k..].contains(&b']') {
        return None;
    }
    Some(host)
}

/// The host of "host:port", else the trimmed input.
pub fn parse_client_ip(remote_addr: &[u8]) -> Vec<u8> {
    let remote_addr = trim_whitespace(remote_addr);
    if remote_addr.is_empty() {
        return Vec::new();
    }
    match host_from_host_port(remote_addr) {
        Some(h) => h.to_vec(),
        None => remote_addr.to_vec(),
    }
}

/// IPv4 or IPv6 literal without a zone.
pub fn parse_ip(s: &[u8]) -> Option<IpAddr> {
    let a = ip_address::parse_ip_address(s).ok()?;
    if !a.zone().is_empty() {
        return None;
    }
    a.to_std()
}

/// The IPv4 form of a v4 or v4-mapped address.
pub fn to_ipv4(ip: &IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// `ip_str` equals one listed IP or lies in one listed CIDR (through engine-rules' `ip_network`; a
/// non-UTF-8 address never parses).
pub fn ip_in_list(ip_str: &[u8], list: &[String]) -> bool {
    std::str::from_utf8(ip_str).is_ok_and(|s| ip_network::ip_in_list(s, list))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ip() {
        assert_eq!(parse_client_ip(b" 192.0.2.1:443 "), b"192.0.2.1");
        assert_eq!(parse_client_ip(b"[2001:db8::1]:80"), b"2001:db8::1");
        assert_eq!(parse_client_ip(b"2001:db8::1"), b"2001:db8::1");
        assert_eq!(parse_client_ip(b"192.0.2.50"), b"192.0.2.50");
        assert_eq!(parse_client_ip(b""), b"");
    }

    #[test]
    fn in_list() {
        let list = vec![
            "10.0.0.0/8".to_string(),
            " 192.0.2.7 ".to_string(),
            "2001:db8::/32".into(),
        ];
        assert!(ip_in_list(b"10.1.2.3", &list));
        assert!(ip_in_list(b"::ffff:10.1.2.3", &list));
        assert!(ip_in_list(b"192.0.2.7", &list));
        assert!(ip_in_list(b"2001:db8::5", &list));
        assert!(!ip_in_list(b"11.0.0.1", &list));
        assert!(!ip_in_list(b"not-an-ip", &list));
        // A v4-mapped CIDR is an IPv4 network.
        assert!(ip_in_list(
            b"::ffff:1.2.3.4",
            &["::ffff:0:0/96".to_string()]
        ));
        assert!(ip_in_list(b"1.2.3.4", &["::ffff:0.0.0.0/96".to_string()]));
        assert!(ip_in_list(
            b"10.1.2.3",
            &["::ffff:10.0.0.0/104".to_string()]
        ));
        assert!(ip_in_list(
            b"192.0.2.50",
            &["::ffff:192.0.2.0/120".to_string()]
        ));
        assert!(!ip_in_list(
            b"192.0.3.50",
            &["::ffff:192.0.2.0/120".to_string()]
        ));
        // ::ffff: falls outside a /80, so the network stays IPv6.
        assert!(!ip_in_list(b"1.2.3.4", &["::ffff:0:0/80".to_string()]));
    }
}
