//! The IP address subset the client-IP rules use: `IpAddress` (IPv4, IPv6 with optional zone),
//! `parse_ip_address`, `parse_socket_address`, `parse_ip_prefix`, `IpPrefix::contains` and `network`,
//! with strict acceptance rules (no leading zeros in IPv4 octets, zones only on IPv6, prefix bits
//! without sign or leading zero).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IPv4 or IPv6 address. The default value is the invalid zero address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IpAddress {
    /// 0 = invalid, 4 or 6.
    family: u8,
    bytes: [u8; 16],
    zone: Vec<u8>,
}

/// An address prefix. The default value is the invalid zero prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    address: IpAddress,
    bits: i16, // -1 when invalid
}

/// Parse failure; the message is for logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpParseError(pub String);

impl fmt::Display for IpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn fail<T>(msg: &str) -> Result<T, IpParseError> {
    Err(IpParseError(msg.to_string()))
}

impl IpAddress {
    pub fn from_ipv4(b: [u8; 4]) -> IpAddress {
        let mut bytes = [0u8; 16];
        bytes[12..].copy_from_slice(&b);
        IpAddress {
            family: 4,
            bytes,
            zone: Vec::new(),
        }
    }

    pub fn from_ipv6(bytes: [u8; 16]) -> IpAddress {
        IpAddress {
            family: 6,
            bytes,
            zone: Vec::new(),
        }
    }

    /// From a std address (IPv4 stays IPv4, IPv6 stays IPv6 even when mapped).
    pub fn from_std(ip: IpAddr) -> IpAddress {
        match ip {
            IpAddr::V4(v) => IpAddress::from_ipv4(v.octets()),
            IpAddr::V6(v) => IpAddress::from_ipv6(v.octets()),
        }
    }

    /// The std address (zone dropped); None for the zero Addr.
    pub fn to_std(&self) -> Option<IpAddr> {
        match self.family {
            4 => Some(IpAddr::V4(Ipv4Addr::new(
                self.bytes[12],
                self.bytes[13],
                self.bytes[14],
                self.bytes[15],
            ))),
            6 => Some(IpAddr::V6(Ipv6Addr::from(self.bytes))),
            _ => None,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.family != 0
    }

    pub fn is_ipv4(&self) -> bool {
        self.family == 4
    }

    pub fn is_ipv6(&self) -> bool {
        self.family == 6
    }

    /// An IPv4-mapped IPv6 address.
    pub fn is_ipv4_mapped(&self) -> bool {
        self.is_ipv6()
            && self.bytes[..10].iter().all(|&b| b == 0)
            && self.bytes[10] == 0xff
            && self.bytes[11] == 0xff
    }

    pub fn without_ipv4_mapping(&self) -> IpAddress {
        if self.is_ipv4_mapped() {
            let mut b = [0u8; 4];
            b.copy_from_slice(&self.bytes[12..]);
            return IpAddress::from_ipv4(b);
        }
        self.clone()
    }

    /// IPv4 and the zero address ignore the zone.
    pub fn with_zone(&self, zone: &[u8]) -> IpAddress {
        let mut a = self.clone();
        if a.is_ipv6() {
            a.zone = zone.to_vec();
        }
        a
    }

    pub fn zone(&self) -> &[u8] {
        &self.zone
    }

    /// Bit length: 32, 128, or 0 for the zero address.
    pub fn bit_length(&self) -> i16 {
        match self.family {
            4 => 32,
            6 => 128,
            _ => 0,
        }
    }

    pub fn is_loopback(&self) -> bool {
        let a = self.without_ipv4_mapping();
        if a.is_ipv4() {
            return a.bytes[12] == 127;
        }
        a.is_ipv6() && a.bytes[..15].iter().all(|&b| b == 0) && a.bytes[15] == 1
    }

    /// Whether the address is unspecified (a zoned `::` is not unspecified).
    pub fn is_unspecified(&self) -> bool {
        self.is_valid() && self.zone.is_empty() && {
            let off = if self.is_ipv4() { 12 } else { 0 };
            self.bytes[off..].iter().all(|&b| b == 0)
        }
    }

    /// Masks to the top `bits` bits.
    pub fn to_prefix(&self, bits: i16) -> Option<IpPrefix> {
        if bits < 0 || !self.is_valid() || bits > self.bit_length() {
            return None;
        }
        let mut a = self.clone();
        a.zone.clear();
        let off = if a.is_ipv4() { 12 } else { 0 };
        let total = usize::from(bits as u16) + off * 8;
        for (i, b) in a.bytes.iter_mut().enumerate() {
            let start = i * 8;
            if start >= total {
                *b = 0;
            } else if start + 8 > total {
                *b &= 0xFFu8 << (8 - (total - start));
            }
        }
        Some(IpPrefix { address: a, bits })
    }
}

impl fmt::Display for IpAddress {
    /// Text form ("invalid IP" for the zero address).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_std() {
            None => f.write_str("invalid IP"),
            Some(ip) => {
                write!(f, "{ip}")?;
                if !self.zone.is_empty() {
                    write!(f, "%{}", String::from_utf8_lossy(&self.zone))?;
                }
                Ok(())
            }
        }
    }
}

impl IpPrefix {
    /// Builds a prefix (invalid bits give an invalid prefix; the zone is dropped).
    pub fn new(addr: &IpAddress, bits: i16) -> IpPrefix {
        if bits < 0 || bits > addr.bit_length() || !addr.is_valid() {
            return IpPrefix {
                address: addr.with_zone(b""),
                bits: -1,
            };
        }
        IpPrefix {
            address: addr.with_zone(b""),
            bits,
        }
    }

    pub fn address(&self) -> &IpAddress {
        &self.address
    }

    /// The prefix length (-1 when invalid).
    pub fn bits(&self) -> i16 {
        self.bits
    }

    pub fn is_valid(&self) -> bool {
        self.address.is_valid() && self.bits >= 0 && self.bits <= self.address.bit_length()
    }

    /// The network of the prefix, host bits cleared (the zero prefix when invalid).
    pub fn network(&self) -> IpPrefix {
        self.address.to_prefix(self.bits).unwrap_or_default()
    }

    /// Same family, no zone, top bits equal.
    pub fn contains(&self, ip: &IpAddress) -> bool {
        if !self.is_valid()
            || !ip.zone.is_empty()
            || ip.bit_length() == 0
            || ip.bit_length() != self.address.bit_length()
        {
            return false;
        }
        match (ip.to_prefix(self.bits), self.address.to_prefix(self.bits)) {
            (Some(a), Some(b)) => a.address.bytes == b.address.bytes,
            _ => false,
        }
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.is_valid() {
            return f.write_str("invalid Prefix");
        }
        write!(f, "{}/{}", self.address, self.bits)
    }
}

fn parse_ipv4_fields(s: &[u8], fields: &mut [u8]) -> Result<(), IpParseError> {
    let (mut val, mut pos, mut dig_len) = (0u32, 0usize, 0);
    for i in 0..s.len() {
        let c = s[i];
        if c.is_ascii_digit() {
            if dig_len == 1 && val == 0 {
                return fail("IPv4 field has octet with leading zero");
            }
            val = val * 10 + u32::from(c - b'0');
            dig_len += 1;
            if val > 255 {
                return fail("IPv4 field has value >255");
            }
        } else if c == b'.' {
            if i == 0 || i == s.len() - 1 || s[i - 1] == b'.' {
                return fail("IPv4 field must have at least one digit");
            }
            if pos == 3 {
                return fail("IPv4 address too long");
            }
            fields[pos] = val as u8;
            pos += 1;
            val = 0;
            dig_len = 0;
        } else {
            return fail("unexpected character");
        }
    }
    if pos < 3 {
        return fail("IPv4 address too short");
    }
    fields[3] = val as u8;
    Ok(())
}

fn parse_ipv6(input: &[u8]) -> Result<IpAddress, IpParseError> {
    let mut s = input;
    let mut zone: &[u8] = b"";
    if let Some(i) = s.iter().position(|&c| c == b'%') {
        zone = &s[i + 1..];
        s = &s[..i];
        if zone.is_empty() {
            return fail("zone must be a non-empty string");
        }
    }
    let mut ip = [0u8; 16];
    let mut ellipsis: isize = -1;
    if s.len() >= 2 && s[0] == b':' && s[1] == b':' {
        ellipsis = 0;
        s = &s[2..];
        if s.is_empty() {
            return Ok(IpAddress::from_ipv6([0; 16]).with_zone(zone));
        }
    }
    let mut i = 0usize;
    while i < 16 {
        let mut off = 0;
        let mut acc: u32 = 0;
        while off < s.len() {
            let c = s[off];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => break,
            };
            acc = (acc << 4) + u32::from(d);
            if off > 3 {
                return fail("each group must have 4 or less digits");
            }
            if acc > 0xFFFF {
                return fail("IPv6 field has value >=2^16");
            }
            off += 1;
        }
        if off == 0 {
            return fail("each colon-separated field must have at least one digit");
        }
        if off < s.len() && s[off] == b'.' {
            if ellipsis < 0 && i != 12 {
                return fail(
                    "embedded IPv4 address must replace the final 2 fields of the address",
                );
            }
            if i + 4 > 16 {
                return fail(
                    "too many hex fields to fit an embedded IPv4 at the end of the address",
                );
            }
            parse_ipv4_fields(s, &mut ip[i..i + 4])?;
            s = b"";
            i += 4;
            break;
        }
        ip[i] = (acc >> 8) as u8;
        ip[i + 1] = acc as u8;
        i += 2;
        s = &s[off..];
        if s.is_empty() {
            break;
        }
        if s[0] != b':' {
            return fail("unexpected character, want colon");
        } else if s.len() == 1 {
            return fail("colon must be followed by more characters");
        }
        s = &s[1..];
        if s[0] == b':' {
            if ellipsis >= 0 {
                return fail("multiple :: in address");
            }
            ellipsis = i as isize;
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }
    if !s.is_empty() {
        return fail("trailing garbage after address");
    }
    if i < 16 {
        if ellipsis < 0 {
            return fail("address string too short");
        }
        let e = ellipsis as usize;
        let n = 16 - i;
        let mut j = i;
        while j > e {
            j -= 1;
            ip[j + n] = ip[j];
        }
        ip[e..e + n].fill(0);
    } else if ellipsis >= 0 {
        return fail("the :: must expand to at least one field of zeros");
    }
    Ok(IpAddress::from_ipv6(ip).with_zone(zone))
}

pub fn parse_ip_address(s: &[u8]) -> Result<IpAddress, IpParseError> {
    for &c in s {
        match c {
            b'.' => {
                let mut f = [0u8; 4];
                parse_ipv4_fields(s, &mut f)?;
                return Ok(IpAddress::from_ipv4(f));
            }
            b':' => return parse_ipv6(s),
            b'%' => return fail("missing IPv6 address"),
            _ => {}
        }
    }
    fail("unable to parse IP")
}

fn parse_port(s: &[u8]) -> Option<u16> {
    wafio_bytetext::literal::parse_uint(s, 10, 16)
        .ok()
        .map(|v| v as u16)
}

pub fn parse_socket_address(s: &[u8]) -> Result<(IpAddress, u16), IpParseError> {
    let Some(i) = s.iter().rposition(|&c| c == b':') else {
        return fail("not an ip:port");
    };
    let (mut ip, port) = (&s[..i], &s[i + 1..]);
    if ip.is_empty() {
        return fail("no IP");
    }
    if port.is_empty() {
        return fail("no port");
    }
    let mut v6 = false;
    if ip[0] == b'[' {
        if ip.len() < 2 || ip[ip.len() - 1] != b']' {
            return fail("missing ]");
        }
        ip = &ip[1..ip.len() - 1];
        v6 = true;
    }
    let Some(port) = parse_port(port) else {
        return fail("invalid port");
    };
    let a = parse_ip_address(ip)?;
    if v6 && a.is_ipv4() {
        return fail("square brackets can only be used with IPv6 addresses");
    } else if !v6 && a.is_ipv6() {
        return fail("IPv6 addresses must be surrounded by square brackets");
    }
    Ok((a, port))
}

/// Parses `address/bits` (the result is not masked).
pub fn parse_ip_prefix(s: &[u8]) -> Result<IpPrefix, IpParseError> {
    let Some(i) = s.iter().rposition(|&c| c == b'/') else {
        return fail("no '/'");
    };
    let ip = parse_ip_address(&s[..i])?;
    if ip.is_ipv6() && !ip.zone.is_empty() {
        return fail("IPv6 zones cannot be present in a prefix");
    }
    let bits_str = &s[i + 1..];
    if bits_str.len() > 1 && !(b'1'..=b'9').contains(&bits_str[0]) {
        return fail("bad bits after slash");
    }
    let Ok(bits) = wafio_bytetext::literal::parse_decimal(bits_str) else {
        return fail("bad bits after slash");
    };
    let max_bits = if ip.is_ipv6() { 128 } else { 32 };
    if !(0..=max_bits).contains(&bits) {
        return fail("prefix length out of range");
    }
    Ok(IpPrefix::new(&ip, bits as i16))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> IpAddress {
        parse_ip_address(s.as_bytes()).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn parse_ip_address_rules() {
        for ok in [
            "1.2.3.4",
            "::",
            "::1",
            "fe80::1%eth0",
            "::ffff:1.2.3.4",
            "2001:db8::68",
            "1:2:3:4:5:6:7:8",
            "1::7.8.9.10",
        ] {
            assert!(parse_ip_address(ok.as_bytes()).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "01.2.3.4",
            "1.2.3",
            "1.2.3.4.5",
            "256.1.1.1",
            "1.2.3.4%eth0",
            "fe80::1%",
            "1:2:3:4:5:6:7:8:9",
            "1::2::3",
            "12345::",
            "%eth0",
            "1.2.3.",
            "::1.2.3",
        ] {
            assert!(parse_ip_address(bad.as_bytes()).is_err(), "{bad}");
        }
        assert_eq!(a("::ffff:1.2.3.4").without_ipv4_mapping(), a("1.2.3.4"));
        assert_eq!(a("2001:0db8:0:0:0:0:0:1").to_string(), "2001:db8::1");
        assert_eq!(a("fe80::1%eth0").to_string(), "fe80::1%eth0");
        assert!(
            a("127.9.9.9").is_loopback()
                && a("::1").is_loopback()
                && a("::ffff:127.0.0.1").is_loopback()
        );
        assert!(
            a("0.0.0.0").is_unspecified()
                && a("::").is_unspecified()
                && !a("::%x").is_unspecified()
        );
    }

    #[test]
    fn parse_socket_address_rules() {
        assert_eq!(
            parse_socket_address(b"1.2.3.4:80").unwrap(),
            (a("1.2.3.4"), 80)
        );
        assert_eq!(parse_socket_address(b"[::1]:443").unwrap(), (a("::1"), 443));
        for bad in [
            "1.2.3.4",
            "::1:80",
            "[1.2.3.4]:80",
            "1.2.3.4:",
            "1.2.3.4:65536",
            ":80",
            "1.2.3.4:+1",
            "[::1:80",
        ] {
            assert!(parse_socket_address(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn ip_prefix_rules() {
        let p = parse_ip_prefix(b"10.1.2.3/8").unwrap();
        assert_eq!(p.network().to_string(), "10.0.0.0/8");
        assert!(p.contains(&a("10.200.0.1")) && !p.contains(&a("11.0.0.1")));
        assert!(!p.contains(&a("::ffff:10.0.0.1")), "different family");
        let p6 = parse_ip_prefix(b"fc00::/7").unwrap();
        assert!(p6.contains(&a("fd12::1")) && !p6.contains(&a("fd12::1%eth0")));
        for bad in [
            "10.0.0.0/08",
            "10.0.0.0/+8",
            "10.0.0.0/33",
            "10.0.0.0",
            "fe80::1%x/64",
            "10.0.0.0/",
            "10.0.0.0/-1",
        ] {
            assert!(parse_ip_prefix(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(parse_ip_prefix(b"0.0.0.0/0").is_ok());
        assert_eq!(parse_ip_prefix(b"::ffff:10.0.0.0/104").unwrap().bits(), 104);
    }
}
