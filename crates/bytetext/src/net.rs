//! IP address parsing and the address predicates the engines call.

fn hex_digit_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

/// A parsed address; the zone itself is not kept (see `has_zone`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpAddress {
    pub bytes: [u8; 16],
    pub is_ipv4: bool,
    pub has_zone: bool,
}

fn parse_ipv4_octets(s: &[u8], fields: &mut [u8]) -> Result<(), ()> {
    let mut val: u32 = 0;
    let mut pos = 0;
    let mut dig_len = 0;
    for (i, &c) in s.iter().enumerate() {
        if c.is_ascii_digit() {
            if dig_len == 1 && val == 0 {
                return Err(());
            }
            val = val * 10 + u32::from(c - b'0');
            dig_len += 1;
            if val > 255 {
                return Err(());
            }
        } else if c == b'.' {
            if i == 0 || i == s.len() - 1 || s[i - 1] == b'.' {
                return Err(());
            }
            if pos == 3 {
                return Err(());
            }
            fields[pos] = val as u8;
            pos += 1;
            val = 0;
            dig_len = 0;
        } else {
            return Err(());
        }
    }
    if pos < 3 {
        return Err(());
    }
    fields[3] = val as u8;
    Ok(())
}

fn parse_ipv6(input: &[u8]) -> Result<IpAddress, ()> {
    let mut s = input;
    let mut zone: &[u8] = &[];
    if let Some(i) = s.iter().position(|&c| c == b'%') {
        zone = &s[i + 1..];
        s = &s[..i];
        if zone.is_empty() {
            return Err(());
        }
    }
    let mut ip = [0u8; 16];
    let mut ellipsis: isize = -1;
    if s.len() >= 2 && s[0] == b':' && s[1] == b':' {
        ellipsis = 0;
        s = &s[2..];
        if s.is_empty() {
            return Ok(IpAddress {
                bytes: ip,
                is_ipv4: false,
                has_zone: !zone.is_empty(),
            });
        }
    }
    let mut i = 0usize;
    while i < 16 {
        let mut off = 0;
        let mut acc: u32 = 0;
        while off < s.len() {
            let c = s[off];
            if c.is_ascii_hexdigit() {
                acc = (acc << 4) + u32::from(hex_digit_value(c));
            } else {
                break;
            }
            if off > 3 {
                return Err(());
            }
            if acc > 0xFFFF {
                return Err(());
            }
            off += 1;
        }
        if off == 0 {
            return Err(());
        }
        if off < s.len() && s[off] == b'.' {
            if ellipsis < 0 && i != 12 {
                return Err(());
            }
            if i + 4 > 16 {
                return Err(());
            }
            parse_ipv4_octets(s, &mut ip[i..i + 4])?;
            s = &[];
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
        if s[0] != b':' || s.len() == 1 {
            return Err(());
        }
        s = &s[1..];
        if s[0] == b':' {
            if ellipsis >= 0 {
                return Err(());
            }
            ellipsis = i as isize;
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }
    if !s.is_empty() {
        return Err(());
    }
    if i < 16 {
        if ellipsis < 0 {
            return Err(());
        }
        let e = ellipsis as usize;
        let n = 16 - i;
        for j in (e..i).rev() {
            ip[j + n] = ip[j];
        }
        for b in &mut ip[e..e + n] {
            *b = 0;
        }
    } else if ellipsis >= 0 {
        return Err(());
    }
    Ok(IpAddress {
        bytes: ip,
        is_ipv4: false,
        has_zone: !zone.is_empty(),
    })
}

/// The input is not a valid address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpParseError;

pub fn parse_ip_address(s: &[u8]) -> Result<IpAddress, IpParseError> {
    parse_ip_address_inner(s).map_err(|()| IpParseError)
}

fn parse_ip_address_inner(s: &[u8]) -> Result<IpAddress, ()> {
    for &c in s {
        match c {
            b'.' => {
                let mut f = [0u8; 4];
                parse_ipv4_octets(s, &mut f)?;
                let mut b = [0u8; 16];
                b[10] = 0xff;
                b[11] = 0xff;
                b[12..].copy_from_slice(&f);
                return Ok(IpAddress {
                    bytes: b,
                    is_ipv4: true,
                    has_zone: false,
                });
            }
            b':' => return parse_ipv6(s),
            b'%' => return Err(()),
            _ => {}
        }
    }
    Err(())
}

/// An IP address as 4 or 16 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpBytes(pub Vec<u8>);

impl IpBytes {
    /// An IPv4 address in the 16-byte v4-mapped form.
    pub fn v4(a: u8, b: u8, c: u8, d: u8) -> IpBytes {
        let mut v = vec![0u8; 16];
        v[10] = 0xff;
        v[11] = 0xff;
        v[12] = a;
        v[13] = b;
        v[14] = c;
        v[15] = d;
        IpBytes(v)
    }
    pub fn to_ipv4_octets(&self) -> Option<&[u8]> {
        let ip = &self.0;
        if ip.len() == 4 {
            return Some(ip);
        }
        if ip.len() == 16 && ip[..10].iter().all(|&b| b == 0) && ip[10] == 0xff && ip[11] == 0xff {
            return Some(&ip[12..16]);
        }
        None
    }
    pub fn to_ipv6_octets(&self) -> Option<[u8; 16]> {
        match self.0.len() {
            4 => IpBytes::v4(self.0[0], self.0[1], self.0[2], self.0[3])
                .0
                .try_into()
                .ok(),
            16 => self.0.clone().try_into().ok(),
            _ => None,
        }
    }
    fn equal16(&self, other: &[u8; 16]) -> bool {
        self.to_ipv6_octets().is_some_and(|b| &b == other)
    }
    pub fn is_unspecified(&self) -> bool {
        self.equal16(&IpBytes::v4(0, 0, 0, 0).0.try_into().unwrap_or([0; 16]))
            || self.equal16(&[0u8; 16])
    }
    pub fn is_loopback(&self) -> bool {
        if let Some(v4) = self.to_ipv4_octets() {
            return v4[0] == 127;
        }
        let mut lo = [0u8; 16];
        lo[15] = 1;
        self.equal16(&lo)
    }
    pub fn is_private(&self) -> bool {
        if let Some(v4) = self.to_ipv4_octets() {
            return v4[0] == 10
                || (v4[0] == 172 && v4[1] & 0xf0 == 16)
                || (v4[0] == 192 && v4[1] == 168);
        }
        self.0.len() == 16 && self.0[0] & 0xfe == 0xfc
    }
    pub fn is_link_local_multicast(&self) -> bool {
        if let Some(v4) = self.to_ipv4_octets() {
            return v4[0] == 224 && v4[1] == 0 && v4[2] == 0;
        }
        self.0.len() == 16 && self.0[0] == 0xff && self.0[1] & 0x0f == 0x02
    }
    pub fn is_link_local_unicast(&self) -> bool {
        if let Some(v4) = self.to_ipv4_octets() {
            return v4[0] == 169 && v4[1] == 254;
        }
        self.0.len() == 16 && self.0[0] == 0xfe && self.0[1] & 0xc0 == 0x80
    }
}

/// Parses an address; a zoned address is rejected.
pub fn parse_ip(s: &[u8]) -> Option<IpBytes> {
    match parse_ip_address(s) {
        Ok(a) if !a.has_zone => Some(IpBytes(a.bytes.to_vec())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_matches_reference() {
        assert!(parse_ip(b"127.0.0.1").is_some());
        assert!(parse_ip(b"127.000.0.1").is_none());
        assert!(
            parse_ip(b"::ffff:127.0.0.1")
                .unwrap()
                .to_ipv4_octets()
                .is_some()
        );
        assert!(parse_ip(b"fe80::1%eth0").is_none());
        assert!(parse_ip(b"1::2::3").is_none());
        assert!(parse_ip(b"::").unwrap().is_unspecified());
        assert!(parse_ip(b"10.1.2.3").unwrap().is_private());
        assert!(parse_ip(b"fd00::1").unwrap().is_private());
        assert!(parse_ip(b"169.254.1.1").unwrap().is_link_local_unicast());
        assert!(parse_ip(b"::1").unwrap().is_loopback());
        assert!(parse_ip(b"1.2.3").is_none());
        assert!(parse_ip(b"256.1.1.1").is_none());
    }
}
