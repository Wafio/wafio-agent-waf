//! Client IP trust and the control plane's `ClientIPPolicy`.

use std::sync::LazyLock;

use crate::ip_address::{
    IpAddress, IpPrefix, parse_ip_address, parse_ip_prefix, parse_socket_address,
};
use crate::proxyconfig::{ProxyConfig, ProxyError};
use crate::text_helpers::{quote, trim_whitespace, trim_whitespace_str};

/// Caps `proxy_config.trusted_proxies`.
pub const MAX_TRUSTED_PROXIES: usize = 64;

/// Bounds the X-Forwarded-For walk; a longer chain falls back to the peer.
const MAX_FORWARDED_HOPS: usize = 32;

/// Longer than any IP address with a port; longer hops are garbage.
const MAX_FORWARDED_HOP_LEN: usize = 64;

/// Applies when trust_forwarded is true and trusted_proxies is empty:
/// loopback, RFC 1918 and RFC 4193.
static DEFAULT_TRUSTED_PEERS: LazyLock<Vec<IpPrefix>> = LazyLock::new(|| {
    [
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ]
    .iter()
    .map(|s| parse_ip_prefix(s.as_bytes()).expect("static prefix"))
    .collect()
});

impl ProxyConfig {
    /// The address WAF decisions treat as the client. `xff` holds the X-Forwarded-For header lines
    /// in arrival order; `x_real_ip` the last X-Real-IP line, "" when absent.
    pub fn client_ip<S: AsRef<[u8]>>(
        &self,
        peer: &IpAddress,
        xff: &[S],
        x_real_ip: &[u8],
    ) -> IpAddress {
        let peer = peer.without_ipv4_mapping().with_zone(b"");
        if !self.may_supply_forwarded_headers(&peer) {
            return peer;
        }
        if carries_forwarded_for(xff) {
            return self.resolve_forwarded_chain(&peer, xff);
        }
        if !trim_whitespace(x_real_ip).is_empty() && !x_real_ip.contains(&b',') {
            return self.resolve_forwarded_chain(&peer, &[x_real_ip]);
        }
        peer
    }

    /// Reports whether a TCP peer may supply forwarded headers.
    pub fn may_supply_forwarded_headers(&self, peer: &IpAddress) -> bool {
        self.trust_forwarded && self.hop_is_trusted(&peer.without_ipv4_mapping())
    }

    /// Reports whether `a` is an address this config treats as a proxy rather
    /// than a client. With trust_forwarded off and no list, none is.
    pub fn is_proxy_address(&self, a: &IpAddress) -> bool {
        if !self.trust_forwarded && self.trusted_proxies.is_empty() {
            return false;
        }
        self.hop_is_trusted(&a.without_ipv4_mapping().with_zone(b""))
    }

    fn hop_is_trusted(&self, a: &IpAddress) -> bool {
        if self.trusted_proxies.is_empty() {
            return DEFAULT_TRUSTED_PEERS.iter().any(|p| p.contains(a));
        }
        match &self.trusted {
            Some(list) => list.iter().any(|p| p.contains(a)),
            // Built without parse_proxy_config (tests); compile on the fly.
            None => build_trusted_prefixes(&self.trusted_proxies)
                .iter()
                .any(|p| p.contains(a)),
        }
    }

    fn resolve_forwarded_chain<S: AsRef<[u8]>>(&self, peer: &IpAddress, lines: &[S]) -> IpAddress {
        let mut hops = 0;
        for line in lines.iter().rev() {
            let mut rest = line.as_ref();
            if trim_whitespace(rest).is_empty() {
                continue; // a blank header line carries no hop
            }
            loop {
                let comma = rest.iter().rposition(|&c| c == b',');
                let hop = match comma {
                    Some(i) => &rest[i + 1..],
                    None => rest,
                };
                hops += 1;
                if hops > MAX_FORWARDED_HOPS {
                    return peer.clone();
                }
                let Some(a) = read_forwarded_hop(hop) else {
                    return peer.clone();
                };
                if a.is_loopback() {
                    return peer.clone();
                }
                if !self.hop_is_trusted(&a) {
                    return a;
                }
                match comma {
                    None => break,
                    Some(i) => rest = &rest[..i],
                }
            }
        }
        // Every hop was trusted: no header names an untrusted client.
        peer.clone()
    }

    /// What the dashboard should flag about this config.
    pub fn warnings(&self) -> Vec<ProxyWarning> {
        if self.trust_forwarded && self.trusted_proxies.is_empty() {
            return vec![ProxyWarning {
                code: PROXY_WARN_TRUSTED_PROXIES_UNSET.into(),
                message: "Forwarded headers are trusted from any private peer — set trusted proxies. If the agent runs behind Docker or Kubernetes NAT, every client arrives from a private address and can name its own IP: list the real proxies.".into(),
            }];
        }
        if !self.trust_forwarded && !self.trusted_proxies.is_empty() {
            return vec![ProxyWarning {
                code: PROXY_WARN_TRUSTED_PROXIES_IGNORED.into(),
                message: "Trusted proxies are set but forwarded headers are not trusted, so the list has no effect.".into(),
            }];
        }
        Vec::new()
    }
}

fn carries_forwarded_for<S: AsRef<[u8]>>(lines: &[S]) -> bool {
    lines
        .iter()
        .any(|l| !trim_whitespace(l.as_ref()).is_empty())
}

/// Accepts "ip", "ip:port", "[ipv6]" and "[ipv6]:port". Zones and the
/// unspecified address are rejected; v4-mapped IPv6 is unmapped.
fn read_forwarded_hop(s: &[u8]) -> Option<IpAddress> {
    let s = trim_whitespace(s);
    if s.is_empty() || s.len() > MAX_FORWARDED_HOP_LEN {
        return None;
    }
    let a = match parse_ip_address(s) {
        Ok(a) => a,
        Err(_) => {
            if let Ok((a, _)) = parse_socket_address(s) {
                a
            } else if s.len() > 2 && s[0] == b'[' && s[s.len() - 1] == b']' {
                parse_ip_address(&s[1..s.len() - 1]).ok()?
            } else {
                return None;
            }
        }
    };
    if !a.zone().is_empty() {
        return None;
    }
    let a = a.without_ipv4_mapping();
    if a.is_unspecified() {
        return None;
    }
    Some(a)
}

/// Reads one trusted_proxies entry: an IP address (single-host prefix) or a
/// CIDR; v4-mapped IPv6 prefixes become IPv4 ones.
fn read_trusted_proxy_entry(s: &str) -> Option<IpPrefix> {
    let s = trim_whitespace_str(s).as_bytes();
    let mut p = if s.contains(&b'/') {
        parse_ip_prefix(s).ok()?
    } else {
        let a = parse_ip_address(s).ok()?;
        if !a.zone().is_empty() {
            return None;
        }
        IpPrefix::new(&a, a.bit_length())
    };
    if p.address().is_ipv4_mapped() {
        if p.bits() < 96 {
            return None;
        }
        p = IpPrefix::new(&p.address().without_ipv4_mapping(), p.bits() - 96);
    }
    Some(p.network())
}

/// Minimum trusted_proxies prefix lengths (rejecting only /0 was bypassable
/// with two halves).
const MIN_TRUSTED_PREFIX_V4: i16 = 8;
const MIN_TRUSTED_PREFIX_V6: i16 = 16;

fn too_broad(p: &IpPrefix) -> bool {
    if p.address().is_ipv4() {
        return p.bits() < MIN_TRUSTED_PREFIX_V4;
    }
    p.bits() < MIN_TRUSTED_PREFIX_V6
}

/// Keeps the valid entries that are not too broad. Non-None for a non-empty
/// list, so an all-invalid list trusts nobody instead of the default.
pub(crate) fn build_trusted_prefixes(list: &[String]) -> Vec<IpPrefix> {
    list.iter()
        .filter_map(|s| read_trusted_proxy_entry(s))
        .filter(|p| !too_broad(p))
        .collect()
}

pub(crate) fn check_trusted_proxies(list: &[String]) -> Result<(), ProxyError> {
    if list.len() > MAX_TRUSTED_PROXIES {
        return Err(ProxyError(format!(
            "trusted_proxies: too many entries (max {MAX_TRUSTED_PROXIES})"
        )));
    }
    for (i, s) in list.iter().enumerate() {
        let Some(p) = read_trusted_proxy_entry(s) else {
            return Err(ProxyError(format!(
                "trusted_proxies[{i}]: {} is not an IP address or CIDR",
                quote(&shorten_entry(s))
            )));
        };
        if too_broad(&p) {
            return Err(ProxyError(format!(
                "trusted_proxies[{i}]: {} is too broad (at least /{MIN_TRUSTED_PREFIX_V4} for IPv4, /{MIN_TRUSTED_PREFIX_V6} for IPv6); list the proxies' own addresses",
                quote(&shorten_entry(s))
            )));
        }
    }
    Ok(())
}

/// The first 64 bytes plus "…" (a cut may split a rune).
fn shorten_entry(s: &str) -> Vec<u8> {
    const N: usize = 64;
    if s.len() > N {
        let mut cut = s.as_bytes()[..N].to_vec();
        cut.extend_from_slice("…".as_bytes());
        return cut;
    }
    s.as_bytes().to_vec()
}

/// Proxy config warning codes.
pub const PROXY_WARN_TRUSTED_PROXIES_UNSET: &str = "TRUSTED_PROXIES_UNSET";
pub const PROXY_WARN_TRUSTED_PROXIES_IGNORED: &str = "TRUSTED_PROXIES_IGNORED";

/// An advisory about a stored proxy config.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProxyWarning {
    pub code: String,
    pub message: String,
}

/// Parses a stored proxy_config and returns its warnings (none when it does
/// not parse).
pub fn proxy_config_warnings(raw: &[u8]) -> Vec<ProxyWarning> {
    match crate::proxyconfig::parse_proxy_config(raw) {
        Ok(pc) => pc.warnings(),
        Err(_) => Vec::new(),
    }
}

/// Forwarded-client headers the control plane can read behind a proxy.
pub const PROXY_HEADER_FORWARDED_FOR: &str = "X-Forwarded-For";
pub const PROXY_HEADER_REAL_IP: &str = "X-Real-IP";

/// The control plane's client-address rule (server.trusted_proxies,
/// server.proxy_header): the TCP peer is the client unless it is a listed
/// proxy.
#[derive(Clone, Debug, Default)]
pub struct ClientIpPolicy {
    pc: ProxyConfig,
    header: &'static str,
}

impl ClientIpPolicy {
    /// Validates `trusted` and `header` ("" = X-Forwarded-For, or X-Real-IP,
    /// case-insensitive). An empty list trusts no peer.
    pub fn new(trusted: &[String], header: &str) -> Result<ClientIpPolicy, ProxyError> {
        let list: Vec<String> = trusted
            .iter()
            .map(|s| trim_whitespace_str(s))
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        if let Err(e) = check_trusted_proxies(&list) {
            return Err(ProxyError(format!("server.{}", e.0)));
        }
        let h = match crate::text_helpers::to_lowercase(trim_whitespace_str(header).as_bytes())
            .as_slice()
        {
            b"" | b"x-forwarded-for" => PROXY_HEADER_FORWARDED_FOR,
            b"x-real-ip" => PROXY_HEADER_REAL_IP,
            _ => {
                return Err(ProxyError(format!(
                    "server.proxy_header: {} is not {PROXY_HEADER_FORWARDED_FOR} or {PROXY_HEADER_REAL_IP}",
                    quote(&shorten_entry(header))
                )));
            }
        };
        let mut p = ClientIpPolicy {
            pc: ProxyConfig::default(),
            header: h,
        };
        if !list.is_empty() {
            p.pc.trust_forwarded = true;
            p.pc.trusted = Some(build_trusted_prefixes(&list));
            p.pc.trusted_proxies = list;
        }
        Ok(p)
    }

    /// Reports whether any proxy is trusted.
    pub fn enabled(&self) -> bool {
        self.pc.trust_forwarded
    }

    /// The forwarded-client header the policy reads.
    pub fn header(&self) -> &'static str {
        if self.header.is_empty() {
            PROXY_HEADER_FORWARDED_FOR
        } else {
            self.header
        }
    }

    /// The client address for a request from `peer`; only the configured
    /// header is read.
    pub fn client_ip<S: AsRef<[u8]>>(
        &self,
        peer: &IpAddress,
        xff: &[S],
        x_real_ip: &[u8],
    ) -> IpAddress {
        if !self.enabled() {
            return peer.without_ipv4_mapping().with_zone(b"");
        }
        if self.header == PROXY_HEADER_REAL_IP {
            return self.pc.client_ip::<&[u8]>(peer, &[], x_real_ip);
        }
        self.pc.client_ip(peer, xff, b"")
    }
}

#[cfg(test)]
mod tests;
