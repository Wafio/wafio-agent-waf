//! Client IP trust on the inline proxy.
//! The route's `ProxyConfig` decides whether the TCP peer may name the
//! client; these helpers apply it to the request, to the headers the upstream
//! receives and to the "local client" challenge exemption. Request headers are
//! `(name, value)` pairs in arrival order; names match case-insensitively.

use std::net::IpAddr;

use wafio_bytetext::strings::eq_ignore_case;
use wafio_domain::ProxyConfig;
use wafio_domain::ip_address::IpAddress;

pub const HEADER_X_REAL_IP: &str = "X-Real-IP";
pub const HEADER_X_FORWARDED_FOR: &str = "X-Forwarded-For";

/// The TCP peer, unmapped (a v4 client on a dual-stack
/// listener is IPv4). `None` (no IP peer) is the invalid zero IpAddress.
pub fn tcp_peer_address(remote: Option<IpAddr>) -> IpAddress {
    remote
        .map(|ip| IpAddress::from_std(ip).without_ipv4_mapping())
        .unwrap_or_default()
}

fn values<'a, N: AsRef<[u8]>, V: AsRef<[u8]>>(
    headers: &'a [(N, V)],
    name: &'a str,
) -> impl Iterator<Item = &'a [u8]> + 'a {
    headers
        .iter()
        .filter(move |(n, _)| n.as_ref().eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, v)| v.as_ref())
}

/// The client IP for WAF decisions: the TCP peer,
/// unless trust_forwarded is on and the peer is a trusted proxy; then
/// X-Forwarded-For is walked from the right (X-Real-IP only without XFF).
pub fn effective_client_ip<N: AsRef<[u8]>, V: AsRef<[u8]>>(
    peer: &IpAddress,
    headers: &[(N, V)],
    pxy: &ProxyConfig,
) -> String {
    if !pxy.may_supply_forwarded_headers(peer) {
        return peer.to_string();
    }
    let xff: Vec<&[u8]> = values(headers, HEADER_X_FORWARDED_FOR).collect();
    let x_real_ip = values(headers, HEADER_X_REAL_IP).last().unwrap_or(b"");
    pxy.client_ip(peer, &xff, x_real_ip).to_string()
}

/// From a trusted proxy: the incoming chain (every header line, in order, trimmed, empty lines
/// dropped) plus the TCP peer. Otherwise the peer alone, so a client's own hops never reach the upstream.
pub fn outgoing_forwarded_for<N: AsRef<[u8]>, V: AsRef<[u8]>>(
    peer: &IpAddress,
    headers: &[(N, V)],
    pxy: &ProxyConfig,
) -> Vec<u8> {
    let peer_s = peer.to_string().into_bytes();
    if !pxy.may_supply_forwarded_headers(peer) {
        return peer_s;
    }
    let mut parts: Vec<&[u8]> = values(headers, HEADER_X_FORWARDED_FOR)
        .map(wafio_bytetext::strings::trim_whitespace)
        .filter(|s| !s.is_empty())
        .collect();
    parts.push(&peer_s);
    parts.join(&b", "[..])
}

/// X-Real-IP / X-Forwarded-For under any case and with `_` for `-`
/// (nginx-style backends and CGI treat those as the same header; PHP-FPM maps both to
/// `HTTP_X_FORWARDED_FOR`).
pub fn is_client_address_header(name: &[u8]) -> bool {
    let dashed: Vec<u8> = name
        .iter()
        .map(|&c| if c == b'_' { b'-' } else { c })
        .collect();
    eq_ignore_case(&dashed, HEADER_X_REAL_IP.as_bytes())
        || eq_ignore_case(&dashed, HEADER_X_FORWARDED_FOR.as_bytes())
}

/// Removes every incoming X-Real-IP and X-Forwarded-For line
/// (any case, underscore spellings included) and every `Proxy` line (httpoxy) from the upstream
/// header list, then appends the replacements. The route's `request_headers` are applied after this.
/// The other lines keep their order.
pub fn rewrite_upstream_client_headers(
    upstream: &mut Vec<(Vec<u8>, Vec<u8>)>,
    remote: &[u8],
    forwarded_for: Vec<u8>,
) {
    upstream.retain(|(n, _)| !is_client_address_header(n) && !eq_ignore_case(n, b"Proxy"));
    upstream.push((HEADER_X_REAL_IP.as_bytes().to_vec(), remote.to_vec()));
    upstream.push((HEADER_X_FORWARDED_FOR.as_bytes().to_vec(), forwarded_for));
}

/// True for a loopback or private client that is the TCP
/// peer itself. An address from X-Forwarded-For or X-Real-IP never counts.
pub fn is_direct_local_client(peer: &IpAddress, client_ip: &str) -> bool {
    let peer_s = peer.to_string();
    if !peer.is_ipv4() || strip_port(client_ip) != peer_s {
        return false;
    }
    matches!(parse_dotted_quad(&peer_s), Some(n) if is_non_routable_ipv4(n))
}

/// Drops a trailing ":port" from an IPv4
/// address; an IPv6 address (several colons) is returned unchanged.
pub fn strip_port(ip: &str) -> &str {
    if let Some(i) = ip.rfind(':')
        && ip.find(':') == Some(i)
    {
        return &ip[..i];
    }
    ip
}

/// Non-routable IPv4 ranges: 127/8, 10/8, 172.16/12,
/// 192.168/16, 169.254/16, 100.64/10.
pub fn is_non_routable_ipv4(n: u32) -> bool {
    n >> 24 == 127
        || n >> 24 == 10
        || (n >> 20) & 0xFFF == 0xAC1
        || n >> 16 == 0xC0A8
        || n >> 16 == 0xA9FE
        || (n >> 22) == 0x191
}

/// Dotted decimal to u32 (leading zeros
/// accepted, trailing bytes refused).
pub fn parse_dotted_quad(s: &str) -> Option<u32> {
    let mut s = s.as_bytes();
    let mut result: u32 = 0;
    for i in 0..4 {
        if s.is_empty() {
            return None;
        }
        let mut octet: u32 = 0;
        let mut j = 0;
        while j < s.len() && s[j].is_ascii_digit() {
            octet = octet * 10 + u32::from(s[j] - b'0');
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
    if !s.is_empty() {
        return None; // trailing chars
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafio_domain::ip_address::parse_ip_address;
    use wafio_domain::parse_proxy_config;

    const LISTED: &str =
        r#"{"trust_forwarded":true,"trusted_proxies":["10.0.0.0/8","2001:db8:ffff::/48"]}"#;
    const PRIVATE: &str = r#"{"trust_forwarded":true}"#;

    fn peer(s: &str) -> IpAddress {
        tcp_peer_address(Some(s.parse().unwrap()))
    }

    #[test]
    fn effective_client_ip_cases() {
        type H = &'static [(&'static str, &'static str)];
        let cases: &[(&str, &str, &str, H, &str)] = &[
            (
                "spoofed XFF from untrusted peer",
                LISTED,
                "203.0.113.7",
                &[("X-Forwarded-For", "1.2.3.4")],
                "203.0.113.7",
            ),
            (
                "X-Real-IP from untrusted peer",
                LISTED,
                "203.0.113.7",
                &[("X-Real-IP", "1.2.3.4")],
                "203.0.113.7",
            ),
            (
                "chain through two trusted proxies",
                LISTED,
                "10.0.0.2",
                &[("X-Forwarded-For", "6.6.6.6, 1.2.3.4, 10.0.0.1")],
                "1.2.3.4",
            ),
            (
                "proxy adds its own line",
                LISTED,
                "10.0.0.2",
                &[
                    ("X-Forwarded-For", "6.6.6.6"),
                    ("X-Forwarded-For", "1.2.3.4"),
                ],
                "1.2.3.4",
            ),
            (
                "lower-case header names",
                LISTED,
                "10.0.0.1",
                &[("x-forwarded-for", "1.2.3.4")],
                "1.2.3.4",
            ),
            (
                "garbage value",
                LISTED,
                "10.0.0.1",
                &[("X-Forwarded-For", "evil")],
                "10.0.0.1",
            ),
            (
                "IPv6 peer and client",
                LISTED,
                "2001:db8:ffff::1",
                &[("X-Forwarded-For", "2001:db8:1::5")],
                "2001:db8:1::5",
            ),
            (
                "IPv6 untrusted peer",
                LISTED,
                "2001:db8:1::1",
                &[("X-Forwarded-For", "1.2.3.4")],
                "2001:db8:1::1",
            ),
            (
                "X-Real-IP from trusted peer",
                LISTED,
                "10.0.0.1",
                &[("X-Real-IP", "1.2.3.4")],
                "1.2.3.4",
            ),
            (
                "last X-Real-IP line",
                LISTED,
                "10.0.0.1",
                &[("X-Real-IP", "6.6.6.6"), ("X-Real-IP", "1.2.3.4")],
                "1.2.3.4",
            ),
            (
                "XFF wins over X-Real-IP",
                LISTED,
                "10.0.0.1",
                &[("X-Real-IP", "6.6.6.6"), ("X-Forwarded-For", "1.2.3.4")],
                "1.2.3.4",
            ),
            (
                "empty list: private peer trusted",
                PRIVATE,
                "192.168.1.1",
                &[("X-Forwarded-For", "1.2.3.4")],
                "1.2.3.4",
            ),
            (
                "empty list: loopback peer trusted",
                PRIVATE,
                "127.0.0.1",
                &[("X-Real-IP", "1.2.3.4")],
                "1.2.3.4",
            ),
            (
                "empty list: public peer ignored",
                PRIVATE,
                "198.51.100.9",
                &[("X-Forwarded-For", "1.2.3.4"), ("X-Real-IP", "5.6.7.8")],
                "198.51.100.9",
            ),
            (
                "trust_forwarded absent",
                "{}",
                "127.0.0.1",
                &[("X-Forwarded-For", "1.2.3.4")],
                "127.0.0.1",
            ),
            (
                "trust_forwarded false",
                r#"{"trust_forwarded":false}"#,
                "10.0.0.1",
                &[("X-Forwarded-For", "1.2.3.4")],
                "10.0.0.1",
            ),
            ("no forwarded headers", LISTED, "10.0.0.1", &[], "10.0.0.1"),
            (
                "v4-mapped peer unmapped",
                "{}",
                "::ffff:10.0.0.1",
                &[],
                "10.0.0.1",
            ),
        ];
        for (name, cfg, p, headers, want) in cases {
            let pxy = parse_proxy_config(cfg.as_bytes()).unwrap();
            assert_eq!(
                effective_client_ip(&peer(p), headers, &pxy),
                *want,
                "{name}"
            );
        }
    }

    #[test]
    fn nat_peer_cannot_claim_loopback() {
        let pxy = parse_proxy_config(PRIVATE.as_bytes()).unwrap();
        for h in [
            [("X-Forwarded-For", "127.0.0.1")],
            [("X-Forwarded-For", "10.9.9.9, 192.168.0.1")],
            [("X-Real-IP", "127.0.0.1")],
            [("X-Real-IP", "::1")],
        ] {
            assert_eq!(
                effective_client_ip(&peer("172.17.0.1"), &h, &pxy),
                "172.17.0.1",
                "{h:?}"
            );
        }
    }

    #[test]
    fn upstream_forwarded_headers() {
        let pxy =
            parse_proxy_config(br#"{"trust_forwarded":true,"trusted_proxies":["10.0.0.0/8"]}"#)
                .unwrap();
        let spoof = [
            ("X-Forwarded-For", "6.6.6.6"),
            ("X-Forwarded-For", "7.7.7.7, 8.8.8.8"),
            ("X-Real-IP", "9.9.9.9"),
            ("X-Real-IP", "5.5.5.5"),
        ];
        let off = parse_proxy_config(br#"{"trust_forwarded":false}"#).unwrap();
        type H<'a> = &'a [(&'a str, &'a str)];
        let cases: &[(&ProxyConfig, &str, H, &str, &str)] = &[
            (&pxy, "203.0.113.7", &spoof, "203.0.113.7", "203.0.113.7"),
            (&off, "10.0.0.2", &spoof, "10.0.0.2", "10.0.0.2"),
            (&pxy, "203.0.113.7", &[], "203.0.113.7", "203.0.113.7"),
            (
                &pxy,
                "10.0.0.2",
                &[
                    ("X-Forwarded-For", "6.6.6.6"),
                    ("X-Forwarded-For", "1.2.3.4, 10.0.0.1"),
                    ("X-Real-IP", "9.9.9.9"),
                ],
                "6.6.6.6, 1.2.3.4, 10.0.0.1, 10.0.0.2",
                "1.2.3.4",
            ),
            (
                &pxy,
                "10.0.0.2",
                &[("X-Forwarded-For", "  "), ("X-Forwarded-For", " 1.2.3.4 ")],
                "1.2.3.4, 10.0.0.2",
                "1.2.3.4",
            ),
        ];
        for (cfg, p, headers, want_xff, want_xri) in cases {
            let pe = peer(p);
            let remote = effective_client_ip(&pe, headers, cfg);
            let mut up: Vec<(Vec<u8>, Vec<u8>)> = headers
                .iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect();
            up.push((b"x-real-ip".to_vec(), b"1.1.1.1".to_vec()));
            rewrite_upstream_client_headers(
                &mut up,
                remote.as_bytes(),
                outgoing_forwarded_for(&pe, headers, cfg),
            );
            let get = |name: &str| -> Vec<String> {
                up.iter()
                    .filter(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
                    .map(|(_, v)| String::from_utf8(v.clone()).unwrap())
                    .collect()
            };
            assert_eq!(
                get("X-Forwarded-For"),
                vec![want_xff.to_string()],
                "{p} {headers:?}"
            );
            assert_eq!(
                get("X-Real-IP"),
                vec![want_xri.to_string()],
                "{p} {headers:?}"
            );
        }
    }

    /// TestSetUpstreamClientHeadersDropsSpoofsAndProxy: underscore spellings and `Proxy` never reach
    /// the upstream.
    #[test]
    fn upstream_headers_drop_spoofs_and_proxy() {
        for name in [
            "X_Forwarded_For",
            "x_real_ip",
            "X-Real_IP",
            "X_FORWARDED-FOR",
            "Proxy",
            "proxy",
        ] {
            let mut up: Vec<(Vec<u8>, Vec<u8>)> = vec![
                (name.as_bytes().to_vec(), b"6.6.6.6".to_vec()),
                (name.as_bytes().to_vec(), b"7.7.7.7".to_vec()),
                (b"X-Forwarded-For".to_vec(), b"5.5.5.5".to_vec()),
                (b"User-Agent".to_vec(), b"t".to_vec()),
            ];
            rewrite_upstream_client_headers(&mut up, b"203.0.113.7", b"203.0.113.7".to_vec());
            let names: Vec<&[u8]> = up.iter().map(|(n, _)| n.as_slice()).collect();
            assert_eq!(
                names,
                [&b"User-Agent"[..], b"X-Real-IP", b"X-Forwarded-For"],
                "{name}"
            );
            assert!(
                up.iter().skip(1).all(|(_, v)| v == b"203.0.113.7"),
                "{name}"
            );
        }
        for (n, want) in [
            ("X-Real-IP", true),
            ("x-forwarded-for", true),
            ("X_REAL_IP", true),
            ("X-Forwarded_For", true),
            ("X-Real-IP2", false),
            ("X Real IP", false),
            ("Proxy", false),
            ("", false),
        ] {
            assert_eq!(is_client_address_header(n.as_bytes()), want, "{n:?}");
        }
    }

    #[test]
    fn local_socket_client() {
        assert!(is_direct_local_client(&peer("127.0.0.1"), "127.0.0.1:5555"));
        assert!(is_direct_local_client(&peer("192.168.1.2"), "192.168.1.2"));
        assert!(!is_direct_local_client(&peer("10.0.0.1"), "192.168.7.7"));
        assert!(!is_direct_local_client(&peer("203.0.113.1"), "203.0.113.1"));
        assert!(!is_direct_local_client(&peer("::1"), "::1"));
        assert!(!is_direct_local_client(
            &parse_ip_address(b"::1").unwrap(),
            "::1"
        ));
    }

    #[test]
    fn iprep_helpers() {
        assert_eq!(strip_port("1.2.3.4:80"), "1.2.3.4");
        assert_eq!(strip_port("2001:db8::1"), "2001:db8::1");
        assert_eq!(parse_dotted_quad("10.0.0.1"), Some(0x0A000001));
        assert_eq!(parse_dotted_quad("010.0.0.1"), Some(0x0A000001));
        assert_eq!(parse_dotted_quad("256.0.0.1"), None);
        assert_eq!(parse_dotted_quad("1.2.3"), None);
        assert_eq!(parse_dotted_quad("1.2.3.4:80"), None);
        assert!(is_non_routable_ipv4(
            parse_dotted_quad("100.64.0.1").unwrap()
        ));
        assert!(!is_non_routable_ipv4(
            parse_dotted_quad("100.128.0.1").unwrap()
        ));
    }
}
