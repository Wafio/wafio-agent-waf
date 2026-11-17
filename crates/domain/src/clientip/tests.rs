//! Tests of client IP trust and the client IP policy.

use super::*;
use crate::proxyconfig::{ProxyConfig, parse_proxy_config};

fn must_proxy_config(raw: &str) -> ProxyConfig {
    let pc = parse_proxy_config(raw.as_bytes()).unwrap_or_else(|e| panic!("parse {raw}: {e}"));
    pc.validate()
        .unwrap_or_else(|e| panic!("validate {raw}: {e}"));
    pc
}

fn ip(s: &str) -> IpAddress {
    parse_ip_address(s.as_bytes()).unwrap()
}

const LISTED: &str =
    r#"{"trust_forwarded":true,"trusted_proxies":["10.0.0.0/8","2001:db8:ffff::/48"]}"#;
const PRIVATE: &str = r#"{"trust_forwarded":true}"#;
const OFF: &str = r#"{"trust_forwarded":false,"trusted_proxies":["10.0.0.0/8"]}"#;

/// (name, config, peer, X-Forwarded-For lines, X-Real-IP, want)
type ClientIpCase<'a> = (&'a str, &'a str, &'a str, &'a [&'a str], &'a str, &'a str);

#[test]
fn proxy_config_client_ip() {
    let cases: &[ClientIpCase] = &[
        (
            "spoofed XFF from untrusted peer",
            LISTED,
            "203.0.113.7",
            &["1.2.3.4"],
            "",
            "203.0.113.7",
        ),
        (
            "spoofed XFF chain from untrusted peer",
            LISTED,
            "203.0.113.7",
            &["1.2.3.4, 10.0.0.1"],
            "",
            "203.0.113.7",
        ),
        (
            "X-Real-IP from untrusted peer",
            LISTED,
            "203.0.113.7",
            &[],
            "1.2.3.4",
            "203.0.113.7",
        ),
        (
            "absent trust_forwarded is off",
            "{}",
            "10.0.0.1",
            &["1.2.3.4"],
            "5.6.7.8",
            "10.0.0.1",
        ),
        (
            "trust_forwarded false ignores a listed peer",
            OFF,
            "10.0.0.1",
            &["1.2.3.4"],
            "5.6.7.8",
            "10.0.0.1",
        ),
        (
            "empty list: public peer ignored",
            PRIVATE,
            "198.51.100.9",
            &["1.2.3.4"],
            "5.6.7.8",
            "198.51.100.9",
        ),
        (
            "empty list: link-local peer ignored",
            PRIVATE,
            "169.254.1.1",
            &["1.2.3.4"],
            "",
            "169.254.1.1",
        ),
        (
            "empty list: CGNAT peer ignored",
            PRIVATE,
            "100.64.0.1",
            &["1.2.3.4"],
            "",
            "100.64.0.1",
        ),
        (
            "one trusted proxy",
            LISTED,
            "10.0.0.1",
            &["1.2.3.4"],
            "",
            "1.2.3.4",
        ),
        (
            "client-supplied hops left of the real client are ignored",
            LISTED,
            "10.0.0.1",
            &["6.6.6.6, 7.7.7.7, 1.2.3.4"],
            "",
            "1.2.3.4",
        ),
        (
            "chain through two trusted proxies",
            LISTED,
            "10.0.0.2",
            &["6.6.6.6, 1.2.3.4, 10.0.0.1"],
            "",
            "1.2.3.4",
        ),
        (
            "two header lines are one list",
            LISTED,
            "10.0.0.2",
            &["6.6.6.6", "1.2.3.4, 10.0.0.1"],
            "",
            "1.2.3.4",
        ),
        (
            "spoofed private hop left of the client",
            LISTED,
            "10.0.0.1",
            &["10.9.9.9, 1.2.3.4"],
            "",
            "1.2.3.4",
        ),
        (
            "every hop trusted: the peer",
            LISTED,
            "10.0.0.2",
            &["10.0.0.5, 10.0.0.1"],
            "",
            "10.0.0.2",
        ),
        (
            "private client behind a listed proxy",
            LISTED,
            "10.0.0.1",
            &["192.168.1.5"],
            "",
            "192.168.1.5",
        ),
        (
            "loopback hop is never the client",
            LISTED,
            "10.0.0.1",
            &["127.0.0.1"],
            "",
            "10.0.0.1",
        ),
        (
            "IPv6 loopback hop is never the client",
            LISTED,
            "10.0.0.1",
            &["1.2.3.4, ::1"],
            "",
            "10.0.0.1",
        ),
        (
            "trusted X-Real-IP is the peer",
            LISTED,
            "10.0.0.1",
            &[],
            "10.0.0.7",
            "10.0.0.1",
        ),
        (
            "loopback X-Real-IP is never the client",
            LISTED,
            "10.0.0.1",
            &[],
            "127.0.0.1",
            "10.0.0.1",
        ),
        (
            "XFF wins over X-Real-IP",
            LISTED,
            "10.0.0.1",
            &["1.2.3.4"],
            "6.6.6.6",
            "1.2.3.4",
        ),
        (
            "X-Real-IP when XFF absent",
            LISTED,
            "10.0.0.1",
            &[],
            "1.2.3.4",
            "1.2.3.4",
        ),
        (
            "X-Real-IP when XFF blank",
            LISTED,
            "10.0.0.1",
            &["  "],
            "1.2.3.4",
            "1.2.3.4",
        ),
        (
            "no forwarded headers",
            LISTED,
            "10.0.0.1",
            &[],
            "",
            "10.0.0.1",
        ),
        (
            "hop with port",
            LISTED,
            "10.0.0.1",
            &["1.2.3.4:5678"],
            "",
            "1.2.3.4",
        ),
        (
            "hop spelled as v4-mapped v6",
            LISTED,
            "10.0.0.1",
            &["::ffff:1.2.3.4"],
            "",
            "1.2.3.4",
        ),
        (
            "empty list: loopback peer",
            PRIVATE,
            "127.0.0.1",
            &["1.2.3.4"],
            "",
            "1.2.3.4",
        ),
        (
            "empty list: RFC 1918 172.16/12 peer",
            PRIVATE,
            "172.20.1.1",
            &["1.2.3.4"],
            "",
            "1.2.3.4",
        ),
        (
            "empty list: RFC 1918 192.168/16 peer",
            PRIVATE,
            "192.168.1.1",
            &[],
            "1.2.3.4",
            "1.2.3.4",
        ),
        (
            "empty list: IPv6 loopback peer",
            PRIVATE,
            "::1",
            &["2001:db8::1"],
            "",
            "2001:db8::1",
        ),
        (
            "empty list: RFC 4193 peer",
            PRIVATE,
            "fd00::1",
            &["1.2.3.4"],
            "",
            "1.2.3.4",
        ),
        (
            "empty list: v4-mapped private peer",
            PRIVATE,
            "::ffff:10.0.0.1",
            &["1.2.3.4"],
            "",
            "1.2.3.4",
        ),
        (
            "empty list: private hops are skipped",
            PRIVATE,
            "127.0.0.1",
            &["1.2.3.4, 192.168.0.10"],
            "",
            "1.2.3.4",
        ),
        (
            "NAT peer: spoofed loopback XFF",
            PRIVATE,
            "172.17.0.1",
            &["127.0.0.1"],
            "",
            "172.17.0.1",
        ),
        (
            "NAT peer: spoofed private XFF chain",
            PRIVATE,
            "172.17.0.1",
            &["10.9.9.9, 192.168.0.1"],
            "",
            "172.17.0.1",
        ),
        (
            "NAT peer: spoofed loopback X-Real-IP",
            PRIVATE,
            "172.17.0.1",
            &[],
            "127.0.0.1",
            "172.17.0.1",
        ),
        (
            "NAT peer: spoofed RFC 4193 X-Real-IP",
            PRIVATE,
            "fd00::5",
            &[],
            "fd00::9",
            "fd00::5",
        ),
        (
            "NAT peer: public XFF is taken (residual, flagged)",
            PRIVATE,
            "172.17.0.1",
            &["8.8.8.8"],
            "",
            "8.8.8.8",
        ),
        (
            "IPv6 trusted peer and client",
            LISTED,
            "2001:db8:ffff::1",
            &["2001:db8:1::5"],
            "",
            "2001:db8:1::5",
        ),
        (
            "IPv6 client normalized",
            LISTED,
            "10.0.0.1",
            &["2001:DB8:0:0::5"],
            "",
            "2001:db8::5",
        ),
        (
            "bracketed IPv6 hop with port",
            LISTED,
            "10.0.0.1",
            &["[2001:db8::5]:443"],
            "",
            "2001:db8::5",
        ),
        (
            "IPv6 untrusted peer",
            LISTED,
            "2001:db8:1::1",
            &["1.2.3.4"],
            "",
            "2001:db8:1::1",
        ),
        (
            "garbage XFF",
            LISTED,
            "10.0.0.1",
            &["not-an-ip"],
            "",
            "10.0.0.1",
        ),
        (
            "garbage rightmost hop",
            LISTED,
            "10.0.0.1",
            &["1.2.3.4, evil"],
            "",
            "10.0.0.1",
        ),
        (
            "garbage behind a trusted hop",
            LISTED,
            "10.0.0.2",
            &["evil, 10.0.0.1"],
            "",
            "10.0.0.2",
        ),
        (
            "empty element",
            LISTED,
            "10.0.0.1",
            &["1.2.3.4,,"],
            "",
            "10.0.0.1",
        ),
        (
            "XFF unknown token",
            LISTED,
            "10.0.0.1",
            &["unknown"],
            "",
            "10.0.0.1",
        ),
        (
            "XFF with zone",
            LISTED,
            "10.0.0.1",
            &["fe80::1%eth0"],
            "",
            "10.0.0.1",
        ),
        (
            "XFF script payload",
            LISTED,
            "10.0.0.1",
            &["<script>alert(1)</script>"],
            "",
            "10.0.0.1",
        ),
        (
            "garbage X-Real-IP",
            LISTED,
            "10.0.0.1",
            &[],
            "1.2.3.4, 5.6.7.8",
            "10.0.0.1",
        ),
        (
            "X-Real-IP SQL payload",
            LISTED,
            "10.0.0.1",
            &[],
            "1' OR '1'='1",
            "10.0.0.1",
        ),
    ];
    for (name, cfg, peer, xff, xri, want) in cases {
        let pc = must_proxy_config(cfg);
        let got = pc.client_ip(&ip(peer), xff, xri.as_bytes());
        assert_eq!(got.to_string(), *want, "{name}");
    }
}

#[test]
fn proxy_config_client_ip_hop_limit() {
    let pc = must_proxy_config(r#"{"trust_forwarded":true,"trusted_proxies":["10.0.0.0/8"]}"#);
    let mut hops = vec!["1.2.3.4".to_string()];
    for i in 0..MAX_FORWARDED_HOPS {
        hops.push(format!("10.0.{}.{}", i / 250, i % 250 + 1));
    }
    let got = pc.client_ip(&ip("10.0.0.1"), &[hops.join(", ")], b"");
    assert_eq!(got.to_string(), "10.0.0.1", "over-long trusted chain");
    let got = pc.client_ip(
        &ip("10.0.0.1"),
        &[hops[..MAX_FORWARDED_HOPS].join(", ")],
        b"",
    );
    assert_eq!(got.to_string(), "1.2.3.4", "chain at the bound");
}

#[test]
fn proxy_config_trusted_prefixes_fail_closed() {
    let peer = ip("10.0.0.1");
    let hand = ProxyConfig {
        trust_forwarded: true,
        trusted_proxies: vec!["10.0.0.0/8".into()],
        ..Default::default()
    };
    assert_eq!(
        hand.client_ip(&peer, &["1.2.3.4"], b"").to_string(),
        "1.2.3.4"
    );
    for list in [
        r#"["nonsense"]"#,
        r#"["0.0.0.0/1","128.0.0.0/1"]"#,
        r#"["::/0"]"#,
    ] {
        let raw = format!(r#"{{"trust_forwarded":true,"trusted_proxies":{list}}}"#);
        let bad = parse_proxy_config(raw.as_bytes()).unwrap();
        assert_eq!(bad.client_ip(&peer, &["1.2.3.4"], b""), peer, "list {list}");
        assert!(
            !bad.may_supply_forwarded_headers(&ip("8.8.8.8")),
            "list {list} trusts 8.8.8.8"
        );
    }
}

#[test]
fn parse_proxy_config_trusted_proxies() {
    let pc = must_proxy_config(
        r#"{"trust_forwarded":true,"trusted_proxies":[" 10.0.0.5 ","192.168.0.0/16","2001:db8::/32","::ffff:172.16.0.0/108"]}"#,
    );
    for a in ["10.0.0.5", "192.168.44.1", "2001:db8:1::1", "172.16.9.9"] {
        assert!(
            pc.may_supply_forwarded_headers(&ip(a)),
            "{a} should be trusted"
        );
    }
    for a in ["10.0.0.6", "127.0.0.1", "2001:db9::1", "172.32.0.1"] {
        assert!(
            !pc.may_supply_forwarded_headers(&ip(a)),
            "{a} should not be trusted"
        );
    }
}

#[test]
fn proxy_config_validate_trusted_proxies() {
    let many: Vec<String> = (0..=MAX_TRUSTED_PROXIES)
        .map(|i| format!(r#""10.0.{i}.0/24""#))
        .collect();
    let exactly = format!(
        r#"{{"trusted_proxies":[{}]}}"#,
        many[..MAX_TRUSTED_PROXIES].join(",")
    );
    let too_many = format!(r#"{{"trusted_proxies":[{}]}}"#, many.join(","));
    let cases: Vec<(&str, &str, &str)> = vec![
        (
            "cidr and bare ips",
            r#"{"trusted_proxies":["10.0.0.0/8","192.0.2.1","2001:db8::/32","::1"]}"#,
            "",
        ),
        ("exactly max", &exactly, ""),
        (
            "too many",
            &too_many,
            "trusted_proxies: too many entries (max 64)",
        ),
        (
            "bad cidr",
            r#"{"trusted_proxies":["10.0.0.0/33"]}"#,
            "trusted_proxies[0]",
        ),
        (
            "hostname",
            r#"{"trusted_proxies":["10.0.0.1","lb.internal"]}"#,
            "trusted_proxies[1]",
        ),
        (
            "empty entry",
            r#"{"trusted_proxies":[""]}"#,
            "trusted_proxies[0]",
        ),
        (
            "zone",
            r#"{"trusted_proxies":["fe80::1%eth0"]}"#,
            "trusted_proxies[0]",
        ),
        (
            "v4 any",
            r#"{"trusted_proxies":["0.0.0.0/0"]}"#,
            "is too broad",
        ),
        ("v6 any", r#"{"trusted_proxies":["::/0"]}"#, "is too broad"),
        (
            "v4 halves",
            r#"{"trusted_proxies":["0.0.0.0/1","128.0.0.0/1"]}"#,
            "trusted_proxies[0]: \"0.0.0.0/1\" is too broad",
        ),
        (
            "v4 /7",
            r#"{"trusted_proxies":["10.0.0.0/8","10.0.0.0/7"]}"#,
            "trusted_proxies[1]",
        ),
        ("v4 /8 allowed", r#"{"trusted_proxies":["10.0.0.0/8"]}"#, ""),
        (
            "v6 /15",
            r#"{"trusted_proxies":["2000::/15"]}"#,
            "is too broad",
        ),
        (
            "v6 /3",
            r#"{"trusted_proxies":["2000::/3"]}"#,
            "is too broad",
        ),
        ("v6 /16 allowed", r#"{"trusted_proxies":["2001::/16"]}"#, ""),
        (
            "v4-mapped /104 is v4 /8",
            r#"{"trusted_proxies":["::ffff:10.0.0.0/104"]}"#,
            "",
        ),
        (
            "v4-mapped /100 is v4 /4",
            r#"{"trusted_proxies":["::ffff:0.0.0.0/100"]}"#,
            "is too broad",
        ),
        ("not a list", r#"{"trusted_proxies":"10.0.0.0/8"}"#, "parse"),
    ];
    for (name, json, want_err) in cases {
        let res = match parse_proxy_config(json.as_bytes()) {
            Ok(pc) => pc.validate().map_err(|e| e.0),
            Err(e) => Err(format!("parse: {}", e.0)),
        };
        match (want_err.is_empty(), res) {
            (true, Ok(())) => {}
            (true, Err(e)) => panic!("{name}: unexpected error {e}"),
            (false, Ok(())) => panic!("{name}: want error {want_err}"),
            (false, Err(e)) => {
                assert!(
                    e.contains(want_err),
                    "{name}: error {e:?}, want {want_err:?}"
                );
                assert!(e.len() <= 300, "{name}: error message too long");
            }
        }
    }
}

#[test]
fn proxy_config_warnings_table() {
    let cases: &[(&str, &[&str])] = &[
        ("{}", &[]),
        (r#"{"trust_forwarded":false}"#, &[]),
        (
            r#"{"trust_forwarded":true}"#,
            &[PROXY_WARN_TRUSTED_PROXIES_UNSET],
        ),
        (
            r#"{"trust_forwarded":true,"trusted_proxies":[]}"#,
            &[PROXY_WARN_TRUSTED_PROXIES_UNSET],
        ),
        (
            r#"{"trust_forwarded":true,"trusted_proxies":["10.0.0.1"]}"#,
            &[],
        ),
        (
            r#"{"trust_forwarded":false,"trusted_proxies":["10.0.0.1"]}"#,
            &[PROXY_WARN_TRUSTED_PROXIES_IGNORED],
        ),
        (
            r#"{"trusted_proxies":["10.0.0.1"]}"#,
            &[PROXY_WARN_TRUSTED_PROXIES_IGNORED],
        ),
    ];
    for (json, want) in cases {
        let got = proxy_config_warnings(json.as_bytes());
        assert!(got.iter().all(|w| !w.message.is_empty()));
        let codes: Vec<&str> = got.iter().map(|w| w.code.as_str()).collect();
        assert_eq!(codes, *want, "{json}");
    }
    let unset = proxy_config_warnings(br#"{"trust_forwarded":true}"#)[0]
        .message
        .clone();
    for want in ["trusted proxies", "Docker", "Kubernetes", "NAT"] {
        assert!(unset.contains(want), "{want}");
    }
    assert!(unset.len() <= 256);
    assert!(proxy_config_warnings(b"not json").is_empty());
}

#[test]
fn client_ip_policy_validation() {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let cases: Vec<(&str, Vec<String>, &str, &str)> = vec![
        ("empty", vec![], "", ""),
        ("blank entries dropped", s(&[" ", ""]), "", ""),
        (
            "ips and cidrs",
            s(&["127.0.0.1", " 10.0.0.0/8 ", "::1", "fd00::/16"]),
            "x-real-ip",
            "",
        ),
        ("ipv4 wildcard", s(&["0.0.0.0/0"]), "", "too broad"),
        ("ipv6 wildcard", s(&["::/0"]), "", "too broad"),
        (
            "split wildcard",
            s(&["0.0.0.0/1", "128.0.0.0/1"]),
            "",
            "too broad",
        ),
        ("garbage", s(&["nginx"]), "", "not an IP address or CIDR"),
        ("unknown header", vec![], "Forwarded", "server.proxy_header"),
    ];
    for (name, list, header, want_err) in cases {
        match (ClientIpPolicy::new(&list, header), want_err) {
            (Ok(_), "") => {}
            (Err(e), "") => panic!("{name}: {e}"),
            (Ok(_), w) => panic!("{name}: want {w}"),
            (Err(e), w) => assert!(e.0.contains(w), "{name}: {e}"),
        }
    }
    let many = vec!["10.0.0.1".to_string(); MAX_TRUSTED_PROXIES + 1];
    assert!(ClientIpPolicy::new(&many, "").is_err());
}

#[test]
fn client_ip_policy_resolves() {
    let proxy = ip("127.0.0.1");
    let xff = ClientIpPolicy::new(&["127.0.0.1".into(), "10.1.0.0/16".into()], "").unwrap();
    let real = ClientIpPolicy::new(&["127.0.0.1".into()], "X-Real-IP").unwrap();
    let none = ClientIpPolicy::new(&[], "").unwrap();
    type PolicyCase<'a> = (
        &'a str,
        &'a ClientIpPolicy,
        IpAddress,
        &'a [&'a str],
        &'a str,
        &'a str,
    );
    let cases: &[PolicyCase] = &[
        (
            "no proxy configured",
            &none,
            proxy.clone(),
            &["198.51.100.7"],
            "198.51.100.8",
            "127.0.0.1",
        ),
        (
            "untrusted peer",
            &xff,
            ip("203.0.113.5"),
            &["198.51.100.7"],
            "",
            "203.0.113.5",
        ),
        (
            "nginx appended the client",
            &xff,
            proxy.clone(),
            &["198.51.100.7"],
            "",
            "198.51.100.7",
        ),
        (
            "client-sent entries left of nginx's",
            &xff,
            proxy.clone(),
            &["1.2.3.4, 198.51.100.7"],
            "",
            "198.51.100.7",
        ),
        (
            "trusted inner hops skipped",
            &xff,
            proxy.clone(),
            &["198.51.100.7, 10.1.2.3"],
            "",
            "198.51.100.7",
        ),
        (
            "every hop trusted",
            &xff,
            proxy.clone(),
            &["10.1.2.3"],
            "",
            "127.0.0.1",
        ),
        (
            "loopback hop",
            &xff,
            proxy.clone(),
            &["127.0.0.2"],
            "",
            "127.0.0.1",
        ),
        (
            "malformed hop",
            &xff,
            proxy.clone(),
            &["not-an-ip"],
            "",
            "127.0.0.1",
        ),
        ("no header", &xff, proxy.clone(), &[], "", "127.0.0.1"),
        (
            "X-Real-IP ignored",
            &xff,
            proxy.clone(),
            &[],
            "198.51.100.8",
            "127.0.0.1",
        ),
        (
            "X-Real-IP chosen",
            &real,
            proxy.clone(),
            &["1.2.3.4"],
            "198.51.100.8",
            "198.51.100.8",
        ),
        (
            "X-Real-IP list refused",
            &real,
            proxy.clone(),
            &[],
            "1.2.3.4, 198.51.100.8",
            "127.0.0.1",
        ),
        (
            "X-Real-IP with port",
            &real,
            proxy.clone(),
            &[],
            "198.51.100.8:4431",
            "198.51.100.8",
        ),
        (
            "IPv6 client",
            &xff,
            ip("::ffff:127.0.0.1"),
            &["2001:db8::7"],
            "",
            "2001:db8::7",
        ),
    ];
    for (name, p, peer, xffs, xri, want) in cases {
        assert_eq!(
            p.client_ip(peer, xffs, xri.as_bytes()).to_string(),
            *want,
            "{name}"
        );
    }
    assert!(!none.enabled() && xff.enabled());
    assert_eq!(real.header(), PROXY_HEADER_REAL_IP);
    assert_eq!(xff.header(), PROXY_HEADER_FORWARDED_FOR);
}
