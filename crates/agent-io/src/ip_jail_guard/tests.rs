use std::sync::MutexGuard;

use super::*;
use wafio_domain::parse_proxy_config;

/// The guard state is process-wide: tests touching it run one at a time.
pub(crate) static GUARD_TEST_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn clear_jail_guard() -> MutexGuard<'static, ()> {
    let g = GUARD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_jail_guard_for_test(Some(vec![parse_ip_address(b"203.0.113.200").unwrap()]));
    g
}

#[test]
fn jail_refusal_classes() {
    let _g = clear_jail_guard();
    install_control_plane_endpoints(&["198.51.100.50:9090".parse().unwrap()]);
    install_trusted_proxy_configs(vec![
        parse_proxy_config(br#"{"trust_forwarded":true,"trusted_proxies":["192.0.2.0/24"]}"#)
            .unwrap(),
    ]);
    for (name, ip, want) in [
        ("loopback v4", "127.0.0.1", JAIL_EXEMPT_LOOPBACK),
        ("loopback v4 other", "127.8.9.10", JAIL_EXEMPT_LOOPBACK),
        ("loopback v6", "::1", JAIL_EXEMPT_LOOPBACK),
        (
            "loopback v4-mapped",
            "::ffff:127.0.0.1",
            JAIL_EXEMPT_LOOPBACK,
        ),
        ("unspecified v4", "0.0.0.0", JAIL_EXEMPT_UNSPECIFIED),
        ("unspecified v6", "::", JAIL_EXEMPT_UNSPECIFIED),
        ("link-local v4", "169.254.1.1", JAIL_EXEMPT_LINK_LOCAL),
        ("link-local v6", "fe80::1", JAIL_EXEMPT_LINK_LOCAL),
        ("multicast v4", "224.0.0.1", JAIL_EXEMPT_MULTICAST),
        ("multicast v6", "ff02::1", JAIL_EXEMPT_MULTICAST),
        ("broadcast", "255.255.255.255", JAIL_EXEMPT_BROADCAST),
        ("own address", "203.0.113.200", JAIL_EXEMPT_LOCAL_INTERFACE),
        ("control plane", "198.51.100.50", JAIL_EXEMPT_CONTROL_PLANE),
        (
            "control plane v4-mapped",
            "::ffff:198.51.100.50",
            JAIL_EXEMPT_CONTROL_PLANE,
        ),
        ("trusted proxy", "192.0.2.77", JAIL_EXEMPT_TRUSTED_PROXY),
        ("not an ip", "not-an-ip", JAIL_EXEMPT_INVALID),
        ("truncated ip", "1.2.3", JAIL_EXEMPT_INVALID),
        ("public ip jailed", "203.0.113.7", ""),
        ("public v6 jailed", "2001:db8::7", ""),
        ("private without default trust jailed", "10.1.2.3", ""),
        ("zone stripped", "fe80::1%eth0", JAIL_EXEMPT_LINK_LOCAL),
    ] {
        assert_eq!(jail_exemption_reason(Instant::now(), ip), want, "{name}");
    }
}

#[test]
fn jail_refusal_private_follows_proxy_trust() {
    let _g = clear_jail_guard();
    let private = ["10.1.2.3", "172.16.5.5", "192.168.1.9", "fd00::5"];
    for ip in private {
        assert_eq!(jail_exemption_reason(Instant::now(), ip), "", "{ip}");
    }
    install_trusted_proxy_configs(vec![
        parse_proxy_config(br#"{"trust_forwarded":false}"#).unwrap(),
    ]);
    for ip in private {
        assert_eq!(jail_exemption_reason(Instant::now(), ip), "", "{ip}");
    }
    install_trusted_proxy_configs(vec![
        parse_proxy_config(br#"{"trust_forwarded":true}"#).unwrap(),
    ]);
    for ip in private {
        assert_eq!(
            jail_exemption_reason(Instant::now(), ip),
            JAIL_EXEMPT_TRUSTED_PROXY,
            "{ip}"
        );
    }
    assert_eq!(jail_exemption_reason(Instant::now(), "203.0.113.7"), "");
}

#[test]
fn jail_refusal_pinned_control_plane() {
    let _g = clear_jail_guard();
    set_pinned_cp_endpoints(Some(&["198.51.100.77:9090".parse().unwrap()][..]));
    assert_eq!(
        jail_exemption_reason(Instant::now(), "198.51.100.77"),
        JAIL_EXEMPT_CONTROL_PLANE
    );
}

#[test]
fn jail_control_plane_resolved() {
    let _g = clear_jail_guard();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(refresh_jail_control_plane("dns:///198.51.100.60:9090"));
    assert_eq!(
        jail_exemption_reason(Instant::now(), "198.51.100.60"),
        JAIL_EXEMPT_CONTROL_PLANE
    );
    // a failure keeps the previous set
    rt.block_on(refresh_jail_control_plane("no-port"));
    assert_eq!(
        jail_exemption_reason(Instant::now(), "198.51.100.60"),
        JAIL_EXEMPT_CONTROL_PLANE
    );
}

#[test]
fn own_address_does_not_block_on_refresh() {
    let _g = clear_jail_guard();
    let now = Instant::now();
    let a = parse_ip_address(b"203.0.113.200").unwrap();
    assert!(is_local_interface_address(now, &a));
    let held = OWN.refresh.lock().unwrap(); // a refresh is "in progress"
    let (tx, rx) = std::sync::mpsc::channel();
    let a2 = a.clone();
    std::thread::spawn(move || {
        tx.send(is_local_interface_address(
            now + Duration::from_secs(3600),
            &a2,
        ))
        .unwrap()
    });
    let got = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("reader blocked behind a refresh");
    assert!(got, "stale snapshot lost the address");
    drop(held);
}

#[test]
fn refused_samples_sorted() {
    note_jail_exemption("zz_test_reason");
    note_jail_exemption("aa_test_reason");
    let names: Vec<String> = jail_exemption_samples()
        .into_iter()
        .map(|s| s.labels[0].value.clone())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
    assert!(jail_exemption_count("aa_test_reason") >= 1);
}

#[test]
fn parse_server_endpoint_cases() {
    assert_eq!(
        parse_server_endpoint(" cp.example:9090 ").unwrap(),
        ("cp.example".into(), 9090)
    );
    assert_eq!(
        parse_server_endpoint("dns:///[::1]:443").unwrap(),
        ("::1".into(), 443)
    );
    for bad in ["cp.example", "cp.example:0", ":9090", "cp:70000"] {
        assert!(parse_server_endpoint(bad).is_err(), "{bad}");
    }
}

#[test]
fn procfs_interface_addrs_include_loopback() {
    if std::path::Path::new("/proc/net/fib_trie").exists() {
        let addrs = list_interface_addresses().unwrap();
        assert!(
            addrs.contains(&IpAddress::from_ipv4([127, 0, 0, 1])),
            "{addrs:?}"
        );
    }
}
