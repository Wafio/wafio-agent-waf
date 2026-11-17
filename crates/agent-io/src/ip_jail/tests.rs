//! Tests for the jail tracker, the HTTP enforcer, forwarded client addresses and the jail part
//! of the guard.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;

use super::*;
use crate::ip_jail_guard::tests::clear_jail_guard;
use crate::ip_jail_guard::{JAIL_EXEMPT_LOOPBACK, jail_exemption_count};

struct FakeClock {
    base: Instant,
    offset_s: Arc<AtomicU64>,
}

impl FakeClock {
    fn advance(&self, d: Duration) {
        self.offset_s.fetch_add(d.as_secs(), Ordering::SeqCst);
    }
}

fn test_jail_tracker(
    threshold: i64,
    window: Duration,
    duration: Duration,
    enforce: Option<Enforce>,
) -> (JailTracker, FakeClock) {
    let clk = FakeClock {
        base: Instant::now(),
        offset_s: Arc::new(AtomicU64::new(0)),
    };
    let mut j = JailTracker::new(threshold, window, duration, 1024, enforce);
    let (base, off) = (clk.base, clk.offset_s.clone());
    j.set_clock(move || base + Duration::from_secs(off.load(Ordering::SeqCst)));
    (j, clk)
}

fn channel_enforce() -> (Enforce, mpsc::Receiver<(String, Duration)>) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let enf: Enforce = Arc::new(move |ip: &str, ttl: Duration| {
        tx.lock().unwrap().send((ip.to_string(), ttl)).unwrap()
    });
    (enf, rx)
}

const MIN: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);

#[test]
fn triggers_at_threshold_once() {
    let _g = clear_jail_guard();
    let (enf, rx) = channel_enforce();
    let (j, _) = test_jail_tracker(3, MIN, HOUR, Some(enf));
    j.record_block("203.0.113.7");
    j.record_block("203.0.113.7");
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "jailed before threshold"
    );
    j.record_block("203.0.113.7");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(1)).unwrap().0,
        "203.0.113.7"
    );
    j.record_block("203.0.113.7");
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "re-triggered without fresh window"
    );
}

#[test]
fn window_expiry() {
    let _g = clear_jail_guard();
    let (j, clk) = test_jail_tracker(2, MIN, HOUR, None);
    j.record_block("198.51.100.1");
    clk.advance(2 * MIN);
    j.record_block("198.51.100.1");
    assert_eq!(j.count("198.51.100.1"), 1);
}

#[test]
fn sliding_window_trims_old_blocks() {
    let _g = clear_jail_guard();
    let (enf, rx) = channel_enforce();
    let (j, clk) = test_jail_tracker(5, MIN, HOUR, Some(enf));
    for i in 0..20 {
        j.record_block("203.0.113.9");
        assert!(j.count("203.0.113.9") <= 2, "block {i}");
        clk.advance(Duration::from_secs(50));
    }
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
    for _ in 0..5 {
        j.record_block("203.0.113.9");
        clk.advance(Duration::from_secs(1));
    }
    assert!(
        rx.recv_timeout(Duration::from_secs(1)).is_ok(),
        "burst inside the window not jailed"
    );
}

#[test]
fn independent_ips_and_disabled() {
    let _g = clear_jail_guard();
    let (j, _) = test_jail_tracker(3, MIN, HOUR, None);
    j.record_block("198.51.100.1");
    j.record_block("198.51.100.2");
    j.record_block("198.51.100.2");
    assert_eq!((j.count("198.51.100.1"), j.count("198.51.100.2")), (1, 2));
    let off = JailTracker::new(0, MIN, HOUR, 1024, None);
    for _ in 0..10 {
        off.record_block("203.0.113.9");
    }
    assert_eq!(off.count("203.0.113.9"), 0);
}

#[test]
fn enforce_duration() {
    let _g = clear_jail_guard();
    let (enf, rx) = channel_enforce();
    let (j, _) = test_jail_tracker(1, MIN, 45 * MIN, Some(enf));
    j.record_block("203.0.113.11");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        ("203.0.113.11".to_string(), 45 * MIN)
    );
}

#[test]
fn bounded_tracking() {
    let _g = clear_jail_guard();
    let mut j = JailTracker::new(1000, MIN, HOUR, 128, None);
    j.set_clock(Instant::now);
    for i in 0..4096 {
        j.record_block(&format!("198.51.{}.{}", (i / 250) % 100, i % 250 + 1));
    }
    assert!(j.tracked() <= 128, "{}", j.tracked());
}

#[test]
fn refused_never_enforces_and_counts() {
    let _g = clear_jail_guard();
    let (enf, rx) = channel_enforce();
    let (j, _) = test_jail_tracker(1, MIN, HOUR, Some(enf));
    let before = jail_exemption_count(JAIL_EXEMPT_LOOPBACK);
    for _ in 0..3 {
        j.record_block("127.0.0.1");
    }
    assert_eq!(jail_exemption_count(JAIL_EXEMPT_LOOPBACK) - before, 3);
    assert_eq!(j.count("127.0.0.1"), 0);
    j.record_block("203.0.113.7");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(1)).unwrap().0,
        "203.0.113.7"
    );
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
}

#[test]
fn enforce_panic_is_recovered() {
    let _g = clear_jail_guard();
    let enf: Enforce = Arc::new(|_: &str, _: Duration| panic!("boom"));
    let (j, _) = test_jail_tracker(1, MIN, HOUR, Some(enf));
    j.record_block("203.0.113.8");
    std::thread::sleep(Duration::from_millis(50));
}

#[test]
fn jail_hook_skips_forwarded_and_coverage_raised() {
    let _g = clear_jail_guard();
    let (enf, rx) = channel_enforce();
    let j = JailTracker::new(1, MIN, HOUR, 1024, Some(enf));
    let before = jail_exemption_count(JAIL_EXEMPT_FORWARDED);
    report_block_to_jail(Some(&j), "block", false, true, "203.0.113.50");
    assert_eq!(jail_exemption_count(JAIL_EXEMPT_FORWARDED), before + 1);
    assert_eq!(j.count("203.0.113.50"), 0);
    report_block_to_jail(Some(&j), "block", true, false, "203.0.113.52:40000");
    report_block_to_jail(Some(&j), "log", false, false, "203.0.113.52:40000");
    assert_eq!(j.count("203.0.113.52"), 0);
    report_block_to_jail(Some(&j), "block", false, false, "203.0.113.51:40000");
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2)).unwrap().0,
        "203.0.113.51"
    );
    assert!(rx.try_recv().is_err());
    report_block_to_jail(None, "block", false, false, "203.0.113.51");
}

fn scratch_file(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wafio-agent-io-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("host-agent.token")
}

#[test]
fn http_jail_enforcer_wire_format() {
    let _g = clear_jail_guard();
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for conn in ln.incoming() {
            let mut c = conn.unwrap();
            c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = c.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                let s = String::from_utf8_lossy(&req);
                if let Some(h) = s.find("\r\n\r\n") {
                    let cl: usize = s
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    if req.len() >= h + 4 + cl {
                        break;
                    }
                }
            }
            c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            tx.send(String::from_utf8(req).unwrap()).unwrap();
        }
    });
    let token_file = scratch_file("wire");
    let _ = std::fs::remove_file(&token_file);
    let enforce = host_agent_jail_enforcer(
        &format!("http://{addr}/api/ebpf/blocklist"),
        token_file.to_str().unwrap(),
    );
    enforce("203.0.113.99", 30 * MIN);
    assert!(
        rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "request sent without a token file"
    );

    std::fs::write(&token_file, "tok_first\n").unwrap();
    enforce("203.0.113.99", 30 * MIN);
    let req = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(
        req.starts_with("POST /api/ebpf/blocklist HTTP/1.1\r\n"),
        "{req}"
    );
    assert!(req.contains("Authorization: Bearer tok_first\r\n"), "{req}");
    assert!(
        req.ends_with(r#"{"entries":[{"ip":"203.0.113.99","ttl_ms":1800000}],"origin":"jail"}"#),
        "{req}"
    );

    std::fs::write(&token_file, "tok_second").unwrap();
    enforce("203.0.113.99", 30 * MIN);
    assert!(
        rx.recv_timeout(Duration::from_secs(2))
            .unwrap()
            .contains("Authorization: Bearer tok_second\r\n")
    );
}

/// `HTTP_PROXY` / `NO_PROXY` handling: a request to a host that is
/// not exempt goes to the proxy in absolute form with its `Proxy-Authorization`; loopback hosts and
/// `NO_PROXY` entries are dialled directly; `https://` and `socks5://` proxies are refused.
#[test]
fn jail_post_follows_the_proxy_environment() {
    use wafio_control::proxy_env::ProxyConfig;
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let paddr = ln.local_addr().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for conn in ln.incoming() {
            let mut c = conn.unwrap();
            c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !String::from_utf8_lossy(&req).contains("\"origin\":\"jail\"}") {
                let n = c.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
            }
            c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            tx.send(String::from_utf8(req).unwrap()).unwrap();
        }
    });
    let body = br#"{"entries":[],"origin":"jail"}"#;
    let via = |proxy: &str, no: &str, url: &str| {
        let cfg = ProxyConfig::from_parts(proxy, "", no, false);
        http_post_via(&cfg, url, "tok", body, Duration::from_millis(400))
    };
    // A named host is proxied: absolute-form target, the proxy's credentials.
    let proxy = format!("http://u:p@{paddr}");
    assert_eq!(
        via(&proxy, "", "http://jail.example:8080/api/x?y=1"),
        Ok(200)
    );
    let req = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(
        req.starts_with(
            "POST http://jail.example:8080/api/x?y=1 HTTP/1.1\r\nHost: jail.example:8080\r\n"
        ),
        "{req}"
    );
    assert!(req.contains("Proxy-Authorization: Basic dTpw\r\n"), "{req}");
    assert!(req.contains("Authorization: Bearer tok\r\n"), "{req}");
    // NO_PROXY and loopback targets never reach the proxy (here nothing listens at the target).
    assert!(via(&proxy, "10.1.2.3", "http://10.1.2.3:1/x").is_err());
    assert!(via(&proxy, "", "http://127.0.0.1:1/x").is_err());
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
    // Proxies the client cannot speak to are an error, not a direct connection.
    for p in ["https://127.0.0.1:1", "socks5://127.0.0.1:1"] {
        let e = via(p, "", "http://jail.example/x").unwrap_err();
        assert!(e.contains("connect to proxy"), "{e}");
    }
}

#[test]
fn enforcer_selection_and_token_usable() {
    assert!(jail_enforcer_from_config("", "").is_none());
    assert!(jail_enforcer_from_config("k", "http://127.0.0.1:1/x").is_some());
    let path = scratch_file("usable");
    let _ = std::fs::remove_file(&path);
    let p = path.to_str().unwrap();
    assert!(check_host_agent_token(true, p).is_ok());
    assert!(check_host_agent_token(false, p).is_err());
    std::fs::write(&path, "  \n").unwrap();
    assert_eq!(
        check_host_agent_token(false, p).unwrap_err(),
        "local API token file is empty"
    );
    std::fs::write(&path, "tok").unwrap();
    assert!(check_host_agent_token(false, p).is_ok());
}

#[test]
fn skip_log_rate_limited() {
    let s = SkippedPushLog::new(MIN);
    let t0 = Instant::now();
    assert!(s.note(t0, "permission denied"));
    for i in 1..=50 {
        assert!(
            !s.note(t0 + Duration::from_secs(i), "permission denied"),
            "skip {i}"
        );
    }
    assert!(s.note(t0 + 2 * MIN, "permission denied"));
}

#[test]
fn format_jail_ttl_strings() {
    assert_eq!(format_jail_ttl(HOUR), "1h0m0s");
    assert_eq!(format_jail_ttl(45 * MIN), "45m0s");
    assert_eq!(format_jail_ttl(Duration::from_secs(90)), "1m30s");
    assert_eq!(format_jail_ttl(Duration::from_secs(5)), "5s");
}
