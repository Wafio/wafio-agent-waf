//! Per-client-IP limit of `POST /_wafio/challenge/verify`. The endpoint is answered before the
//! WAF pipeline and the L7 flood limiter, and each wrong answer can leave a pinned spent token
//! behind, so it has its own limit: a fixed window per address in a bounded LRU (an IPv6 client
//! counts by its /64). Process-wide, like the stores in `challenge_replay`.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use wafio_domain::ip_address::{IpPrefix, parse_ip_address};
use wafio_lru::Cache;

use crate::challenge_handler::PageResponse;
use crate::challenge_replay::parse_limit_setting;

pub const DEFAULT_VERIFY_LIMIT: i64 = 120;
pub const VERIFY_WINDOW_SECS: i64 = 60;
/// Bounds the table; an evicted address starts a fresh window.
pub const VERIFY_TABLE_CAP: usize = 50_000;

#[derive(Default)]
struct Window {
    start: i64,
    count: i64,
}

/// Verify POSTs per client address in fixed windows of [`VERIFY_WINDOW_SECS`].
pub struct VerifyLimiter(Cache<Window>);

impl VerifyLimiter {
    pub fn new(capacity: usize) -> VerifyLimiter {
        VerifyLimiter(Cache::new(capacity))
    }

    /// Counts one verify POST from `client_ip` at `now` (unix seconds) and reports whether it is
    /// within `limit` per window (<= 0 = off).
    pub fn admit(&self, limit: i64, client_ip: &[u8], now: i64) -> bool {
        if limit <= 0 {
            return true;
        }
        let mut within = true;
        self.0.update(&client_key(client_ip), |w, _| {
            if now - w.start >= VERIFY_WINDOW_SECS {
                w.start = now;
                w.count = 0;
            }
            w.count += 1;
            within = w.count <= limit;
        });
        within
    }
}

/// The address, or the /64 of an IPv6 address (an IPv4-mapped one counts as IPv4, a zone is
/// dropped); an unparsable address is its own key.
fn client_key(ip: &[u8]) -> Vec<u8> {
    let Ok(a) = parse_ip_address(ip) else {
        return ip.to_vec();
    };
    let a = a.with_zone(b"").without_ipv4_mapping();
    if a.is_ipv4() {
        a.to_string().into_bytes()
    } else {
        IpPrefix::new(&a, 64).network().to_string().into_bytes()
    }
}

static LIMITER: LazyLock<VerifyLimiter> = LazyLock::new(|| VerifyLimiter::new(VERIFY_TABLE_CAP));
static VERIFY_LIMIT: AtomicI64 = AtomicI64::new(DEFAULT_VERIFY_LIMIT);
static REFUSED: AtomicU64 = AtomicU64::new(0);

/// For `WAFIO_CHALLENGE_VERIFY_MAX_PER_MIN`: empty = default 120, 0 = off, invalid or negative
/// = default. The flag is true for an invalid value, which the caller logs
/// (`[wafio-waf-agent] ignoring invalid WAFIO_CHALLENGE_VERIFY_MAX_PER_MIN=%q; using 120`).
pub fn parse_verify_limit(v: &str) -> (i64, bool) {
    parse_limit_setting(v, DEFAULT_VERIFY_LIMIT)
}

/// Sets the limit (0 = off); call before serving.
pub fn set_verify_limit(n: i64) {
    VERIFY_LIMIT.store(n, Ordering::Relaxed);
}

/// Counts one verify POST on the process-wide table and limit and reports whether it may go on.
pub fn verify_post_allowed(client_ip: &[u8], now: i64) -> bool {
    let within = LIMITER.admit(VERIFY_LIMIT.load(Ordering::Relaxed), client_ip, now);
    if !within {
        REFUSED.fetch_add(1, Ordering::Relaxed);
    }
    within
}

/// Verify POSTs refused by the limit since the process started.
pub fn verify_refused_total() -> u64 {
    REFUSED.load(Ordering::Relaxed)
}

/// The answer to a refused verify POST: sent before any verify work.
pub fn verify_limited_response() -> PageResponse {
    PageResponse {
        status: 429,
        headers: vec![("Retry-After", VERIFY_WINDOW_SECS.to_string().into_bytes())],
        body: b"too many requests".to_vec(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000;

    #[test]
    fn window_counts_per_address() {
        let l = VerifyLimiter::new(64);
        let ip = b"198.51.100.1";
        for (i, want) in [true, true, false, false].into_iter().enumerate() {
            assert_eq!(l.admit(2, ip, T0 + i as i64), want, "request {}", i + 1);
        }
        assert!(
            !l.admit(2, ip, T0 + 59),
            "inside the window, must stay refused"
        );
        assert!(l.admit(2, ip, T0 + 60), "a new window starts at 60 s");
        assert!(
            l.admit(2, b"198.51.100.2", T0),
            "another address has its own count"
        );
    }

    #[test]
    fn limit_zero_is_off() {
        let l = VerifyLimiter::new(64);
        for _ in 0..1000 {
            assert!(l.admit(0, b"198.51.100.1", T0), "limit 0 must not refuse");
        }
    }

    #[test]
    fn keys_group_ipv6_by_64_and_unmap_ipv4() {
        let same = [
            ("2001:db8:1:2::1", "2001:db8:1:2:ffff::9"),
            ("::ffff:198.51.100.7", "198.51.100.7"),
            ("fe80::1%eth0", "fe80::2"),
        ];
        for (a, b) in same {
            assert_eq!(
                client_key(a.as_bytes()),
                client_key(b.as_bytes()),
                "{a} {b}"
            );
        }
        assert_ne!(
            client_key(b"2001:db8:1:2::1"),
            client_key(b"2001:db8:1:3::1"),
            "different /64 networks must not share a key"
        );
        assert_ne!(
            client_key(b"198.51.100.7"),
            client_key(b"198.51.100.8"),
            "IPv4 addresses are counted one by one"
        );
        assert_eq!(
            client_key(b"not-an-ip"),
            b"not-an-ip",
            "an unparsable address is its own key"
        );
    }

    /// The /64 is one client: a spray of addresses in it shares one window.
    #[test]
    fn one_ipv6_network_shares_a_window() {
        let l = VerifyLimiter::new(64);
        assert!(l.admit(2, b"2001:db8:1:2::1", T0));
        assert!(l.admit(2, b"2001:db8:1:2::2", T0));
        assert!(!l.admit(2, b"2001:db8:1:2::3", T0));
        assert!(
            l.admit(2, b"2001:db8:1:3::1", T0),
            "the next /64 is another client"
        );
    }

    #[test]
    fn env_values() {
        for (inp, want) in [
            ("", (120, false)),
            ("0", (0, false)),
            ("30", (30, false)),
            ("-1", (120, true)),
            ("x", (120, true)),
            (" 5 ", (5, false)),
            (" ", (120, true)),
        ] {
            assert_eq!(parse_verify_limit(inp), want, "{inp:?}");
        }
    }

    #[test]
    fn refusal_answer() {
        let r = verify_limited_response();
        assert_eq!(r.status, 429);
        assert_eq!(r.headers, vec![("Retry-After", b"60".to_vec())]);
        assert_eq!(r.body, b"too many requests");
    }
}
