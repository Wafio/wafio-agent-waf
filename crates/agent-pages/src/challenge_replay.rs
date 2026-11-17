//! The two in-memory stores behind the challenge: spent tokens (a solved PoW or puzzle token
//! mints one outcome) and the networks that presented each cookie id. Both are process-wide
//! and per process: a restart empties them.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};

use wafio_bytetext::strings::trim_whitespace;
use wafio_domain::ip_address::{IpPrefix, parse_ip_address};
use wafio_lru::Cache;

use crate::challenge::parse_int;
use crate::crypto::sha256;

pub const SPENT_TOKEN_CAP: usize = 100_000;
pub const DEFAULT_COOKIE_NETWORK_LIMIT: i64 = 8;

/// Wall-clock Unix seconds: what the pin hooks compare an entry's expiry with.
fn wall_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Counts the evictions of entries whose protection still held: the table held nothing else, so
/// a spent token can be used again or a revoked cookie works again.
fn count_pinned_evictions(c: &mut Cache<impl Default>) -> Arc<AtomicU64> {
    let n = Arc::new(AtomicU64::new(0));
    let hook = n.clone();
    c.set_evict_hook(move |protected| {
        if protected {
            hook.fetch_add(1, Ordering::Relaxed);
        }
    });
    n
}

/// Spent challenge tokens. Each entry holds the token's own expiry and is pinned (survives LRU
/// churn) until then; one `Cache::update` makes check-and-mark atomic per key.
pub struct SpentTokenSet {
    cache: Cache<i64>,
    pinned_evictions: Arc<AtomicU64>,
}

impl SpentTokenSet {
    pub fn new(capacity: usize) -> SpentTokenSet {
        let mut cache = Cache::new(capacity);
        cache.set_pin_hook(|expiry: &i64| *expiry >= wall_now());
        let pinned_evictions = count_pinned_evictions(&mut cache);
        SpentTokenSet {
            cache,
            pinned_evictions,
        }
    }

    /// Records `key` until `expiry` (unix seconds) and reports false
    /// when it was already spent and is still unexpired at `now`. The key is stored as its SHA-256.
    pub fn mark(&self, key: &[u8], expiry: i64, now: i64) -> bool {
        let mut fresh = false;
        self.cache.update(&sha256(key), |v, created| {
            if created || *v < now {
                *v = expiry;
                fresh = true;
            }
        });
        fresh
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Tokens evicted while still unexpired.
    pub fn pinned_evictions(&self) -> u64 {
        self.pinned_evictions.load(Ordering::Relaxed)
    }
}

/// The networks one cookie id was presented from.
#[derive(Default)]
struct Seen {
    nets: Vec<Vec<u8>>,
    expiry: i64,
    revoked: bool,
}

/// Network limit per cookie: one cookie id may be presented from at most `limit` distinct
/// networks, then it is revoked until it expires. A revoked entry is pinned until the cookie's
/// expiry, so cookie churn cannot evict it.
pub struct CookieNetworks {
    cache: Cache<Seen>,
    pinned_evictions: Arc<AtomicU64>,
}

impl CookieNetworks {
    pub fn new(capacity: usize) -> CookieNetworks {
        let mut cache = Cache::new(capacity);
        cache.set_pin_hook(|v: &Seen| v.revoked && v.expiry >= wall_now());
        let pinned_evictions = count_pinned_evictions(&mut cache);
        CookieNetworks {
            cache,
            pinned_evictions,
        }
    }

    /// Revoked cookies evicted while still unexpired.
    pub fn pinned_evictions(&self) -> u64 {
        self.pinned_evictions.load(Ordering::Relaxed)
    }

    /// With the limit given (<= 0 = off): records the network presenting cookie `id` (valid
    /// until `expiry`, unix seconds) and reports whether the cookie may still be used.
    pub fn allow(&self, limit: i64, id: &[u8], expiry: i64, client_ip: &[u8]) -> bool {
        if limit <= 0 {
            return true;
        }
        let key = network_key_for_client(client_ip);
        let mut ok = true;
        self.cache.update(id, |v, _| {
            v.expiry = expiry;
            if v.revoked {
                ok = false;
            } else if !v.nets.contains(&key) {
                if v.nets.len() as i64 >= limit {
                    v.revoked = true;
                    ok = false;
                } else {
                    v.nets.push(key);
                }
            }
        });
        ok
    }
}

/// The IPv4 /16 or IPv6 /48 of the client (an IPv4-mapped address counts as
/// IPv4, a zone is dropped); an unparsable address is its own key.
pub fn network_key_for_client(ip: &[u8]) -> Vec<u8> {
    let Ok(a) = parse_ip_address(ip) else {
        return ip.to_vec();
    };
    let a = a.with_zone(b"").without_ipv4_mapping();
    let bits = if a.is_ipv4() { 16 } else { 48 };
    IpPrefix::new(&a, bits).network().to_string().into_bytes()
}

static SPENT_TOKEN_SET: LazyLock<SpentTokenSet> =
    LazyLock::new(|| SpentTokenSet::new(SPENT_TOKEN_CAP));
static COOKIE_NETWORKS: LazyLock<CookieNetworks> =
    LazyLock::new(|| CookieNetworks::new(SPENT_TOKEN_CAP));
static COOKIE_NETWORK_LIMIT: AtomicI64 = AtomicI64::new(DEFAULT_COOKIE_NETWORK_LIMIT);

/// Marks a token spent on the process-wide store.
pub fn record_token_spent(key: &[u8], expiry: i64, now: i64) -> bool {
    SPENT_TOKEN_SET.mark(key, expiry, now)
}

/// The cookie network check on the process-wide store and limit.
pub fn cookie_network_allowed(id: &[u8], expiry: i64, client_ip: &[u8]) -> bool {
    COOKIE_NETWORKS.allow(
        COOKIE_NETWORK_LIMIT.load(Ordering::Relaxed),
        id,
        expiry,
        client_ip,
    )
}

/// Spent tokens the process-wide store evicted while still unexpired: each one can be used again.
pub fn spent_token_pinned_evictions() -> u64 {
    SPENT_TOKEN_SET.pinned_evictions()
}

/// Revoked cookies the process-wide store evicted while still unexpired: each one works again.
pub fn revoked_cookie_pinned_evictions() -> u64 {
    COOKIE_NETWORKS.pinned_evictions()
}

/// Sets the limit (0 = off); call before serving.
pub fn set_cookie_network_limit(n: i64) {
    COOKIE_NETWORK_LIMIT.store(n, Ordering::Relaxed);
}

/// The limit in force.
pub fn current_cookie_network_limit() -> i64 {
    COOKIE_NETWORK_LIMIT.load(Ordering::Relaxed)
}

/// A limit from the environment: empty = `default`, 0 = off, invalid or negative = `default`. The
/// flag is true for an invalid value, which the caller logs.
pub(crate) fn parse_limit_setting(v: &str, default: i64) -> (i64, bool) {
    if v.is_empty() {
        return (default, false);
    }
    match parse_int(trim_whitespace(v.as_bytes()), 10) {
        Some(n) if n >= 0 => (n, false),
        _ => (default, true),
    }
}

/// For `WAFIO_CHALLENGE_COOKIE_MAX_NETWORKS`: empty = default 8,
/// 0 = off, invalid or negative = default. The flag is true for an invalid value, which the
/// caller logs (`[wafio-waf-agent] ignoring invalid WAFIO_CHALLENGE_COOKIE_MAX_NETWORKS=%q; using 8`).
pub fn parse_cookie_network_limit(v: &str) -> (i64, bool) {
    parse_limit_setting(v, DEFAULT_COOKIE_NETWORK_LIMIT)
}

/// The expiry of "salt:expiry:difficulty:hmac"; an unparsable one (cannot happen
/// after validation) lasts the nonce TTL.
pub fn pow_token_deadline(tok: &[u8], now: i64) -> i64 {
    let p = wafio_bytetext::strings::splitn(tok, b":", 5);
    if p.len() == 4
        && let Some(e) = parse_int(p[1], 10)
    {
        return e;
    }
    now + 360
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn network_keys() {
        for (inp, want) in [
            ("203.0.113.5", "203.0.0.0/16"),
            ("::ffff:203.0.113.5", "203.0.0.0/16"),
            ("2001:db8:1:2::1", "2001:db8:1::/48"),
            ("fe80::1%eth0", "fe80::/48"),
            ("not-an-ip", "not-an-ip"),
            ("203.0.113.5:80", "203.0.113.5:80"),
            ("", ""),
        ] {
            assert_eq!(
                String::from_utf8(network_key_for_client(inp.as_bytes())).unwrap(),
                want,
                "{inp:?}"
            );
        }
    }

    #[test]
    fn max_networks_parsing() {
        for (inp, want) in [
            ("", (8, false)),
            ("0", (0, false)),
            ("3", (3, false)),
            ("-1", (8, true)),
            ("x", (8, true)),
            (" 5 ", (5, false)),
            (" ", (8, true)),
            ("+4", (4, false)),
            ("99999999999999999999", (8, true)),
        ] {
            assert_eq!(parse_cookie_network_limit(inp), want, "{inp:?}");
        }
    }

    #[test]
    fn spent_token_expiry_is_reusable_and_one_wins() {
        let s = SpentTokenSet::new(64);
        assert!(s.mark(b"k", NOW - 1, NOW), "first mark must succeed");
        assert!(
            s.mark(b"k", NOW + 60, NOW),
            "an expired entry is dropped lazily"
        );
        assert!(!s.mark(b"k", NOW + 60, NOW), "a live entry blocks");
        assert!(s.mark(b"other", NOW + 60, NOW));
    }

    #[test]
    fn exactly_one_of_many_racing_submissions_spends_the_token() {
        let s = SpentTokenSet::new(64);
        let wins = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|sc| {
            for _ in 0..64 {
                sc.spawn(|| {
                    if s.mark(b"race", NOW + 60, NOW) {
                        wins.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(wins.load(Ordering::SeqCst), 1);
    }

    /// Spent tokens are pinned until their expiry: churn of other entries (here lapsed ones,
    /// which are not pinned) cannot evict them and re-open a replay.
    #[test]
    fn spent_tokens_survive_churn() {
        let s = SpentTokenSet::new(64);
        let live = wall_now() + 3600;
        assert!(s.mark(b"victim", live, wall_now()));
        for i in 0..5000 {
            s.mark(format!("churn-{i}").as_bytes(), wall_now() - 60, wall_now());
        }
        assert!(!s.mark(b"victim", live, wall_now()), "replay possible");
        assert!(s.len() <= 64);
    }

    #[test]
    fn cookie_network_limit() {
        let c = CookieNetworks::new(1024);
        let exp = wall_now() + 3600;
        let v4 = |i: i32| format!("11.{i}.0.1");
        // The ninth network revokes for good, the first included.
        let id = b"aaaaaaaaaaaaaaa1";
        for i in 1..=8 {
            assert!(c.allow(8, id, exp, v4(i).as_bytes()), "network {i} refused");
        }
        assert!(
            !c.allow(8, id, exp, v4(9).as_bytes()),
            "9th network accepted"
        );
        assert!(
            !c.allow(8, id, exp, v4(1).as_bytes()),
            "revoked cookie accepted again from its first network"
        );
        // One user on v4 and v6 (and a mapped address).
        let id = b"aaaaaaaaaaaaaaa2";
        for ip in [
            "203.0.113.5",
            "2001:db8:1:2::1",
            "203.0.113.9",
            "2001:db8:1:ffff::7",
            "::ffff:203.0.113.77",
        ] {
            assert!(c.allow(8, id, exp, ip.as_bytes()), "{ip} refused");
        }
        // The same /16 counts once.
        let id = b"aaaaaaaaaaaaaaa3";
        for i in 0..50 {
            assert!(
                c.allow(8, id, exp, format!("198.51.{i}.1").as_bytes()),
                "host {i} of one /16 refused"
            );
        }
        // Limit 0 (or less) is off.
        let id = b"aaaaaaaaaaaaaaa4";
        for i in 1..=30 {
            assert!(c.allow(0, id, exp, v4(i).as_bytes()));
        }
    }

    /// A revoked cookie is pinned until its expiry: minting many other cookie ids cannot flush the
    /// revocation and bring the cookie back.
    #[test]
    fn revoked_cookie_survives_churn() {
        let c = CookieNetworks::new(64);
        let exp = wall_now() + 3600;
        let id = b"bbbbbbbbbbbbbbb1";
        assert!(c.allow(1, id, exp, b"192.0.2.1"));
        assert!(
            !c.allow(1, id, exp, b"198.51.100.1"),
            "second network accepted with max 1"
        );
        for i in 0..5000 {
            c.allow(
                1,
                format!("churn{}", 1_000_000_000 + i).as_bytes(),
                exp,
                b"203.0.113.1",
            );
        }
        assert!(
            !c.allow(1, id, exp, b"192.0.2.1"),
            "revoked cookie accepted again after cache churn"
        );
    }

    /// An eviction of a still-protected entry is counted; one whose protection lapsed is not.
    #[test]
    fn pinned_evictions_are_counted() {
        let live = wall_now() + 3600;
        let s = SpentTokenSet::new(1);
        s.mark(b"a", live, wall_now());
        s.mark(b"b", live, wall_now());
        assert_eq!(
            s.pinned_evictions(),
            1,
            "a live token went from a full table"
        );

        let s = SpentTokenSet::new(1);
        s.mark(b"old", wall_now() - 60, wall_now());
        s.mark(b"new", live, wall_now());
        assert_eq!(s.pinned_evictions(), 0, "a lapsed token counted as pinned");

        let c = CookieNetworks::new(1);
        assert!(c.allow(1, b"c1", live, b"198.51.100.1"));
        assert!(
            !c.allow(1, b"c1", live, b"203.0.113.1"),
            "second network must revoke"
        );
        assert_eq!(c.pinned_evictions(), 0);
        c.allow(1, b"c2", live, b"198.51.100.1");
        assert_eq!(
            c.pinned_evictions(),
            1,
            "the revoked cookie went from a full table"
        );
    }

    #[test]
    fn pow_token_expiry_reads_the_second_field() {
        assert_eq!(pow_token_deadline(b"salt:1234:12:mac", NOW), 1234);
        assert_eq!(pow_token_deadline(b"salt:1234:12:mac:x", NOW), NOW + 360);
        assert_eq!(pow_token_deadline(b"junk", NOW), NOW + 360);
    }
}
