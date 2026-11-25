//! The IP jail never drops
//! an address the agent, the control plane or the customer's own proxy tier
//! depends on. Classes, in order: invalid / unspecified / loopback /
//! link-local / multicast / broadcast, own_address (on this host's
//! interfaces), control_plane (an endpoint the agent dials), trusted_proxy (a
//! proxy hop under an app's proxy_config). RFC 1918 / 4193 addresses are
//! refused only in that last case.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use wafio_domain::ProxyConfig;
use wafio_domain::ip_address::{IpAddress, parse_ip_address};

use crate::metrics::{Label, Sample};

pub const JAIL_EXEMPT_INVALID: &str = "invalid";
pub const JAIL_EXEMPT_UNSPECIFIED: &str = "unspecified";
pub const JAIL_EXEMPT_LOOPBACK: &str = "loopback";
pub const JAIL_EXEMPT_LINK_LOCAL: &str = "link_local";
pub const JAIL_EXEMPT_MULTICAST: &str = "multicast";
pub const JAIL_EXEMPT_BROADCAST: &str = "broadcast";
pub const JAIL_EXEMPT_LOCAL_INTERFACE: &str = "own_address";
pub const JAIL_EXEMPT_CONTROL_PLANE: &str = "control_plane";
pub const JAIL_EXEMPT_TRUSTED_PROXY: &str = "trusted_proxy";
/// The client address came from forwarded headers, not the TCP peer
/// the XDP jail would act on.
pub const JAIL_EXEMPT_FORWARDED: &str = "forwarded";
/// The client address came from forwarded headers and the TCP peer is not this host, so
/// a kernel block target cannot trust it.
pub const JAIL_EXEMPT_FORWARDED_REMOTE_PEER: &str = "forwarded_remote_peer";

static EXEMPTION_COUNTS: Mutex<BTreeMap<String, Arc<AtomicU64>>> = Mutex::new(BTreeMap::new());

pub fn note_jail_exemption(reason: &str) {
    let mut m = EXEMPTION_COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    m.entry(reason.to_string())
        .or_default()
        .fetch_add(1, Ordering::Relaxed);
}

pub fn jail_exemption_count(reason: &str) -> u64 {
    let m = EXEMPTION_COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    m.get(reason).map_or(0, |c| c.load(Ordering::Relaxed))
}

/// Samples of `wafio_waf_jail_refused` by reason, sorted.
pub fn jail_exemption_samples() -> Vec<Sample> {
    let m = EXEMPTION_COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    m.iter()
        .map(|(n, c)| Sample {
            labels: vec![Label {
                name: "reason".into(),
                value: n.clone(),
            }],
            value: c.load(Ordering::Relaxed) as f64,
        })
        .collect()
}

static EXEMPTION_LOG: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// Logs one line per reason a minute.
pub fn log_jail_exemption(now: Instant, ip: &str, reason: &str) {
    {
        let mut g = EXEMPTION_LOG.lock().unwrap_or_else(|e| e.into_inner());
        let last = g.get_or_insert_default();
        if let Some(t) = last.get(reason)
            && now.saturating_duration_since(*t) < Duration::from_secs(60)
        {
            return;
        }
        last.insert(reason.to_string(), now);
    }
    tracing::warn!(
        "[ip-jail] refused to jail {}: {reason} (counted in wafio_waf_jail_refused)",
        wafio_domain::text_helpers::quote(ip.as_bytes())
    );
}

static PROXY_CONFIGS: RwLock<Option<Arc<Vec<ProxyConfig>>>> = RwLock::new(None);
static CONTROL_PLANE_ENDPOINTS: RwLock<Option<Arc<HashSet<IpAddress>>>> = RwLock::new(None);
static PINNED_CP: RwLock<Option<Arc<Vec<IpAddress>>>> = RwLock::new(None);

/// The proxy_config of every live route, refreshed
/// on each bundle apply.
pub fn install_trusted_proxy_configs(cfgs: Vec<ProxyConfig>) {
    *PROXY_CONFIGS.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(cfgs));
}

/// The resolved control-plane addresses.
pub fn install_control_plane_endpoints(eps: &[SocketAddr]) {
    let m: HashSet<IpAddress> = eps
        .iter()
        .map(|ep| IpAddress::from_std(ep.ip()).without_ipv4_mapping())
        .collect();
    *CONTROL_PLANE_ENDPOINTS
        .write()
        .unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(m));
}

/// Control-plane endpoints written by the host agent's control-plane
/// pass-through; never set by the WAF agent itself.
pub fn set_pinned_cp_endpoints(eps: Option<&[SocketAddr]>) {
    let v = eps.map(|eps| {
        Arc::new(
            eps.iter()
                .map(|ep| IpAddress::from_std(ep.ip()).without_ipv4_mapping())
                .collect(),
        )
    });
    *PINNED_CP.write().unwrap_or_else(|e| e.into_inner()) = v;
}

/// Clears every process-wide guard input; tests only.
#[doc(hidden)]
pub fn reset_jail_guard_for_test(own: Option<Vec<IpAddress>>) {
    *PROXY_CONFIGS.write().unwrap_or_else(|e| e.into_inner()) = None;
    *CONTROL_PLANE_ENDPOINTS
        .write()
        .unwrap_or_else(|e| e.into_inner()) = None;
    *PINNED_CP.write().unwrap_or_else(|e| e.into_inner()) = None;
    let _g = OWN.refresh.lock().unwrap_or_else(|e| e.into_inner());
    *OWN.snap.write().unwrap_or_else(|e| e.into_inner()) = None;
    *OWN.list.write().unwrap_or_else(|e| e.into_inner()) =
        own.map(|v| Box::new(move || Ok(v.clone())) as ListFn);
}

/// Max control-plane endpoints kept.
const CONTROL_PLANE_ENDPOINT_CAP: usize = 16;

/// Splits the `--grpc-server` value into host and port
/// ("host:port", "[v6]:port", optional "dns:///").
pub fn parse_server_endpoint(server_addr: &str) -> Result<(String, u16), String> {
    let mut addr = wafio_domain::text_helpers::trim_whitespace_str(server_addr);
    if let Some(i) = addr.rfind("://") {
        addr = &addr[i + 3..];
        addr = addr.strip_prefix('/').unwrap_or(addr);
    }
    let (host, port) = crate::url_parse::split_host_and_port(addr.as_bytes())?;
    let port = std::str::from_utf8(&port)
        .ok()
        .and_then(|p| p.parse::<u16>().ok());
    match port {
        Some(p) if p != 0 && !host.is_empty() => {
            Ok((String::from_utf8_lossy(&host).into_owned(), p))
        }
        _ => Err(format!(
            "control-plane address {} has no usable host:port",
            wafio_domain::text_helpers::quote(server_addr.as_bytes())
        )),
    }
}

/// Resolves `server_addr` to at most
/// 16 unique, valid, specified TCP endpoints.
pub async fn lookup_control_plane_endpoints(server_addr: &str) -> Result<Vec<SocketAddr>, String> {
    let (host, port) = parse_server_endpoint(server_addr)?;
    let addrs: Vec<IpAddress> = match parse_ip_address(host.as_bytes()) {
        Ok(ip) => vec![ip],
        Err(_) => {
            let fut = tokio::net::lookup_host((host.as_str(), port));
            match tokio::time::timeout(Duration::from_secs(3), fut).await {
                Ok(Ok(it)) => it.map(|sa| IpAddress::from_std(sa.ip())).collect(),
                Ok(Err(e)) => return Err(format!("resolve {host}: {e}")),
                Err(_) => return Err(format!("resolve {host}: timed out")),
            }
        }
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for a in addrs {
        let a = a.without_ipv4_mapping().with_zone(b"");
        if !a.is_valid() || a.is_unspecified() || !seen.insert(a.clone()) {
            continue;
        }
        if let Some(ip) = a.to_std() {
            out.push(SocketAddr::new(ip, port));
        }
        if out.len() == CONTROL_PLANE_ENDPOINT_CAP {
            break;
        }
    }
    if out.is_empty() {
        return Err(format!(
            "control-plane address {} resolved to no usable address",
            wafio_domain::text_helpers::quote(host.as_bytes())
        ));
    }
    Ok(out)
}

/// Resolves the gRPC server address so the jail
/// can refuse it; a failure only logs and keeps the previous set.
pub async fn refresh_jail_control_plane(server_addr: &str) {
    if server_addr.is_empty() {
        return;
    }
    match tokio::time::timeout(
        Duration::from_secs(5),
        lookup_control_plane_endpoints(server_addr),
    )
    .await
    {
        Ok(Ok(eps)) => install_control_plane_endpoints(&eps),
        Ok(Err(e)) => tracing::warn!(
            "[ip-jail] control-plane address not resolved, not protected from jailing: {e}"
        ),
        Err(_) => tracing::warn!(
            "[ip-jail] control-plane address not resolved, not protected from jailing: context deadline exceeded"
        ),
    }
}

type ListFn = Box<dyn Fn() -> Result<Vec<IpAddress>, String> + Send + Sync>;

struct LocalInterfaceSnapshot {
    at: Instant,
    set: HashSet<IpAddress>,
}

struct LocalInterfaces {
    refresh: Mutex<()>,
    snap: RwLock<Option<Arc<LocalInterfaceSnapshot>>>,
    list: RwLock<Option<ListFn>>,
}

static OWN: LocalInterfaces = LocalInterfaces {
    refresh: Mutex::new(()),
    snap: RwLock::new(None),
    list: RwLock::new(None),
};

fn refresh_local_interfaces(now: Instant) {
    let listed = match &*OWN.list.read().unwrap_or_else(|e| e.into_inner()) {
        Some(f) => f(),
        None => list_interface_addresses(),
    };
    let set = listed
        .unwrap_or_default()
        .into_iter()
        .map(|a| a.without_ipv4_mapping().with_zone(b""))
        .collect();
    *OWN.snap.write().unwrap_or_else(|e| e.into_inner()) =
        Some(Arc::new(LocalInterfaceSnapshot { at: now, set }));
}

fn snapshot() -> Option<Arc<LocalInterfaceSnapshot>> {
    OWN.snap.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Whether `a` is in the last interface-address snapshot; the first call
/// fills it synchronously, later callers refresh it once it is older than
/// 30 s while everyone else keeps using the stale set.
pub fn is_local_interface_address(now: Instant, a: &IpAddress) -> bool {
    let s = match snapshot() {
        None => {
            let _g = OWN.refresh.lock().unwrap_or_else(|e| e.into_inner());
            if snapshot().is_none() {
                refresh_local_interfaces(now);
            }
            snapshot()
        }
        Some(s) if now.saturating_duration_since(s.at) > Duration::from_secs(30) => {
            match OWN.refresh.try_lock() {
                Ok(_g) => {
                    refresh_local_interfaces(now);
                    snapshot()
                }
                Err(_) => Some(s),
            }
        }
        s => s,
    };
    s.is_some_and(|s| s.set.contains(a))
}

/// The host's interface addresses, from procfs.
/// shortcut: Linux procfs only (IPv4 LOCAL /32 entries of fib_trie, IPv6
/// if_inet6); switch to getifaddrs if `libc` becomes a workspace dependency.
fn list_interface_addresses() -> Result<Vec<IpAddress>, String> {
    let mut out = Vec::new();
    if let Ok(trie) = std::fs::read_to_string("/proc/net/fib_trie") {
        let mut last: Option<&str> = None;
        for line in trie.lines() {
            let t = line.trim();
            if let Some(ip) = t.strip_prefix("|-- ") {
                last = Some(ip);
            } else if t.starts_with("/32 host LOCAL")
                && let Some(ip) = last
                && let Ok(a) = parse_ip_address(ip.as_bytes())
            {
                out.push(a);
            }
        }
    }
    if let Ok(v6) = std::fs::read_to_string("/proc/net/if_inet6") {
        for line in v6.lines() {
            let Some(hex) = line.split_whitespace().next() else {
                continue;
            };
            if hex.len() != 32 {
                continue;
            }
            let mut b = [0u8; 16];
            let ok = (0..16).all(|i| {
                u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                    .map(|v| b[i] = v)
                    .is_ok()
            });
            if ok {
                out.push(IpAddress::from_ipv6(b));
            }
        }
    }
    Ok(out)
}

fn is_link_local_unicast(a: &IpAddress) -> bool {
    match a.to_std() {
        Some(std::net::IpAddr::V4(v)) => v.octets()[0] == 169 && v.octets()[1] == 254,
        Some(std::net::IpAddr::V6(v)) => v.segments()[0] & 0xffc0 == 0xfe80,
        None => false,
    }
}

fn is_multicast(a: &IpAddress) -> bool {
    match a.to_std() {
        Some(std::net::IpAddr::V4(v)) => v.octets()[0] & 0xf0 == 0xe0,
        Some(std::net::IpAddr::V6(v)) => v.octets()[0] == 0xff,
        None => false,
    }
}

/// Why `ip` must not be jailed, "" when it may be.
pub fn jail_exemption_reason(now: Instant, ip: &str) -> &'static str {
    let Ok(a) = parse_ip_address(ip.as_bytes()) else {
        return JAIL_EXEMPT_INVALID;
    };
    let a = a.without_ipv4_mapping().with_zone(b"");
    if a.is_unspecified() {
        return JAIL_EXEMPT_UNSPECIFIED;
    }
    if a.is_loopback() {
        return JAIL_EXEMPT_LOOPBACK;
    }
    if is_link_local_unicast(&a) {
        return JAIL_EXEMPT_LINK_LOCAL;
    }
    if is_multicast(&a) {
        return JAIL_EXEMPT_MULTICAST;
    }
    if a == IpAddress::from_ipv4([255, 255, 255, 255]) {
        return JAIL_EXEMPT_BROADCAST;
    }
    if is_local_interface_address(now, &a) {
        return JAIL_EXEMPT_LOCAL_INTERFACE;
    }
    if CONTROL_PLANE_ENDPOINTS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|cp| cp.contains(&a))
    {
        return JAIL_EXEMPT_CONTROL_PLANE;
    }
    if PINNED_CP
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|p| p.contains(&a))
    {
        return JAIL_EXEMPT_CONTROL_PLANE;
    }
    if PROXY_CONFIGS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .is_some_and(|cfgs| cfgs.iter().any(|c| c.is_proxy_address(&a)))
    {
        return JAIL_EXEMPT_TRUSTED_PROXY;
    }
    ""
}

#[cfg(test)]
pub(crate) mod tests;
