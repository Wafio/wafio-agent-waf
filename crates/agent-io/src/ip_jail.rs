//! The L7 → XDP feedback loop. Block verdicts per IP are counted in a sliding window;
//! at the threshold the enforcement callback jails the IP at the host agent.
//! The in-process eBPF enforcer is out of scope (the WAF agent never owns the
//! kernel firewall); the HTTP enforcer POSTs to the host agent's local API.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::client_ip::strip_port;
use crate::ip_jail_guard::{
    JAIL_EXEMPT_FORWARDED, jail_exemption_reason, log_jail_exemption, note_jail_exemption,
};

/// Jails `ip` for `ttl`. Called on its own thread, may block.
pub type Enforce = Arc<dyn Fn(&str, Duration) + Send + Sync>;

pub const DEFAULT_HOST_AGENT_TOKEN_PATH: &str = "/run/wafio/host-agent.token";

const MAX_TOKEN_FILE_SIZE: usize = 1024;

static AGENT_PANIC_HOOK: OnceLock<fn()> = OnceLock::new();

/// Registers the agent panic hook (the agent panic counter lives with the
/// heartbeat metrics). Set once at start.
pub fn set_agent_panic_hook(f: fn()) {
    let _ = AGENT_PANIC_HOOK.set(f);
}

/// Reads the host agent's local API token on every call (the host
/// agent writes a new token each start).
pub fn read_host_agent_token(path: &str) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut buf = vec![0u8; MAX_TOKEN_FILE_SIZE];
    let n = match f.read(&mut buf) {
        Ok(n) => n,
        Err(e) => return Err(format!("read local API token: {e}")),
    };
    if n == 0 {
        return Err("read local API token: EOF".into());
    }
    let token =
        String::from_utf8_lossy(wafio_bytetext::strings::trim_whitespace(&buf[..n])).into_owned();
    if token.is_empty() {
        return Err("local API token file is empty".into());
    }
    Ok(token)
}

/// The jail enforcer without the in-process eBPF path: the HTTP enforcer
/// when `jail_url` is set (`token_file` "" = default), else `None` (jail off).
pub fn jail_enforcer_from_config(token_file: &str, jail_url: &str) -> Option<Enforce> {
    if jail_url.is_empty() {
        return None;
    }
    let token_file = if token_file.is_empty() {
        DEFAULT_HOST_AGENT_TOKEN_PATH
    } else {
        token_file
    };
    Some(host_agent_jail_enforcer(jail_url, token_file))
}

/// Enforcer that POSTs `{"entries":[{"ip","ttl_ms"}],"origin":"jail"}`
/// with the host agent's local API token, read from `token_file` on every push.
pub fn host_agent_jail_enforcer(endpoint: &str, token_file: &str) -> Enforce {
    let endpoint = endpoint.to_string();
    let token_file = token_file.to_string();
    let skips = Arc::new(SkippedPushLog::new(SKIPPED_PUSH_LOG_INTERVAL));
    Arc::new(move |ip: &str, ttl: Duration| {
        let token = match read_host_agent_token(&token_file) {
            Ok(t) => t,
            Err(e) => {
                skips.note(Instant::now(), &e);
                return;
            }
        };
        // The object keys are sorted.
        let mut body = br#"{"entries":[{"ip":"#.to_vec();
        wafio_domain::json_text::append_quoted_string(&mut body, ip.as_bytes());
        body.extend_from_slice(
            format!(
                r#","ttl_ms":{}}}],"origin":"jail"}}"#,
                ttl.as_millis() as i64
            )
            .as_bytes(),
        );
        match http_post(&endpoint, &token, &body, Duration::from_secs(3)) {
            Err(e) => tracing::warn!("[ip-jail] jail POST {ip} failed: {e}"),
            Ok(200) => tracing::info!(
                "[ip-jail] {ip} jailed via {endpoint} for {}",
                format_jail_ttl(ttl)
            ),
            Ok(status) => tracing::warn!("[ip-jail] jail POST {ip} status {status}"),
        }
    })
}

/// Minimal HTTP/1.1 POST for the host agent's loopback local API, through the proxy
/// named by `HTTP_PROXY` / `NO_PROXY` (loopback hosts are never proxied).
/// shortcut: plain http:// only (the host agent's local API is not TLS) and, for a proxy, an
/// http:// one (no `https://` or `socks5://` proxy); add them when a jail URL needs it.
fn http_post(endpoint: &str, token: &str, body: &[u8], timeout: Duration) -> Result<u16, String> {
    http_post_via(
        wafio_control::proxy_env::global(),
        endpoint,
        token,
        body,
        timeout,
    )
}

fn http_post_via(
    proxies: &wafio_control::proxy_env::ProxyConfig,
    endpoint: &str,
    token: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<u16, String> {
    let quoted = || wafio_domain::text_helpers::quote(endpoint.as_bytes());
    let u = crate::url_parse::parse(endpoint.as_bytes())
        .map_err(|e| format!("Post {}: {e}", quoted()))?;
    if u.scheme != b"http" {
        return Err(format!(
            "Post {}: unsupported protocol scheme {}",
            quoted(),
            wafio_domain::text_helpers::quote(&u.scheme)
        ));
    }
    let host = String::from_utf8_lossy(&u.host).into_owned();
    let port = if u.port().is_empty() {
        "80".to_string()
    } else {
        String::from_utf8_lossy(u.port()).into_owned()
    };
    let hostname = String::from_utf8_lossy(u.hostname()).into_owned();
    let proxy = proxies
        .proxy_for("http", &hostname, &String::from_utf8_lossy(u.port()))
        .map_err(|e| format!("Post {}: {e}", quoted()))?;
    if let Some(p) = &proxy
        && matches!(p.scheme.as_str(), "https" | "socks5" | "socks5h")
    {
        return Err(format!(
            "Post {}: connect to proxy: {} proxies are not supported by the jail client",
            quoted(),
            p.scheme
        ));
    }
    let deadline = Instant::now() + timeout;
    let dial = match &proxy {
        Some(p) => p.http_address(),
        None => wafio_control::proxy_env::format_host_port(&hostname, &port),
    };
    let addr = dial
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("no address for {host}"))?;
    let mut c = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    let left = || {
        deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1))
    };
    c.set_write_timeout(Some(left()))
        .map_err(|e| e.to_string())?;
    let mut target = if u.path.is_empty() {
        b"/".to_vec()
    } else {
        u.path.clone()
    };
    if !u.raw_query.is_empty() {
        target.push(b'?');
        target.extend_from_slice(&u.raw_query);
    }
    let mut req = Vec::new();
    req.extend_from_slice(b"POST ");
    if proxy.is_some() {
        // A request through an HTTP proxy carries the absolute URL.
        req.extend_from_slice(format!("http://{host}").as_bytes());
    }
    req.extend_from_slice(&target);
    let proxy_auth = proxy
        .as_ref()
        .and_then(|p| p.basic_authorization())
        .map(|a| format!("Proxy-Authorization: {a}\r\n"))
        .unwrap_or_default();
    req.extend_from_slice(
        format!(
            " HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {}\r\nContent-Length: {}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\n{proxy_auth}Connection: close\r\n\r\n",
            crate::user_agent(),
            body.len()
        )
        .as_bytes(),
    );
    req.extend_from_slice(body);
    c.write_all(&req).map_err(|e| e.to_string())?;
    let mut head = Vec::new();
    let mut buf = [0u8; 512];
    while !head.contains(&b'\n') {
        c.set_read_timeout(Some(left()))
            .map_err(|e| e.to_string())?;
        let n = c.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF".into());
        }
        head.extend_from_slice(&buf[..n]);
    }
    let line = String::from_utf8_lossy(&head[..head.iter().position(|&b| b == b'\n').unwrap_or(0)])
        .into_owned();
    line.split(' ')
        .nth(1)
        .and_then(|s| s.trim().parse::<u16>().ok())
        .ok_or_else(|| format!("malformed HTTP response {line:?}"))
}

/// Formats a jail TTL as hours, minutes and seconds (`1h2m3s`), or as `500ms` below one second.
fn format_jail_ttl(d: Duration) -> String {
    let mut s = d.as_secs();
    let ms = d.subsec_millis();
    if s == 0 && ms > 0 {
        return format!("{ms}ms");
    }
    let mut out = String::new();
    if s >= 3600 {
        out.push_str(&format!("{}h", s / 3600));
        s %= 3600;
        out.push_str(&format!("{}m", s / 60));
        s %= 60;
    } else if s >= 60 {
        out.push_str(&format!("{}m", s / 60));
        s %= 60;
    }
    out.push_str(&format!("{s}s"));
    out
}

/// How often a skipped jail push is logged.
pub const SKIPPED_PUSH_LOG_INTERVAL: Duration = Duration::from_secs(300);

/// Rate-limits the "token unreadable" log.
pub struct SkippedPushLog {
    every: Duration,
    state: Mutex<(Option<Instant>, u64)>,
}

impl SkippedPushLog {
    pub fn new(every: Duration) -> SkippedPushLog {
        SkippedPushLog {
            every,
            state: Mutex::new((None, 0)),
        }
    }

    /// Records a skipped push and reports whether it was logged.
    pub fn note(&self, now: Instant, err: &str) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.1 += 1;
        if let Some(last) = st.0
            && now.saturating_duration_since(last) < self.every
        {
            return false;
        }
        tracing::warn!(
            "[ip-jail] {} jail push(es) skipped: host-agent token unreadable: {err}",
            st.1
        );
        *st = (Some(now), 0);
        true
    }
}

/// Succeeds when the jail is in-process, otherwise when
/// the host agent's token file is readable now.
pub fn check_host_agent_token(in_process: bool, token_file: &str) -> Result<(), String> {
    if in_process {
        return Ok(());
    }
    let token_file = if token_file.is_empty() {
        DEFAULT_HOST_AGENT_TOKEN_PATH
    } else {
        token_file
    };
    read_host_agent_token(token_file).map(|_| ())
}

type Clock = Box<dyn Fn() -> Instant + Send + Sync>;

pub struct JailTracker {
    threshold: i64,
    window: Duration,
    duration: Duration,
    max_tracked_ips: usize,
    events: Mutex<HashMap<String, Vec<Instant>>>,
    enforce: Option<Enforce>,
    now: Clock,
}

impl JailTracker {
    /// Threshold ≤ 0 disables tracking; `max_ips` bounds
    /// memory under spoofed-IP floods; `enforce` may be `None`.
    pub fn new(
        threshold: i64,
        window: Duration,
        duration: Duration,
        max_ips: usize,
        enforce: Option<Enforce>,
    ) -> JailTracker {
        JailTracker {
            threshold,
            window,
            duration,
            max_tracked_ips: max_ips,
            events: Mutex::new(HashMap::new()),
            enforce,
            now: Box::new(Instant::now),
        }
    }

    /// Replaces the clock; tests only.
    pub fn set_clock(&mut self, now: impl Fn() -> Instant + Send + Sync + 'static) {
        self.now = Box::new(now);
    }

    /// Records a block verdict for `ip`; at the threshold the
    /// enforcement fires on its own thread and the window resets.
    pub fn record_block(&self, ip: &str) {
        if self.threshold <= 0 || ip.is_empty() {
            return;
        }
        let now = (self.now)();
        let reason = jail_exemption_reason(now, ip);
        if !reason.is_empty() {
            note_jail_exemption(reason);
            log_jail_exemption(now, ip, reason);
            return;
        }
        let fire = {
            let mut ev = self.events.lock().unwrap_or_else(|e| e.into_inner());
            self.evict_expired(&mut ev, now);
            if ev.len() >= self.max_tracked_ips
                && let Some(k) = ev.keys().next().cloned()
            {
                ev.remove(&k); // spoofed-IP flood guard: drop one arbitrary IP
            }
            let list = ev.entry(ip.to_string()).or_default();
            self.drop_events_before_window(list, now);
            list.push(now);
            let fire = list.len() as i64 >= self.threshold;
            if fire {
                ev.remove(ip); // reset window after jail
            }
            fire
        };
        if fire && let Some(enforce) = self.enforce.clone() {
            let (ip, ttl) = (ip.to_string(), self.duration);
            std::thread::spawn(move || {
                if let Err(p) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| enforce(&ip, ttl)))
                {
                    if let Some(hook) = AGENT_PANIC_HOOK.get() {
                        hook();
                    }
                    let msg = p
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| p.downcast_ref::<String>().cloned())
                        .unwrap_or_default();
                    tracing::error!("[ip-jail] enforce panic recovered: {msg}");
                }
            });
        }
    }

    /// In-window block events for `ip`.
    pub fn count(&self, ip: &str) -> usize {
        let now = (self.now)();
        let mut ev = self.events.lock().unwrap_or_else(|e| e.into_inner());
        self.evict_expired(&mut ev, now);
        match ev.get_mut(ip) {
            Some(list) => {
                self.drop_events_before_window(list, now);
                list.len()
            }
            None => 0,
        }
    }

    /// Tracked IPs; diagnostics and tests.
    pub fn tracked(&self) -> usize {
        self.events.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Drops the leading events older than now − window.
    fn drop_events_before_window(&self, list: &mut Vec<Instant>, now: Instant) {
        let i = list
            .iter()
            .take_while(|t| now.saturating_duration_since(**t) > self.window)
            .count();
        list.drain(..i);
    }

    /// Drops IPs whose newest event left the window.
    fn evict_expired(&self, ev: &mut HashMap<String, Vec<Instant>>, now: Instant) {
        ev.retain(|_, list| {
            list.last()
                .is_some_and(|t| now.saturating_duration_since(*t) <= self.window)
        });
    }
}

/// Feeds a block verdict to the jail unless it was
/// raised only by a coverage gap (`CoverageRaised`); a client named by a
/// trusted proxy's forwarded headers is refused.
pub fn report_block_to_jail(
    jail: Option<&JailTracker>,
    action: &str,
    coverage_raised: bool,
    client_forwarded: bool,
    remote_addr: &str,
) {
    let Some(jail) = jail else { return };
    if action != "block" || coverage_raised {
        return;
    }
    if client_forwarded {
        note_jail_exemption(JAIL_EXEMPT_FORWARDED);
        log_jail_exemption(Instant::now(), remote_addr, JAIL_EXEMPT_FORWARDED);
        return;
    }
    jail.record_block(strip_port(remote_addr));
}

#[cfg(test)]
mod tests;
