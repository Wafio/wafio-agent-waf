//! Outbound proxies.
//!
//! - [`ProxyConfig`]: `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` and their lower-case spellings (the
//!   first non-empty one wins), read once per process ([`global`]), `NO_PROXY` entries as IP, CIDR,
//!   `host:port`, `.domain`, `*.domain`, `*`, loopback and `localhost` never proxied, `HTTP_PROXY`
//!   refused when `REQUEST_METHOD` is set (CGI). The schemes pick the variable: an `http` request
//!   reads `HTTP_PROXY`, an `https` one `HTTPS_PROXY`.
//! - [`http_connect`] / [`socks5_connect`]: the tunnels (`CONNECT host:port`, `Proxy-Authorization:
//!   Basic` from the proxy URL's userinfo; SOCKS5 with optional user/password) over any async stream.
//! - [`open_grpc_relay`]: the control-plane channel: `HTTPS_PROXY` / `NO_PROXY` decide, a plain
//!   `CONNECT host:port` goes to the proxy whatever its scheme (no TLS to an `https://` proxy, no
//!   SOCKS), the proxy resolves the target name and a proxy URL without a port means port 443.
//!
//! shortcut: `NO_PROXY` hosts are matched as written; an internationalised host name is not
//! converted to punycode first.

use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use wafio_bytetext::net::{IpBytes, parse_ip, parse_ip_address};
use wafio_bytetext::url;

/// A parsed proxy URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyUrl {
    /// Lower-case scheme; `http` when the value had none.
    pub scheme: String,
    /// Host name or address, without brackets.
    pub host: String,
    /// Digits as written; empty = the scheme's default.
    pub port: String,
    /// Decoded userinfo (user name and password).
    pub user: Option<(Vec<u8>, Vec<u8>)>,
}

impl ProxyUrl {
    /// `host:port` (IPv6 in brackets) with `default_port` when the URL names none.
    pub fn address(&self, default_port: &str) -> String {
        let port = if self.port.is_empty() {
            default_port
        } else {
            &self.port
        };
        format_host_port(&self.host, port)
    }

    /// `host:port` with the scheme's default port (80 for an unknown scheme).
    pub fn http_address(&self) -> String {
        self.address(match default_port(&self.scheme) {
            "" => "80",
            p => p,
        })
    }

    /// `Basic base64(user:password)` for the userinfo.
    pub fn basic_authorization(&self) -> Option<String> {
        self.user.as_ref().map(|(u, p)| {
            let mut cred = u.clone();
            cred.push(b':');
            cred.extend_from_slice(p);
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(cred)
            )
        })
    }
}

pub fn format_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Splits `host:port` (None for a malformed address). The host has no brackets.
pub fn split_host_and_port(s: &str) -> Option<(&str, &str)> {
    let i = s.rfind(':')?;
    let (host, j, k);
    if s.starts_with('[') {
        let end = s.find(']')?;
        if end + 1 == s.len() || end + 1 != i {
            return None;
        }
        host = &s[1..end];
        j = 1;
        k = end + 1;
    } else {
        host = &s[..i];
        if host.contains(':') {
            return None;
        }
        j = 0;
        k = 0;
    }
    if s[j..].contains('[') || s[k..].contains(']') {
        return None;
    }
    Some((host, &s[i + 1..]))
}

/// The host (brackets removed) and the port of a URL's `host:port` part.
pub fn split_url_host(hostport: &str) -> (&str, &str) {
    let (mut host, mut port) = (hostport, "");
    if let Some(c) = hostport.rfind(':')
        && hostport[c + 1..].bytes().all(|b| b.is_ascii_digit())
    {
        host = &hostport[..c];
        port = &hostport[c + 1..];
    }
    if host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    (host, port)
}

fn default_port(scheme: &str) -> &'static str {
    match scheme {
        "http" => "80",
        "https" => "443",
        "socks5" | "socks5h" => "1080",
        _ => "",
    }
}

/// Parses a proxy value into the pieces `ProxyUrl` keeps, and whether it had a scheme and a host.
fn parse_proxy_url(s: &str) -> Option<(ProxyUrl, bool)> {
    let u = url::parse(s.as_bytes()).ok()?;
    let scheme = String::from_utf8_lossy(&u.scheme).into_owned();
    let hostport = String::from_utf8_lossy(&u.host).into_owned();
    let (host, port) = split_url_host(&hostport);
    let user = userinfo(s, &scheme);
    let complete = !scheme.is_empty() && !hostport.is_empty();
    Some((
        ProxyUrl {
            scheme,
            host: host.to_string(),
            port: port.to_string(),
            user: user.flatten(),
        },
        complete,
    ))
}

/// The decoded userinfo of `s` (`Some(None)` when there is an authority without one).
fn userinfo(s: &str, scheme: &str) -> Option<Option<(Vec<u8>, Vec<u8>)>> {
    let s = s.split('#').next()?;
    let after = if scheme.is_empty() {
        s
    } else {
        s.get(scheme.len() + 1..)?
    };
    let auth = after.strip_prefix("//")?;
    let auth = &auth[..auth.find(['/', '?']).unwrap_or(auth.len())];
    let Some((ui, _)) = auth.rsplit_once('@') else {
        return Some(None);
    };
    let (u, p) = ui.split_once(':').unwrap_or((ui, ""));
    let dec = |x: &str| url::unescape_path_segment(x.as_bytes()).ok();
    Some(Some((dec(u)?, dec(p)?)))
}

/// A value that is not a full URL gets `http://` in front; None = the value is ignored (a proxy
/// that cannot be parsed is dropped).
fn parse_proxy(proxy: &str) -> Option<ProxyUrl> {
    if proxy.is_empty() {
        return None;
    }
    let first = parse_proxy_url(proxy);
    if let Some((u, true)) = first {
        return Some(u);
    }
    // shortcut: a URL with a scheme but no host whose "http://" form is invalid stays unusable
    // here; no proxy is closer to the intent.
    parse_proxy_url(&format!("http://{proxy}"))
        .map(|(u, _)| u)
        .filter(|u| !u.host.is_empty())
}

enum IpMatch {
    /// A network and its prefix length: 4 bytes for IPv4, 16 for IPv6.
    Cidr(Vec<u8>, u32),
    /// An address (16-byte form) and an optional port.
    Address([u8; 16], String),
}

struct DomainMatch {
    host: String,
    port: String,
    match_host: bool,
}

#[derive(Default)]
pub struct ProxyConfig {
    http: Option<ProxyUrl>,
    https: Option<ProxyUrl>,
    cgi: bool,
    /// `NO_PROXY` was `*`.
    all: bool,
    ips: Vec<IpMatch>,
    domains: Vec<DomainMatch>,
}

fn bits_match(a: &[u8], b: &[u8], prefix: u32) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    rem == 0 || {
        let mask = 0xffu8 << (8 - rem);
        a[full] & mask == b[full] & mask
    }
}

impl ProxyConfig {
    pub fn from_env() -> ProxyConfig {
        let any = |names: [&str; 2]| {
            names
                .iter()
                .filter_map(|n| std::env::var(n).ok())
                .find(|v| !v.is_empty())
                .unwrap_or_default()
        };
        ProxyConfig::from_parts(
            &any(["HTTP_PROXY", "http_proxy"]),
            &any(["HTTPS_PROXY", "https_proxy"]),
            &any(["NO_PROXY", "no_proxy"]),
            std::env::var_os("REQUEST_METHOD").is_some_and(|v| !v.is_empty()),
        )
    }

    pub fn from_parts(http: &str, https: &str, no_proxy: &str, cgi: bool) -> ProxyConfig {
        let mut c = ProxyConfig {
            http: parse_proxy(http),
            https: parse_proxy(https),
            cgi,
            ..Default::default()
        };
        for p in no_proxy.split(',') {
            let p = p.trim().to_lowercase();
            if p.is_empty() {
                continue;
            }
            if p == "*" {
                c.all = true;
                c.ips.clear();
                c.domains.clear();
                return c;
            }
            if let Some(m) = parse_network_prefix(&p) {
                c.ips.push(m);
                continue;
            }
            let (mut phost, pport) = match split_host_and_port(&p) {
                Some((h, port)) => {
                    if h.is_empty() {
                        continue;
                    }
                    (h.to_string(), port.to_string())
                }
                None => (p.clone(), String::new()),
            };
            if let Some(ip) = parse_ip(phost.as_bytes()) {
                if let Some(b) = ip.to_ipv6_octets() {
                    c.ips.push(IpMatch::Address(b, pport));
                }
                continue;
            }
            if phost.is_empty() {
                continue;
            }
            // foo.com matches bar.foo.com; .foo.com and *.foo.com only the subdomains
            if let Some(rest) = phost.strip_prefix("*.") {
                phost = format!(".{rest}");
            }
            let match_host = !phost.starts_with('.');
            if match_host {
                phost = format!(".{phost}");
            }
            c.domains.push(DomainMatch {
                host: phost,
                port: pport,
                match_host,
            });
        }
        c
    }

    /// The proxy for a request to `host` (no brackets) and `port` (empty = the scheme's default),
    /// None for a direct one.
    pub fn proxy_for(
        &self,
        scheme: &str,
        host: &str,
        port: &str,
    ) -> Result<Option<ProxyUrl>, String> {
        let proxy = match scheme {
            "https" => self.https.as_ref(),
            "http" => {
                if self.http.is_some() && self.cgi {
                    return Err("refusing to use HTTP_PROXY value in CGI environment; see golang.org/s/cgihttpproxy".into());
                }
                self.http.as_ref()
            }
            _ => None,
        };
        let Some(proxy) = proxy else {
            return Ok(None);
        };
        let port = if port.is_empty() {
            default_port(scheme)
        } else {
            port
        };
        Ok(self.use_proxy(host, port).then(|| proxy.clone()))
    }

    fn use_proxy(&self, host: &str, port: &str) -> bool {
        if host == "localhost" {
            return false;
        }
        let ip = host_ip(host);
        if ip.as_ref().is_some_and(IpBytes::is_loopback) {
            return false;
        }
        let host = host.trim().to_lowercase();
        if self.all {
            return false;
        }
        if let Some(ip) = &ip {
            for m in &self.ips {
                let hit = match m {
                    IpMatch::Cidr(net, prefix) => ip_in(ip, net, *prefix),
                    IpMatch::Address(a, p) => {
                        ip.to_ipv6_octets().is_some_and(|b| &b == a) && (p.is_empty() || p == port)
                    }
                };
                if hit {
                    return false;
                }
            }
            return true; // a domain entry never matches an address
        }
        !self.domains.iter().any(|m| {
            (host.ends_with(&m.host) || (m.match_host && host == m.host[1..]))
                && (m.port.is_empty() || m.port == port)
        })
    }
}

/// Parses an IP address as bytes (a zone is allowed and dropped).
fn host_ip(host: &str) -> Option<IpBytes> {
    let a = parse_ip_address(host.as_bytes()).ok()?;
    Some(IpBytes(a.bytes.to_vec()))
}

/// Whether `ip` is in the network stored as 4 bytes (IPv4) or 16 bytes (IPv6).
fn ip_in(ip: &IpBytes, net: &[u8], prefix: u32) -> bool {
    match ip.to_ipv4_octets() {
        Some(v4) => net.len() == 4 && bits_match(v4, net, prefix),
        None => net.len() == 16 && ip.0.len() == 16 && bits_match(&ip.0, net, prefix),
    }
}

fn parse_network_prefix(s: &str) -> Option<IpMatch> {
    let (addr, mask) = s.split_once('/')?;
    let a = parse_ip_address(addr.as_bytes()).ok()?;
    if a.has_zone || mask.is_empty() || !mask.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u32 = mask.parse().ok()?;
    if n > if a.is_ipv4 { 32 } else { 128 } {
        return None;
    }
    if a.is_ipv4 {
        return Some(IpMatch::Cidr(a.bytes[12..].to_vec(), n));
    }
    // A v4-mapped network is a 4-byte network whose mask is the last four bytes of the 16-byte one.
    if let Some(v4) = IpBytes(a.bytes.to_vec()).to_ipv4_octets() {
        return Some(IpMatch::Cidr(v4.to_vec(), n.saturating_sub(96)));
    }
    Some(IpMatch::Cidr(a.bytes.to_vec(), n))
}

/// The process-wide configuration, read from the environment on first use.
pub fn global() -> &'static ProxyConfig {
    static G: OnceLock<ProxyConfig> = OnceLock::new();
    G.get_or_init(ProxyConfig::from_env)
}

// ── tunnels ─────────────────────────────────────────────────────────────────────────────────

/// Why a tunnel was not opened.
#[derive(Debug)]
pub enum TunnelError {
    /// Reading or writing the proxy connection failed, or the proxy answered something that is not HTTP.
    Io(String),
    /// The proxy answered a status other than 200.
    Refused {
        /// `403 Forbidden`.
        status: String,
        /// The response head as received.
        head: String,
    },
}

impl std::fmt::Display for TunnelError {
    /// The reason phrase of a refusal.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::Io(e) => f.write_str(e),
            TunnelError::Refused { status, .. } => f.write_str(
                status
                    .split_once(' ')
                    .map_or("unknown status code", |x| x.1),
            ),
        }
    }
}

fn io_error(e: std::io::Error) -> TunnelError {
    TunnelError::Io(e.to_string())
}

/// Reads up to the blank line ending a response head, one byte at a time so nothing the proxy
/// sent after it is consumed (a TLS server never speaks first, but the bytes stay the caller's).
async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> Result<String, TunnelError> {
    const MAX: usize = 64 << 10;
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    while !(head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n")) {
        if head.len() >= MAX {
            return Err(TunnelError::Io(
                "server response headers exceeded 65536 bytes".into(),
            ));
        }
        match io.read(&mut b).await.map_err(io_error)? {
            0 => return Err(TunnelError::Io("EOF".into())),
            _ => head.push(b[0]),
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// `CONNECT target HTTP/1.1` over `io`, with `Proxy-Authorization` when given; Ok on a 200.
pub async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    target: &str,
    proxy_auth: Option<&str>,
    ua: &str,
) -> Result<(), TunnelError> {
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {ua}\r\n");
    if let Some(a) = proxy_auth {
        req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    io.write_all(req.as_bytes()).await.map_err(io_error)?;
    io.flush().await.map_err(io_error)?;
    let head = read_head(io).await?;
    let line = head.lines().next().unwrap_or("");
    let status = line
        .split_once(' ')
        .filter(|(v, _)| v.starts_with("HTTP/"))
        .map(|x| x.1.trim().to_string())
        .filter(|s| s.len() >= 3 && s.as_bytes()[..3].iter().all(u8::is_ascii_digit))
        .ok_or_else(|| TunnelError::Io(format!("malformed HTTP response {line:?}")))?;
    if status.starts_with("200") && status[3..].chars().next().is_none_or(|c| c == ' ') {
        Ok(())
    } else {
        Err(TunnelError::Refused { status, head })
    }
}

/// SOCKS5 CONNECT (RFC 1928) to `host:port`; the proxy resolves a name. `auth` is the
/// user/password of the proxy URL (RFC 1929), offered next to "no authentication".
pub async fn socks5_connect<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    host: &str,
    port: u16,
    auth: Option<(&[u8], &[u8])>,
) -> Result<(), String> {
    let e = |e: std::io::Error| e.to_string();
    let greeting: &[u8] = if auth.is_some() {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    };
    io.write_all(greeting).await.map_err(e)?;
    let mut r = [0u8; 2];
    io.read_exact(&mut r).await.map_err(e)?;
    if r[0] != 5 {
        return Err("unexpected protocol version".into());
    }
    match r[1] {
        0 => {}
        2 => {
            let (u, p) = auth.ok_or("unsupported authentication method")?;
            if u.len() > 255 || p.len() > 255 {
                return Err("invalid username/password".into());
            }
            let mut m = vec![1, u.len() as u8];
            m.extend_from_slice(u);
            m.push(p.len() as u8);
            m.extend_from_slice(p);
            io.write_all(&m).await.map_err(e)?;
            io.read_exact(&mut r).await.map_err(e)?;
            if r != [1, 0] {
                return Err("authentication failed".into());
            }
        }
        0xff => return Err("no acceptable authentication methods".into()),
        _ => return Err("unsupported authentication method".into()),
    }
    let mut m = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            m.push(1);
            m.extend_from_slice(&a.octets());
        }
        Ok(IpAddr::V6(a)) => {
            m.push(4);
            m.extend_from_slice(&a.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err("name too long".into());
            }
            m.extend_from_slice(&[3, host.len() as u8]);
            m.extend_from_slice(host.as_bytes());
        }
    }
    m.extend_from_slice(&port.to_be_bytes());
    io.write_all(&m).await.map_err(e)?;
    let mut h = [0u8; 4];
    io.read_exact(&mut h).await.map_err(e)?;
    if h[0] != 5 {
        return Err("unexpected protocol version".into());
    }
    if h[1] != 0 {
        return Err(match h[1] {
            1 => "general SOCKS server failure",
            2 => "connection not allowed by ruleset",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "TTL expired",
            7 => "command not supported",
            8 => "address type not supported",
            _ => "unknown error",
        }
        .into());
    }
    let skip = match h[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0u8; 1];
            io.read_exact(&mut n).await.map_err(e)?;
            usize::from(n[0])
        }
        _ => return Err("unknown address type".into()),
    };
    let mut rest = vec![0u8; skip + 2];
    io.read_exact(&mut rest).await.map_err(e)?;
    Ok(())
}

/// `CONNECT target` with its error texts: a write error is wrapped twice, a response that cannot
/// be read is `reading server HTTP response: …`, any other status than 200 is
/// `failed to do connect handshake, response: %q` of the re-serialised response (status line,
/// `Connection: close` for a close-delimited body, `Content-Length`, the other headers in sorted
/// order, the body), or, when its body cannot be read, `…, status code: <status>`.
///
/// shortcut: a chunked refusal body is dumped as `status code: …` rather than decoded and written
/// back as `Transfer-Encoding: chunked`.
async fn grpc_connect<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    target: &str,
    proxy_auth: Option<&str>,
    ua: &str,
) -> Result<(), String> {
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: {ua}\r\n");
    if let Some(a) = proxy_auth {
        req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    let werr = |e: std::io::Error| {
        format!("failed to write the HTTP request: failed to write the HTTP request: {e}")
    };
    io.write_all(req.as_bytes()).await.map_err(werr)?;
    io.flush().await.map_err(werr)?;
    let rerr = |e: String| {
        // An early EOF reads as "unexpected EOF".
        let e = if e == "EOF" {
            "unexpected EOF".to_string()
        } else {
            e
        };
        format!("reading server HTTP response: {e}")
    };
    let head = match read_head(io).await {
        Ok(h) => h,
        Err(TunnelError::Io(e)) => return Err(rerr(e)),
        Err(e) => return Err(rerr(e.to_string())),
    };
    let quoted = |s: &str| wafio_bytetext::literal::quote(s.as_bytes());
    let bad = |what: &str, v: &str| rerr(format!("{what} {}", String::from_utf8_lossy(&quoted(v))));
    let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let line = lines.next().unwrap_or("");
    let (proto, status) = line
        .split_once(' ')
        .ok_or_else(|| bad("malformed HTTP response", line))?;
    let status = status.trim_start_matches(' ');
    let (code, reason) = status.split_once(' ').unwrap_or((status, ""));
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("malformed HTTP status code", code));
    }
    let version = proto
        .strip_prefix("HTTP/")
        .and_then(|v| v.split_once('.'))
        .filter(|(a, b)| {
            [a, b]
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
        });
    let Some((major, minor)) = version else {
        return Err(bad("malformed HTTP version", proto));
    };
    if code == "200" {
        return Ok(());
    }
    let fallback = format!("failed to do connect handshake, status code: {code} {reason}");
    // The headers: canonical keys, values trimmed, in sorted order.
    let mut hdrs: Vec<(String, String)> = Vec::new();
    for l in lines.take_while(|l| !l.is_empty()) {
        if let Some((k, v)) = l.split_once(':') {
            let mut up = true;
            let key: String = k
                .chars()
                .map(|c| {
                    let c = if up {
                        c.to_ascii_uppercase()
                    } else {
                        c.to_ascii_lowercase()
                    };
                    up = c == '-';
                    c
                })
                .collect();
            hdrs.push((key, v.trim().to_string()));
        }
    }
    hdrs.sort_by(|a, b| a.0.cmp(&b.0));
    let get = |name: &str| {
        hdrs.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let chunked = get("Transfer-Encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    if chunked {
        return Err(fallback);
    }
    let mut body = Vec::new();
    let declared = match get("Content-Length") {
        Some(v) => Some(v.parse::<usize>().map_err(|_| fallback.clone())?),
        None => None,
    };
    let read = async {
        match declared {
            Some(n) if n <= 1 << 20 => {
                body.resize(n, 0);
                io.read_exact(&mut body).await.map(drop)
            }
            Some(_) => Err(std::io::Error::other("too long")),
            None => (&mut *io)
                .take(1 << 20)
                .read_to_end(&mut body)
                .await
                .map(drop),
        }
    };
    if !matches!(
        tokio::time::timeout(Duration::from_secs(5), read).await,
        Ok(Ok(()))
    ) {
        return Err(fallback);
    }
    let minor_at_least_1 = (
        major.parse::<u32>().unwrap_or(0),
        minor.parse::<u32>().unwrap_or(0),
    ) >= (1, 1);
    let close = get("Connection")
        .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")));
    let mut dump = format!("{proto} {code} {reason}\r\n");
    if declared.is_none() && minor_at_least_1 && !close {
        dump.push_str("Connection: close\r\n");
    }
    if declared.is_some() {
        dump.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (k, v) in &hdrs {
        if !matches!(
            k.as_str(),
            "Content-Length" | "Transfer-Encoding" | "Trailer"
        ) {
            dump.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    dump.push_str("\r\n");
    let mut out = dump.into_bytes();
    out.extend_from_slice(&body);
    Err(format!(
        "failed to do connect handshake, response: {}",
        String::from_utf8_lossy(&wafio_bytetext::literal::quote(&out))
    ))
}

/// How long the tunnel dial and the relay wait for a connection.
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);

/// The control-plane channel through `proxy`. tonic dials TCP itself, so this opens the tunnel
/// first (`CONNECT target`, the target name unresolved: the proxy resolves it) and returns the
/// loopback port of a relay that serves exactly one connection with it; the caller points the
/// endpoint at `127.0.0.1:<port>` (TLS name and authority unchanged). Err is the text
/// `transport: Error while dialing: …`.
///
/// shortcut: one connection per call. A stream that loses its connection ends and the link dials
/// again with a new tunnel, so the channel never needs a second one; use `connect_with_connector`
/// (needs `hyper-util` as a workspace dependency) to drop the relay.
pub async fn open_grpc_relay(proxy: &ProxyUrl, target: &str, ua: &str) -> Result<u16, String> {
    let dial = async {
        let mut up = tokio::net::TcpStream::connect(proxy.address("443"))
            .await
            .map_err(|e| e.to_string())?;
        grpc_connect(&mut up, target, proxy.basic_authorization().as_deref(), ua).await?;
        Ok::<_, String>(up)
    };
    let mut up = tokio::time::timeout(DIAL_TIMEOUT, dial)
        .await
        .map_err(|_| "context deadline exceeded".to_string())??;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    tokio::spawn(async move {
        if let Ok(Ok((mut down, _))) = tokio::time::timeout(DIAL_TIMEOUT, listener.accept()).await {
            drop(listener);
            let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
        }
    });
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn proxy_for(c: &ProxyConfig, url: &str) -> Option<String> {
        let (scheme, rest) = url.split_once("://").unwrap();
        let auth = rest.split('/').next().unwrap();
        let (h, p) = split_url_host(auth);
        c.proxy_for(scheme, h, p)
            .unwrap()
            .map(|u| format!("{}://{}", u.scheme, u.address("")))
    }

    #[test]
    fn schemes_pick_the_variable_and_loopback_is_never_proxied() {
        let c = ProxyConfig::from_parts("http://hp:3128", "https://sp:3129", "", false);
        assert_eq!(
            proxy_for(&c, "http://example.com"),
            Some("http://hp:3128".into())
        );
        assert_eq!(
            proxy_for(&c, "https://example.com"),
            Some("https://sp:3129".into())
        );
        for direct in [
            "http://localhost",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "https://127.0.0.2",
            "http://[::1]",
            "http://[::ffff:127.0.0.1]:80",
        ] {
            assert_eq!(proxy_for(&c, direct), None, "{direct}");
        }
        // only HTTPS_PROXY set: plain http goes direct, and the reverse
        let c = ProxyConfig::from_parts("", "http://sp:1", "", false);
        assert_eq!(proxy_for(&c, "http://example.com"), None);
        assert_eq!(
            proxy_for(&c, "https://example.com"),
            Some("http://sp:1".into())
        );
        assert_eq!(
            ProxyConfig::default().proxy_for("https", "example.com", ""),
            Ok(None)
        );
    }

    #[test]
    fn proxy_values_are_completed_like_parse_proxy() {
        let parse = |s: &str| parse_proxy(s).map(|u| (u.scheme, u.host, u.port));
        let t = |a: &str, b: &str, c: &str| Some((a.into(), b.into(), c.into()));
        assert_eq!(parse("proxy:3128"), t("http", "proxy", "3128"));
        assert_eq!(parse("1.2.3.4:3128"), t("http", "1.2.3.4", "3128"));
        assert_eq!(parse("localhost"), t("http", "localhost", ""));
        assert_eq!(parse("https://p.example"), t("https", "p.example", ""));
        assert_eq!(parse("socks5://p:1080"), t("socks5", "p", "1080"));
        assert_eq!(parse("socks5h://p:1080"), t("socks5h", "p", "1080"));
        assert_eq!(parse("[::1]:3128"), t("http", "::1", "3128"));
        assert_eq!(parse(""), None);
        let u = parse_proxy("http://us%40er:p%3Ass@h:1/").unwrap();
        assert_eq!(u.user, Some((b"us@er".to_vec(), b"p:ss".to_vec())));
        assert_eq!(u.basic_authorization().unwrap(), "Basic dXNAZXI6cDpzcw==");
        assert_eq!(parse_proxy("http://h:1").unwrap().user, None);
        // a port-less proxy URL means 80 for an HTTP client, 443 for gRPC
        let p = parse_proxy("http://h").unwrap();
        assert_eq!(
            (p.address("80"), p.address("443")),
            ("h:80".into(), "h:443".into())
        );
        assert_eq!(
            parse_proxy("http://[::1]:7").unwrap().address("80"),
            "[::1]:7"
        );
    }

    #[test]
    fn no_proxy_entries() {
        let c = |np: &str| ProxyConfig::from_parts("http://p:1", "http://p:1", np, false);
        let via = |c: &ProxyConfig, u: &str| proxy_for(c, u).is_some();
        // a name matches itself and its subdomains
        let n = c("example.com");
        assert!(!via(&n, "http://example.com"));
        assert!(!via(&n, "http://foo.example.com"));
        assert!(!via(&n, "http://EXAMPLE.com"));
        assert!(via(&n, "http://notexample.com"));
        // a leading dot or *. only the subdomains
        for np in [".example.com", "*.example.com"] {
            let n = c(np);
            assert!(via(&n, "http://example.com"), "{np}");
            assert!(!via(&n, "http://foo.example.com"), "{np}");
        }
        // ports compare as written: the default port of the scheme counts
        let n = c("example.com:80");
        assert!(!via(&n, "http://example.com"));
        assert!(!via(&n, "http://example.com:80"));
        assert!(via(&n, "https://example.com"));
        assert!(via(&n, "http://example.com:8080"));
        // addresses and networks
        let n = c("1.2.3.4, 10.0.0.0/8, fd00::/8, [2001:db8::1]:8443");
        assert!(!via(&n, "http://1.2.3.4"));
        assert!(!via(&n, "http://10.9.8.7"));
        assert!(via(&n, "http://11.9.8.7"));
        assert!(!via(&n, "http://[fd12::1]"));
        assert!(via(&n, "http://[fe80::1]"));
        assert!(!via(&n, "https://[2001:db8::1]:8443"));
        assert!(via(&n, "https://[2001:db8::1]:443"));
        // a v4-mapped address matches the v4 entries
        assert!(!via(&n, "http://[::ffff:10.1.1.1]"));
        // a domain entry never matches an address literal
        assert!(via(&c("0.0.0.1"), "http://example.com"));
        assert!(via(&c("4"), "http://1.2.3.4"));
        // `*` turns proxying off, later entries are not read, junk is ignored
        assert!(!via(&c("*"), "http://example.com"));
        assert!(!via(&c("a.com, *, b.com"), "http://example.com"));
        let junk = c(",, :80, ,example.org");
        assert!(via(&junk, "http://example.com"));
        assert!(!via(&junk, "http://example.org"));
    }

    #[test]
    fn cgi_refuses_http_proxy_only() {
        let c = ProxyConfig::from_parts("http://p:1", "http://p:1", "", true);
        assert!(c.proxy_for("http", "example.com", "").is_err());
        assert!(c.proxy_for("https", "example.com", "").unwrap().is_some());
        // no HTTP_PROXY: nothing to refuse
        let c = ProxyConfig::from_parts("", "http://p:1", "", true);
        assert_eq!(c.proxy_for("http", "example.com", ""), Ok(None));
    }

    #[test]
    fn host_port_splitting() {
        assert_eq!(split_host_and_port("h:80"), Some(("h", "80")));
        assert_eq!(split_host_and_port("[::1]:80"), Some(("::1", "80")));
        assert_eq!(split_host_and_port("h"), None);
        assert_eq!(split_host_and_port("::1"), None);
        assert_eq!(split_host_and_port("[::1]"), None);
        assert_eq!(split_url_host("h:"), ("h", ""));
        assert_eq!(split_url_host("[::1]"), ("::1", ""));
        assert_eq!(split_url_host("[::1]:9"), ("::1", "9"));
    }

    /// A one-shot fake proxy: reads the request head, replies `reply`, forwards the head to `tx`.
    async fn fake(reply: &'static str) -> (u16, tokio::sync::oneshot::Receiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let head = read_head(&mut s).await.unwrap();
            let _ = tx.send(head);
            s.write_all(reply.as_bytes()).await.unwrap();
            let mut b = [0u8; 16];
            let n = s.read(&mut b).await.unwrap_or(0);
            let _ = s.write_all(&b[..n]).await; // an echo behind the tunnel
        });
        (port, rx)
    }

    #[tokio::test]
    async fn connect_sends_the_target_and_proxy_credentials() {
        let (port, rx) = fake("HTTP/1.1 200 Connection established\r\n\r\n").await;
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let p = parse_proxy("http://u:p@127.0.0.1:1").unwrap();
        http_connect(
            &mut s,
            "example.com:443",
            p.basic_authorization().as_deref(),
            "t/1",
        )
        .await
        .unwrap();
        let head = rx.await.unwrap();
        assert!(
            head.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(head.contains("\r\nHost: example.com:443\r\n"), "{head}");
        assert!(
            head.contains("\r\nProxy-Authorization: Basic dTpw\r\n"),
            "{head}"
        );
        // the stream is a tunnel afterwards
        s.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
    }

    #[tokio::test]
    async fn a_refused_connect_reports_the_reason_phrase() {
        let (port, _rx) = fake("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let e = http_connect(&mut s, "h:443", None, "t/1")
            .await
            .unwrap_err();
        assert_eq!(e.to_string(), "Forbidden");
        assert!(matches!(e, TunnelError::Refused { .. }));
        let (port, _rx) = fake("garbage\r\n\r\n").await;
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        assert!(matches!(
            http_connect(&mut s, "h:443", None, "t/1")
                .await
                .unwrap_err(),
            TunnelError::Io(_)
        ));
    }

    /// A SOCKS5 server for one connection: expects `methods`, answers `pick`, optionally checks
    /// the user/password, then reports the requested address and echoes.
    async fn socks(
        pick: u8,
        creds: Option<(&'static [u8], &'static [u8])>,
    ) -> (u16, tokio::sync::oneshot::Receiver<(Vec<u8>, String)>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 2];
            s.read_exact(&mut g).await.unwrap();
            let mut methods = vec![0u8; g[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            s.write_all(&[5, pick]).await.unwrap();
            if pick == 2 {
                let mut v = [0u8; 2];
                s.read_exact(&mut v).await.unwrap();
                let mut u = vec![0u8; v[1] as usize];
                s.read_exact(&mut u).await.unwrap();
                let mut pl = [0u8; 1];
                s.read_exact(&mut pl).await.unwrap();
                let mut p = vec![0u8; pl[0] as usize];
                s.read_exact(&mut p).await.unwrap();
                let ok = creds == Some((&u[..], &p[..]));
                s.write_all(&[1, u8::from(!ok)]).await.unwrap();
                if !ok {
                    return;
                }
            }
            let mut h = [0u8; 4];
            s.read_exact(&mut h).await.unwrap();
            let target = match h[3] {
                3 => {
                    let mut n = [0u8; 1];
                    s.read_exact(&mut n).await.unwrap();
                    let mut name = vec![0u8; n[0] as usize];
                    s.read_exact(&mut name).await.unwrap();
                    String::from_utf8(name).unwrap()
                }
                1 => {
                    let mut a = [0u8; 4];
                    s.read_exact(&mut a).await.unwrap();
                    IpAddr::from(a).to_string()
                }
                _ => panic!("atyp {}", h[3]),
            };
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            let _ = tx.send((methods, format!("{target}:{}", u16::from_be_bytes(port))));
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            let mut b = [0u8; 4];
            let n = s.read(&mut b).await.unwrap_or(0);
            let _ = s.write_all(&b[..n]).await;
        });
        (port, rx)
    }

    #[tokio::test]
    async fn socks5_resolves_names_at_the_proxy_and_authenticates() {
        let (port, rx) = socks(0, None).await;
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        socks5_connect(&mut s, "example.com", 443, None)
            .await
            .unwrap();
        assert_eq!(rx.await.unwrap(), (vec![0], "example.com:443".to_string()));
        s.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");

        let (port, rx) = socks(2, Some((b"u", b"p"))).await;
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        socks5_connect(&mut s, "10.1.2.3", 80, Some((b"u", b"p")))
            .await
            .unwrap();
        assert_eq!(rx.await.unwrap(), (vec![0, 2], "10.1.2.3:80".to_string()));

        let (port, _rx) = socks(2, Some((b"u", b"p"))).await;
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let e = socks5_connect(&mut s, "h", 1, Some((b"u", b"bad")))
            .await
            .unwrap_err();
        assert_eq!(e, "authentication failed");
    }

    #[tokio::test]
    async fn the_grpc_relay_serves_one_connection_through_the_tunnel() {
        let (port, rx) = fake("HTTP/1.1 200 OK\r\n\r\n").await;
        let p = parse_proxy(&format!("http://127.0.0.1:{port}")).unwrap();
        let relay = open_grpc_relay(&p, "cp.example:9090", "t/1").await.unwrap();
        assert!(
            rx.await
                .unwrap()
                .starts_with("CONNECT cp.example:9090 HTTP/1.1\r\n")
        );
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", relay))
            .await
            .unwrap();
        c.write_all(b"abcd").await.unwrap();
        let mut b = [0u8; 4];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"abcd");

        // the re-serialised response (sorted headers, `Content-Length` first), quoted with `%q`.
        for (reply, want) in [
            (
                "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                r#"failed to do connect handshake, response: "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n""#,
            ),
            (
                "HTTP/1.1 403 Forbidden\r\nx-b: 2\r\nContent-Length: 3\r\nX-A: 1\r\n\r\nabc",
                r#"failed to do connect handshake, response: "HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\nX-A: 1\r\nX-B: 2\r\n\r\nabc""#,
            ),
            (
                "garbage\r\n\r\n",
                r#"reading server HTTP response: malformed HTTP response "garbage""#,
            ),
            (
                "HTTP/1.1 20 OK\r\n\r\n",
                r#"reading server HTTP response: malformed HTTP status code "20""#,
            ),
            (
                "HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                "failed to do connect handshake, status code: 403 Forbidden",
            ),
        ] {
            let (port, _rx) = fake(reply).await;
            let p = parse_proxy(&format!("http://127.0.0.1:{port}")).unwrap();
            let e = open_grpc_relay(&p, "cp.example:9090", "t/1")
                .await
                .unwrap_err();
            assert_eq!(e, want, "{reply:?}");
        }
        // The proxy hangs up before answering: an unexpected EOF.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let _ = read_head(&mut s).await;
        });
        let p = parse_proxy(&format!("http://127.0.0.1:{port}")).unwrap();
        let e = open_grpc_relay(&p, "cp.example:9090", "t/1")
            .await
            .unwrap_err();
        assert_eq!(e, "reading server HTTP response: unexpected EOF");
        let e = open_grpc_relay(&parse_proxy("http://127.0.0.1:1").unwrap(), "x:1", "t/1")
            .await
            .unwrap_err();
        assert!(e.contains("refused") || e.contains("Connection"), "{e}");
    }
}
