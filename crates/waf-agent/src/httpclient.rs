//! A small HTTP/1.1 client on Pingora's `Connector` (rustls, platform CA store) for the
//! agent's downloads: security data (`fetch-data`), FireHOL lists, good-bot ranges, CAPTCHA
//! siteverify, the SIEM webhook. Follows up to 10 redirects; bodies are read whole up to a cap.
//!
//! Proxies come from the environment (`wafio_control::proxy_env`): `HTTP_PROXY` for
//! `http://` URLs, `HTTPS_PROXY` for `https://` ones, `NO_PROXY`, lower-case spellings, read once.
//! A plain-HTTP request through an `http`/`https` proxy goes out in absolute form with
//! `Proxy-Authorization`; an `https` URL gets a `CONNECT host:port` tunnel (TLS to the target
//! inside it); a `socks5`/`socks5h` proxy is tunnelled by SOCKS5 with the name resolved at the
//! proxy. An `https://` proxy gets TLS first.
//!
//! `wafio_bytetext::url::parse` decides what URL is accepted (control characters, bad host
//! characters, ports and escapes are refused with a `parse "…"` error), the fragment is never
//! sent, an empty port (`http://h:/`) is the default port, and a redirect `Location` is resolved
//! against the request URL (`//host/x` switches host, dot segments).
//!
//! shortcut: an internationalised host name is not converted to punycode.

use std::sync::Arc;
use std::time::Duration;

use pingora::connectors::L4Connect;
use pingora::connectors::http::Connector;
use pingora::http::RequestHeader;
use pingora::protocols::l4::stream::Stream;
use pingora::protocols::l4::virt::{VirtualSockOpt, VirtualSocket, VirtualSocketStream};
use pingora::upstreams::peer::HttpPeer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wafio_bytetext::base64::STANDARD;
use wafio_bytetext::url::{self, unescape_path_segment};
use wafio_control::proxy_env::{self, ProxyConfig, ProxyUrl, TunnelError};

/// A response: status and the (possibly capped) body.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

struct Target {
    tls: bool,
    /// Host name or address without brackets; an IPv6 zone is unescaped (`[fe80::1%25en0]` is
    /// `fe80::1%en0`).
    host: String,
    port: u16,
    /// The port digits as written (`080` stays `080`, empty = the scheme's default): the proxy
    /// decision compares them with `NO_PROXY` as text.
    port_text: String,
    /// `host[:port]` as written, without userinfo (what an absolute-form request line names).
    authority: String,
    /// The `Host` header: the authority without an IPv6 zone.
    host_header: String,
    /// The userinfo as written (before the last `@`); a relative redirect keeps it.
    userinfo: Option<String>,
    /// `Authorization: Basic …` for it.
    basic: Option<String>,
    /// The escaped path (empty when the URL has none).
    path: String,
    /// The raw query; `Some("")` is a trailing `?`.
    query: Option<String>,
}

impl Target {
    fn request_target(&self) -> String {
        let path = if self.path.is_empty() {
            "/"
        } else {
            &self.path
        };
        match &self.query {
            Some(q) => format!("{path}?{q}"),
            None => path.to_string(),
        }
    }
}

/// The `Authorization` value for a URL's userinfo: valid userinfo only, split at the first `:`,
/// percent-decoded and sent as `Basic base64(user ":" password)`. Err is the URL parse failure.
fn basic_authorization(userinfo: &str, url: &str) -> Result<String, String> {
    let fail = |why: &dyn std::fmt::Display| format!("parse {:?}: {why}", mask_password(url));
    if !userinfo
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(&c))
    {
        return Err(fail(&"net/url: invalid userinfo"));
    }
    let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let dec = |s: &str| unescape_path_segment(s.as_bytes()).map_err(|e| fail(&e));
    let mut cred = dec(user)?;
    cred.push(b':');
    cred.extend(dec(pass)?);
    Ok(format!(
        "Basic {}",
        String::from_utf8_lossy(&STANDARD.encode(&cred))
    ))
}

/// `url` as shown in an error, the password written `***`.
fn mask_password(url: &str) -> String {
    let Some(i) = url.find("://").map(|i| i + 3) else {
        return url.to_string();
    };
    let end = url[i..].find(['/', '?']).map_or(url.len(), |e| i + e);
    match url[i..end].rsplit_once('@') {
        Some((ui, _)) if ui.contains(':') => {
            let user = ui.split_once(':').map_or(ui, |(u, _)| u);
            format!("{}{user}:***{}", &url[..i], &url[i + ui.len()..])
        }
        _ => url.to_string(),
    }
}

/// Whether `e` is a URL parse failure: the request is refused and nothing is dialled.
pub fn is_parse_error(e: &str) -> bool {
    e.starts_with("parse ")
}

/// The lower-cased scheme (empty when there is none) and what follows it.
fn split_scheme(raw: &str) -> (String, &str) {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if i > 0 => {}
            b':' if i > 0 => return (raw[..i].to_ascii_lowercase(), &raw[i + 1..]),
            _ => break,
        }
    }
    (String::new(), raw)
}

/// Cuts the query before looking at the authority: `(rest, query)`, `Some("")` for a lone
/// trailing `?`.
fn split_query(rest: &str) -> (&str, Option<&str>) {
    if rest.ends_with('?') && rest.matches('?').count() == 1 {
        return (&rest[..rest.len() - 1], Some(""));
    }
    match rest.split_once('?') {
        Some((r, q)) => (r, Some(q)),
        None => (rest, None),
    }
}

/// The text is acceptable as a URL: no control character and what `wafio_bytetext::url::parse`
/// accepts (host characters, port, escapes).
fn validate(url: &str, why: impl Fn(&str) -> String) -> Result<(), String> {
    if url.bytes().any(|b| b < b' ' || b == 0x7f) {
        return Err(why("net/url: invalid control character in URL"));
    }
    url::parse(url.as_bytes())
        .map(drop)
        .map_err(|_| why("invalid URL"))
}

fn parse(url: &str) -> Result<Target, String> {
    validate(url, |w| format!("parse {:?}: {w}", mask_password(url)))?;
    let no_fragment = url.split('#').next().unwrap_or(url);
    let (scheme, rest) = split_scheme(no_fragment);
    let tls = match scheme.as_str() {
        "https" => true,
        "http" => false,
        _ => return Err(format!("unsupported protocol scheme {scheme:?}")),
    };
    let (rest, query) = split_query(rest);
    let no_host = || "http: no Host in request URL".to_string();
    let after = rest.strip_prefix("//").ok_or_else(no_host)?;
    let (authority, path) = after.split_at(after.find('/').unwrap_or(after.len()));
    let (userinfo, authority) = match authority.rsplit_once('@') {
        Some((u, a)) => (Some(u), a),
        None => (None, authority),
    };
    if authority.is_empty() {
        return Err(no_host());
    }
    let (host, port) = proxy_env::split_url_host(authority);
    if host.is_empty() {
        return Err(format!("no host in {url:?}"));
    }
    let (host, host_header) = unescape_zone(host, authority);
    let port_text = port.to_string();
    // An empty port (`http://h:/`) is the default one; the digits are valid, the number may not be.
    let port = if port.is_empty() {
        if tls { 443 } else { 80 }
    } else {
        port.parse::<u16>()
            .map_err(|_| format!("dial tcp: address {port}: invalid port"))?
    };
    Ok(Target {
        tls,
        host,
        port,
        port_text,
        authority: authority.to_string(),
        host_header,
        basic: userinfo.map(|u| basic_authorization(u, url)).transpose()?,
        userinfo: userinfo.map(String::from),
        path: encoded_path(path),
        query: query.map(String::from),
    })
}

/// An IP literal with a zone: `fe80::1%25en0` names the zone `en0` (the zone
/// is percent-decoded). Returns the host to dial and the `Host` header's authority, which has no
/// zone.
fn unescape_zone(host: &str, authority: &str) -> (String, String) {
    let Some(i) = host.find("%25").filter(|_| authority.starts_with('[')) else {
        return (host.to_string(), authority.to_string());
    };
    let mut zone = Vec::new();
    let b = &host.as_bytes()[i + 1..];
    let mut k = 0;
    while k < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match b.get(k..k + 3) {
            Some([b'%', h, l]) if hex(*h).is_some() && hex(*l).is_some() => {
                zone.push((hex(*h).unwrap_or(0) * 16 + hex(*l).unwrap_or(0)) as u8);
                k += 3;
            }
            _ => {
                zone.push(b[k]);
                k += 1;
            }
        }
    }
    let mut dial = host[..i].to_string();
    dial.push('%');
    dial.push_str(&String::from_utf8_lossy(&zone[2..]));
    // The header keeps everything but the zone: `[fe80::1%25en0]:80` -> `[fe80::1]:80`.
    let header = authority.find("%25").map_or_else(
        || authority.to_string(),
        |z| match authority[z..].find(']') {
            Some(e) => format!("{}{}", &authority[..z], &authority[z + e..]),
            None => authority.to_string(),
        },
    );
    (dial, header)
}

/// Whether `c` must be escaped in a path.
fn should_escape_path(c: u8) -> bool {
    !(c.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@".contains(&c))
}

/// The escaped path for a path written `raw`: the text itself when it is a valid encoding,
/// else the decoded path escaped again.
fn encoded_path(raw: &str) -> String {
    let valid = raw
        .bytes()
        .all(|c| b"!$&'()*+,;=:@[]%".contains(&c) || !should_escape_path(c));
    if valid {
        return raw.to_string();
    }
    let decoded = unescape_path_segment(raw.as_bytes()).unwrap_or_else(|_| raw.as_bytes().to_vec());
    let mut out = String::with_capacity(decoded.len());
    for c in decoded {
        if should_escape_path(c) {
            out.push_str(&format!("%{c:02X}"));
        } else {
            out.push(c as char);
        }
    }
    out
}

/// Resolves dot segments (RFC 3986 §5.2.4) on an already-escaped path.
fn remove_dot_segments(base: &str, reference: &str) -> String {
    let full = if reference.is_empty() {
        base.to_string()
    } else if !reference.starts_with('/') {
        let i = base.rfind('/').map_or(0, |i| i + 1);
        format!("{}{reference}", &base[..i])
    } else {
        reference.to_string()
    };
    if full.is_empty() {
        return String::new();
    }
    let mut dst = String::from("/");
    let (mut first, mut found, mut remaining, mut elem) = (true, true, full.as_str(), "");
    while found {
        let (e, r) = match remaining.split_once('/') {
            Some((e, r)) => (e, r),
            None => {
                found = false;
                (remaining, "")
            }
        };
        (elem, remaining) = (e, r);
        if elem == "." {
            first = false;
            continue;
        }
        if elem == ".." {
            let kept = &dst[1..];
            dst = match kept.rfind('/') {
                Some(i) => format!("/{}", &kept[..i]),
                None => {
                    first = true;
                    "/".to_string()
                }
            };
        } else {
            if !first {
                dst.push('/');
            }
            dst.push_str(elem);
            first = false;
        }
    }
    if elem == "." || elem == ".." {
        dst.push('/');
    }
    // An initial '/' was written, but there must not be two.
    if dst.len() > 1 && dst.as_bytes()[1] == b'/' {
        dst.remove(0);
    }
    dst
}

/// The redirect target of `location` relative to `base` (reference resolution). Err is the
/// "failed to parse Location header" error.
fn resolve(base: &Target, location: &str) -> Result<String, String> {
    validate(location, |w| {
        format!("failed to parse Location header {location:?}: {w}")
    })?;
    let loc = location.split('#').next().unwrap_or(location);
    let (scheme, rest) = split_scheme(loc);
    let (rest, query) = split_query(rest);
    let net_path = (!scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//");
    let (authority, path) = if net_path {
        let after = &rest[2..];
        after.split_at(after.find('/').unwrap_or(after.len()))
    } else {
        ("", rest)
    };
    let out_scheme = if scheme.is_empty() {
        if base.tls { "https" } else { "http" }
    } else {
        scheme.as_str()
    };
    let query_part = |q: Option<&str>| q.map_or(String::new(), |q| format!("?{q}"));
    if !scheme.is_empty() && !net_path && !path.starts_with('/') {
        return Ok(format!("{scheme}:{rest}")); // opaque: the next hop reports the scheme or the host
    }
    if !scheme.is_empty() || !authority.is_empty() {
        // absoluteURI or net_path
        let p = remove_dot_segments(&encoded_path(path), "");
        return Ok(format!(
            "{out_scheme}://{authority}{p}{}",
            query_part(query)
        ));
    }
    // abs_path or rel_path: the base's userinfo and host
    let query = if path.is_empty() && query.is_none() {
        base.query.as_deref().filter(|q| !q.is_empty())
    } else {
        query
    };
    let ui = base
        .userinfo
        .as_ref()
        .map_or(String::new(), |u| format!("{u}@"));
    let p = remove_dot_segments(&base.path, &encoded_path(path));
    Ok(format!(
        "{out_scheme}://{ui}{}{p}{}",
        base.authority,
        query_part(query)
    ))
}

/// A request body with its `Content-Type`.
type Body<'a> = Option<(&'a str, &'a [u8])>;

const FORM: &str = "application/x-www-form-urlencoded";

/// What [`request_with`] sends beyond a plain GET/POST, and how it reads the answer.
#[derive(Clone, Copy, Debug)]
pub struct RequestOptions<'a> {
    /// Request body and its `Content-Type`.
    pub body: Body<'a>,
    /// Extra request headers.
    pub headers: &'a [(&'a str, &'a str)],
    /// Follow redirects (up to 10). With false a 3xx answer is returned as it is, which keeps
    /// credentials from following a redirect.
    pub follow: bool,
    /// The answer body is at most this long.
    pub cap: usize,
    /// A longer body is cut at `cap` instead of being an error.
    pub truncate: bool,
    /// One deadline for the whole exchange.
    pub timeout: Duration,
}

// ── dialling ────────────────────────────────────────────────────────────────────────────────

/// How a request reaches its server.
struct Plan {
    peer: HttpPeer,
    /// The request line carries the absolute URI (plain HTTP through an HTTP proxy).
    absolute: bool,
    /// `Proxy-Authorization` for that proxy.
    proxy_auth: Option<String>,
}

/// `host:port` resolved by the system (blocking lookup off the runtime).
async fn lookup(host: &str, port: u16, what: &'static str) -> Result<std::net::SocketAddr, String> {
    let addr = proxy_env::format_host_port(host, &port.to_string());
    let host = host.to_string();
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        addr.to_socket_addrs()
            .map_err(|e| format!("{what}: lookup {host}: {e}"))?
            .next()
            .ok_or_else(|| format!("{what}: lookup {host}: no such host"))
    })
    .await
    .map_err(|e| e.to_string())?
}

fn peer(addr: std::net::SocketAddr, tls: bool, sni: &str) -> HttpPeer {
    let mut peer = HttpPeer::new(addr, tls, sni.to_string());
    peer.options.connection_timeout = Some(Duration::from_secs(30));
    peer.options.total_connection_timeout = Some(Duration::from_secs(30));
    peer
}

async fn plan(t: &Target, ua: &str, proxies: &ProxyConfig) -> Result<Plan, String> {
    let scheme = if t.tls { "https" } else { "http" };
    let Some(p) = proxies.proxy_for(scheme, &t.host, &t.port_text)? else {
        let addr = lookup(&t.host, t.port, "dial tcp").await?;
        return Ok(Plan {
            peer: peer(addr, t.tls, &t.host),
            absolute: false,
            proxy_auth: None,
        });
    };
    let socks = matches!(p.scheme.as_str(), "socks5" | "socks5h");
    if !socks && !t.tls {
        // The first hop is the proxy, the request names the whole URI.
        let port = p
            .port
            .parse()
            .unwrap_or(if p.scheme == "https" { 443 } else { 80 });
        let addr = lookup(&p.host, port, "dial tcp")
            .await
            .map_err(|e| format!("proxyconnect tcp: {e}"))?;
        return Ok(Plan {
            peer: peer(addr, p.scheme == "https", &p.host),
            absolute: true,
            proxy_auth: p.basic_authorization(),
        });
    }
    // A tunnel to the target (SOCKS5, or CONNECT for https): opened here, handed to Pingora as the
    // connection it then runs TLS over.
    let stream = dial_tunnel(&p, &t.host, t.port, ua).await?;
    let mut peer = peer(([0, 0, 0, 0], 0).into(), t.tls, &t.host);
    peer.options.custom_l4 = Some(Arc::new(Tunnel(std::sync::Mutex::new(Some(stream)))));
    Ok(Plan {
        peer,
        absolute: false,
        proxy_auth: None,
    })
}

/// The stream a tunnel opened, given to Pingora's connector once.
struct Tunnel(std::sync::Mutex<Option<Stream>>);

impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tunnel")
    }
}

#[async_trait::async_trait]
impl L4Connect for Tunnel {
    async fn connect(
        &self,
        _: &pingora::protocols::l4::socket::SocketAddr,
    ) -> pingora::Result<Stream> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| {
                pingora::Error::explain(pingora::ErrorType::ConnectError, "proxy tunnel used twice")
            })
    }
}

/// A TLS (or plain) proxy connection as a Pingora virtual socket.
struct Wrap<S>(S);

impl<S> std::fmt::Debug for Wrap<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyConnection")
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Wrap<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Wrap<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> VirtualSocket for Wrap<S> {
    fn set_socket_option(&self, _: VirtualSockOpt) -> std::io::Result<()> {
        Ok(())
    }
}

/// TLS to an `https://` proxy with the platform roots (before CONNECT).
async fn tls_to_proxy(
    tcp: tokio::net::TcpStream,
    host: &str,
) -> Result<pingora::tls::ClientTlsStream<tokio::net::TcpStream>, String> {
    use pingora::tls::{ClientConfig, RootCertStore, ServerName, TlsConnector, version};
    pingora::tls::install_default_crypto_provider();
    let mut roots = RootCertStore::empty();
    pingora::tls::load_platform_certs_incl_env_into_store(&mut roots).map_err(|e| e.to_string())?;
    let config = ClientConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())
}

/// Opens the connection to `host:port` through `p`: SOCKS5 or `CONNECT`, over TLS first when
/// the proxy is an `https://` one.
async fn dial_tunnel(p: &ProxyUrl, host: &str, port: u16, ua: &str) -> Result<Stream, String> {
    let socks = matches!(p.scheme.as_str(), "socks5" | "socks5h");
    let proxy_addr = p.http_address();
    let tcp = tokio::net::TcpStream::connect(&proxy_addr)
        .await
        .map_err(|e| format!("proxyconnect tcp: dial tcp {proxy_addr}: {e}"))?;
    let target = proxy_env::format_host_port(host, &port.to_string());
    async fn open<S: AsyncRead + AsyncWrite + Unpin>(
        io: &mut S,
        socks: bool,
        p: &ProxyUrl,
        (host, port, target): (&str, u16, &str),
        proxy_addr: &str,
        ua: &str,
    ) -> Result<(), String> {
        if socks {
            let auth = p.user.as_ref().map(|(u, pw)| (u.as_slice(), pw.as_slice()));
            return proxy_env::socks5_connect(io, host, port, auth)
                .await
                .map_err(|e| format!("socks connect tcp {proxy_addr}->{target}: {e}"));
        }
        proxy_env::http_connect(io, target, p.basic_authorization().as_deref(), ua)
            .await
            .map_err(|e: TunnelError| e.to_string())
    }
    let t = (host, port, target.as_str());
    if p.scheme == "https" {
        let mut tls = tls_to_proxy(tcp, &p.host)
            .await
            .map_err(|e| format!("proxyconnect tcp: {e}"))?;
        open(&mut tls, socks, p, t, &proxy_addr, ua).await?;
        Ok(VirtualSocketStream::new(Box::new(Wrap(tls))).into())
    } else {
        let mut tcp = tcp;
        open(&mut tcp, socks, p, t, &proxy_addr, ua).await?;
        Ok(tcp.into())
    }
}

/// One request (no redirects).
async fn once(
    method: &str,
    url: &str,
    ua: &str,
    o: &RequestOptions<'_>,
    proxies: &ProxyConfig,
    deadline: tokio::time::Instant,
    in_body: &std::sync::atomic::AtomicBool,
) -> Result<(u16, Option<String>, Vec<u8>), String> {
    let (body, headers, cap) = (o.body, o.headers, o.cap);
    let t = parse(url)?;
    let plan = plan(&t, ua, proxies).await?;
    let connector = Connector::new(None);
    let (mut s, _) = connector
        .get_http_session(&plan.peer)
        .await
        .map_err(|e| e.to_string())?;
    // Whatever is left of the one deadline the whole exchange shares.
    let timeout = deadline
        .saturating_duration_since(tokio::time::Instant::now())
        .max(Duration::from_millis(1));
    s.set_read_timeout(Some(timeout));
    s.set_write_timeout(Some(timeout));
    let uri = t.request_target();
    let target = if plan.absolute {
        format!("http://{}{uri}", t.authority)
    } else {
        uri
    };
    let mut req =
        RequestHeader::build(method, target.as_bytes(), None).map_err(|e| e.to_string())?;
    let _ = req.insert_header("Host", t.host_header.as_str());
    let _ = req.insert_header("User-Agent", ua);
    let _ = req.insert_header("Accept-Encoding", "identity");
    let _ = req.insert_header("Connection", "close");
    if let Some((content_type, body)) = body {
        let _ = req.insert_header("Content-Type", content_type);
        let _ = req.insert_header("Content-Length", body.len().to_string());
    }
    // Before the caller's headers, so an `Authorization` the caller sends wins.
    if let Some(a) = &t.basic {
        let _ = req.insert_header("Authorization", a.as_str());
    }
    if let Some(a) = &plan.proxy_auth {
        let _ = req.insert_header("Proxy-Authorization", a.as_str());
    }
    for (k, v) in headers {
        let _ = req.insert_header(k.to_string(), *v);
    }
    s.write_request_header(Box::new(req))
        .await
        .map_err(|e| e.to_string())?;
    if let Some((_, body)) = body {
        s.write_request_body(bytes::Bytes::copy_from_slice(body), true)
            .await
            .map_err(|e| e.to_string())?;
    }
    s.finish_request_body().await.map_err(|e| e.to_string())?;
    s.read_response_header().await.map_err(|e| e.to_string())?;
    let (status, location) = {
        let h = s.response_header().ok_or("no response header")?;
        (
            h.status.as_u16(),
            h.headers
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
        )
    };
    in_body.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut body = Vec::new();
    if method != "HEAD" {
        while let Some(chunk) = s.read_response_body().await.map_err(|e| e.to_string())? {
            body.extend_from_slice(&chunk);
            if body.len() > cap {
                if o.truncate {
                    body.truncate(cap);
                    break;
                }
                return Err(format!("response body larger than {cap} bytes"));
            }
        }
    }
    s.shutdown().await;
    Ok((status, location, body))
}

/// `method` on `url`, following redirects (at most 10 requests; 301/302/303 turn any method
/// but GET and HEAD into a body-less GET, 307/308 keep both).
pub async fn request(
    method: &str,
    url: &str,
    ua: &str,
    form: Option<&[u8]>,
    cap: usize,
    timeout: Duration,
) -> Result<Response, String> {
    let body = form.map(|f| (FORM, f));
    request_with(
        method,
        url,
        ua,
        &RequestOptions {
            body,
            headers: &[],
            follow: true,
            cap,
            truncate: false,
            timeout,
        },
    )
    .await
}

/// `request` with the body, headers and redirect policy of `opts`.
pub async fn request_with(
    method: &str,
    url: &str,
    ua: &str,
    opts: &RequestOptions<'_>,
) -> Result<Response, String> {
    request_via(method, url, ua, opts, proxy_env::global()).await
}

/// `request_with` with an explicit proxy configuration (the process one is read from the
/// environment, once): what the tests that need a proxy of their own call.
pub async fn request_via(
    method: &str,
    url: &str,
    ua: &str,
    opts: &RequestOptions<'_>,
    proxies: &ProxyConfig,
) -> Result<Response, String> {
    let mut url = url.to_string();
    let mut method = method.to_string();
    // One deadline for the whole exchange: every redirect and the body.
    let deadline = tokio::time::Instant::now() + opts.timeout;
    // The reported method is the first request's, whatever a redirect turned it into.
    let op = method_text(&method);
    let mut o = *opts;
    // The URL of the request that was answered last.
    let mut last = url.clone();
    for _ in 0..10 {
        let in_body = std::sync::atomic::AtomicBool::new(false);
        let fut = once(&method, &url, ua, &o, proxies, deadline, &in_body);
        // The connection's own read timeout is the time left to the same deadline, so either timer can fire first.
        // An error that arrives at or after the deadline is the deadline, whichever one reported it.
        let outcome = match tokio::time::timeout_at(deadline, fut).await {
            Ok(Err(_)) if tokio::time::Instant::now() >= deadline => Err(()),
            Ok(r) => Ok(r),
            Err(_) => Err(()),
        };
        let (status, location, body) = match outcome {
            Ok(r) => r?,
            // The body read reports the bare cause; before that the error names the method and URL.
            Err(()) if in_body.load(std::sync::atomic::Ordering::Relaxed) => {
                return Err(
                    "context deadline exceeded (Client.Timeout or context cancellation while reading body)"
                        .into(),
                );
            }
            Err(()) => {
                return Err(format!(
                    "{op} {:?}: context deadline exceeded (Client.Timeout exceeded while awaiting headers)",
                    mask_password(&url)
                ));
            }
        };
        last.clone_from(&url);
        match (status, location) {
            // A 3xx without a Location (or an empty one) is returned as it is.
            (301 | 302 | 303 | 307 | 308, Some(loc)) if o.follow && !loc.is_empty() => {
                url = resolve(&parse(&url)?, &loc)?;
                // The caller's own headers do not follow a redirect (none are set for the plain
                // downloads that do follow).
                o.headers = &[];
                if matches!(status, 301..=303) && method != "GET" && method != "HEAD" {
                    method = "GET".into();
                    o.body = None;
                }
            }
            _ => return Ok(Response { status, body }),
        }
    }
    Err(format!(
        "{op} {:?}: stopped after 10 redirects",
        mask_password(&last)
    ))
}

/// The method as the error text prints it (`Get`, `Post`, `Head`).
fn method_text(m: &str) -> String {
    let mut c = m.chars();
    c.next().map_or(String::new(), |f| {
        f.to_uppercase()
            .chain(c.flat_map(char::to_lowercase))
            .collect()
    })
}

/// Blocking GET (runs the request on the current or a temporary runtime).
pub fn get_blocking(
    url: &str,
    ua: &str,
    cap: usize,
    timeout: Duration,
) -> Result<Response, String> {
    block_on(request("GET", url, ua, None, cap, timeout))
}

/// Blocking HEAD.
pub fn head_blocking(url: &str, ua: &str, timeout: Duration) -> Result<Response, String> {
    block_on(request("HEAD", url, ua, None, 0, timeout))
}

/// Blocking form POST.
pub fn post_form_blocking(
    url: &str,
    ua: &str,
    form: &[u8],
    cap: usize,
    timeout: Duration,
) -> Result<Response, String> {
    block_on(request("POST", url, ua, Some(form), cap, timeout))
}

pub(crate) fn block_on<T>(f: impl std::future::Future<Output = T>) -> T {
    match tokio::runtime::Handle::try_current() {
        // On a runtime thread (spawn_blocking): drive it there.
        Ok(h) => h.block_on(f),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(f),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parts_and_redirects() {
        let t = parse("https://download.db-ip.com/free/x.mmdb.gz").unwrap();
        assert_eq!(
            (t.tls, t.host.as_str(), t.port, t.request_target().as_str()),
            (true, "download.db-ip.com", 443, "/free/x.mmdb.gz")
        );
        let t = parse("http://127.0.0.1:8080?a=1").unwrap();
        assert_eq!((t.port, t.request_target().as_str()), (8080, "/?a=1"));
        let t = parse("http://[::1]:81/p").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("::1", 81));
        assert!(parse("ftp://x").is_err());
        let base = parse("https://h/a/b").unwrap();
        assert_eq!(resolve(&base, "/c").unwrap(), "https://h/c");
        assert_eq!(resolve(&base, "c").unwrap(), "https://h/a/c");
        assert_eq!(resolve(&base, "http://o/x").unwrap(), "http://o/x");
    }

    #[test]
    fn get_and_redirect_against_a_local_server() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for (i, s) in l.incoming().flatten().enumerate().take(2) {
                let mut s = s;
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                if i == 0 {
                    assert!(req.starts_with("GET /first HTTP/1.1"), "{req}");
                    assert!(req.contains("User-Agent: t/1"), "{req}");
                    let _ = s.write_all(
                        b"HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\n\r\n",
                    );
                } else {
                    assert!(req.starts_with("GET /second"), "{req}");
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
                }
            }
        });
        let r = get_blocking(
            &format!("http://127.0.0.1:{port}/first"),
            "t/1",
            1 << 20,
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
    }

    /// A local server: answers connection `i` with `reply(i, port)` and sends the request
    /// head it read to the channel.
    fn serve(
        reply: impl Fn(usize, u16) -> String + Send + 'static,
    ) -> (u16, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for (i, s) in l.incoming().flatten().enumerate() {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = s.write_all(reply(i, port).as_bytes());
            }
        });
        (port, rx)
    }

    /// The values of header `name` in a request head.
    fn header<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
        head.lines()
            .skip(1)
            .filter_map(|l| l.split_once(": "))
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
            .collect()
    }

    fn get_with(url: &str, headers: &[(&str, &str)]) -> Response {
        block_on(request_with(
            "GET",
            url,
            "t/1",
            &RequestOptions {
                body: None,
                headers,
                follow: true,
                cap: 1 << 20,
                truncate: false,
                timeout: Duration::from_secs(10),
            },
        ))
        .unwrap()
    }

    #[test]
    fn userinfo_parses_escapes_and_empty_parts() {
        let auth = |u: &str| parse(&format!("http://{u}@h/")).unwrap().basic.unwrap();
        assert_eq!(auth("user:pass"), "Basic dXNlcjpwYXNz");
        // Percent-decoded after the split at the first ':'.
        assert_eq!(auth("user:pa%3Ass"), "Basic dXNlcjpwYTpzcw==");
        assert_eq!(auth("tok"), "Basic dG9rOg==");
        assert_eq!(auth(""), "Basic Og==");
        // The last '@' ends the userinfo.
        let t = parse("http://u:p@ss@h:8/x").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("h", 8));
        assert_eq!(t.basic.as_deref(), Some("Basic dTpwQHNz"));
        assert!(parse("http://h/@x").unwrap().basic.is_none());
        // What URL parsing rejects: a character outside the valid userinfo set, a bad escape.
        for bad in ["a b:c", "u:%zz", "%4:x", "\u{e9}:x"] {
            let e = parse(&format!("http://{bad}@h/")).err().unwrap_or_default();
            assert!(is_parse_error(&e), "{bad}: {e}");
        }
        assert!(is_parse_error(&parse("http://h:99x/").err().unwrap()));
        // Not parse errors: the request fails these.
        assert!(!is_parse_error(&parse("ftp://h/").err().unwrap()));
    }

    #[test]
    fn errors_never_show_the_password() {
        assert_eq!(
            mask_password("https://u:secret@h/p?q=@"),
            "https://u:***@h/p?q=@"
        );
        assert_eq!(mask_password("https://tok@h/p"), "https://tok@h/p");
        assert_eq!(mask_password("https://h/a@b:c"), "https://h/a@b:c");
        let e = parse("http://u:s%zzret@h/").err().unwrap();
        assert!(!e.contains("s%zzret") && e.contains("u:***@h"), "{e}");
    }

    #[test]
    fn relative_redirect_keeps_the_userinfo() {
        let base = parse("https://u:p@h/a/b").unwrap();
        assert_eq!(resolve(&base, "c").unwrap(), "https://u:p@h/a/c");
        assert_eq!(resolve(&base, "/c").unwrap(), "https://u:p@h/c");
        assert_eq!(resolve(&base, "http://o/x").unwrap(), "http://o/x");
    }

    /// The client sends `Authorization: Basic` for the userinfo of the URL, again on a relative
    /// hop and not after an absolute one without it; the Host header never has it.
    #[test]
    fn userinfo_is_sent_as_basic_auth() {
        let (port, seen) = serve(|i, port| match i {
            0 => "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n".into(),
            1 => format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/abs\r\nContent-Length: 0\r\n\r\n"
            ),
            _ => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into(),
        });
        let r = get_with(&format!("http://user:pass@127.0.0.1:{port}/first"), &[]);
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        let heads: Vec<String> = seen.try_iter().collect();
        assert_eq!(heads.len(), 3);
        for (h, path) in heads.iter().zip(["/first", "/next", "/abs"]) {
            assert!(h.starts_with(&format!("GET {path} HTTP/1.1")), "{h}");
            assert_eq!(header(h, "host"), [format!("127.0.0.1:{port}")], "{h}");
        }
        for h in &heads[..2] {
            assert_eq!(header(h, "authorization"), ["Basic dXNlcjpwYXNz"], "{h}");
        }
        assert!(
            header(&heads[2], "authorization").is_empty(),
            "{}",
            heads[2]
        );
    }

    /// An `Authorization` the caller sets wins (Basic is set only when there is none); a URL
    /// without userinfo sends none.
    #[test]
    fn caller_authorization_wins_and_none_without_userinfo() {
        let ok = |_, _| "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string();
        let (port, seen) = serve(ok);
        get_with(
            &format!("http://u:p@127.0.0.1:{port}/"),
            &[("Authorization", "Bearer x")],
        );
        assert_eq!(header(&seen.recv().unwrap(), "authorization"), ["Bearer x"]);
        let (port, seen) = serve(ok);
        get_with(&format!("http://127.0.0.1:{port}/"), &[]);
        assert!(header(&seen.recv().unwrap(), "authorization").is_empty());
    }

    // ── URL handling ────────────────────────────────────────────────────────────────────────

    /// Reference resolution of RFC 3986 §5.4.
    #[test]
    fn redirect_targets_resolve_against_the_base_url() {
        let base = parse("http://a/b/c/d;p?q").unwrap();
        for (loc, want) in [
            ("g", "http://a/b/c/g"),
            ("./g", "http://a/b/c/g"),
            ("g/", "http://a/b/c/g/"),
            ("/g", "http://a/g"),
            ("//g", "http://g"),
            ("//g/x", "http://g/x"),
            ("?y", "http://a/b/c/d;p?y"),
            ("g?y", "http://a/b/c/g?y"),
            ("#s", "http://a/b/c/d;p?q"),
            ("g#s", "http://a/b/c/g"),
            ("", "http://a/b/c/d;p?q"),
            (".", "http://a/b/c/"),
            ("./", "http://a/b/c/"),
            ("..", "http://a/b/"),
            ("../", "http://a/b/"),
            ("../g", "http://a/b/g"),
            ("../..", "http://a/"),
            ("../../", "http://a/"),
            ("../../g", "http://a/g"),
            ("../../../g", "http://a/g"),
            ("/./g", "http://a/g"),
            ("/../g", "http://a/g"),
            ("g.", "http://a/b/c/g."),
            ("..g", "http://a/b/c/..g"),
            ("./../g", "http://a/b/g"),
            ("./g/.", "http://a/b/c/g/"),
            ("g/./h", "http://a/b/c/g/h"),
            ("g/../h", "http://a/b/c/h"),
            ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
            ("g?y/./x", "http://a/b/c/g?y/./x"),
            ("https://o/x/../y", "https://o/y"),
        ] {
            assert_eq!(resolve(&base, loc).unwrap(), want, "{loc:?}");
        }
        // a host-less base path, an https base, a query-only reference with a forced empty query
        let base = parse("https://h").unwrap();
        assert_eq!(resolve(&base, "x").unwrap(), "https://h/x");
        assert_eq!(
            resolve(&base, "//o.example/p").unwrap(),
            "https://o.example/p"
        );
        assert_eq!(
            resolve(&parse("http://h/p?").unwrap(), "").unwrap(),
            "http://h/p"
        );
        assert!(resolve(&base, "http://a b/").is_err());
        // a byte a path may not hold unescaped is escaped again
        assert_eq!(resolve(&base, "/x\\y").unwrap(), "https://h/x%5Cy");
        let e = resolve(&base, "/a\u{7f}").unwrap_err();
        assert!(e.starts_with("failed to parse Location header"), "{e}");
    }

    #[test]
    fn the_fragment_is_never_sent_and_an_empty_port_is_the_default() {
        let t = parse("http://h/x?y=1#frag").unwrap();
        assert_eq!(t.request_target(), "/x?y=1");
        assert_eq!(parse("http://h#frag").unwrap().request_target(), "/");
        assert_eq!(parse("http://h?#frag").unwrap().request_target(), "/?");
        assert_eq!(parse("http://h/a#f/b").unwrap().request_target(), "/a");
        // a fragment may hold what a path may not
        assert_eq!(parse("http://h/#a b").unwrap().request_target(), "/");

        let t = parse("http://h:/").unwrap();
        assert_eq!((t.port, t.authority.as_str()), (80, "h:"));
        let t = parse("https://h:/p").unwrap();
        assert_eq!((t.port, t.host.as_str()), (443, "h"));
        let t = parse("http://[::1]:/").unwrap();
        assert_eq!((t.port, t.host.as_str()), (80, "::1"));
        // the digits are a valid URL, the number is not for the dialler
        let e = parse("http://h:99999/").err().unwrap();
        assert_eq!(e, "dial tcp: address 99999: invalid port");
        assert!(!is_parse_error(&e));
        // the Host header is the authority as written
        assert_eq!(parse("http://u@h:80/").unwrap().authority, "h:80");
    }

    #[test]
    fn control_characters_and_bad_hosts_are_parse_errors() {
        for bad in [
            "http://h/\n",
            "http://h/a\r\nHost: x",
            "http://h/\u{7f}",
            "http://h\u{0}/",
            "http://a b/",
            "http://h\\x/",
            "http://ex{ample.com/",
            "http://h^/",
            "http://%41/",
            "http://h:80a/",
            "http://[::1/",
            "http://a:1:2/",
            "http://h/%zz",
        ] {
            let e = parse(bad).err().unwrap_or_default();
            assert!(is_parse_error(&e), "{bad:?}: {e:?}");
        }
        let e = parse("http://h/\n").err().unwrap();
        assert!(e.contains("invalid control character"), "{e}");
        // not parse errors: refused when the request is made
        for (u, why) in [
            ("ftp://h/", "unsupported protocol scheme \"ftp\""),
            ("h/x", "unsupported protocol scheme \"\""),
            ("http:foo", "http: no Host in request URL"),
            ("http:///x", "http: no Host in request URL"),
            ("HTTP://h/", ""),
        ] {
            match parse(u) {
                Ok(_) => assert!(why.is_empty(), "{u}"),
                Err(e) => assert_eq!(e, why, "{u}"),
            }
        }
        // what the request line carries: valid encodings stay, the rest is escaped again
        assert_eq!(
            parse("http://h/a(b)%20c").unwrap().request_target(),
            "/a(b)%20c"
        );
        assert_eq!(parse("http://h/a b").unwrap().request_target(), "/a%20b");
        assert_eq!(
            parse("http://h/\u{e9}").unwrap().request_target(),
            "/%C3%A9"
        );
        assert_eq!(parse("http://h/a%3Fb").unwrap().request_target(), "/a%3Fb");
    }

    /// A redirect to `//host/path` leaves for that host; the first hop's own path is not reused.
    #[test]
    fn a_protocol_relative_redirect_switches_host() {
        let (b, seen_b) = serve(|_, _| "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into());
        let (a, seen_a) = serve(move |_, _| {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: //127.0.0.1:{b}/x?y=1#f\r\nContent-Length: 0\r\n\r\n"
            )
        });
        let r = get_with(&format!("http://127.0.0.1:{a}/first"), &[]);
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        assert!(seen_a.recv().unwrap().starts_with("GET /first HTTP/1.1"));
        let h = seen_b.recv().unwrap();
        assert!(h.starts_with("GET /x?y=1 HTTP/1.1"), "{h}");
        assert_eq!(header(&h, "host"), [format!("127.0.0.1:{b}")]);
    }

    /// The client stops after 10 requests, treats an empty `Location` as none, and only turns 301/302/303
    /// on methods other than GET and HEAD into GET.
    #[test]
    fn redirect_rules_cap_hops_and_rewrite_methods() {
        let (port, seen) = serve(|i, _| {
            let _ = i;
            "HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n".into()
        });
        let e = block_on(request(
            "GET",
            &format!("http://127.0.0.1:{port}/"),
            "t/1",
            None,
            1024,
            Duration::from_secs(10),
        ))
        .unwrap_err();
        // The first request's method and the URL of the last request answered.
        assert_eq!(
            e,
            format!("Get \"http://127.0.0.1:{port}/again\": stopped after 10 redirects")
        );
        assert_eq!(seen.try_iter().count(), 10, "ten requests, not eleven");

        let (port, seen) =
            serve(|_, _| "HTTP/1.1 302 Found\r\nLocation: \r\nContent-Length: 0\r\n\r\n".into());
        let r = get_with(&format!("http://127.0.0.1:{port}/"), &[]);
        assert_eq!(r.status, 302, "an empty Location is no redirect");
        assert_eq!(seen.try_iter().count(), 1);

        let (port, seen) = serve(|i, _| match i {
            0 => "HTTP/1.1 303 See Other\r\nLocation: /n\r\nContent-Length: 0\r\n\r\n".into(),
            _ => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into(),
        });
        block_on(request(
            "HEAD",
            &format!("http://127.0.0.1:{port}/"),
            "t/1",
            None,
            0,
            Duration::from_secs(10),
        ))
        .unwrap();
        let heads: Vec<String> = seen.try_iter().collect();
        assert!(heads[0].starts_with("HEAD /"), "{}", heads[0]);
        assert!(
            heads[1].starts_with("HEAD /n"),
            "a 303 keeps HEAD: {}",
            heads[1]
        );
    }

    /// The timeout is one deadline for the whole exchange, redirects included, and its text
    /// says what was being waited for.
    #[test]
    fn one_deadline_covers_every_hop_and_the_body() {
        use std::io::{Read, Write};
        // Every hop answers after 250 ms with a redirect to itself: ten would take 2.5 s.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut s = s;
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf);
                    std::thread::sleep(Duration::from_millis(250));
                    let _ = s.write_all(
                        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n",
                    );
                });
            }
        });
        let t = std::time::Instant::now();
        let e = block_on(request(
            "POST",
            &format!("http://127.0.0.1:{port}/"),
            "t/1",
            Some(&b"a=b"[..]),
            1024,
            Duration::from_millis(900),
        ))
        .unwrap_err();
        assert!(
            t.elapsed() < Duration::from_millis(1800),
            "{:?}",
            t.elapsed()
        );
        assert!(e.starts_with("Post \"http://127.0.0.1:"), "{e}");
        assert!(
            e.ends_with(
                ": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"
            ),
            "{e}"
        );
        // A body that never ends: the bare cause, as the body read reports it.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc");
                std::thread::sleep(Duration::from_secs(3));
            }
        });
        let e = block_on(request(
            "GET",
            &format!("http://127.0.0.1:{port}/"),
            "t/1",
            None,
            1024,
            Duration::from_millis(500),
        ))
        .unwrap_err();
        assert_eq!(
            e,
            "context deadline exceeded (Client.Timeout or context cancellation while reading body)"
        );
    }

    /// URL parsing unescapes an IPv6 zone, the `Host` header drops it, and the port digits stay as
    /// written for the `NO_PROXY` comparison.
    #[test]
    fn ipv6_zone_and_port_text_parse_in_urls() {
        let t = parse("http://[fe80::1%25en0]:8080/x").unwrap();
        assert_eq!(t.host, "fe80::1%en0");
        assert_eq!(t.authority, "[fe80::1%25en0]:8080");
        assert_eq!(t.host_header, "[fe80::1]:8080");
        assert_eq!((t.port, t.port_text.as_str()), (8080, "8080"));
        let t = parse("http://[fe80::1%25en%30]/x").unwrap();
        assert_eq!(
            (t.host.as_str(), t.host_header.as_str()),
            ("fe80::1%en0", "[fe80::1]")
        );
        let t = parse("http://h:080/").unwrap();
        assert_eq!((t.port, t.port_text.as_str()), (80, "080"));
        assert_eq!(parse("http://h/").unwrap().port_text, "");
        // `h:080` is not `h:80` to NO_PROXY: the text decides.
        let pc = ProxyConfig::from_parts("http://127.0.0.1:3128", "", "h:80", false);
        assert!(pc.proxy_for("http", "h", "080").unwrap().is_some());
        assert!(pc.proxy_for("http", "h", "80").unwrap().is_none());
        assert!(
            pc.proxy_for("http", "h", "").unwrap().is_none(),
            "the default port is 80"
        );
    }

    // ── proxies ──────────────────────────────────────────────────────────────────────────────

    fn proxies(http: &str, https: &str, no_proxy: &str) -> ProxyConfig {
        ProxyConfig::from_parts(http, https, no_proxy, false)
    }

    fn get_via(url: &str, pc: &ProxyConfig) -> Result<Response, String> {
        block_on(request_via(
            "GET",
            url,
            "t/1",
            &RequestOptions {
                body: None,
                headers: &[],
                follow: true,
                cap: 1 << 20,
                truncate: false,
                timeout: Duration::from_secs(10),
            },
            pc,
        ))
    }

    /// `HTTP_PROXY`: the request goes to the proxy in absolute form with `Proxy-Authorization`;
    /// the target name is never resolved here (`.invalid` cannot be).
    #[test]
    fn http_through_an_http_proxy_names_the_whole_uri() {
        let (port, seen) = serve(|_, _| "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into());
        let pc = proxies(&format!("http://pu:pp@127.0.0.1:{port}"), "", "");
        let r = get_via("http://example.invalid:8081/a/b?x=1#frag", &pc).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        let h = seen.recv().unwrap();
        assert!(
            h.starts_with("GET http://example.invalid:8081/a/b?x=1 HTTP/1.1\r\n"),
            "{h}"
        );
        assert_eq!(header(&h, "host"), ["example.invalid:8081"]);
        assert_eq!(header(&h, "proxy-authorization"), ["Basic cHU6cHA="]);
        assert!(header(&h, "authorization").is_empty());
        // the URL's own userinfo is the target's credential, the proxy's is separate
        let (port, seen) = serve(|_, _| "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into());
        let pc = proxies(&format!("127.0.0.1:{port}"), "", "");
        get_via("http://t:s@example.invalid/", &pc).unwrap();
        let h = seen.recv().unwrap();
        assert!(h.starts_with("GET http://example.invalid/ HTTP/1.1"), "{h}");
        assert_eq!(header(&h, "authorization"), ["Basic dDpz"]);
        assert!(header(&h, "proxy-authorization").is_empty());
    }

    /// `HTTPS_PROXY`: an https URL asks for a tunnel with `CONNECT host:port`; the answer's reason
    /// phrase is the error, and no HTTP_PROXY is read for it.
    #[test]
    fn https_asks_the_proxy_for_a_tunnel() {
        let (port, seen) =
            serve(|_, _| "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".into());
        let pc = proxies(
            "http://127.0.0.1:1",
            &format!("http://u:p@127.0.0.1:{port}"),
            "",
        );
        let e = get_via("https://example.invalid/x", &pc).unwrap_err();
        assert_eq!(e, "Forbidden");
        let h = seen.recv().unwrap();
        assert!(
            h.starts_with("CONNECT example.invalid:443 HTTP/1.1\r\n"),
            "{h}"
        );
        assert_eq!(header(&h, "host"), ["example.invalid:443"]);
        assert_eq!(header(&h, "proxy-authorization"), ["Basic dTpw"]);
        assert_eq!(header(&h, "user-agent"), ["t/1"]);
        let e = get_via("https://example.invalid:8443/x", &pc).unwrap_err();
        assert_eq!(e, "Forbidden");
        assert!(
            seen.recv()
                .unwrap()
                .starts_with("CONNECT example.invalid:8443 ")
        );
        // a proxy that is not there is a proxyconnect error
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let pc = proxies("", &format!("http://127.0.0.1:{closed}"), "");
        let e = get_via("https://example.invalid/x", &pc).unwrap_err();
        assert!(
            e.starts_with("proxyconnect tcp: dial tcp 127.0.0.1:"),
            "{e}"
        );
    }

    /// `NO_PROXY` and loopback targets are dialled directly, whatever the proxy variables say.
    #[test]
    fn no_proxy_and_loopback_connect_directly() {
        let (proxy, seen) = serve(|_, _| "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into());
        let pc = proxies(
            &format!("http://127.0.0.1:{proxy}"),
            "",
            "example.invalid, .corp.invalid",
        );
        for url in ["http://example.invalid/", "http://a.corp.invalid/"] {
            let e = get_via(url, &pc).unwrap_err();
            assert!(e.starts_with("dial tcp: lookup "), "{url}: {e}");
        }
        let (port, direct) = serve(|_, _| "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into());
        get_via(&format!("http://127.0.0.1:{port}/p"), &pc).unwrap();
        assert!(direct.recv().unwrap().starts_with("GET /p HTTP/1.1"));
        assert_eq!(seen.try_iter().count(), 0, "the proxy heard nothing");
    }

    /// A SOCKS5 proxy: the tunnel carries the name, the request inside is in origin form.
    #[test]
    fn socks5_proxy_tunnels_and_the_request_is_origin_form() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).unwrap();
            s.write_all(&[5, 0]).unwrap();
            let mut h = [0u8; 4];
            s.read_exact(&mut h).unwrap();
            let mut n = [0u8; 1];
            s.read_exact(&mut n).unwrap();
            let mut name = vec![0u8; n[0] as usize];
            s.read_exact(&mut name).unwrap();
            let mut p = [0u8; 2];
            s.read_exact(&mut p).unwrap();
            tx.send((
                h[3],
                String::from_utf8(name).unwrap(),
                u16::from_be_bytes(p),
            ))
            .unwrap();
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap();
            tx.send((0, String::from_utf8_lossy(&buf[..n]).into_owned(), 0))
                .unwrap();
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        });
        let pc = proxies(&format!("socks5://127.0.0.1:{port}"), "", "");
        let r = get_via("http://example.invalid:8082/s?q=1", &pc).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        assert_eq!(rx.recv().unwrap(), (3, "example.invalid".to_string(), 8082));
        let head = rx.recv().unwrap().1;
        assert!(head.starts_with("GET /s?q=1 HTTP/1.1\r\n"), "{head}");
        assert_eq!(header(&head, "host"), ["example.invalid:8082"]);
    }

    #[test]
    fn a_proxy_value_with_the_cgi_flag_is_refused_for_http_only() {
        let pc = ProxyConfig::from_parts("http://127.0.0.1:1", "", "", true);
        let e = get_via("http://example.invalid/", &pc).unwrap_err();
        assert!(
            e.starts_with("refusing to use HTTP_PROXY value in CGI environment"),
            "{e}"
        );
    }
}
