//! Runtime configuration the binary fills from a WAF bundle, and the route build.
//!
//! The binary decodes the bundle, builds one [`AppAnalysisSetup`] per app (rules JSON →
//! `AnalyzeConfig`, stores carried over from the app's previous executor, custom rules,
//! challenge) and hands the apps to [`crate::Proxy::apply`] as [`AppSpec`]s. Everything that
//! needs Pingora or the FastCGI pool (upstream parsing, timeouts, pools) is built here.

use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::siem::SiemEventSender;
use tokio::sync::Semaphore;
use wafio_agent_io::fastcgi_client::{
    FastCgiConnectionPool, FastCgiDeadlines, parse_upstream_spec,
};
use wafio_agent_io::ip_jail::JailTracker;
use wafio_agent_io::ws_config::{WsAppPolicy, parse_ws_app_policy};
use wafio_agent_pages::challenge::ChallengeSettings;
use wafio_application::AnalyzeConfig;
use wafio_domain::text_helpers::quote;
use wafio_domain::{
    ProxyConfig, is_unlimited, parse_maintenance, parse_proxy_config, strip_path_prefix_fault,
    timeout_or_default_ms,
};

use crate::cert_store::BookChange;
use crate::maintenance::MaintenanceRoute;
use crate::redirect::MainHost;
use crate::static_files::{StaticFolder, StaticSpec};

/// What one app's requests are analysed with. Immutable once applied; a bundle replaces it as
/// a whole.
#[derive(Default)]
pub struct AppAnalysisSetup {
    /// The analysis config, `cache_base_semantic_config` already called.
    pub analyze: AnalyzeConfig,
    /// The challenge settings; `None` = no challenge configured. Prepared
    /// (`finalize_challenge_settings`); the app's falls back to the project's when the app has none
    /// enabled.
    pub challenge: Option<ChallengeSettings>,
    /// The IP jail (`--jail-threshold` …); `None` = L7→XDP jail off.
    pub jail: Option<Arc<JailTracker>>,
    /// The verdicts a webhook receives (`siem.enabled` with a `webhook_url`); `None` = no SIEM.
    pub siem: Option<Arc<dyn SiemEventSender>>,
}

/// One bundle app (the fields the route build reads) plus its executor.
pub struct AppSpec {
    pub app_id: String,
    pub listen_host: String,
    /// 0 = no listener: such an app belongs to a legacy single listener, which `wafio-waf-agent`
    /// never serves; it is accepted and ignored.
    pub listen_port: u16,
    /// `upstream_url`: `http(s)://…`, `unix:/path`, `http://unix:/path:`, `fcgi:…`.
    pub upstream: String,
    /// "block" | "monitor"; anything else is "block".
    pub mode: String,
    /// `proxy_config` JSON as in the bundle; empty = defaults.
    pub proxy_config: Vec<u8>,
    /// The app's own `rules_json` (only its `websocket` block is read here).
    pub rules_json: Vec<u8>,
    pub fcgi_doc_root: String,
    pub fcgi_index: String,
    /// Keep FastCGI connections open between requests (nginx `fastcgi_keep_conn`); off closes
    /// each one after its reply. Read only for an `fcgi:` upstream.
    pub fcgi_keep_conn: bool,
    /// The `maintenance` object of the bundle app; empty = none.
    pub maintenance: Vec<u8>,
    pub analysis: Arc<AppAnalysisSetup>,
    /// The agent serves the app over HTTPS itself (its bundle entry has a `tls` object) and opens
    /// no listener at the bundle's address for it; `None` = only the bundle listener, as before.
    pub tls: Option<TlsSite>,
    /// Compression of the answers the upstream sends whole; `None` = off.
    pub compression: Option<CompressionSpec>,
    /// Files of a folder that the app answers itself; `None` = none.
    pub static_files: Option<StaticSpec>,
}

/// The compression settings of one app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionSpec {
    /// Answers shorter than this go as they are. At most [`MAX_MIN_COMPRESS_BYTES`].
    pub min_bytes: usize,
}

/// The largest `CompressionSpec::min_bytes`: 1 MiB.
pub const MAX_MIN_COMPRESS_BYTES: usize = 1 << 20;

/// One app's HTTPS settings, from the bundle entry of the app.
#[derive(Clone)]
pub struct TlsSite {
    /// `host:port` of the TLS listener (an IPv6 host in brackets); apps naming the same address
    /// share it.
    pub listen: String,
    /// The host names the app answers for: lower case, no port, no trailing dot. SNI and `Host`
    /// are matched against them.
    pub hosts: Vec<String>,
    /// What this apply does to the certificate the book serves for the app: replaces it, leaves
    /// it (the one served before, or nothing), or removes it.
    pub certificate: BookChange,
    /// `host:port` of a plain listener that redirects these hosts to HTTPS once the app has a real
    /// certificate and answers HTTP-01 validations; `None` = no such listener.
    pub redirect_listen: Option<String>,
    /// The main host name: one of `hosts`, lower case. A request under another of the hosts is
    /// redirected to it, on both listeners. `None` = no redirect.
    pub canonical_host: Option<String>,
}

/// Prints no certificate: the entry holds a private key.
impl fmt::Debug for TlsSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSite")
            .field("listen", &self.listen)
            .field("hosts", &self.hosts)
            .field("redirect_listen", &self.redirect_listen)
            .field("canonical_host", &self.canonical_host)
            .finish_non_exhaustive()
    }
}

pub(crate) enum Target {
    Http(HttpTarget),
    Fcgi(Arc<FastCgiConnectionPool>),
}

pub(crate) struct HttpTarget {
    /// "http" | "https".
    pub scheme: &'static str,
    /// "host:port" ("localhost" for a unix socket).
    pub host: String,
    /// `Some(path)` for a unix-socket upstream.
    pub unix: Option<String>,
    /// Resolved per dial with a one-minute DNS cache.
    dns: Mutex<Option<(Instant, SocketAddr)>>,
}

const DNS_CACHE: Duration = Duration::from_secs(60);

impl HttpTarget {
    pub async fn resolve(&self) -> std::io::Result<SocketAddr> {
        if let Some((at, a)) = *self.dns.lock().unwrap_or_else(|e| e.into_inner())
            && at.elapsed() < DNS_CACHE
        {
            return Ok(a);
        }
        let a = tokio::net::lookup_host(self.host.as_str())
            .await?
            .next()
            .ok_or_else(|| std::io::Error::other("no address"))?;
        *self.dns.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), a));
        Ok(a)
    }
}

/// A built route: the app's upstream, limits and analysis setup.
pub struct Route {
    pub(crate) app_id: String,
    pub(crate) upstream: String,
    pub(crate) mode: String,
    pub(crate) proxy_config: ProxyConfig,
    pub(crate) ws: WsAppPolicy,
    /// `Some` while maintenance mode is on for the app, with its pages built.
    pub(crate) maintenance: Option<MaintenanceRoute>,
    pub(crate) analysis: Arc<AppAnalysisSetup>,
    /// The agent is the edge for this app (it terminates TLS): fingerprint headers count only
    /// from a trusted proxy.
    pub(crate) edge: bool,
    /// Where the other host names of the app are sent; `None` = nowhere.
    pub(crate) main_host: Option<MainHost>,
    pub(crate) compression: Option<CompressionSpec>,
    /// The folder that answers `GET` and `HEAD` after the verdict, if the app has one.
    pub(crate) static_files: Option<Arc<StaticFolder>>,
    pub(crate) target: Target,
    /// `timeouts.upstream_ms` resolved (default 30 s); ignored when `upstream_unlimited`.
    pub(crate) upstream_timeout: Duration,
    pub(crate) upstream_unlimited: bool,
    /// `timeouts.connect_ms` (default 3 s when unset or unlimited).
    pub(crate) connect_deadline: Duration,
    /// Upstream connection cap and how long a request waits for a slot.
    pub(crate) connection_slots: Arc<Semaphore>,
    pub(crate) connection_wait: Duration,
    /// How long an idle upstream connection is kept.
    pub(crate) idle_connection_timeout: Duration,
}

impl Route {
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// Whether the route sends the app's other host names to a main host or takes a path prefix
    /// off what the upstream sees.
    pub fn redirects(&self) -> bool {
        self.main_host.is_some() || !self.proxy_config.strip_path_prefix.is_empty()
    }

    /// The HTTP upstream's address (resolved per dial, one-minute DNS cache).
    pub(crate) async fn target_address(&self) -> std::io::Result<SocketAddr> {
        match &self.target {
            Target::Http(t) => t.resolve().await,
            Target::Fcgi(_) => Err(std::io::Error::other("FastCGI route")),
        }
    }

    pub(crate) fn fcgi(&self) -> Option<&Arc<FastCgiConnectionPool>> {
        match &self.target {
            Target::Fcgi(p) => Some(p),
            Target::Http(_) => None,
        }
    }

    /// The inbound header buffer size, never below 16 KiB.
    pub(crate) fn header_buffer_size(&self) -> usize {
        (self.proxy_config.read_buffer_bytes.max(16 * 1024)) as usize
    }

    /// The listener-level settings that cannot change on a running listener.
    pub(crate) fn listener_limits(&self) -> (i64, i64, i64, usize) {
        (
            self.proxy_config.timeouts.read_ms,
            self.proxy_config.timeouts.write_ms,
            self.proxy_config.max_body_bytes,
            self.header_buffer_size(),
        )
    }
}

/// The idle connection timeout: 3 s when unset.
pub fn resolve_idle_timeout(ms: i64) -> Duration {
    Duration::from_millis(if ms <= 0 { 3000 } else { ms as u64 })
}

/// The socket path of a unix-socket upstream (`unix:/path` or `http://unix:/path:`), if it is one.
pub fn unix_socket_path_of_upstream(upstream: &str) -> Option<String> {
    if let Some(p) = upstream.strip_prefix("unix:") {
        let p = p.trim_end_matches(':');
        if !p.is_empty() {
            return Some(p.to_string());
        }
    }
    for prefix in ["http://unix:", "https://unix:"] {
        if let Some(p) = upstream.strip_prefix(prefix) {
            let p = p.trim_end_matches([':', '/']);
            if !p.is_empty() {
                return Some(p.to_string());
            }
        }
    }
    None
}

/// The scheme and host of an `http(s)://` upstream (the default port added).
fn parse_http_upstream(app_id: &str, upstream: &str) -> Result<(&'static str, String), String> {
    let u = wafio_agent_io::url_parse::parse(upstream.as_bytes()).map_err(|e| {
        format!(
            "app {}: parse upstream {}: {e}",
            quote(app_id.as_bytes()),
            quote(upstream.as_bytes())
        )
    })?;
    let scheme = match u.scheme.as_slice() {
        b"http" => "http",
        b"https" => "https",
        s => {
            return Err(format!(
                "app {}: upstream scheme must be http or https (or unix:/path), got {}",
                quote(app_id.as_bytes()),
                quote(s)
            ));
        }
    };
    let mut host = String::from_utf8_lossy(&u.host).into_owned();
    if !host.contains(':') {
        host.push_str(if scheme == "https" { ":443" } else { ":80" });
    }
    Ok((scheme, host))
}

/// Validates the upstream and builds its client (HTTP target or FastCGI pool).
pub fn build_route(app: &AppSpec) -> Result<Route, String> {
    let upstream = app.upstream.trim();
    if upstream.is_empty() {
        return Err(format!(
            "app {}: empty upstream",
            quote(app.app_id.as_bytes())
        ));
    }
    let mode = match app.mode.trim().to_lowercase().as_str() {
        "monitor" => "monitor",
        _ => "block",
    };
    let pxy = parse_proxy_config(&app.proxy_config).map_err(|e| {
        format!(
            "app {}: proxy_config: {}",
            quote(app.app_id.as_bytes()),
            e.0
        )
    })?;
    if let Some(why) = strip_path_prefix_fault(&pxy.strip_path_prefix) {
        return Err(format!(
            "app {}: strip_path_prefix {why}",
            quote(app.app_id.as_bytes())
        ));
    }
    if app
        .compression
        .is_some_and(|c| c.min_bytes > MAX_MIN_COMPRESS_BYTES)
    {
        return Err(format!(
            "app {}: compression min_bytes must be at most {MAX_MIN_COMPRESS_BYTES}",
            quote(app.app_id.as_bytes())
        ));
    }
    let main_host = match &app.tls {
        Some(site) => {
            let port = site
                .listen
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse().ok());
            // `Proxy::apply` refuses a listen address without a port; the route is built before it.
            port.and_then(|port| MainHost::new(site, port))
        }
        None => None,
    };
    let ws = parse_ws_app_policy(&app.rules_json)
        .map_err(|e| format!("app {}: {e}", quote(app.app_id.as_bytes())))?;
    let upstream_to =
        Duration::from_millis(timeout_or_default_ms(pxy.timeouts.upstream_ms, 30000).max(0) as u64);
    let upstream_unlimited = is_unlimited(pxy.timeouts.upstream_ms);
    let connect_ms = timeout_or_default_ms(pxy.timeouts.connect_ms, 0);
    let target = if upstream.starts_with("fcgi:") {
        let to = FastCgiDeadlines {
            read: upstream_to,
            write: upstream_to,
            unlimited: upstream_unlimited,
            dial: Duration::from_millis(
                timeout_or_default_ms(pxy.timeouts.connect_ms, 5000).max(0) as u64,
            ),
            slot_wait: Duration::from_millis(pxy.conn_wait_ms.max(0) as u64),
            max_idle_age: resolve_idle_timeout(pxy.idle_conn_ms),
        };
        let pool = parse_upstream_spec(
            upstream,
            &app.fcgi_doc_root,
            &app.fcgi_index,
            app.fcgi_keep_conn,
            pxy.max_conns,
            to,
        )
        .map_err(|e| format!("app {}: {e}", quote(app.app_id.as_bytes())))?;
        Target::Fcgi(pool)
    } else if let Some(sock) = unix_socket_path_of_upstream(upstream) {
        Target::Http(HttpTarget {
            scheme: "http",
            host: "localhost".into(),
            unix: Some(sock),
            dns: Mutex::new(None),
        })
    } else {
        let (scheme, host) = parse_http_upstream(&app.app_id, upstream)?;
        Target::Http(HttpTarget {
            scheme,
            host,
            unix: None,
            dns: Mutex::new(None),
        })
    };
    Ok(Route {
        app_id: app.app_id.clone(),
        upstream: upstream.to_string(),
        mode: mode.to_string(),
        connection_slots: Arc::new(Semaphore::new(pxy.max_conns.clamp(1, 65535) as usize)),
        connection_wait: Duration::from_millis(pxy.conn_wait_ms.max(0) as u64),
        idle_connection_timeout: resolve_idle_timeout(pxy.idle_conn_ms),
        connect_deadline: Duration::from_millis(if connect_ms > 0 {
            connect_ms as u64
        } else {
            3000
        }),
        proxy_config: pxy,
        ws,
        maintenance: parse_maintenance(&app.maintenance).map(MaintenanceRoute::new),
        analysis: app.analysis.clone(),
        edge: app.tls.is_some(),
        main_host,
        compression: app.compression,
        static_files: app
            .static_files
            .as_ref()
            .map(|spec| Arc::new(StaticFolder::new(&app.app_id, spec))),
        target,
        upstream_timeout: upstream_to,
        upstream_unlimited,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_upstreams() {
        assert_eq!(
            unix_socket_path_of_upstream("unix:/run/a.sock").as_deref(),
            Some("/run/a.sock")
        );
        assert_eq!(
            unix_socket_path_of_upstream("unix:/run/a.sock:").as_deref(),
            Some("/run/a.sock")
        );
        assert_eq!(
            unix_socket_path_of_upstream("http://unix:/run/a.sock:").as_deref(),
            Some("/run/a.sock")
        );
        assert_eq!(
            unix_socket_path_of_upstream("https://unix:/run/a.sock:/").as_deref(),
            Some("/run/a.sock")
        );
        assert_eq!(unix_socket_path_of_upstream("unix:"), None);
        assert_eq!(unix_socket_path_of_upstream("http://127.0.0.1:80"), None);
    }

    #[test]
    fn http_upstreams() {
        assert_eq!(
            parse_http_upstream("a", "http://10.0.0.1").unwrap(),
            ("http", "10.0.0.1:80".into())
        );
        assert_eq!(
            parse_http_upstream("a", "HTTPS://u:p@example.com/x").unwrap(),
            ("https", "example.com:443".into())
        );
        assert_eq!(
            parse_http_upstream("a", "http://h:8080?x").unwrap(),
            ("http", "h:8080".into())
        );
        assert_eq!(
            parse_http_upstream("a", "http://[::1]").unwrap(),
            ("http", "[::1]".into())
        );
        assert_eq!(
            parse_http_upstream("a", "ftp://h").unwrap_err(),
            "app \"a\": upstream scheme must be http or https (or unix:/path), got \"ftp\""
        );
        assert!(parse_http_upstream("a", "h:80").is_err());
        // Refusals of a malformed URL.
        assert_eq!(
            parse_http_upstream("a", "http://[::1").unwrap_err(),
            "app \"a\": parse upstream \"http://[::1\": parse \"http://[::1\": missing ']' in host"
        );
        assert!(
            parse_http_upstream("a", "http://h/%zz")
                .unwrap_err()
                .contains("invalid URL escape \"%zz\"")
        );
    }
}
