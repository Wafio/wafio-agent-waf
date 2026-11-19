//! HTTPS listeners: the TLS handshake between accept and the HTTP/1 loop, the host names one
//! shared listener serves, and the plain listener that sends its hosts to HTTPS.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use pingora::listeners::tls::Acceptor;
use pingora::protocols::Ssl;
use pingora::protocols::Stream;
use pingora::protocols::l4::stream::Stream as TcpStream;
use pingora::server::ShutdownWatch;

use crate::cert_store::{CertStore, CertTable, server_config};
use crate::client_hello;
use crate::config::{Route, TlsSite};
use crate::head_parser::UriParts;
use crate::proxy::Shared;
use crate::request::TlsClient;
use crate::response::OutboundResponse;
use crate::route::{HeadLimits, RouteApp, Site, serve_connection};
use crate::upstream::ms;

/// One deadline for reading the first TLS record and finishing the handshake.
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The apps of an HTTPS listener and the host names each answers for.
#[derive(Default)]
struct Sites {
    apps: Vec<Arc<RouteApp>>,
    /// Lower case host name to its index in `apps`.
    hosts: HashMap<Vec<u8>, usize>,
}

/// One HTTPS listener: the certificates it serves and the apps behind its host names.
pub(crate) struct TlsListener {
    sites: RwLock<Sites>,
    store: Arc<CertStore>,
    acceptor: Acceptor,
    /// `Route::listener_limits` of every app on the listener, which are all equal.
    limits: (i64, i64, i64, usize),
}

impl TlsListener {
    pub(crate) fn new(store: Arc<CertStore>, limits: (i64, i64, i64, usize)) -> TlsListener {
        TlsListener {
            sites: RwLock::default(),
            acceptor: Acceptor::from_server_config(server_config(store.clone())),
            store,
            limits,
        }
    }

    pub(crate) fn limits(&self) -> (i64, i64, i64, usize) {
        self.limits
    }

    pub(crate) fn store(&self) -> &Arc<CertStore> {
        &self.store
    }

    /// Makes `sites` and `certs` what the listener serves from the next handshake and request on.
    /// An app the listener already has keeps its `RouteApp`, so running requests and open
    /// connections follow the new route.
    pub(crate) fn set_sites(
        &self,
        sites: Vec<(Arc<Route>, TlsSite)>,
        certs: CertTable,
        shared: &Arc<Shared>,
    ) {
        let mut next = Sites::default();
        {
            let current = self.sites.read().unwrap_or_else(PoisonError::into_inner);
            for (route, site) in sites {
                let app = match current
                    .apps
                    .iter()
                    .find(|a| a.route().app_id() == route.app_id())
                {
                    Some(app) => {
                        app.set_route(route);
                        app.clone()
                    }
                    None => Arc::new(RouteApp::new(route, shared.clone())),
                };
                let index = next.apps.len();
                next.apps.push(app);
                for host in &site.hosts {
                    next.hosts
                        .insert(host.to_ascii_lowercase().into_bytes(), index);
                }
            }
        }
        self.store.install(certs);
        *self.sites.write().unwrap_or_else(PoisonError::into_inner) = next;
    }

    /// The routes of the apps on the listener.
    pub(crate) fn routes(&self) -> Vec<Arc<Route>> {
        let sites = self.sites.read().unwrap_or_else(PoisonError::into_inner);
        sites.apps.iter().map(|a| a.route()).collect()
    }

    fn app_for(&self, name: &[u8]) -> Option<Arc<RouteApp>> {
        let sites = self.sites.read().unwrap_or_else(PoisonError::into_inner);
        sites.hosts.get(name).map(|&i| sites.apps[i].clone())
    }

    /// Reads the first record, which also gives the JA4, then lets rustls handshake over the same
    /// bytes. `None`: the client is gone, spoke no TLS or no certificate fits its name.
    async fn handshake(&self, mut stream: TcpStream) -> Option<(Stream, TlsClient)> {
        let record = client_hello::read_first_record(&mut stream).await.ok()?;
        let ja4 = client_hello::parse(&record).map(|hello| hello.ja4);
        stream.rewind(&record);
        drop(record);
        let tls = match self.acceptor.tls_handshake(stream).await {
            Ok(tls) => tls,
            Err(e) => {
                tracing::debug!("TLS handshake failed: {e}");
                return None;
            }
        };
        // The resolver refuses a hello without a known name, so a finished handshake has one.
        let server_name = tls.get_ssl()?.server_name()?.to_ascii_lowercase();
        Some((Box::new(tls), TlsClient { server_name, ja4 }))
    }
}

/// The certificates for `sites`, read from their files. A host name may belong to one app only.
/// Nothing is installed: the listener switches once every listener of an apply is ready.
pub(crate) fn prepare_certificates(
    store: &CertStore,
    sites: &[(Arc<Route>, TlsSite)],
) -> Result<CertTable, String> {
    let mut seen = HashSet::new();
    for (_, site) in sites {
        for host in &site.hosts {
            if !seen.insert(host.to_ascii_lowercase()) {
                return Err(format!("host name {host} is served by two apps"));
            }
        }
    }
    let pairs: Vec<_> = sites
        .iter()
        .map(|(_, site)| (site.hosts.clone(), site.cert.clone()))
        .collect();
    store.prepare(&pairs)
}

/// An accepted connection of an HTTPS listener: the handshake, then the HTTP/1 loop. A failed
/// handshake, or one not finished within `handshake_timeout`, closes the connection without an
/// answer.
pub(crate) async fn serve_tls(
    listener: Arc<TlsListener>,
    stream: TcpStream,
    stop: ShutdownWatch,
    handshake_timeout: Duration,
) {
    let handshake = tokio::time::timeout(handshake_timeout, listener.handshake(stream));
    let Ok(Some((stream, client))) = handshake.await else {
        return;
    };
    let site = TlsConn {
        listener,
        client: Arc::new(client),
    };
    serve_connection(site, stream, stop).await;
}

struct TlsConn {
    listener: Arc<TlsListener>,
    client: Arc<TlsClient>,
}

impl Site for TlsConn {
    fn limits(&self) -> HeadLimits {
        let (read_ms, write_ms, _, cap) = self.listener.limits;
        HeadLimits {
            cap,
            read_to: ms(read_ms),
            write_ms,
        }
    }

    /// The app of the `Host` name, only when it is the name the certificate was chosen for: a
    /// client must not reach another app's host over a connection set up for this one.
    fn app(&self, host: &[u8]) -> Option<Arc<RouteApp>> {
        let name = host_name(host);
        if name != self.client.server_name.as_bytes() {
            return None;
        }
        self.listener.app_for(name)
    }

    fn tls(&self) -> Option<Arc<TlsClient>> {
        Some(self.client.clone())
    }
}

/// `host` without its port and trailing dot.
fn host_name(host: &[u8]) -> &[u8] {
    let host = match host.iter().rposition(|&c| c == b':') {
        Some(colon) if !host.ends_with(b"]") => &host[..colon],
        _ => host,
    };
    host.strip_suffix(b".").unwrap_or(host)
}

/// The host names a plain listener sends to HTTPS, with the HTTPS port of each.
pub(crate) struct RedirectTable(RwLock<HashMap<String, u16>>);

impl RedirectTable {
    pub(crate) fn new(hosts: HashMap<String, u16>) -> RedirectTable {
        RedirectTable(RwLock::new(hosts))
    }

    pub(crate) fn set(&self, hosts: HashMap<String, u16>) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = hosts;
    }

    /// `308` to the same host and target over HTTPS for a known host, `404` for any other.
    pub(crate) fn answer(&self, parts: &UriParts) -> OutboundResponse {
        let hosts = self.0.read().unwrap_or_else(PoisonError::into_inner);
        let known = std::str::from_utf8(host_name(&parts.host))
            .ok()
            .and_then(|name| hosts.get_key_value(name));
        let Some((name, &port)) = known else {
            return OutboundResponse::error(404, "Not Found");
        };
        let mut location = format!("https://{name}").into_bytes();
        if port != 443 {
            location.extend_from_slice(format!(":{port}").as_bytes());
        }
        // `OPTIONS *` and an absolute-form target without a path have no origin-form target.
        if !parts.uri.starts_with(b"/") {
            location.push(b'/');
        }
        if parts.uri.starts_with(b"/") || parts.uri.starts_with(b"?") {
            location.extend_from_slice(&parts.uri);
        }
        let mut response = OutboundResponse::new(308);
        response.set(b"Location", &location);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(host: &str, uri: &str) -> UriParts {
        UriParts {
            host: host.as_bytes().to_vec(),
            uri: uri.as_bytes().to_vec(),
            user: None,
        }
    }

    #[test]
    fn host_name_drops_port_and_trailing_dot() {
        assert_eq!(host_name(b"shop.example.com"), b"shop.example.com");
        assert_eq!(host_name(b"shop.example.com:8443"), b"shop.example.com");
        assert_eq!(host_name(b"shop.example.com."), b"shop.example.com");
        assert_eq!(host_name(b"shop.example.com.:443"), b"shop.example.com");
        assert_eq!(host_name(b"[::1]:443"), b"[::1]");
        assert_eq!(host_name(b"[::1]"), b"[::1]");
        assert_eq!(host_name(b""), b"");
    }

    #[test]
    fn redirect_keeps_host_path_and_query() {
        let table = RedirectTable::new(HashMap::from([
            ("shop.example.com".to_owned(), 443),
            ("alt.example.com".to_owned(), 8443),
        ]));
        let location = |host: &str, uri: &str| {
            let r = table.answer(&parts(host, uri));
            (r.status, r.peek(b"Location").map(<[u8]>::to_vec))
        };
        assert_eq!(
            location("shop.example.com:80", "/a/b?c=d"),
            (308, Some(b"https://shop.example.com/a/b?c=d".to_vec()))
        );
        assert_eq!(
            location("alt.example.com", "/"),
            (308, Some(b"https://alt.example.com:8443/".to_vec()))
        );
        assert_eq!(
            location("shop.example.com", "*"),
            (308, Some(b"https://shop.example.com/".to_vec()))
        );
        assert_eq!(
            location("shop.example.com", "?x=1"),
            (308, Some(b"https://shop.example.com/?x=1".to_vec()))
        );
        assert_eq!(location("other.example.com", "/"), (404, None));
        assert_eq!(location("", "/"), (404, None));
    }
}
