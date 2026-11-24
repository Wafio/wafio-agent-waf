//! HTTPS listeners: the TLS handshake between accept and the HTTP/1 loop, the host names one
//! shared listener serves, the answers to certificate validation (HTTP-01 on the TLS and the
//! redirect listener, TLS-ALPN-01 in the handshake) and the plain listener that sends its hosts
//! to HTTPS once they have a real certificate.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use pingora::listeners::tls::Acceptor;
use pingora::protocols::l4::stream::Stream as TcpStream;
use pingora::protocols::{ALPN, Ssl, Stream};
use pingora::server::ShutdownWatch;
use pingora::tls::sign::CertifiedKey;
use pingora::tls::{ClientHello, ResolvesServerCert};
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;

use crate::cert_store::{ACME_TLS_ALPN, BookChange, CertBook, server_config};
use crate::client_hello;
use crate::config::{Route, TlsSite};
use crate::head_parser::UriParts;
use crate::proxy::Shared;
use crate::redirect::https_location;
use crate::request::TlsClient;
use crate::response::OutboundResponse;
use crate::route::{HeadLimits, RouteApp, Site, serve_connection};
use crate::upstream::ms;

/// One deadline for reading the first TLS record and finishing the handshake.
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// What the answer to a client that must wait for its certificate asks it to do.
const RETRY_AFTER_SECS: &[u8] = b"60";

/// The write timeout of an answer made before an app is chosen, on a listener whose apps all have
/// none: a client that stops reading must not hold the connection for ever.
const UNBOUNDED_WRITE_MS: i64 = 60_000;

/// The apps of an HTTPS listener and the host names each answers for.
struct Sites {
    apps: Vec<SiteApp>,
    /// Lower case host name to its index in `apps`.
    hosts: HashMap<Vec<u8>, usize>,
    /// What a connection is held to until an app is chosen.
    limits: HeadLimits,
}

struct SiteApp {
    id: String,
    app: Arc<RouteApp>,
}

impl Sites {
    /// The table for `sites`. An app that `current` has keeps its `RouteApp`, so running requests
    /// and open connections follow the new route.
    fn build(
        current: Option<&Sites>,
        sites: Vec<(Arc<Route>, TlsSite)>,
        shared: &Arc<Shared>,
    ) -> Sites {
        let mut next = Sites {
            apps: Vec::new(),
            hosts: HashMap::new(),
            limits: shared_limits(
                &sites
                    .iter()
                    .map(|(route, _)| limits_of(route))
                    .collect::<Vec<_>>(),
            ),
        };
        for (route, site) in sites {
            let id = route.app_id().to_owned();
            let app = match current.and_then(|c| c.apps.iter().find(|a| a.id == id)) {
                Some(held) => {
                    held.app.set_route(route);
                    held.app.clone()
                }
                None => Arc::new(RouteApp::new(route, shared.clone())),
            };
            let index = next.apps.len();
            next.apps.push(SiteApp { id, app });
            for host in &site.hosts {
                next.hosts
                    .insert(host.to_ascii_lowercase().into_bytes(), index);
            }
        }
        next
    }
}

/// The read timeout, write timeout (both in milliseconds as `proxy_config` has them) and read
/// buffer size of an app.
type AppLimits = (i64, i64, usize);

fn limits_of(route: &Route) -> AppLimits {
    (
        route.proxy_config.timeouts.read_ms,
        route.proxy_config.timeouts.write_ms,
        route.header_buffer_size(),
    )
}

/// What a connection of a listener shared by `apps` is held to until its request is routed: the
/// largest buffer and the largest finite read timeout, since the app is not known yet. Answers
/// made before routing use the largest finite write timeout, or a fixed one when no app has any.
fn shared_limits(apps: &[AppLimits]) -> HeadLimits {
    let largest_finite =
        |pick: fn(&AppLimits) -> i64| apps.iter().filter_map(|a| ms(pick(a))).max();
    HeadLimits {
        cap: apps.iter().map(|a| a.2).max().unwrap_or(16 << 10),
        read_to: largest_finite(|a| a.0),
        write_ms: largest_finite(|a| a.1).map_or(UNBOUNDED_WRITE_MS, |d| d.as_millis() as i64),
    }
}

/// The certificate resolver of one listener: SNI name, then app, then the book.
struct Resolver {
    sites: Arc<RwLock<Sites>>,
    book: Arc<CertBook>,
}

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for Resolver {
    /// The certificate of the app the SNI name belongs to. A hello that offers `acme-tls/1` is a
    /// validation of that name and gets the challenge key, or no handshake. `None` (no SNI, a
    /// name no app has, nothing in the book) refuses the handshake.
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?.to_ascii_lowercase();
        let sites = self.sites.read().unwrap_or_else(PoisonError::into_inner);
        let app = &sites.apps[*sites.hosts.get(name.as_bytes())?];
        if hello
            .alpn()
            .is_some_and(|mut offered| offered.any(|protocol| protocol == ACME_TLS_ALPN))
        {
            return self.book.alpn_challenge(&name);
        }
        Some(self.book.get(&app.id)?.key)
    }
}

/// One HTTPS listener: the apps behind its host names and the handshake that picks their
/// certificates from the book.
pub(crate) struct TlsListener {
    sites: Arc<RwLock<Sites>>,
    book: Arc<CertBook>,
    acceptor: Acceptor,
}

impl TlsListener {
    pub(crate) fn new(sites: Vec<(Arc<Route>, TlsSite)>, shared: &Arc<Shared>) -> TlsListener {
        let sites = Arc::new(RwLock::new(Sites::build(None, sites, shared)));
        let resolver = Arc::new(Resolver {
            sites: sites.clone(),
            book: shared.book.clone(),
        });
        TlsListener {
            acceptor: Acceptor::from_server_config(server_config(resolver)),
            sites,
            book: shared.book.clone(),
        }
    }

    /// Makes `sites` what the listener serves from the next handshake and request on. Limits and
    /// timeouts change with it, in place. The book is switched by the caller first.
    pub(crate) fn set_sites(&self, sites: Vec<(Arc<Route>, TlsSite)>, shared: &Arc<Shared>) {
        let next = {
            let current = self.sites.read().unwrap_or_else(PoisonError::into_inner);
            Sites::build(Some(&current), sites, shared)
        };
        *self.sites.write().unwrap_or_else(PoisonError::into_inner) = next;
    }

    fn limits(&self) -> HeadLimits {
        self.sites
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .limits
    }

    /// The routes of the apps on the listener.
    pub(crate) fn routes(&self) -> Vec<Arc<Route>> {
        let sites = self.sites.read().unwrap_or_else(PoisonError::into_inner);
        sites.apps.iter().map(|a| a.app.route()).collect()
    }

    fn app_for(&self, name: &[u8]) -> Option<Arc<RouteApp>> {
        let sites = self.sites.read().unwrap_or_else(PoisonError::into_inner);
        sites.hosts.get(name).map(|&i| sites.apps[i].app.clone())
    }

    /// Whether the book holds only the placeholder for the app of `name`.
    fn has_placeholder(&self, name: &str) -> bool {
        let sites = self.sites.read().unwrap_or_else(PoisonError::into_inner);
        sites
            .hosts
            .get(name.as_bytes())
            .and_then(|&i| self.book.get(&sites.apps[i].id))
            .is_some_and(|entry| entry.placeholder)
    }

    /// Reads the first record, which also gives the JA4 and the SNI name, then lets rustls
    /// handshake over the same bytes. `None`: the client is gone, spoke no TLS, no certificate
    /// fits its name, or it was a TLS-ALPN-01 validation, which ends with the handshake. The flag
    /// says that the app had only its placeholder before or after the handshake.
    async fn handshake(&self, mut stream: TcpStream) -> Option<(Stream, TlsClient, bool)> {
        let record = client_hello::read_first_record(&mut stream).await.ok()?;
        let hello = client_hello::parse(&record);
        stream.rewind(&record);
        drop(record);
        // The name of the hello, before rustls looks at the book: a switch during the handshake
        // must not let a client that is about to get the placeholder reach the app.
        let before = hello
            .as_ref()
            .and_then(|h| h.server_name.as_deref())
            .is_some_and(|name| self.has_placeholder(name));
        let ja4 = hello.map(|h| h.ja4);
        let mut tls = match self.acceptor.tls_handshake(stream).await {
            Ok(tls) => tls,
            Err(e) => {
                tracing::debug!("TLS handshake failed: {e}");
                return None;
            }
        };
        if matches!(tls.selected_alpn_proto(), Some(ALPN::Custom(p)) if p.protocol() == ACME_TLS_ALPN)
        {
            // The validator has the certificate; there is nothing to ask of this connection.
            let _ = tokio::time::timeout(Duration::from_secs(1), tls.shutdown()).await;
            return None;
        }
        // The resolver refuses a hello without a known name, so a finished handshake has one.
        let server_name = tls.get_ssl()?.server_name()?.to_ascii_lowercase();
        let placeholder = before || self.has_placeholder(&server_name);
        Some((Box::new(tls), TlsClient { server_name, ja4 }, placeholder))
    }
}

/// The book changes for the apps of the TLS listeners of an apply, put into `entries`, as each
/// site says. A host name may belong to one app only. Nothing is switched: the book follows once
/// every listener of the apply is ready.
pub(crate) fn prepare_certificates(
    sites: &[(Arc<Route>, TlsSite)],
    entries: &mut HashMap<String, BookChange>,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    for (_, site) in sites {
        for host in &site.hosts {
            if !seen.insert(host.to_ascii_lowercase()) {
                return Err(format!("host name {host} is served by two apps"));
            }
        }
    }
    for (route, site) in sites {
        entries.insert(route.app_id().to_owned(), site.certificate.clone());
    }
    Ok(())
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
    let Ok(Some((stream, client, placeholder))) = handshake.await else {
        return;
    };
    let site = TlsConn {
        listener,
        client: Arc::new(client),
        placeholder,
    };
    serve_connection(site, stream, stop).await;
}

struct TlsConn {
    listener: Arc<TlsListener>,
    client: Arc<TlsClient>,
    /// The app had only its placeholder when this connection was set up: it is answered
    /// validations and `503`, whatever the book holds by now.
    placeholder: bool,
}

impl Site for TlsConn {
    fn limits(&self) -> HeadLimits {
        self.listener.limits()
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

    fn early_answer(&self, method: &[u8], parts: &UriParts) -> Option<OutboundResponse> {
        challenge_response(&self.listener.book, method, parts)
            .or_else(|| self.placeholder.then(not_ready))
    }

    fn head_fits(&self, app: &RouteApp, len: usize) -> bool {
        len <= app.route().header_buffer_size()
    }

    fn body_deadline(
        &self,
        app: &RouteApp,
        started: Instant,
        _head_deadline: Option<Instant>,
    ) -> Option<Instant> {
        ms(app.route().proxy_config.timeouts.read_ms).map(|d| started + d)
    }
}

/// `host` without its port and trailing dot.
pub(crate) fn host_name(host: &[u8]) -> &[u8] {
    let host = match host.iter().rposition(|&c| c == b':') {
        Some(colon) if !host.ends_with(b"]") => &host[..colon],
        _ => host,
    };
    host.strip_suffix(b".").unwrap_or(host)
}

const CHALLENGE_PATH: &[u8] = b"/.well-known/acme-challenge/";
const MAX_TOKEN_LEN: usize = 128;

/// The token of a request target that is exactly `/.well-known/acme-challenge/<token>`: 1 to 128
/// base64url characters, no query, no further path.
fn challenge_token(target: &[u8]) -> Option<&str> {
    let token = target.strip_prefix(CHALLENGE_PATH)?;
    let base64url = |c: &u8| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_');
    if !(1..=MAX_TOKEN_LEN).contains(&token.len()) || !token.iter().all(base64url) {
        return None;
    }
    std::str::from_utf8(token).ok()
}

/// The answer to an HTTP-01 validation: `200` and the key authorization, for a `GET` of the
/// token's path whose host (port and trailing dot left off) is the name that is being validated.
/// Anything else is not for this function and goes on to the listener's own handling.
fn challenge_response(
    book: &CertBook,
    method: &[u8],
    parts: &UriParts,
) -> Option<OutboundResponse> {
    if method != b"GET" {
        return None;
    }
    let token = challenge_token(&parts.uri)?;
    let host = std::str::from_utf8(host_name(&parts.host)).ok()?;
    let authorization = book.http01_authorization(host, token)?;
    Some(OutboundResponse::with(
        200,
        "application/octet-stream",
        authorization,
    ))
}

/// What a client gets for a name whose certificate is not ready: wait and ask again.
fn not_ready() -> OutboundResponse {
    let mut response = OutboundResponse::error(
        503,
        "The certificate for this site is not ready yet. Try again in a minute.",
    );
    response.set(b"Retry-After", RETRY_AFTER_SECS);
    response
}

/// Where a plain listener sends one host name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectTarget {
    /// The HTTPS port of the host.
    pub port: u16,
    /// The app the host belongs to: its certificate decides whether the redirect is sent.
    pub app_id: String,
    /// The app's main host name: the redirect goes to it, whatever host the request named.
    pub canonical_host: Option<String>,
}

/// The host names a plain listener sends to HTTPS, with the target of each.
pub(crate) struct RedirectTable {
    hosts: RwLock<HashMap<String, RedirectTarget>>,
    book: Arc<CertBook>,
}

impl RedirectTable {
    pub(crate) fn new(
        hosts: HashMap<String, RedirectTarget>,
        book: Arc<CertBook>,
    ) -> RedirectTable {
        RedirectTable {
            hosts: RwLock::new(hosts),
            book,
        }
    }

    pub(crate) fn set(&self, hosts: HashMap<String, RedirectTarget>) {
        *self.hosts.write().unwrap_or_else(PoisonError::into_inner) = hosts;
    }

    /// The answer to a request: an HTTP-01 validation of a name that is being validated, `404` for
    /// a host that is not in the table, `503` while the host's app has no real certificate (plain
    /// HTTP would carry its logins, and a `308` is cached by the browser that follows it into a
    /// refused handshake), else `308` over HTTPS to the app's main host if it has one, the same host
    /// if not, with the same target.
    pub(crate) fn answer(&self, method: &[u8], parts: &UriParts) -> OutboundResponse {
        if let Some(response) = challenge_response(&self.book, method, parts) {
            return response;
        }
        let hosts = self.hosts.read().unwrap_or_else(PoisonError::into_inner);
        let known = std::str::from_utf8(host_name(&parts.host))
            .ok()
            .and_then(|name| hosts.get_key_value(name));
        let Some((name, target)) = known else {
            return OutboundResponse::error(404, "Not Found");
        };
        if self
            .book
            .get(&target.app_id)
            .is_none_or(|entry| entry.placeholder)
        {
            return not_ready();
        }
        let host = target.canonical_host.as_deref().unwrap_or(name);
        let location = https_location(host, target.port, &parts.uri);
        let mut response = OutboundResponse::new(308);
        response.set(b"Location", &location);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_store::BookEntry;
    use crate::cert_store::tests::{CertFiles, Scratch, load_certified_key};
    use crate::head_parser::{parse_head, uri_parts};

    fn parts(host: &str, uri: &str) -> UriParts {
        UriParts {
            host: host.as_bytes().to_vec(),
            uri: uri.as_bytes().to_vec(),
            user: None,
        }
    }

    fn a_key(dir: &Scratch, name: &str) -> Arc<CertifiedKey> {
        let files: CertFiles = dir.pair(name);
        Arc::new(load_certified_key(&files).unwrap())
    }

    fn a_real_entry(dir: &Scratch, name: &str) -> BookChange {
        BookChange::Set(BookEntry {
            key: a_key(dir, name),
            placeholder: false,
        })
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
    fn redirect_keeps_host_path_and_query_once_the_certificate_is_real() {
        let dir = Scratch::new();
        let book = Arc::new(CertBook::default());
        book.follow(HashMap::from([
            ("shop".to_owned(), a_real_entry(&dir, "shop")),
            ("alt".to_owned(), a_real_entry(&dir, "alt")),
        ]));
        let target = |port, app: &str| RedirectTarget {
            port,
            app_id: app.to_owned(),
            canonical_host: None,
        };
        let table = RedirectTable::new(
            HashMap::from([
                ("shop.example.com".to_owned(), target(443, "shop")),
                ("alt.example.com".to_owned(), target(8443, "alt")),
            ]),
            book,
        );
        let location = |host: &str, uri: &str| {
            let r = table.answer(b"GET", &parts(host, uri));
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

    #[test]
    fn redirect_answers_503_until_the_app_has_a_real_certificate() {
        let dir = Scratch::new();
        let book = Arc::new(CertBook::default());
        let table = RedirectTable::new(
            HashMap::from([(
                "shop.example.com".to_owned(),
                RedirectTarget {
                    port: 443,
                    app_id: "shop".to_owned(),
                    canonical_host: None,
                },
            )]),
            book.clone(),
        );
        let ask = |host: &str| table.answer(b"GET", &parts(host, "/cart"));

        // Nothing in the book, then the placeholder: the host is known but cannot be served.
        book.follow(HashMap::from([("shop".to_owned(), BookChange::Keep)]));
        for held in [None, Some(a_key(&dir, "placeholder"))] {
            if let Some(key) = held {
                assert!(book.set("shop", key, true));
            }
            let r = ask("shop.example.com");
            assert_eq!(r.status, 503);
            assert_eq!(r.peek(b"Retry-After"), Some(&b"60"[..]));
            assert!(r.peek(b"Location").is_none());
            assert_eq!(
                r.body.iter().filter(|&&c| c == b'\n').count(),
                0,
                "one line"
            );
            // An unknown host is still 404, whatever the certificate.
            assert_eq!(ask("other.example.com").status, 404);
        }
        assert!(book.set("shop", a_key(&dir, "real"), false));
        assert_eq!(ask("shop.example.com").status, 308);
    }

    #[test]
    fn redirect_serves_http01_before_anything_else() {
        let book = Arc::new(CertBook::default());
        let table = RedirectTable::new(HashMap::new(), book.clone());
        let path = "/.well-known/acme-challenge/tok-1";
        assert_eq!(
            table
                .answer(b"GET", &parts("shop.example.com", path))
                .status,
            404
        );
        let _offered = book.offer_http01("shop.example.com", "tok-1", "tok-1.thumb");
        let r = table.answer(b"GET", &parts("shop.example.com:80", path));
        assert_eq!((r.status, r.body.as_slice()), (200, &b"tok-1.thumb"[..]));
        // Only the name that is being validated, only GET, only that token.
        assert_eq!(
            table
                .answer(b"GET", &parts("other.example.com", path))
                .status,
            404
        );
        assert_eq!(
            table
                .answer(b"POST", &parts("shop.example.com", path))
                .status,
            404
        );
        let other = "/.well-known/acme-challenge/tok-2";
        assert_eq!(
            table
                .answer(b"GET", &parts("shop.example.com", other))
                .status,
            404
        );
    }

    #[test]
    fn challenge_tokens_are_one_to_128_base64url_characters_and_nothing_else() {
        let path = |token: &str| format!("/.well-known/acme-challenge/{token}").into_bytes();
        assert_eq!(challenge_token(&path("a")), Some("a"));
        assert_eq!(challenge_token(&path("Ab0-_z")), Some("Ab0-_z"));
        let longest = "x".repeat(128);
        assert_eq!(challenge_token(&path(&longest)), Some(longest.as_str()));
        for bad in [
            String::new(),
            "x".repeat(129),
            "a b".into(),
            "a/b".into(),
            "a.b".into(),
            "a=".into(),
            "a%41".into(),
            "a?x=1".into(),
            "a\n".into(),
            "ä".into(),
        ] {
            assert_eq!(challenge_token(&path(&bad)), None, "{bad:?}");
        }
        for other in [
            &b"/"[..],
            b"/.well-known/acme-challenge",
            b"/.well-known/acme-challenge/",
            b"/.well-known/other/tok",
            b"/x/.well-known/acme-challenge/tok",
            b"/.Well-Known/acme-challenge/tok",
            b"*",
        ] {
            assert_eq!(challenge_token(other), None, "{other:?}");
        }
    }

    #[test]
    fn a_shared_listener_is_held_to_the_largest_buffer_and_the_largest_finite_timeouts() {
        let limits = shared_limits(&[(1_000, 2_000, 16 << 10), (3_000, 500, 64 << 10)]);
        assert_eq!(
            (limits.cap, limits.read_to, limits.write_ms),
            (64 << 10, Some(Duration::from_secs(3)), 2_000)
        );
        // An unlimited timeout (-1) does not lift the finite one of the other app.
        let limits = shared_limits(&[(-1, -1, 16 << 10), (1_000, 700, 16 << 10)]);
        assert_eq!(
            (limits.read_to, limits.write_ms),
            (Some(Duration::from_secs(1)), 700)
        );
        // No finite read timeout: none before routing either. No finite write timeout: 60 s.
        let limits = shared_limits(&[(-1, -1, 16 << 10), (-1, -1, 32 << 10)]);
        assert_eq!(
            (limits.cap, limits.read_to, limits.write_ms),
            (32 << 10, None, 60_000)
        );
        // One app: what the plain listener would use.
        let limits = shared_limits(&[(60_000, 90_000, 16 << 10)]);
        assert_eq!(
            (limits.read_to, limits.write_ms),
            (Some(Duration::from_secs(60)), 90_000)
        );
    }

    /// A small generator, so a failing case can be played again from its seed.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    fn mutate(bytes: &mut Vec<u8>, rng: &mut XorShift) {
        let at = rng.below(bytes.len());
        match rng.below(6) {
            0 if !bytes.is_empty() => bytes[at] ^= 1 << rng.below(8),
            1 if !bytes.is_empty() => bytes[at] = rng.next() as u8,
            2 => bytes.truncate(at),
            3 if !bytes.is_empty() => {
                bytes.remove(at);
            }
            4 => bytes.insert(at, rng.next() as u8),
            _ => {
                // A piece of the request put in again, as a duplicated line or a doubled path.
                let (from, len) = (rng.below(bytes.len()), 1 + rng.below(16));
                let piece = bytes[from..(from + len).min(bytes.len())].to_vec();
                bytes.splice(at..at, piece).for_each(drop);
            }
        }
    }

    /// Mutated requests for a bounded time. A request is answered as a validation exactly when it is
    /// a `GET` of the pending token's path with the pending name as its host, and then with the key
    /// authorization; nothing else is, and nothing panics. `WAFIO_HTTP01_FUZZ_SECS` and
    /// `WAFIO_HTTP01_FUZZ_SEED` run a longer session by hand.
    #[test]
    fn http01_request_fuzz_answers_only_the_pending_challenge() {
        const NAME: &str = "shop.example.com";
        const PATH: &str = "/.well-known/acme-challenge/abc-DEF_123";
        let book = Arc::new(CertBook::default());
        let _offered = book.offer_http01(NAME, "abc-DEF_123", "abc-DEF_123.thumb");
        let seeds: Vec<Vec<u8>> = [
            format!("GET {PATH} HTTP/1.1\r\nHost: {NAME}\r\n\r\n"),
            format!("GET {PATH} HTTP/1.1\r\nHost: {NAME}:80\r\n\r\n"),
            format!("GET http://{NAME}{PATH} HTTP/1.1\r\nHost: other.test\r\n\r\n"),
            format!("GET {PATH}?x=1 HTTP/1.1\r\nHost: {NAME}\r\n\r\n"),
            format!(
                "GET {PATH}%41 HTTP/1.1\r\nHost: {}.\r\n\r\n",
                NAME.to_uppercase()
            ),
            format!("HEAD {PATH} HTTP/1.1\r\nHost: {NAME}\r\n\r\n"),
            format!("GET /.well-known/acme-challenge/ HTTP/1.1\r\nHost: {NAME}\r\n\r\n"),
            format!("GET {PATH} HTTP/1.1\r\nHost: [::1]:80\r\nHost: {NAME}\r\n\r\n"),
        ]
        .into_iter()
        .map(String::into_bytes)
        .collect();

        let env = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
        let budget = Duration::from_secs(env("WAFIO_HTTP01_FUZZ_SECS").unwrap_or(3));
        let mut rng = XorShift(env("WAFIO_HTTP01_FUZZ_SEED").unwrap_or(0x5eed_4321_dcba_10f1));
        let start = std::time::Instant::now();
        let (mut cases, mut parsed, mut answered) = (0u64, 0u64, 0u64);
        'run: for round in 0.. {
            for seed in &seeds {
                if start.elapsed() > budget {
                    break 'run;
                }
                let mut raw = seed.clone();
                if round > 0 {
                    for _ in 0..1 + rng.below(4) {
                        mutate(&mut raw, &mut rng);
                    }
                }
                cases += 1;
                let Ok(head) = parse_head(&raw) else { continue };
                let Ok(parts) = uri_parts(&head.host, &head.request_target) else {
                    continue;
                };
                parsed += 1;
                let host = String::from_utf8_lossy(&parts.host).into_owned();
                let named = host == NAME
                    || host == format!("{NAME}.")
                    || host.strip_prefix(NAME).is_some_and(|rest| {
                        let port = rest.strip_prefix(".:").or_else(|| rest.strip_prefix(':'));
                        port.is_some_and(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
                    });
                let exact = head.method == b"GET" && parts.uri == PATH.as_bytes();
                let got = challenge_response(&book, &head.method, &parts);
                let context = format!("{:?}", String::from_utf8_lossy(&raw));
                match got {
                    Some(response) => {
                        answered += 1;
                        assert!(exact && host.starts_with(NAME), "answered {context}");
                        assert_eq!(response.status, 200, "{context}");
                        assert_eq!(response.body, b"abc-DEF_123.thumb", "{context}");
                    }
                    None => assert!(!(exact && named), "not answered {context}"),
                }
            }
        }
        eprintln!("http-01 fuzz: {cases} cases, {parsed} parsed, {answered} answered");
        assert!(
            cases > 2000 && parsed > 500 && answered > 200,
            "{cases} {parsed} {answered}"
        );
    }
}
