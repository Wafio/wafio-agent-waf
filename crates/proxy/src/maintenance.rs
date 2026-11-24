//! Maintenance mode of the proxy. An app whose bundle entry turns it on answers 503 from the
//! request head: the gate runs before the body is read, so nothing of the body is buffered,
//! analysed or forwarded. The pages are built when the route is built. The same module decides
//! which open sessions (WebSocket, event streams) end when maintenance turns on, and answers
//! the CORS preflight of a browser app that wants to read the 503.
//!
//! CORS on the maintenance answer only. The body is the operator's public text and the end
//! time, the answer sets no cookie and no upstream data is involved, so a page of any origin
//! may read it, with credentials, and learns nothing it could not get by loading the page.
//! A preflight is answered without `Allow-Credentials` and with `Max-Age: 0`: the agent cannot
//! link a preflight to the request after it, and maintenance may end in between, so an approval
//! that allowed credentials (or stayed in the browser's cache) would let a page on another site
//! send a credentialed, non-simple request to the upstream. The limit that follows: a request
//! with credentials that needs a preflight still fails in the browser during maintenance.
//! Without credentials an approval can still let one request through when maintenance ends in
//! between; it carries no cookie and no HTTP authentication, so it is a request anyone could
//! send, only from the visitor's address. No `Access-Control-Allow-Private-Network` is sent.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::watch;
use wafio_agent_io::client_ip::{effective_client_ip, tcp_peer_address};
use wafio_agent_pages::maintenance::MaintenancePages;
use wafio_domain::{MaintenanceSettings, path_matches};
use wafio_engine_rules::ip_network::ip_in_list;
use wafio_engine_rules::{decode_forwarded_path, forwarded_path_readings, strip_path_parameters};

use crate::config::Route;
use crate::decision::now_unix;
use crate::head_parser::{Head, is_valid_scheme, tchar};
use crate::metrics::MAINTENANCE_RESPONSES;
use crate::response::OutboundResponse;

/// An app's maintenance settings with what a request needs, prepared when the route is built.
pub(crate) struct MaintenanceRoute {
    settings: MaintenanceSettings,
    pages: MaintenancePages,
    /// The allowed paths with their path parameters removed (the `;` rule).
    plain_paths: Vec<Vec<u8>>,
}

impl MaintenanceRoute {
    pub(crate) fn new(settings: MaintenanceSettings) -> MaintenanceRoute {
        MaintenanceRoute {
            pages: MaintenancePages::new(&settings),
            plain_paths: settings
                .allow_paths
                .iter()
                .map(|entry| strip_path_parameters(entry))
                .collect(),
            settings,
        }
    }

    /// Whether this client and path get the maintenance answer: the client is on no allowed
    /// address and the path is on no allowed path.
    pub(crate) fn blocks(&self, client: &str, path: &[u8]) -> bool {
        !(ip_in_list(client, &self.settings.allow_ips) || self.allows_path(path))
    }

    /// An allowed path that holds a `;` must also pass with the path parameters removed from it
    /// and from the entries, since servlet containers route `/healthz/..;/admin` to `/admin`.
    fn allows_path(&self, path: &[u8]) -> bool {
        self.settings.allows_path(path)
            && (!path.contains(&b';')
                || path_matches(&self.plain_paths, &forwarded_path_readings(path).0))
    }
}

/// The client address and the decoded path the allow lists are matched against.
fn client_and_path(route: &Route, head: &Head, peer_ip: Option<IpAddr>) -> (String, Vec<u8>) {
    (
        effective_client_ip(&tcp_peer_address(peer_ip), &head.lines, &route.proxy_config),
        decode_forwarded_path(&head.request_target).0,
    )
}

/// The first header line named `name` (any letter case).
fn header<'a>(head: &'a Head, name: &[u8]) -> Option<&'a [u8]> {
    head.lines
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

/// The gate: `Some` is the whole answer for a request of an app in maintenance mode, whose
/// client and path are not allowed. With maintenance off it is one `Option` check.
pub(crate) fn gate(
    route: &Route,
    head: &Head,
    peer_ip: Option<IpAddr>,
) -> Option<OutboundResponse> {
    let m = route.maintenance.as_ref()?;
    let (client, path) = client_and_path(route, head, peer_ip);
    m.blocks(&client, &path).then(|| m.answer(head))
}

impl MaintenanceRoute {
    /// The 503, or the answer to a preflight. It is counted, not recorded as a decision.
    fn answer(&self, head: &Head) -> OutboundResponse {
        MAINTENANCE_RESPONSES.fetch_add(1, Ordering::Relaxed);
        let origin = origin(head);
        let mut r = match origin.and_then(|o| preflight(head, o)) {
            Some(r) => r,
            None => {
                let (content_type, body, retry_after) = self
                    .pages
                    .page(header(head, b"accept").unwrap_or_default(), now_unix());
                let mut r = OutboundResponse::with(503, content_type, body);
                r.add(b"Cache-Control", b"no-store");
                r.add(b"X-Content-Type-Options", b"nosniff");
                if let Some(seconds) = retry_after {
                    r.add(b"Retry-After", seconds.to_string().as_bytes());
                }
                r.add(b"Vary", b"Origin");
                if let Some(o) = origin {
                    r.add(b"Access-Control-Allow-Origin", o);
                    r.add(b"Access-Control-Allow-Credentials", b"true");
                    r.add(b"Access-Control-Expose-Headers", b"Retry-After");
                }
                r
            }
        };
        // The body is not read, and draining an unknown one to keep the connection would buy
        // nothing during maintenance: the answer ends the connection (the lingering close that
        // follows drains a bounded amount, so the client can read the answer).
        r.close |= head.content_length > 0 || head.content_length == -1 || head.expect_continue;
        r
    }
}

/// The `Origin` of the request when there is exactly one line and it is valid: `null`, or
/// `scheme://host[:port]`, printable ASCII without a comma, at most 256 bytes.
fn origin(head: &Head) -> Option<&[u8]> {
    let mut lines = head
        .lines
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(b"origin"));
    let (_, value) = lines.next()?;
    (lines.next().is_none() && valid_origin(value)).then_some(value.as_slice())
}

fn valid_origin(o: &[u8]) -> bool {
    if o.len() > 256 || !o.iter().all(|&b| (0x21..=0x7e).contains(&b) && b != b',') {
        return false;
    }
    if o == b"null" {
        return true;
    }
    let Some(i) = memchr::memmem::find(o, b"://") else {
        return false;
    };
    let authority = &o[i + 3..];
    is_valid_scheme(&o[..i])
        && !authority.is_empty()
        && !authority.iter().any(|b| b"/?#@\\".contains(b))
}

/// The answer to `OPTIONS` with an `Origin` and an `Access-Control-Request-Method`: 204, the
/// origin and the requested method allowed, no credentials, no caching.
fn preflight(head: &Head, origin: &[u8]) -> Option<OutboundResponse> {
    if head.method != b"OPTIONS" {
        return None;
    }
    let method = header(head, b"access-control-request-method")
        .filter(|m| !m.is_empty() && m.len() <= 32 && m.iter().all(|&c| tchar(c)))?;
    let mut r = OutboundResponse::new(204);
    r.add(b"Access-Control-Allow-Origin", origin);
    r.add(b"Access-Control-Allow-Methods", method);
    if let Some(requested) = header(head, b"access-control-request-headers")
        .filter(|h| h.len() <= 1024 && is_name_list(h))
    {
        r.add(b"Access-Control-Allow-Headers", requested);
    }
    r.add(b"Access-Control-Max-Age", b"0");
    r.add(
        b"Vary",
        b"Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
    );
    r.add(b"Cache-Control", b"no-store");
    r.add(b"X-Content-Type-Options", b"nosniff");
    Some(r)
}

/// Whether `list` is header names separated by commas, each with optional spaces or tabs around
/// it: current browsers send `a,b`, older ones `a, b`.
fn is_name_list(list: &[u8]) -> bool {
    list.split(|&c| c == b',').all(|item| {
        let mut words = item
            .split(|&c| c == b' ' || c == b'\t')
            .filter(|w| !w.is_empty());
        matches!((words.next(), words.next()), (Some(w), None) if w.iter().all(|&c| tchar(c)))
    })
}

/// Follows the route of one app for a session or stream of one client, so that it can end when
/// maintenance turns on for that client.
pub(crate) struct Watch {
    route: watch::Receiver<Arc<Route>>,
    client: String,
    path: Vec<u8>,
}

impl Watch {
    pub(crate) fn new(
        mut route: watch::Receiver<Arc<Route>>,
        client: String,
        path: Vec<u8>,
    ) -> Watch {
        // The route may have changed since the request was decided: the first wait checks it.
        route.mark_changed();
        Watch {
            route,
            client,
            path,
        }
    }

    /// A watch for the client and path of the request in `head`.
    pub(crate) fn for_request(
        route: watch::Receiver<Arc<Route>>,
        current: &Route,
        head: &Head,
        peer_ip: Option<IpAddr>,
    ) -> Watch {
        let (client, path) = client_and_path(current, head, peer_ip);
        Watch::new(route, client, path)
    }

    /// Resolves when the current route puts this client in maintenance, now or after a later
    /// route change; it never resolves while the client is allowed or maintenance is off. Each
    /// route is checked once, when it is new, so a stream that calls this for every piece it
    /// relays pays for no check in between.
    pub(crate) async fn maintenance_on(&mut self) {
        loop {
            if self.route.changed().await.is_err() {
                // The app is gone; the shutdown signal ends what is left.
                std::future::pending::<()>().await;
            }
            // Cloned, so the channel's lock is not held while the lists are matched.
            let route = self.route.borrow_and_update().clone();
            if route
                .maintenance
                .as_ref()
                .is_some_and(|m| m.blocks(&self.client, &self.path))
            {
                return;
            }
        }
    }
}

/// Whether a response with this `Content-Type` is a server-sent event stream.
pub(crate) fn is_event_stream(content_type: &[u8]) -> bool {
    let media = content_type
        .split(|&c| c == b';')
        .next()
        .unwrap_or_default();
    media
        .trim_ascii()
        .eq_ignore_ascii_case(b"text/event-stream")
}

#[cfg(test)]
mod tests {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::sync::Arc;

    use super::*;
    use crate::config::{AppSpec, build_route};
    use crate::head_parser::parse_head;

    thread_local! {
        static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    }

    /// Counts the allocations of the calling thread; everything else goes to the system allocator.
    struct Counting;

    // SAFETY: every call is forwarded to `System` with the same arguments; the counter is a
    // const-initialised thread local without a destructor.
    #[allow(unsafe_code)]
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOCATIONS.with(|c| c.set(c.get() + 1));
            // SAFETY: the caller's contract for `alloc` is passed on unchanged.
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: `ptr` came from `System.alloc` with this layout (see `alloc`).
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static COUNTING: Counting = Counting;

    fn route(maintenance: &str) -> Route {
        build_route(&AppSpec {
            app_id: "a".into(),
            listen_host: String::new(),
            listen_port: 0,
            upstream: "http://127.0.0.1:1".into(),
            mode: "block".into(),
            proxy_config: Vec::new(),
            rules_json: Vec::new(),
            fcgi_doc_root: String::new(),
            fcgi_index: String::new(),
            fcgi_keep_conn: false,
            maintenance: maintenance.as_bytes().to_vec(),
            analysis: Arc::new(crate::testing::analysis_setup(b"{}")),
            tls: None,
            compression: None,
        })
        .unwrap()
    }

    fn head(raw: &str) -> Head {
        parse_head(raw.as_bytes()).unwrap()
    }

    /// With maintenance off a request pays for one `Option` check: no allocation, no lock (the
    /// gate gets the route the request already holds).
    #[test]
    fn the_gate_of_an_app_that_is_not_in_maintenance_allocates_nothing() {
        let off = route("");
        let head = head(
            "POST /a?b=1 HTTP/1.1\r\nHost: a\r\nOrigin: https://x.example\r\nContent-Length: 3\r\n\r\n",
        );
        let peer = Some("203.0.113.5".parse().unwrap());
        assert!(gate(&off, &head, peer).is_none());
        let before = ALLOCATIONS.with(Cell::get);
        for _ in 0..1000 {
            assert!(gate(&off, &head, peer).is_none());
        }
        assert_eq!(ALLOCATIONS.with(Cell::get) - before, 0);

        // A route with maintenance on does the work: a blocked client gets an answer.
        let on = route(r#"{"enabled":true,"allow_ips":["198.51.100.1"]}"#);
        let before = ALLOCATIONS.with(Cell::get);
        assert_eq!(gate(&on, &head, peer).unwrap().status, 503);
        assert!(ALLOCATIONS.with(Cell::get) > before);
        assert!(gate(&on, &head, Some("198.51.100.1".parse().unwrap())).is_none());
    }

    async fn resolves(w: &mut Watch) -> bool {
        tokio::time::timeout(std::time::Duration::from_millis(50), w.maintenance_on())
            .await
            .is_ok()
    }

    /// A watch checks the route it starts with, since maintenance may have come on after the
    /// request was decided, and then every new route.
    #[tokio::test]
    async fn a_watch_checks_the_route_it_starts_with_and_each_new_one() {
        let client = || "198.51.100.1".to_string();
        let (_tx, rx) = watch::channel(Arc::new(route(r#"{"enabled":true}"#)));
        assert!(resolves(&mut Watch::new(rx, client(), b"/chat".to_vec())).await);

        let (tx, rx) = watch::channel(Arc::new(route("")));
        let mut w = Watch::new(rx, client(), b"/chat".to_vec());
        assert!(!resolves(&mut w).await);
        tx.send_replace(Arc::new(route(
            r#"{"enabled":true,"allow_ips":["198.51.100.1"]}"#,
        )));
        assert!(!resolves(&mut w).await, "an allowed client stays");
        tx.send_replace(Arc::new(route(
            r#"{"enabled":true,"allow_paths":["/chat"]}"#,
        )));
        assert!(!resolves(&mut w).await, "an allowed path stays");
        tx.send_replace(Arc::new(route(r#"{"enabled":true}"#)));
        assert!(resolves(&mut w).await);
    }

    #[test]
    fn an_origin_is_null_or_scheme_and_authority_of_printable_bytes() {
        for yes in [
            "null",
            "https://a.example",
            "http://a.example:8080",
            "https://[2001:db8::1]:8443",
            "chrome-extension://abcdef",
        ] {
            assert!(valid_origin(yes.as_bytes()), "{yes}");
        }
        let long = format!("https://{}", "a".repeat(250));
        for no in [
            "",
            "Null",
            "a.example",
            "https://",
            "://a.example",
            "1http://a.example",
            "https://a.example/",
            "https://a.example?x=1",
            "https://a.example#f",
            "https://u@a.example",
            "https://a.example,https://b.example",
            "https://a b.example",
            "https://a.example\\",
            "https://\u{e9}.example",
            long.as_str(),
        ] {
            assert!(!valid_origin(no.as_bytes()), "{no}");
        }
        assert!(valid_origin(
            format!("https://{}", "a".repeat(248)).as_bytes()
        ));
    }

    #[test]
    fn requested_headers_are_names_separated_by_commas() {
        for yes in [
            "content-type",
            "content-type,x-token",
            "content-type, x-token",
            "a ,\tb",
        ] {
            assert!(is_name_list(yes.as_bytes()), "{yes}");
        }
        for no in ["", " ", ",", "a,,b", "a,", "x-a b", "x-a;q", "a\u{c}"] {
            assert!(!is_name_list(no.as_bytes()), "{no:?}");
        }
    }

    #[test]
    fn an_event_stream_is_named_by_its_media_type_alone() {
        for yes in [
            "text/event-stream",
            "Text/Event-Stream; charset=utf-8",
            " text/event-stream ;q=1",
        ] {
            assert!(is_event_stream(yes.as_bytes()), "{yes}");
        }
        for no in [
            "",
            "text/event-streams",
            "text/plain; x=text/event-stream",
            "application/octet-stream",
        ] {
            assert!(!is_event_stream(no.as_bytes()), "{no}");
        }
    }
}
