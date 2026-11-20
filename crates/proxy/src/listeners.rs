//! Listeners added, changed and removed at runtime: the plain listener of an app, an HTTPS
//! listener shared by the apps that name its address, and a plain listener that redirects to HTTPS.
//! An address can change from one of these to another without closing its socket.
//!
//! Pingora's `Server` fixes its services and listeners before `run_forever`, so the accept loops
//! are our own: each listener is a tokio socket whose connections go through
//! `route::serve_connection` (head guard, HTTP/1 parsing, keep-alive loop) into the route's
//! `RouteApp`; an HTTPS listener does its TLS handshake first.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{TcpListener as StdListener, ToSocketAddrs};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pingora::protocols::l4::listener::Listener as L4Listener;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::cert_store::CertBook;
use crate::config::{Route, TlsSite};
use crate::https::{RedirectTable, RedirectTarget, TlsListener, prepare_certificates, serve_tls};
use crate::proxy::Shared;
use crate::route::{PlainSite, RouteApp, serve_connection, serve_redirect};

/// How long the connections of a retired route may drain.
pub const ROUTE_DRAIN_GRACE: Duration = Duration::from_secs(30);
const LISTEN_BACKLOG: u32 = 4096;

/// What a listener address serves.
pub enum Serves {
    /// One app on the plain listener its bundle entry names.
    App(Arc<Route>),
    /// Every app that names this address as its HTTPS listener.
    Tls(Vec<(Arc<Route>, TlsSite)>),
    /// A plain listener that sends these host names to HTTPS.
    Redirect(HashMap<String, RedirectTarget>),
}

pub struct RouteSpec {
    /// `listen_host:listen_port` (an IPv6 host in brackets); also the key a reload hands sockets over by.
    pub address: String,
    pub serves: Serves,
}

/// `Route::listener_limits`.
type Limits = (i64, i64, i64, usize);

impl Serves {
    /// The limits and timeouts a plain listener cannot change in place. `None`: an HTTPS listener
    /// takes them from its apps on every apply, and a redirect listener has none.
    fn limits(&self) -> Option<Limits> {
        match self {
            Serves::App(route) => Some(route.listener_limits()),
            Serves::Tls(_) | Serves::Redirect(_) => None,
        }
    }
}

/// What a live listener serves.
#[derive(Clone)]
enum Served {
    App(Arc<RouteApp>),
    Tls(Arc<TlsListener>),
    Redirect(Arc<RedirectTable>),
}

impl Served {
    fn limits(&self) -> Option<Limits> {
        match self {
            Served::App(app) => Some(app.route().listener_limits()),
            Served::Tls(_) | Served::Redirect(_) => None,
        }
    }

    fn routes(&self) -> Vec<Arc<Route>> {
        match self {
            Served::App(app) => vec![app.route()],
            Served::Tls(listener) => listener.routes(),
            Served::Redirect(_) => Vec::new(),
        }
    }

    fn is_kind_of(&self, serves: &Serves) -> bool {
        matches!(
            (self, serves),
            (Served::App(_), Serves::App(_))
                | (Served::Tls(_), Serves::Tls(_))
                | (Served::Redirect(_), Serves::Redirect(_))
        )
    }
}

struct Live {
    served: Served,
    stop: watch::Sender<bool>,
    /// A duplicate of the listening socket: stops it on retire, is handed to a successor.
    sock: StdListener,
    done: JoinHandle<()>,
}

struct Inner {
    live: HashMap<String, Live>,
    inherited: HashMap<String, StdListener>,
    first_applied: bool,
    closed: bool,
}

pub struct RouteManager {
    shared: Arc<Shared>,
    drain: Duration,
    /// The deadline of an HTTPS client's first record and handshake.
    handshake_timeout: Duration,
    /// Connections one listener serves at once.
    connection_limit: usize,
    inner: Mutex<Inner>,
}

impl RouteManager {
    /// `inherited`: sockets a predecessor handed over (`upgrade::inherited_listeners`).
    pub(crate) fn new(
        shared: Arc<Shared>,
        drain: Duration,
        handshake_timeout: Duration,
        connection_limit: usize,
        inherited: HashMap<String, StdListener>,
    ) -> Self {
        RouteManager {
            shared,
            drain,
            handshake_timeout,
            connection_limit,
            inner: Mutex::new(Inner {
                live: HashMap::new(),
                inherited,
                first_applied: false,
                closed: false,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn addresses(&self) -> Vec<String> {
        self.lock().live.keys().cloned().collect()
    }

    pub(crate) fn certificates(&self) -> Arc<CertBook> {
        self.shared.book.clone()
    }

    /// The route of the app on the plain listener at `addr`.
    pub fn route(&self, addr: &str) -> Option<Arc<Route>> {
        match &self.lock().live.get(addr)?.served {
            Served::App(app) => Some(app.route()),
            _ => None,
        }
    }

    /// Makes the live listeners exactly `specs`. Every certificate is read and every new socket
    /// bound first; a failure changes nothing. Kept listeners get the new config in place (no
    /// reconnect), removed ones stop accepting at once and drain in the background. A listener
    /// whose address now serves another kind keeps its socket: the old accept loop stops and
    /// drains, a new one starts on the same socket. Must run inside the tokio runtime. The cause
    /// of an error is logged.
    pub fn apply(&self, specs: Vec<RouteSpec>) -> Result<(), String> {
        let mut inner = self.lock();
        if inner.closed {
            return Err("agent is shutting down".into());
        }
        let wanted: HashSet<String> = specs.iter().map(|s| s.address.clone()).collect();
        if wanted.len() != specs.len() {
            return Err("duplicate listener in WAF bundle".into());
        }
        // The limits and timeouts of a plain listener cannot change in place.
        for spec in &specs {
            if let Some(live) = inner.live.get(&spec.address)
                && live.served.is_kind_of(&spec.serves)
                && live.served.limits() != spec.serves.limits()
            {
                return Err(
                    "route listener limits or timeouts changed; agent restart required".into(),
                );
            }
        }
        // Certificates are read before anything binds or switches.
        let mut certificates = HashMap::new();
        for spec in &specs {
            let Serves::Tls(sites) = &spec.serves else {
                continue;
            };
            prepare_certificates(&self.shared.book, sites, &mut certificates).map_err(|e| {
                tracing::warn!("TLS listener {}: {e}", spec.address);
                "invalid TLS site settings".to_string()
            })?;
        }
        let mut fresh: HashMap<String, (StdListener, bool)> = HashMap::new();
        for spec in &specs {
            if inner.live.contains_key(&spec.address) {
                continue;
            }
            let sock = match inner.inherited.remove(&spec.address) {
                Some(s) => Ok((s, true)),
                None => bind(&spec.address).map(|s| (s, false)),
            };
            match sock {
                Ok(s) => {
                    fresh.insert(spec.address.clone(), s);
                }
                Err(e) => {
                    // Inherited sockets go back; freshly bound ones close.
                    for (addr, (s, inherited)) in fresh {
                        if inherited {
                            inner.inherited.insert(addr, s);
                        }
                    }
                    tracing::warn!("failed to bind WAF route listener {}: {e}", spec.address);
                    return Err("failed to bind WAF route listener".into());
                }
            }
        }
        let mut old_pools: Vec<_> = inner
            .live
            .values()
            .flat_map(|l| l.served.routes())
            .filter_map(|r| r.fcgi().cloned())
            .collect();
        // The book switches before the listeners do, so a host a listener starts to serve has its
        // certificate by then.
        self.shared.book.follow(certificates);
        for spec in specs {
            let same_kind = inner
                .live
                .get(&spec.address)
                .map(|live| live.served.is_kind_of(&spec.serves));
            let sock = match same_kind {
                Some(true) => {
                    let live = &inner.live[&spec.address];
                    self.update(&live.served, spec.serves);
                    continue;
                }
                Some(false) => {
                    // The socket stays open so its accept queue is kept: the old loop drains its
                    // connections, the new kind takes the socket like an inherited one.
                    let old = inner.live.remove(&spec.address).expect("listed");
                    let _ = old.stop.send(true);
                    old.sock
                }
                None => fresh.remove(&spec.address).expect("bound above").0,
            };
            let served = self.build(spec.serves);
            let live = self.start(sock, served).map_err(|e| {
                tracing::warn!("failed to start WAF route listener {}: {e}", spec.address);
                "failed to bind WAF route listener".to_string()
            })?;
            inner.live.insert(spec.address, live);
        }
        let gone: Vec<String> = inner
            .live
            .keys()
            .filter(|a| !wanted.contains(*a))
            .cloned()
            .collect();
        for addr in gone {
            let live = inner.live.remove(&addr).expect("listed");
            retire(live);
        }
        // FastCGI pools of replaced routes: every pooled connection pins a PHP-FPM worker.
        let live_pools: Vec<_> = inner
            .live
            .values()
            .flat_map(|l| l.served.routes())
            .filter_map(|r| r.fcgi().cloned())
            .collect();
        old_pools.retain(|p| !live_pools.iter().any(|l| Arc::ptr_eq(l, p)));
        old_pools.iter().for_each(|p| p.close());
        if !inner.first_applied {
            // Handed-over sockets the first configuration does not use close now.
            inner.inherited.clear();
            inner.first_applied = true;
        }
        Ok(())
    }

    /// The state of a new listener, holding `serves`. The book already has the certificates of an
    /// HTTPS listener's apps.
    fn build(&self, serves: Serves) -> Served {
        match serves {
            Serves::App(route) => Served::App(Arc::new(RouteApp::new(route, self.shared.clone()))),
            Serves::Tls(sites) => Served::Tls(Arc::new(TlsListener::new(sites, &self.shared))),
            Serves::Redirect(hosts) => Served::Redirect(Arc::new(RedirectTable::new(
                hosts,
                self.shared.book.clone(),
            ))),
        }
    }

    /// Puts `serves` into a live listener of the same kind.
    fn update(&self, served: &Served, serves: Serves) {
        match (served, serves) {
            (Served::App(app), Serves::App(route)) => app.set_route(route),
            (Served::Tls(listener), Serves::Tls(sites)) => {
                listener.set_sites(sites, &self.shared);
            }
            (Served::Redirect(table), Serves::Redirect(hosts)) => table.set(hosts),
            _ => unreachable!("kinds checked above"),
        }
    }

    fn start(&self, sock: StdListener, served: Served) -> io::Result<Live> {
        let dup = sock.try_clone()?;
        sock.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(sock)?;
        let (stop, rx) = watch::channel(false);
        let done = tokio::spawn(accept_loop(
            listener,
            served.clone(),
            rx,
            self.drain,
            self.connection_limit,
            self.handshake_timeout,
        ));
        Ok(Live {
            served,
            stop,
            sock: dup,
            done,
        })
    }

    /// The listening sockets by address, for `upgrade::spawn_successor`. Valid while `self` lives.
    pub fn handover_fds(&self) -> Vec<(String, RawFd)> {
        self.lock()
            .live
            .iter()
            .map(|(a, l)| (a.clone(), l.sock.as_raw_fd()))
            .collect()
    }

    /// Stops accepting on every listener and waits until their connections drained (or the
    /// drain timeout passed). `handed_over`: a successor serves the same sockets, so they are
    /// closed but not shut down. Later `apply` calls fail.
    pub async fn shutdown(&self, handed_over: bool) {
        let lives: Vec<Live> = {
            let mut inner = self.lock();
            inner.closed = true;
            inner.live.drain().map(|(_, l)| l).collect()
        };
        let mut waits = Vec::new();
        for live in lives {
            if !handed_over {
                close_listeners(&live.sock);
            }
            let _ = live.stop.send(true);
            waits.push(live.done);
        }
        for w in waits {
            let _ = w.await;
        }
    }
}

/// Retires a route: the port refuses connections before this returns (for every descriptor
/// of the socket, a successor's copy included) and can be bound again by a later bundle; open
/// connections drain in the background.
fn retire(live: Live) {
    close_listeners(&live.sock);
    let _ = live.stop.send(true);
}

/// `shutdown(SHUT_RD)` on a listening socket resets its accept queue and leaves it unbound for
/// every descriptor.
fn close_listeners(sock: &StdListener) {
    let _ = nix::sys::socket::shutdown(sock.as_raw_fd(), nix::sys::socket::Shutdown::Read);
}

fn bind(addr: &str) -> io::Result<StdListener> {
    let sa = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address"))?;
    let sock = if sa.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    sock.set_reuseaddr(true)?;
    sock.bind(sa)?;
    sock.listen(LISTEN_BACKLOG)?.into_std()
}

async fn accept_loop(
    listener: tokio::net::TcpListener,
    served: Served,
    stop: watch::Receiver<bool>,
    drain: Duration,
    connection_limit: usize,
    handshake_timeout: Duration,
) {
    let listener = L4Listener::from(listener);
    let mut conns = JoinSet::new();
    let slots = Arc::new(tokio::sync::Semaphore::new(connection_limit));
    let mut stopped = stop.clone();
    loop {
        tokio::select! {
            biased;
            _ = async { let _ = stopped.wait_for(|v| *v).await; } => break,
            accepted = listener.accept() => match accepted {
                Ok(mut stream) => {
                    let _ = stream.set_nodelay();
                    // Past the connection limit a plain connection gets a 503 and closes; an HTTPS
                    // one closes before any handshake work.
                    let Ok(permit) = slots.clone().try_acquire_owned() else {
                        if !matches!(served, Served::Tls(_)) {
                            conns.spawn(refuse(Box::new(stream)));
                        }
                        continue;
                    };
                    let shutdown = stop.clone();
                    match &served {
                        Served::App(app) => {
                            let app = app.clone();
                            conns.spawn(async move {
                                let _permit = permit;
                                serve_connection(PlainSite(app), Box::new(stream), shutdown).await;
                            });
                        }
                        Served::Tls(tls) => {
                            let tls = tls.clone();
                            conns.spawn(async move {
                                let _permit = permit;
                                serve_tls(tls, stream, shutdown, handshake_timeout).await;
                            });
                        }
                        Served::Redirect(table) => {
                            let table = table.clone();
                            conns.spawn(async move {
                                let _permit = permit;
                                serve_redirect(table, Box::new(stream), shutdown).await;
                            });
                        }
                    }
                }
                Err(e) => {
                    if *stop.borrow() {
                        break;
                    }
                    tracing::warn!("route accept failed: {e}");
                    let emfile = e.raw_os_error() == Some(24);
                    tokio::time::sleep(Duration::from_millis(if emfile { 1000 } else { 10 })).await;
                }
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    drop(listener);
    let _ = tokio::time::timeout(drain, async { while conns.join_next().await.is_some() {} }).await;
    if !conns.is_empty() {
        tracing::info!(
            "closed {} connection(s) still open after the drain timeout",
            conns.len()
        );
    }
    conns.abort_all();
}

/// The answer to a connection past the connection limit.
async fn refuse(mut stream: pingora::protocols::Stream) {
    use tokio::io::AsyncWriteExt;
    let r = crate::response::OutboundResponse::error(
        503,
        "The connection cannot be served because Server.Concurrency limit exceeded",
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        let _ = stream.write_all(&r.wire(false, false, true, now)).await;
        let _ = stream.shutdown().await;
    })
    .await;
}
