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
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::cert_store::CertBook;
use crate::config::{Route, TlsSite};
use crate::https::{RedirectTable, RedirectTarget, TlsListener, prepare_certificates, serve_tls};
use crate::proxy::Shared;
use crate::route::{PlainSite, RouteApp, serve_connection, serve_redirect};

/// How long the connections of a retired route may drain.
pub const ROUTE_DRAIN_GRACE: Duration = Duration::from_secs(30);
/// The error of an apply that could not bind an address its bundle names, so the caller can tell it
/// from a refusal that no retry will change.
pub const BIND_ERROR: &str = "failed to bind WAF route listener";
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
    /// Resolves when the accept loop no longer accepts; taken by the first `stop_accepting`.
    accepting: Option<oneshot::Receiver<()>>,
    done: JoinHandle<()>,
}

struct Inner {
    live: HashMap<String, Live>,
    inherited: HashMap<String, StdListener>,
    first_applied: bool,
    closed: bool,
    /// The address and the error of the bind or socket setup that failed the last apply.
    bind_failure: Option<(String, io::ErrorKind)>,
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
                bind_failure: None,
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

    /// The address and the error kind that made the last `apply` fail with `BIND_ERROR`, for the
    /// caller that holds off other applies until it has read them. `None` after an apply that
    /// failed for another reason or succeeded.
    pub fn bind_failure(&self) -> Option<(String, io::ErrorKind)> {
        self.lock().bind_failure.clone()
    }

    /// The route of the app on the plain listener at `addr`.
    pub fn route(&self, addr: &str) -> Option<Arc<Route>> {
        match &self.lock().live.get(addr)?.served {
            Served::App(app) => Some(app.route()),
            _ => None,
        }
    }

    /// Makes the live listeners exactly `specs`. Every certificate is read and every new socket
    /// bound and made ready for its accept loop first; a failure changes nothing. Kept listeners
    /// get the new config in place (no reconnect), removed ones stop accepting at once and drain in
    /// the background. A listener whose address now serves another kind keeps its socket: a new
    /// accept loop starts on it, then the old one stops and drains. Must run inside the tokio
    /// runtime. The cause of an error is logged.
    pub fn apply(&self, specs: Vec<RouteSpec>) -> Result<(), String> {
        let mut inner = self.lock();
        inner.bind_failure = None;
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
        // The certificates the apps bring are collected before anything binds or switches.
        let mut certificates = HashMap::new();
        for spec in &specs {
            let Serves::Tls(sites) = &spec.serves else {
                continue;
            };
            prepare_certificates(sites, &mut certificates).map_err(|e| {
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
                    give_back(&mut inner, fresh);
                    tracing::warn!("failed to bind WAF route listener {}: {e}", spec.address);
                    inner.bind_failure = Some((spec.address.clone(), e.kind()));
                    return Err(BIND_ERROR.into());
                }
            }
        }
        // Everything that can still fail happens here, before the first change: a descriptor
        // that cannot be had must not leave an address closed or the book switched.
        let mut opened: HashMap<String, Opened> = HashMap::new();
        for spec in &specs {
            let sock = match inner.live.get(&spec.address) {
                Some(live) if live.served.is_kind_of(&spec.serves) => continue,
                Some(live) => &live.sock,
                None => &fresh[&spec.address].0,
            };
            match open(sock) {
                Ok(o) => {
                    opened.insert(spec.address.clone(), o);
                }
                Err(e) => {
                    give_back(&mut inner, fresh);
                    tracing::warn!("failed to start WAF route listener {}: {e}", spec.address);
                    inner.bind_failure = Some((spec.address.clone(), e.kind()));
                    return Err(BIND_ERROR.into());
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
            if let Some(live) = inner.live.get(&spec.address)
                && live.served.is_kind_of(&spec.serves)
            {
                self.update(&live.served, spec.serves);
                continue;
            }
            let opened = opened.remove(&spec.address).expect("opened above");
            let served = self.build(spec.serves);
            let live = self.launch(opened, served);
            // A listener that changes kind keeps its socket, so its accept queue is kept: the new
            // loop has the socket by now, and the old one drains its connections.
            if let Some(old) = inner.live.insert(spec.address, live) {
                let _ = old.stop.send(true);
            }
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

    /// Starts the accept loop of a new listener.
    fn launch(&self, (listener, dup): Opened, served: Served) -> Live {
        let (stop, rx) = watch::channel(false);
        let (ended, accepting) = oneshot::channel();
        let done = tokio::spawn(accept_loop(
            listener,
            served.clone(),
            rx,
            self.drain,
            self.connection_limit,
            self.handshake_timeout,
            ended,
        ));
        Live {
            served,
            stop,
            sock: dup,
            accepting: Some(accepting),
            done,
        }
    }

    /// The listening sockets by address, for `upgrade::spawn_successor`. Valid while `self` lives.
    pub fn handover_fds(&self) -> Vec<(String, RawFd)> {
        self.lock()
            .live
            .iter()
            .map(|(a, l)| (a.clone(), l.sock.as_raw_fd()))
            .collect()
    }

    /// Stops accepting on every listener and returns once no accept loop of this process accepts
    /// any more; connections already accepted go on until `shutdown`. `handed_over`: a successor
    /// serves the same sockets, so they are closed but not shut down. Later `apply` calls fail.
    pub async fn stop_accepting(&self, handed_over: bool) {
        let receivers: Vec<_> = {
            let mut inner = self.lock();
            inner.closed = true;
            inner
                .live
                .values_mut()
                .filter_map(|live| {
                    if !handed_over {
                        close_listeners(&live.sock);
                    }
                    let _ = live.stop.send(true);
                    live.accepting.take()
                })
                .collect()
        };
        for accepting in receivers {
            // An error is a loop that ended another way: it accepts no more either.
            let _ = accepting.await;
        }
    }

    /// Stops accepting on every listener and waits until their connections drained (or the
    /// drain timeout passed). `handed_over`: as for `stop_accepting`. Later `apply` calls fail.
    pub async fn shutdown(&self, handed_over: bool) {
        self.stop_accepting(handed_over).await;
        let lives: Vec<Live> = self.lock().live.drain().map(|(_, l)| l).collect();
        for live in lives {
            let _ = live.done.await;
        }
    }
}

/// What a new accept loop needs from a socket: its tokio listener, and the duplicate that `Live`
/// keeps for a hand-over and for the next kind change.
type Opened = (tokio::net::TcpListener, StdListener);

/// Descriptors for a new accept loop on `sock`, which stays open and unchanged.
fn open(sock: &StdListener) -> io::Result<Opened> {
    let dup = sock.try_clone()?;
    let accepting = sock.try_clone()?;
    accepting.set_nonblocking(true)?;
    Ok((tokio::net::TcpListener::from_std(accepting)?, dup))
}

/// Puts the sockets a predecessor handed over back; freshly bound ones close.
fn give_back(inner: &mut Inner, fresh: HashMap<String, (StdListener, bool)>) {
    for (addr, (s, inherited)) in fresh {
        if inherited {
            inner.inherited.insert(addr, s);
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
    ended: oneshot::Sender<()>,
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
    let _ = ended.send(());
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
