//! Per-app listeners added, changed and removed at runtime.
//!
//! Pingora's `Server` fixes its services and listeners before `run_forever`, so the accept loops
//! are our own: each listener is a tokio socket whose connections go through Pingora's
//! `route::serve_connection` (head guard, Pingora's HTTP/1 parsing, keep-alive loop) into the route's `RouteApp`.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{TcpListener as StdListener, ToSocketAddrs};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pingora::protocols::l4::listener::Listener as L4Listener;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::config::Route;
use crate::proxy::Shared;
use crate::route::RouteApp;

/// How long the connections of a retired route may drain.
pub const ROUTE_DRAIN_GRACE: Duration = Duration::from_secs(30);
const LISTEN_BACKLOG: u32 = 4096;

pub struct RouteSpec {
    /// `listen_host:listen_port` (an IPv6 host in brackets); also the key a reload hands sockets over by.
    pub address: String,
    pub route: Arc<Route>,
}

struct Live {
    app: Arc<RouteApp>,
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
    inner: Mutex<Inner>,
}

impl RouteManager {
    /// `inherited`: sockets a predecessor handed over (`upgrade::inherited_listeners`).
    pub(crate) fn new(
        shared: Arc<Shared>,
        drain: Duration,
        inherited: HashMap<String, StdListener>,
    ) -> Self {
        RouteManager {
            shared,
            drain,
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

    pub fn route(&self, addr: &str) -> Option<Arc<Route>> {
        self.lock().live.get(addr).map(|l| l.app.route())
    }

    /// Makes the live listeners exactly `specs`. Every new socket is bound first; a bind
    /// failure changes nothing. Kept listeners get the new config in place (no reconnect),
    /// removed ones stop accepting at once and drain in the background. Must run inside the
    /// tokio runtime. The cause of an error is logged.
    pub fn apply(&self, specs: Vec<RouteSpec>) -> Result<(), String> {
        let mut inner = self.lock();
        if inner.closed {
            return Err("agent is shutting down".into());
        }
        let wanted: HashSet<String> = specs.iter().map(|s| s.address.clone()).collect();
        if wanted.len() != specs.len() {
            return Err("duplicate listener in WAF bundle".into());
        }
        // The listener limits and timeouts cannot change in place.
        for spec in &specs {
            if let Some(live) = inner.live.get(&spec.address)
                && live.app.route().listener_limits() != spec.route.listener_limits()
            {
                return Err(
                    "route listener limits or timeouts changed; agent restart required".into(),
                );
            }
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
            .filter_map(|l| l.app.route().fcgi().cloned())
            .collect();
        for spec in specs {
            match inner.live.get(&spec.address) {
                Some(live) => live.app.set_route(spec.route),
                None => {
                    let (sock, _) = fresh.remove(&spec.address).expect("bound above");
                    let live = self.start(sock, spec.route).map_err(|e| {
                        tracing::warn!("failed to start WAF route listener {}: {e}", spec.address);
                        "failed to bind WAF route listener".to_string()
                    })?;
                    inner.live.insert(spec.address, live);
                }
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
            .filter_map(|l| l.app.route().fcgi().cloned())
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

    fn start(&self, sock: StdListener, route: Arc<Route>) -> io::Result<Live> {
        let dup = sock.try_clone()?;
        sock.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(sock)?;
        let (stop, rx) = watch::channel(false);
        let app = Arc::new(RouteApp::new(route, self.shared.clone()));
        let done = tokio::spawn(accept_loop(listener, app.clone(), rx, self.drain));
        Ok(Live {
            app,
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
    app: Arc<RouteApp>,
    stop: watch::Receiver<bool>,
    drain: Duration,
) {
    let listener = L4Listener::from(listener);
    let mut conns = JoinSet::new();
    let slots = Arc::new(tokio::sync::Semaphore::new(crate::route::CONNECTION_LIMIT));
    let mut stopped = stop.clone();
    loop {
        tokio::select! {
            biased;
            _ = async { let _ = stopped.wait_for(|v| *v).await; } => break,
            accepted = listener.accept() => match accepted {
                Ok(mut stream) => {
                    let _ = stream.set_nodelay();
                    // Past the connection limit the connection gets a 503 and closes.
                    let Ok(permit) = slots.clone().try_acquire_owned() else {
                        conns.spawn(refuse(Box::new(stream)));
                        continue;
                    };
                    let (app, shutdown) = (app.clone(), stop.clone());
                    conns.spawn(async move {
                        let _permit = permit;
                        crate::route::serve_connection(app, Box::new(stream), shutdown).await;
                    });
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
