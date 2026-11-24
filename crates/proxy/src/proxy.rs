//! The inline proxy: process-wide dependencies plus the per-app listeners.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::TcpListener as StdListener;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Duration;

use pingora::connectors::TransportConnector;
use pingora::connectors::http::Connector;
use wafio_agent_pages::challenge_handler::CaptchaVerifier;
use wafio_agent_pages::goodbot::VerifiedBotChecker;
use wafio_agent_pages::iprep::ReputationChecker;

use crate::cert_store::CertBook;
use crate::config::{AppSpec, Route, TlsSite, build_route};
use crate::decision::DecisionSink;
use crate::edge_stats::{CompressionCounters, EdgeStats};
use crate::https::{RedirectTarget, TLS_HANDSHAKE_TIMEOUT};
use crate::listeners::{ROUTE_DRAIN_GRACE, RouteManager, RouteSpec, Serves};
use crate::route::CONNECTION_LIMIT;

/// Process-wide dependencies, set once at start.
pub struct ProxyOptions {
    /// Every decision event, unredacted. Must not block.
    pub decisions: DecisionSink,
    /// FireHOL levels (`--iprep-level1-file` … or downloads); `None` = no lookups.
    pub ip_rep: Option<Arc<ReputationChecker>>,
    /// Search-engine crawler ranges (the binary refreshes it and loads `Bundle.GoodBotCIDRs`).
    pub good_bots: Option<Arc<VerifiedBotChecker>>,
    /// Turnstile / hCaptcha siteverify client, called on a blocking thread;
    /// `None` = every CAPTCHA token fails verification.
    pub captcha: Option<Arc<dyn CaptchaVerifier + Send + Sync>>,
    /// Sockets handed over by a predecessor (`upgrade::inherited_listeners`).
    pub inherited: HashMap<String, StdListener>,
    /// Drain timeout of a removed or shut down route.
    pub drain_timeout: Duration,
    /// How long a client of an HTTPS listener has for its first TLS record and the handshake.
    pub tls_handshake_timeout: Duration,
    /// Connections one listener serves at once; more are closed (a plain listener answers 503).
    pub connection_limit: usize,
}

impl ProxyOptions {
    pub fn new(decisions: DecisionSink) -> ProxyOptions {
        ProxyOptions {
            decisions,
            ip_rep: None,
            good_bots: None,
            captcha: None,
            inherited: HashMap::new(),
            drain_timeout: ROUTE_DRAIN_GRACE,
            tls_handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
            connection_limit: CONNECTION_LIMIT,
        }
    }
}

/// What every route handler shares.
pub(crate) struct Shared {
    pub decisions: DecisionSink,
    pub ip_rep: Option<Arc<ReputationChecker>>,
    pub good_bots: Option<Arc<VerifiedBotChecker>>,
    pub captcha: Option<Arc<dyn CaptchaVerifier + Send + Sync>>,
    pub connector: Connector,
    pub transport: TransportConnector,
    /// The certificates of every TLS listener, by app.
    pub book: Arc<CertBook>,
    /// What the edge parts of each app count.
    pub edge: EdgeStats,
}

pub struct Proxy {
    manager: RouteManager,
    shared: Arc<Shared>,
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

impl Proxy {
    pub fn new(opts: ProxyOptions) -> Proxy {
        let shared = Arc::new(Shared {
            decisions: opts.decisions,
            ip_rep: opts.ip_rep,
            good_bots: opts.good_bots,
            captcha: opts.captcha,
            connector: Connector::new(None),
            transport: TransportConnector::new(None),
            book: Arc::default(),
            edge: EdgeStats::default(),
        });
        Proxy {
            shared: shared.clone(),
            manager: RouteManager::new(
                shared,
                opts.drain_timeout,
                opts.tls_handshake_timeout,
                opts.connection_limit,
                opts.inherited,
            ),
        }
    }

    /// Makes the live listeners exactly the bundle's apps with a listen port, plus the HTTPS and
    /// redirect listeners of the apps that have a `tls` site; such an app opens no plain listener
    /// of its own. Every route is built, every certificate read and every new socket bound first;
    /// any error changes nothing. Kept
    /// listeners switch to the new route for their next request, removed ones stop accepting at
    /// once and drain; FastCGI pools of replaced routes are closed, and a request still running
    /// there finishes on its own connection. The binary publishes its executors (stores for the
    /// next bundle) only after `Ok`. Must run inside the tokio runtime.
    pub fn apply(&self, apps: Vec<AppSpec>) -> Result<(), String> {
        let mut specs = Vec::new();
        let mut addresses = HashSet::new();
        let mut proxy_cfgs = Vec::new();
        let mut https: BTreeMap<String, Vec<(Arc<Route>, TlsSite)>> = BTreeMap::new();
        let mut redirects: BTreeMap<String, HashMap<String, RedirectTarget>> = BTreeMap::new();
        for app in &apps {
            let route = build_route(app).map_err(|e| {
                tracing::warn!("[waf-agent] {e}");
                "invalid app route in WAF bundle".to_string()
            })?;
            let route = Arc::new(route);
            proxy_cfgs.push(route.proxy_config.clone());
            if let Some(site) = &app.tls {
                let Some(port) = site
                    .listen
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse().ok())
                else {
                    tracing::warn!(
                        "[waf-agent] app {}: TLS listen address has no port",
                        app.app_id
                    );
                    return Err("invalid TLS site settings".into());
                };
                if let Some(address) = &site.redirect_listen {
                    let hosts = redirects.entry(address.clone()).or_default();
                    let target = RedirectTarget {
                        port,
                        app_id: app.app_id.clone(),
                        canonical_host: site.canonical_host.clone(),
                    };
                    for host in &site.hosts {
                        let other = hosts.insert(host.to_ascii_lowercase(), target.clone());
                        if other.is_some_and(|other| other != target) {
                            tracing::warn!(
                                "[waf-agent] app {}: host {host} redirects to two places",
                                app.app_id
                            );
                            return Err("invalid TLS site settings".into());
                        }
                    }
                }
                https
                    .entry(site.listen.clone())
                    .or_default()
                    .push((route.clone(), site.clone()));
                // The bundle's address is not served: the app answers on its HTTPS listener only.
                continue;
            }
            if app.listen_port == 0 {
                continue;
            }
            let host = if app.listen_host.is_empty() {
                "0.0.0.0"
            } else {
                app.listen_host.as_str()
            };
            let addr = format_host_port(host, app.listen_port);
            if !addresses.insert(addr.clone()) {
                return Err("duplicate listener in WAF bundle".into());
            }
            specs.push(RouteSpec {
                address: addr,
                serves: Serves::App(route),
            });
        }
        specs.extend(https.into_iter().map(|(address, sites)| RouteSpec {
            address,
            serves: Serves::Tls(sites),
        }));
        specs.extend(redirects.into_iter().map(|(address, hosts)| RouteSpec {
            address,
            serves: Serves::Redirect(hosts),
        }));
        self.manager.apply(specs)?;
        wafio_agent_io::ip_jail_guard::install_trusted_proxy_configs(proxy_cfgs);
        self.shared
            .edge
            .retain(&apps.iter().map(|a| a.app_id.as_str()).collect());
        Ok(())
    }

    /// What the compression of `app_id` did over the last hour; `None` for an app that never
    /// compressed or counted anything since this process started.
    pub fn compression_counters(&self, app_id: &str) -> Option<CompressionCounters> {
        let now = u64::try_from(crate::decision::now_unix()).unwrap_or(0);
        Some(self.shared.edge.get(app_id)?.compression_counters(now))
    }

    /// The certificates the TLS listeners serve, by app id, and the validation answers they give.
    pub fn certificates(&self) -> Arc<CertBook> {
        self.manager.certificates()
    }

    /// The address and the error kind behind the last `apply` that failed with
    /// `listeners::BIND_ERROR`. Read it before the next apply.
    pub fn bind_failure(&self) -> Option<(String, std::io::ErrorKind)> {
        self.manager.bind_failure()
    }

    /// Live listen addresses.
    pub fn addresses(&self) -> Vec<String> {
        self.manager.addresses()
    }

    /// The route currently served on `addr` (tests, diagnostics).
    pub fn route(&self, addr: &str) -> Option<Arc<Route>> {
        self.manager.route(addr)
    }

    /// The listening sockets by address, for `upgrade::spawn_successor`.
    pub fn handover_fds(&self) -> Vec<(String, RawFd)> {
        self.manager.handover_fds()
    }

    /// Stops accepting and returns once no accept loop of this process accepts any more;
    /// connections already accepted go on until `shutdown`. Later `apply` calls fail.
    /// `handed_over`: a successor serves the same sockets (close, never shut down).
    pub async fn stop_accepting(&self, handed_over: bool) {
        self.manager.stop_accepting(handed_over).await;
    }

    /// Stops accepting and drains; later `apply` calls fail.
    /// `handed_over`: a successor serves the same sockets (close, never shut down).
    pub async fn shutdown(&self, handed_over: bool) {
        self.manager.shutdown(handed_over).await;
    }
}
