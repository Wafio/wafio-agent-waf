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

use crate::cert_store::CERT_POLL_INTERVAL;
use crate::config::{AppSpec, Route, TlsSite, build_route};
use crate::decision::DecisionSink;
use crate::listeners::{ROUTE_DRAIN_GRACE, RouteManager, RouteSpec, Serves};

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
    /// How often the certificate files of an HTTPS listener are checked for a change.
    pub cert_poll_interval: Duration,
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
            cert_poll_interval: CERT_POLL_INTERVAL,
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
}

pub struct Proxy {
    manager: RouteManager,
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
        });
        Proxy {
            manager: RouteManager::new(
                shared,
                opts.drain_timeout,
                opts.cert_poll_interval,
                opts.inherited,
            ),
        }
    }

    /// Makes the live listeners exactly the bundle's apps with a listen port, plus the HTTPS and
    /// redirect listeners of the apps that have a `tls` site. Every route is built, every
    /// certificate read and every new socket bound first; any error changes nothing. Kept
    /// listeners switch to the new route for their next request, removed ones stop accepting at
    /// once and drain;
    /// FastCGI pools of replaced routes are closed. The binary publishes its executors (stores
    /// for the next bundle) only after `Ok`. Must run inside the tokio runtime.
    pub fn apply(&self, apps: Vec<AppSpec>) -> Result<(), String> {
        let mut specs = Vec::new();
        let mut addresses = HashSet::new();
        let mut proxy_cfgs = Vec::new();
        let mut https: BTreeMap<String, Vec<(Arc<Route>, TlsSite)>> = BTreeMap::new();
        let mut redirects: BTreeMap<String, HashMap<String, u16>> = BTreeMap::new();
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
                    for host in &site.hosts {
                        let other = hosts.insert(host.to_ascii_lowercase(), port);
                        if other.is_some_and(|other| other != port) {
                            tracing::warn!(
                                "[waf-agent] app {}: host {host} redirects to two HTTPS ports",
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
        Ok(())
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

    /// Stops accepting and drains; later `apply` calls fail.
    /// `handed_over`: a successor serves the same sockets (close, never shut down).
    pub async fn shutdown(&self, handed_over: bool) {
        self.manager.shutdown(handed_over).await;
    }
}
