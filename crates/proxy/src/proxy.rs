//! The inline proxy: process-wide dependencies plus the per-app listeners.

use std::collections::{HashMap, HashSet};
use std::net::TcpListener as StdListener;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Duration;

use pingora::connectors::TransportConnector;
use pingora::connectors::http::Connector;
use wafio_agent_pages::challenge_handler::CaptchaVerifier;
use wafio_agent_pages::goodbot::VerifiedBotChecker;
use wafio_agent_pages::iprep::ReputationChecker;

use crate::config::{AppSpec, Route, build_route};
use crate::decision::DecisionSink;
use crate::listeners::{ROUTE_DRAIN_GRACE, RouteManager, RouteSpec};

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
            manager: RouteManager::new(shared, opts.drain_timeout, opts.inherited),
        }
    }

    /// Makes the live listeners exactly the bundle's apps with a listen port. Every route is
    /// built and every new socket bound first; any error changes nothing. Kept listeners switch
    /// to the new route for their next request, removed ones stop accepting at once and drain;
    /// FastCGI pools of replaced routes are closed. The binary publishes its executors (stores
    /// for the next bundle) only after `Ok`. Must run inside the tokio runtime.
    pub fn apply(&self, apps: Vec<AppSpec>) -> Result<(), String> {
        let mut specs = Vec::new();
        let mut addresses = HashSet::new();
        let mut proxy_cfgs = Vec::new();
        for app in &apps {
            let route = build_route(app).map_err(|e| {
                tracing::warn!("[waf-agent] {e}");
                "invalid app route in WAF bundle".to_string()
            })?;
            proxy_cfgs.push(route.proxy_config.clone());
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
                route: Arc::new(route),
            });
        }
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
