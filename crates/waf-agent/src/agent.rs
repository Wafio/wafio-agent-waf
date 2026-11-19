//! A WAF bundle turned into executors and app specs, published to the proxy
//! (`wafio_proxy::Proxy::apply`).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use wafio_agent_pages::goodbot::VerifiedBotChecker;
use wafio_application::RateLimitStore;
use wafio_application::blocklist::BlockStore;
use wafio_control::{BundleError, BundleSink};
use wafio_engine_rules::json_decode;
use wafio_engine_rules::{CustomGuiRule, CustomScriptRule, TuningRule};
use wafio_proxy::{AppAnalysisSetup, AppSpec, TlsSite};

use crate::bundle::{Bundle, BundleApp, UnblockEntry, decode_bundle};
use crate::executor::{BaseExecutor, Stores, executor_for_rules};
use crate::ready::Ready;

/// The proxy side (`wafio_proxy::Proxy::apply`): builds every route, binds every new
/// address, then switches; any error changes nothing. A trait so tests can fake it.
pub trait RouteSink: Send + Sync + 'static {
    fn apply(&self, apps: Vec<AppSpec>) -> Result<(), String>;
}

impl RouteSink for wafio_proxy::Proxy {
    fn apply(&self, apps: Vec<AppSpec>) -> Result<(), String> {
        wafio_proxy::Proxy::apply(self, apps)
    }
}

#[derive(Default)]
struct State {
    /// The shared executor: None until the first configuration bundle.
    shared: Option<Arc<AppAnalysisSetup>>,
    /// The per-app executors with the stores each app's executor uses.
    per_app: HashMap<String, (Arc<AppAnalysisSetup>, Stores)>,
    /// Generation and agent id of the configuration in force.
    generation: i64,
    agent_id: String,
    closed: bool,
}

/// The agent state minus the request path (the proxy crate's).
pub struct Agent {
    /// The startup executor; its stores are the shared ones.
    base: BaseExecutor,
    base_stores: Stores,
    state: Mutex<State>,
    routes: Arc<dyn RouteSink>,
    good_bots: Arc<VerifiedBotChecker>,
    ready: Arc<Ready>,
    /// The apps the agent also serves over HTTPS itself, by app id (the local TLS sites file).
    tls_sites: HashMap<String, TlsSite>,
}

fn apply_error(s: &str) -> BundleError {
    BundleError::Apply(s.to_string())
}

pub fn format_host_port(host: &str, port: i64) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

impl Agent {
    pub fn new(
        base: BaseExecutor,
        base_stores: Stores,
        routes: Arc<dyn RouteSink>,
        good_bots: Arc<VerifiedBotChecker>,
        ready: Arc<Ready>,
    ) -> Agent {
        Agent {
            base,
            base_stores,
            state: Mutex::new(State::default()),
            routes,
            good_bots,
            ready,
            tls_sites: HashMap::new(),
        }
    }

    /// The apps served over HTTPS by the agent: an app in the map gets its `TlsSite`, one that is
    /// not behaves as the bundle says.
    pub fn with_tls_sites(mut self, sites: HashMap<String, TlsSite>) -> Agent {
        self.tls_sites = sites;
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The shared executor (None before the first bundle).
    pub fn shared_executor(&self) -> Option<Arc<AppAnalysisSetup>> {
        self.lock().shared.clone()
    }

    /// `perAppExec[app_id]`.
    pub fn app_executor(&self, app_id: &str) -> Option<Arc<AppAnalysisSetup>> {
        self.lock().per_app.get(app_id).map(|(e, _)| e.clone())
    }

    /// The app ids with an executor (sorted).
    pub fn app_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.lock().per_app.keys().cloned().collect();
        v.sort();
        v
    }

    /// The stores an app's executor uses (the shared ones for `None`).
    pub fn stores(&self, app_id: Option<&str>) -> Option<Stores> {
        match app_id {
            None => Some(self.base_stores.clone()),
            Some(id) => self.lock().per_app.get(id).map(|(_, s)| s.clone()),
        }
    }

    /// (generation, agent_id) of the configuration in force.
    pub fn generation(&self) -> (i64, String) {
        let st = self.lock();
        (st.generation, st.agent_id.clone())
    }

    /// Later bundles are refused.
    pub fn close(&self) {
        self.lock().closed = true;
    }

    /// Every store in use: the shared (startup) ones and each app's.
    fn all_stores(&self) -> Vec<Stores> {
        let st = self.lock();
        std::iter::once(self.base_stores.clone())
            .chain(st.per_app.values().map(|(_, s)| s.clone()))
            .collect()
    }

    /// Drops expired entries from every store (every 2 minutes).
    pub fn sweep_expired_stores(&self) {
        let (now, wall) = (Instant::now(), SystemTime::now());
        for s in self.all_stores() {
            s.rate.cleanup_expired(now);
            s.block.cleanup_expired(wall);
        }
    }

    /// Every executor's stores, shared ones included.
    fn release_unblocked_entries(&self, entries: &[UnblockEntry]) {
        if entries.is_empty() {
            return;
        }
        let stores = self.all_stores();
        for ue in entries {
            for s in &stores {
                match ue.type_.as_str() {
                    "ratelimit" => s.rate.unblock(ue.scope.as_bytes(), ue.key.as_bytes()),
                    "login_scope" => s.rate.clear_login_scope(ue.scope.as_bytes()),
                    "blockpolicy" => s.block.clear_block(ue.key.as_bytes()),
                    _ => {}
                }
            }
        }
        tracing::info!("[waf-agent] processed {} unblock entries", entries.len());
    }

    pub fn install_bundle(&self, b: &Bundle) -> Result<(), BundleError> {
        // Validate the complete management batch before clearing any state.
        for e in &b.unblock_entries {
            match e.type_.as_str() {
                "ratelimit" if e.scope.is_empty() || e.key.is_empty() => {
                    return Err(apply_error("invalid rate-limit unblock identity"));
                }
                "login_scope" if e.scope.is_empty() => {
                    return Err(apply_error("invalid login unblock scope"));
                }
                "blockpolicy" if e.key.is_empty() => {
                    return Err(apply_error("invalid block-policy unblock key"));
                }
                "ratelimit" | "login_scope" | "blockpolicy" => {}
                _ => return Err(apply_error("unsupported unblock command")),
            }
        }
        if b.management_only {
            self.release_unblocked_entries(&b.unblock_entries);
            return Ok(());
        }
        // One apply at a time; the proxy call happens under it too.
        let mut st = self.lock();
        // Generations are ordered only within one agent identity.
        if b.generation > 0 && b.generation < st.generation && b.agent_id == st.agent_id {
            return Err(apply_error("stale WAF bundle generation"));
        }
        let rules: &[u8] = if b.rules_json.is_empty() {
            wafio_engine_rules::builtin_rules_json()
        } else {
            &b.rules_json
        };
        let (shared, _) =
            executor_for_rules(&self.base, rules, &b.project_id, Some(&self.base_stores))
                .map_err(BundleError::Apply)?;
        let shared = Arc::new(shared);
        let mut executors: HashMap<String, (Arc<AppAnalysisSetup>, Stores)> = HashMap::new();
        let mut specs: Vec<AppSpec> = Vec::new();
        let mut addresses: HashSet<String> = HashSet::new();
        let mut unbindable = false;
        let mut with_scripts = 0u64;
        for app in &b.apps {
            if executors.contains_key(&app.app_id) {
                return Err(apply_error("duplicate app in WAF bundle"));
            }
            let app_rules = if wafio_agent_io::ws_config::is_empty_rules_json(&app.rules_json) {
                rules
            } else {
                &app.rules_json
            };
            let prior = st.per_app.get(&app.app_id).map(|(_, s)| s.clone());
            let (mut exec, stores) =
                executor_for_rules(&self.base, app_rules, &b.project_id, prior.as_ref())
                    .map_err(BundleError::Apply)?;
            if exec.challenge.is_none()
                && let Some(c) = &shared.challenge
                && c.enabled
            {
                exec.challenge = Some(c.clone());
            }
            let (gui, script, tuning) = decode_custom_rules(app);
            let (gui, tuning) = wafio_engine_rules::retain_usable_regex_rules(gui, tuning);
            exec.analyze.custom_gui_rules = gui;
            let (script, runner) = crate::script_rules::compile(&app.app_id, script);
            with_scripts += u64::from(script.iter().any(|r| r.enabled));
            exec.analyze.custom_script_rules = script;
            exec.analyze.script_runner = Some(runner);
            exec.analyze.custom_tuning_rules = tuning;
            let exec = Arc::new(exec);
            executors.insert(app.app_id.clone(), (exec.clone(), stores));
            let spec = app_spec(app, exec, self.tls_sites.get(&app.app_id).cloned());
            // The route is built here, so a bad route fails before later apps are built.
            if let Err(e) = wafio_proxy::config::build_route(&spec) {
                tracing::info!("[waf-bundle] {e}");
                return Err(apply_error("invalid app route in WAF bundle"));
            }
            if app.listen_port > 0 {
                let host = if app.listen_host.is_empty() {
                    "0.0.0.0"
                } else {
                    &app.listen_host
                };
                if !addresses.insert(format_host_port(host, app.listen_port)) {
                    return Err(apply_error("duplicate listener in WAF bundle"));
                }
                unbindable |= app.listen_port > i64::from(u16::MAX);
            }
            specs.push(spec);
        }
        if st.closed {
            return Err(apply_error("agent is shutting down"));
        }
        if unbindable {
            // Binding refuses the port when the sockets are reserved.
            return Err(apply_error("failed to bind WAF route listener"));
        }
        self.routes.apply(specs).map_err(BundleError::Apply)?;
        crate::script_rules::set_apps_with_script_rules(with_scripts);
        st.shared = Some(shared);
        st.per_app = executors;
        st.generation = b.generation;
        st.agent_id = b.agent_id.clone();
        drop(st);
        if !b.good_bot_cidrs.is_empty()
            && let Some(msg) = self.good_bots.load_ranges_from_cidrs(&b.good_bot_cidrs)
        {
            tracing::info!("{msg}");
        }
        self.release_unblocked_entries(&b.unblock_entries);
        self.ready.signal();
        Ok(())
    }
}

/// The `AppSpec` of a bundle app (`listen_port` ≤ 0 = no listener; > 65535 is refused by
/// `install_bundle` before this is used).
fn app_spec(app: &BundleApp, executor: Arc<AppAnalysisSetup>, tls: Option<TlsSite>) -> AppSpec {
    AppSpec {
        app_id: app.app_id.clone(),
        listen_host: app.listen_host.clone(),
        listen_port: u16::try_from(app.listen_port.max(0)).unwrap_or(0),
        upstream: app.upstream.clone(),
        mode: app.mode.clone(),
        proxy_config: app.proxy_config.clone(),
        rules_json: app.rules_json.clone(),
        fcgi_doc_root: app.fcgi_doc_root.clone(),
        fcgi_index: app.fcgi_index.clone(),
        maintenance: app.maintenance.clone(),
        analysis: executor,
        tls,
    }
}

/// The per-app custom rules: each raw rule that decodes cleanly is kept.
fn decode_custom_rules(
    app: &BundleApp,
) -> (Vec<CustomGuiRule>, Vec<CustomScriptRule>, Vec<TuningRule>) {
    fn each<T: Default>(
        raws: &[Vec<u8>],
        dec: fn(
            &mut json_decode::DecodeTrace,
            &json_decode::Value,
            &mut T,
        ) -> Result<(), json_decode::JsonDecodeError>,
    ) -> Vec<T> {
        raws.iter()
            .filter_map(|raw| {
                let mut r = T::default();
                json_decode::decode_into(raw, &mut r, dec).ok().map(|_| r)
            })
            .collect()
    }
    (
        each(
            &app.custom_gui_rules,
            wafio_engine_rules::decode_custom_gui_rule,
        ),
        each(
            &app.custom_script_rules,
            wafio_engine_rules::decode_custom_script_rule,
        ),
        each(
            &app.custom_tuning_rules,
            wafio_engine_rules::decode_tuning_rule,
        ),
    )
}

/// The `BundleSink` the control link calls (on a blocking thread).
pub struct Sink(pub Arc<Agent>);

impl BundleSink for Sink {
    fn apply(&self, bundle_json: &[u8], generation: i64) -> Result<(), BundleError> {
        let mut b = decode_bundle(bundle_json).map_err(BundleError::Decode)?;
        b.generation = generation;
        self.0.install_bundle(&b)
    }

    fn check(&self, bundle_json: &[u8]) -> Result<(), String> {
        decode_bundle(bundle_json).map(|_| ())
    }
}

#[cfg(test)]
mod tests;
