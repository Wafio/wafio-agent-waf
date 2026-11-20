//! A WAF bundle turned into executors and app specs, published to the proxy
//! (`wafio_proxy::Proxy::apply`).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use wafio_agent_pages::goodbot::VerifiedBotChecker;
use wafio_application::RateLimitStore;
use wafio_application::blocklist::BlockStore;
use wafio_control::{AckCode, BundleError, BundleSink, CertificateInstall, CertificateSink};
use wafio_engine_rules::json_decode;
use wafio_engine_rules::{CustomGuiRule, CustomScriptRule, TuningRule};
use wafio_proxy::{AppAnalysisSetup, AppSpec, TlsSite};

use crate::bundle::{Bundle, BundleApp, UnblockEntry, decode_bundle};
use crate::executor::{BaseExecutor, Stores, executor_for_rules};
use crate::ready::Ready;
use crate::tls::dir::KeyDir;
use crate::tls::entry::Settings;
use crate::tls::{Applied, Keys, book_entry};

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
    /// The key directory and what the apps with a `tls` object are served with; `None` when the
    /// agent has no usable key directory, which leaves the `tls` objects unread.
    tls: Option<Keys>,
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
        }
    }

    /// The agent serves the apps whose bundle entry has a `tls` object over HTTPS, from the
    /// certificates in `dir`. Without it the object is ignored and the app is served as its bundle
    /// says.
    pub fn with_key_dir(self, dir: KeyDir) -> Agent {
        self.lock().tls = Some(Keys::new(dir));
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

    /// Whether the agent has a key directory and this process is the one that writes in it.
    pub fn holds_keys(&self) -> bool {
        self.lock().tls.as_ref().is_some_and(Keys::holds_lock)
    }

    /// Whether the agent has a key directory, which it may be waiting for the lock of.
    pub fn waits_for_keys(&self) -> bool {
        self.lock().tls.as_ref().is_some_and(|k| !k.holds_lock())
    }

    /// Takes the key directory lock if the process that held it let go, and then does what could
    /// not be done without it. Returns whether there is nothing left to wait for: this process
    /// holds the lock, or it has no key directory, or it is closing and leaves the lock to the
    /// process that replaces it. Blocking: it may write.
    pub fn take_over_keys(&self) -> bool {
        let mut st = self.lock();
        let closed = st.closed;
        match st.tls.as_mut() {
            Some(keys) if !closed => keys.take_over(),
            _ => true,
        }
    }

    /// Lets go of the key directory lock for the process that takes over. Call it after `close`:
    /// from then on this process applies nothing and so writes nothing.
    pub fn release_keys(&self) {
        if let Some(keys) = self.lock().tls.as_mut() {
            keys.release();
        }
    }

    /// The apply lock. While it is held no bundle is applied, no certificate is switched and
    /// nothing is written in the key directory by any other part of the process, so what its
    /// holder read from the bundle in force is still true when it commits a change that depends on
    /// it.
    pub fn apply_lock(&self) -> ApplyLock<'_> {
        ApplyLock { st: self.lock() }
    }

    /// The apps of the bundle in force that have a `tls` object, by app id: their checked
    /// settings and the file each is served from.
    pub fn tls_apps(&self) -> Vec<(String, Settings, Option<String>)> {
        let st = self.lock();
        let mut apps: Vec<_> = st.tls.as_ref().map_or_else(Vec::new, |keys| {
            keys.applied()
                .iter()
                .map(|(id, a)| {
                    let file = a.served.as_ref().map(|s| s.file.clone());
                    (id.clone(), a.settings.clone(), file)
                })
                .collect()
        });
        apps.sort_by(|a, b| a.0.cmp(&b.0));
        apps
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
        // The `tls` objects are checked and their certificates read before the first app is built;
        // an object that fails a check refuses the whole bundle, as an invalid route does.
        let tls = match &st.tls {
            Some(keys) => keys.prepare(&b.apps).map_err(|rejected| {
                tracing::warn!(
                    "[waf-bundle] app {:?}: invalid TLS entry, {}",
                    rejected.app_id.chars().take(64).collect::<String>(),
                    rejected.refusal
                );
                apply_error("invalid TLS site settings")
            })?,
            None => HashMap::new(),
        };
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
            let spec = app_spec(app, exec, tls.get(&app.app_id).map(tls_site));
            // The route is built here, so a bad route fails before later apps are built.
            if let Err(e) = wafio_proxy::config::build_route(&spec) {
                tracing::info!("[waf-bundle] {e}");
                return Err(apply_error("invalid app route in WAF bundle"));
            }
            // An app with an HTTPS site opens no listener at its bundle address, so that address
            // is neither checked for a duplicate nor for a port that cannot be bound.
            if app.listen_port > 0 && spec.tls.is_none() {
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
        self.routes.apply(specs).map_err(|e| {
            if e == wafio_proxy::listeners::BIND_ERROR {
                BundleError::Bind(e)
            } else {
                BundleError::Apply(e)
            }
        })?;
        crate::script_rules::set_apps_with_script_rules(with_scripts);
        st.shared = Some(shared);
        st.per_app = executors;
        st.generation = b.generation;
        st.agent_id = b.agent_id.clone();
        if let Some(keys) = st.tls.as_mut() {
            keys.commit(tls);
        }
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

/// The apply lock of an agent (`Agent::apply_lock`).
pub struct ApplyLock<'a> {
    st: std::sync::MutexGuard<'a, State>,
}

impl ApplyLock<'_> {
    /// The checked `tls` settings of `app_id` in the bundle in force; `None` for an app that is not
    /// served over HTTPS by the agent, or that is not in the bundle.
    pub fn settings(&self, app_id: &str) -> Option<&Settings> {
        Some(&self.st.tls.as_ref()?.applied().get(app_id)?.settings)
    }
}

/// The proxy's view of an app's `tls` object: where it listens and which certificate it brings.
fn tls_site(applied: &Applied) -> TlsSite {
    TlsSite {
        listen: applied.settings.listen.clone(),
        hosts: applied.settings.hosts.clone(),
        certificate: applied.served.as_ref().map(book_entry),
        redirect_listen: applied.settings.redirect_listen.clone(),
    }
}

/// The `AppSpec` of a bundle app (`listen_port` ≤ 0 = no listener). A port above 65535 is
/// refused by `install_bundle` for an app without an HTTPS site; for an app with one it becomes 0,
/// since that app opens no listener at its bundle address.
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
        fcgi_keep_conn: app.fcgi_keep_conn,
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

/// The `CertificateSink` the control link calls (on a blocking thread). The agent keeps no
/// uploaded certificate yet, so every install is answered as one its bundle does not name.
pub struct Certificates;

impl CertificateSink for Certificates {
    fn install(&self, _: &mut CertificateInstall) -> Result<(), AckCode> {
        Err(AckCode::NotInBundle)
    }
}

#[cfg(test)]
mod tests;
