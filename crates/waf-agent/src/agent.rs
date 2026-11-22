//! A WAF bundle turned into executors and app specs, published to the proxy
//! (`wafio_proxy::Proxy::apply`).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use wafio_agent_pages::goodbot::VerifiedBotChecker;
use wafio_application::RateLimitStore;
use wafio_application::blocklist::BlockStore;
use wafio_control::{
    AckCode, BundleError, BundleSink, CertificateInstall, CertificateSink, WAF_BUNDLE_RETRY_MAX,
};
use wafio_engine_rules::json_decode;
use wafio_engine_rules::{CustomGuiRule, CustomScriptRule, TuningRule};
use wafio_proxy::cert_store::{BookChange, BookEntry, CertBook};
use wafio_proxy::{AppAnalysisSetup, AppSpec, TlsSite};

use crate::bundle::{Bundle, BundleApp, UnblockEntry, decode_bundle};
use crate::executor::{BaseExecutor, Stores, executor_for_rules};
use crate::ready::Ready;
use crate::tls::acme::placeholder;
use crate::tls::dir::KeyDir;
use crate::tls::entry::{Settings, Source};
use crate::tls::install::{LoadKey, Secrets, load_key};
use crate::tls::metrics::TlsMetrics;
use crate::tls::pacer::Statuses;
use crate::tls::status;
use crate::tls::{Applied, Keys, book_entry};

/// What `Proxy::apply` says of a bundle whose `tls` settings it refuses.
const TLS_SETTINGS_REFUSED: &str = "invalid TLS site settings";

/// The proxy side (`wafio_proxy::Proxy::apply`): builds every route, binds every new
/// address, then switches; any error changes nothing. A trait so tests can fake it.
pub trait RouteSink: Send + Sync + 'static {
    fn apply(&self, apps: Vec<AppSpec>) -> Result<(), String>;

    /// The certificates the TLS listeners serve.
    fn certificates(&self) -> Arc<CertBook>;

    /// The address and the error kind of the bind that failed the last `apply`.
    fn bind_failure(&self) -> Option<(String, std::io::ErrorKind)>;
}

impl RouteSink for wafio_proxy::Proxy {
    fn apply(&self, apps: Vec<AppSpec>) -> Result<(), String> {
        wafio_proxy::Proxy::apply(self, apps)
    }

    fn certificates(&self) -> Arc<CertBook> {
        wafio_proxy::Proxy::certificates(self)
    }

    fn bind_failure(&self) -> Option<(String, std::io::ErrorKind)> {
        wafio_proxy::Proxy::bind_failure(self)
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
    /// A successor is being started: no new order begins.
    orders_paused: bool,
    /// The key directory and what the apps with a `tls` object are served with; `None` when the
    /// agent has no usable key directory, which leaves the `tls` objects unread.
    tls: Option<Keys>,
    /// What the control plane hears of a bundle that was refused for a reason that concerns the
    /// HTTPS settings of its apps; taken by `bundle_finished`, and cleared by the next apply.
    refusal: Option<status::Refusal>,
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
    /// Where the certificate statuses go; without it none is made.
    statuses: Option<Statuses>,
    /// The worker that orders certificates, and what wakes it.
    orders: orders::Orders,
    /// What the agent counts of its certificates.
    tls_metrics: Arc<TlsMetrics>,
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
            statuses: None,
            orders: orders::Orders::default(),
            tls_metrics: Arc::default(),
        }
    }

    /// The counts and gauges of the certificates, for the metrics listener.
    pub fn tls_metrics(&self) -> Arc<TlsMetrics> {
        self.tls_metrics.clone()
    }

    /// The certificate statuses of the apps served over HTTPS are offered to `statuses`.
    pub fn with_statuses(mut self, statuses: Statuses) -> Agent {
        self.statuses = Some(statuses);
        self
    }

    /// The agent serves the apps whose bundle entry has a `tls` object over HTTPS, from the
    /// certificates in `dir`. Without it the object is ignored and the app is served as its bundle
    /// says.
    pub fn with_key_dir(self, dir: KeyDir) -> Agent {
        self.lock().tls = Some(Keys::new(dir).with_metrics(self.tls_metrics.clone()));
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

    /// Later bundles are refused, and no order is taken in.
    pub fn close(&self) {
        self.lock().closed = true;
        self.orders.wake();
    }

    /// Whether the agent has a key directory and this process is the one that writes in it.
    #[cfg(test)]
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
        let held = match st.tls.as_mut() {
            Some(keys) if !closed => {
                let had = keys.holds_lock();
                let before = keys.served_leaves();
                let held = keys.take_over(&self.routes.certificates());
                if held
                    && !had
                    && let Some(out) = &self.statuses
                {
                    // What the process that let go ordered may change what an ordered app reports,
                    // and a certificate it installed what an uploaded app is served. Any other
                    // uploaded status stays out: an offer would replace one that waits out its gap.
                    let after = keys.served_leaves();
                    let mut all = keys.ordered_statuses();
                    all.extend(keys.statuses(None).into_iter().filter(|s| {
                        s.source != status::SOURCE_ACME
                            && before.get(&s.app_id) != after.get(&s.app_id)
                    }));
                    out.changed(all);
                }
                held
            }
            _ => true,
        };
        drop(st);
        if held {
            // The orders that waited for the lock are due now.
            self.orders.wake();
        }
        held
    }

    /// Lets go of the key directory lock for the process that takes over, and stops the worker that
    /// orders certificates: the process that takes over orders from then on. Call it after
    /// `close`: from then on this process applies nothing and so writes nothing.
    pub fn release_keys(&self) {
        self.orders.stop();
        if let Some(keys) = self.lock().tls.as_mut() {
            keys.release();
        }
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
        st.refusal = None;
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
        let prepared = match &st.tls {
            Some(keys) => keys.prepare(&b.apps).map_err(|rejected| {
                tracing::warn!(
                    "[waf-bundle] app {:?}: invalid TLS entry, {}",
                    rejected.app_id.chars().take(64).collect::<String>(),
                    rejected.refusal
                );
                status::refusal(&b.apps, keys.applied(), status::REFUSED_SETTINGS, 0)
            }),
            None => {
                // Said at every bundle: such an app is served in plain HTTP at its bundle address.
                let ignored = b.apps.iter().filter(|app| app.tls.is_some()).count();
                if ignored > 0 {
                    tracing::warn!(
                        "[waf-bundle] the key directory is not usable: the TLS settings of {ignored} app(s) are ignored, and they are served in plain HTTP at their bundle address"
                    );
                }
                Ok(HashMap::new())
            }
        };
        let tls = match prepared {
            Ok(tls) => tls,
            Err(failed) => {
                st.refusal = Some(failed);
                return Err(apply_error(TLS_SETTINGS_REFUSED));
            }
        };
        let book = self.routes.certificates();
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
            let spec = app_spec(
                app,
                exec,
                tls.get(&app.app_id)
                    .map(|applied| tls_site(&app.app_id, applied, &book)),
            );
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
        if let Err(e) = self.routes.apply(specs) {
            return Err(self.refused_by_proxy(&mut st, &b.apps, &tls, e));
        }
        crate::script_rules::set_apps_with_script_rules(with_scripts);
        st.shared = Some(shared);
        st.per_app = executors;
        st.generation = b.generation;
        st.agent_id = b.agent_id.clone();
        if let Some(keys) = st.tls.as_mut() {
            keys.commit(tls);
        }
        drop(st);
        // An app that asks for a certificate may be due.
        self.orders.wake();
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

impl Agent {
    /// The error of a bundle the proxy refused. When the cause is one of the HTTPS settings, the
    /// apps with a `tls` entry get a `failed` status that says what, for the control plane to show.
    fn refused_by_proxy(
        &self,
        st: &mut State,
        apps: &[BundleApp],
        tls: &HashMap<String, Applied>,
        error: String,
    ) -> BundleError {
        if error == wafio_proxy::listeners::BIND_ERROR {
            // Only an address of an HTTPS or redirect listener tells of a failed HTTPS setting.
            let failure = self.routes.bind_failure().filter(|(address, _)| {
                tls.values().any(|a| {
                    a.settings.listen == *address
                        || a.settings.redirect_listen.as_deref() == Some(address.as_str())
                })
            });
            if let (Some((address, kind)), Some(keys)) = (failure, &st.tls) {
                let why = format!("cannot listen on {address}: {kind}");
                // The bundle is tried again after the longest wait, for as long as it takes.
                let retry_at =
                    status::unix_now().saturating_add_unsigned(WAF_BUNDLE_RETRY_MAX.as_secs());
                st.refusal = Some(status::refusal(apps, keys.applied(), &why, retry_at));
            }
            BundleError::Bind(error)
        } else {
            if error == TLS_SETTINGS_REFUSED
                && let Some(keys) = &st.tls
            {
                st.refusal = Some(status::refusal(
                    apps,
                    keys.applied(),
                    status::REFUSED_SETTINGS,
                    0,
                ));
            }
            BundleError::Apply(error)
        }
    }

    /// Checks an uploaded certificate against the bundle in force and, if it holds, serves it from
    /// the next handshake on. The apply lock is held for all of it. The buffers that hold the key
    /// are wiped on every way out, a panic included.
    pub fn install_certificate(&self, install: &CertificateInstall) -> Result<(), AckCode> {
        self.install_certificate_with(install, load_key)
    }

    /// `install_certificate` with the function that reads the key, which a test replaces to stop
    /// an install between its check and its commit.
    pub(crate) fn install_certificate_with(
        &self,
        install: &CertificateInstall,
        load: LoadKey,
    ) -> Result<(), AckCode> {
        let mut secrets = Secrets::default();
        let mut guard = self.lock();
        let st = &mut *guard;
        let keys = st.tls.as_mut().ok_or(AckCode::NotInBundle)?;
        keys.install(install, &self.routes.certificates(), &mut secrets, load)?;
        if let Some(out) = &self.statuses {
            out.changed(keys.statuses(Some(&install.app_id)));
        }
        Ok(())
    }

    /// A live bundle was handled: the control plane hears the state of the apps it names, or that
    /// the bundle was refused because of its HTTPS settings. A refusal leaves the bundle in force
    /// as it was, so an app of it that still asks for a certificate goes on asking.
    pub fn report_bundle(&self) {
        let Some(out) = &self.statuses else { return };
        let mut guard = self.lock();
        let st = &mut *guard;
        let Some(keys) = &st.tls else { return };
        match st.refusal.take() {
            Some(refusal) => {
                // An ordered app gets no `failed` from the refusal, but a live bundle is answered
                // for it too, with the state of its order now, while the refused bundle orders it
                // as the bundle in force does.
                let mut failed = refusal.failed;
                failed.extend(
                    keys.ordered_statuses()
                        .into_iter()
                        .filter(|s| refusal.ordered.contains(&s.app_id)),
                );
                out.after_refusal(failed, keys.statuses(None));
            }
            None => out.after_bundle(keys.statuses(None), true),
        }
    }
}

/// Whether the book serves `app_id` the placeholder, and it names exactly `hosts`.
fn has_placeholder_for(book: &CertBook, app_id: &str, hosts: &[String]) -> bool {
    book.get(app_id).is_some_and(|entry| {
        entry.placeholder && crate::tls::acme::names::dns_names(entry.key.cert[0].as_ref()) == hosts
    })
}

/// The proxy's view of an app's `tls` object: where it listens and which certificate it brings.
fn tls_site(app_id: &str, applied: &Applied, book: &CertBook) -> TlsSite {
    let ordered = applied.settings.source == Source::Acme;
    let certificate = match &applied.served {
        Some(served) => BookChange::Set(book_entry(served)),
        // The placeholder the book holds for these hosts stays: a new one would show a browser that
        // clicked through the warning another certificate each time a bundle comes in.
        None if ordered && has_placeholder_for(book, app_id, &applied.settings.hosts) => {
            BookChange::Keep
        }
        // An app that is ordered a certificate has nothing to serve before the first one: a
        // placeholder, so that a handshake succeeds and the app is answered `503` until then.
        None if ordered => match placeholder::certificate(&applied.settings.hosts) {
            Ok(key) => BookChange::Set(BookEntry {
                key,
                placeholder: true,
            }),
            Err(e) => {
                tracing::info!("[acme] app {app_id}: no placeholder certificate: {e}");
                BookChange::Keep
            }
        },
        // Any other app with nothing to serve (no certificate named, or an uploaded one that has not
        // arrived) holds nothing, a placeholder left from an earlier source included.
        None => BookChange::Clear,
    };
    TlsSite {
        listen: applied.settings.listen.clone(),
        hosts: applied.settings.hosts.clone(),
        certificate,
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
        // What an earlier bundle left for the control plane is not about this one.
        self.0.lock().refusal = None;
        let mut b = decode_bundle(bundle_json).map_err(BundleError::Decode)?;
        b.generation = generation;
        self.0.install_bundle(&b)
    }

    fn check(&self, bundle_json: &[u8]) -> Result<(), String> {
        decode_bundle(bundle_json).map(|_| ())
    }
}

/// The `CertificateSink` the control link calls (on a blocking thread).
pub struct Certificates(pub Arc<Agent>);

impl CertificateSink for Certificates {
    fn install(&self, install: &mut CertificateInstall) -> Result<(), AckCode> {
        self.0.install_certificate(install)
    }

    fn bundle_finished(&self) {
        self.0.report_bundle();
    }
}

mod orders;

#[cfg(test)]
mod tests;
