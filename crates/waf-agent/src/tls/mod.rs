//! Apps the agent serves over HTTPS itself: the `tls` object of a bundle app, and the key
//! directory that holds the certificate each one is served from.
//!
//! `Keys` is the state of that part of the agent. It lives in the agent's apply state, so every
//! change of what is served and every write in the directory happens under the apply lock, one at
//! a time, in the order the bundles and installs arrive.

pub mod acme;
pub mod dir;
pub mod entry;
pub(crate) mod install;
pub mod metrics;
pub mod pacer;
pub mod state_file;
pub mod status;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pingora::tls::sign::CertifiedKey;
use wafio_control::{AckCode, CertificateInstall, CertificateStatus};
use wafio_proxy::cert_store::{BookEntry, CertBook, leaf_sha256};
use zeroize::Zeroizing;

use crate::bundle::BundleApp;
use acme::ca::CaError;
use acme::order::{Issued, Job};
use acme::schedule::{self, Plan};
use acme::wait;
use dir::{KeyDir, MAX_KEY_FILE, ReadError};
use entry::{Refusal, Settings, Source, check, is_known_source};
use install::{LoadKey, Secrets, load_key, pair_from_file, verify_and_store};
use metrics::TlsMetrics;
use state_file::{AppRecord, STATE_FILE, StateFile, is_key_file};

/// Why the second start in a row that finds an order unfinished counts as a failure.
pub(crate) const INTERRUPTED: &str = "the agent stopped while the order ran, again and again";

/// The certificate an app is served with, and where it came from.
#[derive(Clone)]
pub struct Served {
    /// The file of the key directory it was read from.
    pub file: String,
    /// Lower case hex SHA-256 of the DER of the leaf.
    pub leaf_sha256: String,
    pub key: Arc<CertifiedKey>,
}

/// Prints no key.
impl std::fmt::Debug for Served {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Served")
            .field("file", &self.file)
            .field("leaf_sha256", &self.leaf_sha256)
            .finish_non_exhaustive()
    }
}

/// An app of the bundle in force that has a `tls` object.
#[derive(Clone, Debug)]
pub struct Applied {
    pub settings: Settings,
    /// What the app is served with; `None` while there is no certificate for it.
    pub served: Option<Served>,
}

/// The entry of an app that failed a check, which refuses the bundle.
#[derive(Debug)]
pub struct Rejected {
    pub app_id: String,
    pub refusal: Refusal,
}

/// The key directory and what the bundle in force serves from it.
pub struct Keys {
    dir: KeyDir,
    /// What `state.json` is to say. Until a bundle is applied it is what was read.
    state: StateFile,
    /// What the file says now; `None` when it could not be read, so the next write replaces it.
    written: Option<StateFile>,
    applied: HashMap<String, Applied>,
    /// A bundle has been applied. Before that the directory says nothing about which files are
    /// wanted, so none is removed.
    bundle_seen: bool,
    /// The app whose certificate is being ordered, if one is. One order runs at a time.
    running: Option<String>,
    metrics: Arc<TlsMetrics>,
}

/// What the worker that orders certificates does next.
pub enum NextOrder {
    /// An order is due; it counts as running until `finish_order`.
    Order(Job),
    /// Nothing is due. The earliest time something is, if it is known; else until the bundle or
    /// the key directory lock changes.
    Wait(Option<i64>),
}

impl Keys {
    pub fn new(dir: KeyDir) -> Keys {
        let (state, intact) = StateFile::load(&dir);
        Keys {
            dir,
            written: intact.then(|| state.clone()),
            state,
            applied: HashMap::new(),
            bundle_seen: false,
            running: None,
            metrics: Arc::default(),
        }
    }

    /// Counts and gauges into `metrics`, which the metrics listener reads.
    pub fn with_metrics(mut self, metrics: Arc<TlsMetrics>) -> Keys {
        self.metrics = metrics;
        self
    }

    /// Whether this process is the one that writes in the directory.
    pub fn holds_lock(&self) -> bool {
        self.dir.holds_lock()
    }

    /// The apps of the bundle in force that have a `tls` object.
    pub fn applied(&self) -> &HashMap<String, Applied> {
        &self.applied
    }

    /// Checks the `tls` object of every app of a bundle and finds the certificate each is served
    /// with. Changes nothing: `commit` makes it so once the proxy has taken the bundle.
    pub fn prepare(&self, apps: &[BundleApp]) -> Result<HashMap<String, Applied>, Rejected> {
        let mut next = HashMap::new();
        let mut unknown_source_logged = false;
        for app in apps {
            let Some(entry) = &app.tls else { continue };
            let settings = check(&app.app_id, entry).map_err(|refusal| Rejected {
                app_id: app.app_id.clone(),
                refusal,
            })?;
            if !is_known_source(&entry.source) && !unknown_source_logged {
                unknown_source_logged = true;
                tracing::info!(
                    "[waf-bundle] app {}: TLS source {:?} is not known to this agent; no certificate is served for it",
                    app.app_id,
                    entry.source.chars().take(32).collect::<String>()
                );
            }
            let served = self.resolve(&app.app_id, &settings);
            next.insert(app.app_id.clone(), Applied { settings, served });
        }
        Ok(next)
    }

    /// What the app is served with: the certificate its settings want if the directory has it;
    /// else the one it is served with now (a replaced certificate, a changed source or host list
    /// keeps serving the previous one until the new one arrives); else, after a restart, the file
    /// the state remembers. Settings that name no file (no source, one this agent does not know,
    /// uploaded with no certificate) serve nothing, so a certificate the bundle dropped is not
    /// served on.
    fn resolve(&self, app_id: &str, settings: &Settings) -> Option<Served> {
        let file = settings.wanted_file(app_id)?;
        let previous = self.applied.get(app_id).and_then(|a| a.served.as_ref());
        let leaf = settings
            .certificate
            .as_ref()
            .map(|c| c.leaf_sha256.as_str());
        if let Some(held) = previous
            && held.file == file
            && leaf.is_none_or(|leaf| leaf == held.leaf_sha256)
        {
            return Some(held.clone());
        }
        match self.load(&file, leaf) {
            Ok(served) => return Some(served),
            Err(Fault::Read(ReadError::Missing)) => {}
            Err(e) => tracing::info!("[tls] app {app_id}: {file}: {e}"),
        }
        if let Some(held) = previous {
            return Some(held.clone());
        }
        // The wanted file was tried with its leaf above; reading it again without one would serve
        // a certificate the bundle does not name.
        let remembered = self
            .state
            .apps
            .get(app_id)?
            .served
            .as_deref()
            .filter(|remembered| *remembered != file)?;
        match self.load(remembered, None) {
            Ok(served) => Some(served),
            Err(e) => {
                tracing::info!("[tls] app {app_id}: {remembered}: {e}");
                None
            }
        }
    }

    /// Reads `file` and builds its key. With `leaf` the certificate must be that one.
    fn load(&self, file: &str, leaf: Option<&str>) -> Result<Served, Fault> {
        // The file holds the key, so the text is wiped once the key is read from it, and so is
        // the DER of the key.
        let pem = Zeroizing::new(self.dir.read(file, MAX_KEY_FILE).map_err(Fault::Read)?);
        let key = pair_from_file(&pem, &mut Secrets::default(), load_key).map_err(Fault::Pem)?;
        let leaf_sha256 = leaf_sha256(&key);
        if leaf.is_some_and(|want| want != leaf_sha256) {
            return Err(Fault::OtherLeaf);
        }
        Ok(Served {
            file: file.to_owned(),
            leaf_sha256,
            key: Arc::new(key),
        })
    }

    /// Installs an uploaded certificate for an app of the bundle in force: checks it, writes its
    /// file, serves it from the next handshake on and drops the file it replaces. The caller holds
    /// the apply lock for all of it, so the bundle the checks read is the one in force when the
    /// certificate is switched in.
    ///
    /// The checks, first failure wins: the bundle names this app, certificate and leaf for an
    /// uploaded source; the certificate is not held already (then there is nothing to do); then
    /// those of `install::verify_and_store`; then the write.
    pub(crate) fn install(
        &mut self,
        install: &CertificateInstall,
        book: &CertBook,
        secrets: &mut Secrets,
        load: LoadKey,
    ) -> Result<(), AckCode> {
        let result = self.install_checked(install, book, secrets, load);
        self.metrics.install(result);
        result
    }

    fn install_checked(
        &mut self,
        install: &CertificateInstall,
        book: &CertBook,
        secrets: &mut Secrets,
        load: LoadKey,
    ) -> Result<(), AckCode> {
        let app = self
            .applied
            .get(&install.app_id)
            .ok_or(AckCode::NotInBundle)?;
        let named = app
            .settings
            .certificate
            .as_ref()
            .filter(|c| {
                app.settings.source == Source::Uploaded
                    && c.id == install.certificate_id
                    && c.leaf_sha256 == install.leaf_sha256
            })
            .ok_or(AckCode::NotInBundle)?;
        let file = format!("{}.pem", named.id);
        if app
            .served
            .as_ref()
            .is_some_and(|s| s.file == file && s.leaf_sha256 == named.leaf_sha256)
        {
            return Ok(());
        }
        let leaf = named.leaf_sha256.clone();
        let mut written = None;
        verify_and_store(install, secrets, load, |key, text| {
            self.dir.write(&file, text).map_err(|e| {
                tracing::info!("[tls] cannot write {file}: {}", e.kind());
                AckCode::WriteFailed
            })?;
            written = Some(Served {
                file: file.clone(),
                leaf_sha256: leaf,
                key,
            });
            Ok(())
        })?;
        let served = written.expect("the write ran");
        if !book.set(&install.app_id, served.key.clone(), false) {
            // The book does not hold the app: it is not in the bundle that is in force.
            let _ = self.dir.remove(&file);
            return Err(AckCode::NotInBundle);
        }
        self.serve(&install.app_id, served);
        Ok(())
    }

    /// Records that `app_id` is served `served` now, in the state file too, and drops the files
    /// that nothing needs any more: the certificate it replaced.
    fn serve(&mut self, app_id: &str, served: Served) {
        self.state.apps.entry(app_id.to_owned()).or_default().served = Some(served.file.clone());
        if let Some(app) = self.applied.get_mut(app_id) {
            app.served = Some(served);
        }
        self.publish_expiry();
        self.settle(&HashSet::new());
    }

    /// Tells the metrics when the certificate of each app of the bundle in force ends. An app that
    /// is served none, or only the placeholder, is left out.
    fn publish_expiry(&self) {
        let expiry = self
            .applied
            .iter()
            .filter_map(|(id, app)| {
                let der = app.served.as_ref()?.key.cert.first()?.as_ref();
                Some((id.clone(), acme::names::validity(der)?.1))
            })
            .collect();
        self.metrics.set_expiry(expiry);
    }

    /// The bundle is in force: `next` is what is applied now. The state and the directory follow,
    /// if this process holds the lock; if not, they follow when it takes the lock over.
    ///
    /// What the state knows of the orders of an app is kept while the app is ordered still, the
    /// failures and the wait they set included: only a success or a new request id lets an app
    /// order before its time, so editing the hosts of an app cannot be a way round it.
    pub fn commit(&mut self, next: HashMap<String, Applied>) {
        self.applied = next;
        self.bundle_seen = true;
        let mut apps = std::collections::BTreeMap::new();
        for (id, app) in &self.applied {
            let mut record = self.state.apps.get(id).cloned().unwrap_or_default();
            record.served = app.served.as_ref().map(|s| s.file.clone());
            if app.settings.source != Source::Acme {
                record = AppRecord {
                    served: record.served,
                    ..AppRecord::default()
                };
            }
            if record.served.is_some() || record.has_orders() {
                apps.insert(id.clone(), record);
            }
        }
        self.state = StateFile { apps };
        self.publish_expiry();
        self.settle(&HashSet::new());
    }

    /// The order to start next, if one is due: the app that has been due the longest. Only the
    /// process that holds the key directory lock orders. The app counts as running until
    /// `finish_order`. `directory` is the authority the agent orders from now. Blocking: it may
    /// write.
    pub fn next_order(&mut self, now: i64, directory: &str) -> NextOrder {
        if !self.dir.holds_lock() || self.running.is_some() {
            return NextOrder::Wait(None);
        }
        self.count_unfinished(now);
        let mut first: Option<(i64, &String)> = None;
        let mut wake: Option<i64> = None;
        for (id, app) in &self.applied {
            if app.settings.source != Source::Acme {
                continue;
            }
            let own = schedule::own(id, &app.settings, app.served.as_ref());
            match schedule::plan(&app.settings, self.state.apps.get(id), own, now, directory) {
                Plan::Due { since } if first.is_none_or(|(s, i)| (since, id) < (s, i)) => {
                    first = Some((since, id));
                }
                Plan::Wait { until } => wake = Some(wake.map_or(until, |w| w.min(until))),
                Plan::Due { .. } | Plan::Idle => {}
            }
        }
        let Some((_, id)) = first else {
            return NextOrder::Wait(wake);
        };
        let id = id.clone();
        let app = &self.applied[&id];
        let settings = &app.settings;
        let own = schedule::own(&id, settings, app.served.as_ref());
        let kind = schedule::choose(settings, self.state.apps.get(&id), own);
        let job = Job {
            hosts: settings.hosts.clone(),
            request_id: settings.request_id.clone(),
            kind,
            missing_listener: schedule::missing_listener(settings, kind),
            app_id: id.clone(),
        };
        self.running = Some(id);
        NextOrder::Order(job)
    }

    /// The app whose certificate is being ordered, if one is.
    #[cfg(test)]
    pub(crate) fn running(&self) -> Option<&str> {
        self.running.as_deref()
    }

    /// Notes in `state.json` that the order of `job` is about to ask the authority for something,
    /// and syncs it. A start that finds the note still there knows the order ended with no
    /// outcome (the process was killed), and `count_unfinished` sees to it that a crash loop does
    /// not order again and again. An order is not made if the note cannot be written.
    pub fn begin_attempt(&mut self, job: &Job, now: i64) -> Result<(), String> {
        let record = self.state.apps.entry(job.app_id.clone()).or_default();
        record.attempt_started = now.max(1);
        record.attempt_request_id.clone_from(&job.request_id);
        if self.save_state() {
            Ok(())
        } else {
            Err("the start of the order cannot be written to state.json".to_owned())
        }
    }

    /// An attempt that is on record while no order of this process runs is one that was cut short
    /// by a crash: it is no failure the first time, and the app is ordered again at once. The
    /// second one in a row counts as a failure, with the backoff, so that a process that is
    /// restarted over and over cannot spend the authority's limits. An attempt that the process
    /// before this one cut short at a hand-over is no crash: it noted so (`release`).
    fn count_unfinished(&mut self, now: i64) {
        let cut_short: Vec<String> = self
            .applied
            .iter()
            .filter(|(_, app)| app.settings.source == Source::Acme)
            .map(|(id, _)| id.clone())
            .filter(|id| {
                self.state
                    .apps
                    .get(id)
                    .is_some_and(|r| r.attempt_started != 0)
            })
            .collect();
        for id in &cut_short {
            let Some(record) = self.state.apps.get_mut(id) else {
                continue;
            };
            record.interrupted = record.interrupted.saturating_add(1);
            record.attempt_started = 0;
            let attempt_id = std::mem::take(&mut record.attempt_request_id);
            if record.interrupted < 2 {
                tracing::info!(
                    "[acme] app {id}: the agent stopped during an order; ordering again"
                );
                continue;
            }
            if record.request_id != attempt_id {
                record.failures = 0;
                record.request_id = attempt_id;
            }
            record.failures = record.failures.saturating_add(1);
            record.next_attempt_unix = now.saturating_add(wait::backoff(record.failures));
            record.tried_hosts.clear();
            record.error = status::error_text(INTERRUPTED);
            self.metrics.order_failed();
            tracing::info!("[acme] app {id}: {INTERRUPTED}");
        }
        if !cut_short.is_empty() {
            self.settle(&HashSet::new());
        }
    }

    /// The order of `app_id` is over and nothing of it is kept.
    pub fn abandon_order(&mut self, app_id: &str) {
        if self.running.as_deref() == Some(app_id) {
            self.running = None;
        }
    }

    /// Takes in what the order of `job` came to, under the apply lock. If the app is no longer
    /// served by order, or its hosts changed meanwhile, the order is dropped and nothing is
    /// written: the book follows the bundle. A certificate is kept as `acme-<app_id>.pem`, served
    /// from the next handshake on in place of the placeholder or the certificate it replaces, and
    /// remembered in `state.json`. A new request id in the bundle does not drop it: the same hosts
    /// and source still ask for it, and the new id orders next.
    ///
    /// The app counts as ordering until this is done, so `stop_order` can note an error in it.
    pub fn finish_order(
        &mut self,
        job: &Job,
        outcome: Result<Issued, CaError>,
        book: &CertBook,
        directory: &str,
        now: i64,
    ) {
        self.take_in(job, outcome, book, directory, now);
        self.abandon_order(&job.app_id);
    }

    /// The order of `job` ended on an internal error that nothing took in: a failure with its
    /// wait, so the authority is not asked again at once. One taken in before the error is no
    /// failure.
    pub fn stop_order(&mut self, job: &Job, book: &CertBook, now: i64) {
        if self.running.as_deref() == Some(job.app_id.as_str()) {
            let stopped = Err(CaError::new("the order stopped on an internal error"));
            self.finish_order(job, stopped, book, "", now);
        }
    }

    fn take_in(
        &mut self,
        job: &Job,
        outcome: Result<Issued, CaError>,
        book: &CertBook,
        directory: &str,
        now: i64,
    ) {
        // The order is over, however it ended: nothing of it is left unfinished.
        if let Some(record) = self.state.apps.get_mut(&job.app_id) {
            record.end_attempt();
        }
        let ordered = self
            .applied
            .get(&job.app_id)
            .is_some_and(|a| a.settings.source == Source::Acme && a.settings.hosts == job.hosts);
        if !ordered {
            tracing::info!(
                "[acme] app {}: the order is dropped, the app is no longer served by order for these hosts",
                job.app_id
            );
            if self
                .state
                .apps
                .get(&job.app_id)
                .is_some_and(|r| r.served.is_none() && !r.has_orders())
            {
                self.state.apps.remove(&job.app_id);
            }
            self.settle(&HashSet::new());
            return;
        }
        let issued = match outcome {
            Ok(issued) => issued,
            Err(e) => {
                let wait = wait::ca_wait_until(e.problem.as_deref(), e.retry_after.as_deref(), now);
                return self.order_failed(job, &e.line(), wait, now);
            }
        };
        let file = format!("acme-{}.pem", job.app_id);
        if let Err(e) = self.dir.write(&file, &issued.file) {
            tracing::info!(
                "[acme] app {}: cannot write {file}: {}",
                job.app_id,
                e.kind()
            );
            return self.order_failed(
                job,
                &format!("cannot keep the certificate ({})", e.kind()),
                0,
                now,
            );
        }
        if !book.set(&job.app_id, issued.key.clone(), false) {
            // The listeners do not hold the app: nothing can serve the certificate, and an order
            // that left no trace would be made again at once.
            let _ = self.dir.remove(&file);
            return self.order_failed(job, "the certificate cannot be served", 0, now);
        }
        let served = Served {
            file: file.clone(),
            leaf_sha256: leaf_sha256(&issued.key),
            key: issued.key,
        };
        let record = self.state.apps.entry(job.app_id.clone()).or_default();
        record.request_id.clone_from(&job.request_id);
        record.directory = directory.to_owned();
        record.worked = job.kind.as_str().to_owned();
        record.forget_failures();
        self.metrics.order_issued();
        tracing::info!("[acme] app {}: issued, served from {file}", job.app_id);
        self.serve(&job.app_id, served);
    }

    /// Notes that the order of `job` failed: no new order before the backoff is over (and the
    /// authority's wait, `ca_wait`, if it set one), and the other challenge next time. A request
    /// id the failures did not answer starts the backoff again.
    fn order_failed(&mut self, job: &Job, error: &str, ca_wait: i64, now: i64) {
        let mut text = format!("the order failed ({}): {error}", job.kind.as_str());
        if let Some(note) = job.missing_listener {
            text.push_str("; ");
            text.push_str(note);
        }
        tracing::info!("[acme] app {}: {}", job.app_id, status::error_text(&text));
        let record = self.state.apps.entry(job.app_id.clone()).or_default();
        if record.request_id != job.request_id {
            record.failures = 0;
        }
        record.request_id.clone_from(&job.request_id);
        record.tried = job.kind.as_str().to_owned();
        record.tried_hosts.clone_from(&job.hosts);
        record.failures = record.failures.saturating_add(1);
        record.next_attempt_unix = now.saturating_add(wait::backoff(record.failures));
        record.ca_wait_unix = ca_wait;
        record.error = status::error_text(&text);
        self.metrics.order_failed();
        self.settle(&HashSet::new());
    }

    /// The statuses of the apps of the bundle in force that have one to report; `only` narrows it
    /// to one app.
    pub fn statuses(&self, only: Option<&str>) -> Vec<CertificateStatus> {
        let mut all = status::current(&self.applied, only);
        for (id, app) in &self.applied {
            if app.settings.source == Source::Acme && only.is_none_or(|only| only == id) {
                all.push(status::ordered(
                    id,
                    &app.settings,
                    app.served.as_ref(),
                    self.state.apps.get(id),
                    self.running.as_deref() == Some(id),
                ));
            }
        }
        all.sort_by(|a, b| a.app_id.cmp(&b.app_id));
        all
    }

    /// Reads a file of the key directory that is none of an app's: the account.
    pub fn read_file(&self, name: &str, limit: usize) -> Result<Vec<u8>, ReadError> {
        self.dir.read(name, limit)
    }

    /// Writes such a file, if this process holds the lock.
    pub fn write_file(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        self.dir.write(name, data)
    }

    pub fn remove_file(&self, name: &str) -> std::io::Result<()> {
        self.dir.remove(name)
    }

    /// Takes the lock if the process that held it let go, and then does what it could not do
    /// before: it takes in what that process did after this one applied its bundle, and writes.
    /// Returns whether this process holds the lock.
    pub fn take_over(&mut self, book: &CertBook) -> bool {
        if self.dir.holds_lock() {
            return true;
        }
        if !self.dir.try_lock() {
            return false;
        }
        tracing::info!("[tls] this process writes in the key directory now");
        // The process that let go may have got a newer bundle than the one this process applied
        // and written its certificates since: those are files this process does not know about.
        let (theirs, _) = StateFile::load(&self.dir);
        let known: HashSet<&str> = self
            .written
            .iter()
            .flat_map(StateFile::served_files)
            .collect();
        let newer: HashSet<String> = theirs
            .served_files()
            .filter(|file| !known.contains(file))
            .map(str::to_owned)
            .collect();
        self.adopt(&theirs, book);
        self.settle(&newer);
        true
    }

    /// Takes in the orders the process that let go ended after this one applied its bundle, for
    /// the apps this one orders for: the certificate it kept, and the failure it noted with the
    /// time of the next attempt. Without them this process would order again at once, a second
    /// issuance for the same names, and write its own state over theirs.
    fn adopt(&mut self, theirs: &StateFile, book: &CertBook) {
        let ordered: Vec<String> = self
            .applied
            .iter()
            .filter(|(_, a)| a.settings.source == Source::Acme)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ordered {
            let before = self.written.as_ref().and_then(|w| w.apps.get(&id));
            if let Some(record) = theirs.apps.get(&id).filter(|r| Some(*r) != before) {
                self.state
                    .apps
                    .entry(id.clone())
                    .or_default()
                    .take_orders_from(record);
            }
            self.serve_ordered(&id, book);
        }
    }

    /// Serves the app from its own certificate file when that holds another certificate than the
    /// one it is served with: a process that let go of the directory wrote it.
    fn serve_ordered(&mut self, app_id: &str, book: &CertBook) {
        let Some(file) = self
            .applied
            .get(app_id)
            .and_then(|a| a.settings.wanted_file(app_id))
        else {
            return;
        };
        let served = match self.load(&file, None) {
            Ok(served) => served,
            Err(Fault::Read(ReadError::Missing)) => return,
            Err(e) => return tracing::info!("[tls] app {app_id}: {file}: {e}"),
        };
        let held = self.applied.get(app_id).and_then(|a| a.served.as_ref());
        if held.is_some_and(|h| h.file == file && h.leaf_sha256 == served.leaf_sha256) {
            return;
        }
        if !book.set(app_id, served.key.clone(), false) {
            return;
        }
        tracing::info!(
            "[acme] app {app_id}: serves {file}, which the process that handed over ordered"
        );
        // Not `serve`: it would clean the directory before the files of that process are known to
        // be kept.
        self.state.apps.entry(app_id.to_owned()).or_default().served = Some(file);
        if let Some(app) = self.applied.get_mut(app_id) {
            app.served = Some(served);
        }
        self.publish_expiry();
    }

    /// Lets go of the lock for the process that takes over. An order that the hand-over cuts short
    /// is noted as no attempt that was left unfinished, so the process that takes over orders
    /// again without counting a crash.
    pub fn release(&mut self) {
        if self.dir.holds_lock() {
            if let Some(record) = self
                .running
                .as_ref()
                .and_then(|id| self.state.apps.get_mut(id))
            {
                record.end_attempt();
            }
            self.save_state();
            self.dir.release_lock();
            tracing::info!("[tls] key directory lock handed over");
        }
    }

    /// Writes the state if it changed and removes the files nothing needs, when this process may
    /// write and a bundle has said what is wanted. `keep` names files to leave in place besides
    /// the ones the bundle uses.
    fn settle(&mut self, keep: &HashSet<String>) {
        if !self.dir.holds_lock() || !self.bundle_seen {
            return;
        }
        self.save_state();
        self.remove_unused(keep);
    }

    /// Writes the state if it changed, and says whether the file holds it. What the file cannot
    /// hold (see `StateFile::fit`) is cut from the state in memory too.
    fn save_state(&mut self) -> bool {
        if self.written.as_ref() == Some(&self.state) {
            return true;
        }
        let Some(bytes) = self.state.fit() else {
            tracing::info!("[tls] {STATE_FILE} would be larger than the agent reads; not written");
            return false;
        };
        match self.dir.write(STATE_FILE, &bytes) {
            Ok(()) => {
                self.written = Some(self.state.clone());
                true
            }
            Err(e) => {
                tracing::info!("[tls] cannot write {STATE_FILE}: {}", e.kind());
                false
            }
        }
    }

    /// Removes each certificate file of the agent (`<uuid>.pem`, `acme-<uuid>.pem`) that no app of
    /// the bundle names and none serves: the certificate an app was served with goes once the one
    /// that replaces it is served. Any other file is none of the agent's and stays.
    fn remove_unused(&self, keep: &HashSet<String>) {
        let needed: HashSet<String> = self
            .applied
            .iter()
            .flat_map(|(id, a)| {
                a.settings
                    .wanted_file(id)
                    .into_iter()
                    .chain(a.served.iter().map(|s| s.file.clone()))
            })
            .collect();
        let files = match self.dir.pem_files() {
            Ok(files) => files,
            Err(e) => {
                tracing::info!("[tls] cannot list the key directory: {}", e.kind());
                return;
            }
        };
        for file in files
            .iter()
            .filter(|f| is_key_file(f) && !needed.contains(*f) && !keep.contains(*f))
        {
            match self.dir.remove(file) {
                Ok(()) => tracing::info!("[tls] removed {file}: no app of the bundle uses it"),
                Err(e) => tracing::info!("[tls] cannot remove {file}: {}", e.kind()),
            }
        }
    }
}

/// The book entry that serves `served`.
pub fn book_entry(served: &Served) -> BookEntry {
    BookEntry {
        key: served.key.clone(),
        placeholder: false,
    }
}

enum Fault {
    Read(ReadError),
    Pem(wafio_proxy::cert_store::PairFault),
    OtherLeaf,
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::Read(e) => write!(f, "cannot read: {e}"),
            Fault::Pem(e) => write!(f, "{e}"),
            Fault::OtherLeaf => f.write_str("holds another certificate than the bundle names"),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::install::tests::{Made, fixture, install_for};
    use super::*;
    use crate::bundle::decode_bundle;
    use dir::tests::{Scratch, my_uid};
    use std::path::Path;
    use std::process::Command;
    use wafio_proxy::cert_store::{BookChange, certified_key_from_pem};

    const APP: &str = "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11";
    const OTHER_APP: &str = "6f1c0c64-4f7e-4a06-8cf3-0b7c2a6d1e90";
    const X: &str = "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77";
    const Y: &str = "7e1f3a90-2c1d-4b8e-9a55-1d3c4f6a8b02";

    /// A new self-signed key and certificate for `name`: the text of one key file, and the
    /// SHA-256 of the leaf.
    pub(crate) fn make_pem(work: &Path, name: &str) -> (Vec<u8>, String) {
        let (key, crt) = (
            work.join(format!("{name}.key")),
            work.join(format!("{name}.crt")),
        );
        let out = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
            ])
            .args([
                "-nodes",
                "-days",
                "2",
                "-subj",
                &format!("/CN={name}"),
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&crt)
            .output()
            .expect("openssl is installed");
        assert!(out.status.success(), "openssl req failed");
        let pem = [std::fs::read(&key).unwrap(), std::fs::read(&crt).unwrap()].concat();
        let leaf = leaf_sha256(&certified_key_from_pem(&pem).unwrap());
        (pem, leaf)
    }

    /// The apps of a bundle: each `(app id, tls object)`.
    fn apps(entries: &[(&str, String)]) -> Vec<BundleApp> {
        let list: Vec<String> = entries
            .iter()
            .map(|(id, tls)| format!(r#"{{"app_id":"{id}","tls":{tls}}}"#))
            .collect();
        decode_bundle(format!(r#"{{"apps":[{}]}}"#, list.join(",")).as_bytes())
            .unwrap()
            .apps
    }

    fn uploaded(cert: &str, leaf: &str) -> String {
        format!(
            r#"{{"listen":"0.0.0.0:443","hosts":["shop.example.com"],"source":"uploaded","certificate_id":"{cert}","leaf_sha256":"{leaf}"}}"#
        )
    }

    fn apply(keys: &mut Keys, entries: &[(&str, String)]) -> HashMap<String, Applied> {
        let next = keys.prepare(&apps(entries)).unwrap();
        keys.commit(next.clone());
        next
    }

    fn served(applied: &HashMap<String, Applied>, app: &str) -> Option<String> {
        applied[app].served.as_ref().map(|s| s.file.clone())
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn state_on_disk(dir: &Path) -> StateFile {
        serde_json::from_slice(&std::fs::read(dir.join(STATE_FILE)).unwrap()).unwrap()
    }

    fn keys(s: &Scratch) -> Keys {
        Keys::new(KeyDir::open(&s.dir(), my_uid()).unwrap())
    }

    #[test]
    fn a_certificate_is_served_from_the_file_the_bundle_names_and_the_one_it_replaces_goes() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let ((x_pem, x_leaf), (y_pem, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let (x_file, y_file) = (format!("{X}.pem"), format!("{Y}.pem"));

        // The bundle names X, which is not there: nothing is served, and nothing is written for it.
        let first = apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        assert_eq!(served(&first, APP), None);

        k.dir.write(&x_file, &x_pem).unwrap();
        let second = apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        assert_eq!(served(&second, APP), Some(x_file.clone()));
        assert_eq!(
            second[APP].served.as_ref().unwrap().leaf_sha256,
            x_leaf,
            "the leaf is the digest of the certificate in the file"
        );
        assert_eq!(
            state_on_disk(&s.dir()).apps[APP].served.as_deref(),
            Some(x_file.as_str())
        );

        // The bundle names Y before its file is there: X stays served, and X.pem stays.
        let third = apply(&mut k, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&third, APP), Some(x_file.clone()));
        assert_eq!(files(&s.dir()), [x_file.as_str(), STATE_FILE, "tls.lock"]);

        // Y arrives: it is served and X.pem is gone, in the same apply.
        k.dir.write(&y_file, &y_pem).unwrap();
        let fourth = apply(&mut k, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&fourth, APP), Some(y_file.clone()));
        assert_eq!(files(&s.dir()), [y_file.as_str(), STATE_FILE, "tls.lock"]);
        assert_eq!(
            state_on_disk(&s.dir()).apps[APP].served.as_deref(),
            Some(y_file.as_str())
        );
    }

    #[test]
    fn a_file_with_another_certificate_than_the_bundle_names_is_not_served() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let ((x_pem, _), (_, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        k.dir.write(&format!("{X}.pem"), &x_pem).unwrap();
        let applied = apply(&mut k, &[(APP, uploaded(X, &y_leaf))]);
        assert_eq!(served(&applied, APP), None);
        for bad in [&b"not a key file"[..], b"", &x_pem[..x_pem.len() / 2]] {
            k.dir.write(&format!("{X}.pem"), bad).unwrap();
            assert_eq!(
                served(&apply(&mut k, &[(APP, uploaded(X, &y_leaf))]), APP),
                None
            );
        }
    }

    #[test]
    fn a_damaged_file_keeps_the_certificate_in_use() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let ((x_pem, x_leaf), (_, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let x_file = format!("{X}.pem");
        k.dir.write(&x_file, &x_pem).unwrap();
        apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        k.dir.write(&format!("{Y}.pem"), b"half a file").unwrap();
        let applied = apply(&mut k, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&applied, APP), Some(x_file));
    }

    #[test]
    fn the_state_drops_apps_that_left_the_bundle_with_their_files() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let ((x_pem, x_leaf), (y_pem, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        k.dir.write(&format!("{X}.pem"), &x_pem).unwrap();
        k.dir.write(&format!("{Y}.pem"), &y_pem).unwrap();
        // A file that is none of the agent's stays, whatever the bundle says.
        std::fs::write(s.dir().join("notes.pem"), "an operator's file").unwrap();
        apply(
            &mut k,
            &[
                (APP, uploaded(X, &x_leaf)),
                (OTHER_APP, uploaded(Y, &y_leaf)),
            ],
        );
        assert_eq!(state_on_disk(&s.dir()).apps.len(), 2);

        // An app without a `tls` object is not served and not remembered.
        let plain = decode_bundle(
            format!(
                r#"{{"apps":[{{"app_id":"{OTHER_APP}"}},{{"app_id":"{APP}","tls":{}}}]}}"#,
                uploaded(X, &x_leaf)
            )
            .as_bytes(),
        )
        .unwrap()
        .apps;
        let next = k.prepare(&plain).unwrap();
        k.commit(next);
        let state = state_on_disk(&s.dir());
        assert_eq!(state.apps.keys().collect::<Vec<_>>(), [APP]);
        assert_eq!(
            files(&s.dir()),
            [
                format!("{X}.pem").as_str(),
                "notes.pem",
                STATE_FILE,
                "tls.lock"
            ]
        );

        let none = k.prepare(&[]).unwrap();
        k.commit(none);
        assert!(state_on_disk(&s.dir()).apps.is_empty());
        assert_eq!(files(&s.dir()), ["notes.pem", STATE_FILE, "tls.lock"]);
    }

    /// Source `""`, one the agent does not know, and `uploaded` with no certificate named.
    fn entries_that_name_no_file() -> [String; 3] {
        let entry = |source: &str| {
            format!(
                r#"{{"listen":"0.0.0.0:443","hosts":["shop.example.com"],"source":"{source}"}}"#
            )
        };
        [entry(""), entry("mystery"), entry("uploaded")]
    }

    #[test]
    fn an_app_whose_settings_name_no_file_is_served_nothing_and_the_certificate_it_had_goes() {
        let s = Scratch::new();
        let (x_pem, x_leaf) = make_pem(&s.0, "x");
        let x_file = format!("{X}.pem");
        for restart in [false, true] {
            for none in entries_that_name_no_file() {
                let mut k = keys(&s);
                k.dir.write(&x_file, &x_pem).unwrap();
                let first = apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
                assert_eq!(served(&first, APP), Some(x_file.clone()));
                if restart {
                    // The state remembers X.pem, and must not bring it back.
                    drop(k);
                    k = keys(&s);
                }
                let applied = apply(&mut k, &[(APP, none.clone())]);
                assert_eq!(served(&applied, APP), None, "{none}, restart {restart}");
                assert_eq!(files(&s.dir()), [STATE_FILE, "tls.lock"], "{none}");
                assert!(state_on_disk(&s.dir()).apps.is_empty());
            }
        }
    }

    #[test]
    fn a_restart_before_the_new_certificate_arrives_serves_the_one_the_state_remembers() {
        let s = Scratch::new();
        let ((x_pem, x_leaf), (y_pem, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let (x_file, y_file) = (format!("{X}.pem"), format!("{Y}.pem"));
        {
            let mut k = keys(&s);
            k.dir.write(&x_file, &x_pem).unwrap();
            apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        }
        // A new process, and a bundle that names Y, which has not arrived.
        let mut k = keys(&s);
        let applied = apply(&mut k, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&applied, APP), Some(x_file.clone()));
        assert!(files(&s.dir()).contains(&x_file));
        k.dir.write(&y_file, &y_pem).unwrap();
        let applied = apply(&mut k, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&applied, APP), Some(y_file));
        assert!(!files(&s.dir()).contains(&x_file));
    }

    #[test]
    fn after_a_restart_a_file_with_another_certificate_than_the_bundle_names_is_not_served() {
        let s = Scratch::new();
        let ((x_pem, x_leaf), (y_pem, _)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let x_file = format!("{X}.pem");
        {
            let mut k = keys(&s);
            k.dir.write(&x_file, &x_pem).unwrap();
            apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        }
        // Another pair under the name of X: the state remembers X.pem, but the leaf is not X's.
        std::fs::write(s.dir().join(&x_file), &y_pem).unwrap();
        let mut k = keys(&s);
        let applied = apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        assert_eq!(served(&applied, APP), None);
    }

    #[test]
    fn a_process_that_does_not_hold_the_lock_serves_what_it_reads_and_writes_nothing_until_it_does()
    {
        let s = Scratch::new();
        let ((x_pem, x_leaf), (y_pem, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let (x_file, y_file) = (format!("{X}.pem"), format!("{Y}.pem"));
        let mut first = keys(&s);
        first.dir.write(&x_file, &x_pem).unwrap();
        apply(&mut first, &[(APP, uploaded(X, &x_leaf))]);
        std::fs::write(s.dir().join(format!("{OTHER_APP}.pem")), "an orphan").unwrap();
        let before = (
            files(&s.dir()),
            std::fs::read(s.dir().join(STATE_FILE)).unwrap(),
        );
        assert_eq!(before.0.len(), 4);

        // The successor: it reads X and serves it, and the bundle that names Y changes nothing on disk.
        let mut second = keys(&s);
        assert!(!second.holds_lock() && !second.take_over(&CertBook::default()));
        let applied = apply(&mut second, &[(APP, uploaded(X, &x_leaf))]);
        assert_eq!(served(&applied, APP), Some(x_file.clone()));
        std::fs::write(s.dir().join(&y_file), &y_pem).unwrap();
        let applied = apply(&mut second, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&applied, APP), Some(y_file.clone()));
        let after = (
            files(&s.dir()),
            std::fs::read(s.dir().join(STATE_FILE)).unwrap(),
        );
        let orphan = format!("{OTHER_APP}.pem");
        let mut everything = [
            x_file.as_str(),
            orphan.as_str(),
            y_file.as_str(),
            STATE_FILE,
            "tls.lock",
        ];
        everything.sort_unstable();
        assert_eq!(after.0, everything, "nothing was removed or made");
        assert_eq!(after.1, before.1, "the state was not written");

        // The first lets go: the second takes the lock and does what it put off.
        first.release();
        assert!(second.take_over(&CertBook::default()) && second.holds_lock());
        assert_eq!(files(&s.dir()), [y_file.as_str(), STATE_FILE, "tls.lock"]);
        assert_eq!(
            state_on_disk(&s.dir()).apps[APP].served.as_deref(),
            Some(y_file.as_str())
        );
    }

    #[test]
    fn a_file_the_process_it_replaces_wrote_after_this_one_started_stays_when_it_takes_over() {
        let s = Scratch::new();
        let ((x_pem, x_leaf), (y_pem, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let (x_file, y_file) = (format!("{X}.pem"), format!("{Y}.pem"));
        let mut first = keys(&s);
        first.dir.write(&x_file, &x_pem).unwrap();
        apply(&mut first, &[(APP, uploaded(X, &x_leaf))]);

        // The successor starts from the bundle that names X, and the first gets a newer one that
        // names Y, writes it and records it.
        let mut second = keys(&s);
        apply(&mut second, &[(APP, uploaded(X, &x_leaf))]);
        first.dir.write(&y_file, &y_pem).unwrap();
        apply(&mut first, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(files(&s.dir()), [y_file.as_str(), STATE_FILE, "tls.lock"]);

        first.release();
        assert!(second.take_over(&CertBook::default()));
        assert_eq!(
            files(&s.dir()),
            [y_file.as_str(), STATE_FILE, "tls.lock"],
            "Y.pem is not in the bundle this process applied, and it is the one in use"
        );
        let applied = apply(&mut second, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&applied, APP), Some(y_file));
    }

    #[test]
    fn no_file_is_removed_before_a_bundle_has_said_which_are_wanted() {
        let s = Scratch::new();
        let (x_pem, _) = make_pem(&s.0, "x");
        let mut first = keys(&s);
        first.dir.write(&format!("{X}.pem"), &x_pem).unwrap();
        let mut second = keys(&s);
        first.release();
        assert!(second.take_over(&CertBook::default()));
        assert!(files(&s.dir()).contains(&format!("{X}.pem")));
        let none = second.prepare(&[]).unwrap();
        second.commit(none);
        assert!(!files(&s.dir()).contains(&format!("{X}.pem")));
    }

    #[test]
    fn a_certificate_the_listeners_cannot_take_is_a_failure_with_a_wait_and_leaves_no_file() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let acme = r#"{"listen":"0.0.0.0:443","hosts":["shop.example.com"],"source":"acme","acme_request_id":"r1"}"#;
        apply(&mut k, &[(APP, acme.to_owned())]);
        let NextOrder::Order(job) = k.next_order(1_800_000_000, "https://ca.test/dir") else {
            panic!("an order is due");
        };
        let (pem, _) = make_pem(&s.0, "x");
        let issued = Issued {
            key: Arc::new(certified_key_from_pem(&pem).unwrap()),
            file: Zeroizing::new(pem),
        };
        // The book holds no app, as when the proxy has dropped it.
        k.finish_order(
            &job,
            Ok(issued),
            &CertBook::default(),
            "https://ca.test/dir",
            1_800_000_000,
        );
        assert!(!files(&s.dir()).contains(&format!("acme-{APP}.pem")));
        let record = &state_on_disk(&s.dir()).apps[APP];
        assert_eq!(
            (
                record.failures,
                record.next_attempt_unix,
                record.request_id.as_str()
            ),
            (1, 1_800_000_000 + 600, "r1"),
            "an order that left no trace would be made again at once"
        );
        assert!(matches!(
            k.next_order(1_800_000_001, "https://ca.test/dir"),
            NextOrder::Wait(Some(_))
        ));
    }

    #[test]
    fn a_damaged_state_file_is_replaced_by_the_next_write() {
        let s = Scratch::new();
        {
            let k = keys(&s);
            k.dir.write(STATE_FILE, b"{\"apps\":{\"a\"").unwrap();
        }
        let mut k = keys(&s);
        let none = k.prepare(&[]).unwrap();
        k.commit(none);
        assert!(state_on_disk(&s.dir()).apps.is_empty());
    }

    #[test]
    fn an_entry_that_fails_a_check_names_its_app_and_changes_nothing() {
        let s = Scratch::new();
        let k = keys(&s);
        let good = uploaded(X, &"ab".repeat(32));
        let bad = good.replace("shop.example.com", "*.example.com");
        let rejected = k
            .prepare(&apps(&[(APP, good), (OTHER_APP, bad)]))
            .unwrap_err();
        assert_eq!(
            (rejected.app_id.as_str(), rejected.refusal.field),
            (OTHER_APP, "hosts")
        );
        assert!(k.applied().is_empty());
        let rejected = k
            .prepare(&apps(&[("shop", uploaded(X, &"ab".repeat(32)))]))
            .unwrap_err();
        assert_eq!(rejected.refusal.field, "app_id");
    }

    /// The book of an agent whose bundle has these apps and no certificate in it yet.
    fn book_of(apps: &[&str]) -> CertBook {
        let book = CertBook::default();
        book.follow(
            apps.iter()
                .map(|a| ((*a).to_owned(), BookChange::Keep))
                .collect(),
        );
        book
    }

    fn install_pair(
        k: &mut Keys,
        book: &CertBook,
        made: &Made,
        cert_id: &str,
    ) -> Result<(), AckCode> {
        let mut install = install_for(made);
        install.app_id = APP.to_owned();
        install.certificate_id = cert_id.to_owned();
        k.install(&install, book, &mut Secrets::default(), load_key)
    }

    fn held_leaf(book: &CertBook, app: &str) -> Option<String> {
        Some(leaf_sha256(&book.get(app)?.key))
    }

    #[test]
    fn an_installed_certificate_is_written_served_and_the_one_it_replaces_goes() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let book = book_of(&[APP]);
        let f = fixture();
        let (x_file, y_file) = (format!("{X}.pem"), format!("{Y}.pem"));

        apply(&mut k, &[(APP, uploaded(X, &f.ec.leaf))]);
        assert_eq!(served(k.applied(), APP), None);
        assert_eq!(install_pair(&mut k, &book, &f.ec, X), Ok(()));
        assert_eq!(served(k.applied(), APP), Some(x_file.clone()));
        assert_eq!(held_leaf(&book, APP), Some(f.ec.leaf.clone()));
        assert_eq!(files(&s.dir()), [x_file.as_str(), STATE_FILE, "tls.lock"]);
        let mode = std::fs::metadata(s.dir().join(&x_file)).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
            0o600
        );
        assert_eq!(
            state_on_disk(&s.dir()).apps[APP].served.as_deref(),
            Some(x_file.as_str())
        );

        // The bundle names Y: X stays served until Y is installed, and then X.pem goes.
        apply(&mut k, &[(APP, uploaded(Y, &f.rsa.leaf))]);
        assert_eq!(held_leaf(&book, APP), Some(f.ec.leaf.clone()));
        assert_eq!(install_pair(&mut k, &book, &f.rsa, Y), Ok(()));
        assert_eq!(held_leaf(&book, APP), Some(f.rsa.leaf.clone()));
        assert_eq!(served(k.applied(), APP), Some(y_file.clone()));
        assert_eq!(files(&s.dir()), [y_file.as_str(), STATE_FILE, "tls.lock"]);
        assert_eq!(
            state_on_disk(&s.dir()).apps[APP].served.as_deref(),
            Some(y_file.as_str())
        );
        // What is on disk reads back as the pair that was installed.
        let on_disk = std::fs::read(s.dir().join(&y_file)).unwrap();
        assert_eq!(
            leaf_sha256(&certified_key_from_pem(&on_disk).unwrap()),
            f.rsa.leaf
        );
    }

    fn install_with(made: &Made, app: &str, cert_id: &str) -> CertificateInstall {
        let mut install = install_for(made);
        install.app_id = app.to_owned();
        install.certificate_id = cert_id.to_owned();
        install
    }

    #[test]
    fn an_install_the_bundle_does_not_name_is_refused_and_changes_nothing() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let book = book_of(&[APP]);
        let f = fixture();
        apply(&mut k, &[(APP, uploaded(X, &f.ec.leaf))]);
        let before = files(&s.dir());
        assert!(!before.iter().any(|f| f.ends_with(".pem")));

        for (what, install) in [
            (
                "an app the bundle does not have",
                install_with(&f.ec, OTHER_APP, X),
            ),
            (
                "a leaf the bundle does not name",
                install_with(&f.rsa, APP, X),
            ),
            (
                "a certificate id the bundle does not name",
                install_with(&f.ec, APP, Y),
            ),
        ] {
            let got = k.install(&install, &book, &mut Secrets::default(), load_key);
            assert_eq!(got, Err(AckCode::NotInBundle), "{what}");
            assert_eq!(files(&s.dir()), before, "{what}");
        }

        // A source that is not uploaded, and one with no certificate named.
        let acme = r#"{"listen":"0.0.0.0:443","hosts":["shop.example.com"],"source":"acme"}"#;
        let bare = r#"{"listen":"0.0.0.0:443","hosts":["shop.example.com"],"source":"uploaded"}"#;
        for (what, tls) in [("acme", acme), ("no certificate", bare)] {
            apply(&mut k, &[(APP, tls.to_owned())]);
            let got = install_pair(&mut k, &book, &f.ec, X);
            assert_eq!(got, Err(AckCode::NotInBundle), "{what}");
            assert!(
                !files(&s.dir()).iter().any(|f| f.ends_with(".pem")),
                "{what}"
            );
        }

        // An app that left the bundle: the install that was sent for it is refused, and the app
        // is not put back into the book.
        apply(&mut k, &[(APP, uploaded(X, &f.ec.leaf))]);
        let none = k.prepare(&[]).unwrap();
        k.commit(none);
        book.follow(HashMap::new());
        assert_eq!(
            install_pair(&mut k, &book, &f.ec, X),
            Err(AckCode::NotInBundle)
        );
        assert!(book.get(APP).is_none());
        assert!(!files(&s.dir()).iter().any(|f| f.ends_with(".pem")));
    }

    #[test]
    fn a_certificate_that_is_held_is_acked_without_a_write_and_a_refused_one_leaves_no_trace() {
        let s = Scratch::new();
        let mut first = keys(&s);
        let book = book_of(&[APP]);
        let f = fixture();
        apply(&mut first, &[(APP, uploaded(X, &f.ec.leaf))]);
        assert_eq!(install_pair(&mut first, &book, &f.ec, X), Ok(()));

        // A process that holds no lock cannot write: for what it holds the install is still
        // acked, and for anything else it is the retryable refusal, with nothing left behind.
        let mut second = keys(&s);
        assert!(!second.holds_lock());
        let book2 = book_of(&[APP]);
        apply(&mut second, &[(APP, uploaded(X, &f.ec.leaf))]);
        let before = files(&s.dir());
        assert_eq!(install_pair(&mut second, &book2, &f.ec, X), Ok(()), "held");
        assert_eq!(files(&s.dir()), before);

        apply(&mut second, &[(APP, uploaded(Y, &f.rsa.leaf))]);
        assert_eq!(
            install_pair(&mut second, &book2, &f.rsa, Y),
            Err(AckCode::WriteFailed)
        );
        assert_eq!(files(&s.dir()), before, "no file and no temporary file");
        assert_eq!(served(second.applied(), APP), Some(format!("{X}.pem")));
        assert_eq!(
            held_leaf(&book2, APP),
            None,
            "and the book is as the bundle left it"
        );

        // A pair the checks refuse leaves the directory and the book as they were.
        apply(&mut first, &[(APP, uploaded(Y, &f.rsa.leaf))]);
        let before = files(&s.dir());
        let mut bad = install_with(&f.rsa, APP, Y);
        bad.key_pem = f.ec.key.clone();
        let got = first.install(&bad, &book, &mut Secrets::default(), load_key);
        assert_eq!(got, Err(AckCode::KeyMismatch));
        assert_eq!(files(&s.dir()), before);
        assert_eq!(held_leaf(&book, APP), Some(f.ec.leaf.clone()));
        assert_eq!(served(first.applied(), APP), Some(format!("{X}.pem")));
    }

    // The next order: its time, a crash, and what is counted.

    const DIR: &str = "https://ca.test/dir";
    const T0: i64 = 1_800_000_000;

    fn acme(request_id: &str) -> String {
        format!(
            r#"{{"listen":"0.0.0.0:443","hosts":["shop.example.com"],"source":"acme","acme_request_id":"{request_id}"}}"#
        )
    }

    /// The order that is due at `now`, which counts as running from then on.
    fn order(k: &mut Keys, now: i64) -> Job {
        match k.next_order(now, DIR) {
            NextOrder::Order(job) => job,
            NextOrder::Wait(until) => {
                panic!("an order is due at {now}, not waiting until {until:?}")
            }
        }
    }

    /// The time the next order waits for, if it waits.
    fn waits_until(k: &mut Keys, now: i64) -> Option<i64> {
        match k.next_order(now, DIR) {
            NextOrder::Wait(until) => until,
            NextOrder::Order(job) => panic!("no order is due at {now}, one is: {job:?}"),
        }
    }

    fn fails(k: &mut Keys, job: &Job, now: i64, error: CaError) {
        k.finish_order(job, Err(error), &CertBook::default(), DIR, now);
    }

    fn record_on_disk(s: &Scratch) -> AppRecord {
        state_on_disk(&s.dir()).apps[APP].clone()
    }

    fn rate_limited(retry_after: Option<&str>) -> CaError {
        CaError {
            problem: Some(acme::wait::RATE_LIMITED.to_owned()),
            text: "too many certificates already issued".to_owned(),
            retry_after: retry_after.map(str::to_owned),
        }
    }

    fn issued(s: &Scratch) -> Issued {
        let (pem, _) = make_pem(&s.0, "issued");
        Issued {
            key: Arc::new(certified_key_from_pem(&pem).unwrap()),
            file: Zeroizing::new(pem),
        }
    }

    #[test]
    fn the_backoff_is_10_minutes_1_hour_4_hours_12_hours_then_a_day_and_a_success_resets_it() {
        let s = Scratch::new();
        let mut k = keys(&s);
        apply(&mut k, &[(APP, acme("r1"))]);
        let mut now = T0;
        for (failures, wait) in [
            (1, 600),
            (2, 3600),
            (3, 4 * 3600),
            (4, 12 * 3600),
            (5, 86_400),
            (6, 86_400),
            (7, 86_400),
        ] {
            let job = order(&mut k, now);
            fails(&mut k, &job, now, CaError::new("the authority said no"));
            let record = record_on_disk(&s);
            assert_eq!(
                (record.failures, record.next_attempt_unix - now),
                (failures, wait)
            );
            let at = record.next_attempt_unix;
            assert_eq!(waits_until(&mut k, at - 1), Some(at), "not a second before");
            now = at;
        }

        // A success forgets the failures, and the next failure is the first again.
        let job = order(&mut k, now);
        k.finish_order(&job, Ok(issued(&s)), &book_of(&[APP]), DIR, now);
        let record = record_on_disk(&s);
        assert_eq!(
            (
                record.failures,
                record.next_attempt_unix,
                record.worked.as_str()
            ),
            (0, 0, job.kind.as_str())
        );
        assert_eq!(record.directory, DIR);
        // The certificate is whole now and nothing is due; a new id asks for another.
        apply(&mut k, &[(APP, acme("r2"))]);
        let job = order(&mut k, now + 1);
        fails(&mut k, &job, now + 1, CaError::new("no"));
        let record = record_on_disk(&s);
        assert_eq!((record.failures, record.next_attempt_unix), (1, now + 601));
    }

    #[test]
    fn a_new_request_id_starts_the_backoff_again_and_is_ordered_at_once() {
        let s = Scratch::new();
        let mut k = keys(&s);
        apply(&mut k, &[(APP, acme("r1"))]);
        let mut now = T0;
        for _ in 0..3 {
            let job = order(&mut k, now);
            fails(&mut k, &job, now, CaError::new("no"));
            now = record_on_disk(&s).next_attempt_unix;
        }
        let record = record_on_disk(&s);
        assert_eq!(record.failures, 3);
        // Inside the backoff of four hours, the new id goes at once, and its first failure is the
        // first rung of the ladder.
        let inside = now - 3600;
        apply(&mut k, &[(APP, acme("r2"))]);
        let job = order(&mut k, inside);
        assert_eq!(job.request_id, "r2");
        fails(&mut k, &job, inside, CaError::new("no"));
        let record = record_on_disk(&s);
        assert_eq!(
            (
                record.failures,
                record.next_attempt_unix,
                record.request_id.as_str()
            ),
            (1, inside + 600, "r2")
        );
    }

    #[test]
    fn a_rate_limit_waits_for_the_time_the_authority_names_and_a_new_request_id_does_not_lift_it() {
        let s = Scratch::new();
        let mut k = keys(&s);
        apply(&mut k, &[(APP, acme("r1"))]);
        let job = order(&mut k, T0);
        fails(&mut k, &job, T0, rate_limited(Some("7200")));
        let record = record_on_disk(&s);
        assert_eq!(
            (record.next_attempt_unix, record.ca_wait_unix),
            (T0 + 600, T0 + 7200),
            "the backoff of the agent and the wait of the authority are kept apart"
        );
        // The agent's backoff is over at T0 + 600: the authority's wait holds the order.
        assert_eq!(waits_until(&mut k, T0 + 601), Some(T0 + 7200));
        let [status] = &k.statuses(Some(APP))[..] else {
            panic!("one status");
        };
        assert_eq!(
            (
                status.state.as_str(),
                status.request_id.as_str(),
                status.next_attempt_unix
            ),
            ("failed", "r1", T0 + 7200),
            "the status gives the time the worker waits for"
        );

        // A new request id lifts the backoff, not the wait; its status is failed with that time.
        apply(&mut k, &[(APP, acme("r2"))]);
        assert_eq!(waits_until(&mut k, T0 + 601), Some(T0 + 7200));
        let [status] = &k.statuses(Some(APP))[..] else {
            panic!("one status");
        };
        assert_eq!(
            (
                status.state.as_str(),
                status.request_id.as_str(),
                status.next_attempt_unix
            ),
            ("failed", "r2", T0 + 7200)
        );
        assert!(
            status.error.contains("too many certificates"),
            "{}",
            status.error
        );
        assert_eq!(waits_until(&mut k, T0 + 7199), Some(T0 + 7200));

        // At its end the new id is ordered, and a failure that is no rate limit leaves no wait.
        let job = order(&mut k, T0 + 7200);
        assert_eq!(job.request_id, "r2");
        fails(&mut k, &job, T0 + 7200, CaError::new("no"));
        let record = record_on_disk(&s);
        assert_eq!(
            (
                record.failures,
                record.next_attempt_unix,
                record.ca_wait_unix
            ),
            (1, T0 + 7800, 0)
        );
    }

    #[test]
    fn a_rate_limit_waits_an_hour_at_least_and_a_week_at_most() {
        for (retry_after, wait) in [
            (None, 3600),
            (Some("60"), 3600),
            (Some("not a time"), 3600),
            (Some("90000"), 90_000),
            (Some("99999999999999999999"), 7 * 86_400),
        ] {
            let s = Scratch::new();
            let mut k = keys(&s);
            apply(&mut k, &[(APP, acme("r1"))]);
            let job = order(&mut k, T0);
            fails(&mut k, &job, T0, rate_limited(retry_after));
            assert_eq!(
                record_on_disk(&s).ca_wait_unix - T0,
                wait,
                "{retry_after:?}"
            );
        }
    }

    #[test]
    fn the_start_of_an_order_is_on_disk_and_a_start_that_finds_it_counts_it() {
        let s = Scratch::new();
        let mut k = keys(&s);
        apply(&mut k, &[(APP, acme("r1"))]);
        let job = order(&mut k, T0);
        assert!(!s.dir().join(STATE_FILE).exists(), "nothing yet");
        k.begin_attempt(&job, T0 + 1).unwrap();
        let record = record_on_disk(&s);
        assert_eq!(
            (
                record.attempt_started,
                record.attempt_request_id.as_str(),
                record.interrupted
            ),
            (T0 + 1, "r1", 0)
        );

        // The process is killed: it lets go of nothing but the lock, which the system takes.
        drop(k);
        let mut k = keys(&s);
        apply(&mut k, &[(APP, acme("r1"))]);
        // The first unfinished attempt is no failure; the order is made again at once.
        let job = order(&mut k, T0 + 6);
        let record = record_on_disk(&s);
        assert_eq!(
            (record.attempt_started, record.interrupted, record.failures),
            (0, 1, 0)
        );
        k.begin_attempt(&job, T0 + 6).unwrap();
        assert_eq!(
            record_on_disk(&s).interrupted,
            1,
            "carried with the next note"
        );

        // Killed again: the second in a row is a failure, with the backoff, and no order.
        drop(k);
        let mut k = keys(&s);
        apply(&mut k, &[(APP, acme("r1"))]);
        assert_eq!(waits_until(&mut k, T0 + 11), Some(T0 + 11 + 600));
        let record = record_on_disk(&s);
        assert_eq!(
            (
                record.failures,
                record.next_attempt_unix,
                record.request_id.as_str()
            ),
            (1, T0 + 611, "r1")
        );
        assert_eq!(record.error, INTERRUPTED);
        let [status] = &k.statuses(Some(APP))[..] else {
            panic!("one status");
        };
        assert_eq!(
            (
                status.state.as_str(),
                status.next_attempt_unix,
                status.error.as_str()
            ),
            ("failed", T0 + 611, INTERRUPTED)
        );

        // A start inside the wait finds nothing unfinished, and orders nothing.
        drop(k);
        let mut k = keys(&s);
        apply(&mut k, &[(APP, acme("r1"))]);
        assert_eq!(waits_until(&mut k, T0 + 16), Some(T0 + 611));

        // After the wait the order is made, and killed again: the next one counts at once, with
        // the next rung of the ladder, and does not order again before it.
        let job = order(&mut k, T0 + 611);
        k.begin_attempt(&job, T0 + 611).unwrap();
        drop(k);
        let mut k = keys(&s);
        apply(&mut k, &[(APP, acme("r1"))]);
        assert_eq!(waits_until(&mut k, T0 + 616), Some(T0 + 616 + 3600));
        assert_eq!(record_on_disk(&s).failures, 2);

        // An order that ends, whatever way, is no unfinished attempt: the count starts again.
        let job = order(&mut k, T0 + 616 + 3600);
        k.begin_attempt(&job, T0 + 4300).unwrap();
        fails(&mut k, &job, T0 + 4300, CaError::new("no"));
        let record = record_on_disk(&s);
        assert_eq!(
            (
                record.attempt_started,
                record.attempt_request_id.as_str(),
                record.interrupted
            ),
            (0, "", 0)
        );
        assert_eq!(record.failures, 3);
    }

    #[test]
    fn an_attempt_without_a_note_in_the_state_file_is_not_made() {
        let s = Scratch::new();
        let mut first = keys(&s);
        apply(&mut first, &[(APP, acme("r1"))]);
        let job = order(&mut first, T0);
        // A process that does not hold the lock cannot write the note, so it asks nothing.
        let mut second = keys(&s);
        apply(&mut second, &[(APP, acme("r1"))]);
        assert!(second.begin_attempt(&job, T0).is_err());
        assert!(first.begin_attempt(&job, T0).is_ok());
    }

    /// A first process that holds the lock with an order begun, and a second that started over the
    /// same directory meanwhile and has read that note.
    fn begun_with_a_successor(s: &Scratch) -> (Keys, Keys, CertBook) {
        let mut first = keys(s);
        apply(&mut first, &[(APP, acme("r1"))]);
        let job = order(&mut first, T0);
        first.begin_attempt(&job, T0).unwrap();
        let mut second = keys(s);
        assert!(!second.holds_lock());
        assert_eq!(second.state.apps[APP].attempt_started, T0);
        apply(&mut second, &[(APP, acme("r1"))]);
        (first, second, book_of(&[APP]))
    }

    #[test]
    fn an_order_cut_short_by_a_hand_over_is_no_crash_for_the_process_that_takes_over() {
        let s = Scratch::new();
        let (mut first, mut second, book) = begun_with_a_successor(&s);
        first.release();
        assert!(second.take_over(&book));
        let job = order(&mut second, T0 + 3);
        assert_eq!(job.request_id, "r1", "it orders at once");
        let record = &second.state.apps[APP];
        assert_eq!(
            (record.interrupted, record.failures, record.attempt_started),
            (0, 0, 0),
            "neither a crash nor a failure"
        );
        // Nor does the one after it count the attempt the successor has begun as a crash.
        second.begin_attempt(&job, T0 + 3).unwrap();
        assert_eq!(record_on_disk(&s).interrupted, 0);
    }

    #[test]
    fn an_order_the_predecessor_finishes_is_adopted_and_counts_for_nothing() {
        let s = Scratch::new();
        let (mut first, mut second, book) = begun_with_a_successor(&s);
        // The predecessor's order ends in a failure after the successor read its note.
        let job = Job {
            app_id: APP.to_owned(),
            hosts: vec!["shop.example.com".to_owned()],
            request_id: "r1".to_owned(),
            kind: acme::Kind::TlsAlpn01,
            missing_listener: None,
        };
        fails(&mut first, &job, T0 + 2, CaError::new("no"));
        first.release();
        assert!(second.take_over(&book));
        let record = &second.state.apps[APP];
        assert_eq!(
            (record.failures, record.attempt_started, record.interrupted),
            (1, 0, 0),
            "the failure is adopted, and the note of the order is gone with it"
        );
        assert_eq!(waits_until(&mut second, T0 + 3), Some(T0 + 602));
    }

    #[test]
    fn an_order_that_a_killed_predecessor_left_unfinished_counts_for_the_successor() {
        let s = Scratch::new();
        let (first, mut second, book) = begun_with_a_successor(&s);
        drop(first);
        assert!(second.take_over(&book));
        let job = order(&mut second, T0 + 6);
        assert_eq!(job.request_id, "r1");
        assert_eq!(second.state.apps[APP].interrupted, 1);
    }

    #[test]
    fn a_state_the_agent_could_not_read_back_is_not_written_and_the_file_stays() {
        let s = Scratch::new();
        let mut k = keys(&s);
        apply(&mut k, &[(APP, acme("r1"))]);
        let job = order(&mut k, T0);
        fails(&mut k, &job, T0, CaError::new("no"));
        let before = std::fs::read(s.dir().join(STATE_FILE)).unwrap();

        // More apps than a file can hold, as a corrupt or hostile state in memory might say.
        let mut state = StateFile::default();
        for n in 0..20_000 {
            let record = AppRecord {
                error: "e".repeat(1024),
                request_id: format!("request-{n}"),
                directory: "d".repeat(64),
                ..AppRecord::default()
            };
            state
                .apps
                .insert(format!("{n:08x}-0000-4000-8000-000000000000"), record);
        }
        k.state = state;
        assert!(!k.save_state());
        assert_eq!(std::fs::read(s.dir().join(STATE_FILE)).unwrap(), before);
        assert!(
            k.begin_attempt(&job, T0).is_err(),
            "no order without its note"
        );
        // The file is still one the agent reads.
        assert_eq!(StateFile::load(&k.dir).0.apps.len(), 1);
    }

    fn metric_lines(m: &Arc<TlsMetrics>) -> String {
        let reg = wafio_agent_io::metrics::Registry::new();
        m.register(&reg);
        String::from_utf8(reg.write()).unwrap()
    }

    #[test]
    fn orders_and_installs_are_counted_and_the_expiry_series_follows_what_is_served() {
        let m = Arc::new(TlsMetrics::default());
        let s = Scratch::new();
        let mut k = keys(&s).with_metrics(m.clone());
        let book = book_of(&[APP]);
        let f = fixture();

        // Orders: a failure, then a certificate.
        apply(&mut k, &[(APP, acme("r1"))]);
        let job = order(&mut k, T0);
        fails(&mut k, &job, T0, CaError::new("no"));
        assert!(
            !metric_lines(&m).contains("app_id="),
            "the placeholder has no series"
        );
        let job = order(&mut k, T0 + 600);
        k.finish_order(&job, Ok(issued(&s)), &book, DIR, T0 + 600);
        let text = metric_lines(&m);
        assert!(
            text.contains("wafio_waf_acme_orders_total{result=\"failed\"} 1\n"),
            "{text}"
        );
        assert!(
            text.contains("wafio_waf_acme_orders_total{result=\"issued\"} 1\n"),
            "{text}"
        );
        let expiry = format!("wafio_waf_tls_certificate_expiry_seconds{{app_id=\"{APP}\"}} ");
        assert!(text.contains(&expiry), "{text}");
        assert!(
            text.matches("app_id=").count() == 1 && !text.contains(&format!("{OTHER_APP}\"")),
            "{text}"
        );

        // An order that is dropped, or one that is cut short once, counts as neither.
        apply(&mut k, &[(APP, acme("r2"))]);
        let job = order(&mut k, T0 + 700);
        k.begin_attempt(&job, T0 + 700).unwrap();
        apply(&mut k, &[]);
        k.finish_order(&job, Ok(issued(&s)), &book, DIR, T0 + 800);
        let text = metric_lines(&m);
        assert!(
            text.contains("wafio_waf_acme_orders_total{result=\"issued\"} 1\n"),
            "{text}"
        );
        assert!(!text.contains("app_id="), "the app left the bundle: {text}");

        // Installs: a refusal and an install that holds, then the app stops serving it.
        apply(&mut k, &[(APP, uploaded(X, &f.ec.leaf))]);
        let book = book_of(&[APP]);
        assert_eq!(
            install_pair(&mut k, &book, &f.rsa, Y),
            Err(AckCode::NotInBundle)
        );
        assert_eq!(install_pair(&mut k, &book, &f.ec, X), Ok(()));
        let text = metric_lines(&m);
        for line in [
            "wafio_waf_certificate_installs_total{result=\"ok\"} 1\n",
            "wafio_waf_certificate_installs_total{result=\"not_in_bundle\"} 1\n",
        ] {
            assert!(text.contains(line), "{line}: {text}");
        }
        assert!(text.contains(&expiry), "served after the install: {text}");
        let nothing = r#"{"listen":"0.0.0.0:443","hosts":["shop.example.com"],"source":""}"#;
        apply(&mut k, &[(APP, nothing.to_owned())]);
        assert!(
            !metric_lines(&m).contains("app_id="),
            "it stops serving that certificate"
        );
    }
}
