//! The agent's side of ordering certificates: what the worker asks of the applied state, under the
//! apply lock, and how the worker is started and stopped.

use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use wafio_proxy::cert_store::CertBook;
use zeroize::Zeroizing;

use super::Agent;
use crate::tls::NextOrder;
use crate::tls::acme::ACCOUNT_FILE;
use crate::tls::acme::account::AccountFile;
use crate::tls::acme::ca::{Ca, CaError};
use crate::tls::acme::order::{Issued, Job};
use crate::tls::acme::worker::Worker;
use crate::tls::dir::MAX_KEY_FILE;
use crate::tls::status;

/// What wakes the worker, and the worker.
#[derive(Default)]
pub(super) struct Orders {
    wake: Notify,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl Orders {
    /// Something that decides what is due changed.
    pub(super) fn wake(&self) {
        self.wake.notify_one();
    }

    /// Stops the worker, and the order it is running with it: whatever the order put up is taken
    /// down as the order is dropped.
    pub(super) fn stop(&self) {
        let worker = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(worker) = worker {
            worker.abort();
        }
    }
}

/// The account file of the key directory, for the worker.
struct AccountInKeyDir(Arc<Agent>);

impl AccountFile for AccountInKeyDir {
    fn read(&self) -> Option<Zeroizing<Vec<u8>>> {
        let st = self.0.lock();
        let bytes = st
            .tls
            .as_ref()?
            .read_file(ACCOUNT_FILE, MAX_KEY_FILE)
            .ok()?;
        Some(Zeroizing::new(bytes))
    }

    fn write(&self, text: &[u8]) -> Result<(), String> {
        let st = self.0.lock();
        let keys = st.tls.as_ref().ok_or("no key directory")?;
        keys.write_file(ACCOUNT_FILE, text)
            .map_err(|e| e.kind().to_string())
    }

    fn remove(&self) {
        if let Some(keys) = self.0.lock().tls.as_ref() {
            let _ = keys.remove_file(ACCOUNT_FILE);
        }
    }
}

impl Agent {
    /// Starts the worker that orders the certificates of the apps whose source is `acme` from the
    /// authority at `directory`. It orders only while this process holds the key directory lock,
    /// and is stopped when the lock is let go.
    pub fn start_acme(self: &Arc<Agent>, ca: Arc<dyn Ca>, directory: String) {
        self.start_acme_with(ca, directory, status::unix_now);
    }

    /// `start_acme` with the clock the worker reads, which a test moves.
    pub(crate) fn start_acme_with(
        self: &Arc<Agent>,
        ca: Arc<dyn Ca>,
        directory: String,
        clock: fn() -> i64,
    ) {
        let account = Arc::new(AccountInKeyDir(self.clone()));
        let worker = Worker::new(self.clone(), ca, account, directory, clock);
        let handle = tokio::spawn(worker.run());
        let mut slot = self.orders.worker.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = slot.replace(handle) {
            old.abort();
        }
    }

    /// The book of certificates and challenge answers of the TLS listeners.
    pub fn certificate_book(&self) -> Arc<CertBook> {
        self.routes.certificates()
    }

    /// Waits until something that decides what is due may have changed.
    pub(crate) async fn orders_changed(&self) {
        self.orders.wake.notified().await;
    }

    /// The order to start next, if one is due, when the authority at `directory` is the one the
    /// agent orders from. A started order is reported `pending`, and so is whatever the look
    /// changed: a crash loop counted as a failure, a wait that ended. Blocking: it may write.
    pub(crate) fn next_order(&self, now: i64, directory: &str) -> Option<NextOrder> {
        let mut guard = self.lock();
        let st = &mut *guard;
        if st.closed {
            return None;
        }
        if st.orders_paused {
            return Some(NextOrder::Wait(None));
        }
        let keys = st.tls.as_mut()?;
        let (next, changed) = keys.next_order(now, directory);
        if let Some(out) = &self.statuses {
            if changed {
                out.changed(keys.statuses(None));
            } else if let NextOrder::Order(job) = &next {
                out.changed(keys.statuses(Some(&job.app_id)));
            }
        }
        Some(next)
    }

    /// Notes the start of the order of `job` in the state file, before the authority is asked
    /// anything; see `Keys::begin_attempt`. Blocking: it writes.
    pub(crate) fn begin_attempt(&self, job: &Job, now: i64) -> Result<(), String> {
        let mut guard = self.lock();
        let keys = guard.tls.as_mut().ok_or("there is no key directory")?;
        keys.begin_attempt(job, now)
    }

    /// An order ended on an internal error while it was taken in; see `Keys::stop_order`.
    /// Blocking: it may write.
    pub(crate) fn order_stopped(&self, job: &Job, now: i64) {
        let mut guard = self.lock();
        let st = &mut *guard;
        let Some(keys) = st.tls.as_mut() else { return };
        keys.stop_order(job, &self.routes.certificates(), now);
        if let Some(out) = &self.statuses {
            out.changed(keys.statuses(Some(&job.app_id)));
        }
    }

    /// Lets go of an order that nothing could take in, so that the worker goes on.
    pub(crate) fn abandon_order(&self, app_id: &str) {
        if let Some(keys) = self.lock().tls.as_mut() {
            keys.abandon_order(app_id);
        }
    }

    /// No new order starts until `resume_orders`: the authority's check of a name could reach the
    /// successor being started, which has no answer for it. A running order goes on.
    pub fn pause_orders(&self) {
        self.lock().orders_paused = true;
    }

    /// The take-over failed: orders start again.
    pub fn resume_orders(&self) {
        self.lock().orders_paused = false;
        self.orders.wake();
    }

    /// Takes in what an order came to, and reports the state it leaves. Blocking: it may write.
    pub(crate) fn order_done(
        &self,
        job: &Job,
        outcome: Result<Issued, CaError>,
        directory: &str,
        now: i64,
    ) {
        let mut guard = self.lock();
        let st = &mut *guard;
        let Some(keys) = st.tls.as_mut() else { return };
        // A process that has closed still takes in an order that ends while it holds the lock:
        // the one that takes over finds the certificate and does not order again. Once the lock is
        // handed over it writes nothing, and the one that takes over orders.
        if st.closed && !keys.holds_lock() {
            keys.abandon_order(&job.app_id);
            return;
        }
        keys.finish_order(job, outcome, &self.routes.certificates(), directory, now);
        if let Some(out) = &self.statuses {
            out.changed(keys.statuses(Some(&job.app_id)));
        }
    }
}
