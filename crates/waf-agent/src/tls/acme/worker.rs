//! The worker that orders certificates, one at a time, for the apps whose source is `acme`: the
//! app that has been due the longest first. It runs in the process that holds the key directory
//! lock and is stopped when the lock is handed over.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use super::ATTEMPT_CAP;
use super::account::{ACCOUNT_UNKNOWN, AccountFile, Accounts};
use super::ca::{Ca, CaError};
use super::order::{self, Issued, Job};
use super::wait::RATE_LIMITED;
use crate::agent::Agent;
use crate::tls::NextOrder;

/// The longest the worker sleeps before it looks again. A sleep counts the time the process runs,
/// not the clock the due times are in, which may be set or may go on while the machine is
/// suspended.
const MAX_SLEEP: Duration = Duration::from_secs(3600);

/// An order that runs as a task of its own, so that a panic in it ends that order and not the
/// worker, and that is stopped when the worker is: whatever it put up is taken down when its
/// future is dropped.
struct Attempt(JoinHandle<Result<Issued, CaError>>);

impl Drop for Attempt {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct Worker {
    agent: Arc<Agent>,
    ca: Arc<dyn Ca>,
    accounts: Arc<tokio::sync::Mutex<Accounts>>,
    directory: String,
    /// The time, in seconds since the epoch. A test moves it.
    clock: fn() -> i64,
}

impl Worker {
    pub fn new(
        agent: Arc<Agent>,
        ca: Arc<dyn Ca>,
        file: Arc<dyn AccountFile>,
        directory: String,
        clock: fn() -> i64,
    ) -> Worker {
        let accounts = Accounts::new(ca.clone(), file, directory.clone());
        Worker {
            agent,
            ca,
            accounts: Arc::new(tokio::sync::Mutex::new(accounts)),
            directory,
            clock,
        }
    }

    /// Orders what is due, waits for the next thing that is, and ends when the agent closes.
    pub async fn run(self) {
        loop {
            let now = (self.clock)();
            // It may write the state file, so it runs where a write may.
            let (agent, directory) = (self.agent.clone(), self.directory.clone());
            let next = tokio::task::spawn_blocking(move || agent.next_order(now, &directory)).await;
            let until = match next {
                Ok(None) | Err(_) => return,
                Ok(Some(NextOrder::Order(job))) => {
                    self.order(job).await;
                    continue;
                }
                Ok(Some(NextOrder::Wait(until))) => until,
            };
            // A change that comes between the question and the wait is not lost: it leaves a note.
            let changed = self.agent.orders_changed();
            match until {
                Some(until) => {
                    let wait = Duration::from_secs(until.saturating_sub(now).max(1).unsigned_abs())
                        .min(MAX_SLEEP);
                    tokio::select! {
                        () = changed => {}
                        () = tokio::time::sleep(wait) => {}
                    }
                }
                None => changed.await,
            }
        }
    }

    async fn order(&self, job: Job) {
        let result = self.attempt(&job).await.map_err(|mut e| {
            // The client library leaves `Retry-After` out of an error, and a rate limit sets its
            // wait by it.
            if e.problem.as_deref() == Some(RATE_LIMITED) {
                e.retry_after = self.ca.retry_after();
            }
            e
        });
        if let Err(e) = &result
            && e.problem.as_deref() == Some(ACCOUNT_UNKNOWN)
        {
            self.accounts.lock().await.forget().await;
        }
        let (agent, directory, now) = (self.agent.clone(), self.directory.clone(), (self.clock)());
        let ended = job.clone();
        let done =
            tokio::task::spawn_blocking(move || agent.order_done(&job, result, &directory, now))
                .await;
        if done.is_err() {
            self.stopped(&ended).await;
        }
    }

    /// An order that panicked while it was taken in is noted as failed, so the next one waits. It
    /// writes the key directory, so it runs under `spawn_blocking`; a second panic only lets go.
    async fn stopped(&self, job: &Job) {
        let (agent, ended, now) = (self.agent.clone(), job.clone(), (self.clock)());
        let noted = tokio::task::spawn_blocking(move || agent.order_stopped(&ended, now)).await;
        if noted.is_err() {
            tracing::info!(
                "[acme] app {}: the order could not be noted as failed; it is let go of",
                job.app_id
            );
            self.agent.abandon_order(&job.app_id);
        }
    }

    /// One order, within the time an attempt may take. A failure is a value, a panic and the cap
    /// included.
    async fn attempt(&self, job: &Job) -> Result<Issued, CaError> {
        // Nothing is asked of the authority before the state file says an order has begun: a
        // process that is killed and started again over and over must not make an order each time.
        let (agent, begun, now) = (self.agent.clone(), job.clone(), (self.clock)());
        match tokio::task::spawn_blocking(move || agent.begin_attempt(&begun, now)).await {
            Ok(Ok(())) => {}
            Ok(Err(why)) => return Err(CaError::new(why)),
            Err(_) => return Err(CaError::new("the order stopped on an internal error")),
        }
        let (accounts, book, job) = (
            self.accounts.clone(),
            self.agent.certificate_book(),
            job.clone(),
        );
        let mut task = Attempt(tokio::spawn(async move {
            let account = accounts.lock().await.get().await?;
            order::execute(&*account, &book, &job).await
        }));
        match tokio::time::timeout(ATTEMPT_CAP, &mut task.0).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) if e.is_panic() => {
                Err(CaError::new("the order stopped on an internal error"))
            }
            Ok(Err(_)) => Err(CaError::new("the order was stopped")),
            Err(_) => {
                // Wait for the order to be gone, so that what it put up is taken down by now.
                task.0.abort();
                let _ = (&mut task.0).await;
                Err(CaError::new("the order took longer than 3 minutes"))
            }
        }
    }
}
