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
use crate::agent::Agent;
use crate::tls::NextOrder;

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
        let accounts = Accounts::new(ca, file, directory.clone());
        Worker {
            agent,
            accounts: Arc::new(tokio::sync::Mutex::new(accounts)),
            directory,
            clock,
        }
    }

    /// Orders what is due, waits for the next thing that is, and ends when the agent closes.
    pub async fn run(self) {
        loop {
            let now = (self.clock)();
            let until = match self.agent.next_order(now) {
                None => return,
                Some(NextOrder::Order(job)) => {
                    self.order(job).await;
                    continue;
                }
                Some(NextOrder::Wait(until)) => until,
            };
            // A change that comes between the question and the wait is not lost: it leaves a note.
            let changed = self.agent.orders_changed();
            match until {
                Some(until) => {
                    let wait = Duration::from_secs(until.saturating_sub(now).max(1).unsigned_abs());
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
        let result = self.attempt(&job).await;
        if let Err(e) = &result
            && e.problem.as_deref() == Some(ACCOUNT_UNKNOWN)
        {
            self.accounts.lock().await.forget().await;
        }
        let (agent, directory, now) = (self.agent.clone(), self.directory.clone(), (self.clock)());
        let stopped = job.clone();
        let done =
            tokio::task::spawn_blocking(move || agent.order_done(&job, result, &directory, now))
                .await;
        if done.is_err() {
            // The order is over and the next one must not wait for it, nor start at once.
            self.agent.order_stopped(&stopped, (self.clock)());
        }
    }

    /// One order, within the time an attempt may take. A failure is a value, a panic and the cap
    /// included.
    async fn attempt(&self, job: &Job) -> Result<Issued, CaError> {
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
