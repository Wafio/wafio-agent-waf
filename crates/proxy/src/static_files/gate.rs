//! A bound on the blocking threads the folders use. The runtime has one pool of blocking threads
//! (512 by default) that the control link, compression and the key work share, and a disk that
//! stops answering (a network mount whose server is down, a failing drive) parks every thread
//! that touches it for good. The folders therefore hold a few slots of that pool. A request waits
//! a moment for one (a burst on a healthy disk is served), and a disk that has taken them all
//! turns the rest away.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How long a look or a read may take, and how long a read waits for a slot, before the disk is
/// taken as not answering.
pub(crate) const DISK_DEADLINE: Duration = Duration::from_secs(5);

/// How long a lookup waits for a slot: long enough for a burst of requests on a healthy disk to
/// take their turns, short enough that a disk that has stopped answering costs a request little.
pub(crate) const LOOKUP_WAIT: Duration = Duration::from_millis(100);

/// The fewest slots a gate has; more workers get two slots each.
const MIN_SLOTS: usize = 8;

/// One slot of a gate, held by the work that took it. Dropping it gives the slot back.
pub(crate) type Slot = OwnedSemaphorePermit;

#[derive(Clone)]
pub(crate) struct DiskGate {
    slots: Arc<Semaphore>,
    deadline: Duration,
}

impl DiskGate {
    pub fn new(slots: usize, deadline: Duration) -> DiskGate {
        DiskGate {
            slots: Arc::new(Semaphore::new(slots)),
            deadline,
        }
    }

    /// The slots of a gate that the options do not size: twice the workers, at least
    /// [`MIN_SLOTS`].
    pub fn default_slots() -> usize {
        (2 * crate::worker_count()).max(MIN_SLOTS)
    }

    /// How long a read may take, and how long it waits for a slot.
    pub fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Runs `work` on a blocking thread and returns what it returned. `None` when no slot came
    /// free within `wait` (zero: none is waited for), when the work did not return within the
    /// deadline, or when it panicked; each is counted. The wait holds no thread. The slot is held
    /// by the thread and given back only when `work` returns, so a thread that is stuck on the
    /// disk keeps its slot and no more threads pile up behind it. Work that hands back more than
    /// 64 KiB fills a buffer the caller made (see `LOOKUP_READ_MAX` in the parent module).
    pub async fn run<T: Send + 'static>(
        &self,
        wait: Duration,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        self.run_counting(wait, crate::metrics::count_static_unavailable, work)
            .await
    }

    /// [`DiskGate::run`] that calls `unavailable` instead of counting a static folder's miss, for
    /// work that is not a folder's.
    pub async fn run_counting<T: Send + 'static>(
        &self,
        wait: Duration,
        unavailable: fn(),
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        self.run_slot(wait, unavailable, move |_slot| work()).await
    }

    /// [`DiskGate::run_counting`] for work that is given its slot and may hand it back in its
    /// result, to be used by [`DiskGate::run_held`] for a second step.
    pub async fn run_slot<T: Send + 'static>(
        &self,
        wait: Duration,
        unavailable: fn(),
        work: impl FnOnce(Slot) -> T + Send + 'static,
    ) -> Option<T> {
        let slot = tokio::time::timeout(wait, self.slots.clone().acquire_owned())
            .await
            .ok()
            .and_then(Result::ok);
        let Some(slot) = slot else {
            unavailable();
            return None;
        };
        self.spawn(unavailable, move || work(slot)).await
    }

    /// Runs `work` on a blocking thread on a slot that is already held, so that a file the first
    /// step found is read on the slot that found it and the descriptor closes on a blocking thread:
    /// no second wait, only the deadline. The slot goes back when `work` returns. As for
    /// [`DiskGate::run`], `None` when the work did not return within the deadline or panicked.
    pub async fn run_held<T: Send + 'static>(
        &self,
        slot: Slot,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        self.spawn(crate::metrics::count_static_unavailable, move || {
            let _slot = slot;
            work()
        })
        .await
    }

    async fn spawn<T: Send + 'static>(
        &self,
        unavailable: fn(),
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        match tokio::time::timeout(self.deadline, tokio::task::spawn_blocking(job)).await {
            Ok(Ok(out)) => Some(out),
            Ok(Err(_)) => {
                crate::metrics::count_agent_panic();
                None
            }
            Err(_) => {
                unavailable();
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    const SHORT: Duration = Duration::from_millis(150);
    const NO_WAIT: Duration = Duration::ZERO;

    /// A job that returns when the test sends on the channel it is given.
    fn held() -> (mpsc::Sender<()>, impl FnOnce() -> u32 + Send + 'static) {
        let (tx, rx) = mpsc::channel::<()>();
        (tx, move || {
            let _ = rx.recv();
            7
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn work_that_returns_gives_its_result_and_its_slot_back() {
        let gate = DiskGate::new(1, SHORT);
        for round in 0..3 {
            assert_eq!(gate.run(NO_WAIT, move || round).await, Some(round));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_gate_runs_nothing_and_counts_it() {
        let gate = DiskGate::new(0, SHORT);
        let before = crate::metrics::STATIC_UNAVAILABLE.load(std::sync::atomic::Ordering::Relaxed);
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        let out = gate
            .run(NO_WAIT, move || {
                flag.store(true, std::sync::atomic::Ordering::SeqCst)
            })
            .await;
        assert_eq!(out, None);
        assert!(
            !ran.load(std::sync::atomic::Ordering::SeqCst),
            "the work did not start"
        );
        let after = crate::metrics::STATIC_UNAVAILABLE.load(std::sync::atomic::Ordering::Relaxed);
        assert!(after > before, "the refusal is counted");
    }

    /// The slot of a job that does not return in time stays taken, so the next request is turned
    /// away at once and the stuck threads cannot grow past the slots; when the job does return the
    /// slot is free again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_job_that_does_not_return_keeps_its_slot_until_it_does() {
        let gate = DiskGate::new(1, SHORT);
        let (release, stuck) = held();
        assert_eq!(
            gate.run(NO_WAIT, stuck).await,
            None,
            "no answer within the deadline"
        );
        let started = std::time::Instant::now();
        assert_eq!(
            gate.run(NO_WAIT, || 1).await,
            None,
            "the slot is still held"
        );
        assert!(
            started.elapsed() < SHORT,
            "a full gate answers without waiting"
        );
        release.send(()).unwrap();
        let mut got = None;
        for _ in 0..50 {
            got = gate.run(NO_WAIT, || 2).await;
            if got.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(got, Some(2), "the slot is given back when the job returns");
    }

    /// A read that must not be cut because the gate is briefly full waits for a slot, but only up
    /// to the deadline.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_queued_job_waits_for_a_slot_and_gives_up_at_the_deadline() {
        let gate = Arc::new(DiskGate::new(1, Duration::from_secs(5)));
        let (release, stuck) = held();
        let first = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.run(NO_WAIT, stuck).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        let waiting = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.run(Duration::from_secs(5), || 3).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        release.send(()).unwrap();
        assert_eq!(first.await.unwrap(), Some(7));
        assert_eq!(
            waiting.await.unwrap(),
            Some(3),
            "it ran once the slot came free"
        );

        let short = DiskGate::new(1, SHORT);
        let (_keep, stuck) = held();
        assert_eq!(short.run(NO_WAIT, stuck).await, None);
        let started = std::time::Instant::now();
        assert_eq!(short.run(SHORT, || 4).await, None, "no slot came free");
        assert!(started.elapsed() >= SHORT, "it waited the deadline first");
    }

    /// A file the first step found is read on the slot that found it: with the gate full, the
    /// second step still runs at once, and the slot is free again after it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_step_runs_on_the_slot_of_the_first_and_gives_it_back() {
        let gate = DiskGate::new(1, SHORT);
        let slot = gate
            .run_slot(NO_WAIT, || {}, |slot| slot)
            .await
            .expect("the slot was free");
        assert_eq!(gate.run(NO_WAIT, || 1).await, None, "the gate is full");
        let started = std::time::Instant::now();
        assert_eq!(
            gate.run_held(slot, || 2).await,
            Some(2),
            "the second step needs no other slot"
        );
        assert!(started.elapsed() < SHORT, "and waits for none");
        assert_eq!(gate.run(NO_WAIT, || 3).await, Some(3), "the slot is back");
    }

    /// A second step on a stuck disk is cut at the deadline, and its thread keeps the slot.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_step_that_does_not_return_keeps_the_slot_until_it_does() {
        let gate = DiskGate::new(1, SHORT);
        let slot = gate.run_slot(NO_WAIT, || {}, |slot| slot).await.unwrap();
        let (release, stuck) = held();
        assert_eq!(gate.run_held(slot, stuck).await, None);
        assert_eq!(
            gate.run(NO_WAIT, || 1).await,
            None,
            "the slot is still held"
        );
        release.send(()).unwrap();
        let mut got = None;
        for _ in 0..50 {
            got = gate.run(NO_WAIT, || 2).await;
            if got.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(got, Some(2), "the slot is given back when the job returns");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_job_that_panics_gives_nothing_and_its_slot_back() {
        let gate = DiskGate::new(1, SHORT);
        let before = crate::metrics::PANIC_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            gate.run(NO_WAIT, || -> u32 { panic!("on purpose") }).await,
            None
        );
        assert!(crate::metrics::PANIC_COUNT.load(std::sync::atomic::Ordering::Relaxed) > before);
        assert_eq!(gate.run(NO_WAIT, || 5).await, Some(5));
    }
}
