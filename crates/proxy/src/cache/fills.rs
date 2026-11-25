//! The fill lock and the marks of keys that are not kept. One request at a time fetches the answer
//! for a key that has no copy; the others wait for it, up to [`FILL_WAIT`], instead of asking the
//! application together. A fill that ends with nothing stored wakes every waiter at once, and
//! marks the key so that the next requests do not queue behind a fill that will not help them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::watch;

use super::key::PrimaryId;

/// The longest a request waits for another's fill of its key.
pub(crate) const FILL_WAIT: Duration = Duration::from_secs(5);
/// How long a key stays marked as not kept when the answer does not say.
pub(crate) const MARK_DEFAULT_S: u64 = 30;
/// The longest a mark lasts, whatever the answer says.
pub(crate) const MARK_MAX_S: u64 = 600;
/// The most keys marked at once; past it a key is simply not marked.
const MARKS_MAX: usize = 4096;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
pub(crate) struct Fills {
    inflight: Mutex<HashMap<PrimaryId, watch::Receiver<()>>>,
    /// Key to the second its mark ends.
    marks: Mutex<HashMap<PrimaryId, u64>>,
}

/// Held by the request that fetches the answer for a key. Dropping it, however the fetch ended,
/// wakes the requests that wait.
pub(crate) struct FillGuard {
    fills: Arc<Fills>,
    id: PrimaryId,
    _done: watch::Sender<()>,
}

impl Drop for FillGuard {
    fn drop(&mut self) {
        lock(&self.fills.inflight).remove(&self.id);
        // `_done` drops after this, which ends every wait.
    }
}

/// What a request finds when it wants the key.
pub(crate) enum Turn {
    /// The request fetches the answer.
    Lead(FillGuard),
    /// Another request is fetching it: wait for it with [`wait`].
    Wait(watch::Receiver<()>),
    /// The key is marked as not kept, or the request may not fill and nothing is in flight: go on.
    Free,
}

impl Fills {
    /// The turn of a request for `id` at second `now`. `lead` says the request may fetch for
    /// others (it can make a copy); one that cannot waits for a fetch that is in flight and
    /// otherwise goes on.
    pub fn turn(self: &Arc<Self>, id: PrimaryId, lead: bool, now: u64) -> Turn {
        if self.marked(&id, now) {
            return Turn::Free;
        }
        let mut inflight = lock(&self.inflight);
        if let Some(rx) = inflight.get(&id) {
            return Turn::Wait(rx.clone());
        }
        if !lead {
            return Turn::Free;
        }
        let (tx, rx) = watch::channel(());
        inflight.insert(id, rx);
        Turn::Lead(FillGuard {
            fills: self.clone(),
            id,
            _done: tx,
        })
    }

    /// Takes the lock only if nobody has it and the key is not marked: a refresh in the background
    /// is one at a time, and is skipped when anything is already fetching the key.
    pub fn try_lead(self: &Arc<Self>, id: PrimaryId, now: u64) -> Option<FillGuard> {
        match self.turn(id, true, now) {
            Turn::Lead(guard) => Some(guard),
            Turn::Wait(_) | Turn::Free => None,
        }
    }

    /// Marks the key as not kept for `seconds` from `now`.
    pub fn mark(&self, id: PrimaryId, seconds: u64, now: u64) {
        let mut marks = lock(&self.marks);
        if marks.len() >= MARKS_MAX {
            marks.retain(|_, until| *until > now);
        }
        if marks.len() < MARKS_MAX || marks.contains_key(&id) {
            marks.insert(id, now.saturating_add(seconds.min(MARK_MAX_S)));
        }
    }

    pub fn marked(&self, id: &PrimaryId, now: u64) -> bool {
        lock(&self.marks).get(id).is_some_and(|until| now < *until)
    }

    /// Forgets the marks, which a purge or a change of settings may have made untrue.
    pub fn clear_marks(&self) {
        lock(&self.marks).clear();
    }
}

/// Waits for the fetch behind `rx` to end, at most [`FILL_WAIT`]. Returns true when it ended.
pub(crate) async fn wait(rx: watch::Receiver<()>) -> bool {
    wait_up_to(rx, FILL_WAIT).await
}

async fn wait_up_to(mut rx: watch::Receiver<()>, limit: Duration) -> bool {
    tokio::time::timeout(limit, rx.changed()).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> PrimaryId {
        [n; 32]
    }

    #[tokio::test]
    async fn one_request_leads_the_others_wait_and_wake_when_the_guard_drops() {
        let fills = Arc::new(Fills::default());
        let Turn::Lead(guard) = fills.turn(id(1), true, 100) else {
            panic!("the first leads");
        };
        let Turn::Wait(rx) = fills.turn(id(1), true, 100) else {
            panic!("the second waits");
        };
        let Turn::Wait(other) = fills.turn(id(1), false, 100) else {
            panic!("one that cannot fill waits too");
        };
        assert!(
            matches!(fills.turn(id(2), true, 100), Turn::Lead(_)),
            "another key"
        );
        let waiting = tokio::spawn(async move { (wait(rx).await, wait(other).await) });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!waiting.is_finished());
        drop(guard);
        let (a, b) = tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(a && b, "both woke at once when the fetch ended");
        assert!(
            matches!(fills.turn(id(1), true, 100), Turn::Lead(_)),
            "the lock is free again"
        );
    }

    #[tokio::test]
    async fn a_wait_ends_at_its_limit_when_nothing_wakes_it() {
        let fills = Arc::new(Fills::default());
        let Turn::Lead(_guard) = fills.turn(id(1), true, 0) else {
            panic!()
        };
        let Turn::Wait(rx) = fills.turn(id(1), true, 0) else {
            panic!()
        };
        assert!(
            !wait_up_to(rx, Duration::from_millis(50)).await,
            "timed out"
        );
        assert_eq!(FILL_WAIT, Duration::from_secs(5));
    }

    #[test]
    fn a_request_that_cannot_fill_does_not_take_the_lock() {
        let fills = Arc::new(Fills::default());
        assert!(matches!(fills.turn(id(1), false, 100), Turn::Free));
        assert!(matches!(fills.turn(id(1), true, 100), Turn::Lead(_)));
    }

    #[test]
    fn a_marked_key_has_no_lock_until_the_mark_ends() {
        let fills = Arc::new(Fills::default());
        fills.mark(id(1), 30, 100);
        assert!(fills.marked(&id(1), 129) && !fills.marked(&id(1), 130));
        assert!(matches!(fills.turn(id(1), true, 129), Turn::Free));
        let held = fills.turn(id(1), true, 130);
        assert!(matches!(held, Turn::Lead(_)));
        assert!(fills.try_lead(id(1), 130).is_none(), "the lock is taken");
        fills.mark(id(2), 5000, 0);
        assert!(fills.marked(&id(2), MARK_MAX_S - 1) && !fills.marked(&id(2), MARK_MAX_S));
        fills.clear_marks();
        assert!(!fills.marked(&id(2), 1));
    }

    #[test]
    fn the_marks_are_bounded() {
        let fills = Fills::default();
        for n in 0..(MARKS_MAX as u32 + 10) {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&n.to_le_bytes());
            fills.mark(key, 30, 100);
        }
        assert!(lock(&fills.marks).len() <= MARKS_MAX);
        // Ended marks make room.
        let mut key = [9u8; 32];
        key[0] = 7;
        fills.mark(key, 30, 10_000);
        assert!(fills.marked(&key, 10_001));
    }
}
