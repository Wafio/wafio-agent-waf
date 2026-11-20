//! When the agent sends the certificate status of an app.
//!
//! The control plane takes a few statuses of an app at once and then one every 10 seconds, so the
//! pacer lets each app send at most one in that time. What it is given is the latest status of an
//! app, never a list of changes: a change that comes inside the window goes out at its end, as the
//! latest state, and the ones before it are not sent. A status that asks for a certificate
//! (`missing`) is repeated every minute until the state changes, as the control plane expects.
//!
//! The pacer knows nothing of where a state comes from: whoever decides a status offers it, so
//! the states of an ordered certificate go through it as they are.

use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::time::Instant;
use wafio_control::CertificateStatus;

use super::status::State;

/// The shortest time between two statuses of one app.
pub const MIN_GAP: Duration = Duration::from_secs(10);
/// How often a `missing` status is sent again.
pub const MISSING_EVERY: Duration = Duration::from_secs(60);

/// Statuses for the pacer, from whoever knows a state.
pub struct Offer {
    pub statuses: Vec<CertificateStatus>,
    /// Send them even when they say what the last one said: a live bundle was handled, and the
    /// control plane takes the first status after each as the answer to it.
    pub forced: bool,
    /// The statuses are all there are: an app that is not among them has left the bundle, and
    /// nothing more is said of it.
    pub whole: bool,
}

/// The end of the pacer that states are offered to.
#[derive(Clone)]
pub struct Statuses(mpsc::UnboundedSender<Offer>);

/// The end that reads the offers, for `run`.
pub struct Offers(mpsc::UnboundedReceiver<Offer>);

impl Statuses {
    pub fn channel() -> (Statuses, Offers) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Statuses(tx), Offers(rx))
    }

    /// A live bundle was handled; these are the statuses it leaves. With `whole` the apps that are
    /// not among them are forgotten.
    pub fn after_bundle(&self, statuses: Vec<CertificateStatus>, whole: bool) {
        self.offer(statuses, true, whole);
    }

    /// The state of these apps may have changed; the pacer sends what differs from the last.
    pub fn changed(&self, statuses: Vec<CertificateStatus>) {
        self.offer(statuses, false, false);
    }

    fn offer(&self, statuses: Vec<CertificateStatus>, forced: bool, whole: bool) {
        // The pacer ends with the process; an offer to a pacer that has gone is of no use.
        let _ = self.0.send(Offer {
            statuses,
            forced,
            whole,
        });
    }
}

impl Offers {
    /// What has been offered and not yet taken, for a test of the side that offers.
    #[cfg(test)]
    pub fn drain(&mut self) -> Vec<Offer> {
        std::iter::from_fn(|| self.0.try_recv().ok()).collect()
    }
}

/// What the control plane should hear about one app, and what it has heard.
struct Slot {
    wanted: CertificateStatus,
    sent: Option<(Instant, CertificateStatus)>,
    /// A live bundle asked for a status, which goes even if it says what the last one said.
    forced: bool,
    /// When `wanted` is sent next, if it is.
    due: Option<Instant>,
}

impl Slot {
    /// When `wanted` goes. A status that differs from the last, or that a bundle asked for, goes
    /// at once, or when the gap since the last one is over; a `missing` one that is neither goes
    /// again a minute after the last; nothing else is due.
    fn next_due(&self, now: Instant) -> Option<Instant> {
        let last = self.sent.as_ref().map(|(at, _)| *at);
        let changed = self
            .sent
            .as_ref()
            .is_none_or(|(_, sent)| !same(sent, &self.wanted));
        if self.forced || changed {
            Some(last.map_or(now, |at| (at + MIN_GAP).max(now)))
        } else if self.wanted.state == State::Missing.as_str() {
            last.map(|at| at + MISSING_EVERY)
        } else {
            None
        }
    }
}

/// Whether two statuses say the same, whatever time they were made.
fn same(a: &CertificateStatus, b: &CertificateStatus) -> bool {
    CertificateStatus {
        unix_time: 0,
        ..a.clone()
    } == CertificateStatus {
        unix_time: 0,
        ..b.clone()
    }
}

#[derive(Default)]
pub struct Pacer {
    slots: BTreeMap<String, Slot>,
}

impl Pacer {
    pub fn offer(&mut self, now: Instant, offer: Offer) {
        if offer.whole {
            let named: HashSet<&str> = offer.statuses.iter().map(|s| s.app_id.as_str()).collect();
            self.slots.retain(|app, _| named.contains(app.as_str()));
        }
        for status in offer.statuses {
            let slot = self
                .slots
                .entry(status.app_id.clone())
                .or_insert_with(|| Slot {
                    wanted: status.clone(),
                    sent: None,
                    forced: false,
                    due: None,
                });
            slot.wanted = status;
            slot.forced |= offer.forced;
            slot.due = slot.next_due(now);
        }
    }

    /// When the next status is due, if any is.
    pub fn next_due(&self) -> Option<Instant> {
        self.slots.values().filter_map(|s| s.due).min()
    }

    /// The statuses that are due at `now`, made now.
    pub fn take_due(&mut self, now: Instant) -> Vec<CertificateStatus> {
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
        let mut due = Vec::new();
        for slot in self.slots.values_mut() {
            if slot.due.is_none_or(|at| at > now) {
                continue;
            }
            slot.sent = Some((now, slot.wanted.clone()));
            slot.forced = false;
            slot.due = slot.next_due(now);
            due.push(CertificateStatus {
                unix_time,
                ..slot.wanted.clone()
            });
        }
        due
    }
}

/// Sends the statuses that are offered, paced, until the offering end is gone.
pub async fn run(mut offers: Offers, mut send: impl FnMut(CertificateStatus)) {
    let mut pacer = Pacer::default();
    loop {
        let wake = pacer.next_due();
        tokio::select! {
            offer = offers.0.recv() => match offer {
                Some(offer) => pacer.offer(Instant::now(), offer),
                None => return,
            },
            _ = async {
                match wake {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {}
        }
        for status in pacer.take_due(Instant::now()) {
            send(status);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn status(app: &str, state: State) -> CertificateStatus {
        CertificateStatus {
            app_id: app.into(),
            source: "uploaded".into(),
            state: state.as_str().into(),
            certificate_id: "cert".into(),
            ..Default::default()
        }
    }

    /// A pacer on the paused clock: what is offered to it, and what it sent and when (whole
    /// seconds since the start).
    struct Rig {
        statuses: Statuses,
        sent: Arc<Mutex<Vec<(u64, String, String)>>>,
        origin: Instant,
    }

    impl Rig {
        fn start() -> Rig {
            let (statuses, offers) = Statuses::channel();
            let sent = Arc::new(Mutex::new(Vec::new()));
            let (origin, log) = (Instant::now(), sent.clone());
            tokio::spawn(run(offers, move |s| {
                assert!(
                    s.unix_time > 1_700_000_000,
                    "the time the state was seen is set"
                );
                log.lock()
                    .unwrap()
                    .push((origin.elapsed().as_secs(), s.app_id, s.state));
            }));
            Rig {
                statuses,
                sent,
                origin,
            }
        }

        /// Lets the clock run to `secs` after the start, and the pacer with it.
        async fn at(&self, secs: u64) {
            tokio::time::sleep_until(self.origin + Duration::from_secs(secs)).await;
        }

        fn sent(&self, app: &str) -> Vec<(u64, String)> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, a, _)| a == app)
                .map(|(t, _, state)| (*t, state.clone()))
                .collect()
        }
    }

    fn at_state(t: u64, state: State) -> (u64, String) {
        (t, state.as_str().to_owned())
    }

    #[tokio::test(start_paused = true)]
    async fn an_app_sends_one_status_in_ten_seconds_and_a_change_in_the_window_goes_at_its_end() {
        let rig = Rig::start();
        rig.statuses.changed(vec![status("a", State::Missing)]);
        rig.at(1).await;
        assert_eq!(
            rig.sent("a"),
            [at_state(0, State::Missing)],
            "the first goes at once"
        );

        // Two changes inside the window: only the latest goes, when the window ends.
        rig.statuses.changed(vec![status("a", State::Active)]);
        rig.at(3).await;
        rig.statuses.changed(vec![status("a", State::Failed)]);
        rig.at(9).await;
        assert_eq!(rig.sent("a").len(), 1, "nothing before the window ends");
        rig.at(11).await;
        assert_eq!(
            rig.sent("a"),
            [at_state(0, State::Missing), at_state(10, State::Failed)]
        );

        // Another app has a window of its own.
        rig.statuses.changed(vec![status("b", State::Active)]);
        rig.at(12).await;
        assert_eq!(rig.sent("b"), [at_state(11, State::Active)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_state_that_was_already_sent_is_sent_again_only_after_a_live_bundle() {
        let rig = Rig::start();
        rig.statuses.changed(vec![status("a", State::Active)]);
        rig.at(30).await;
        rig.statuses.changed(vec![status("a", State::Active)]);
        rig.at(40).await;
        assert_eq!(rig.sent("a").len(), 1, "it says what the last said");

        rig.statuses
            .after_bundle(vec![status("a", State::Active)], true);
        rig.at(41).await;
        assert_eq!(
            rig.sent("a").len(),
            2,
            "a live bundle asks for one, and the window is over"
        );

        // A bundle inside the window of the last status goes at the end of it, once.
        rig.statuses
            .after_bundle(vec![status("a", State::Active)], true);
        rig.statuses
            .after_bundle(vec![status("a", State::Active)], true);
        rig.at(45).await;
        assert_eq!(rig.sent("a").len(), 2);
        rig.at(52).await;
        assert_eq!(
            rig.sent("a"),
            [
                at_state(0, State::Active),
                at_state(40, State::Active),
                at_state(50, State::Active)
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn missing_is_sent_again_every_minute_until_the_certificate_is_held() {
        let rig = Rig::start();
        rig.statuses
            .after_bundle(vec![status("a", State::Missing)], true);
        rig.at(190).await;
        let times: Vec<u64> = rig.sent("a").iter().map(|(t, _)| *t).collect();
        assert_eq!(times, [0, 60, 120, 180]);

        // The install lands: `active` goes at once, and the repeats stop.
        rig.statuses.changed(vec![status("a", State::Active)]);
        rig.at(200).await;
        assert_eq!(rig.sent("a").last().unwrap(), &at_state(190, State::Active));
        rig.at(600).await;
        assert_eq!(rig.sent("a").len(), 5, "nothing after active");
    }

    #[tokio::test(start_paused = true)]
    async fn a_change_that_is_undone_inside_the_window_is_not_sent_at_all() {
        let rig = Rig::start();
        rig.statuses.changed(vec![status("a", State::Missing)]);
        rig.at(5).await;
        rig.statuses.changed(vec![status("a", State::Active)]);
        rig.at(6).await;
        rig.statuses.changed(vec![status("a", State::Missing)]);
        rig.at(30).await;
        assert_eq!(rig.sent("a"), [at_state(0, State::Missing)]);
        rig.at(65).await;
        assert_eq!(
            rig.sent("a"),
            [at_state(0, State::Missing), at_state(60, State::Missing)],
            "only the repeat"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_app_that_left_the_bundle_is_forgotten_with_its_repeats() {
        let rig = Rig::start();
        rig.statuses.after_bundle(
            vec![
                status("gone", State::Missing),
                status("stays", State::Missing),
            ],
            true,
        );
        rig.at(1).await;
        // The next bundle names one of them, with a status that has changed.
        rig.statuses
            .after_bundle(vec![status("stays", State::Active)], true);
        rig.at(300).await;
        assert_eq!(rig.sent("gone"), [at_state(0, State::Missing)]);
        assert_eq!(
            rig.sent("stays"),
            [at_state(0, State::Missing), at_state(10, State::Active)]
        );

        // A refusal names the apps it knows and forgets none: the others go on as they were.
        rig.statuses
            .after_bundle(vec![status("other", State::Missing)], true);
        rig.at(301).await;
        rig.statuses
            .after_bundle(vec![status("stays", State::Failed)], false);
        rig.at(400).await;
        assert_eq!(rig.sent("other").len(), 2, "repeated at 360");
    }

    #[tokio::test(start_paused = true)]
    async fn the_pacer_ends_when_nothing_can_offer_to_it_any_more() {
        let (statuses, offers) = Statuses::channel();
        let ended = tokio::spawn(run(offers, |_| {}));
        drop(statuses);
        tokio::time::timeout(Duration::from_secs(1), ended)
            .await
            .expect("it ends")
            .unwrap();
    }
}
