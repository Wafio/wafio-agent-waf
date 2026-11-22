//! When the agent sends the certificate status of an app.
//!
//! The control plane takes a few statuses of an app at once and then one every 10 seconds, so the
//! pacer lets each app send at most one in that time. What it is given is the latest status of an
//! app, never a list of changes: a change that comes inside the window goes out at its end, as the
//! latest state, and the ones before it are not sent. A status that asks for a certificate
//! (`missing`) is repeated every minute until the state changes, as the control plane expects. A
//! refused bundle does not end that: the bundle in force still names the certificate, so the
//! request goes on after the `failed` that says why the new bundle was not taken.
//!
//! The pacer knows nothing of where a state comes from: whoever decides a status offers it, so
//! the states of an ordered certificate go through it as they are.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;
use wafio_control::CertificateStatus;

use super::status::{State, unix_now};

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
    /// What the bundle in force says of all its apps, for the offer of a refused bundle. An app of
    /// `statuses` that is `missing` there asks again once its `failed` has gone out: the bundle in
    /// force still names a certificate it does not hold.
    pub in_force: Vec<CertificateStatus>,
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
        self.offer(statuses, true, whole, Vec::new());
    }

    /// A live bundle was refused; `failed` says so for the apps it names, and `in_force` is what
    /// the bundle that is still in force says of all its apps. An app of neither is forgotten.
    pub fn after_refusal(&self, failed: Vec<CertificateStatus>, in_force: Vec<CertificateStatus>) {
        self.offer(failed, true, false, in_force);
    }

    /// The state of these apps may have changed; the pacer sends what differs from the last.
    pub fn changed(&self, statuses: Vec<CertificateStatus>) {
        self.offer(statuses, false, false, Vec::new());
    }

    fn offer(
        &self,
        statuses: Vec<CertificateStatus>,
        forced: bool,
        whole: bool,
        in_force: Vec<CertificateStatus>,
    ) {
        // The pacer ends with the process; an offer to a pacer that has gone is of no use.
        let _ = self.0.send(Offer {
            statuses,
            forced,
            whole,
            in_force,
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
    /// What `wanted` becomes once it has been sent: the `missing` of the bundle in force, for an
    /// app whose bundle was refused. The refusal is said once, and the request for the
    /// certificate goes on every minute as before.
    resume: Option<CertificateStatus>,
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
        // A live bundle says which apps matter: a whole offer names them all; a refusal names the
        // apps of the refused bundle and `in_force` lists the others. A slot of any other app goes,
        // so the apps that a stream of refused bundles names do not pile up.
        if offer.whole || offer.forced {
            let named: HashSet<&str> = offer
                .statuses
                .iter()
                .chain(&offer.in_force)
                .map(|s| s.app_id.as_str())
                .collect();
            self.slots.retain(|app, _| named.contains(app.as_str()));
        }
        for status in offer.statuses {
            let resume = offer
                .in_force
                .iter()
                .find(|s| s.app_id == status.app_id && s.state == State::Missing.as_str())
                .cloned();
            let slot = self
                .slots
                .entry(status.app_id.clone())
                .or_insert_with(|| Slot {
                    wanted: status.clone(),
                    resume: None,
                    sent: None,
                    forced: false,
                    due: None,
                });
            slot.wanted = status;
            slot.resume = resume;
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
        let unix_time = unix_now();
        let mut due = Vec::new();
        for slot in self.slots.values_mut() {
            if slot.due.is_none_or(|at| at > now) {
                continue;
            }
            slot.sent = Some((now, slot.wanted.clone()));
            slot.forced = false;
            due.push(CertificateStatus {
                unix_time,
                ..slot.wanted.clone()
            });
            if let Some(back) = slot.resume.take() {
                slot.wanted = back;
            }
            slot.due = slot.next_due(now);
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

        // A refusal lists the apps in force too: the ones it does not name go on as they were.
        rig.statuses.after_bundle(
            vec![
                status("other", State::Missing),
                status("stays", State::Active),
            ],
            true,
        );
        rig.at(301).await;
        rig.statuses.after_refusal(
            vec![status("stays", State::Failed)],
            vec![
                status("other", State::Missing),
                status("stays", State::Active),
            ],
        );
        rig.at(400).await;
        assert_eq!(rig.sent("other").len(), 2, "repeated at 360");
    }

    #[tokio::test(start_paused = true)]
    async fn the_apps_of_refused_bundles_are_kept_only_until_the_next_one() {
        let mut pacer = Pacer::default();
        let now = Instant::now();
        let kept = status("kept", State::Active);
        pacer.offer(
            now,
            Offer {
                statuses: vec![kept.clone()],
                forced: true,
                whole: true,
                in_force: Vec::new(),
            },
        );
        // Each refused bundle names apps of its own that are not in force.
        for named in [["a1", "a2"], ["b1", "b2"]] {
            pacer.offer(
                now,
                Offer {
                    statuses: named.map(|app| status(app, State::Failed)).to_vec(),
                    forced: true,
                    whole: false,
                    in_force: vec![kept.clone()],
                },
            );
        }
        assert_eq!(
            pacer.slots.keys().map(String::as_str).collect::<Vec<_>>(),
            ["b1", "b2", "kept"],
            "the bundle in force and the last refused one"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_is_said_once_and_the_request_for_the_certificate_goes_on() {
        let rig = Rig::start();
        rig.statuses
            .after_bundle(vec![status("a", State::Missing)], true);
        rig.at(20).await;
        // A bundle is refused: both apps of it hear `failed`, and the bundle in force still has
        // `a` waiting for its certificate.
        rig.statuses.after_refusal(
            vec![status("a", State::Failed), status("b", State::Failed)],
            vec![status("a", State::Missing), status("c", State::Active)],
        );
        rig.at(200).await;
        assert_eq!(
            rig.sent("a"),
            [
                at_state(0, State::Missing),
                at_state(20, State::Failed),
                at_state(30, State::Missing),
                at_state(90, State::Missing),
                at_state(150, State::Missing),
            ],
            "asks again a window after the `failed`, then every minute"
        );
        assert_eq!(
            rig.sent("b"),
            [at_state(20, State::Failed)],
            "the bundle in force does not have it waiting, so it stays failed"
        );
        assert!(
            rig.sent("c").is_empty(),
            "an app the refusal does not name is left alone"
        );

        // The retry of the bundle is refused again, and the request goes on after it.
        rig.statuses.after_refusal(
            vec![status("a", State::Failed)],
            vec![status("a", State::Missing)],
        );
        rig.at(300).await;
        assert_eq!(
            rig.sent("a")[5..],
            [
                at_state(200, State::Failed),
                at_state(210, State::Missing),
                at_state(270, State::Missing)
            ]
        );

        // The certificate arrives, and the asking ends.
        rig.statuses.changed(vec![status("a", State::Active)]);
        rig.at(700).await;
        assert_eq!(rig.sent("a").len(), 9);
        assert_eq!(rig.sent("a").last().unwrap(), &at_state(300, State::Active));
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_that_is_followed_by_a_state_before_it_is_sent_leaves_no_request_behind() {
        let rig = Rig::start();
        rig.statuses.changed(vec![status("a", State::Active)]);
        rig.at(1).await;
        // Inside the window: refused, and then the certificate shows up before `failed` goes.
        rig.statuses.after_refusal(
            vec![status("a", State::Failed)],
            vec![status("a", State::Missing)],
        );
        rig.statuses.changed(vec![status("a", State::Active)]);
        rig.at(500).await;
        assert_eq!(
            rig.sent("a"),
            [at_state(0, State::Active), at_state(10, State::Active)],
            "only the latest state goes, and nothing is asked for"
        );
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
