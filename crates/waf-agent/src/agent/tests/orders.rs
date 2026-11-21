//! Certificates ordered through the agent: the worker, the applied state, the book of the
//! listeners and the statuses, against an authority of the test's own.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use tokio::sync::Notify;
use wafio_proxy::cert_store::{BookEntry, leaf_sha256};

use super::*;
use crate::tls::acme::ACCOUNT_FILE;
use crate::tls::acme::ca::CaError;
use crate::tls::acme::mock::{ACCOUNT_KEY, Issue, MockCa, Step};
use crate::tls::acme::names::dns_names;
use crate::tls::state_file::{STATE_FILE, StateFile};

const BASE: i64 = 1_800_000_000;
const DIRECTORY: &str = "https://ca.test/directory";
const HOST: &str = "shop.example.com";
const RATE_LIMITED: &str = "urn:ietf:params:acme:error:rateLimited";

thread_local! {
    static ORIGIN: tokio::time::Instant = tokio::time::Instant::now();
}

/// Everything the process logs while the tests run, which `capture_logs` starts to keep.
static LOG: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

struct Capture;

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::INFO
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Text(String);
        impl tracing::field::Visit for Text {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?} ", field.name()));
            }
        }
        let mut text = Text(String::new());
        event.record(&mut text);
        LOG.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_str(&format!("{}\n", text.0));
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

fn capture_logs() {
    let _ = tracing::subscriber::set_global_default(Capture);
}

/// The time the worker reads: seconds since the epoch, moved by the clock of the test runtime.
fn clock() -> i64 {
    BASE + i64::try_from(ORIGIN.with(|origin| origin.elapsed().as_secs())).unwrap()
}

/// The `tls` object of an app that is ordered a certificate.
fn acme_object(listen: &str, redirect: Option<&str>, hosts: &[&str], request_id: &str) -> String {
    let hosts: Vec<String> = hosts.iter().map(|h| format!("\"{h}\"")).collect();
    let redirect = redirect.map_or(String::new(), |r| format!(r#","redirect_listen":"{r}""#));
    format!(
        r#"{{"listen":"{listen}","hosts":[{}],"source":"acme","acme_request_id":"{request_id}"{redirect}}}"#,
        hosts.join(",")
    )
}

/// The agent over a key directory that exists already, with the statuses it offers.
fn agent_over(scratch: &Scratch) -> (Arc<Agent>, Arc<FakeProxy>, Offers) {
    let stores = Stores::new();
    let base = startup_executor(&stores, "", None).unwrap();
    let proxy = Arc::new(FakeProxy::default());
    let (statuses, offers) = Statuses::channel();
    let agent = Agent::new(
        base,
        stores,
        proxy.clone(),
        Arc::new(VerifiedBotChecker::new()),
        Arc::new(Ready::new(ReadyActions::default())),
    )
    .with_statuses(statuses)
    .with_key_dir(KeyDir::open(&scratch.dir(), my_uid()).unwrap());
    (Arc::new(agent), proxy, offers)
}

struct Rig {
    agent: Arc<Agent>,
    proxy: Arc<FakeProxy>,
    dir: Arc<Scratch>,
    ca: MockCa,
    offers: Offers,
}

fn rig() -> Rig {
    rig_over(Arc::new(Scratch::new()), None)
}

/// A process of the agent over `dir`, ordering from `authority` if there is one, else from a new
/// one.
fn rig_over(dir: Arc<Scratch>, authority: Option<&MockCa>) -> Rig {
    let (agent, proxy, offers) = agent_over(&dir);
    let book = agent.certificate_book();
    let ca = match authority {
        Some(authority) => authority.with_book(book),
        None => MockCa::new(book),
    };
    Rig {
        agent,
        proxy,
        dir,
        ca,
        offers,
    }
}

/// An app of a bundle: its id, the hosts of its `tls` object and its request id.
type Entry<'a> = (&'a str, &'a [&'a str], &'a str);

impl Rig {
    fn start(&self) {
        self.start_at(DIRECTORY);
    }

    fn start_at(&self, directory: &str) {
        self.agent
            .start_acme_with(Arc::new(self.ca.clone()), directory.into(), clock);
    }

    /// The process ends and another starts over the same directory, ordering from the same
    /// authority.
    fn restart(self) -> Rig {
        self.agent.close();
        self.agent.release_keys();
        let Rig { dir, ca, .. } = self;
        rig_over(dir, Some(&ca))
    }

    /// A live bundle with these apps, each on port 443 with a redirect listener.
    fn apply(&self, apps: &[Entry<'_>], generation: i64) {
        let list: Vec<String> = apps
            .iter()
            .enumerate()
            .map(|(i, (id, hosts, request_id))| {
                let tls = acme_object("0.0.0.0:443", None, hosts, request_id);
                app_json(id, 18080 + u32::try_from(i).unwrap(), Some(&tls))
            })
            .collect();
        self.apply_json(&bundle_of(&list), generation);
    }

    fn apply_json(&self, json: &str, generation: i64) {
        super::apply(&self.agent, json, generation).unwrap();
        self.agent.report_bundle();
    }

    fn book(&self, app: &str) -> Option<BookEntry> {
        self.proxy.book.get(app)
    }

    /// Whether the app is served a certificate that is not the placeholder.
    fn issued(&self, app: &str) -> bool {
        self.book(app).is_some_and(|e| !e.placeholder)
    }

    fn leaf(&self, app: &str) -> String {
        leaf_sha256(&self.book(app).expect("a certificate in the book").key)
    }

    fn files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.dir.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn state(&self) -> StateFile {
        match std::fs::read(self.dir.dir().join(STATE_FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap(),
            Err(_) => StateFile::default(),
        }
    }

    /// What the control plane would be told of an app now.
    fn status(&self, app: &str) -> CertificateStatus {
        let st = self.agent.lock();
        let mut all = st.tls.as_ref().unwrap().statuses(Some(app));
        assert_eq!(all.len(), 1, "one status");
        all.remove(0)
    }

    fn ordering(&self) -> bool {
        self.agent.lock().tls.as_ref().unwrap().running().is_some()
    }

    /// The states and request ids of the acme statuses offered since the last call, with
    /// repeats of one state left out.
    fn told(&mut self) -> Vec<(String, String)> {
        let mut told: Vec<(String, String)> = Vec::new();
        for offer in self.offers.drain() {
            for status in offer.statuses.iter().filter(|s| s.source == "acme") {
                let now = (status.state.clone(), status.request_id.clone());
                if told.last() != Some(&now) {
                    told.push(now);
                }
            }
        }
        told
    }
}

fn pair(state: &str, request_id: &str) -> (String, String) {
    (state.to_owned(), request_id.to_owned())
}

/// Waits, in real time, until `ready`.
async fn until(what: &str, mut ready: impl FnMut() -> bool) {
    for _ in 0..4000 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("gave up waiting until {what}");
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn an_ordered_app_is_served_a_placeholder_until_its_certificate_is_issued_and_then_that() {
    let mut r = rig();
    let go = Arc::new(Notify::new());
    r.ca.script().pause = Some((Step::Certificate, go.clone()));
    r.start();
    r.apply(&[(SHOP, &[HOST], "r1")], 1);
    r.ca.reached.notified().await;

    // The order is at its last step. The app has the placeholder, which names its host, and
    // nothing of it is on disk.
    let held = r.book(SHOP).expect("the app is served something");
    assert!(held.placeholder);
    assert_eq!(dns_names(held.key.cert[0].as_ref()), [HOST]);
    let before = r.files();
    assert!(
        !before
            .iter()
            .any(|f| f.starts_with("acme-") && f.ends_with(".pem")),
        "{before:?}"
    );
    let site = r.proxy.tls.lock().unwrap()[0][0].clone().unwrap();
    assert!(matches!(&site.certificate, BookChange::Set(e) if e.placeholder));
    assert_eq!(r.status(SHOP).state, "pending");

    go.notify_one();
    until("the certificate is served", || r.issued(SHOP)).await;
    until("the order is taken in", || !r.ordering()).await;

    let file = format!("acme-{SHOP}.pem");
    assert_eq!(mode(&r.dir.dir().join(&file)), 0o600);
    let mut expected = vec![
        file.clone(),
        ACCOUNT_FILE.to_owned(),
        STATE_FILE.to_owned(),
        "tls.lock".to_owned(),
    ];
    expected.sort();
    assert_eq!(r.files(), expected);
    let served = held_by_agent(&r, SHOP);
    assert_eq!(served.0.as_deref(), Some(file.as_str()));
    assert_eq!(served.1, r.leaf(SHOP));
    // `state.json` remembers the order.
    let record = r.state().apps[SHOP].clone();
    assert_eq!(record.served.as_deref(), Some(file.as_str()));
    assert_eq!(
        (
            record.request_id.as_str(),
            record.directory.as_str(),
            record.worked.as_str()
        ),
        ("r1", DIRECTORY, "tls-alpn-01")
    );
    assert_eq!(
        (
            record.failures,
            record.next_attempt_unix,
            record.error.as_str()
        ),
        (0, 0, "")
    );
    // The control plane was told `pending` and then `active`, with the chain in use.
    assert_eq!(r.told(), [pair("pending", "r1"), pair("active", "r1")]);
    let status = r.status(SHOP);
    assert_eq!(status.state, "active");
    assert_eq!(status.leaf_sha256, r.leaf(SHOP));
    assert!(!status.chain_pem.is_empty());
    assert_eq!((status.error.as_str(), status.next_attempt_unix), ("", 0));
}

/// The file and the leaf the agent says an app is served from.
fn held_by_agent(r: &Rig, app: &str) -> (Option<String>, String) {
    let st = r.agent.lock();
    let applied = &st.tls.as_ref().unwrap().applied()[app];
    let served = applied.served.as_ref().expect("served");
    (Some(served.file.clone()), served.leaf_sha256.clone())
}

#[tokio::test]
async fn the_account_is_made_once_kept_in_a_private_file_and_told_to_nobody() {
    capture_logs();
    let mut r = rig();
    r.start();
    r.apply(
        &[(SHOP, &[HOST], "r1"), (BLOG, &["blog.example.com"], "r1")],
        1,
    );
    until("both are served", || r.issued(SHOP) && r.issued(BLOG)).await;
    until("the orders are taken in", || !r.ordering()).await;
    assert_eq!(
        r.ca.script().created,
        [DIRECTORY],
        "one account for two orders"
    );

    let path = r.dir.dir().join(ACCOUNT_FILE);
    assert_eq!(mode(&path), 0o600);
    let kept = std::fs::read_to_string(&path).unwrap();
    assert!(
        kept.contains(ACCOUNT_KEY) && kept.contains(DIRECTORY),
        "{kept}"
    );
    // Not in the state, and not in anything the control plane is told.
    let state = std::fs::read_to_string(r.dir.dir().join(STATE_FILE)).unwrap();
    assert!(
        !state.contains(ACCOUNT_KEY) && !state.contains("key_pkcs8"),
        "{state}"
    );
    let told = format!(
        "{:?}",
        r.offers
            .drain()
            .iter()
            .map(|o| &o.statuses)
            .collect::<Vec<_>>()
    );
    assert!(!told.contains(ACCOUNT_KEY), "{told}");
    let status = format!("{:?}", (r.status(SHOP), r.status(BLOG)));
    assert!(!status.contains(ACCOUNT_KEY));
    // The orders went through the directory they were made for.
    assert_eq!(r.ca.script().orders.len(), 2);
    // Nor in anything the process logged, which says that it made the account.
    let log = LOG.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        log.contains("made an account at https://ca.test/directory"),
        "{log}"
    );
    assert!(
        !log.contains(ACCOUNT_KEY) && !log.contains("key_pkcs8"),
        "{log}"
    );
}

/// A key directory whose `state.json` says `state`.
fn seeded(state: &str) -> Arc<Scratch> {
    let dir = Scratch::new();
    std::fs::create_dir(dir.dir()).unwrap();
    std::fs::set_permissions(dir.dir(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(dir.dir().join(STATE_FILE), state).unwrap();
    Arc::new(dir)
}

#[tokio::test]
async fn the_account_is_taken_from_its_file_after_a_restart_and_made_again_for_another_directory() {
    let first = rig();
    first.start();
    first.apply(&[(SHOP, &[HOST], "r1")], 1);
    until("the certificate is served", || first.issued(SHOP)).await;
    until("the order is taken in", || !first.ordering()).await;
    assert_eq!(first.ca.script().created, [DIRECTORY]);
    let kept = std::fs::read(first.dir.dir().join(ACCOUNT_FILE)).unwrap();

    // The next process finds the account in the directory. The bundle asks for a new certificate
    // (a new id), so an order is made.
    let again = first.restart();
    again.start();
    again.apply(&[(SHOP, &[HOST], "r2")], 1);
    until("the order is made", || again.ca.script().orders.len() == 2).await;
    until("the order is taken in", || !again.ordering()).await;
    {
        let script = again.ca.script();
        assert_eq!(script.created, [DIRECTORY], "no second account");
        assert_eq!(script.restored.len(), 1);
        assert_eq!(script.restored[0].as_bytes(), &kept[..]);
    }

    // Another directory: the account is made again and the file names that one.
    let other = again.restart();
    other.start_at("https://ca.test/other");
    other.apply(&[(SHOP, &[HOST], "r3")], 1);
    until("the second account is made", || {
        other.ca.script().created.len() == 2
    })
    .await;
    until("the order is taken in", || !other.ordering()).await;
    assert_eq!(
        other.ca.script().created,
        [DIRECTORY, "https://ca.test/other"]
    );
    let kept = std::fs::read_to_string(other.dir.dir().join(ACCOUNT_FILE)).unwrap();
    assert!(kept.contains("https://ca.test/other") && !kept.contains(DIRECTORY));
}

const A: &str = "1a2b3c4d-0000-4000-8000-00000000000a";
const B: &str = "1a2b3c4d-0000-4000-8000-00000000000b";
const C: &str = "1a2b3c4d-0000-4000-8000-00000000000c";

#[tokio::test]
async fn orders_run_one_at_a_time_and_the_app_that_has_been_due_the_longest_goes_first() {
    // Each app failed an order before, and its wait ended at a different time.
    let waiting = |until: i64| {
        format!(r#"{{"request_id":"r1","failures":1,"next_attempt_unix":{until},"error":"no"}}"#)
    };
    let state = format!(
        r#"{{"apps":{{"{A}":{},"{B}":{},"{C}":{}}}}}"#,
        waiting(BASE - 100),
        waiting(BASE - 300),
        waiting(BASE - 200)
    );
    let r = rig_over(seeded(&state), None);
    let go = Arc::new(Notify::new());
    r.ca.script().pause = Some((Step::WaitReady, go.clone()));
    r.start();
    r.apply(
        &[
            (A, &["a.example.com"], "r1"),
            (B, &["b.example.com"], "r1"),
            (C, &["c.example.com"], "r1"),
        ],
        1,
    );
    for host in ["b.example.com", "c.example.com", "a.example.com"] {
        r.ca.reached.notified().await;
        {
            let script = r.ca.script();
            assert_eq!(script.orders.last().unwrap(), &[host.to_owned()]);
            assert_eq!(script.running, 1, "one order at a time");
        }
        // Nothing else starts while this one waits.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(r.ca.script().running, 1);
        go.notify_one();
    }
    until("all three are served", || {
        [A, B, C].iter().all(|app| r.issued(app))
    })
    .await;
    let script = r.ca.script();
    assert_eq!(script.most_running, 1);
    assert_eq!(script.orders.len(), 3);
}

#[tokio::test]
async fn only_the_process_that_holds_the_key_directory_lock_orders_and_it_stops_at_the_hand_over() {
    let x = rig();
    let go = Arc::new(Notify::new());
    x.ca.script().pause = Some((Step::WaitReady, go.clone()));
    // The process that takes over runs beside it for a while and finds the lock taken.
    let y = {
        let (agent, proxy, offers) = agent_over(&x.dir);
        let ca = MockCa::new(agent.certificate_book());
        Rig {
            agent,
            proxy,
            dir: x.dir.clone(),
            ca,
            offers,
        }
    };
    assert!(x.agent.holds_keys() && y.agent.waits_for_keys());
    x.start();
    y.start();
    x.apply(&[(SHOP, &[HOST], "r1")], 1);
    y.apply(&[(SHOP, &[HOST], "r1")], 1);
    x.ca.reached.notified().await;
    assert!(
        x.proxy.book.alpn_challenge(HOST).is_some(),
        "the order has its answer up"
    );

    // The one that does not hold the lock orders nothing, and writes nothing, however long it waits.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(y.ca.script().orders.is_empty());
    assert!(y.book(SHOP).unwrap().placeholder);
    assert!(
        !x.files()
            .iter()
            .any(|f| f.starts_with("acme-") && f.ends_with(".pem"))
    );

    // The hand-over stops the order that runs, and what it put up goes with it.
    x.agent.close();
    x.agent.release_keys();
    until("the order is stopped", || {
        x.ca.script().running == 0 && x.proxy.book.alpn_challenge(HOST).is_none()
    })
    .await;
    assert_eq!(x.ca.script().orders.len(), 1, "it starts no other");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !x.files()
            .iter()
            .any(|f| f.starts_with("acme-") && f.ends_with(".pem"))
    );

    // The other takes the lock and orders from then on.
    assert!(y.agent.take_over_keys());
    until("the successor orders and serves", || y.issued(SHOP)).await;
    assert_eq!(y.ca.script().orders.len(), 1);
    assert!(x.files().contains(&format!("acme-{SHOP}.pem")));
}

/// An order of SHOP that has come to its last step, and what lets it end.
async fn mid_order() -> (Rig, Arc<Notify>) {
    let r = rig();
    let go = Arc::new(Notify::new());
    r.ca.script().pause = Some((Step::Certificate, go.clone()));
    r.start();
    r.apply(&[(SHOP, &[HOST], "r1")], 1);
    r.ca.reached.notified().await;
    (r, go)
}

/// Lets the order end and checks that nothing of it was kept: no certificate file, nothing in the
/// book, nothing in the state, and no other order.
async fn nothing_is_kept(r: &Rig, go: &Notify) {
    go.notify_one();
    until("the order is over", || !r.ordering()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let files = r.files();
    assert!(!files.iter().any(|f| f.ends_with(".pem")), "{files:?}");
    assert!(r.book(SHOP).is_none_or(|e| e.placeholder));
    assert!(!r.state().apps.contains_key(SHOP), "{:?}", r.state());
    assert_eq!(r.ca.script().orders.len(), 1, "no other order");
}

#[tokio::test]
async fn an_order_that_ends_after_its_app_left_the_bundle_is_dropped() {
    let (r, go) = mid_order().await;
    r.apply(&[], 2);
    nothing_is_kept(&r, &go).await;
    assert!(r.book(SHOP).is_none());
}

#[tokio::test]
async fn an_order_that_ends_after_its_app_left_gateway_mode_is_dropped() {
    let (r, go) = mid_order().await;
    r.apply_json(&bundle_of(&[app_json(SHOP, 18080, None)]), 2);
    nothing_is_kept(&r, &go).await;
    assert!(r.book(SHOP).is_none());
}

#[tokio::test]
async fn an_order_that_ends_after_its_app_changed_source_is_dropped() {
    let (r, go) = mid_order().await;
    let tls = format!(r#"{{"listen":"0.0.0.0:443","hosts":["{HOST}"],"source":"uploaded"}}"#);
    r.apply_json(&bundle_of(&[app_json(SHOP, 18080, Some(&tls))]), 2);
    nothing_is_kept(&r, &go).await;
    assert!(r.book(SHOP).is_none());
}

#[tokio::test]
async fn an_order_that_ends_after_the_hosts_changed_is_dropped_and_the_new_hosts_are_ordered() {
    let (r, go) = mid_order().await;
    r.apply(&[(SHOP, &[HOST, "www.example.com"], "r1")], 2);
    go.notify_one();
    // The certificate for the old hosts is not served; the new ones are ordered.
    r.ca.reached.notified().await;
    {
        let script = r.ca.script();
        assert_eq!(script.orders.len(), 2);
        assert_eq!(script.orders[1], [HOST, "www.example.com"]);
    }
    assert!(r.book(SHOP).unwrap().placeholder);
    assert!(!r.files().iter().any(|f| f.ends_with(".pem")));
    go.notify_one();
    until("the new certificate is served", || r.issued(SHOP)).await;
    let served = r.book(SHOP).unwrap();
    assert_eq!(
        dns_names(served.key.cert[0].as_ref()),
        [HOST, "www.example.com"]
    );
}

#[tokio::test]
async fn a_new_request_id_mid_order_keeps_the_certificate_and_orders_again_at_once() {
    let (mut r, go) = mid_order().await;
    r.told();
    r.apply(&[(SHOP, &[HOST], "r2")], 2);
    go.notify_one();
    until("the certificate is served", || r.issued(SHOP)).await;
    let first = r.leaf(SHOP);
    // The new id asked for another: it is ordered at once and the first one stays served.
    r.ca.reached.notified().await;
    assert_eq!(r.ca.script().orders.len(), 2);
    assert_eq!(r.leaf(SHOP), first);
    let status = r.status(SHOP);
    assert_eq!(
        (
            status.state.as_str(),
            status.request_id.as_str(),
            status.leaf_sha256.as_str()
        ),
        ("pending", "r2", first.as_str()),
        "the order of r1 does not report for r2"
    );
    assert!(
        !status.chain_pem.is_empty(),
        "the chain in use is described meanwhile"
    );
    assert!(
        !r.told().contains(&pair("active", "r1")),
        "a finished order reports only while its id is the bundle's"
    );
    go.notify_one();
    until("the second certificate is served", || {
        r.issued(SHOP) && r.leaf(SHOP) != first
    })
    .await;
    until("it is taken in", || !r.ordering()).await;
    let status = r.status(SHOP);
    assert_eq!(
        (status.state.as_str(), status.request_id.as_str()),
        ("active", "r2")
    );
    assert_eq!(r.state().apps[SHOP].request_id, "r2");
    assert_eq!(r.told().last(), Some(&pair("active", "r2")));
}

#[tokio::test(start_paused = true)]
async fn a_failed_order_is_reported_failed_and_the_next_one_waits_ten_minutes_with_the_other_challenge()
 {
    let mut r = rig();
    r.ca.script().fail = Some((
        Step::Finalize,
        CaError {
            problem: Some(RATE_LIMITED.into()),
            text: "too many certificates".into(),
        },
    ));
    r.start();
    r.apply(&[(SHOP, &[HOST], "r1")], 1);
    until("the order failed", || r.status(SHOP).state == "failed").await;
    until("the failure is taken in", || !r.ordering()).await;

    let status = r.status(SHOP);
    assert_eq!(
        status.error,
        format!("the order failed (tls-alpn-01): {RATE_LIMITED}: too many certificates")
    );
    assert!(
        (BASE + 600..BASE + 620).contains(&status.next_attempt_unix),
        "{}",
        status.next_attempt_unix
    );
    assert_eq!(status.request_id, "r1");
    assert!(
        status.chain_pem.is_empty(),
        "nothing is served but the placeholder"
    );
    assert!(r.book(SHOP).unwrap().placeholder);
    assert_eq!(r.told(), [pair("pending", "r1"), pair("failed", "r1")]);
    let record = r.state().apps[SHOP].clone();
    assert_eq!(
        (
            record.failures,
            record.tried.as_str(),
            record.request_id.as_str()
        ),
        (1, "tls-alpn-01", "r1")
    );
    assert_eq!(record.next_attempt_unix, status.next_attempt_unix);
    assert_eq!(record.error, status.error);

    // No new order before its time.
    tokio::time::advance(Duration::from_secs(550)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(r.ca.script().orders.len(), 1);
    // Then the other challenge is tried.
    tokio::time::advance(Duration::from_secs(60)).await;
    until("the next order", || r.ca.script().orders.len() == 2).await;
    until("its failure is taken in", || !r.ordering()).await;
    let script = r.ca.script();
    assert!(
        script
            .events
            .contains(&"answer shop.example.com tls-alpn-01".to_owned())
    );
    assert!(
        script
            .events
            .contains(&"answer shop.example.com http-01".to_owned()),
        "{:?}",
        script.events
    );
    drop(script);
    assert_eq!(r.state().apps[SHOP].failures, 2);
}

#[tokio::test]
async fn a_new_request_id_orders_at_once_without_waiting_for_the_next_attempt() {
    let mut r = rig();
    r.ca.script().fail = Some((Step::Finalize, CaError::new("no")));
    r.start();
    r.apply(&[(SHOP, &[HOST], "r1")], 1);
    until("the order failed", || r.status(SHOP).state == "failed").await;
    until("the failure is taken in", || !r.ordering()).await;
    r.ca.script().fail = None;
    r.told();

    r.apply(&[(SHOP, &[HOST], "r2")], 2);
    until("the app is served", || r.issued(SHOP)).await;
    until("it is taken in", || !r.ordering()).await;
    assert_eq!(r.ca.script().orders.len(), 2);
    assert_eq!(r.told().last(), Some(&pair("active", "r2")));
    let record = r.state().apps[SHOP].clone();
    assert_eq!(
        (
            record.failures,
            record.next_attempt_unix,
            record.tried.as_str(),
            record.worked.as_str()
        ),
        (0, 0, "", "http-01"),
        "it worked with the other challenge, which is the one to start with next time"
    );
}

#[tokio::test]
async fn a_failure_names_the_port_the_challenge_needs_when_the_app_does_not_listen_on_it() {
    let r = rig();
    r.ca.script().fail = Some((Step::Ready, CaError::new("connection refused")));
    r.start();
    let tls = acme_object("0.0.0.0:8443", None, &[HOST], "r1");
    r.apply_json(&bundle_of(&[app_json(SHOP, 18080, Some(&tls))]), 1);
    until("the order failed", || r.status(SHOP).state == "failed").await;
    assert_eq!(
        r.status(SHOP).error,
        "the order failed (tls-alpn-01): connection refused; this app does not listen on port 443"
    );
}

#[tokio::test]
async fn the_error_of_a_failed_order_is_cleaned_cut_and_withheld_when_it_looks_like_a_key() {
    let long = "x".repeat(5000);
    let cases = [
        (
            "bad\nresponse\u{7} from the\u{0} server",
            "the order failed (tls-alpn-01): badresponse from the server".to_owned(),
        ),
        (
            "-----BEGIN PRIVATE KEY----- oops",
            crate::tls::status::ERROR_WITHHELD.to_owned(),
        ),
        (
            "the PRIVATE KEY is wrong",
            crate::tls::status::ERROR_WITHHELD.to_owned(),
        ),
        (
            long.as_str(),
            format!("the order failed (tls-alpn-01): {}", "x".repeat(1024 - 32)),
        ),
    ];
    for (said, shown) in cases {
        let r = rig();
        r.ca.script().fail = Some((Step::Finalize, CaError::new(said)));
        r.start();
        r.apply(&[(SHOP, &[HOST], "r1")], 1);
        until("the order failed", || r.status(SHOP).state == "failed").await;
        assert_eq!(r.status(SHOP).error, shown, "{said:.30}");
        let kept = std::fs::read_to_string(r.dir.dir().join(STATE_FILE)).unwrap();
        assert!(!kept.contains("BEGIN"), "{kept}");
    }
}

#[tokio::test]
async fn a_failed_order_reports_only_while_its_request_id_is_the_bundles() {
    let mut r = rig();
    let go = Arc::new(Notify::new());
    {
        let mut script = r.ca.script();
        script.pause = Some((Step::Finalize, go.clone()));
        script.fail = Some((Step::Certificate, CaError::new("the authority said no")));
    }
    r.start();
    r.apply(&[(SHOP, &[HOST], "r1")], 1);
    r.ca.reached.notified().await;
    r.apply(&[(SHOP, &[HOST], "r2")], 2);
    go.notify_one();
    // The order of r1 fails; r2 is pending, and is ordered at once, which fails too.
    until("the second order", || r.ca.script().orders.len() == 2).await;
    r.ca.reached.notified().await;
    go.notify_one();
    until("r2 failed", || r.status(SHOP).state == "failed").await;
    let told = r.told();
    assert!(!told.contains(&pair("failed", "r1")), "{told:?}");
    assert_eq!(told.last(), Some(&pair("failed", "r2")), "{told:?}");
    assert!(told.contains(&pair("pending", "r2")), "{told:?}");
}

#[tokio::test]
async fn an_app_whose_certificate_is_in_the_directory_is_active_after_a_restart_without_an_order() {
    let first = rig();
    first.start();
    first.apply(&[(SHOP, &[HOST], "r1")], 1);
    until("the certificate is served", || first.issued(SHOP)).await;
    until("it is taken in", || !first.ordering()).await;
    let leaf = first.leaf(SHOP);

    let mut again = first.restart();
    again.start();
    again.apply(&[(SHOP, &[HOST], "r1")], 1);
    assert_eq!(
        again.leaf(SHOP),
        leaf,
        "the file is served from the first handshake"
    );
    assert!(!again.book(SHOP).unwrap().placeholder);
    assert_eq!(again.status(SHOP).state, "active");
    assert_eq!(again.told(), [pair("active", "r1")]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(again.ca.script().orders.len(), 1, "nothing is due");
}

#[tokio::test]
async fn a_restart_does_not_start_an_order_before_the_time_the_last_failure_set() {
    let state = format!(
        r#"{{"apps":{{"{SHOP}":{{"request_id":"r1","failures":1,"tried":"tls-alpn-01","next_attempt_unix":{},"error":"the order failed (tls-alpn-01): no"}}}}}}"#,
        BASE + 3000
    );
    let mut r = rig_over(seeded(&state), None);
    r.start();
    r.apply(&[(SHOP, &[HOST], "r1")], 1);
    let status = r.status(SHOP);
    assert_eq!(
        (
            status.state.as_str(),
            status.error.as_str(),
            status.next_attempt_unix
        ),
        ("failed", "the order failed (tls-alpn-01): no", BASE + 3000)
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(r.ca.script().orders.is_empty(), "it waits");
    assert!(r.book(SHOP).unwrap().placeholder);
    assert_eq!(r.told(), [pair("failed", "r1")]);
}

#[tokio::test]
async fn a_host_the_served_certificate_does_not_cover_is_ordered_with_the_old_chain_in_use_meanwhile()
 {
    let mut r = rig();
    r.start();
    r.apply(&[(SHOP, &[HOST], "r1")], 1);
    until("the certificate is served", || r.issued(SHOP)).await;
    until("it is taken in", || !r.ordering()).await;
    let first = r.leaf(SHOP);
    r.told();
    let go = Arc::new(Notify::new());
    r.ca.script().pause = Some((Step::Certificate, go.clone()));

    r.apply(&[(SHOP, &[HOST, "www.example.com"], "r1")], 2);
    r.ca.reached.notified().await;
    assert_eq!(r.ca.script().orders[1], [HOST, "www.example.com"]);
    assert_eq!(
        r.leaf(SHOP),
        first,
        "the old certificate is served meanwhile"
    );
    let status = r.status(SHOP);
    assert_eq!(status.state, "pending");
    assert_eq!(status.leaf_sha256, first);
    go.notify_one();
    until("the new certificate is served", || r.leaf(SHOP) != first).await;
    until("it is taken in", || !r.ordering()).await;
    assert_eq!(r.status(SHOP).state, "active");
    assert_eq!(
        dns_names(r.book(SHOP).unwrap().key.cert[0].as_ref()),
        [HOST, "www.example.com"]
    );
    assert_eq!(r.files().iter().filter(|f| f.ends_with(".pem")).count(), 1);
}

#[tokio::test]
async fn an_issued_certificate_that_is_not_usable_is_a_failure_and_is_not_served() {
    for issue in [Issue::OtherKey, Issue::FirstNameOnly, Issue::Garbage] {
        let r = rig();
        r.ca.script().issue = issue;
        r.start();
        let tls = acme_object("0.0.0.0:443", None, &[HOST, "www.example.com"], "r1");
        r.apply_json(&bundle_of(&[app_json(SHOP, 18080, Some(&tls))]), 1);
        until("the order failed", || r.status(SHOP).state == "failed").await;
        assert!(r.book(SHOP).unwrap().placeholder, "{issue:?}");
        assert!(!r.files().iter().any(|f| f.ends_with(".pem")), "{issue:?}");
        assert!(
            r.status(SHOP).error.contains("issued"),
            "{}",
            r.status(SHOP).error
        );
    }
}

// ── with the real listeners of the proxy ────────────────────────────────────────────────────

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A client that takes any certificate, so that it can ask which one it was given.
#[derive(Debug)]
struct TakesAny;

impl rustls::client::danger::ServerCertVerifier for TakesAny {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The status line and head of the answer to a request on a stream.
async fn answer<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let request = format!("GET /cart HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    head.extend_from_slice(&buf[..n]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
    })
    .await;
    let head = String::from_utf8_lossy(&head).into_owned();
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, head)
}

/// The leaf the server presents to `host` on `port`, and the status the app answers there.
async fn over_tls(port: u16, host: &str) -> (String, u16) {
    pingora::tls::install_default_crypto_provider();
    let mut config = pingora::tls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TakesAny))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let name = pingora::tls::ServerName::try_from(host.to_owned()).unwrap();
    let mut tls = pingora::tls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .unwrap();
    let leaf = {
        let (_, session) = tls.get_ref();
        wafio_proxy::cert_store::sha256_hex(session.peer_certificates().unwrap()[0].as_ref())
    };
    let (status, _) = answer(&mut tls, host).await;
    (leaf, status)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listeners_answer_503_while_only_the_placeholder_is_served_and_308_once_the_issued_one_is()
 {
    let scratch = Arc::new(Scratch::new());
    let stores = Stores::new();
    let base = startup_executor(&stores, "", None).unwrap();
    let proxy = Arc::new(wafio_proxy::Proxy::new(wafio_proxy::ProxyOptions::new(
        Arc::new(|_| {}),
    )));
    let agent = Arc::new(
        Agent::new(
            base,
            stores,
            proxy.clone(),
            Arc::new(VerifiedBotChecker::new()),
            Arc::new(Ready::new(ReadyActions::default())),
        )
        .with_key_dir(KeyDir::open(&scratch.dir(), my_uid()).unwrap()),
    );
    let ca = MockCa::new(agent.certificate_book());
    let go = Arc::new(Notify::new());
    ca.script().pause = Some((Step::Certificate, go.clone()));
    agent.start_acme_with(Arc::new(ca.clone()), DIRECTORY.into(), clock);

    let (https, plain) = (free_port(), free_port());
    let tls = acme_object(
        &format!("127.0.0.1:{https}"),
        Some(&format!("127.0.0.1:{plain}")),
        &["shop.test"],
        "r1",
    );
    let json = bundle_of(&[app_json(SHOP, 18080, Some(&tls))]);
    // A bundle applies on a blocking thread, as the link applies it.
    let a = agent.clone();
    tokio::task::spawn_blocking(move || apply(&a, &json, 1).unwrap())
        .await
        .unwrap();
    ca.reached.notified().await;

    // Only the placeholder: the redirect listener does not send anyone to HTTPS yet, and the
    // handshake gets the placeholder, whose app is not reached.
    let redirect = |port| async move {
        use tokio::io::AsyncReadExt;
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let (status, head) = answer(&mut tcp, "shop.test").await;
        let _ = tcp.read(&mut [0u8; 1]).await;
        (status, head)
    };
    let (status, head) = redirect(plain).await;
    assert_eq!(status, 503, "{head}");
    assert!(
        head.to_ascii_lowercase().contains("retry-after: 60"),
        "{head}"
    );
    assert!(!head.to_ascii_lowercase().contains("location:"), "{head}");
    let (placeholder_leaf, status) = over_tls(https, "shop.test").await;
    assert_eq!(status, 503);

    // The issued certificate arrives with no restart: the listeners use it for the next
    // connection.
    go.notify_one();
    let mut served = None;
    for _ in 0..2000 {
        let (leaf, _) = over_tls(https, "shop.test").await;
        if leaf != placeholder_leaf {
            served = Some(leaf);
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let served = served.expect("the issued certificate is served");
    let book = agent.certificate_book().get(SHOP).unwrap();
    assert!(!book.placeholder);
    assert_eq!(served, leaf_sha256(&book.key));
    let (status, head) = redirect(plain).await;
    assert_eq!(status, 308, "{head}");
    assert!(
        head.contains(&format!("https://shop.test:{https}/cart")),
        "{head}"
    );
    let (leaf, status) = over_tls(https, "shop.test").await;
    assert_eq!(leaf, served);
    assert_ne!(
        status, 503,
        "the app is reached now (its upstream is not there)"
    );
}

/// Whether the book answers a validation of `HOST` by either challenge.
fn answers(r: &Rig) -> bool {
    r.proxy.book.alpn_challenge(HOST).is_some()
        || r.proxy
            .book
            .http01_authorization(HOST, &format!("token-{HOST}"))
            .is_some()
}

#[tokio::test]
async fn an_order_that_panics_fails_and_takes_its_answers_down_and_the_worker_goes_on() {
    let mut r = rig();
    r.ca.script().panic = Some(Step::Finalize);
    r.start();
    r.apply(&[(SHOP, &[HOST], "r1")], 1);
    until("the order failed", || r.status(SHOP).state == "failed").await;
    assert_eq!(
        r.status(SHOP).error,
        "the order failed (tls-alpn-01): the order stopped on an internal error"
    );
    assert!(!answers(&r), "the answers are down");
    assert!(r.book(SHOP).unwrap().placeholder);
    // The worker is alive: a new request id orders again, and this one goes through.
    r.ca.script().panic = None;
    r.apply(&[(SHOP, &[HOST], "r2")], 2);
    until("the app is served", || r.issued(SHOP)).await;
    until("it is taken in", || !r.ordering()).await;
    assert_eq!(r.told().last(), Some(&pair("active", "r2")));
}

#[tokio::test(start_paused = true)]
async fn an_order_that_takes_longer_than_three_minutes_fails_and_takes_its_answers_down() {
    let mut r = rig();
    r.ca.script().hang = Some(Step::WaitReady);
    r.start();
    r.apply(&[(SHOP, &[HOST], "r1")], 1);
    until("the answers are up", || answers(&r)).await;
    tokio::time::advance(Duration::from_secs(170)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(answers(&r), "still within the three minutes");
    assert_eq!(r.status(SHOP).state, "pending");
    tokio::time::advance(Duration::from_secs(15)).await;
    until("the order failed", || r.status(SHOP).state == "failed").await;
    assert_eq!(
        r.status(SHOP).error,
        "the order failed (tls-alpn-01): the order took longer than 3 minutes"
    );
    assert!(!answers(&r), "the answers are down");
    assert_eq!(r.ca.script().running, 0);
    assert_eq!(r.told().last(), Some(&pair("failed", "r1")));
}

#[tokio::test]
async fn an_authority_that_does_not_know_the_account_gets_a_new_one_for_the_next_order() {
    let r = rig();
    r.ca.script().fail = Some((
        Step::NewOrder,
        CaError {
            problem: Some(crate::tls::acme::account::ACCOUNT_UNKNOWN.into()),
            text: "no account here".into(),
        },
    ));
    r.start();
    r.apply(&[(SHOP, &[HOST], "r1")], 1);
    until("the order failed", || r.status(SHOP).state == "failed").await;
    until("it is taken in", || !r.ordering()).await;
    assert!(
        !r.dir.dir().join(ACCOUNT_FILE).exists(),
        "the account the authority does not know is not kept"
    );
    r.ca.script().fail = None;
    r.apply(&[(SHOP, &[HOST], "r2")], 2);
    until("the app is served", || r.issued(SHOP)).await;
    assert_eq!(r.ca.script().created, [DIRECTORY, DIRECTORY]);
    assert!(r.dir.dir().join(ACCOUNT_FILE).exists());
}
