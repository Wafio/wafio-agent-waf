//! Black-box test: an in-process fake control plane (tonic, mTLS with the
//! fixture CA) records what the link sends and drives what it receives.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};
use wafio_control::*;
use wafio_proto::v1::agent_control_server::{AgentControl, AgentControlServer};
use wafio_proto::v1::agent_message::Kind as Out;
use wafio_proto::v1::server_message::Kind as In;
use wafio_proto::v1::*;

const WAIT: Duration = Duration::from_secs(5);

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).unwrap()
}

/// The state directory of one test, in memory where the host has /dev/shm. The link writes the
/// bundle cache with an fsync after it acks a bundle, off the stream, so a slow disk no longer holds
/// the messages behind the bundle; the tests that read the cache still wait for it, and on tmpfs
/// an fsync returns at once. The cache's own disk handling is tested in the crate's bundle cache
/// tests.
fn tmpdir(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let shm = Path::new("/dev/shm");
    let base = if shm.is_dir() {
        shm.to_path_buf()
    } else {
        std::env::temp_dir()
    };
    let d = base.join(format!("wafio-link-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Removes the state directory of a test whose link is done. The cache write of an applied bundle
/// runs after its ack, so it is finished first: a write still running would put files back.
async fn clean_up(link: &ControlLink, state: PathBuf) {
    link.finish_cache_write().await;
    std::fs::remove_dir_all(state).unwrap();
}

/// The cache once it holds `generation`: the link acks a bundle before it writes the cache.
async fn cached(state: &Path, generation: i64) -> CachedBundle {
    let end = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(c) = load_bundle_cache(state, &|_| Ok(()))
            && c.generation == generation
        {
            return c;
        }
        assert!(
            std::time::Instant::now() < end,
            "generation {generation} not cached within a minute"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ── fake control plane ──────────────────────────────────────────────────────

struct Conn {
    inbound: Streaming<AgentMessage>,
    out: mpsc::Sender<Result<ServerMessage, Status>>,
}

impl Conn {
    async fn next(&mut self) -> Option<AgentMessage> {
        tokio::time::timeout(WAIT, self.inbound.message())
            .await
            .expect("agent message")
            .ok()
            .flatten()
    }

    /// The next message other than a heartbeat.
    async fn next_non_heartbeat(&mut self) -> AgentMessage {
        loop {
            let m = self.next().await.expect("stream open");
            if !matches!(m.kind, Some(Out::Heartbeat(_))) {
                return m;
            }
        }
    }

    async fn next_ack(&mut self, id: &str) -> CommandAck {
        loop {
            if let Some(Out::Ack(a)) = self.next_non_heartbeat().await.kind
                && a.command_id == id
            {
                return a;
            }
        }
    }

    /// The next `n` acks, in the order they arrive, with the heartbeats left out.
    async fn next_acks(&mut self, n: usize) -> Vec<CommandAck> {
        let mut acks = Vec::new();
        while acks.len() < n {
            if let Some(Out::Ack(a)) = self.next_non_heartbeat().await.kind {
                acks.push(a);
            }
        }
        acks
    }

    async fn send(&self, k: In) {
        self.out
            .send(Ok(ServerMessage { kind: Some(k) }))
            .await
            .unwrap();
    }
}

#[derive(Default)]
struct FakeOptions {
    reject: Option<Status>,
    auto_welcome: bool,
    malware: Vec<u8>,
    /// `DownloadMalwareDatabase` answers with this status.
    download_status: Option<Status>,
}

struct Fake {
    conns: mpsc::UnboundedSender<Conn>,
    options: FakeOptions,
}

#[tonic::codegen::async_trait]
impl AgentControl for Fake {
    type StreamStream = ReceiverStream<Result<ServerMessage, Status>>;
    async fn stream(
        &self,
        req: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        if let Some(s) = &self.options.reject {
            return Err(s.clone());
        }
        let (tx, rx) = mpsc::channel(16);
        if self.options.auto_welcome {
            let w = Welcome {
                agent_id: "agent-uuid".into(),
                server_time_unix: 1,
                heartbeat_seconds: 30,
            };
            tx.send(Ok(ServerMessage {
                kind: Some(In::Welcome(w)),
            }))
            .await
            .unwrap();
        }
        let _ = self.conns.send(Conn {
            inbound: req.into_inner(),
            out: tx,
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type DownloadMalwareDatabaseStream = tonic::codegen::tokio_stream::Iter<
        std::vec::IntoIter<Result<MalwareDatabaseChunk, Status>>,
    >;
    async fn download_malware_database(
        &self,
        _: Request<MalwareDatabaseRequest>,
    ) -> Result<Response<Self::DownloadMalwareDatabaseStream>, Status> {
        if let Some(s) = &self.options.download_status {
            return Err(s.clone());
        }
        let data = self.options.malware.clone();
        let sum: String = Sha256::digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let chunks = vec![
            Ok(MalwareDatabaseChunk {
                data: data[..data.len() / 2].to_vec(),
                sha256: String::new(),
            }),
            Ok(MalwareDatabaseChunk {
                data: data[data.len() / 2..].to_vec(),
                sha256: String::new(),
            }),
            Ok(MalwareDatabaseChunk {
                data: vec![],
                sha256: sum,
            }),
        ];
        Ok(Response::new(tonic::codegen::tokio_stream::iter(chunks)))
    }
}

async fn start_fake(opts: FakeOptions) -> (String, mpsc::UnboundedReceiver<Conn>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::unbounded_channel();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(read("server.crt"), read("server.key")))
        .client_ca_root(Certificate::from_pem(read("ca.crt")));
    let svc = AgentControlServer::new(Fake {
        conns: tx,
        options: opts,
    });
    tokio::spawn(
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(svc)
            .serve_with_incoming(TcpIncoming::from(listener)),
    );
    (addr, rx)
}

async fn next_conn(rx: &mut mpsc::UnboundedReceiver<Conn>) -> Conn {
    tokio::time::timeout(WAIT, rx.recv())
        .await
        .expect("agent (re)connects")
        .unwrap()
}

// ── agent side ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct Sink {
    applied: Mutex<Vec<(String, i64)>>,
    fail: Mutex<Option<BundleError>>,
    /// What the full decode (`check`) says about a document.
    check_error: Mutex<Option<String>>,
    /// The start and the end of every apply and install, in the order they ran.
    log: Mutex<Vec<String>>,
    /// Every apply and install takes this long, so a handler that does not wait for the one
    /// before it shows up as an overlap in `log`.
    delay: Mutex<Duration>,
    /// The key each install carried when the sink got it, by command id.
    keys: Mutex<Vec<(String, Vec<u8>)>>,
    /// Installs this sink refuses, by command id.
    refuse: Mutex<HashMap<String, AckCode>>,
    /// The install under this command id makes the sink panic.
    panic_on: Mutex<Option<String>>,
}

impl BundleSink for Sink {
    fn apply(&self, json: &[u8], generation: i64) -> Result<(), BundleError> {
        if let Some(e) = self.fail.lock().unwrap().clone() {
            return Err(e);
        }
        self.log
            .lock()
            .unwrap()
            .push(format!("apply {generation} start"));
        std::thread::sleep(*self.delay.lock().unwrap());
        self.applied
            .lock()
            .unwrap()
            .push((String::from_utf8(json.to_vec()).unwrap(), generation));
        self.log
            .lock()
            .unwrap()
            .push(format!("apply {generation} end"));
        Ok(())
    }

    fn check(&self, _: &[u8]) -> Result<(), String> {
        self.check_error.lock().unwrap().clone().map_or(Ok(()), Err)
    }
}

impl CertificateSink for Sink {
    fn install(&self, install: &mut CertificateInstall) -> Result<(), AckCode> {
        let id = install.command_id.clone();
        self.log.lock().unwrap().push(format!("install {id} start"));
        std::thread::sleep(*self.delay.lock().unwrap());
        self.keys
            .lock()
            .unwrap()
            .push((id.clone(), install.key_pem.clone()));
        if self.panic_on.lock().unwrap().as_deref() == Some(id.as_str()) {
            panic!("sink failed");
        }
        self.log.lock().unwrap().push(format!("install {id} end"));
        match self.refuse.lock().unwrap().get(&id) {
            Some(code) => Err(*code),
            None => Ok(()),
        }
    }
}

const COUNTERS: HeartbeatCounters = HeartbeatCounters {
    analyze_panics_total: 1,
    engine_panics_total: 2,
    partial_coverage_total: 3,
    parse_budget_exhausted_total: 4,
    script_incomplete_total: 11,
    script_errors_total: 12,
    script_rules_rejected_total: 13,
    script_runs_in_flight: -1,
    agent_panics_total: 15,
    analyze_latency_p50_us: 16,
    analyze_latency_p95_us: 17,
    analyze_latency_p99_us: 18,
    analyze_latency_samples: 19,
    regex_rules_dropped_total: 20,
};

struct Stats;
impl AgentStats for Stats {
    fn counters(&self) -> HeartbeatCounters {
        COUNTERS
    }
    fn host_info_json(&self) -> Vec<u8> {
        br#"{"hostname":"h","agent_kind":"waf","siem_delivery":{}}"#.to_vec()
    }
}

#[derive(Default)]
struct Sec {
    installs: Mutex<Vec<Vec<u8>>>,
    fetches: Mutex<Vec<Vec<String>>>,
}
impl SecurityData for Sec {
    fn replace_malware_snapshot(&self, _dir: &Path, data: Vec<u8>) -> Result<(), String> {
        self.installs.lock().unwrap().push(data);
        Ok(())
    }
    fn download_components(&self, _dir: &Path, only: &[String], _force: bool) -> Vec<FetchResult> {
        self.fetches.lock().unwrap().push(only.to_vec());
        only.iter()
            .map(|c| FetchResult {
                component: c.clone(),
                error: Some("no license".into()),
            })
            .collect()
    }
}

fn redact(ev: &mut DecisionEvent) {
    ev.request_headers.remove(b"Authorization".as_slice());
}

fn config(addr: &str, server_name: &str, client: &str, state_dir: &Path) -> ControlConfig {
    let p = |n: &str| fixture(n).to_string_lossy().to_string();
    let mut cfg = ControlConfig::load(
        addr,
        server_name,
        &p(&format!("{client}.crt")),
        &p(&format!("{client}.key")),
        &p("ca.crt"),
        "edge-1",
        "wafh_old",
        "test",
    )
    .unwrap();
    cfg.state_dir = state_dir.to_string_lossy().to_string();
    cfg.security_data_dir = state_dir.join("secdata").to_string_lossy().to_string();
    cfg
}

fn link(cfg: ControlConfig, sink: Arc<Sink>, sec: Arc<Sec>) -> Arc<ControlLink> {
    link_writing(cfg, sink, sec, Arc::new(save_bundle_cache))
}

/// [`link`] with `write` as the way a bundle reaches the cache directory.
fn link_writing(
    cfg: ControlConfig,
    sink: Arc<Sink>,
    sec: Arc<Sec>,
    write: CacheWrite,
) -> Arc<ControlLink> {
    ControlLink::with_cache_write(
        cfg,
        Hooks {
            bundles: sink.clone(),
            certificates: sink,
            stats: Arc::new(Stats),
            security_data: sec,
            redact,
            on_dial: |_| {},
        },
        write,
    )
}

fn hello(m: AgentMessage) -> Hello {
    match m.kind {
        Some(Out::Hello(h)) => h,
        other => panic!("expected Hello, got {other:?}"),
    }
}

fn heartbeat(m: AgentMessage) -> Heartbeat {
    match m.kind {
        Some(Out::Heartbeat(h)) => h,
        other => panic!("expected Heartbeat, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_session_end_to_end() {
    let malware = format!("{:064x}\tMalware.Test\n", 42).into_bytes();
    let (addr, mut conns) = start_fake(FakeOptions {
        malware: malware.clone(),
        ..Default::default()
    })
    .await;
    let state = tmpdir("session");
    let (sink, sec) = (Arc::new(Sink::default()), Arc::new(Sec::default()));
    // Server name differs from the dialled address (cert SAN is DNS:localhost).
    let link = link(
        config(&addr, "localhost", "client", &state),
        sink.clone(),
        sec.clone(),
    );
    let task = link.start();

    // Hello, then the first heartbeat with host info.
    let mut c = next_conn(&mut conns).await;
    let h = hello(c.next().await.unwrap());
    assert_eq!(h.agent_name, "edge-1");
    assert_eq!(h.agent_version, "wafio-waf-agent/test");
    assert_eq!(
        (
            h.bundle_generation,
            h.host_key.as_str(),
            h.agent_kind.as_str()
        ),
        (0, "wafh_old", "waf")
    );
    assert!(
        h.features.is_empty(),
        "the link reports only what the agent sets: {:?}",
        h.features
    );
    let hb = heartbeat(c.next().await.unwrap());
    assert_eq!(
        hb.host_info_json,
        br#"{"hostname":"h","agent_kind":"waf","siem_delivery":{}}"#
    );
    assert_eq!(
        (
            hb.analyze_panics_total,
            hb.engine_panics_total,
            hb.partial_coverage_total,
            hb.parse_budget_exhausted_total
        ),
        (Some(1), Some(2), Some(3), Some(4))
    );
    assert_eq!(
        (
            hb.script_incomplete_total,
            hb.script_errors_total,
            hb.script_rules_rejected_total,
            hb.script_runs_in_flight
        ),
        (Some(11), Some(12), Some(13), Some(-1))
    );
    assert_eq!(
        (
            hb.agent_panics_total,
            hb.analyze_latency_p50_us,
            hb.analyze_latency_p95_us
        ),
        (Some(15), Some(16), Some(17))
    );
    assert_eq!(
        (
            hb.analyze_latency_p99_us,
            hb.analyze_latency_samples,
            hb.regex_rules_dropped_total
        ),
        (Some(18), Some(19), Some(20))
    );
    assert_eq!((hb.bundle_source, hb.bundle_generation), (None, None));
    assert!(hb.unix_time > 1_700_000_000);
    assert!(link.connected());

    // Welcome → malware sync over DownloadMalwareDatabase, then the security-data report.
    c.send(In::Welcome(Welcome {
        agent_id: "agent-uuid".into(),
        server_time_unix: 1,
        heartbeat_seconds: 30,
    }))
    .await;
    let st = c.next_ack("secdata:status").await;
    assert!(st.ok);
    let status: serde_json::Value = serde_json::from_str(&st.error).unwrap();
    assert_eq!(status.as_object().unwrap().len(), 9);
    assert!(
        status.get("crs").is_none(),
        "the retired component is not reported"
    );
    assert_eq!(*sec.installs.lock().unwrap(), vec![malware.clone()]);

    // A configuration bundle: applied with the message's generation, acked, cached.
    let bundle = r#"{"agent_id":"a1","generation":5,"apps":[{"app_id":"x","listen_port":8080}]}"#;
    c.send(In::Bundle(BundleUpdate {
        command_id: "init-1".into(),
        generation: 7,
        bundle_json: bundle.into(),
    }))
    .await;
    let a = c.next_ack("init-1").await;
    assert!(a.ok && a.error.is_empty(), "{a:?}");
    assert_eq!(*sink.applied.lock().unwrap(), vec![(bundle.to_string(), 7)]);
    let on_disk = cached(&state, 7).await;
    assert_eq!(BundleProbe::parse(&on_disk.bundle).unwrap().generation, 7);
    assert_eq!(link.bundle_status(), ("live".to_string(), 7));

    // A management command is applied and acked but never cached or counted as config.
    let unblock =
        r#"{"management_only":true,"unblock_entries":[{"type":"blockpolicy","key":"1.2.3.4"}]}"#;
    c.send(In::Bundle(BundleUpdate {
        command_id: "u1".into(),
        generation: 0,
        bundle_json: unblock.into(),
    }))
    .await;
    assert!(c.next_ack("u1").await.ok);
    assert_eq!(
        load_bundle_cache(&state, &|_| Ok(())).unwrap().generation,
        7
    );
    assert_eq!(link.bundle_status(), ("live".to_string(), 7));

    // A bundle that does not decode is refused once, not retried.
    c.send(In::Bundle(BundleUpdate {
        command_id: "bad".into(),
        generation: 8,
        bundle_json: b"not json".to_vec(),
    }))
    .await;
    let bad = c.next_ack("bad").await;
    assert_eq!(
        (bad.ok, bad.error.as_str()),
        (
            false,
            "invalid character 'o' in literal null (expecting 'u')"
        )
    );
    // An empty bundle is ignored (no ack): the Ping reply comes next.
    c.send(In::Bundle(BundleUpdate {
        command_id: "empty".into(),
        generation: 9,
        bundle_json: vec![],
    }))
    .await;

    // Ping → heartbeat without host info, now with the bundle provenance.
    c.send(In::Ping(Ping { nonce: 9 })).await;
    let hb = heartbeat(c.next().await.unwrap());
    assert!(hb.host_info_json.is_empty());
    assert_eq!(
        (hb.bundle_source.as_deref(), hb.bundle_generation),
        (Some("live"), Some(7))
    );

    // Decisions: redacted, made valid UTF-8, sent over the stream.
    let mut ev = DecisionEvent {
        uri: b"/search?q=\xff\xfe".to_vec(),
        action: b"block".to_vec(),
        score: 175,
        coverage: b"field_cap".to_vec(),
        match_value: Some(b"secret".to_vec()),
        ..Default::default()
    };
    ev.request_headers = HashMap::from([
        (b"Authorization".to_vec(), b"Bearer x".to_vec()),
        (b"User-Agent".to_vec(), b"sqlmap".to_vec()),
    ]);
    link.queue_decision_event(ev);
    let d = match c.next_non_heartbeat().await.kind {
        Some(Out::Decision(d)) => d,
        other => panic!("expected decision, got {other:?}"),
    };
    assert_eq!(
        (
            d.uri.as_str(),
            d.action.as_str(),
            d.score,
            d.coverage.as_str()
        ),
        ("/search?q=\u{FFFD}", "block", 175, "field_cap")
    );
    assert_eq!(
        d.request_headers,
        HashMap::from([("User-Agent".to_string(), "sqlmap".to_string())])
    );
    let t = link.telemetry_stats();
    assert_eq!((t.decisions, t.blocks, t.sent, t.dropped), (1, 1, 1, 0));

    // Key rotation: acked, then the link reconnects with the new key and the generation.
    c.send(In::KeyRotation(KeyRotation {
        command_id: "kr-1".into(),
        new_host_key: "wafh_new".into(),
    }))
    .await;
    assert!(c.next_ack("kr-1").await.ok);
    assert!(
        tokio::time::timeout(WAIT, async { while c.next().await.is_some() {} })
            .await
            .is_ok(),
        "agent closed its side"
    );
    let mut c = next_conn(&mut conns).await;
    let h = hello(c.next().await.unwrap());
    assert_eq!((h.host_key.as_str(), h.bundle_generation), ("wafh_new", 7));
    assert_eq!(link.host_key(), "wafh_new");

    // FetchSecurityData: malware from the control plane, the rest through download_components.
    c.send(In::FetchSecurityData(FetchSecurityData {
        command_id: "f1".into(),
        components: " malware, geoip-country ,".into(),
        force: true,
        malware_from_control_plane: true,
    }))
    .await;
    let a = c.next_ack("f1").await;
    assert_eq!(
        (a.ok, a.error.as_str()),
        (false, "geoip-country: no license")
    );
    assert_eq!(
        *sec.fetches.lock().unwrap(),
        vec![vec!["geoip-country".to_string()]]
    );
    assert_eq!(sec.installs.lock().unwrap().len(), 2);

    // The control plane drops the stream: the link comes back on its own.
    drop(c);
    let mut c = next_conn(&mut conns).await;
    assert_eq!(hello(c.next().await.unwrap()).bundle_generation, 7);

    task.abort();
    clean_up(&link, state).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_handshake_outcomes() {
    let state = tmpdir("probe");
    let (addr, _conns) = start_fake(FakeOptions {
        auto_welcome: true,
        ..Default::default()
    })
    .await;
    // RSA PKCS#8 client key (dashboard bundle) and SEC1 P-256 (install.sh), IP SAN.
    for client in ["client-rsa", "client"] {
        let l = link(
            config(&addr, "", client, &state),
            Arc::default(),
            Arc::default(),
        );
        l.exchange_hello()
            .await
            .unwrap_or_else(|e| panic!("{client}: {e}"));
    }

    let (rej, _c) = start_fake(FakeOptions {
        reject: Some(Status::permission_denied("invalid host_key")),
        ..Default::default()
    })
    .await;
    let e = link(
        config(&rej, "localhost", "client", &state),
        Arc::default(),
        Arc::default(),
    )
    .exchange_hello()
    .await
    .unwrap_err();
    assert!(e.rejected(), "{e}");
    assert_eq!(e.grpc_status().unwrap().message(), "invalid host_key");
    assert_eq!(
        e.to_string(),
        "rpc error: code = PermissionDenied desc = invalid host_key"
    );

    // Outages are not rejections: the agent may start from its cache.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let e = link(
        config(&closed, "localhost", "client", &state),
        Arc::default(),
        Arc::default(),
    )
    .exchange_hello()
    .await
    .unwrap_err();
    assert!(
        !e.rejected()
            && e.to_string()
                .starts_with("open stream: rpc error: code = Unavailable"),
        "{e}"
    );
    let e = link(
        config(&addr, "wrong.example", "client", &state),
        Arc::default(),
        Arc::default(),
    )
    .exchange_hello()
    .await
    .unwrap_err();
    assert!(!e.rejected(), "{e}");

    let mut cfg = config(&addr, "localhost", "client", &state);
    cfg.ca_pem = b"not a pem".to_vec();
    let e = link(cfg, Arc::default(), Arc::default())
        .exchange_hello()
        .await
        .unwrap_err();
    assert_eq!(e.to_string(), "append CA: invalid PEM");
    std::fs::remove_dir_all(state).unwrap();
}

// With the control plane down the cached bundle is applied before connecting and
// reported in the heartbeat; an old one is flagged stale; a refused one is not reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn starts_from_cached_bundle() {
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let raw = br#"{"agent_id":"a1","generation":42,"apps":[]}"#;

    let state = tmpdir("cache");
    save_bundle_cache(&state, raw, 42, SystemTime::now()).unwrap();
    let sink = Arc::new(Sink::default());
    let l = link(
        config(&closed, "localhost", "client", &state),
        sink.clone(),
        Arc::default(),
    );
    assert!(l.is_cached_bundle_usable());
    let task = l.start();
    tokio::time::timeout(WAIT, async {
        while sink.applied.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert_eq!(sink.applied.lock().unwrap()[0].1, 42);
    assert_eq!(l.bundle_status(), ("cache".to_string(), 42));
    let hb = l.heartbeat(None);
    assert_eq!(
        (hb.bundle_source.as_deref(), hb.bundle_generation),
        (Some("cache"), Some(42))
    );

    let mut cfg = config(&closed, "localhost", "client", &state);
    cfg.bundle_cache_max_age = Duration::from_secs(3600);
    save_bundle_cache(
        &state,
        raw,
        42,
        SystemTime::now() - Duration::from_secs(7200),
    )
    .unwrap();
    let l = link(cfg, Arc::default(), Arc::default());
    assert_eq!(l.install_cached_bundle(), CacheStart::Applied);
    assert_eq!(l.bundle_status(), ("cache_stale".to_string(), 42));

    let sink = Arc::new(Sink::default());
    *sink.fail.lock().unwrap() = Some(BundleError::Apply("address in use".into()));
    let l = link(
        config(&closed, "localhost", "client", &state),
        sink,
        Arc::default(),
    );
    assert_eq!(l.install_cached_bundle(), CacheStart::NotApplied);
    assert_eq!(l.bundle_status(), (String::new(), 0));
    assert_eq!(l.heartbeat(None).bundle_source, None);

    // No state directory: no cache.
    let l = link(
        config(&closed, "localhost", "client", Path::new("")),
        Arc::default(),
        Arc::default(),
    );
    assert!(!l.is_cached_bundle_usable());
    assert_eq!(l.install_cached_bundle(), CacheStart::NotApplied);
    std::fs::remove_dir_all(state).unwrap();
}

/// Conformance scenario `grpc-bundle-refused`: the ack of a bundle that does not decode carries
/// the decoder's text (syntax, top-level kind, type of a probed field), once, no retry. The
/// probe reads four fields: when the sink's full decode (`check`) has an error, that first
/// error of the whole document is the one reported.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undecodable_bundles_are_acked_with_the_decoder_error_text() {
    let (addr, mut conns) = start_fake(FakeOptions {
        malware: b"x".to_vec(),
        ..Default::default()
    })
    .await;
    let state = tmpdir("decode");
    let (sink, sec) = (Arc::new(Sink::default()), Arc::new(Sec::default()));
    let link = link(
        config(&addr, "localhost", "client", &state),
        sink.clone(),
        sec,
    );
    let task = link.start();
    let mut c = next_conn(&mut conns).await;
    c.send(In::Welcome(Welcome::default())).await;

    let mut refuse = async |id: &str, json: &str| {
        c.send(In::Bundle(BundleUpdate {
            command_id: id.into(),
            generation: 3,
            bundle_json: json.into(),
        }))
        .await;
        let a = c.next_ack(id).await;
        assert!(!a.ok, "{json}");
        a.error
    };
    for (json, want) in [
        (r#"{"apps":"#, "unexpected end of JSON input"),
        ("[1,2]", "expected an object, got an array"),
        (
            r#"{"generation":"3"}"#,
            "generation: expected an integer, got a string",
        ),
        (
            r#"{"generation":1.5}"#,
            "generation: expected an integer, got the number 1.5",
        ),
        (
            r#"{"management_only":1}"#,
            "management_only: expected true or false, got a number",
        ),
        (r#"{"apps":[1]}"#, "apps: expected an object, got a number"),
        (
            r#"{"unblock_entries":{}}"#,
            "unblock_entries: expected an array, got an object",
        ),
    ] {
        assert_eq!(refuse("probe", json).await, want, "{json}");
    }
    // The first error of the document is reported: the app's own field, not the later element.
    *sink.check_error.lock().unwrap() =
        Some("apps.listen_port: expected an integer, got a string".into());
    assert_eq!(
        refuse("full", r#"{"apps":[{"listen_port":"80"},1]}"#).await,
        "apps.listen_port: expected an integer, got a string"
    );
    assert!(sink.applied.lock().unwrap().is_empty());
    assert_eq!(link.bundle_status(), (String::new(), 0));

    task.abort();
    clean_up(&link, state).await;
}

/// A control message may be 4 MiB; a bigger one ends the stream, and the link opens a new one
/// without applying anything. The control plane keeps every bundle under the limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_over_four_mebibytes_ends_the_stream() {
    let (addr, mut conns) = start_fake(FakeOptions {
        malware: b"x".to_vec(),
        ..Default::default()
    })
    .await;
    let state = tmpdir("size");
    let (sink, sec) = (Arc::new(Sink::default()), Arc::new(Sec::default()));
    let link = link(
        config(&addr, "localhost", "client", &state),
        sink.clone(),
        sec,
    );
    let task = link.start();
    let mut c = next_conn(&mut conns).await;
    c.send(In::Welcome(Welcome::default())).await;

    let padded = |total: usize| {
        let head = r#"{"generation":5,"pad":""#;
        let tail = r#""}"#;
        format!(
            "{head}{}{tail}",
            "a".repeat(total - head.len() - tail.len())
        )
    };
    let fits = padded((4 << 20) - 1024);
    c.send(In::Bundle(BundleUpdate {
        command_id: "fits".into(),
        generation: 5,
        bundle_json: fits.clone().into(),
    }))
    .await;
    assert!(c.next_ack("fits").await.ok);
    assert_eq!(sink.applied.lock().unwrap().len(), 1);

    // The message holds the bundle and a few bytes of framing, so a bundle of exactly the
    // limit is already too big.
    c.send(In::Bundle(BundleUpdate {
        command_id: "big".into(),
        generation: 6,
        bundle_json: padded(4 << 20).into(),
    }))
    .await;
    let mut c = next_conn(&mut conns).await;
    assert_eq!(hello(c.next().await.unwrap()).bundle_generation, 5);
    assert_eq!(
        sink.applied.lock().unwrap().len(),
        1,
        "the big bundle was not applied"
    );

    task.abort();
    clean_up(&link, state).await;
}

/// Conformance scenario `grpc-fetch-security-data`: the server's refusal of
/// `DownloadMalwareDatabase` arrives on `Recv`, so anything but a connection that cannot take
/// the call is "interrupted".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malware_download_refusals_report_the_refusal_text() {
    for (status, want) in [
        (
            Status::unimplemented("unknown method"),
            "malware: malware transfer interrupted; previous database retained",
        ),
        (
            Status::permission_denied("no"),
            "malware: malware transfer interrupted; previous database retained",
        ),
        (
            Status::unavailable("no connection"),
            "malware: control-plane malware download unavailable",
        ),
    ] {
        let (addr, mut conns) = start_fake(FakeOptions {
            download_status: Some(status.clone()),
            ..Default::default()
        })
        .await;
        let state = tmpdir("malware-refused");
        let link = link(
            config(&addr, "localhost", "client", &state),
            Arc::default(),
            Arc::default(),
        );
        let task = link.start();
        let mut c = next_conn(&mut conns).await;
        c.send(In::FetchSecurityData(FetchSecurityData {
            command_id: "fsd-1".into(),
            components: "malware".into(),
            malware_from_control_plane: true,
            ..Default::default()
        }))
        .await;
        // The status report goes out before the ack.
        assert!(c.next_ack("secdata:status").await.ok);
        let a = c.next_ack("fsd-1").await;
        assert_eq!((a.ok, a.error.as_str()), (false, want), "{status}");
        task.abort();
        clean_up(&link, state).await;
    }
}

fn bundle_message(id: &str, generation: i64) -> In {
    In::Bundle(BundleUpdate {
        command_id: id.into(),
        generation,
        bundle_json: format!(r#"{{"generation":{generation},"apps":[]}}"#).into(),
    })
}

fn install_message(id: &str) -> In {
    In::CertificateInstall(CertificateInstall {
        command_id: id.into(),
        app_id: "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11".into(),
        certificate_id: "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77".into(),
        chain_pem: b"chain".to_vec(),
        key_pem: format!("key of {id}").into_bytes(),
        leaf_sha256: "ab".repeat(32),
    })
}

/// An install is handled between the bundles around it, in the order the stream delivered them,
/// and the acks go out in that order. Each handler takes time, so one that ran ahead of the one
/// before it would show as an overlap in the sink's log.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn installs_and_bundles_keep_stream_order() {
    let (addr, mut conns) = start_fake(FakeOptions::default()).await;
    let state = tmpdir("order");
    let sink = Arc::new(Sink::default());
    *sink.delay.lock().unwrap() = Duration::from_millis(40);
    sink.refuse
        .lock()
        .unwrap()
        .insert("i2".into(), AckCode::KeyMismatch);
    let link = link(
        config(&addr, "localhost", "client", &state),
        sink.clone(),
        Arc::default(),
    );
    let task = link.start();
    let mut c = next_conn(&mut conns).await;
    hello(c.next().await.unwrap());

    for m in [
        bundle_message("b1", 1),
        install_message("i1"),
        bundle_message("b2", 2),
        install_message("i2"),
    ] {
        c.send(m).await;
    }
    let acks = c.next_acks(4).await;
    assert_eq!(
        acks.iter()
            .map(|a| (a.command_id.as_str(), a.ok, a.error.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("b1", true, ""),
            ("i1", true, ""),
            ("b2", true, ""),
            ("i2", false, "key_mismatch"),
        ]
    );
    assert_eq!(
        *sink.log.lock().unwrap(),
        vec![
            "apply 1 start",
            "apply 1 end",
            "install i1 start",
            "install i1 end",
            "apply 2 start",
            "apply 2 end",
            "install i2 start",
            "install i2 end",
        ]
    );
    // The sink got each key whole: it is zeroed only after the sink returned.
    assert_eq!(
        *sink.keys.lock().unwrap(),
        vec![
            ("i1".to_string(), b"key of i1".to_vec()),
            ("i2".to_string(), b"key of i2".to_vec()),
        ]
    );
    task.abort();
    clean_up(&link, state).await;
}

/// A sink that panics is a refusal the control plane may retry, and the link goes on with the
/// next message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_panicking_certificate_sink_is_acked_write_failed_and_the_stream_goes_on() {
    let (addr, mut conns) = start_fake(FakeOptions::default()).await;
    let state = tmpdir("panic");
    let sink = Arc::new(Sink::default());
    *sink.panic_on.lock().unwrap() = Some("boom".into());
    let link = link(
        config(&addr, "localhost", "client", &state),
        sink.clone(),
        Arc::default(),
    );
    let task = link.start();
    let mut c = next_conn(&mut conns).await;
    hello(c.next().await.unwrap());
    // The first heartbeat, with the host info, is read first so the Ping reply is the next one.
    heartbeat(c.next().await.unwrap());

    c.send(install_message("boom")).await;
    c.send(install_message("fine")).await;
    let acks = c.next_acks(2).await;
    assert_eq!(
        acks.iter()
            .map(|a| (a.command_id.as_str(), a.ok, a.error.as_str()))
            .collect::<Vec<_>>(),
        vec![("boom", false, "write_failed"), ("fine", true, "")]
    );
    assert_eq!(sink.keys.lock().unwrap()[0].1, b"key of boom");
    c.send(In::Ping(Ping { nonce: 1 })).await;
    assert!(heartbeat(c.next().await.unwrap()).host_info_json.is_empty());
    task.abort();
    clean_up(&link, state).await;
}

/// A control plane that never sends an install, as one that predates the message, sees what it
/// saw before: no new Hello feature, no certificate status, the same acks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_plane_that_sends_no_install_sees_no_certificate_traffic() {
    let (addr, mut conns) = start_fake(FakeOptions::default()).await;
    let state = tmpdir("older");
    let link = link(
        config(&addr, "localhost", "client", &state),
        Arc::default(),
        Arc::default(),
    );
    let task = link.start();
    let mut c = next_conn(&mut conns).await;
    let h = hello(c.next().await.unwrap());
    assert!(h.features.is_empty(), "{:?}", h.features);
    heartbeat(c.next().await.unwrap());

    c.send(bundle_message("b1", 1)).await;
    c.send(In::Bundle(BundleUpdate {
        command_id: "u1".into(),
        generation: 0,
        bundle_json: br#"{"management_only":true}"#.to_vec(),
    }))
    .await;
    c.send(In::Ping(Ping { nonce: 2 })).await;
    let mut seen = Vec::new();
    loop {
        match c.next().await.expect("stream open").kind {
            Some(Out::Heartbeat(hb)) if hb.host_info_json.is_empty() => break,
            other => seen.push(other),
        }
    }
    let acks: Vec<_> = seen
        .iter()
        .map(|k| match k {
            Some(Out::Ack(a)) => (a.command_id.as_str(), a.ok, a.error.as_str()),
            other => panic!("unexpected message {other:?}"),
        })
        .collect();
    assert_eq!(acks, vec![("b1", true, ""), ("u1", true, "")]);
    task.abort();
    clean_up(&link, state).await;
}

/// A status handed to the link while a stream is up goes out on it with its fields as given.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reported_certificate_status_goes_out_on_the_stream() {
    let (addr, mut conns) = start_fake(FakeOptions::default()).await;
    let state = tmpdir("status");
    let link = link(
        config(&addr, "localhost", "client", &state),
        Arc::default(),
        Arc::default(),
    );
    let task = link.start();
    let mut c = next_conn(&mut conns).await;
    hello(c.next().await.unwrap());
    assert!(link.connected());

    let status = CertificateStatus {
        app_id: "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11".into(),
        source: "uploaded".into(),
        state: "missing".into(),
        certificate_id: "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77".into(),
        unix_time: 1_700_000_000,
        ..Default::default()
    };
    link.report_certificate_status(status.clone());
    let got = loop {
        match c.next().await.expect("stream open").kind {
            Some(Out::CertificateStatus(s)) => break s,
            Some(Out::Heartbeat(_)) => {}
            other => panic!("unexpected message {other:?}"),
        }
    };
    assert_eq!(got, status);
    task.abort();
    clean_up(&link, state).await;
}

/// A cache write that a test holds back: it notes the generation it was asked to write, waits until
/// the test lets it go, and then writes the file as the link does.
#[derive(Default)]
struct HeldWrites {
    started: Mutex<Vec<i64>>,
    open: Mutex<bool>,
    opened: std::sync::Condvar,
}

impl HeldWrites {
    fn writer(self: &Arc<Self>) -> CacheWrite {
        let held = self.clone();
        Arc::new(
            move |dir: &Path, bundle: &[u8], generation: i64, now: SystemTime| {
                held.started.lock().unwrap().push(generation);
                let mut open = held.open.lock().unwrap();
                while !*open {
                    let (guard, wait) = held.opened.wait_timeout(open, 6 * WAIT).unwrap();
                    open = guard;
                    if wait.timed_out() {
                        return Err("the test never let the write go".into());
                    }
                }
                drop(open);
                save_bundle_cache(dir, bundle, generation, now)
            },
        )
    }

    fn let_go(&self) {
        *self.open.lock().unwrap() = true;
        self.opened.notify_all();
    }

    fn started(&self) -> Vec<i64> {
        self.started.lock().unwrap().clone()
    }
}

/// Waits until `done` is true, for at most a minute.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(
            std::time::Instant::now() < end,
            "{what}: not within a minute"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// With the cache write held back for the whole test, the ack of a bundle and the acks of the
/// commands behind it still go out, and the file is not there yet. Of the bundles that arrive
/// while the write is held, only the newest is written once it goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_cache_write_holds_back_neither_the_ack_of_a_bundle_nor_the_commands_after_it() {
    let (addr, mut conns) = start_fake(FakeOptions::default()).await;
    let state = tmpdir("slow-write");
    let held = Arc::new(HeldWrites::default());
    let link = link_writing(
        config(&addr, "localhost", "client", &state),
        Arc::default(),
        Arc::default(),
        held.writer(),
    );
    let task = link.start();
    let mut c = next_conn(&mut conns).await;
    hello(c.next().await.unwrap());

    c.send(bundle_message("b1", 1)).await;
    let a = c.next_ack("b1").await;
    assert!(a.ok, "{a:?}");
    until("the first write to start", || held.started() == [1]).await;
    let file = state.join(BUNDLE_CACHE_FILE_NAME);
    assert!(!file.exists(), "the ack came while the write was held");

    // Commands sent after the bundle: an install, a management command, and three more bundles.
    c.send(install_message("i1")).await;
    assert!(c.next_ack("i1").await.ok);
    c.send(In::Bundle(BundleUpdate {
        command_id: "u1".into(),
        generation: 0,
        bundle_json: br#"{"management_only":true,"unblock_entries":[{"type":"blockpolicy","key":"1.2.3.4"}]}"#
            .to_vec(),
    }))
    .await;
    assert!(c.next_ack("u1").await.ok);
    for generation in 2..=4 {
        let id = format!("b{generation}");
        c.send(bundle_message(&id, generation)).await;
        assert!(c.next_ack(&id).await.ok);
    }
    assert!(!file.exists(), "every ack came while the write was held");
    assert_eq!(link.bundle_status(), ("live".to_string(), 4));

    held.let_go();
    cached(&state, 4).await;
    link.finish_cache_write().await;
    assert_eq!(
        held.started(),
        [1, 4],
        "the bundles of generations 2 and 3 were replaced while they waited"
    );
    task.abort();
    clean_up(&link, state).await;
}

/// Every line the link logs, from any thread: the cache writer logs from a thread of its own, which
/// a subscriber set for one thread would miss.
fn logged_lines() -> &'static Mutex<Vec<String>> {
    static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static ONCE: std::sync::Once = std::sync::Once::new();

    struct Collect;
    impl tracing::Subscriber for Collect {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Text(String);
            impl tracing::field::Visit for Text {
                fn record_debug(&mut self, _: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                    self.0.push_str(&format!("{v:?} "));
                }
            }
            let mut text = Text(String::new());
            event.record(&mut text);
            LINES.lock().unwrap().push(text.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    ONCE.call_once(|| tracing::subscriber::set_global_default(Collect).unwrap());
    &LINES
}

/// A write that fails is logged and does not undo the bundle: it is acked and in force. The write
/// of the next bundle goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_cache_write_is_logged_and_the_next_bundle_writes_again() {
    let lines = logged_lines();
    let (addr, mut conns) = start_fake(FakeOptions::default()).await;
    let state = tmpdir("write-fails");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let write: CacheWrite = Arc::new(
        move |dir: &Path, bundle: &[u8], generation: i64, now: SystemTime| {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Err("no space left on device (marker 4711)".into())
            } else {
                save_bundle_cache(dir, bundle, generation, now)
            }
        },
    );
    let sink = Arc::new(Sink::default());
    let link = link_writing(
        config(&addr, "localhost", "client", &state),
        sink.clone(),
        Arc::default(),
        write,
    );
    let task = link.start();
    let mut c = next_conn(&mut conns).await;
    hello(c.next().await.unwrap());

    c.send(bundle_message("b1", 1)).await;
    assert!(c.next_ack("b1").await.ok);
    until("the failure to be logged", || {
        lines.lock().unwrap().iter().any(|l| {
            l.contains(
                "cache write failed (bundle still applied): no space left on device (marker 4711)",
            )
        })
    })
    .await;
    assert_eq!(link.bundle_status(), ("live".to_string(), 1));
    assert_eq!(sink.applied.lock().unwrap().len(), 1);
    assert!(!state.join(BUNDLE_CACHE_FILE_NAME).exists());

    c.send(bundle_message("b2", 2)).await;
    assert!(c.next_ack("b2").await.ok);
    cached(&state, 2).await;
    task.abort();
    clean_up(&link, state).await;
}
