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

fn tmpdir(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("wafio-link-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
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
}

impl BundleSink for Sink {
    fn apply(&self, json: &[u8], generation: i64) -> Result<(), BundleError> {
        if let Some(e) = self.fail.lock().unwrap().clone() {
            return Err(e);
        }
        self.applied
            .lock()
            .unwrap()
            .push((String::from_utf8(json.to_vec()).unwrap(), generation));
        Ok(())
    }

    fn check(&self, _: &[u8]) -> Result<(), String> {
        self.check_error.lock().unwrap().clone().map_or(Ok(()), Err)
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
    ControlLink::new(
        cfg,
        Hooks {
            bundles: sink,
            stats: Arc::new(Stats),
            security_data: sec,
            redact,
            on_dial: |_| {},
        },
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
    let cached = load_bundle_cache(&state, &|_| Ok(())).unwrap();
    assert_eq!(cached.generation, 7);
    assert_eq!(BundleProbe::parse(&cached.bundle).unwrap().generation, 7);
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
    std::fs::remove_dir_all(state).unwrap();
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
    assert!(l.install_cached_bundle());
    assert_eq!(l.bundle_status(), ("cache_stale".to_string(), 42));

    let sink = Arc::new(Sink::default());
    *sink.fail.lock().unwrap() = Some(BundleError::Apply("address in use".into()));
    let l = link(
        config(&closed, "localhost", "client", &state),
        sink,
        Arc::default(),
    );
    assert!(!l.install_cached_bundle());
    assert_eq!(l.bundle_status(), (String::new(), 0));
    assert_eq!(l.heartbeat(None).bundle_source, None);

    // No state directory: no cache.
    let l = link(
        config(&closed, "localhost", "client", Path::new("")),
        Arc::default(),
        Arc::default(),
    );
    assert!(!l.is_cached_bundle_usable() && !l.install_cached_bundle());
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
    std::fs::remove_dir_all(state).unwrap();
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
    std::fs::remove_dir_all(state).unwrap();
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
        std::fs::remove_dir_all(state).unwrap();
    }
}
