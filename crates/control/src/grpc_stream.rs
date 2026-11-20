//! The WAF agent's mTLS gRPC stream to the control plane (`AgentControl.Stream`). Its state lives
//! in one [`ControlLink`] per process.

use crate::bundle_cache::BUNDLE_SOURCE_LIVE;
use crate::bundle_puller::{BundleError, BundleProbe, BundleSink, is_management_only};
use crate::certificates::{AckCode, CertificateSink, run_install};
use crate::grpc_reconnect::{
    GRPC_CLIENT_KEEPALIVE_TIME, GRPC_CLIENT_KEEPALIVE_TIMEOUT, ReconnectBackoff, jitter,
};
use crate::malware_database::{SecurityData, pull_malware_database};
use crate::proxy_env;
use crate::timestamp::{Timestamp, whole_seconds_text};
use crate::waf_telemetry::{DecisionEvent, Redactor, Telemetry, TelemetryStats};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tracing::info;
use wafio_proto::v1::agent_control_client::AgentControlClient;
use wafio_proto::v1::agent_message::Kind as Out;
use wafio_proto::v1::server_message::Kind as In;
use wafio_proto::v1::{
    AgentMessage, BundleUpdate, CertificateInstall, CertificateStatus, CommandAck,
    FetchSecurityData, Heartbeat, Hello,
};

/// Heartbeat period; `Welcome.heartbeat_seconds` is ignored.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
/// Bound on the initial handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);
/// Connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Messages buffered between the senders and the gRPC request stream.
const STREAM_SEND_BUFFER: usize = 16;
/// Default security-data base directory.
pub const DEFAULT_SECURITY_DATA_DIR: &str = "/etc/wafio/security-data";

/// Retry bounds for a WAF configuration bundle whose apply failed.
pub(crate) const WAF_BUNDLE_RETRY_MIN: Duration = Duration::from_secs(2);
pub(crate) const WAF_BUNDLE_RETRY_MAX: Duration = Duration::from_secs(60);
/// About 8 minutes of retries; a bundle refused for good must not cost a rebuild forever.
pub(crate) const WAF_BUNDLE_RETRY_ATTEMPTS: u32 = 10;

/// The security-data components of the agent profile.
const PROFILE_AGENT_COMPONENTS: [&str; 7] = [
    "geoip-country",
    "geoip-city",
    "geoip-asn",
    "firehol",
    "ja4",
    "ua",
    "malware",
];

/// Link configuration. No `Debug`: it holds the client private key.
#[derive(Clone)]
pub struct ControlConfig {
    /// `--grpc-server` host:port.
    pub server_address: String,
    /// TLS server name (`--grpc-server-name`, see [`default_server_name`]); empty = the
    /// host of `server_address`.
    pub server_name: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
    pub agent_name: String,
    /// The host name.
    pub hostname: String,
    /// `"wafio-waf-agent/"` followed by the agent version.
    pub version: String,
    /// `--host-key`; replaced by a `KeyRotation`.
    pub host_key: String,
    /// `Hello.features`: empty from `load`; the agent sets the capability it reports.
    pub features: Vec<String>,
    /// Bundle cache directory (`--state-dir`); empty disables the cache.
    pub state_dir: String,
    /// When a cached bundle is reported stale; zero = 7 days.
    pub bundle_cache_max_age: Duration,
    /// Security-data base directory for `FetchSecurityData`; empty = `/etc/wafio/security-data`.
    pub security_data_dir: String,
    /// The agent's own configured file per component ("geoip-country", "ua", …),
    /// reported instead of the default layout.
    pub component_paths: BTreeMap<String, String>,
}

impl ControlConfig {
    /// Validate and read the PEM files.
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        server_addr: &str,
        server_name: &str,
        cert_path: &str,
        key_path: &str,
        ca_path: &str,
        agent_name: &str,
        host_key: &str,
        agent_version: &str,
    ) -> Result<Self, String> {
        if server_addr.is_empty() {
            return Err("agent gRPC: serverAddr required".into());
        }
        if agent_name.is_empty() {
            return Err("agent gRPC: agent_name required".into());
        }
        let read =
            |what: &str, p: &str| std::fs::read(p).map_err(|e| format!("read {what} {p}: {e}"));
        Ok(ControlConfig {
            server_address: server_addr.into(),
            server_name: server_name.into(),
            cert_pem: read("client cert", cert_path)?,
            key_pem: read("client key", key_path)?,
            ca_pem: read("CA", ca_path)?,
            agent_name: agent_name.into(),
            hostname: read_hostname(),
            version: format!("wafio-waf-agent/{agent_version}"),
            host_key: host_key.into(),
            features: Vec::new(),
            state_dir: String::new(),
            bundle_cache_max_age: Duration::ZERO,
            security_data_dir: String::new(),
            component_paths: BTreeMap::new(),
        })
    }
}

/// Default for `--grpc-server-name`: everything before the last ':'
/// of `--grpc-server` (brackets kept), or the whole value without one.
pub fn default_server_name(grpc_server: &str) -> String {
    match grpc_server.rfind(':') {
        Some(i) => grpc_server[..i].to_string(),
        None => grpc_server.to_string(),
    }
}

/// The host name from `/proc/sys/kernel/hostname`.
fn read_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.strip_suffix('\n').unwrap_or(&s).to_string())
        .unwrap_or_default()
}

/// Heartbeat fields 5–8 and 11–20, cumulative since process start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeartbeatCounters {
    pub analyze_panics_total: u64,
    pub engine_panics_total: u64,
    pub partial_coverage_total: u64,
    pub parse_budget_exhausted_total: u64,
    pub script_incomplete_total: u64,
    pub script_errors_total: u64,
    pub script_rules_rejected_total: u64,
    pub script_runs_in_flight: i64,
    pub agent_panics_total: u64,
    /// Analyze latency over the last 5 minutes; percentiles are sent only when
    /// `analyze_latency_samples > 0`.
    pub analyze_latency_p50_us: u64,
    pub analyze_latency_p95_us: u64,
    pub analyze_latency_p99_us: u64,
    pub analyze_latency_samples: u64,
    pub regex_rules_dropped_total: u64,
}

/// What the agent reports in heartbeats.
pub trait AgentStats: Send + Sync + 'static {
    fn counters(&self) -> HeartbeatCounters;
    /// `host_info_json` (field 4): the host info plus `siem_delivery`. Called on a blocking
    /// thread.
    fn host_info_json(&self) -> Vec<u8>;
}

/// The agent-side pieces the link calls into.
pub struct Hooks {
    pub bundles: Arc<dyn BundleSink>,
    pub certificates: Arc<dyn CertificateSink>,
    pub stats: Arc<dyn AgentStats>,
    pub security_data: Arc<dyn SecurityData>,
    pub redact: Redactor,
    /// Resolves `server_addr` for the IP jail (the jail never names the control plane), called at
    /// start and before every dial to follow DNS changes. Must not block.
    pub on_dial: fn(&str),
}

/// A stream or handshake failure. Keeps the gRPC status, if any, so the caller can tell a
/// rejection (`PermissionDenied`, `InvalidArgument`, `Unauthenticated`) from an outage.
#[derive(Debug)]
pub struct LinkError {
    message: String,
    status: Option<tonic::Status>,
}

impl LinkError {
    fn other(msg: impl Into<String>) -> Self {
        LinkError {
            message: msg.into(),
            status: None,
        }
    }

    fn status(prefix: Option<&str>, s: tonic::Status) -> Self {
        let text = format!("rpc error: code = {:?} desc = {}", s.code(), s.message());
        let msg = match prefix {
            Some(p) => format!("{p}: {text}"),
            None => text,
        };
        LinkError {
            message: msg,
            status: Some(s),
        }
    }

    pub fn grpc_status(&self) -> Option<&tonic::Status> {
        self.status.as_ref()
    }

    /// The control plane refused this agent (the agent binary exits instead of falling back to
    /// the bundle cache).
    pub fn rejected(&self) -> bool {
        use tonic::Code;
        matches!(
            self.status.as_ref().map(tonic::Status::code),
            Some(Code::PermissionDenied | Code::InvalidArgument | Code::Unauthenticated)
        )
    }
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LinkError {}

/// The send side of one stream. Sends fail once the stream ended.
#[derive(Clone)]
pub(crate) struct StreamSender {
    tx: mpsc::Sender<AgentMessage>,
    alive: watch::Receiver<()>,
}

impl StreamSender {
    /// A sender over `tx`; dropping the returned watch sender ends it.
    pub(crate) fn new(tx: mpsc::Sender<AgentMessage>) -> (Self, watch::Sender<()>) {
        let (alive_tx, alive) = watch::channel(());
        (StreamSender { tx, alive }, alive_tx)
    }

    pub(crate) async fn send(&self, m: AgentMessage) -> Result<(), String> {
        let mut alive = self.alive.clone();
        if alive.has_changed().is_err() {
            return Err("stream ended".into());
        }
        tokio::select! {
            biased;
            r = self.tx.send(m) => r.map_err(|_| "stream ended".to_string()),
            _ = alive.changed() => Err("stream ended".into()),
        }
    }
}

fn ack(command_id: String, ok: bool, error: String) -> AgentMessage {
    AgentMessage {
        kind: Some(Out::Ack(CommandAck {
            command_id,
            ok,
            error,
            payload: Vec::new(),
        })),
    }
}

/// The ack of an install: empty `error` on success, else the code's contract string.
fn install_ack(command_id: String, res: Result<(), AckCode>) -> AgentMessage {
    ack(
        command_id,
        res.is_ok(),
        res.err()
            .map(|c| c.as_str().to_string())
            .unwrap_or_default(),
    )
}

pub(crate) async fn send_bundle_ack(
    send: &StreamSender,
    command_id: &str,
    res: &Result<(), String>,
) {
    let error = res.as_ref().err().cloned().unwrap_or_default();
    let _ = send
        .send(ack(command_id.to_string(), res.is_ok(), error))
        .await;
}

/// The WAF agent's side of the control-plane link.
pub struct ControlLink {
    control_config: Mutex<ControlConfig>,
    hooks: Hooks,
    /// Generation of the configuration in force, sent in Hello.
    pub(crate) last_gen: Mutex<i64>,
    /// (`bundle_source`, `bundle_generation`) for the heartbeat.
    pub(crate) bundle_state: Mutex<(String, i64)>,
    /// Set only while a stream is up.
    active: Mutex<Option<StreamSender>>,
    telemetry: Telemetry,
    malware_lock: tokio::sync::Mutex<()>,
    /// The latest certificate status of each app that the stream has not taken yet.
    statuses: Mutex<BTreeMap<String, CertificateStatus>>,
    /// Wakes the status task; one pending wake-up is enough, as it drains `statuses`.
    status_wake: mpsc::Sender<()>,
}

impl ControlLink {
    /// Arms the link and starts the decision drainer. Call inside a Tokio runtime, before
    /// the proxy emits decisions.
    pub fn new(cfg: ControlConfig, hooks: Hooks) -> Arc<Self> {
        let (status_wake, status_wake_rx) = mpsc::channel(1);
        let link = Arc::new(ControlLink {
            control_config: Mutex::new(cfg),
            hooks,
            last_gen: Mutex::new(0),
            bundle_state: Mutex::new((String::new(), 0)),
            active: Mutex::new(None),
            telemetry: Telemetry::new(),
            malware_lock: tokio::sync::Mutex::const_new(()),
            statuses: Mutex::new(BTreeMap::new()),
            status_wake,
        });
        (link.hooks.on_dial)(&link.config().server_address);
        if let Some(rx) = link.telemetry.rx.lock().unwrap().take() {
            tokio::spawn(flush_decision_queue(Arc::downgrade(&link), rx));
        }
        tokio::spawn(send_certificate_statuses(
            Arc::downgrade(&link),
            status_wake_rx,
        ));
        link
    }

    pub(crate) fn config(&self) -> ControlConfig {
        self.control_config.lock().unwrap().clone()
    }

    pub(crate) fn sink(&self) -> &Arc<dyn BundleSink> {
        &self.hooks.bundles
    }

    /// The host key in force (a `KeyRotation` replaces it). Pass this value to an upgraded
    /// child's environment (as `WAFIO_HOST_KEY`) so the child inherits it.
    pub fn host_key(&self) -> String {
        self.control_config.lock().unwrap().host_key.clone()
    }

    /// Whether the stream is up (`wafio_waf_control_plane_connected`).
    pub fn connected(&self) -> bool {
        self.active.lock().unwrap().is_some()
    }

    /// The telemetry counters (`wafio_waf_telemetry_*`).
    pub fn telemetry_stats(&self) -> TelemetryStats {
        self.telemetry.stats()
    }

    /// Redact, then queue for the stream without blocking.
    pub fn queue_decision_event(&self, mut ev: DecisionEvent) {
        (self.hooks.redact)(&mut ev);
        ev.match_value = None;
        self.telemetry.emit(ev);
    }

    /// Hands a certificate status to the stream without blocking, from any thread. A newer status
    /// of the same app replaces one that has not gone out yet, and a status reported while no
    /// stream is up is dropped. When to report, and how often, is for the caller to decide.
    pub fn report_certificate_status(&self, status: CertificateStatus) {
        self.statuses
            .lock()
            .unwrap()
            .insert(status.app_id.clone(), status);
        // A full channel means a wake-up is already waiting.
        let _ = self.status_wake.try_send(());
    }

    /// One dial + Hello + Welcome within 12 s, so bad credentials fail the start instead of
    /// looping.
    pub async fn exchange_hello(&self) -> Result<(), LinkError> {
        let cfg = self.config();
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, probe_stream(&cfg)).await {
            Ok(r) => r,
            Err(_) => Err(LinkError::status(
                None,
                tonic::Status::deadline_exceeded("context deadline exceeded"),
            )),
        }
    }

    /// Apply the cached bundle, then keep the stream up with backoff. Abort the handle to
    /// stop.
    pub fn start(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let link = self.clone();
        tokio::spawn(async move {
            let l = link.clone();
            let _ = tokio::task::spawn_blocking(move || l.install_cached_bundle()).await;
            link.run_stream_loop().await;
        })
    }

    async fn run_stream_loop(self: Arc<Self>) {
        let mut backoff = ReconnectBackoff::default();
        loop {
            let started = Instant::now();
            let res = self.connect_and_serve().await;
            let wait = backoff.delay(started.elapsed());
            if let Err(e) = res {
                info!(
                    "[agent-grpc] stream ended: {e} (reconnect in ~{})",
                    whole_seconds_text(wait.as_nanos() as i128)
                );
            }
            tokio::time::sleep(jitter(wait)).await;
        }
    }

    async fn connect_and_serve(self: &Arc<Self>) -> Result<(), LinkError> {
        let cfg = self.config();
        (self.hooks.on_dial)(&cfg.server_address);
        let client = connect(&cfg).await?;
        let (tx, rx) = mpsc::channel(STREAM_SEND_BUFFER);
        let (send, alive) = StreamSender::new(tx);
        let retry = Arc::new(BundleRetry::new(WAF_BUNDLE_RETRY_MIN, WAF_BUNDLE_RETRY_MAX));

        let known_gen = *self.last_gen.lock().unwrap();
        send.send(hello(&cfg, known_gen))
            .await
            .map_err(|e| LinkError::other(format!("send hello: {e}")))?;

        // Publish the send side for the decision drainer; withdrawn when this returns.
        *self.active.lock().unwrap() = Some(send.clone());
        struct Unpublish<'a>(&'a ControlLink);
        impl Drop for Unpublish<'_> {
            fn drop(&mut self) {
                *self.0.active.lock().unwrap() = None;
            }
        }
        let _unpublish = Unpublish(self);
        info!(
            "[agent-grpc] connected to {} as {:?}",
            cfg.server_address, cfg.agent_name
        );

        // Everything this stream starts ends with it.
        let mut tasks = JoinSet::new();
        tasks.spawn(self.clone().heartbeat_loop(send.clone()));

        let mut inbound = client
            .clone()
            .stream(ReceiverStream::new(rx))
            .await
            .map_err(|s| LinkError::status(None, s))?
            .into_inner();
        loop {
            while tasks.try_join_next().is_some() {}
            let msg = match inbound.message().await {
                Ok(Some(m)) => m,
                Ok(None) => return Ok(()),
                Err(s) => return Err(LinkError::status(None, s)),
            };
            match msg.kind {
                Some(In::Welcome(w)) => {
                    info!("{}", welcome_log_line(&w));
                    tasks.spawn(self.clone().on_welcome(client.clone(), send.clone()));
                }
                Some(In::Bundle(bu)) => {
                    retry
                        .handle(bu, self.bundle_attempt(), send.clone(), &mut tasks)
                        .await
                }
                Some(In::KeyRotation(kr)) => {
                    info!(
                        "[agent-grpc] key rotation received command_id={}",
                        kr.command_id
                    );
                    if !kr.new_host_key.is_empty() {
                        self.control_config.lock().unwrap().host_key = kr.new_host_key;
                    }
                    let _ = send.send(ack(kr.command_id, true, String::new())).await;
                    // Close our side so the queued ack is flushed before the reconnect.
                    *self.active.lock().unwrap() = None;
                    tasks.shutdown().await;
                    drop((send, alive));
                    let _ = tokio::time::timeout(Duration::from_secs(2), async {
                        while let Ok(Some(_)) = inbound.message().await {}
                    })
                    .await;
                    // Reconnect so the next Hello carries the new credentials.
                    return Err(LinkError::other("key rotation applied — reconnecting"));
                }
                Some(In::Ping(_)) => {
                    let _ = send.send(heartbeat_message(self.heartbeat(None))).await;
                }
                Some(In::FetchSecurityData(fsd)) => {
                    tasks.spawn(self.clone().serve_security_data_request(
                        client.clone(),
                        fsd,
                        send.clone(),
                    ));
                }
                Some(In::CertificateInstall(ci)) => self.handle_install(ci, &send).await,
                None => {}
            }
        }
    }

    /// Runs the install and acks it before the next message is read, so an install and the
    /// bundles around it are handled, and acked, in the order the stream delivered them.
    async fn handle_install(&self, install: CertificateInstall, send: &StreamSender) {
        // The ids only: the message itself is never formatted.
        let (command_id, app_id, certificate_id) = (
            install.command_id.clone(),
            install.app_id.clone(),
            install.certificate_id.clone(),
        );
        let res = run_install(self.hooks.certificates.clone(), install).await;
        match res {
            Ok(()) => info!(
                "[agent-grpc] certificate installed app_id={app_id:?} certificate_id={certificate_id:?}"
            ),
            Err(code) => info!(
                "[agent-grpc] certificate refused app_id={app_id:?} certificate_id={certificate_id:?}: {}",
                code.as_str()
            ),
        }
        let _ = send.send(install_ack(command_id, res)).await;
    }

    /// Host info on connect, then every 30 s.
    async fn heartbeat_loop(self: Arc<Self>, send: StreamSender) {
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() + HEARTBEAT_INTERVAL,
            HEARTBEAT_INTERVAL,
        );
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let stats = self.hooks.stats.clone();
            let info = tokio::task::spawn_blocking(move || stats.host_info_json())
                .await
                .unwrap_or_default();
            let _ = send
                .send(heartbeat_message(self.heartbeat(Some(info))))
                .await;
            tick.tick().await;
        }
    }

    /// Decision totals plus inspection-health counters. `host_info_json` is `None` for Ping
    /// replies.
    pub fn heartbeat(&self, host_info_json: Option<Vec<u8>>) -> Heartbeat {
        let c = self.hooks.stats.counters();
        let t = self.telemetry.stats();
        let mut hb = Heartbeat {
            unix_time: Timestamp::from_system(SystemTime::now()).unix,
            decisions_total: t.decisions,
            blocks_total: t.blocks,
            host_info_json: host_info_json.unwrap_or_default(),
            analyze_panics_total: Some(c.analyze_panics_total),
            engine_panics_total: Some(c.engine_panics_total),
            partial_coverage_total: Some(c.partial_coverage_total),
            parse_budget_exhausted_total: Some(c.parse_budget_exhausted_total),
            regex_rules_dropped_total: Some(c.regex_rules_dropped_total),
            script_incomplete_total: Some(c.script_incomplete_total),
            script_errors_total: Some(c.script_errors_total),
            script_rules_rejected_total: Some(c.script_rules_rejected_total),
            script_runs_in_flight: Some(c.script_runs_in_flight),
            agent_panics_total: Some(c.agent_panics_total),
            analyze_latency_samples: Some(c.analyze_latency_samples),
            ..Default::default()
        };
        if c.analyze_latency_samples > 0 {
            hb.analyze_latency_p50_us = Some(c.analyze_latency_p50_us);
            hb.analyze_latency_p95_us = Some(c.analyze_latency_p95_us);
            hb.analyze_latency_p99_us = Some(c.analyze_latency_p99_us);
        }
        let (source, generation) = self.bundle_status();
        if !source.is_empty() {
            hb.bundle_source = Some(source);
            hb.bundle_generation = Some(generation);
        }
        hb
    }

    fn bundle_attempt(self: &Arc<Self>) -> Attempt {
        let link = self.clone();
        Arc::new(move |bu: &BundleUpdate| link.apply_bundle_update(bu))
    }

    /// Decodes and applies a bundle update, and on success records the generation, the
    /// provenance and the cache. Returns whether a later attempt could succeed.
    pub(crate) fn apply_bundle_update(&self, bu: &BundleUpdate) -> (bool, Result<(), String>) {
        let probe = match BundleProbe::parse(&bu.bundle_json) {
            Ok(p) => p,
            Err(e) => {
                // The sink's full decode reports the first error of the whole document; the probe
                // reads four fields only.
                let e = self.sink().check(&bu.bundle_json).err().unwrap_or(e);
                info!("[agent-grpc] decode bundle: {e}");
                return (false, Err(e));
            }
        };
        // The control plane's generation wins over the embedded one.
        let generation = if bu.generation != 0 {
            bu.generation
        } else {
            probe.generation
        };
        match self.hand_bundle_to_sink(&bu.bundle_json, generation, &probe) {
            Ok(()) => {}
            Err(BundleError::Decode(e)) => {
                info!("[agent-grpc] decode bundle: {e}");
                return (false, Err(e));
            }
            Err(BundleError::Apply(e)) => return (!probe.management_only, Err(e)),
        }
        if !probe.management_only {
            *self.last_gen.lock().unwrap() = generation;
            self.set_bundle_status(BUNDLE_SOURCE_LIVE, generation);
            self.save_applied_bundle(&bu.bundle_json, generation);
        }
        (false, Ok(()))
    }

    /// The observer, then the "applied" log line for configuration bundles.
    pub(crate) fn hand_bundle_to_sink(
        &self,
        json: &[u8],
        generation: i64,
        probe: &BundleProbe,
    ) -> Result<(), BundleError> {
        self.hooks.bundles.apply(json, generation)?;
        if !probe.management_only {
            info!(
                "[waf-bundle] applied generation {generation} — {} apps",
                probe.apps
            );
        }
        Ok(())
    }

    fn security_data_dir(&self) -> String {
        let dir = self
            .control_config
            .lock()
            .unwrap()
            .security_data_dir
            .clone();
        if dir.is_empty() {
            DEFAULT_SECURITY_DATA_DIR.to_string()
        } else {
            dir
        }
    }

    /// After Welcome: sync the malware corpus, then report installed security data.
    async fn on_welcome(self: Arc<Self>, client: AgentControlClient<Channel>, send: StreamSender) {
        let dir = self.security_data_dir();
        let sec = self.hooks.security_data.clone();
        if let Err(e) =
            pull_malware_database(&self.malware_lock, client, Path::new(&dir), sec).await
        {
            info!("[security-data] malware sync: {e}");
        }
        self.send_security_data_status(&send).await;
    }

    /// Download the requested components, report, ack.
    async fn serve_security_data_request(
        self: Arc<Self>,
        client: AgentControlClient<Channel>,
        fsd: FetchSecurityData,
        send: StreamSender,
    ) {
        let dir = self.security_data_dir();
        let mut only: Vec<String> = fsd
            .components
            .trim()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        let mut fetch_only = only.clone();
        let mut errs = Vec::new();
        if fsd.malware_from_control_plane {
            let mut malware = only.is_empty();
            if only.is_empty() {
                only = PROFILE_AGENT_COMPONENTS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect();
            }
            fetch_only = Vec::new();
            for c in only {
                if c == "malware" {
                    malware = true;
                } else {
                    fetch_only.push(c);
                }
            }
            if malware {
                let sec = self.hooks.security_data.clone();
                if let Err(e) =
                    pull_malware_database(&self.malware_lock, client, Path::new(&dir), sec).await
                {
                    errs.push(format!("malware: {e}"));
                }
            }
        }
        // Empty `only` means every component: never fetch the provider by accident.
        if !fsd.malware_from_control_plane || !fetch_only.is_empty() {
            let sec = self.hooks.security_data.clone();
            let (d, force) = (dir.clone(), fsd.force);
            let results = tokio::task::spawn_blocking(move || {
                sec.download_components(Path::new(&d), &fetch_only, force)
            })
            .await
            .unwrap_or_default();
            for r in results {
                if let Some(e) = r.error {
                    errs.push(format!("{}: {e}", r.component));
                }
            }
        }
        self.send_security_data_status(&send).await;
        let err = errs.join("; ");
        let _ = send.send(ack(fsd.command_id, err.is_empty(), err)).await;
    }

    /// Sends a `CommandAck{command_id:"secdata:status"}` whose `error` field carries the JSON
    /// status map.
    async fn send_security_data_status(&self, send: &StreamSender) {
        let dir = self.security_data_dir();
        let paths = self.control_config.lock().unwrap().component_paths.clone();
        let Ok(payload) =
            tokio::task::spawn_blocking(move || security_data_status_json(&dir, &paths)).await
        else {
            return;
        };
        let _ = send.send(ack("secdata:status".into(), true, payload)).await;
    }
}

/// The log line for a Welcome. `agent_id` is the id the dashboard and the API show for this agent;
/// nothing else in the agent reads it.
fn welcome_log_line(w: &wafio_proto::v1::Welcome) -> String {
    format!(
        "[agent-grpc] welcome: agent_id={} heartbeat={}s",
        w.agent_id, w.heartbeat_seconds
    )
}

fn hello(cfg: &ControlConfig, bundle_generation: i64) -> AgentMessage {
    AgentMessage {
        kind: Some(Out::Hello(Hello {
            agent_name: cfg.agent_name.clone(),
            agent_version: cfg.version.clone(),
            hostname: cfg.hostname.clone(),
            bundle_generation,
            host_key: cfg.host_key.clone(),
            agent_kind: "waf".into(),
            features: cfg.features.clone(),
        })),
    }
}

fn heartbeat_message(hb: Heartbeat) -> AgentMessage {
    AgentMessage {
        kind: Some(Out::Heartbeat(hb)),
    }
}

/// The name of a server message kind as the log prints it ("<nil>" for none).
fn kind_name(k: &Option<In>) -> &'static str {
    match k {
        None => "<nil>",
        Some(In::Welcome(_)) => "*agentv1.ServerMessage_Welcome",
        Some(In::Bundle(_)) => "*agentv1.ServerMessage_Bundle",
        Some(In::KeyRotation(_)) => "*agentv1.ServerMessage_KeyRotation",
        Some(In::Ping(_)) => "*agentv1.ServerMessage_Ping",
        Some(In::FetchSecurityData(_)) => "*agentv1.ServerMessage_FetchSecurityData",
        Some(In::CertificateInstall(_)) => "*agentv1.ServerMessage_CertificateInstall",
    }
}

/// Dial, Hello (no generation), wait for Welcome.
async fn probe_stream(cfg: &ControlConfig) -> Result<(), LinkError> {
    let mut client = connect(cfg).await?;
    let (tx, rx) = mpsc::channel(1);
    tx.send(hello(cfg, 0))
        .await
        .map_err(|_| LinkError::other("send hello: stream ended"))?;
    let mut inbound = client
        .stream(ReceiverStream::new(rx))
        .await
        .map_err(|s| LinkError::status(None, s))?
        .into_inner();
    let msg = match inbound.message().await {
        Ok(Some(m)) => m,
        Ok(None) => return Err(LinkError::other("EOF")),
        Err(s) => return Err(LinkError::status(None, s)),
    };
    if !matches!(msg.kind, Some(In::Welcome(_))) {
        return Err(LinkError::other(format!(
            "expected Welcome, got {}",
            kind_name(&msg.kind)
        )));
    }
    drop(tx); // CloseSend
    Ok(())
}

/// The largest message the control plane may send, a bundle included. It is tonic's default made
/// explicit, and the control plane keeps a bundle under it (`engine.MaxAgentBundleBytes`): a larger
/// message ends the stream with `OutOfRange`, the agent reconnects, receives the same bundle and
/// fails again, so it never gets a new configuration.
const MAX_SERVER_MESSAGE_BYTES: usize = 4 << 20;

/// Dial the control plane: mTLS (TLS 1.2+, CA pinned, client certificate), HTTP/2
/// keepalive 30 s / 10 s while a stream is open.
async fn connect(cfg: &ControlConfig) -> Result<AgentControlClient<Channel>, LinkError> {
    if !pem_has_certificate(&cfg.ca_pem) {
        return Err(LinkError::other("append CA: invalid PEM"));
    }
    let authority = if cfg.server_address.starts_with(':') {
        format!("localhost{}", cfg.server_address) // an empty host means localhost
    } else {
        cfg.server_address.clone()
    };
    let server_name = if cfg.server_name.is_empty() {
        split_host(&authority)
    } else {
        cfg.server_name.clone()
    };
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&cfg.ca_pem))
        .identity(Identity::from_pem(&cfg.cert_pem, &cfg.key_pem))
        .domain_name(server_name);
    // The proxy is chosen for `https://host:port` (port 443 when the target names none);
    // HTTP_PROXY is never read for the channel.
    let (thost, tport) = proxy_env::split_url_host(&authority);
    let tport = if tport.is_empty() { "443" } else { tport };
    let proxy = proxy_env::global()
        .proxy_for("https", thost, tport)
        .map_err(LinkError::other)?;
    let origin = format!("https://{authority}");
    let mut endpoint = Endpoint::from_shared(origin.clone())
        .map_err(|e| LinkError::other(format!("dial {}: {}", cfg.server_address, chain(&e))))?;
    if let Some(p) = proxy {
        // tonic dials TCP itself: open the CONNECT tunnel first and point the endpoint at the
        // loopback relay that serves it; the TLS name and the `:authority` stay the target's.
        let target = proxy_env::format_host_port(thost, tport);
        let port = proxy_env::open_grpc_relay(&p, &target, "wafio-waf-agent")
            .await
            .map_err(|e| {
                LinkError::status(
                    Some("open stream"),
                    tonic::Status::unavailable(format!(
                        "connection error: transport: Error while dialing: {e}"
                    )),
                )
            })?;
        endpoint = Endpoint::from_shared(format!("https://127.0.0.1:{port}"))
            .map_err(|e| LinkError::other(format!("dial {}: {}", cfg.server_address, chain(&e))))?
            .origin(
                origin
                    .parse()
                    .map_err(|e| LinkError::other(format!("dial {}: {e}", cfg.server_address)))?,
            );
    }
    let endpoint = endpoint
        .tls_config(tls)
        .map_err(|e| LinkError::other(format!("load client keypair: {}", chain(&e))))?
        .connect_timeout(CONNECT_TIMEOUT)
        .http2_keep_alive_interval(GRPC_CLIENT_KEEPALIVE_TIME)
        .keep_alive_timeout(GRPC_CLIENT_KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(false);
    let channel = endpoint.connect().await.map_err(|e| {
        LinkError::status(
            Some("open stream"),
            tonic::Status::unavailable(format!("connection error: {}", chain(&e))),
        )
    })?;
    Ok(AgentControlClient::new(channel).max_decoding_message_size(MAX_SERVER_MESSAGE_BYTES))
}

/// The host of `host:port`, or the whole authority when it has no port.
fn split_host(authority: &str) -> String {
    if let Some(rest) = authority.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return rest[..end].to_string();
    }
    match authority.rsplit_once(':') {
        Some((h, _)) if !h.contains(':') => h.to_string(),
        _ => authority.to_string(),
    }
}

/// Whether the PEM holds at least one CERTIFICATE block with a DER body. (The DER itself is
/// checked by rustls at connect.)
fn pem_has_certificate(pem: &[u8]) -> bool {
    use base64::Engine;
    let text = String::from_utf8_lossy(pem);
    let mut rest = text.as_ref();
    while let Some(i) = rest.find("-----BEGIN CERTIFICATE-----") {
        rest = &rest[i + 27..];
        let Some(j) = rest.find("-----END CERTIFICATE-----") else {
            return false;
        };
        let body: String = rest[..j].chars().filter(|c| !c.is_whitespace()).collect();
        if base64::engine::general_purpose::STANDARD
            .decode(body)
            .is_ok_and(|der| der.first() == Some(&0x30))
        {
            return true;
        }
        rest = &rest[j..];
    }
    false
}

fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(c) = src {
        s.push_str(": ");
        s.push_str(&c.to_string());
        src = c.source();
    }
    s
}

/// The single consumer of the decision queue: sends over the live stream, drops while
/// there is none.
async fn flush_decision_queue(
    link: Weak<ControlLink>,
    mut rx: mpsc::Receiver<wafio_proto::v1::WafDecisionEvent>,
) {
    while let Some(out) = rx.recv().await {
        let Some(link) = link.upgrade() else { return };
        let Some(send) = link.active.lock().unwrap().clone() else {
            continue;
        };
        let uri = out.uri.clone();
        // Not routine: a failed send ends the stream; log it so the reconnect has a cause.
        match send
            .send(AgentMessage {
                kind: Some(Out::Decision(out)),
            })
            .await
        {
            Ok(()) => {
                link.telemetry
                    .sent
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                link.telemetry
                    .send_fail
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                info!("[agent-grpc] dropping decision for {uri:?}: {e}");
            }
        }
    }
}

/// The single consumer of the certificate statuses: takes the pending ones one app at a time
/// and waits for room in the stream, so a status that is replaced meanwhile goes out once, in
/// its latest form. With no stream up the pending ones are dropped: the next live bundle makes
/// the agent report again.
async fn send_certificate_statuses(link: Weak<ControlLink>, mut wake: mpsc::Receiver<()>) {
    while wake.recv().await.is_some() {
        loop {
            let Some(l) = link.upgrade() else { return };
            let Some((app_id, status)) = l.statuses.lock().unwrap().pop_first() else {
                break;
            };
            let Some(send) = l.active.lock().unwrap().clone() else {
                l.statuses.lock().unwrap().clear();
                break;
            };
            drop(l);
            let msg = AgentMessage {
                kind: Some(Out::CertificateStatus(status)),
            };
            if let Err(e) = send.send(msg).await {
                info!("[agent-grpc] dropping certificate status of app {app_id:?}: {e}");
            }
        }
    }
}

/// One apply of a bundle: (retryable, result).
pub(crate) type Attempt = Arc<dyn Fn(&BundleUpdate) -> (bool, Result<(), String>) + Send + Sync>;

/// Re-applies the newest failed configuration bundle with backoff until
/// it applies (then acks it ok under its command id), a newer bundle arrives, the attempts
/// run out, or the stream ends (the retry runs in the stream's task set). Applies are
/// serialised through `seq`, so a retry never lands after a newer bundle.
pub(crate) struct BundleRetry {
    seq: tokio::sync::Mutex<u64>,
    min_wait: Duration,
    max_wait: Duration,
}

impl BundleRetry {
    pub(crate) fn new(min_wait: Duration, max_wait: Duration) -> Self {
        BundleRetry {
            seq: tokio::sync::Mutex::new(0),
            min_wait,
            max_wait,
        }
    }

    /// Apply `bu` now (the receive loop waits) and schedule retries on failure.
    pub(crate) async fn handle(
        self: &Arc<Self>,
        bu: BundleUpdate,
        attempt: Attempt,
        send: StreamSender,
        tasks: &mut JoinSet<()>,
    ) {
        if bu.bundle_json.is_empty() {
            return;
        }
        let management = is_management_only(&bu.bundle_json);
        let bu = Arc::new(bu);
        let mut seq = self.seq.lock().await;
        if !management {
            *seq += 1; // supersedes any pending retry
        }
        let my_seq = *seq;
        let (retryable, res) = run_attempt(&attempt, &bu).await;
        drop(seq);
        send_bundle_ack(&send, &bu.command_id, &res).await;
        let Err(e) = res else { return };
        if !retryable || management {
            return;
        }
        info!(
            "[agent-grpc] WAF bundle generation {} not applied: {e} (retrying)",
            bu.generation
        );
        tasks.spawn(self.clone().run_retries(bu, attempt, send, my_seq));
    }

    async fn run_retries(
        self: Arc<Self>,
        bu: Arc<BundleUpdate>,
        attempt: Attempt,
        send: StreamSender,
        my_seq: u64,
    ) {
        let mut wait = self.min_wait;
        let mut n = 1;
        loop {
            tokio::time::sleep(wait).await;
            let seq = self.seq.lock().await;
            if *seq != my_seq {
                return; // a newer bundle arrived
            }
            let (retryable, res) = run_attempt(&attempt, &bu).await;
            drop(seq);
            match res {
                Ok(()) => {
                    info!(
                        "[agent-grpc] WAF bundle generation {} applied on retry",
                        bu.generation
                    );
                    send_bundle_ack(&send, &bu.command_id, &Ok(())).await;
                    return;
                }
                Err(_) if !retryable => return,
                Err(e) if n >= WAF_BUNDLE_RETRY_ATTEMPTS => {
                    info!(
                        "[agent-grpc] WAF bundle generation {} still not applied after {n} retries: {e} (giving up until the next bundle or reconnect)",
                        bu.generation
                    );
                    return;
                }
                Err(_) => {}
            }
            wait = (wait * 2).min(self.max_wait);
            n += 1;
        }
    }
}

/// Runs the (blocking) apply off the async workers. A panicking sink is a retryable failure.
async fn run_attempt(attempt: &Attempt, bu: &Arc<BundleUpdate>) -> (bool, Result<(), String>) {
    let (a, b) = (attempt.clone(), bu.clone());
    tokio::task::spawn_blocking(move || a(&b))
        .await
        .unwrap_or_else(|_| (true, Err("bundle apply panicked".into())))
}

#[derive(serde::Serialize)]
struct ComponentInfo {
    exists: bool,
    size_bytes: i64,
    /// RFC 3339 or empty.
    modified_at: String,
    /// Absolute path on the agent host.
    path: String,
}

/// The `secdata:status` payload: per component whether its file exists, its size (a
/// directory sums its files), mtime and absolute path. Configured paths replace the default
/// layout under `dir`.
pub(crate) fn security_data_status_json(
    dir: &str,
    component_paths: &BTreeMap<String, String>,
) -> String {
    let join = |rel: &str| normalize_path(&format!("{dir}/{rel}"));
    let mut checks: BTreeMap<String, String> = [
        ("malware", "malware/malware_hashes.txt"),
        ("firehol-level1", "firehol/firehol_level1.netset"),
        ("firehol-level2", "firehol/firehol_level2.netset"),
        ("ja4", "ja4/ja4.txt"),
        ("ja3", "ja3/ja3.txt"),
        ("ua", "user-agents/bot.txt"),
        ("geoip-country", "geoip/country.mmdb"),
        ("geoip-city", "geoip/city.mmdb"),
        ("geoip-asn", "geoip/asn.mmdb"),
    ]
    .into_iter()
    .map(|(c, rel)| (c.to_string(), join(rel)))
    .collect();
    for (comp, path) in component_paths {
        if !path.is_empty() {
            checks.insert(comp.clone(), path.clone());
        }
    }
    let status: BTreeMap<String, ComponentInfo> = checks
        .into_iter()
        .map(|(comp, path)| {
            let abs = absolute_path(&path);
            let mut info = ComponentInfo {
                exists: false,
                size_bytes: 0,
                modified_at: String::new(),
                path: if abs.is_empty() { path.clone() } else { abs },
            };
            if let Ok(md) = std::fs::metadata(&path) {
                info.exists = true;
                info.size_bytes = if md.is_dir() {
                    walk_size(Path::new(&path))
                } else {
                    md.len() as i64
                };
                if let Ok(t) = md.modified() {
                    info.modified_at = Timestamp::from_system(t).format_rfc3339();
                }
            }
            (comp, info)
        })
        .collect();
    serde_json::to_string(&status).unwrap_or_default()
}

/// Sums the sizes of everything that is not a directory (symlinks not followed, errors
/// skipped).
fn walk_size(p: &Path) -> i64 {
    let Ok(md) = std::fs::symlink_metadata(p) else {
        return 0;
    };
    if !md.is_dir() {
        return md.len() as i64;
    }
    let Ok(entries) = std::fs::read_dir(p) else {
        return 0;
    };
    entries.flatten().map(|e| walk_size(&e.path())).sum()
}

/// The absolute path: cwd-joined and cleaned; "" when the cwd is unknown.
fn absolute_path(p: &str) -> String {
    if p.starts_with('/') {
        return normalize_path(p);
    }
    match std::env::current_dir() {
        Ok(cwd) => normalize_path(&format!("{}/{p}", cwd.to_string_lossy())),
        Err(_) => String::new(),
    }
}

/// Lexically cleans a Unix path (`.` and `..` elements and repeated slashes removed).
pub(crate) fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let rooted = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|p| *p != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            p => out.push(p),
        }
    }
    let joined = out.join("/");
    if rooted {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".into()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn sender() -> (
        StreamSender,
        watch::Sender<()>,
        mpsc::Receiver<AgentMessage>,
    ) {
        let (tx, rx) = mpsc::channel(64);
        let (s, alive) = StreamSender::new(tx);
        (s, alive, rx)
    }

    fn acks(rx: &mut mpsc::Receiver<AgentMessage>) -> Vec<CommandAck> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            if let Some(Out::Ack(a)) = m.kind {
                out.push(a);
            }
        }
        out
    }

    fn bu(id: &str, generation: i64, json: &str) -> BundleUpdate {
        BundleUpdate {
            command_id: id.into(),
            generation,
            bundle_json: json.as_bytes().to_vec(),
        }
    }

    // A failed configuration bundle is retried and acked ok once it applies.
    #[tokio::test]
    async fn bundle_retry_applies_failed_bundle_later() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let attempt: Attempt = Arc::new(move |_| {
            if c.fetch_add(1, Ordering::SeqCst) < 2 {
                (true, Err("WAF bundle observer is not ready".into()))
            } else {
                (false, Ok(()))
            }
        });
        let r = Arc::new(BundleRetry::new(
            Duration::from_millis(1),
            Duration::from_millis(2),
        ));
        let (s, _alive, mut rx) = sender();
        let mut tasks = JoinSet::new();
        r.handle(bu("init-1", 5, r#"{"apps":[]}"#), attempt, s, &mut tasks)
            .await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .unwrap();
        let got = acks(&mut rx);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(!got[0].ok && got[0].error == "WAF bundle observer is not ready");
        assert!(got[1].ok && got[1].command_id == "init-1");
    }

    // A newer bundle supersedes the retry of an older one; a retry ends with the stream.
    #[tokio::test]
    async fn bundle_retry_superseded_and_stream_bound() {
        let applied = Arc::new(Mutex::new(Vec::new()));
        let a = applied.clone();
        let attempt: Attempt = Arc::new(move |b: &BundleUpdate| {
            if b.command_id == "old" {
                a.lock().unwrap().push("old-failed".to_string());
                return (true, Err("bind failed".into()));
            }
            a.lock().unwrap().push(b.command_id.clone());
            (false, Ok(()))
        });
        let r = Arc::new(BundleRetry::new(
            Duration::from_millis(5),
            Duration::from_millis(5),
        ));
        let (s, _alive, _rx) = sender();
        let mut tasks = JoinSet::new();
        r.handle(bu("old", 1, "{}"), attempt.clone(), s.clone(), &mut tasks)
            .await;
        r.handle(bu("new", 2, "{}"), attempt, s.clone(), &mut tasks)
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*applied.lock().unwrap(), vec!["old-failed", "new"]);

        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let failing: Attempt = Arc::new(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            (true, Err("still failing".into()))
        });
        let r2 = Arc::new(BundleRetry::new(
            Duration::from_millis(5),
            Duration::from_millis(5),
        ));
        let mut tasks2 = JoinSet::new();
        r2.handle(bu("x", 3, "{}"), failing, s, &mut tasks2).await;
        drop(tasks2); // stream ended
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // Management-only commands (unblock) are never retried.
    #[tokio::test]
    async fn bundle_retry_skips_management_commands() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let attempt: Attempt = Arc::new(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            (true, Err("unsupported unblock command".into()))
        });
        let r = Arc::new(BundleRetry::new(
            Duration::from_millis(1),
            Duration::from_millis(1),
        ));
        let (s, _alive, _rx) = sender();
        let mut tasks = JoinSet::new();
        r.handle(
            bu("u", 0, r#"{"management_only":true}"#),
            attempt,
            s,
            &mut tasks,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn retry_gives_up_after_ten_attempts() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let attempt: Attempt = Arc::new(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            (true, Err("port taken".into()))
        });
        let r = Arc::new(BundleRetry::new(
            Duration::from_millis(1),
            Duration::from_millis(1),
        ));
        let (s, _alive, _rx) = sender();
        let mut tasks = JoinSet::new();
        r.handle(bu("g", 9, "{}"), attempt, s, &mut tasks).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1 + WAF_BUNDLE_RETRY_ATTEMPTS);
    }

    #[tokio::test]
    async fn sender_fails_after_stream_end() {
        let (s, alive, _rx) = sender();
        assert!(s.send(AgentMessage::default()).await.is_ok());
        drop(alive);
        assert!(s.send(AgentMessage::default()).await.is_err());
    }

    #[test]
    fn the_welcome_line_names_the_dashboard_agent_id() {
        let w = wafio_proto::v1::Welcome {
            agent_id: "7c1f6a52-0d5e-4a38-9b7e-2f4e9a1d0c11".into(),
            server_time_unix: 1,
            heartbeat_seconds: 30,
        };
        assert_eq!(
            welcome_log_line(&w),
            "[agent-grpc] welcome: agent_id=7c1f6a52-0d5e-4a38-9b7e-2f4e9a1d0c11 heartbeat=30s"
        );
    }

    #[test]
    fn security_data_report_includes_malware() {
        let dir = std::env::temp_dir().join(format!("wafio-secdata-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("malware")).unwrap();
        std::fs::write(dir.join("malware/malware_hashes.txt"), b"test").unwrap();
        let d = dir.to_string_lossy().to_string();
        let mut paths = BTreeMap::new();
        paths.insert("ua".to_string(), format!("{d}/custom/../ua.txt"));
        paths.insert("ja3".to_string(), String::new());
        let v: serde_json::Value =
            serde_json::from_str(&security_data_status_json(&d, &paths)).unwrap();
        assert_eq!(v["malware"]["exists"], true);
        assert_eq!(v["malware"]["size_bytes"], 4);
        assert!(
            v.get("crs").is_none(),
            "the agent no longer reports the retired component"
        );
        assert_eq!(v["ua"]["exists"], false);
        assert_eq!(v["ua"]["path"], format!("{d}/ua.txt"));
        assert_eq!(v["ja3"]["path"], format!("{d}/ja3/ja3.txt"));
        assert_eq!(v.as_object().unwrap().len(), 9);
        let m = v["malware"]["modified_at"].as_str().unwrap();
        assert!(Timestamp::parse_rfc3339(m).is_ok(), "{m}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn path_and_server_name_helpers() {
        assert_eq!(normalize_path("/a/b/../c/./d/"), "/a/c/d");
        assert_eq!(normalize_path("/../a"), "/a");
        assert_eq!(normalize_path("../a/.."), "..");
        assert_eq!(normalize_path(""), ".");
        assert_eq!(default_server_name("cp.example.com:9090"), "cp.example.com");
        assert_eq!(default_server_name("[::1]:9090"), "[::1]");
        assert_eq!(default_server_name("cp"), "cp");
        assert_eq!(split_host("[::1]:9090"), "::1");
        assert_eq!(split_host("10.0.0.1:9090"), "10.0.0.1");
        assert_eq!(split_host("cp"), "cp");
        assert!(!pem_has_certificate(b"garbage"));
        assert!(!pem_has_certificate(
            b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"
        ));
    }

    struct FailSink;
    impl BundleSink for FailSink {
        fn apply(&self, _: &[u8], _: i64) -> Result<(), BundleError> {
            Err(BundleError::Apply("connection closed".into()))
        }
    }
    struct ZeroStats;
    impl AgentStats for ZeroStats {
        fn counters(&self) -> HeartbeatCounters {
            HeartbeatCounters::default()
        }
        fn host_info_json(&self) -> Vec<u8> {
            Vec::new()
        }
    }
    struct NoCerts;
    impl CertificateSink for NoCerts {
        fn install(&self, _: &mut CertificateInstall) -> Result<(), AckCode> {
            Err(AckCode::NotInBundle)
        }
    }
    struct NoSec;
    impl SecurityData for NoSec {
        fn replace_malware_snapshot(&self, _: &Path, _: Vec<u8>) -> Result<(), String> {
            Ok(())
        }
        fn download_components(&self, _: &Path, _: &[String], _: bool) -> Vec<crate::FetchResult> {
            Vec::new()
        }
    }

    // A refused bundle is acked negative and moves neither the generation nor the
    // provenance; a heartbeat without samples carries samples=0 and no percentiles.
    #[tokio::test]
    async fn negative_ack_keeps_generation_and_no_percentiles_without_samples() {
        let cfg = ControlConfig {
            server_address: "127.0.0.1:1".into(),
            server_name: String::new(),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
            ca_pem: Vec::new(),
            agent_name: "a".into(),
            hostname: String::new(),
            version: "wafio-waf-agent/test".into(),
            host_key: String::new(),
            features: Vec::new(),
            state_dir: String::new(),
            bundle_cache_max_age: Duration::ZERO,
            security_data_dir: String::new(),
            component_paths: BTreeMap::new(),
        };
        let hooks = Hooks {
            bundles: Arc::new(FailSink),
            certificates: Arc::new(NoCerts),
            stats: Arc::new(ZeroStats),
            security_data: Arc::new(NoSec),
            redact: |_| {},
            on_dial: |_| {},
        };
        let l = ControlLink::new(cfg, hooks);
        *l.last_gen.lock().unwrap() = 5;
        let (retryable, res) = l.apply_bundle_update(&bu("failed", 999, "{}"));
        assert!(retryable && res.is_err());
        assert_eq!(*l.last_gen.lock().unwrap(), 5);
        assert_eq!(l.bundle_status(), (String::new(), 0));
        let (retryable, res) = l.apply_bundle_update(&bu("bad", 1, "{"));
        assert!(
            !retryable && res.is_err(),
            "a decode error is never retried"
        );
        let (retryable, _) = l.apply_bundle_update(&bu("u", 0, r#"{"management_only":true}"#));
        assert!(!retryable, "a management command is never retried");

        let hb = l.heartbeat(None);
        assert_eq!(hb.analyze_latency_samples, Some(0));
        assert!(hb.analyze_latency_p50_us.is_none() && hb.analyze_latency_p95_us.is_none());
        assert!(hb.analyze_latency_p99_us.is_none());
        assert_eq!(hb.decisions_total, 0);
    }

    fn bare_link() -> Arc<ControlLink> {
        ControlLink::new(
            ControlConfig {
                server_address: "127.0.0.1:1".into(),
                server_name: String::new(),
                cert_pem: Vec::new(),
                key_pem: Vec::new(),
                ca_pem: Vec::new(),
                agent_name: "a".into(),
                hostname: String::new(),
                version: "wafio-waf-agent/test".into(),
                host_key: String::new(),
                features: Vec::new(),
                state_dir: String::new(),
                bundle_cache_max_age: Duration::ZERO,
                security_data_dir: String::new(),
                component_paths: BTreeMap::new(),
            },
            Hooks {
                bundles: Arc::new(FailSink),
                certificates: Arc::new(NoCerts),
                stats: Arc::new(ZeroStats),
                security_data: Arc::new(NoSec),
                redact: |_| {},
                on_dial: |_| {},
            },
        )
    }

    fn status(app: &str, state: &str) -> CertificateStatus {
        CertificateStatus {
            app_id: app.into(),
            source: "acme".into(),
            state: state.into(),
            ..Default::default()
        }
    }

    /// The (app, state) of a status message.
    fn status_of(m: AgentMessage) -> (String, String) {
        match m.kind {
            Some(Out::CertificateStatus(s)) => (s.app_id, s.state),
            other => panic!("expected a certificate status, got {other:?}"),
        }
    }

    async fn until(what: &str, mut done: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    // With no stream up a status is dropped, not kept for the next one; any thread may report.
    #[tokio::test]
    async fn statuses_reported_with_no_stream_up_are_dropped() {
        let l = bare_link();
        l.report_certificate_status(status("a", "pending"));
        let from_thread = l.clone();
        std::thread::spawn(move || {
            from_thread.report_certificate_status(status("b", "pending"));
            from_thread.report_certificate_status(status("c", "failed"));
        })
        .join()
        .unwrap();
        until("the status task to drop them", || {
            l.statuses.lock().unwrap().is_empty()
        })
        .await;

        // A stream that comes up afterwards gets only what is reported after it.
        let (tx, mut rx) = mpsc::channel(8);
        let (s, _alive) = StreamSender::new(tx);
        *l.active.lock().unwrap() = Some(s);
        l.report_certificate_status(status("d", "active"));
        let first = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status_of(first), ("d".into(), "active".into()));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(rx.try_recv().is_err(), "nothing else was kept");
    }

    // While the stream is full a newer state of an app replaces the older one that waits, and
    // nothing is lost when room comes: each app goes out once, with its latest state.
    #[tokio::test]
    async fn a_status_task_keeps_the_latest_state_per_app_and_waits_for_room() {
        let l = bare_link();
        let (tx, mut rx) = mpsc::channel(1);
        let (s, _alive) = StreamSender::new(tx);
        *l.active.lock().unwrap() = Some(s.clone());
        // One message fills the stream, so the task blocks on the first status it sends.
        s.send(AgentMessage::default()).await.unwrap();
        l.report_certificate_status(status("z", "pending"));
        until("the task to take the first status", || {
            l.statuses.lock().unwrap().is_empty()
        })
        .await;

        l.report_certificate_status(status("a", "pending"));
        l.report_certificate_status(status("a", "active"));
        l.report_certificate_status(status("b", "failed"));
        l.report_certificate_status(status("a", "failed"));

        let next = async |rx: &mut mpsc::Receiver<AgentMessage>| {
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap()
        };
        assert!(
            next(&mut rx).await.kind.is_none(),
            "the message that filled it"
        );
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(status_of(next(&mut rx).await));
        }
        assert_eq!(
            got,
            vec![
                ("z".to_string(), "pending".to_string()),
                ("a".to_string(), "failed".to_string()),
                ("b".to_string(), "failed".to_string()),
            ]
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(rx.try_recv().is_err(), "the replaced states never went out");
    }

    // A status that cannot be sent because the stream ended is dropped, and the task goes on.
    #[tokio::test]
    async fn a_status_for_a_stream_that_ended_is_dropped() {
        let l = bare_link();
        let (tx, rx) = mpsc::channel(1);
        let (s, alive) = StreamSender::new(tx);
        *l.active.lock().unwrap() = Some(s);
        drop(alive);
        l.report_certificate_status(status("a", "pending"));
        until("the status to be taken", || {
            l.statuses.lock().unwrap().is_empty()
        })
        .await;
        drop(rx);

        let (tx, mut rx) = mpsc::channel(8);
        let (s, _alive) = StreamSender::new(tx);
        *l.active.lock().unwrap() = Some(s);
        l.report_certificate_status(status("b", "active"));
        let m = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status_of(m), ("b".into(), "active".into()));
    }

    #[test]
    fn an_install_ack_carries_the_code_and_nothing_else() {
        let Some(Out::Ack(ok)) = install_ack("c1".into(), Ok(())).kind else {
            panic!("not an ack")
        };
        assert_eq!(
            (
                ok.command_id.as_str(),
                ok.ok,
                ok.error.as_str(),
                ok.payload.len()
            ),
            ("c1", true, "", 0)
        );
        let Some(Out::Ack(no)) = install_ack("c2".into(), Err(AckCode::LeafMismatch)).kind else {
            panic!("not an ack")
        };
        assert_eq!(
            (
                no.command_id.as_str(),
                no.ok,
                no.error.as_str(),
                no.payload.len()
            ),
            ("c2", false, "leaf_mismatch", 0)
        );
    }
}
