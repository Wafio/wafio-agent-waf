//! The agent's run loop: control link, bundle sink, IP jail, IP reputation, good bots, store
//! cleaner, metrics listener, ready signalling, SIGUSR2 upgrade and SIGINT/SIGTERM shutdown.

use std::collections::HashMap;
use std::net::TcpListener as StdListener;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::signal::unix::{SignalKind, signal};
use tracing::info;
use wafio_agent_io::ip_jail::JailTracker;
use wafio_agent_pages::goodbot::{
    BOT_RANGE_SOURCES, GOOD_BOT_BODY_LIMIT, VerifiedBotChecker, parse_bot_ip_ranges,
};
use wafio_agent_pages::iprep::{
    AddressRange, FIREHOL_LEVEL1_LIST_URL, FIREHOL_LEVEL2_LIST_URL, IPREP_USER_AGENT,
    ReputationChecker, parse_netset_partial,
};
use wafio_control::{
    AckCode, AgentStats, CertificateInstall, CertificateSink, ControlConfig, ControlLink,
    HeartbeatCounters, Hooks,
};

use crate::agent::{Agent, Certificates, Sink};
use crate::executor::{Stores, startup_executor};
use crate::flags::{AgentArgs, OsEnv};
use crate::ready::{Ready, ReadyActions};
use crate::reload::{UpgradeState, spawn_successor};
use crate::tls::dir::KeyDir;
use crate::tls::pacer::{self, Statuses};

/// The control link, once created (the proxy's decision sink exists before it).
static LINK: OnceLock<Arc<ControlLink>> = OnceLock::new();

/// READY=1 after 20 s without any bundle (empty project).
const READY_FALLBACK: Duration = Duration::from_secs(20);
/// Store cleaner period.
const CLEANUP_EVERY: Duration = Duration::from_secs(120);
/// How often a process that is waiting for the key directory lock tries to take it.
const KEY_LOCK_POLL: Duration = Duration::from_millis(200);
/// FireHOL refresh period.
const IPREP_REFRESH: Duration = Duration::from_secs(24 * 3600);
/// The `Hello.features` entry of an agent that serves the maintenance page.
const FEATURE_MAINTENANCE_MODE: &str = "maintenance_mode";
/// The `Hello.features` entry of an agent that serves apps over HTTPS from its key directory: it
/// takes `CertificateInstall` and sends `CertificateStatus`.
pub const FEATURE_TLS_CERTIFICATES: &str = "tls_certificates";

struct Stats;

impl AgentStats for Stats {
    fn counters(&self) -> HeartbeatCounters {
        crate::metrics::heartbeat_counters()
    }
    fn host_info_json(&self) -> Vec<u8> {
        crate::hostinfo::heartbeat_host_info()
    }
}

/// A proxy decision handed to the control link (which redacts, then
/// queues without blocking). The JSON-only `mode` field is dropped.
fn emit_decision(ev: wafio_proxy::DecisionEvent) {
    let Some(link) = LINK.get() else { return };
    link.queue_decision_event(wafio_control::DecisionEvent {
        app_id: ev.app_id,
        host: ev.host,
        method: ev.method,
        uri: ev.uri,
        remote_address: ev.remote_addr,
        user_agent: ev.user_agent,
        content_type: ev.content_type,
        action: ev.action,
        score: ev.score,
        categories: ev.categories,
        cwe: ev.cwe,
        match_detail: ev.match_detail,
        analyze_method: ev.analyze_method,
        body_size: ev.body_size,
        latency_us: ev.latency_us,
        body_preview: ev.body_preview,
        event_time_unix: ev.event_time_unix,
        match_source: ev.match_source,
        match_source_exact: ev.match_source_exact,
        match_value: ev.match_value,
        request_headers: ev.request_headers,
        request_body: ev.request_body,
        query_params: ev.query_params,
        payload_type: ev.payload_type,
        coverage: ev.coverage,
        status: ev.status,
    });
}

/// Link hooks for tests (a sink that accepts every bundle).
#[doc(hidden)]
pub fn test_hooks() -> Hooks {
    struct AcceptAll;
    impl wafio_control::BundleSink for AcceptAll {
        fn apply(&self, _: &[u8], _: i64) -> Result<(), wafio_control::BundleError> {
            Ok(())
        }
    }
    struct NoCertificates;
    impl CertificateSink for NoCertificates {
        fn install(&self, _: &mut CertificateInstall) -> Result<(), AckCode> {
            Err(AckCode::NotInBundle)
        }
    }
    Hooks {
        bundles: Arc::new(AcceptAll),
        certificates: Arc::new(NoCertificates),
        stats: Arc::new(Stats),
        security_data: Arc::new(crate::security_data::AgentSecurityData),
        redact: crate::redact::mask_decision_event,
        on_dial,
    }
}

/// The link's `on_dial` hook: resolves the control-plane address for the jail in the background.
fn on_dial(server_addr: &str) {
    if let Ok(h) = tokio::runtime::Handle::try_current() {
        let addr = server_addr.to_string();
        h.spawn(
            async move { wafio_agent_io::ip_jail_guard::refresh_jail_control_plane(&addr).await },
        );
    }
}

/// Reads the netset file, or fetches it (GitHub, UA `wafio-iprep/1.0`, 60 s) without a file:
/// the ranges and the error, which are returned together (a line of 64 KiB or more
/// ends the parse with the ranges read so far; a failed open or request has none).
fn read_netset(path: &str, url: &str) -> (Vec<AddressRange>, Option<String>) {
    let data = if path.is_empty() {
        // Whatever body comes back is parsed, whatever the status.
        match crate::httpclient::get_blocking(
            url,
            IPREP_USER_AGENT,
            256 << 20,
            Duration::from_secs(60),
        ) {
            Ok(r) => r.body,
            Err(e) => return (Vec::new(), Some(e)),
        }
    } else {
        match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                return (
                    Vec::new(),
                    Some(crate::flags::path_error_text("open", path, &e)),
                );
            }
        }
    };
    parse_netset_partial(&data, None)
}

/// A first load where one list failed installs that list's partial ranges (`load_partial`).
fn load_iprep(c: &ReputationChecker, l1: &str, l2: &str) {
    let msg = c.load_partial(
        read_netset(l1, FIREHOL_LEVEL1_LIST_URL),
        read_netset(l2, FIREHOL_LEVEL2_LIST_URL),
        !l1.is_empty() || !l2.is_empty(),
    );
    info!("{msg}");
}

/// The good-bot sources. `WAFIO_TEST_GOODBOT_SOURCES=Name=url,Name=url`
/// replaces them (set but empty: none), so the binary's tests never call Google and Bing
/// (a test seam).
fn good_bot_sources() -> Vec<(String, String)> {
    match std::env::var("WAFIO_TEST_GOODBOT_SOURCES") {
        Ok(v) => v
            .split(',')
            .filter_map(|kv| kv.split_once('='))
            .map(|(n, u)| (n.trim().to_string(), u.trim().to_string()))
            .collect(),
        Err(_) => BOT_RANGE_SOURCES
            .iter()
            .map(|s| (s.name.to_string(), s.url.to_string()))
            .collect(),
    }
}

/// Refreshes from every known source, merged; a failed source keeps nothing of
/// its own but the others still publish.
fn refresh_good_bots(c: &VerifiedBotChecker) {
    let mut per_source = Vec::new();
    for (name, url) in good_bot_sources() {
        // Timeout 30 s, body cut at 2 MiB.
        let fetched = crate::httpclient::get_blocking(
            &url,
            &wafio_agent_io::user_agent(),
            usize::MAX,
            Duration::from_secs(30),
        )
        .and_then(|r| {
            let body = &r.body[..r.body.len().min(GOOD_BOT_BODY_LIMIT)];
            parse_bot_ip_ranges(body)
        });
        match fetched {
            Ok(r) => {
                info!("[goodbot] loaded {name}: {} IPv4 ranges", r.len());
                per_source.push(r);
            }
            Err(e) => info!("[goodbot] fetch {name}: {e} (keeping previous data)"),
        }
    }
    c.refresh(per_source);
}

/// The whole siteverify exchange (connect, send, read): the visitor waits on it and a verify
/// request holds a connection until it ends.
const SITEVERIFY_TIMEOUT: Duration = Duration::from_secs(5);
/// What is read of the provider's answer; a real one is a few hundred bytes. A longer answer is
/// refused, so a hostile provider cannot make the agent buffer an arbitrary body.
const MAX_SITEVERIFY_BODY: usize = 64 << 10;

/// Turnstile / hCaptcha siteverify: a timeout, an oversized answer or a transport error is
/// "no answer", which counts as not verified.
struct Captcha {
    timeout: Duration,
}

impl wafio_agent_pages::challenge_handler::CaptchaVerifier for Captcha {
    fn submit_form(&self, url: &str, body: &[u8]) -> Option<Vec<u8>> {
        crate::httpclient::post_form_blocking(
            url,
            &wafio_agent_io::user_agent(),
            body,
            MAX_SITEVERIFY_BODY,
            self.timeout,
        )
        .ok()
        .map(|r| r.body)
    }
}

/// A challenge limit from its environment variable: the value in force and, for an invalid one,
/// the log line printed before it falls back to the default.
fn challenge_limit_setting(
    name: &str,
    raw: &str,
    parse: fn(&str) -> (i64, bool),
) -> (i64, Option<String>) {
    let (n, invalid) = parse(raw);
    let note = invalid.then(|| {
        format!(
            "[wafio-waf-agent] ignoring invalid {name}={}; using {n}",
            String::from_utf8_lossy(&wafio_agent_pages::challenge::quote_literal(raw.as_bytes()))
        )
    });
    (n, note)
}

/// Reads a challenge limit from the environment, logs an invalid value and installs the result.
fn apply_challenge_limit(name: &str, parse: fn(&str) -> (i64, bool), set: fn(i64)) {
    let raw = std::env::var(name).unwrap_or_default();
    let (n, note) = challenge_limit_setting(name, &raw, parse);
    if let Some(line) = note {
        info!("{line}");
    }
    set(n);
}

/// Everything after flag validation and the engine environment export. Runs inside the Tokio runtime.
/// `keys` is the key directory, opened at start; without one the apps' `tls` objects are ignored.
pub async fn run_waf_agent(
    f: AgentArgs,
    metrics_addr: String,
    keys: Option<KeyDir>,
) -> Result<(), String> {
    // Successor side of an upgrade: take the predecessor's sockets before anything else
    // (it waits on the handover while this process does its first handshake).
    let mut inherited: HashMap<String, StdListener> =
        tokio::task::spawn_blocking(crate::reload::inherited_listeners)
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;

    let mut cfg = ControlConfig::load(
        &f.grpc_server,
        &f.server_name(),
        &f.client_cert,
        &f.client_key,
        &f.ca_cert,
        &f.agent_name,
        &f.host_key,
        crate::hostinfo::AGENT_VERSION,
    )
    .map_err(|e| format!("agent gRPC stream init: {e}"))?;
    // Hello.features: script rules run in this process, the agent answers for an app in maintenance
    // mode itself, and whether a semantic engine is installed.
    cfg.features = vec![
        crate::script_rules::FEATURE_SCRIPT_RULES.into(),
        FEATURE_MAINTENANCE_MODE.into(),
    ];
    // Only an agent that could use its key directory at start takes certificates: without one the
    // `tls` objects of its bundles are ignored, and the control plane must not send a key.
    if keys.is_some() {
        cfg.features.push(FEATURE_TLS_CERTIFICATES.into());
    }
    if !wafio_engine_api::engine().info().installed {
        cfg.features
            .push(crate::gaps::FEATURE_NO_SEMANTIC_ENGINE.into());
    }
    cfg.component_paths = f.component_paths();
    let data_dir = f.resolved_security_data_dir();
    if !data_dir.is_empty() {
        cfg.security_data_dir = data_dir;
    }
    cfg.state_dir = f.state_dir.clone();
    cfg.bundle_cache_max_age = f.bundle_cache_max_age();
    if f.state_dir.is_empty() {
        info!(
            "[wafio-waf-agent] no state directory (--state-dir / STATE_DIRECTORY): bundle cache disabled, a restart without the control plane serves no apps"
        );
    }

    crate::multipart_body::install_engine_hooks();
    // Challenge cookies and tokens of a project without `secret_key` are keyed by this agent's
    // secret, one cookie id may be presented from at most WAFIO_CHALLENGE_COOKIE_MAX_NETWORKS
    // networks, and one client may post at most WAFIO_CHALLENGE_VERIFY_MAX_PER_MIN verify
    // requests a minute.
    wafio_agent_pages::challenge::set_instance_secret(crate::challenge_key::load_or_create(
        &f.state_dir,
    ));
    apply_challenge_limit(
        "WAFIO_CHALLENGE_COOKIE_MAX_NETWORKS",
        wafio_agent_pages::challenge_replay::parse_cookie_network_limit,
        wafio_agent_pages::challenge_replay::set_cookie_network_limit,
    );
    apply_challenge_limit(
        "WAFIO_CHALLENGE_VERIFY_MAX_PER_MIN",
        wafio_agent_pages::challenge_verify_limit::parse_verify_limit,
        wafio_agent_pages::challenge_verify_limit::set_verify_limit,
    );
    wafio_agent_io::ip_jail::set_agent_panic_hook(wafio_proxy::metrics::count_agent_panic);

    let ready = Arc::new(Ready::new(ReadyActions {
        pid_file: f.pid_file.clone(),
        predecessor: crate::reload::predecessor_ready_socket(),
        notify_socket: std::env::var("NOTIFY_SOCKET").unwrap_or_default(),
    }));

    // agent.Run: IP jail, startup executor, inline proxy (IP reputation, good bots, observer).
    let env = OsEnv;
    let mut jail: Option<Arc<JailTracker>> = None;
    if f.jail_threshold > 0 {
        let token_file = f.jail_token_file(&env);
        match wafio_agent_io::ip_jail::jail_enforcer_from_config(&token_file, &f.jail_url) {
            Some(enforce) => {
                let window = if f.jail_window_sec > 0 {
                    Duration::from_secs(f.jail_window_sec as u64)
                } else {
                    Duration::from_secs(60)
                };
                let duration = if f.jail_duration_sec > 0 {
                    Duration::from_secs(f.jail_duration_sec as u64)
                } else {
                    Duration::from_secs(3600)
                };
                jail = Some(Arc::new(JailTracker::new(
                    f.jail_threshold,
                    window,
                    duration,
                    65536,
                    Some(enforce),
                )));
                match wafio_agent_io::ip_jail::check_host_agent_token(false, &token_file) {
                    Err(e) => info!(
                        "WARNING: IP jail inactive: host-agent local API token unreadable ({e}); jail pushes are skipped until it is readable — set WAFIO_LOCAL_API_TOKEN_GROUP to this agent's group in /etc/wafio/host-agent.env and restart the host agent"
                    ),
                    Ok(()) => info!(
                        "IP jail active: {} blocks/{} → XDP jail {}",
                        f.jail_threshold,
                        whole_seconds_text(window),
                        whole_seconds_text(duration)
                    ),
                }
            }
            None => {
                info!("IP jail disabled: no in-process eBPF manager and no --jail-url configured")
            }
        }
    }
    let stores = Stores::new();
    let base = startup_executor(&stores, &f.geo_country_db, jail)?;
    let iprep = Arc::new(ReputationChecker::new());
    let good_bots = Arc::new(VerifiedBotChecker::new());

    // The metrics socket travels with the route sockets on an upgrade.
    let metrics_inherited = if metrics_addr.is_empty() {
        None
    } else {
        inherited.remove(&metrics_addr)
    };
    let mut opts = wafio_proxy::ProxyOptions::new(Arc::new(emit_decision));
    opts.ip_rep = Some(iprep.clone());
    opts.good_bots = Some(good_bots.clone());
    opts.captcha = Some(Arc::new(Captcha {
        timeout: SITEVERIFY_TIMEOUT,
    }));
    opts.inherited = inherited;
    let proxy = Arc::new(wafio_proxy::Proxy::new(opts));
    let (statuses, offers) = Statuses::channel();
    let mut agent = Agent::new(
        base,
        stores,
        proxy.clone(),
        good_bots.clone(),
        ready.clone(),
    )
    .with_statuses(statuses);
    let ordering = keys.is_some();
    if let Some(dir) = keys {
        agent = agent.with_key_dir(dir);
    }
    let agent = Arc::new(agent);
    if ordering {
        let directory = f.resolved_acme_directory()?;
        info!("[acme] certificates are ordered from {directory}");
        agent.start_acme(
            Arc::new(crate::tls::acme::instant::InstantAcme::new(
                crate::tls::acme::http::Http::new(),
            )),
            directory,
        );
    }

    let link = ControlLink::new(
        cfg,
        Hooks {
            bundles: Arc::new(Sink(agent.clone())),
            certificates: Arc::new(Certificates(agent.clone())),
            stats: Arc::new(Stats),
            security_data: Arc::new(crate::security_data::AgentSecurityData),
            redact: crate::redact::mask_decision_event,
            on_dial,
        },
    );
    let _ = LINK.set(link.clone());
    let status_link = link.clone();
    tokio::spawn(pacer::run(offers, move |status| {
        status_link.report_certificate_status(status)
    }));

    // Probe the control plane: credential errors exit; an outage starts from the cache.
    if let Err(e) = link.exchange_hello().await {
        if e.rejected() {
            let msg = e
                .grpc_status()
                .map(|s| s.message().to_string())
                .unwrap_or_default();
            return Err(format!("control-plane rejected agent: {msg}"));
        }
        let usable = {
            let l = link.clone();
            tokio::task::spawn_blocking(move || l.is_cached_bundle_usable())
                .await
                .unwrap_or(false)
        };
        if !usable {
            return Err(format!("initial handshake failed: {e}"));
        }
        info!(
            "[wafio-waf-agent] initial handshake failed ({e}); starting from cached bundle and reconnecting in the background"
        );
    }

    // OpenMetrics listener: loopback only, inherited across an upgrade.
    let mut metrics_sock: Option<StdListener> = None;
    let _metrics_server = if metrics_addr.is_empty() {
        None
    } else {
        let reg = wafio_agent_io::metrics::Registry::new();
        crate::metrics::register_agent_metrics(&reg, link.clone());
        let ln = match metrics_inherited {
            Some(s) => {
                s.set_nonblocking(true).map_err(|e| e.to_string())?;
                tokio::net::TcpListener::from_std(s).map_err(|e| e.to_string())?
            }
            None => wafio_agent_io::metrics::listen(&metrics_addr)
                .await
                .map_err(|e| e.to_string())?,
        };
        metrics_sock = Some(dup_listener(&ln)?);
        info!(
            "[wafio-waf-agent] metrics listening on {}/metrics",
            ln.local_addr()
                .map(|a| a.to_string())
                .unwrap_or(metrics_addr.clone())
        );
        Some(wafio_agent_io::metrics::serve(ln, Arc::new(reg)))
    };

    let mut usr2 = signal(SignalKind::user_defined2()).map_err(|e| e.to_string())?;
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;

    // Fallback: no bundle within 20 s (e.g. empty project) → ready anyway.
    let r = ready.clone();
    tokio::spawn(async move {
        tokio::time::sleep(READY_FALLBACK).await;
        if !r.signaled() {
            info!("[tableflip] ready timeout — no bundle yet, signaling ready");
            r.signal();
        }
    });
    let a = agent.clone();
    tokio::spawn(async move {
        let mut t =
            tokio::time::interval_at(tokio::time::Instant::now() + CLEANUP_EVERY, CLEANUP_EVERY);
        loop {
            t.tick().await;
            let a = a.clone();
            let _ = tokio::task::spawn_blocking(move || {
                a.sweep_expired_stores();
                if let Err(e) = wafio_malware::reload_default_engine(&[]) {
                    info!("[content_scan] database reload failed; retained previous snapshot: {e}");
                }
            })
            .await;
        }
    });
    let gb = good_bots.clone();
    tokio::spawn(async move {
        loop {
            let g = gb.clone();
            let _ = tokio::task::spawn_blocking(move || refresh_good_bots(&g)).await;
            tokio::time::sleep(IPREP_REFRESH).await;
        }
    });
    let (l1, l2) = (f.iprep_level1_file.clone(), f.iprep_level2_file.clone());
    tokio::spawn(async move {
        loop {
            let (c, a, b) = (iprep.clone(), l1.clone(), l2.clone());
            let _ = tokio::task::spawn_blocking(move || load_iprep(&c, &a, &b)).await;
            tokio::time::sleep(IPREP_REFRESH).await;
        }
    });

    // A process that finds the key directory lock taken (the one it replaces holds it until it has
    // stopped accepting) takes it as soon as it is free.
    if agent.waits_for_keys() {
        info!(
            "[tls] another process holds the key directory lock: this one reads what that one wrote and writes nothing in it until that one lets go"
        );
        let a = agent.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(KEY_LOCK_POLL).await;
                let a = a.clone();
                if tokio::task::spawn_blocking(move || a.take_over_keys())
                    .await
                    .unwrap_or(false)
                {
                    return;
                }
            }
        });
    }

    let stream = link.start();
    let upgrade = UpgradeState::default();
    let handed_over = loop {
        tokio::select! {
            _ = usr2.recv() => {
                info!("[tableflip] upgrade requested (SIGUSR2) — spawning new process");
                if let Err(e) = upgrade.begin(ready.signaled()) {
                    info!("[tableflip] upgrade failed: {e}");
                    continue;
                }
                let mut fds = proxy.handover_fds();
                if let Some(s) = &metrics_sock {
                    fds.push((metrics_addr.clone(), s.as_raw_fd()));
                }
                let host_key = link.host_key();
                let mut env = if host_key.is_empty() { Vec::new() } else { vec![("WAFIO_HOST_KEY".to_string(), host_key)] };
                if crate::engine_lib::loaded().is_some() {
                    env.push((crate::engine_lib::ENV_REQUIRED.to_string(), "1".to_string()));
                }
                agent.pause_orders();
                match spawn_successor(fds, &crate::reload::run_dir(), crate::reload::HANDOVER_TIMEOUT, env).await {
                    Ok(pid) => {
                        upgrade.finish(true);
                        info!("[tableflip] upgraded: process {pid} took over; draining");
                        break true;
                    }
                    Err(e) => {
                        upgrade.finish(false);
                        agent.resume_orders();
                        info!("[tableflip] upgrade failed: {e}");
                    }
                }
            }
            _ = term.recv() => break false,
            _ = int.recv() => break false,
        }
    };
    if !handed_over {
        info!("[wafio-waf-agent] shutdown signal — stopping");
    }
    stream.abort();
    agent.close();
    // A successor writes in the key directory from the moment this process no longer accepts.
    proxy.stop_accepting(handed_over).await;
    let a = agent.clone();
    let _ = tokio::task::spawn_blocking(move || a.release_keys()).await;
    proxy.shutdown(handed_over).await;
    Ok(())
}

/// A second descriptor of a listening socket (handed to a successor on upgrade).
fn dup_listener(ln: &tokio::net::TcpListener) -> Result<StdListener, String> {
    ln.as_fd()
        .try_clone_to_owned()
        .map(StdListener::from)
        .map_err(|e| e.to_string())
}

/// Whole seconds as hours, minutes and seconds (log lines only).
fn whole_seconds_text(d: Duration) -> String {
    let s = d.as_secs();
    let (h, m, sec) = (s / 3600, s / 60 % 60, s % 60);
    if h > 0 {
        format!("{h}h{m}m{sec}s")
    } else if m > 0 {
        format!("{m}m{sec}s")
    } else {
        format!("{sec}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use wafio_agent_pages::challenge_handler::verify_captcha;
    use wafio_agent_pages::iprep::ReputationLevel;

    /// A first load where one list fails installs that list's partial ranges (parsing
    /// returns what it parsed with the error, the load stores it when nothing is cached), the
    /// other list loads whole; a file that cannot be opened has no ranges.
    #[test]
    fn first_iprep_load_installs_partial_ranges() {
        let dir = std::env::temp_dir().join(format!("wafio-iprep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (l1, l2) = (dir.join("l1.netset"), dir.join("l2.netset"));
        std::fs::write(&l1, "# block\n5.6.7.8\n").unwrap();
        // The partial ranges are unsorted and unmerged (they are returned as read), so only a list
        // that happens to be in order answers the binary search.
        let mut long = b"7.7.7.0/24\n9.9.9.9\n".to_vec();
        long.extend(std::iter::repeat_n(b'1', 70_000));
        long.extend_from_slice(b"\n8.8.8.8\n");
        std::fs::write(&l2, &long).unwrap();
        let (r, e) = read_netset(l2.to_str().unwrap(), "");
        assert_eq!(
            (r.len(), e.as_deref()),
            (2, Some("bufio.Scanner: token too long"))
        );
        let missing = dir.join("none.netset");
        let (r, e) = read_netset(missing.to_str().unwrap(), "");
        assert!(
            r.is_empty()
                && e.unwrap()
                    .ends_with("none.netset: no such file or directory")
        );

        let c = ReputationChecker::new();
        load_iprep(&c, l1.to_str().unwrap(), l2.to_str().unwrap());
        assert_eq!(c.check(b"5.6.7.8"), ReputationLevel::Block);
        assert_eq!(
            c.check(b"9.9.9.9"),
            ReputationLevel::Challenge,
            "partial level 2 ranges installed"
        );
        assert_eq!(c.check(b"7.7.7.9"), ReputationLevel::Challenge);
        assert_eq!(
            c.check(b"8.8.8.8"),
            ReputationLevel::Clean,
            "past the failing line"
        );
        // Level 1 failing on a later load keeps the cached level 1 list.
        std::fs::write(&l1, &long).unwrap();
        std::fs::write(&l2, "9.9.9.9\n").unwrap();
        load_iprep(&c, l1.to_str().unwrap(), l2.to_str().unwrap());
        assert_eq!(c.check(b"5.6.7.8"), ReputationLevel::Block);
        assert_eq!(
            c.check(b"7.7.7.9"),
            ReputationLevel::Clean,
            "level 2 reloaded whole"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A local siteverify provider: reads one request, sends `answer`, then closes the connection
    /// or, with `hold`, keeps it open until the returned sender is dropped.
    fn provider(answer: Vec<u8>, hold: bool) -> (String, mpsc::Receiver<String>, mpsc::Sender<()>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://127.0.0.1:{}/siteverify",
            l.local_addr().unwrap().port()
        );
        let (seen_tx, seen_rx) = mpsc::channel();
        let (hold_tx, hold_rx) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let _ = seen_tx.send(read_request(&mut s));
                let _ = s.write_all(&answer);
                if hold {
                    let _ = hold_rx.recv();
                }
            }
        });
        (url, seen_rx, hold_tx)
    }

    /// The request head and, by Content-Length, its body.
    fn read_request(s: &mut std::net::TcpStream) -> String {
        let (mut raw, mut buf) = (Vec::new(), [0u8; 4096]);
        loop {
            let n = s.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&raw);
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let want = head
                    .lines()
                    .find_map(|l| {
                        let l = l.to_ascii_lowercase();
                        l.strip_prefix("content-length:")?
                            .trim()
                            .parse::<usize>()
                            .ok()
                    })
                    .unwrap_or(0);
                if body.len() >= want {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&raw).into_owned()
    }

    fn json_answer(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn production() -> Captcha {
        Captcha {
            timeout: SITEVERIFY_TIMEOUT,
        }
    }

    fn verify(url: &str, captcha: &Captcha) -> bool {
        verify_captcha(url, b"tok", b"sec", b"203.0.113.7", captcha)
    }

    #[test]
    fn siteverify_reads_the_success_flag() {
        let (url, seen, _hold) = provider(json_answer(r#"{"success":true}"#), false);
        assert!(verify(&url, &production()), "success:true was not accepted");
        let req = seen.recv().unwrap();
        assert!(req.starts_with("POST /siteverify HTTP/1.1"), "{req}");
        assert!(
            req.ends_with("remoteip=203.0.113.7&response=tok&secret=sec"),
            "{req}"
        );
        for (body, what) in [
            (r#"{"success":false}"#, "success:false"),
            ("not json", "a body that is not JSON"),
        ] {
            let (url, _seen, _hold) = provider(json_answer(body), false);
            assert!(!verify(&url, &production()), "{what} was accepted");
        }
        // No token or no secret never reaches the network.
        let c = production();
        assert!(!verify_captcha("http://127.0.0.1:1/", b"", b"sec", b"", &c));
        assert!(!verify_captcha("http://127.0.0.1:1/", b"tok", b"", b"", &c));
    }

    /// A provider that never answers must not hold the visitor's request: the call ends at the
    /// timeout and counts as not verified.
    #[test]
    fn siteverify_slow_headers_time_out() {
        let (url, _seen, _hold) = provider(Vec::new(), true);
        let t = std::time::Instant::now();
        let slow = Captcha {
            timeout: Duration::from_millis(150),
        };
        assert!(
            !verify(&url, &slow),
            "a provider that never answered verified"
        );
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    }

    /// The timeout also covers a body that stalls after the headers.
    #[test]
    fn siteverify_slow_body_times_out() {
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"success\":true".to_vec();
        let (url, _seen, _hold) = provider(partial, true);
        let t = std::time::Instant::now();
        let slow = Captcha {
            timeout: Duration::from_millis(150),
        };
        assert!(!verify(&url, &slow), "a body that never finished verified");
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    }

    /// A success answer padded past the cap is refused, so the provider cannot make the agent
    /// buffer an arbitrary body; the same answer within the cap passes.
    #[test]
    fn siteverify_oversized_answer_is_refused() {
        let pad = "a".repeat(64 * 1024);
        let big = format!(r#"{{"success":true,"pad":"{pad}"}}"#);
        let (url, _seen, _hold) = provider(json_answer(&big), false);
        assert!(
            !verify(&url, &production()),
            "an answer over the cap was accepted"
        );
        let small = format!(r#"{{"success":true,"pad":"{}"}}"#, &pad[..1024]);
        let (url, _seen, _hold) = provider(json_answer(&small), false);
        assert!(
            verify(&url, &production()),
            "a small success answer was refused"
        );
    }

    #[test]
    fn siteverify_bounds() {
        assert_eq!(SITEVERIFY_TIMEOUT, Duration::from_secs(5));
        assert_eq!(MAX_SITEVERIFY_BODY, 64 * 1024);
    }

    #[test]
    fn challenge_limit_settings_log_text_for_invalid_values() {
        use wafio_agent_pages::challenge_replay::parse_cookie_network_limit;
        use wafio_agent_pages::challenge_verify_limit::parse_verify_limit;
        let name = "WAFIO_CHALLENGE_VERIFY_MAX_PER_MIN";
        for (raw, want) in [("", 120), ("0", 0), ("30", 30), (" 5 ", 5)] {
            assert_eq!(
                challenge_limit_setting(name, raw, parse_verify_limit),
                (want, None),
                "{raw:?}"
            );
        }
        assert_eq!(
            challenge_limit_setting(name, "x", parse_verify_limit),
            (
                120,
                Some(
                    r#"[wafio-waf-agent] ignoring invalid WAFIO_CHALLENGE_VERIFY_MAX_PER_MIN="x"; using 120"#
                        .to_string()
                )
            )
        );
        assert_eq!(
            challenge_limit_setting(
                "WAFIO_CHALLENGE_COOKIE_MAX_NETWORKS",
                "-1",
                parse_cookie_network_limit
            ),
            (
                8,
                Some(
                    r#"[wafio-waf-agent] ignoring invalid WAFIO_CHALLENGE_COOKIE_MAX_NETWORKS="-1"; using 8"#
                        .to_string()
                )
            )
        );
    }

    #[test]
    fn whole_seconds_text_formats_hours_minutes_seconds() {
        use std::time::Duration;
        assert_eq!(super::whole_seconds_text(Duration::from_secs(60)), "1m0s");
        assert_eq!(
            super::whole_seconds_text(Duration::from_secs(3600)),
            "1h0m0s"
        );
        assert_eq!(super::whole_seconds_text(Duration::from_secs(5)), "5s");
    }
}
