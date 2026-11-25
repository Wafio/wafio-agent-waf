//! Black-box test with the real binary: an in-test fake control plane (tonic, mTLS with the
//! control crate's fixture CA) checks what `wafio-waf-agent` sends — Hello (kind, version,
//! the features `script_rules`, `maintenance_mode`, `edge_redirects`, `edge_compression`, `edge_static_files`, `edge_cache`, `tls_certificates` and
//! `no_semantic_engine`), the first heartbeat with host info and counters, the edge status of an app after its bundle, the
//! answer to a cache purge, the malware sync
//! into the security-data dir given by `--security-data-dir`, the bundle ack, READY after the
//! live bundle, the bundle cache, a block decision with its credentials redacted, the refusal of a
//! certificate install. A bundle is acked before its cache write, so the last tests hold the write
//! back (`test-cache-delay`) and signal the agent while it is pending: it is finished before a
//! successor starts and before the process ends, and a crash leaves the earlier cache.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};
use wafio_proto::v1::agent_control_server::{AgentControl, AgentControlServer};
use wafio_proto::v1::agent_message::Kind as Out;
use wafio_proto::v1::server_message::Kind as In;
use wafio_proto::v1::*;

mod common;

const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../control/tests/fixtures");

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(FX).join(name)).unwrap()
}

struct Conn {
    inbound: Streaming<AgentMessage>,
    out: mpsc::Sender<Result<ServerMessage, Status>>,
}

impl Conn {
    async fn next(&mut self) -> AgentMessage {
        tokio::time::timeout(Duration::from_secs(30), self.inbound.message())
            .await
            .expect("agent message")
            .unwrap()
            .expect("stream open")
    }
}

struct Fake {
    conns: mpsc::UnboundedSender<Conn>,
    malware: Vec<u8>,
}

#[tonic::codegen::async_trait]
impl AgentControl for Fake {
    type StreamStream = ReceiverStream<Result<ServerMessage, Status>>;
    async fn stream(
        &self,
        req: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        let (tx, rx) = mpsc::channel(16);
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
        let sum: String = Sha256::digest(&self.malware)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let chunks = vec![
            Ok(MalwareDatabaseChunk {
                data: self.malware.clone(),
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

fn upstream() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                if s.read(&mut buf).unwrap_or(0) > 0 {
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                }
            });
        }
    });
    port
}

fn get(port: u16, target: &str, extra: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(s, "GET {target} HTTP/1.1\r\nHost: app.test\r\nUser-Agent: Mozilla/5.0\r\n{extra}Connection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// Kills a process when the test unwinds, so a failed assertion leaves no agent behind.
struct KillOnDrop(u32);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-KILL", &self.0.to_string()])
            .status();
    }
}

fn malware_snapshot() -> Vec<u8> {
    format!(
        "# Updated: 2026-01-01T00:00:00Z\n{} Test.Sig\n",
        "ab".repeat(32)
    )
    .into_bytes()
}

/// A scratch directory with a state directory and the file every data flag of the agent names.
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wafio-cp-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    std::fs::write(dir.join("data.txt"), "x\n").unwrap();
    dir
}

/// A fake control plane on a port of its own: its address, and the streams that connect to it.
async fn serve_fake(malware: Vec<u8>) -> (String, mpsc::UnboundedReceiver<Conn>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cp = listener.local_addr().unwrap().to_string();
    let (tx, conns) = mpsc::unbounded_channel();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(fx("server.crt"), fx("server.key")))
        .client_ca_root(Certificate::from_pem(fx("ca.crt")));
    tokio::spawn(
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(AgentControlServer::new(Fake { conns: tx, malware }))
            .serve_with_incoming(TcpIncoming::from(listener)),
    );
    (cp, conns)
}

/// The agent against the control plane at `cp`, with its state in `<dir>/state` and its log in
/// `<dir>/agent.log`; READY goes to `notify`.
fn agent_command(dir: &Path, cp: &str, notify: &Path) -> Command {
    let data = dir.join("data.txt");
    let d = data.to_str().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wafio-waf-agent-open"));
    cmd.args(["--grpc-server", cp, "--agent-name", "cf4"])
        .env("WAFIO_HOST_KEY", "wafh_test")
        // No good-bot sources: the test never calls Google and Bing.
        .env("WAFIO_TEST_GOODBOT_SOURCES", "")
        .args([
            "--client-cert",
            &format!("{FX}/client.crt"),
            "--client-key",
            &format!("{FX}/client.key"),
            "--ca-cert",
            &format!("{FX}/ca.crt"),
        ])
        .args([
            "--geo-country-db",
            d,
            "--geo-city-db",
            d,
            "--geo-asn-db",
            d,
            "--bot-ua-file",
            d,
            "--bot-ja4-file",
            d,
        ])
        .args([
            "--iprep-level1-file",
            d,
            "--iprep-level2-file",
            d,
            "--jail-threshold",
            "0",
        ])
        .args([
            "--security-data-dir",
            dir.to_str().unwrap(),
            "--state-dir",
            dir.join("state").to_str().unwrap(),
        ])
        .env("NOTIFY_SOCKET", notify)
        .env("RUNTIME_DIRECTORY", dir)
        // A key directory of its own: the fixed one may belong to an agent installed on this host.
        .env("WAFIO_TEST_TLS_DIR", dir.join("tls"))
        // The same for the response cache directory, which the unit makes for a real agent.
        .env("WAFIO_TEST_CACHE_DIR", cache_dir(dir))
        // A library installed on this host must not give the agent an engine: name one that does not exist.
        .env("WAFIO_ENGINE_LIB", dir.join("no-engine.so"))
        .stderr(Stdio::from(
            std::fs::File::create(dir.join("agent.log")).unwrap(),
        ));
    cmd
}

/// A cache directory of the agent's user and nobody else's, as the unit makes it.
fn cache_dir(dir: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let cache = dir.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
    cache
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_talks_to_the_control_plane() {
    let dir = scratch("talk");
    let malware = malware_snapshot();
    let (cp, mut conns) = serve_fake(malware.clone()).await;

    let notify_path = dir.join("notify.sock");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let (listen, up) = (common::free_port(), upstream());
    let mut child = agent_command(&dir, &cp, &notify_path).spawn().unwrap();
    let _stop_agent = KillOnDrop(child.id());

    // The start probe: Hello without a generation, then the stream is closed.
    let mut probe = tokio::time::timeout(Duration::from_secs(30), conns.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(Out::Hello(h)) = probe.next().await.kind else {
        panic!("probe: no Hello")
    };
    assert_eq!(
        (
            h.agent_kind.as_str(),
            h.agent_name.as_str(),
            h.host_key.as_str()
        ),
        ("waf", "cf4", "wafh_test")
    );
    assert_eq!(h.agent_version, "wafio-waf-agent/dev");
    assert_eq!(
        h.features,
        vec![
            "script_rules",
            "maintenance_mode",
            "edge_redirects",
            "edge_compression",
            "edge_static_files",
            "edge_cache",
            "tls_certificates",
            "no_semantic_engine"
        ],
        "the agent runs script rules, serves the maintenance page itself, applies the main host, the path prefix, compression, static files and the response cache, has a key directory it can use, and this binary has no engine"
    );

    // The stream: Hello, then the first heartbeat with host info and the agent's counters.
    let mut c = tokio::time::timeout(Duration::from_secs(30), conns.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(Out::Hello(h)) = c.next().await.kind else {
        panic!("stream: no Hello")
    };
    assert_eq!(h.bundle_generation, 0);
    let hb = loop {
        if let Some(Out::Heartbeat(hb)) = c.next().await.kind {
            break hb;
        }
    };
    let info: serde_json::Value = serde_json::from_slice(&hb.host_info_json).unwrap();
    assert_eq!(info["agent_kind"], "waf");
    assert_eq!(info["siem_delivery"]["delivered"], 0);
    assert_eq!(hb.analyze_panics_total, Some(0));
    assert_eq!(hb.analyze_latency_samples, Some(0));
    assert_eq!(
        hb.analyze_latency_p99_us, None,
        "no percentiles without samples"
    );

    // A live bundle: acked, cached, READY, the listener proxies.
    let site = dir.join("site");
    std::fs::create_dir_all(&site).unwrap();
    std::fs::write(site.join("static.txt"), "from the folder").unwrap();
    let root = serde_json::json!(site.to_str().unwrap());
    let bundle = format!(
        r#"{{"agent_id":"cf4","project_id":"p","generation":1,"apps":[{{"app_id":"web","listen_host":"127.0.0.1","listen_port":{listen},"upstream":"http://127.0.0.1:{up}","mode":"block","proxy_config":{{"strip_path_prefix":"/shop"}},"compression":{{"enabled":true,"min_bytes":2}},"static_files":{{"enabled":true,"root":{root},"missing":"app","max_age_s":60}},"cache":{{"enabled":true,"disk_bytes":33554432,"memory_bytes":0,"rules":[{{"prefix":"/shop/kept","action":"cache","ttl_s":60,"signed_in":false}}]}},"rules_json":{{"path_exceptions":[{{"path":"/shop/search","block":{{}}}}]}}}}]}}"#
    );
    let bu = BundleUpdate {
        command_id: "b1".into(),
        generation: 3,
        bundle_json: bundle.into_bytes(),
    };
    c.out
        .send(Ok(ServerMessage {
            kind: Some(In::Bundle(bu)),
        }))
        .await
        .unwrap();
    let mut edge = None;
    let ack = loop {
        match c.next().await.kind {
            Some(Out::Ack(a)) if a.command_id == "b1" => break a,
            Some(Out::EdgeStatus(s)) => edge = Some(s),
            _ => {}
        }
    };
    assert!(ack.ok, "bundle refused: {}", ack.error);
    // The edge parts the bundle turns on are reported for the app, with the generation of the bundle.
    let edge = match edge {
        Some(s) => s,
        None => loop {
            if let Some(Out::EdgeStatus(s)) = c.next().await.kind {
                break s;
            }
        },
    };
    assert_eq!((edge.app_id.as_str(), edge.generation), ("web", 3));
    let features: Vec<_> = edge
        .features
        .iter()
        .map(|f| (f.feature.as_str(), f.state.as_str(), f.code.as_str()))
        .collect();
    assert_eq!(
        features,
        [
            ("redirects", "applied", ""),
            ("compression", "applied", ""),
            ("static_files", "applied", ""),
            ("cache", "applied", "")
        ]
    );
    assert_eq!(edge.compression, Some(EdgeCompressionCounters::default()));
    assert_eq!(
        edge.cache,
        Some(EdgeCacheCounters::default()),
        "a cache that has not answered yet reports zeros"
    );
    assert!(edge.unix_time > 0);
    notify
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut buf = [0u8; 128];
    let n = notify.recv(&mut buf).expect("READY after the live bundle");
    assert_eq!(
        std::str::from_utf8(&buf[..n]).unwrap(),
        format!("READY=1\nMAINPID={}\n", child.id())
    );
    // The ack does not wait for the cache write.
    let cache = common::cached_bundle(&dir.join("state"), 3).await;
    assert!(cache.contains("\"generation\":3"), "{cache}");
    let ok = tokio::task::spawn_blocking(move || get(listen, "/shop/hello", ""))
        .await
        .unwrap();
    assert!(ok.starts_with("HTTP/1.1 200") && ok.ends_with("ok"), "{ok}");
    // A file of the app's folder is answered by the agent, under the path prefix, and a path that
    // is not in it goes on to the application.
    let file = tokio::task::spawn_blocking(move || get(listen, "/shop/static.txt", ""))
        .await
        .unwrap();
    assert!(
        file.starts_with("HTTP/1.1 200") && file.ends_with("from the folder"),
        "{file}"
    );
    assert!(file.contains("Cache-Control: max-age=60\r\n"), "{file}");

    // The cache: a path under a rule is kept after the first answer and sent again, and the
    // answers say so. Nothing is stored until the agent has cleaned its directory, a moment after
    // the bundle, so the second answer is waited for.
    let first = tokio::task::spawn_blocking(move || get(listen, "/shop/kept", ""))
        .await
        .unwrap();
    assert!(
        first.starts_with("HTTP/1.1 200") && first.contains("X-Cache: MISS\r\n"),
        "{first}"
    );
    let mut hit = String::new();
    for _ in 0..50 {
        hit = tokio::task::spawn_blocking(move || get(listen, "/shop/kept", ""))
            .await
            .unwrap();
        if hit.contains("X-Cache: HIT\r\n") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        hit.starts_with("HTTP/1.1 200") && hit.contains("X-Cache: HIT\r\n") && hit.ends_with("ok"),
        "{hit}"
    );

    // A blocked request (the path of the app is blocked by a rule; this agent has no engine): the decision reaches
    // the control plane with credentials redacted.
    let blocked = tokio::task::spawn_blocking(move || {
        get(
            listen,
            "/shop/search?q=anything",
            "Authorization: Bearer secret-token\r\n",
        )
    })
    .await
    .unwrap();
    assert!(blocked.starts_with("HTTP/1.1 403"), "{blocked}");
    let mut allowed = None;
    let ev = loop {
        if let Some(Out::Decision(ev)) = c.next().await.kind {
            if ev.action == "block" {
                break ev;
            }
            if ev.action == "allow" {
                allowed.get_or_insert(ev);
            }
        }
    };
    assert_eq!(ev.app_id, "web");
    // This agent has no engine, and the decision of the request that went through says so.
    let allowed = allowed.expect("the request that was forwarded is reported");
    assert_eq!(allowed.coverage, "engine_absent");
    assert!(
        !ev.request_headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("authorization")),
        "{:?}",
        ev.request_headers
    );
    assert!(!format!("{ev:?}").contains("secret-token"));

    // Welcome triggered the malware sync into <security-data dir>/malware.
    let installed = dir.join("malware/malware_hashes.txt");
    for _ in 0..100 {
        if installed.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(std::fs::read(&installed).unwrap(), malware);

    // An install for an app the bundle does not have is refused as not named by it, and the key
    // reaches neither the ack nor the log.
    c.out
        .send(Ok(ServerMessage {
            kind: Some(In::CertificateInstall(CertificateInstall {
                command_id: "ci1".into(),
                app_id: "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11".into(),
                certificate_id: "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77".into(),
                chain_pem: b"chain".to_vec(),
                key_pem: b"INSTALLKEYBYTES".to_vec(),
                leaf_sha256: "ab".repeat(32),
            })),
        }))
        .await
        .unwrap();
    let refused = loop {
        if let Some(Out::Ack(a)) = c.next().await.kind
            && a.command_id == "ci1"
        {
            break a;
        }
    };
    assert_eq!(
        (refused.ok, refused.error.as_str()),
        (false, "not_in_bundle")
    );

    // A purge of the app removes its copies: it is acked once they are gone, and the next request
    // goes to the application. An app that is not in the bundle is not named by it, and an
    // address that is not one is invalid.
    for (id, app, scope, url, code) in [
        ("cp1", "web", "app", "", ""),
        (
            "cp2",
            "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11",
            "app",
            "",
            "not_in_bundle",
        ),
        ("cp3", "web", "url", "kept", "invalid"),
    ] {
        c.out
            .send(Ok(ServerMessage {
                kind: Some(In::CachePurge(CachePurge {
                    command_id: id.into(),
                    app_id: app.into(),
                    scope: scope.into(),
                    url: url.into(),
                })),
            }))
            .await
            .unwrap();
        let ack = loop {
            if let Some(Out::Ack(a)) = c.next().await.kind
                && a.command_id == id
            {
                break a;
            }
        };
        assert_eq!(
            (ack.ok, ack.error.as_str()),
            (code.is_empty(), code),
            "{id}"
        );
    }
    let after = tokio::task::spawn_blocking(move || get(listen, "/shop/kept", ""))
        .await
        .unwrap();
    assert!(
        after.contains("X-Cache: MISS\r\n"),
        "the copy is gone: {after}"
    );
    // A purge of one address, as the dashboard sends it, takes the copy that comes back.
    let mut again = String::new();
    for _ in 0..50 {
        again = tokio::task::spawn_blocking(move || get(listen, "/shop/kept", ""))
            .await
            .unwrap();
        if again.contains("X-Cache: HIT\r\n") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(again.contains("X-Cache: HIT\r\n"), "{again}");
    c.out
        .send(Ok(ServerMessage {
            kind: Some(In::CachePurge(CachePurge {
                command_id: "cp4".into(),
                app_id: "web".into(),
                scope: "url".into(),
                url: "/shop/kept".into(),
            })),
        }))
        .await
        .unwrap();
    let ack = loop {
        if let Some(Out::Ack(a)) = c.next().await.kind
            && a.command_id == "cp4"
        {
            break a;
        }
    };
    assert!(ack.ok, "{}", ack.error);
    let after = tokio::task::spawn_blocking(move || get(listen, "/shop/kept", ""))
        .await
        .unwrap();
    assert!(after.contains("X-Cache: MISS\r\n"), "{after}");

    // KeyRotation: acked, the agent reconnects with the new key...
    let kr = KeyRotation {
        command_id: "k1".into(),
        new_host_key: "wafh_rotated".into(),
    };
    c.out
        .send(Ok(ServerMessage {
            kind: Some(In::KeyRotation(kr)),
        }))
        .await
        .unwrap();
    loop {
        if let Some(Out::Ack(a)) = c.next().await.kind
            && a.command_id == "k1"
        {
            assert!(a.ok, "{}", a.error);
            break;
        }
    }
    drop(c);
    let mut c2 = tokio::time::timeout(Duration::from_secs(30), conns.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(Out::Hello(h)) = c2.next().await.kind else {
        panic!("reconnect: no Hello")
    };
    assert_eq!(
        (h.host_key.as_str(), h.bundle_generation),
        ("wafh_rotated", 3)
    );

    // ...and an upgraded process (SIGUSR2) starts with it (the host key is exported as
    // WAFIO_HOST_KEY).
    let first = child.id();
    assert!(
        Command::new("kill")
            .args(["-USR2", &first.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let mut probe = tokio::time::timeout(Duration::from_secs(60), conns.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(Out::Hello(h)) = probe.next().await.kind else {
        panic!("successor: no Hello")
    };
    assert_eq!(
        h.host_key, "wafh_rotated",
        "successor authenticates with the rotated key"
    );
    let n = notify.recv(&mut buf).expect("successor READY");
    let msg = std::str::from_utf8(&buf[..n]).unwrap().to_string();
    let second: u32 = msg
        .strip_prefix("READY=1\nMAINPID=")
        .and_then(|r| r.trim_end().parse().ok())
        .expect(&msg);
    assert_ne!(second, first);
    let _stop_successor = KillOnDrop(second);
    let status = tokio::task::spawn_blocking(move || child.wait().unwrap())
        .await
        .unwrap();
    assert!(status.success(), "predecessor: {status:?}");
    let ok = tokio::task::spawn_blocking(move || get(listen, "/shop/again", ""))
        .await
        .unwrap();
    assert!(ok.starts_with("HTTP/1.1 200"), "successor serves: {ok}");

    assert!(
        Command::new("kill")
            .args(["-TERM", &second.to_string()])
            .status()
            .unwrap()
            .success()
    );
    for _ in 0..400 {
        if !Path::new(&format!("/proc/{second}")).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let log = std::fs::read_to_string(dir.join("agent.log")).unwrap();
    assert!(
        log.contains("[waf-bundle] applied generation 3 — 1 apps"),
        "{log}"
    );
    assert!(
        log.contains("certificate refused") && log.contains("not_in_bundle"),
        "{log}"
    );
    assert!(!log.contains("INSTALLKEYBYTES"), "{log}");
    assert!(
        log.contains("[wafio-waf-agent] shutdown signal — stopping"),
        "{log}"
    );
    assert!(
        !Path::new(&format!("/proc/{second}")).exists(),
        "successor did not stop: {log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The tests that hold the cache write back need the feature `test-cache-delay`; the one above runs
/// without it.
#[cfg(feature = "test-cache-delay")]
mod held_writes {
    use super::*;
    use std::path::PathBuf;
    use std::process::Child;
    use std::time::SystemTime;

    /// How long the agent holds a cache write back in the tests below: longer than any of them needs
    /// to reach its signal, short enough to wait for.
    const HOLD_MS: u64 = 4000;

    fn bundle_json(listen: u16, up: u16, generation: i64) -> String {
        format!(
            r#"{{"agent_id":"cf4","project_id":"p","generation":{generation},"apps":[{{"app_id":"web","listen_host":"127.0.0.1","listen_port":{listen},"upstream":"http://127.0.0.1:{up}","mode":"block"}}]}}"#
        )
    }

    fn signal(pid: u32, name: &str) {
        assert!(
            Command::new("kill")
                .args([name, &pid.to_string()])
                .status()
                .unwrap()
                .success()
        );
    }

    async fn next_conn(conns: &mut mpsc::UnboundedReceiver<Conn>) -> Conn {
        tokio::time::timeout(Duration::from_secs(60), conns.recv())
            .await
            .expect("a connection")
            .expect("the control plane runs")
    }

    /// The Hello that a new stream opens with.
    async fn hello_of(c: &mut Conn) -> Hello {
        let Some(Out::Hello(h)) = c.next().await.kind else {
            panic!("no Hello")
        };
        h
    }

    /// An agent that holds each cache write back for [`HOLD_MS`], with a stream to the fake control
    /// plane that has said Hello.
    struct Held {
        dir: PathBuf,
        notify: UnixDatagram,
        child: Child,
        _stop: KillOnDrop,
        conns: mpsc::UnboundedReceiver<Conn>,
        stream: Conn,
        /// The generation the agent started from, 0 without a cache.
        hello_generation: i64,
        listen: u16,
        up: u16,
    }

    /// `cached`: the generation of a cache the agent finds at start.
    async fn start_held(tag: &str, cached: Option<i64>) -> Held {
        let dir = scratch(tag);
        let (listen, up) = (common::free_port(), upstream());
        if let Some(generation) = cached {
            let bundle = bundle_json(listen, up, generation);
            wafio_control::save_bundle_cache(
                &dir.join("state"),
                bundle.as_bytes(),
                generation,
                SystemTime::now(),
            )
            .unwrap();
        }
        let (cp, mut conns) = serve_fake(malware_snapshot()).await;
        let notify_path = dir.join("notify.sock");
        let notify = UnixDatagram::bind(&notify_path).unwrap();
        notify
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let child = agent_command(&dir, &cp, &notify_path)
            .env("WAFIO_TEST_CACHE_WRITE_DELAY_MS", HOLD_MS.to_string())
            .spawn()
            .unwrap();
        let stop = KillOnDrop(child.id());
        // The start probe, then the stream.
        hello_of(&mut next_conn(&mut conns).await).await;
        let mut stream = next_conn(&mut conns).await;
        let hello_generation = hello_of(&mut stream).await.bundle_generation;
        Held {
            dir,
            notify,
            child,
            _stop: stop,
            conns,
            stream,
            hello_generation,
            listen,
            up,
        }
    }

    impl Held {
        /// Sends the bundle of `generation` and waits for its ack. The cache write is held back, so
        /// the ack is all there is to see of the bundle.
        async fn send_bundle(&mut self, generation: i64) -> CommandAck {
            let bundle = bundle_json(self.listen, self.up, generation);
            self.stream
                .out
                .send(Ok(ServerMessage {
                    kind: Some(In::Bundle(BundleUpdate {
                        command_id: "b".into(),
                        generation,
                        bundle_json: bundle.into_bytes(),
                    })),
                }))
                .await
                .unwrap();
            loop {
                if let Some(Out::Ack(a)) = self.stream.next().await.kind
                    && a.command_id == "b"
                {
                    return a;
                }
            }
        }

        fn cache_file(&self) -> PathBuf {
            self.dir.join("state/last-bundle.json")
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bundle_that_was_acked_is_cached_before_the_agent_ends() {
        let mut h = start_held("end", None).await;
        let ack = h.send_bundle(4).await;
        assert!(ack.ok, "{}", ack.error);
        assert!(
            !h.cache_file().exists(),
            "the ack came before the write, which is held back"
        );
        signal(h.child.id(), "-TERM");
        let mut child = h.child;
        let status = tokio::task::spawn_blocking(move || child.wait().unwrap())
            .await
            .unwrap();
        assert!(status.success(), "{status:?}");
        let cache = std::fs::read_to_string(h.dir.join("state/last-bundle.json"))
            .expect("the write was finished before the agent ended");
        assert!(cache.contains("\"generation\":4"), "{cache}");
        let _ = std::fs::remove_dir_all(&h.dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_successor_starts_from_the_bundle_its_predecessor_acked() {
        let mut h = start_held("successor", None).await;
        let ack = h.send_bundle(4).await;
        assert!(ack.ok, "{}", ack.error);
        assert!(
            !h.cache_file().exists(),
            "the ack came before the write, which is held back"
        );
        let mut buf = [0u8; 128];
        h.notify.recv(&mut buf).expect("READY after the bundle");
        signal(h.child.id(), "-USR2");

        // The successor's start probe, then its stream, which carries the generation it started from.
        hello_of(&mut next_conn(&mut h.conns).await).await;
        let mut stream = next_conn(&mut h.conns).await;
        assert_eq!(
            hello_of(&mut stream).await.bundle_generation,
            4,
            "the successor started from the bundle the predecessor had acked"
        );
        let n = h.notify.recv(&mut buf).expect("the successor's READY");
        let second: u32 = std::str::from_utf8(&buf[..n])
            .unwrap()
            .strip_prefix("READY=1\nMAINPID=")
            .and_then(|r| r.trim_end().parse().ok())
            .expect("MAINPID");
        let _stop_successor = KillOnDrop(second);
        let mut child = h.child;
        let status = tokio::task::spawn_blocking(move || child.wait().unwrap())
            .await
            .unwrap();
        assert!(status.success(), "predecessor: {status:?}");
        let _ = std::fs::remove_dir_all(&h.dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_crash_between_the_ack_and_the_cache_write_leaves_the_earlier_cache_readable() {
        let mut h = start_held("crash", Some(3)).await;
        assert_eq!(h.hello_generation, 3, "the agent started from the cache");
        let ack = h.send_bundle(4).await;
        assert!(ack.ok, "{}", ack.error);
        // No handler runs: an out-of-memory kill or a power cut.
        h.child.kill().unwrap();
        h.child.wait().unwrap();

        let state = h.dir.join("state");
        let cached = wafio_control::load_bundle_cache(&state, &|_| Ok(()))
            .expect("the cache the agent started from is still readable");
        assert_eq!(cached.generation, 3);
        let names: Vec<String> = std::fs::read_dir(&state)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|n| !n.starts_with(".last-bundle-")),
            "no half-written file stays: {names:?}"
        );
        let _ = std::fs::remove_dir_all(&h.dir);
    }
}
