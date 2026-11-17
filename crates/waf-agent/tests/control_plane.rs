//! Black-box test with the real binary: an in-test fake control plane (tonic, mTLS with the
//! control crate's fixture CA) checks what `wafio-waf-agent` sends — Hello (kind, version,
//! the features `script_rules` and `no_semantic_engine`), the first heartbeat with host info and counters, the malware sync
//! into the security-data dir given by `--security-data-dir`, the bundle ack, READY after the
//! live bundle, the bundle cache, a block decision with its credentials redacted.

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_talks_to_the_control_plane() {
    let dir = std::env::temp_dir().join(format!("wafio-cp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let data = dir.join("data.txt");
    std::fs::write(&data, "x\n").unwrap();
    let d = data.to_str().unwrap().to_string();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cp = listener.local_addr().unwrap().to_string();
    let (tx, mut conns) = mpsc::unbounded_channel();
    let malware = format!(
        "# Updated: 2026-01-01T00:00:00Z\n{} Test.Sig\n",
        "ab".repeat(32)
    )
    .into_bytes();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(fx("server.crt"), fx("server.key")))
        .client_ca_root(Certificate::from_pem(fx("ca.crt")));
    tokio::spawn(
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(AgentControlServer::new(Fake {
                conns: tx,
                malware: malware.clone(),
            }))
            .serve_with_incoming(TcpIncoming::from(listener)),
    );

    let notify_path = dir.join("notify.sock");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let (listen, up) = (
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port(),
        upstream(),
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_wafio-waf-agent-open"))
        .args(["--grpc-server", &cp, "--agent-name", "cf4"])
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
            &d,
            "--geo-city-db",
            &d,
            "--geo-asn-db",
            &d,
            "--bot-ua-file",
            &d,
            "--bot-ja4-file",
            &d,
        ])
        .args([
            "--iprep-level1-file",
            &d,
            "--iprep-level2-file",
            &d,
            "--jail-threshold",
            "0",
        ])
        .args([
            "--security-data-dir",
            dir.to_str().unwrap(),
            "--state-dir",
            dir.join("state").to_str().unwrap(),
        ])
        .env("NOTIFY_SOCKET", &notify_path)
        .env("RUNTIME_DIRECTORY", &dir)
        // A library installed on this host must not give the agent an engine: name one that does not exist.
        .env("WAFIO_ENGINE_LIB", dir.join("no-engine.so"))
        .stderr(Stdio::from(
            std::fs::File::create(dir.join("agent.log")).unwrap(),
        ))
        .spawn()
        .unwrap();
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
        vec!["script_rules", "no_semantic_engine"],
        "the agent runs script rules itself, and this binary has no engine"
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
    let bundle = format!(
        r#"{{"agent_id":"cf4","project_id":"p","generation":1,"apps":[{{"app_id":"web","listen_host":"127.0.0.1","listen_port":{listen},"upstream":"http://127.0.0.1:{up}","mode":"block","rules_json":{{"path_exceptions":[{{"path":"/search","block":{{}}}}]}}}}]}}"#
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
    let ack = loop {
        if let Some(Out::Ack(a)) = c.next().await.kind
            && a.command_id == "b1"
        {
            break a;
        }
    };
    assert!(ack.ok, "bundle refused: {}", ack.error);
    notify
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut buf = [0u8; 128];
    let n = notify.recv(&mut buf).expect("READY after the live bundle");
    assert_eq!(
        std::str::from_utf8(&buf[..n]).unwrap(),
        format!("READY=1\nMAINPID={}\n", child.id())
    );
    let cache = std::fs::read_to_string(dir.join("state/last-bundle.json")).unwrap();
    assert!(cache.contains("\"generation\":3"), "{cache}");
    let ok = tokio::task::spawn_blocking(move || get(listen, "/hello", ""))
        .await
        .unwrap();
    assert!(ok.starts_with("HTTP/1.1 200") && ok.ends_with("ok"), "{ok}");

    // A blocked request (the path of the app is blocked by a rule; this agent has no engine): the decision reaches
    // the control plane with credentials redacted.
    let blocked = tokio::task::spawn_blocking(move || {
        get(
            listen,
            "/search?q=anything",
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
    let ok = tokio::task::spawn_blocking(move || get(listen, "/again", ""))
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
        log.contains("[wafio-waf-agent] shutdown signal — stopping"),
        "{log}"
    );
    assert!(
        !Path::new(&format!("/proc/{second}")).exists(),
        "successor did not stop: {log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
