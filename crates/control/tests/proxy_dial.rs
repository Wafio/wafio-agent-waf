//! The control-plane dial through an outbound proxy: `HTTPS_PROXY` and `NO_PROXY` decide, a
//! plain `CONNECT host:port` carries the unresolved target name, a refusal is a dial error. One
//! test, because the process environment is read once.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};
use wafio_control::*;
use wafio_proto::v1::agent_control_server::{AgentControl, AgentControlServer};
use wafio_proto::v1::server_message::Kind as In;
use wafio_proto::v1::*;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).unwrap()
}

/// A control plane that welcomes every agent.
struct Welcomer;

#[tonic::codegen::async_trait]
impl AgentControl for Welcomer {
    type StreamStream = ReceiverStream<Result<ServerMessage, Status>>;
    async fn stream(
        &self,
        _: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        let (tx, rx) = mpsc::channel(4);
        tx.send(Ok(ServerMessage {
            kind: Some(In::Welcome(Welcome {
                agent_id: "a".into(),
                server_time_unix: 1,
                heartbeat_seconds: 30,
            })),
        }))
        .await
        .unwrap();
        // keep the stream open until the agent hangs up
        tokio::spawn(async move {
            tx.closed().await;
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
        Err(Status::unimplemented("not served"))
    }
}

async fn control_plane() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(read("server.crt"), read("server.key")))
        .client_ca_root(Certificate::from_pem(read("ca.crt")));
    tokio::spawn(
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(AgentControlServer::new(Welcomer))
            .serve_with_incoming(TcpIncoming::from(listener)),
    );
    port
}

/// A CONNECT proxy: records every request head; `denied.test` is refused, everything else is
/// tunnelled to the control plane on `cp_port` whatever name was asked for.
async fn proxy(cp_port: u16) -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if c.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let denied = head.starts_with("CONNECT denied.test:");
                log.lock().unwrap().push(head);
                if denied {
                    let _ = c
                        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                }
                let Ok(mut up) = TcpStream::connect(("127.0.0.1", cp_port)).await else {
                    return;
                };
                let _ = c
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await;
                let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
            });
        }
    });
    (port, seen)
}

fn link(addr: &str) -> Arc<ControlLink> {
    let p = |n: &str| fixture(n).to_string_lossy().to_string();
    let cfg = ControlConfig::load(
        addr,
        "localhost",
        &p("client.crt"),
        &p("client.key"),
        &p("ca.crt"),
        "edge-1",
        "wafh_old",
        "test",
    )
    .unwrap();
    struct NoStats;
    impl AgentStats for NoStats {
        fn counters(&self) -> HeartbeatCounters {
            HeartbeatCounters::default()
        }
        fn host_info_json(&self) -> Vec<u8> {
            b"{}".to_vec()
        }
    }
    struct NoSink;
    impl BundleSink for NoSink {
        fn apply(&self, _: &[u8], _: i64) -> Result<(), BundleError> {
            Ok(())
        }
        fn check(&self, _: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }
    struct NoCertificates;
    impl CertificateSink for NoCertificates {
        fn install(&self, _: &mut CertificateInstall) -> Result<(), AckCode> {
            Err(AckCode::NotInBundle)
        }
    }
    struct NoSec;
    impl SecurityData for NoSec {
        fn replace_malware_snapshot(&self, _: &Path, _: Vec<u8>) -> Result<(), String> {
            Ok(())
        }
        fn download_components(&self, _: &Path, _: &[String], _: bool) -> Vec<FetchResult> {
            Vec::new()
        }
    }
    ControlLink::new(
        cfg,
        Hooks {
            bundles: Arc::new(NoSink),
            certificates: Arc::new(NoCertificates),
            stats: Arc::new(NoStats),
            security_data: Arc::new(NoSec),
            redact: |_| {},
            on_dial: |_| {},
        },
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_control_link_dials_through_https_proxy() {
    let cp = control_plane().await;
    let (pp, seen) = proxy(cp).await;
    // Before the first dial: the environment is read once. A lower-case HTTP_PROXY pointing
    // nowhere must be ignored (the channel only reads HTTPS_PROXY).
    unsafe {
        std::env::set_var("https_proxy", format!("http://u:p@127.0.0.1:{pp}"));
        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:1");
        std::env::set_var("NO_PROXY", "skip.test, .internal");
    }

    // The name does not resolve here: only the proxy can reach it.
    link(&format!("cp.test:{cp}"))
        .exchange_hello()
        .await
        .unwrap();
    {
        let heads = seen.lock().unwrap();
        assert_eq!(heads.len(), 1, "{heads:?}");
        assert!(
            heads[0].starts_with(&format!("CONNECT cp.test:{cp} HTTP/1.1\r\n")),
            "{}",
            heads[0]
        );
        assert!(
            heads[0].contains(&format!("\r\nHost: cp.test:{cp}\r\n")),
            "{}",
            heads[0]
        );
        assert!(
            heads[0].contains("\r\nProxy-Authorization: Basic dTpw\r\n"),
            "{}",
            heads[0]
        );
    }

    // NO_PROXY: dialled directly, which cannot resolve; the proxy hears nothing.
    let e = link(&format!("skip.test:{cp}"))
        .exchange_hello()
        .await
        .unwrap_err();
    assert!(!e.rejected(), "{e}");
    assert_eq!(seen.lock().unwrap().len(), 1);
    let e = link(&format!("db.internal:{cp}"))
        .exchange_hello()
        .await
        .unwrap_err();
    assert!(!e.rejected(), "{e}");
    assert_eq!(seen.lock().unwrap().len(), 1);

    // A refusal is a dial error, not a rejection of the agent.
    let e = link(&format!("denied.test:{cp}"))
        .exchange_hello()
        .await
        .unwrap_err();
    assert!(!e.rejected(), "{e}");
    assert!(
        e.to_string().contains(
            "transport: Error while dialing: failed to do connect handshake, response: \"HTTP/1.1 403 Forbidden"
        ),
        "{e}"
    );

    // Loopback is never proxied, so a local control plane works whatever HTTPS_PROXY says.
    link(&format!("127.0.0.1:{cp}"))
        .exchange_hello()
        .await
        .unwrap();
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "only cp.test and denied.test were proxied"
    );
}
