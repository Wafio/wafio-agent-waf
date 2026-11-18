//! The `maintenance` object of a bundle app reaches the proxy: the app answers 503 while the
//! object is there and proxies again when a later bundle leaves it out. A value it cannot read
//! fails neither the bundle nor the app. A bundle that turns it on ends the open WebSocket sessions
//! of the clients it does not allow.

use std::sync::Arc;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wafio_agent_io::ws_frame::{WsConnection, WsError};
use wafio_agent_pages::goodbot::VerifiedBotChecker;
use wafio_waf_agent::agent::Agent;
use wafio_waf_agent::bundle::decode_bundle;
use wafio_waf_agent::executor::{Stores, startup_executor};
use wafio_waf_agent::ready::{Ready, ReadyActions};

fn bundle(port: u16, upstream: &str, maintenance: &str) -> String {
    let key = if maintenance.is_empty() {
        String::new()
    } else {
        format!(r#","maintenance":{maintenance}"#)
    };
    format!(
        r#"{{"agent_id":"a","project_id":"p","apps":[{{"app_id":"web","listen_host":"127.0.0.1","listen_port":{port},"upstream":"http://{upstream}","mode":"block"{key}}}]}}"#
    )
}

async fn reply(port: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"GET /shop HTTP/1.1\r\nHost: app.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An agent with a proxy, and a way to install a bundle for one app on `port` with the given
/// upstream and `maintenance` object.
struct Rig {
    rt: tokio::runtime::Runtime,
    proxy: Arc<wafio_proxy::Proxy>,
    agent: Agent,
    port: u16,
    upstream: String,
}

impl Rig {
    /// Nothing listens on the default upstream port: a request that is proxied gets 502.
    fn new() -> Rig {
        let rt = wafio_proxy::runtime_builder().build().unwrap();
        let _g = rt.enter();
        let stores = Stores::new();
        let base = startup_executor(&stores, "", None).unwrap();
        let proxy = Arc::new(wafio_proxy::Proxy::new(wafio_proxy::ProxyOptions::new(
            Arc::new(|_| {}),
        )));
        let agent = Agent::new(
            base,
            stores,
            proxy.clone(),
            Arc::new(VerifiedBotChecker::new()),
            Arc::new(Ready::new(ReadyActions::default())),
        );
        drop(_g);
        Rig {
            rt,
            proxy,
            agent,
            port: free_port(),
            upstream: "127.0.0.1:1".into(),
        }
    }

    fn install(&self, generation: i64, maintenance: &str) {
        let _g = self.rt.enter();
        let mut b =
            decode_bundle(bundle(self.port, &self.upstream, maintenance).as_bytes()).unwrap();
        b.generation = generation;
        self.agent.install_bundle(&b).unwrap();
    }
}

#[test]
fn a_bundle_turns_maintenance_mode_on_and_off() {
    let rig = Rig::new();
    let (rt, proxy, port) = (&rig.rt, &rig.proxy, rig.port);
    let install = |generation: i64, maintenance: &str| rig.install(generation, maintenance);

    install(
        1,
        r#"{"enabled":true,"message":"Back at nine.","allow_ips":[]}"#,
    );
    let on = rt.block_on(reply(port));
    assert!(
        on.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "{on}"
    );
    assert!(on.contains("Cache-Control: no-store\r\n"), "{on}");
    assert!(on.contains("Back at nine."), "{on}");

    install(
        2,
        r#"{"enabled":true,"message":"x","allow_ips":["127.0.0.1"]}"#,
    );
    let allowed = rt.block_on(reply(port));
    assert!(allowed.starts_with("HTTP/1.1 502 "), "{allowed}");

    install(3, r#"{"enabled":false}"#);
    assert!(rt.block_on(reply(port)).starts_with("HTTP/1.1 502 "));
    install(4, r#"{"enabled":true}"#);
    assert!(rt.block_on(reply(port)).starts_with("HTTP/1.1 503 "));
    install(5, "");
    assert!(rt.block_on(reply(port)).starts_with("HTTP/1.1 502 "));
    // A value this agent cannot read leaves the app serving the site.
    for (generation, unreadable) in [(6, r#""on""#), (7, "[1]"), (8, r#"{"enabled":"yes"}"#)] {
        install(generation, unreadable);
        assert!(
            rt.block_on(reply(port)).starts_with("HTTP/1.1 502 "),
            "{unreadable}"
        );
    }
    install(
        9,
        r#"{"enabled":true,"end_time":"soon","allow_ips":"all","allow_paths":[7]}"#,
    );
    assert!(rt.block_on(reply(port)).starts_with("HTTP/1.1 503 "));
    rt.block_on(proxy.shutdown(false));
}

/// A WebSocket echo server; its address.
async fn ws_echo() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(async move {
                let Ok(c) = WsConnection::server(Box::new(s)).await else {
                    return;
                };
                while let Ok((kind, msg)) = c.next_data_message().await {
                    if c.send_data_message(kind, &msg).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

async fn ws_open(port: u16, forwarded_for: &str) -> Result<WsConnection, WsError> {
    let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let headers = [("X-Forwarded-For".to_string(), forwarded_for.to_string())];
    WsConnection::client(Box::new(s), "app.test", "/chat", &headers)
        .await
        .map(|(c, _)| c)
        .map_err(|(e, _)| e)
}

async fn echoes(c: &WsConnection) {
    c.send_data_message(1, b"ping").await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), c.next_data_message())
        .await
        .expect("an echo")
        .unwrap();
    assert_eq!(got, (1, b"ping".to_vec()));
}

async fn ends(c: &WsConnection) -> WsError {
    match tokio::time::timeout(Duration::from_secs(2), c.next_data_message()).await {
        Ok(Err(e)) => e,
        other => panic!("expected the session to end, got {other:?}"),
    }
}

#[test]
fn a_bundle_that_turns_maintenance_on_closes_the_sessions_it_does_not_allow() {
    let mut rig = Rig::new();
    let echo = rig.rt.block_on(ws_echo());
    rig.upstream = echo.to_string();
    // The loopback peer may name the client; the addresses below are the clients.
    let install = |generation: i64, maintenance: &str| {
        let _g = rig.rt.enter();
        let mut b = decode_bundle(
            bundle(rig.port, &rig.upstream, maintenance)
                .replacen(
                    r#""mode":"block""#,
                    r#""mode":"block","proxy_config":{"trust_forwarded":true,"trusted_proxies":["127.0.0.1"]}"#,
                    1,
                )
                .as_bytes(),
        )
        .unwrap();
        b.generation = generation;
        rig.agent.install_bundle(&b).unwrap();
    };
    install(1, "");
    let (allowed, other) = rig.rt.block_on(async {
        let allowed = ws_open(rig.port, "203.0.113.9").await.unwrap();
        let other = ws_open(rig.port, "198.51.100.2").await.unwrap();
        echoes(&allowed).await;
        echoes(&other).await;
        (allowed, other)
    });

    install(2, r#"{"enabled":true,"allow_ips":["203.0.113.9"]}"#);
    rig.rt.block_on(async {
        assert_eq!(
            ends(&other).await,
            WsError::Close {
                code: 1001,
                text: "Maintenance".into()
            }
        );
        echoes(&allowed).await;
        assert!(matches!(
            ws_open(rig.port, "198.51.100.2").await.err(),
            Some(WsError::Handshake(_))
        ));
    });

    // Turning it off leaves the session; turning it on without the address ends it.
    install(3, r#"{"enabled":false}"#);
    rig.rt.block_on(async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        echoes(&allowed).await;
    });
    install(4, r#"{"enabled":true}"#);
    rig.rt.block_on(async {
        assert_eq!(
            ends(&allowed).await,
            WsError::Close {
                code: 1001,
                text: "Maintenance".into()
            }
        );
    });
    rig.rt.block_on(rig.proxy.shutdown(false));
}
