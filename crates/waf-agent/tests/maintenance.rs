//! The `maintenance` object of a bundle app reaches the proxy: the app answers 503 while the
//! object is there and proxies again when a later bundle leaves it out. A value it cannot read
//! fails neither the bundle nor the app.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wafio_agent_pages::goodbot::VerifiedBotChecker;
use wafio_waf_agent::agent::Agent;
use wafio_waf_agent::bundle::decode_bundle;
use wafio_waf_agent::executor::{Stores, startup_executor};
use wafio_waf_agent::ready::{Ready, ReadyActions};

fn bundle(port: u16, maintenance: &str) -> String {
    let key = if maintenance.is_empty() {
        String::new()
    } else {
        format!(r#","maintenance":{maintenance}"#)
    };
    // Nothing listens on the upstream port: a request that is proxied gets 502.
    format!(
        r#"{{"agent_id":"a","project_id":"p","apps":[{{"app_id":"web","listen_host":"127.0.0.1","listen_port":{port},"upstream":"http://127.0.0.1:1","mode":"block"{key}}}]}}"#
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

#[test]
fn a_bundle_turns_maintenance_mode_on_and_off() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
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
    let install = |generation: i64, maintenance: &str| {
        let mut b = decode_bundle(bundle(port, maintenance).as_bytes()).unwrap();
        b.generation = generation;
        agent.install_bundle(&b).unwrap();
    };

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
