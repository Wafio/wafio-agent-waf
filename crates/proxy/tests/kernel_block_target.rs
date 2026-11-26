//! Black-box: a block window of a policy with target "kernel" reaches the host agent jail, and
//! only in block mode. The clients come through a trusted local proxy, as a web server on the
//! same host would send them.

mod common;
#[path = "common/fake_engine.rs"]
mod fake_engine;

use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use wafio_agent_io::ip_jail::{Enforce, JailTracker};
use wafio_proxy::AppSpec;

const FROM_CLIENT: &[u8] =
    b"GET /item?id=wafio-test-sql HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n";

fn rules(target: &str) -> String {
    format!(
        r#"{{"block_policy":{{"enabled":true,"block_after_n_blocks":1,"block_duration_sec":600,"key_fields":["remote_addr"]{target}}}}}"#
    )
}

/// An app whose jail is a channel; the flag jail is off (threshold 0).
fn app_with_jail(
    id: &str,
    mode: &str,
    target: &str,
    up: &TestUpstream,
) -> (AppSpec, Receiver<(String, Duration)>) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let enforce: Enforce = Arc::new(move |ip: &str, ttl: Duration| {
        let _ = tx.lock().unwrap().send((ip.to_string(), ttl));
    });
    let mut setup = wafio_proxy::testing::analysis_setup(rules(target).as_bytes());
    setup.jail = Some(Arc::new(JailTracker::new(
        0,
        Duration::from_secs(60),
        Duration::from_secs(3600),
        1024,
        Some(enforce),
    )));
    let mut a = app(id, free_port(), &format!("http://{}", up.addr));
    a.mode = mode.into();
    a.proxy_config = br#"{"trust_forwarded":true,"trusted_proxies":["127.0.0.1"]}"#.to_vec();
    a.analysis = Arc::new(setup);
    (a, rx)
}

#[tokio::test]
async fn kernel_target_jails_the_forwarded_client_once_per_window() {
    let up = http_upstream().await;
    let (a, rx) = app_with_jail("k", "block", r#","target":"kernel""#, &up);
    let (_h, addr) = Harness::serve_with_fake_engine(vec![a]);

    assert_eq!(one(addr, FROM_CLIENT).await.status, 403);
    let (ip, ttl) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(ip, "203.0.113.9");
    assert!(
        ttl <= Duration::from_secs(600) && ttl >= Duration::from_secs(590),
        "{ttl:?}"
    );

    // The window is open: the next request is blocked by the policy and not pushed again.
    assert_eq!(one(addr, FROM_CLIENT).await.status, 403);
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn waf_target_and_a_missing_target_never_jail() {
    let up = http_upstream().await;
    let (waf, rx_waf) = app_with_jail("w", "block", r#","target":"waf""#, &up);
    let (none, rx_none) = app_with_jail("n", "block", "", &up);
    let none_port = none.listen_port;
    let (_h, waf_addr) = Harness::serve_with_fake_engine(vec![waf, none]);
    let none_addr = format!("127.0.0.1:{none_port}").parse().unwrap();

    assert_eq!(one(waf_addr, FROM_CLIENT).await.status, 403);
    assert_eq!(one(none_addr, FROM_CLIENT).await.status, 403);
    assert!(rx_waf.recv_timeout(Duration::from_millis(300)).is_err());
    assert!(rx_none.recv_timeout(Duration::from_millis(300)).is_err());
}

#[tokio::test]
async fn kernel_target_in_monitor_mode_never_jails() {
    let up = http_upstream().await;
    let (a, rx) = app_with_jail("m", "monitor", r#","target":"kernel""#, &up);
    let (_h, addr) = Harness::serve_with_fake_engine(vec![a]);

    assert_eq!(one(addr, FROM_CLIENT).await.status, 200);
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
}
