//! `POST /_wafio/challenge/verify` is limited per client address before any verify work, and only
//! while the challenge is on. Its own test binary: the limit is process-wide.

mod common;

use std::sync::Arc;

use common::*;
use wafio_agent_pages::challenge_verify_limit::{set_verify_limit, verify_refused_total};
use wafio_proxy::{AppSpec, Proxy, ProxyOptions};

const WITH_CHALLENGE: &str =
    r#"{"challenge":{"enabled":true,"secret_key":"0123456789abcdef0123456789abcdef"}}"#;

/// Clients reach the app through a trusted local proxy naming them in X-Forwarded-For.
fn app_with(id: &str, port: u16, upstream: &str, rules: &str) -> AppSpec {
    let mut a = app(id, port, upstream);
    a.proxy_config = br#"{"trust_forwarded":true,"trusted_proxies":["127.0.0.1"]}"#.to_vec();
    a.analysis = analysis_setup(rules);
    a
}

fn verify_post(client: &str) -> Vec<u8> {
    let body = b"token=x&redirect=%2F";
    format!(
        "POST /_wafio/challenge/verify HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nX-Forwarded-For: {client}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    )
    .into_bytes()
}

#[tokio::test]
async fn verify_post_is_limited_per_client_address() {
    set_verify_limit(3);
    let up = http_upstream().await;
    let proxy = Proxy::new(ProxyOptions::new(Arc::new(|_| {})));
    let (on, off) = (free_port(), free_port());
    let u = format!("http://{}", up.addr);
    proxy
        .apply(vec![
            app_with("on", on, &u, WITH_CHALLENGE),
            app_with("off", off, &u, RULES),
        ])
        .unwrap();
    let addr = |p: u16| format!("127.0.0.1:{p}").parse().unwrap();
    let refused_before = verify_refused_total();

    for i in 1..=3 {
        let r = one(addr(on), &verify_post("198.51.100.9")).await;
        assert_ne!(r.status, 429, "request {i} refused inside the limit");
    }
    let over = one(addr(on), &verify_post("198.51.100.9")).await;
    assert_eq!(over.status, 429, "the 4th request must be refused");
    assert_eq!(over.header("retry-after"), Some("60"));
    assert_eq!(over.text(), "too many requests");
    assert_ne!(
        one(addr(on), &verify_post("198.51.100.10")).await.status,
        429,
        "another client address was refused"
    );
    assert_eq!(verify_refused_total() - refused_before, 1);

    // A route without the challenge answers 404 whatever the count.
    for _ in 0..5 {
        let r = one(addr(off), &verify_post("198.51.100.9")).await;
        assert_eq!(r.status, 404);
    }
    assert_eq!(verify_refused_total() - refused_before, 1);
    assert_eq!(up.count(), 0, "a verify POST never reaches the upstream");
}
