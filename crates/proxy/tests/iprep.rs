//! The IP reputation gate and how its hits merge into the request's verdict.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use wafio_agent_pages::challenge::issue_challenge_cookie;
use wafio_agent_pages::iprep::{AddressRange, ReputationChecker, ReputationLists};
use wafio_proxy::{AppSpec, Proxy, ProxyOptions};

const LISTED1: u32 = u32::from_be_bytes([203, 0, 113, 9]);
const LISTED2: u32 = u32::from_be_bytes([198, 51, 100, 7]);

fn rules(challenge: &str) -> String {
    format!(
        r#"{{"challenge":{{"ip_rep_enabled":true,"ip_rep_block_level1":true,"allow_local_ips":false,"secret_key":"0123456789abcdef0123456789abcdef"{challenge}}}}}"#
    )
}

/// Clients reach the app through a trusted local proxy naming them in X-Forwarded-For.
fn iprep_app(id: &str, port: u16, upstream: &str, mode: &str, rules: &str) -> AppSpec {
    let mut a = app(id, port, upstream);
    a.mode = mode.into();
    a.proxy_config = br#"{"trust_forwarded":true,"trusted_proxies":["127.0.0.1"]}"#.to_vec();
    a.analysis = analysis_setup(rules);
    a
}

fn from(ip: &str) -> Vec<u8> {
    format!(
        "GET /p HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nX-Forwarded-For: {ip}\r\n\r\n"
    )
    .into_bytes()
}

#[tokio::test]
async fn level1_blocks_in_block_mode_and_is_recorded_in_monitor_mode() {
    let up = http_upstream().await;
    let events: Events = Arc::default();
    let ev = events.clone();
    let mut opts = ProxyOptions::new(Arc::new(move |e| ev.lock().unwrap().push(e)));
    let checker = ReputationChecker::new();
    checker.store(ReputationLists {
        block: vec![AddressRange {
            start: LISTED1,
            end: LISTED1,
        }],
        challenge: vec![AddressRange {
            start: LISTED2,
            end: LISTED2,
        }],
    });
    opts.ip_rep = Some(Arc::new(checker));
    let proxy = Proxy::new(opts);
    let (pb, pm, pc) = (free_port(), free_port(), free_port());
    let u = format!("http://{}", up.addr);
    proxy
        .apply(vec![
            iprep_app("blk", pb, &u, "block", &rules("")),
            iprep_app("mon", pm, &u, "monitor", &rules("")),
            iprep_app(
                "chl",
                pc,
                &u,
                "block",
                &rules(r#","enabled":true,"trigger":"on_bot_detect""#),
            ),
        ])
        .unwrap();
    let addr = |p: u16| format!("127.0.0.1:{p}").parse().unwrap();
    let last =
        |e: &Mutex<Vec<wafio_proxy::DecisionEvent>>| e.lock().unwrap().last().cloned().unwrap();

    // Block mode, level 1 blocked: the reputation page, never the upstream.
    let resp = one(addr(pb), &from("203.0.113.9")).await;
    assert_eq!(resp.status, 403);
    let e = last(&events);
    assert_eq!(
        (s(&e.action), s(&e.match_detail), s(&e.analyze_method)),
        ("block", "iprep_level1", "challenge_gate")
    );
    assert_eq!(e.categories, vec![b"IPReputation".to_vec()]);
    assert_eq!(up.count(), 0);
    // A clean address passes.
    assert_eq!(one(addr(pb), &from("192.0.2.1")).await.status, 200);

    // Monitor mode: forwarded, the hit is the request's would-be block.
    assert_eq!(one(addr(pm), &from("203.0.113.9")).await.status, 200);
    let e = last(&events);
    assert_eq!(
        (s(&e.action), s(&e.match_detail), s(&e.mode)),
        ("monitor", "iprep_level1", "monitor")
    );

    // Level 2 with the challenge on: the gate challenges even a non-bot client.
    let resp = one(addr(pc), &from("198.51.100.7")).await;
    assert_eq!(resp.header("x-wafio-mitigated"), Some("challenge"));
    let e = last(&events);
    assert_eq!(
        (s(&e.action), s(&e.match_detail)),
        ("challenge", "iprep_challenge")
    );
    assert_eq!(
        e.categories,
        vec![b"BotChallenge".to_vec(), b"IPReputation".to_vec()]
    );

    // Level 2 with the challenge off: allowed, logged with the note.
    assert_eq!(one(addr(pb), &from("198.51.100.7")).await.status, 200);
    let e = last(&events);
    assert_eq!(
        (s(&e.action), s(&e.match_detail)),
        ("log", "iprep_level2; challenge_off")
    );
}

/// A client on the level 2 list is challenged until it holds a valid cookie of this app, then the
/// request reaches the upstream. It used to be challenged on every request, whatever it held.
#[tokio::test]
async fn level2_client_passes_the_challenge_with_a_valid_cookie() {
    let up = http_upstream().await;
    let mut opts = ProxyOptions::new(Arc::new(|_| {}));
    let checker = ReputationChecker::new();
    checker.store(ReputationLists {
        block: Vec::new(),
        challenge: vec![AddressRange {
            start: LISTED2,
            end: LISTED2,
        }],
    });
    opts.ip_rep = Some(Arc::new(checker));
    let proxy = Proxy::new(opts);
    let port = free_port();
    proxy
        .apply(vec![iprep_app(
            "chl",
            port,
            &format!("http://{}", up.addr),
            "block",
            &rules(r#","enabled":true,"trigger":"on_bot_detect""#),
        )])
        .unwrap();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let secret = "0123456789abcdef0123456789abcdef";
    let with_cookie = |cookie: &[u8]| {
        format!(
            "GET /p HTTP/1.1\r\nHost: app.test\r\nAccept: text/html\r\nX-Forwarded-For: 198.51.100.7\r\nCookie: _wafio_ch={}\r\n\r\n",
            s(cookie)
        )
        .into_bytes()
    };

    let resp = one(addr, &from("198.51.100.7")).await;
    assert_eq!(resp.header("x-wafio-mitigated"), Some("challenge"));
    assert_eq!(up.count(), 0);
    let good = issue_challenge_cookie(secret, b"chl", now);
    let resp = one(addr, &with_cookie(&good)).await;
    assert_eq!(resp.status, 200, "a valid cookie must reach the upstream");
    assert_eq!(resp.header("x-wafio-mitigated"), None);
    assert_eq!(up.count(), 1);

    // A cookie of another app and one signed with another key are still challenged.
    for bad in [
        issue_challenge_cookie(secret, b"other-app", now),
        issue_challenge_cookie("another-secret-key-0123456789abcd", b"chl", now),
    ] {
        let resp = one(addr, &with_cookie(&bad)).await;
        assert_eq!(resp.header("x-wafio-mitigated"), Some("challenge"));
    }
    assert_eq!(up.count(), 1);
}
