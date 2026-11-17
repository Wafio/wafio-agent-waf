//! Final verdicts reach the executor's SIEM sender once per request: blocks and logs with the
//! snippets of the body and headers, nothing for an allow, no content snippets for a verdict
//! decided before content inspection.

mod common;
#[path = "common/fake_engine.rs"]
mod fake_engine;

use std::sync::{Arc, Mutex};

use common::*;
use wafio_proxy::{SiemEvent, SiemEventSender};

#[derive(Default)]
struct Collect(Mutex<Vec<SiemEvent>>);

impl SiemEventSender for Collect {
    fn send(&self, evt: &SiemEvent) -> Result<(), String> {
        self.0.lock().unwrap().push(evt.clone());
        Ok(())
    }
}

fn app_with_siem(port: u16, upstream: &str, rules: &str) -> (wafio_proxy::AppSpec, Arc<Collect>) {
    let sink = Arc::new(Collect::default());
    let mut exec = wafio_proxy::testing::analysis_setup(rules.as_bytes());
    exec.siem = Some(sink.clone());
    let mut a = app("a1", port, upstream);
    a.analysis = Arc::new(exec);
    (a, sink)
}

const SQLI: &str = "/item?id=wafio-test-sql&access_token=abc123";

#[tokio::test]
async fn a_block_is_reported_with_its_snippets_and_an_allow_is_not() {
    let up = http_upstream().await;
    let port = free_port();
    let (a, sink) = app_with_siem(port, &format!("http://{}", up.addr), RULES);
    let (_h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    // An attack in the query; a hostile Referer and a session cookie ride along.
    let raw = format!(
        "GET {SQLI} HTTP/1.1\r\nHost: app.test\r\nUser-Agent: curl/8\r\nReferer: http://x.test/?q=wafio-test-xss&token=s3cr3t\r\nCookie: sid=abc; q=wafio-test-xss\r\n\r\n"
    );
    assert_eq!(one(proxy, raw.as_bytes()).await.status, 403);
    assert_eq!(one(proxy, &get("/fine")).await.status, 200);
    let events = sink.0.lock().unwrap().clone();
    assert_eq!(events.len(), 1, "only the block: {events:?}");
    let e = &events[0];
    assert_eq!(
        (
            e.action.as_str(),
            e.analyze_method.as_str(),
            e.categories.as_slice()
        ),
        ("block", "semantic", &["SQLi".to_string()][..])
    );
    assert!(e.score > 0 && e.timestamp.0 > 1_700_000_000);
    assert_eq!(
        (
            e.method.as_slice(),
            e.host.as_slice(),
            e.user_agent.as_slice()
        ),
        (&b"GET"[..], &b"app.test"[..], &b"curl/8"[..])
    );
    // The URI loses its credential-named parameter, keeps the payload.
    let uri = s(&e.uri);
    assert!(
        uri.contains("wafio-test-sql")
            && (uri.contains("access_token=%5Bredacted%5D")
                || uri.contains("access_token=[redacted]")),
        "{uri}"
    );
    assert!(!uri.contains("abc123"), "{uri}");
    // A GET has no body snippet; the headers that look hostile do, the cookie's session id does not.
    assert_eq!(e.body_injection_fields, b"");
    let h = s(&e.header_injection_fields);
    assert!(
        h.starts_with("Referer: ") && h.contains("wafio-test-xss") && !h.contains("s3cr3t"),
        "{h}"
    );
    assert!(h.contains("Cookie: ") && !h.contains("sid=abc"), "{h}");
    // The JSON carries the wire field names.
    let json = String::from_utf8(e.to_json()).unwrap();
    assert!(
        json.starts_with(r#"{"action":"block","score":"#)
            && json.contains(r#""match_source":""#)
            && json.contains(r#""header_injection_fields":"Referer: "#),
        "{json}"
    );
}

#[tokio::test]
async fn the_body_snippet_hides_credentials_and_is_cut_at_512_bytes() {
    let up = http_upstream().await;
    let port = free_port();
    let (a, sink) = app_with_siem(port, &format!("http://{}", up.addr), RULES);
    let (_h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let body = r#"{"q":"wafio-test-sql","password":"hunter2","token":"t0k3n"}"#;
    assert_eq!(
        one(proxy, &post("/login", "application/json", body.as_bytes()))
            .await
            .status,
        403
    );
    let long = format!(r#"{{"q":"wafio-test-sql","pad":"{}"}}"#, "x".repeat(2000));
    assert_eq!(
        one(proxy, &post("/login", "application/json", long.as_bytes()))
            .await
            .status,
        403
    );
    let events = sink.0.lock().unwrap().clone();
    assert_eq!(events.len(), 2);
    let b = s(&events[0].body_injection_fields);
    assert!(
        b.contains("wafio-test-sql")
            && b.contains(r#""password":"[redacted]""#)
            && b.contains(r#""token":"[redacted]""#)
            && !b.contains("hunter2")
            && !b.contains("t0k3n"),
        "{b}"
    );
    let c = &events[1].body_injection_fields;
    assert!(c.len() == 512 + 3 && c.ends_with(b"..."), "{}", c.len());
}

#[tokio::test]
async fn verdicts_decided_before_content_inspection_carry_no_snippets() {
    let up = http_upstream().await;
    let port = free_port();
    // The L7 flood limit decides on the request count alone (`policy`).
    let rules = r#"{"l7_flood":{"enabled":true,"max_requests":1,"window_sec":60}}"#;
    let (a, sink) = app_with_siem(port, &format!("http://{}", up.addr), rules);
    let (_h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    one(proxy, &get("/")).await;
    let raw = b"POST /p HTTP/1.1\r\nHost: a\r\nReferer: wafio-test-xss\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nhello world";
    assert_ne!(one(proxy, raw).await.status, 200);
    let events = sink.0.lock().unwrap().clone();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(
        (events[0].action.as_str(), events[0].analyze_method.as_str()),
        ("block", "policy")
    );
    assert!(
        events[0].body_injection_fields.is_empty() && events[0].header_injection_fields.is_empty(),
        "{:?}",
        events[0]
    );
}
