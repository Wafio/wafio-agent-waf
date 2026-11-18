//! An app in maintenance mode answers 503 itself, from the request head and before any other step:
//! every method, a WebSocket handshake, monitor mode, blocked clients included. The body is not read,
//! nothing reaches the upstream and no decision is recorded. Allowed IPs and paths go through the whole
//! normal pipeline. The answer carries the CORS headers a browser app needs to read it.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wafio_proxy::metrics::MAINTENANCE_RESPONSES;

fn on(extra: &str) -> Vec<u8> {
    format!(r#"{{"enabled":true{extra}}}"#).into_bytes()
}

async fn serve(maintenance: Vec<u8>) -> (Harness, SocketAddr, TestUpstream) {
    let up = http_upstream().await;
    let mut a = app("m", free_port(), &format!("http://{}", up.addr));
    a.maintenance = maintenance;
    let (h, addr) = Harness::serve(vec![a]);
    (h, addr, up)
}

fn with_accept(accept: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: app.test\r\nAccept: {accept}\r\n\r\n").into_bytes()
}

#[tokio::test]
async fn every_method_gets_the_503_page_and_nothing_reaches_the_upstream() {
    let (h, addr, up) = serve(on("")).await;

    let get_reply = one(addr, &get("/shop?id=1")).await;
    assert_eq!(get_reply.status, 503);
    assert_eq!(
        get_reply.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(get_reply.header("cache-control"), Some("no-store"));
    assert_eq!(get_reply.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(get_reply.header("retry-after"), None, "no end time");
    assert!(
        get_reply.text().contains("planned maintenance"),
        "{}",
        get_reply.text()
    );

    let post_reply = one(addr, &post("/cart", "application/json", br#"{"a":1}"#)).await;
    assert_eq!(post_reply.status, 503);
    assert_eq!(post_reply.body, get_reply.body);

    let mut c = Client::connect(addr).await.unwrap();
    c.0.get_mut()
        .write_all(b"HEAD /shop HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await
        .unwrap();
    let head = read_raw(&mut c.0, true).await.unwrap();
    assert!(
        head.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "{head}"
    );
    assert!(head.contains("Cache-Control: no-store\r\n"), "{head}");
    assert!(
        head.contains("X-Content-Type-Options: nosniff\r\n"),
        "{head}"
    );
    assert!(
        head.contains(&format!("Content-Length: {}\r\n", get_reply.body.len())),
        "a HEAD answer states the length of the GET answer: {head}"
    );
    assert!(
        head.ends_with("\r\n\r\n"),
        "a HEAD answer has no body: {head:?}"
    );

    settle().await;
    assert_eq!(
        (up.count(), up.accepts()),
        (0, 0),
        "the upstream was never contacted"
    );
    assert!(h.events().is_empty(), "{:?}", h.events());
}

#[tokio::test]
async fn a_websocket_handshake_is_refused_with_503() {
    let (_h, addr, up) = serve(on("")).await;
    let raw = b"GET /chat HTTP/1.1\r\nHost: app.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://app.test\r\n\r\n";
    let reply = one(addr, raw).await;
    assert_eq!(reply.status, 503);
    assert_eq!(reply.header("upgrade"), None);
    assert_eq!(up.accepts(), 0);
}

#[tokio::test]
async fn monitor_mode_still_answers_503() {
    let up = http_upstream().await;
    let mut a = app("m", free_port(), &format!("http://{}", up.addr));
    a.mode = "monitor".into();
    a.maintenance = on("");
    let (h, addr) = Harness::serve(vec![a]);
    assert_eq!(one(addr, &get("/")).await.status, 503);
    assert_eq!(up.count(), 0);
    assert!(h.events().is_empty());
}

#[tokio::test]
async fn the_accept_header_picks_html_json_or_xml_with_the_message_and_end_time() {
    let end = r#","message":"Back at <nine> & \"ten\"","end_time":"2099-12-31T23:59:59Z""#;
    let (_h, addr, _up) = serve(on(end)).await;

    let html = one(
        addr,
        &with_accept("text/html,application/xhtml+xml,*/*;q=0.8"),
    )
    .await;
    assert_eq!(
        html.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert!(
        html.text()
            .contains("Back at &lt;nine&gt; &amp; &#34;ten&#34;"),
        "{}",
        html.text()
    );
    assert!(html.text().contains(r#"datetime="2099-12-31T23:59:59Z""#));
    let retry: u64 = html
        .header("retry-after")
        .expect("Retry-After")
        .parse()
        .unwrap();
    assert!(retry > 365 * 86_400, "{retry}");

    let json = one(addr, &with_accept("application/json")).await;
    assert_eq!(json.status, 503);
    assert_eq!(
        json.header("content-type"),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(json.header("cache-control"), Some("no-store"));
    assert!(json.header("retry-after").is_some());
    assert!(
        json.text()
            .contains(r##""message": "Back at \u003cnine\u003e \u0026 \"ten\"""##),
        "{}",
        json.text()
    );
    assert!(
        json.text()
            .contains(r#""expected_end": "2099-12-31T23:59:59Z""#),
        "{}",
        json.text()
    );

    let xml = one(addr, &with_accept("text/xml")).await;
    assert_eq!(
        xml.header("content-type"),
        Some("application/xml; charset=utf-8")
    );
    assert!(
        xml.text()
            .contains("<expected_end>2099-12-31T23:59:59Z</expected_end>")
    );
    assert!(
        xml.text()
            .contains("Back at &lt;nine&gt; &amp; &quot;ten&quot;"),
        "{}",
        xml.text()
    );

    let anything = one(addr, &with_accept("*/*")).await;
    assert_eq!(
        anything.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        one(addr, &get("/")).await.header("content-type"),
        Some("text/html; charset=utf-8")
    );
}

#[tokio::test]
async fn a_past_end_time_sends_no_retry_after_and_shows_no_time() {
    let (_h, addr, _up) = serve(on(r#","end_time":"2020-01-01T00:00:00Z""#)).await;
    let json = one(addr, &with_accept("application/json")).await;
    assert_eq!(json.status, 503);
    assert_eq!(json.header("retry-after"), None);
    assert!(
        json.text().contains(r#""expected_end": """#),
        "{}",
        json.text()
    );
}

#[tokio::test]
async fn custom_html_replaces_the_page_for_html_clients_only() {
    let custom = r#","message":"Back at nine.","custom_html":"<h1>Closed</h1>{{WAFIO_MESSAGE}}""#;
    let (_h, addr, _up) = serve(on(custom)).await;
    assert_eq!(
        one(addr, &get("/")).await.text(),
        "<h1>Closed</h1>Back at nine."
    );
    let json = one(addr, &with_accept("application/json")).await;
    assert!(json.text().contains(r#""maintenance": true"#) && !json.text().contains("Closed"));
}

#[tokio::test]
async fn an_allowed_ip_reaches_the_upstream_and_others_do_not() {
    let (_h, addr, up) = serve(on(r#","allow_ips":["203.0.113.7","127.0.0.0/8"]"#)).await;
    let reply = one(addr, &get("/home")).await;
    assert_eq!((reply.status, up.count()), (200, 1));

    let (_h, addr, up) = serve(on(r#","allow_ips":["203.0.113.7","10.0.0.0/8"]"#)).await;
    assert_eq!(one(addr, &get("/home")).await.status, 503);
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn the_client_ip_after_trusted_proxy_handling_is_the_one_matched() {
    let up = http_upstream().await;
    let mut a = app("m", free_port(), &format!("http://{}", up.addr));
    a.proxy_config = br#"{"trust_forwarded":true,"trusted_proxies":["127.0.0.1"]}"#.to_vec();
    a.maintenance = on(r#","allow_ips":["203.0.113.9"]"#);
    let (_h, addr) = Harness::serve(vec![a]);

    let named = b"GET / HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n";
    assert_eq!(one(addr, named).await.status, 200);
    assert_eq!(up.last().header("x-real-ip"), Some("203.0.113.9"));

    let other = b"GET / HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: 203.0.113.10\r\n\r\n";
    assert_eq!(one(addr, other).await.status, 503);
    assert_eq!(up.count(), 1);

    // The peer 127.0.0.1 is not listed, so it gets the page when it names no client.
    assert_eq!(one(addr, &get("/")).await.status, 503);
}

#[tokio::test]
async fn ipv6_clients_and_the_edges_of_a_range_are_matched() {
    let up = http_upstream().await;
    let mut a = app("m", free_port(), &format!("http://{}", up.addr));
    a.proxy_config = br#"{"trust_forwarded":true,"trusted_proxies":["127.0.0.1"]}"#.to_vec();
    a.maintenance = on(r#","allow_ips":["2001:db8::/32","203.0.113.8/30"]"#);
    let (_h, addr) = Harness::serve(vec![a]);
    for (client, status) in [
        ("2001:db8::5", 200),
        ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 200),
        ("2001:db9::5", 503),
        ("203.0.113.8", 200),
        ("203.0.113.11", 200),
        ("203.0.113.7", 503),
        ("203.0.113.12", 503),
    ] {
        let raw = format!("GET / HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: {client}\r\n\r\n");
        assert_eq!(one(addr, raw.as_bytes()).await.status, status, "{client}");
    }
    assert_eq!(up.count(), 4);
}

#[tokio::test]
async fn the_connection_stays_open_after_a_maintenance_answer_when_no_body_follows() {
    let (_h, addr, up) = serve(on(r#","allow_paths":["/ok"]"#)).await;
    let mut c = Client::connect(addr).await.unwrap();
    assert_eq!(c.send(&get("/shop")).await.unwrap().status, 503);
    let posted = c
        .send(b"POST /empty HTTP/1.1\r\nHost: app.test\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    assert_eq!((posted.status, posted.header("connection")), (503, None));
    assert_eq!(c.send(&get("/shop")).await.unwrap().status, 503);
    assert_eq!(c.send(&get("/ok")).await.unwrap().status, 200);
    assert_eq!(up.count(), 1);
    assert!(up.last().line.starts_with("GET /ok "), "{}", up.last().line);
}

/// The body of a refused request is neither read nor drained for long, so its connection ends
/// with the answer.
#[tokio::test]
async fn a_post_with_a_body_gets_connection_close_and_the_body_never_reaches_the_upstream() {
    let (_h, addr, up) = serve(on(r#","allow_paths":["/ok"]"#)).await;
    let mut c = Client::connect(addr).await.unwrap();
    let posted = c
        .send(&post("/upload", "text/plain", b"read and dropped"))
        .await
        .unwrap();
    assert_eq!(
        (posted.status, posted.header("connection")),
        (503, Some("close"))
    );
    assert!(
        at_eof(&mut c.0).await,
        "the connection ends with the answer"
    );
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn a_huge_upload_gets_503_from_the_head_alone_not_413() {
    let up = http_upstream().await;
    let mut a = app("m", free_port(), &format!("http://{}", up.addr));
    a.proxy_config = br#"{"max_body_bytes":1024}"#.to_vec();
    a.maintenance = on("");
    let (_h, addr) = Harness::serve(vec![a]);

    // Only the head is sent: the answer cannot have waited for 100 MiB.
    let mut c = Client::connect(addr).await.unwrap();
    let reply = c
        .send(b"POST /upload HTTP/1.1\r\nHost: app.test\r\nContent-Length: 104857600\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        (reply.status, reply.header("connection")),
        (503, Some("close"))
    );
    assert!(at_eof(&mut c.0).await);

    // A body over the limit that does arrive is still answered 503 and never forwarded.
    let mut c = Client::connect(addr).await.unwrap();
    let mut raw =
        b"POST /upload HTTP/1.1\r\nHost: app.test\r\nContent-Length: 65536\r\n\r\n".to_vec();
    raw.extend(std::iter::repeat_n(b'x', 65536));
    let reply = c.send(&raw).await.unwrap();
    assert_eq!(
        (reply.status, reply.header("connection")),
        (503, Some("close"))
    );
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn expect_100_continue_gets_the_final_503_without_a_100() {
    let (_h, addr, up) = serve(on("")).await;
    for length in ["10", "0"] {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(
            format!("POST /upload HTTP/1.1\r\nHost: app.test\r\nExpect: 100-continue\r\nContent-Length: {length}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut first = [0u8; 12];
        tokio::time::timeout(std::time::Duration::from_secs(2), s.read_exact(&mut first))
            .await
            .expect("an answer")
            .unwrap();
        assert_eq!(&first, b"HTTP/1.1 503", "Content-Length: {length}");
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).await.unwrap();
        let rest = String::from_utf8_lossy(&rest);
        assert!(!rest.contains("100 Continue"), "{rest}");
        assert!(rest.contains("Connection: close\r\n"), "{rest}");
    }
    assert_eq!(up.accepts(), 0);
}

#[tokio::test]
async fn a_chunked_upload_gets_503_and_the_connection_closes() {
    let (_h, addr, up) = serve(on("")).await;
    let mut c = Client::connect(addr).await.unwrap();
    let reply = c
        .send(b"POST /upload HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        (reply.status, reply.header("connection")),
        (503, Some("close"))
    );
    assert!(at_eof(&mut c.0).await);
    // The head alone is enough: no chunk is sent at all.
    let mut c = Client::connect(addr).await.unwrap();
    let reply = c
        .send(b"POST /upload HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(
        (reply.status, reply.header("connection")),
        (503, Some("close"))
    );
    settle().await;
    assert_eq!((up.count(), up.accepts()), (0, 0));
}

#[tokio::test]
async fn pipelined_requests_without_a_body_are_all_answered() {
    let (_h, addr, _up) = serve(on("")).await;
    let mut c = Client::connect(addr).await.unwrap();
    let mut raw = get("/a");
    raw.extend(get("/b"));
    c.0.get_mut().write_all(&raw).await.unwrap();
    for _ in 0..2 {
        let reply = read_reply(&mut c.0).await.unwrap();
        assert_eq!((reply.status, reply.header("connection")), (503, None));
    }
    assert_eq!(c.send(&get("/c")).await.unwrap().status, 503);
}

#[tokio::test]
async fn what_is_pipelined_behind_a_body_is_dropped() {
    let (_h, addr, up) = serve(on("")).await;
    let mut c = Client::connect(addr).await.unwrap();
    let mut raw = post("/upload", "text/plain", b"body");
    raw.extend(get("/after"));
    c.0.get_mut().write_all(&raw).await.unwrap();
    let reply = read_reply(&mut c.0).await.unwrap();
    assert_eq!(
        (reply.status, reply.header("connection")),
        (503, Some("close"))
    );
    assert!(at_eof(&mut c.0).await, "no second answer");
    assert_eq!(up.count(), 0);
}

/// A request hidden in a body, framed either way (Content-Length and chunked at once, or one of
/// them), is never parsed: it would go to an allowed path if it were.
#[tokio::test]
async fn a_request_hidden_in_a_refused_body_is_never_served() {
    let (_h, addr, up) = serve(on(r#","allow_paths":["/ok"]"#)).await;
    let hidden = "GET /ok HTTP/1.1\r\nHost: app.test\r\n\r\n";
    for framing in [
        format!("Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{hidden}"),
        format!("Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n{hidden}"),
        format!("Content-Length: {}\r\n\r\n{hidden}", hidden.len()),
    ] {
        let mut c = Client::connect(addr).await.unwrap();
        let raw = format!("POST /upload HTTP/1.1\r\nHost: app.test\r\n{framing}");
        c.0.get_mut().write_all(raw.as_bytes()).await.unwrap();
        let reply = read_reply(&mut c.0).await.unwrap();
        assert_eq!(
            (reply.status, reply.header("connection")),
            (503, Some("close")),
            "{framing}"
        );
        assert!(at_eof(&mut c.0).await, "no second answer: {framing}");
    }
    settle().await;
    assert_eq!((up.count(), up.accepts()), (0, 0));
}

#[tokio::test]
async fn an_allowed_ip_posts_through_with_its_body_intact() {
    let up = http_upstream().await;
    let mut a = app("m", free_port(), &format!("http://{}", up.addr));
    a.maintenance = on(r#","allow_ips":["127.0.0.1"]"#);
    let (_h, addr) = Harness::serve(vec![a]);
    let body = vec![b'z'; 100_000];
    let reply = one(addr, &post("/upload", "application/octet-stream", &body)).await;
    assert_eq!((reply.status, reply.header("connection")), (200, None));
    assert_eq!(up.last().body, body);
}

#[tokio::test]
async fn an_allowed_path_posts_through_with_its_body_intact() {
    let (_h, addr, up) = serve(on(r#","allow_paths":["/hook"]"#)).await;
    let reply = one(
        addr,
        &post("/hook/stripe", "application/json", br#"{"a":1}"#),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(up.last().body, br#"{"a":1}"#);
    assert_eq!(
        one(addr, &post("/other", "application/json", b"{}"))
            .await
            .status,
        503
    );
    assert_eq!(up.count(), 1);
}

fn with_origin(method: &str, origin: &str, extra: &str) -> Vec<u8> {
    format!("{method} /api HTTP/1.1\r\nHost: app.test\r\nOrigin: {origin}\r\n{extra}\r\n")
        .into_bytes()
}

#[tokio::test]
async fn a_browser_app_on_another_origin_can_read_the_answer() {
    let (_h, addr, up) = serve(on(
        r#","message":"Back soon","end_time":"2099-12-31T23:59:59Z""#,
    ))
    .await;
    for raw in [
        with_origin("GET", "https://shop.example", "Accept: application/json\r\n"),
        b"POST /api HTTP/1.1\r\nHost: app.test\r\nOrigin: https://shop.example\r\nAccept: application/json\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi".to_vec(),
    ] {
        let reply = one(addr, &raw).await;
        assert_eq!(reply.status, 503);
        assert_eq!(
            reply.header("access-control-allow-origin"),
            Some("https://shop.example")
        );
        assert_eq!(reply.header("access-control-allow-credentials"), Some("true"));
        assert_eq!(reply.header("access-control-expose-headers"), Some("Retry-After"));
        assert_eq!(reply.header("vary"), Some("Origin"));
        assert!(reply.header("retry-after").is_some());
        assert!(reply.text().contains(r#""message": "Back soon""#), "{}", reply.text());
        assert_eq!(reply.header("set-cookie"), None);
    }
    // `null` is what a sandboxed frame or a local file sends.
    let reply = one(addr, &with_origin("GET", "null", "")).await;
    assert_eq!(reply.header("access-control-allow-origin"), Some("null"));
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn a_request_without_an_origin_gets_only_vary() {
    let (_h, addr, _up) = serve(on("")).await;
    let reply = one(addr, &get("/")).await;
    assert_eq!(reply.header("vary"), Some("Origin"));
    for name in [
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-expose-headers",
    ] {
        assert_eq!(reply.header(name), None, "{name}");
    }
}

#[tokio::test]
async fn a_preflight_is_answered_with_204_and_never_reaches_the_upstream() {
    let (_h, addr, up) = serve(on("")).await;
    let before = MAINTENANCE_RESPONSES.load(Ordering::SeqCst);
    let reply = one(
        addr,
        &with_origin(
            "OPTIONS",
            "https://shop.example",
            "Access-Control-Request-Method: PUT\r\nAccess-Control-Request-Headers: content-type,x-token\r\n",
        ),
    )
    .await;
    assert_eq!(reply.status, 204);
    assert!(reply.body.is_empty());
    for (name, want) in [
        ("access-control-allow-origin", "https://shop.example"),
        ("access-control-allow-methods", "PUT"),
        ("access-control-allow-headers", "content-type,x-token"),
        ("access-control-max-age", "0"),
        (
            "vary",
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        ),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
    ] {
        assert_eq!(reply.header(name), Some(want), "{name}");
    }
    assert_eq!(reply.header("access-control-allow-credentials"), None);
    assert_eq!(reply.header("content-length"), None);
    assert!(
        MAINTENANCE_RESPONSES.load(Ordering::SeqCst) > before,
        "counted"
    );
    // No requested headers: none allowed.
    let plain = one(
        addr,
        &with_origin("OPTIONS", "null", "Access-Control-Request-Method: GET\r\n"),
    )
    .await;
    assert_eq!(plain.status, 204);
    assert_eq!(plain.header("access-control-allow-headers"), None);
    settle().await;
    assert_eq!((up.count(), up.accepts()), (0, 0));
}

#[tokio::test]
async fn the_preflight_keeps_the_connection_open_and_drops_one_with_a_body() {
    let (_h, addr, _up) = serve(on("")).await;
    let mut c = Client::connect(addr).await.unwrap();
    let preflight = with_origin(
        "OPTIONS",
        "https://a.example",
        "Access-Control-Request-Method: GET\r\n",
    );
    assert_eq!(c.send(&preflight).await.unwrap().status, 204);
    assert_eq!(c.send(&preflight).await.unwrap().status, 204);
    assert_eq!(c.send(&get("/")).await.unwrap().status, 503);
}

#[tokio::test]
async fn a_bad_origin_or_preflight_gets_no_cors_approval() {
    let (_h, addr, up) = serve(on("")).await;
    let long = format!("https://{}.example", "a".repeat(260));
    for origin in [
        "https://a.example/path",
        "https://a.example,https://b.example",
        "https://a.example?x",
        "https://user@a.example",
        "https://",
        "ftp",
        "javascript:alert(1)",
        "1https://a.example",
        long.as_str(),
    ] {
        let reply = one(addr, &with_origin("GET", origin, "")).await;
        assert_eq!(reply.status, 503, "{origin}");
        assert_eq!(
            reply.header("access-control-allow-origin"),
            None,
            "{origin}"
        );
        assert_eq!(reply.header("vary"), Some("Origin"), "{origin}");
        // A preflight with it is the ordinary 503.
        let pre = one(
            addr,
            &with_origin("OPTIONS", origin, "Access-Control-Request-Method: GET\r\n"),
        )
        .await;
        assert_eq!(pre.status, 503, "{origin}");
        assert_eq!(pre.header("access-control-allow-methods"), None, "{origin}");
    }
    // Two Origin lines are not believed.
    let twice = b"GET / HTTP/1.1\r\nHost: app.test\r\nOrigin: https://a.example\r\nOrigin: https://b.example\r\n\r\n";
    assert_eq!(
        one(addr, twice).await.header("access-control-allow-origin"),
        None
    );
    // A method that is not a token, a list that is not header names and commas.
    let long_method = "A".repeat(33);
    for (method, headers, status) in [
        ("GE T", "", 503),
        (long_method.as_str(), "", 503),
        ("GET", "x-a b", 204),
        ("GET", "x-a;q", 204),
    ] {
        let reply = one(
            addr,
            &with_origin(
                "OPTIONS",
                "https://a.example",
                &format!("Access-Control-Request-Method: {method}\r\nAccess-Control-Request-Headers: {headers}\r\n"),
            ),
        )
        .await;
        assert_eq!(reply.status, status, "{method} / {headers}");
        assert_eq!(
            reply.header("access-control-allow-headers"),
            None,
            "{method} / {headers}"
        );
    }
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn a_preflight_from_an_allowed_client_reaches_the_upstream_unchanged() {
    let up = http_upstream().await;
    let mut a = app("m", free_port(), &format!("http://{}", up.addr));
    a.maintenance = on(r#","allow_ips":["127.0.0.1"]"#);
    let (_h, addr) = Harness::serve(vec![a]);
    let reply = one(
        addr,
        &with_origin(
            "OPTIONS",
            "https://a.example",
            "Access-Control-Request-Method: PUT\r\n",
        ),
    )
    .await;
    assert_eq!(reply.status, 200, "the upstream's answer");
    assert_eq!(reply.header("x-up"), Some("1"));
    for name in [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "vary",
    ] {
        assert_eq!(reply.header(name), None, "{name}");
    }
    assert_eq!(up.count(), 1);
    assert_eq!(
        up.last().header("access-control-request-method"),
        Some("PUT")
    );
}

#[tokio::test]
async fn an_app_that_is_not_in_maintenance_proxies_a_preflight_as_before() {
    let up = http_upstream().await;
    for maintenance in [&b""[..], br#"{"enabled":false}"#] {
        let mut a = app("m", free_port(), &format!("http://{}", up.addr));
        a.maintenance = maintenance.to_vec();
        let (_h, addr) = Harness::serve(vec![a]);
        let reply = one(
            addr,
            &with_origin(
                "OPTIONS",
                "https://a.example",
                "Access-Control-Request-Method: PUT\r\n",
            ),
        )
        .await;
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("access-control-allow-origin"), None);
        assert_eq!(reply.header("vary"), None);
    }
    assert_eq!(up.count(), 2);
}

#[tokio::test]
async fn a_fastcgi_app_answers_without_contacting_the_responder() {
    let responder = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fcgi = responder.local_addr().unwrap();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        while responder.accept().await.is_ok() {
            count.fetch_add(1, Ordering::SeqCst);
        }
    });
    let mut a = app("php", free_port(), &format!("fcgi://{fcgi}"));
    a.fcgi_doc_root = "/srv".into();
    a.maintenance = on("");
    let (h, addr) = Harness::serve(vec![a]);
    assert_eq!(one(addr, &get("/index.php")).await.status, 503);
    settle().await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert!(h.events().is_empty());
}

#[tokio::test]
async fn a_forwarded_address_from_an_untrusted_peer_is_not_believed() {
    let (_h, addr, up) = serve(on(r#","allow_ips":["203.0.113.9"]"#)).await;
    let spoofed = b"GET / HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n";
    assert_eq!(one(addr, spoofed).await.status, 503);
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn an_allowed_path_and_what_lies_below_it_reach_the_upstream() {
    let (_h, addr, up) = serve(on(r#","allow_paths":["/healthz","/static/","/hook;v=1"]"#)).await;
    for (path, status) in [
        ("/hook;v=1", 200),
        ("/hook;v=1/stripe", 200),
        ("/hook;v=2", 503),
        ("/healthz", 200),
        ("/healthz/x", 200),
        ("/healthz?probe=1", 200),
        ("/%68ealthz", 200),
        ("/static/app.js", 200),
        ("/healthzx", 503),
        ("/healthz/../admin", 503),
        ("/healthz/..;/admin", 503),
        ("/healthz/x;v=1", 200),
        ("/Healthz", 503),
        ("/static", 503),
        ("/admin", 503),
        ("/", 503),
    ] {
        assert_eq!(one(addr, &get(path)).await.status, status, "{path}");
    }
    assert_eq!(up.count(), 8, "only the allowed paths reached the upstream");
}

#[tokio::test]
async fn allowed_traffic_still_goes_through_the_whole_pipeline() {
    let up = http_upstream().await;
    let mut a = app("m", free_port(), &format!("http://{}", up.addr));
    a.analysis =
        analysis_setup(r#"{"l7_flood":{"enabled":true,"max_requests":1,"window_sec":60}}"#);
    a.maintenance = on(r#","allow_ips":["127.0.0.1"]"#);
    let (h, addr) = Harness::serve(vec![a]);
    assert_eq!(one(addr, &get("/")).await.status, 200);
    let second = one(addr, &get("/")).await;
    assert!(
        second.status != 200 && second.status != 503,
        "{}",
        second.status
    );
    assert_eq!(s(&h.last_event().action), "block");
}

#[tokio::test]
async fn a_client_the_rules_would_block_gets_the_page_without_inspection() {
    let up = http_upstream().await;
    let mut a = app("m", free_port(), &format!("http://{}", up.addr));
    a.analysis =
        analysis_setup(r#"{"l7_flood":{"enabled":true,"max_requests":1,"window_sec":60}}"#);
    a.maintenance = on("");
    let (h, addr) = Harness::serve(vec![a]);
    for _ in 0..3 {
        assert_eq!(one(addr, &get("/?q=1")).await.status, 503);
    }
    settle().await;
    assert!(h.events().is_empty(), "{:?}", h.events());
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn off_means_the_site_and_a_reload_switches_it_on_the_running_listener() {
    let up = http_upstream().await;
    let port = free_port();
    let spec = |maintenance: &[u8]| {
        let mut a = app("m", port, &format!("http://{}", up.addr));
        a.maintenance = maintenance.to_vec();
        a
    };
    let (h, addr) = Harness::serve(vec![spec(br#"{"enabled":false,"message":"x"}"#)]);
    // One kept-alive connection sees both switches: a reload drops no connection.
    let mut c = Client::connect(addr).await.unwrap();
    assert_eq!(c.send(&get("/")).await.unwrap().status, 200);
    h.proxy.apply(vec![spec(&on(""))]).unwrap();
    assert_eq!(c.send(&get("/")).await.unwrap().status, 503);
    h.proxy.apply(vec![spec(b"")]).unwrap();
    assert_eq!(c.send(&get("/")).await.unwrap().status, 200);
    assert_eq!(up.count(), 2);
}

#[tokio::test]
async fn the_answers_are_counted_and_the_pipeline_records_nothing() {
    let (h, addr, up) = serve(on(r#","allow_paths":["/ok"]"#)).await;
    let before = MAINTENANCE_RESPONSES.load(Ordering::SeqCst);
    for _ in 0..3 {
        assert_eq!(one(addr, &get("/")).await.status, 503);
    }
    // Other tests of this file run at the same time and count too.
    assert!(MAINTENANCE_RESPONSES.load(Ordering::SeqCst) >= before + 3);
    assert_eq!(one(addr, &get("/ok")).await.status, 200);
    settle().await;
    let events = h.events();
    assert_eq!(
        events.len(),
        1,
        "only the allowed request left a decision: {events:?}"
    );
    assert_eq!(s(&events[0].uri), "/ok");
    assert_eq!(up.count(), 1);
}
