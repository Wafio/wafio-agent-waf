//! Black-box: what the upstream receives and what the client gets back on the allow path,
//! body limits (400), header block limit (431), upstream errors.

mod common;
#[path = "common/fake_engine.rs"]
mod fake_engine;

use common::*;

#[tokio::test]
async fn forwards_the_request_and_the_answer() {
    let up = http_upstream_with(
        "Server: up-srv\r\nX-Drop: 1\r\nConnection: keep-alive\r\n",
        b"hello",
    )
    .await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.proxy_config = br#"{"req_headers":{"add":{"x-added":"v"},"remove":["X-Secret"]},"resp_headers":{"add":{"x-resp":"r"},"remove":["X-Drop"]}}"#.to_vec();
    let (h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let raw = b"GET /a//b%20c/./d?q=1&z=%41 HTTP/1.1\r\nHost: App.Test\r\nUser-Agent: ua/1\r\nX-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\nConnection: keep-alive, X-Hop\r\nX-Hop: gone\r\nUpgrade: h2c\r\nX-Secret: s\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n";
    let resp = one(proxy, raw).await;
    assert_eq!((resp.status, resp.text().as_str()), (200, "hello"));
    assert_eq!(resp.header("server"), Some("up-srv"));
    assert_eq!(resp.header("x-resp"), Some("r"));
    assert_eq!(resp.header("x-drop"), None);
    let seen = up.last();
    // The decoded, dot-resolved path re-quoted, raw query kept.
    assert_eq!(seen.line, "GET /a/b%20c/d?q=1&z=%41 HTTP/1.1");
    // The URI host is lower-cased; preserve mode keeps it.
    assert_eq!(seen.header("host"), Some("app.test"));
    // An untrusted peer's forwarded headers never reach the upstream.
    assert_eq!(seen.all("x-forwarded-for"), vec!["127.0.0.1"]);
    assert_eq!(seen.all("x-real-ip"), vec!["127.0.0.1"]);
    assert_eq!(seen.header("x-forwarded-host"), Some("app.test"));
    assert_eq!(seen.header("x-forwarded-proto"), Some("http"));
    for gone in ["x-hop", "upgrade", "x-secret"] {
        assert_eq!(seen.header(gone), None, "{gone} forwarded");
    }
    assert_eq!(seen.header("x-added"), Some("v"));
    assert_eq!(seen.header("cookie"), Some("a=1; b=2"));
    assert_eq!(seen.header("user-agent"), Some("ua/1"));
    // Clean allows are recorded too (the sink samples nothing).
    let ev = h.last_event();
    assert_eq!(
        (s(&ev.action), s(&ev.remote_addr), s(&ev.uri)),
        ("allow", "127.0.0.1", "/a//b%20c/./d?q=1&z=%41")
    );
}

/// The underscore spellings of the client IP headers and `Proxy` (httpoxy) never reach an HTTP
/// upstream, where a backend that treats `_` like `-` would read the client's own address. The
/// operator's `request_headers` still apply after the agent's values.
#[tokio::test]
async fn underscore_client_ip_headers_and_proxy_never_reach_the_upstream() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.proxy_config = br#"{"req_headers":{"add":{"x-op":"1"}}}"#.to_vec();
    let (_h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let raw = b"GET / HTTP/1.1\r\nHost: app.test\r\nX_Forwarded_For: 6.6.6.6\r\nx_real_ip: 7.7.7.7\r\nX-Real_IP: 8.8.8.8\r\nX_FORWARDED-FOR: 9.9.9.9\r\nX-Forwarded-For: 5.5.5.5\r\nProxy: http://evil.example:8080\r\nproxy: x\r\nX-Proxy: kept\r\nUser-Agent: t\r\n\r\n";
    assert_eq!(one(proxy, raw).await.status, 200);
    let seen = up.last();
    for gone in [
        "x_forwarded_for",
        "x_real_ip",
        "x-real_ip",
        "x_forwarded-for",
        "proxy",
    ] {
        assert!(
            seen.all(gone).is_empty(),
            "{gone} forwarded: {:?}",
            seen.all(gone)
        );
    }
    assert_eq!(seen.all("x-forwarded-for"), vec!["127.0.0.1"]);
    assert_eq!(seen.all("x-real-ip"), vec!["127.0.0.1"]);
    assert_eq!(seen.header("x-proxy"), Some("kept"));
    assert_eq!(seen.header("user-agent"), Some("t"));
    assert_eq!(seen.header("x-op"), Some("1"));
}

#[tokio::test]
async fn trusted_proxy_names_the_client_and_host_modes() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.proxy_config = br#"{"trust_forwarded":true,"trusted_proxies":["127.0.0.1"],"host_header":{"mode":"upstream"}}"#.to_vec();
    let (h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let raw = b"GET / HTTP/1.1\r\nHost: app.test\r\nX-Forwarded-For: 203.0.113.9\r\nX-Forwarded-Proto: https\r\n\r\n";
    assert_eq!(one(proxy, raw).await.status, 200);
    let seen = up.last();
    assert_eq!(seen.all("x-forwarded-for"), vec!["203.0.113.9, 127.0.0.1"]);
    assert_eq!(seen.header("x-real-ip"), Some("203.0.113.9"));
    assert_eq!(seen.header("x-forwarded-proto"), Some("https"));
    assert_eq!(seen.header("host"), Some(up.addr.to_string().as_str()));
    assert_eq!(s(&h.last_event().remote_addr), "203.0.113.9");
}

#[tokio::test]
async fn body_limit_is_400_and_never_forwarded() {
    let up = http_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.proxy_config = br#"{"max_body_bytes":1024}"#.to_vec();
    let (h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let resp = one(proxy, &post("/x", "text/plain", &[b'a'; 1025])).await;
    assert_eq!(
        (resp.status, resp.text().as_str(), resp.header("connection")),
        (400, "Error when parsing request", Some("close"))
    );
    // Chunked over the limit too.
    let mut raw = b"POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..3 {
        raw.extend_from_slice(b"200\r\n");
        raw.extend_from_slice(&[b'b'; 512]);
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    assert_eq!(one(proxy, &raw).await.status, 400);
    settle().await;
    assert_eq!(up.accepts(), 0);
    assert!(
        h.events().is_empty(),
        "fasthttp answers before the handler: no decision"
    );
    let resp = one(proxy, &post("/x", "text/plain", &[b'a'; 1024])).await;
    assert_eq!(resp.status, 200);
    assert_eq!(up.last().body.len(), 1024);
}

#[tokio::test]
async fn oversized_header_block_is_431() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let raw = format!(
        "GET / HTTP/1.1\r\nHost: a\r\nCookie: {}\r\n\r\n",
        "c".repeat(17 * 1024)
    );
    let resp = one(proxy, raw.as_bytes()).await;
    assert_eq!(
        (resp.status, resp.text().as_str()),
        (431, "Too big request header")
    );
    assert_eq!(up.accepts(), 0);
}

#[tokio::test]
async fn upstream_down_is_502_and_recorded() {
    let port = free_port();
    let (h, proxy) = Harness::serve_with_fake_engine(vec![app(
        "a1",
        port,
        &format!("http://127.0.0.1:{}", free_port()),
    )]);
    let resp = one(proxy, &get("/")).await;
    assert_eq!(
        (resp.status, resp.text().as_str()),
        (502, r#"{"error":"upstream unavailable"}"#)
    );
    assert_eq!(s(&h.last_event().action), "upstream_error");
}

#[tokio::test]
async fn invalid_path_escape_is_400_in_block_mode_and_recorded_in_monitor() {
    let up = http_upstream().await;
    let (pb, pm) = (free_port(), free_port());
    let mut m = app("mon", pm, &format!("http://{}", up.addr));
    m.mode = "monitor".into();
    let (h, block) =
        Harness::serve_with_fake_engine(vec![app("blk", pb, &format!("http://{}", up.addr)), m]);
    let resp = one(block, &get("/a%zzb")).await;
    assert_eq!(resp.status, 400);
    let ev = h.last_event();
    assert_eq!(
        (s(&ev.action), s(&ev.match_detail), s(&ev.analyze_method)),
        ("block", "invalid_path_encoding", "policy")
    );
    assert_eq!(ev.categories, vec![b"ProtocolAttack".to_vec()]);
    assert_eq!(up.accepts(), 0);
    let mon = format!("127.0.0.1:{pm}").parse().unwrap();
    assert_eq!(one(mon, &get("/a%zzb")).await.status, 200);
    let ev = h.last_event();
    assert_eq!(
        (s(&ev.action), s(&ev.match_detail), s(&ev.match_source)),
        ("monitor", "invalid_path_encoding", "path")
    );
    // An invalid escape is kept literally while the rest is decoded.
    assert_eq!(up.last().line, "GET /a%25zzb HTTP/1.1");
}

#[tokio::test]
async fn keepalive_reuses_one_upstream_connection() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let mut c = Client::connect(proxy).await.unwrap();
    for _ in 0..5 {
        assert_eq!(
            c.send(&post("/u", "application/json", br#"{"a":1}"#))
                .await
                .unwrap()
                .status,
            200
        );
    }
    assert_eq!(up.accepts(), 1);
    // Content-Type and Content-Length are sent; the body arrives whole.
    let seen = up.last();
    assert_eq!(
        (seen.header("content-type"), seen.body.as_slice()),
        (Some("application/json"), &br#"{"a":1}"#[..])
    );
}

#[tokio::test]
async fn slow_large_body_is_read_whole_before_the_upstream_is_contacted() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let body: Vec<u8> = (0..(1 << 20)).map(|i| b'a' + (i % 23) as u8).collect();
    let raw = post("/upload", "application/octet-stream", &body);
    let mut c = Client::connect(proxy).await.unwrap();
    use tokio::io::AsyncWriteExt;
    let parts: Vec<_> = raw.chunks(256 * 1024).collect();
    for (i, part) in parts.iter().enumerate() {
        c.0.get_mut().write_all(part).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if i + 1 < parts.len() {
            assert_eq!(
                up.accepts(),
                0,
                "upstream contacted before the body was complete"
            );
        }
    }
    let resp = read_reply(&mut c.0).await.unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(up.last().body, body);
}

#[tokio::test]
async fn expect_100_continue_is_answered_before_the_body() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let mut c = Client::connect(proxy).await.unwrap();
    use tokio::io::AsyncWriteExt;
    c.0.get_mut()
        .write_all(
            b"POST /e HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
        )
        .await
        .unwrap();
    let cont = read_reply(&mut c.0).await.unwrap();
    assert_eq!(cont.status, 100);
    c.0.get_mut().write_all(b"hello").await.unwrap();
    let r = read_reply(&mut c.0).await.unwrap();
    // The 100 is not the final answer: the connection stays open and carries no Connection line
    // (Pingora closes a connection whose response is written before the body is read).
    assert_eq!((r.status, r.header("connection")), (200, None));
    assert_eq!(c.send(&get("/next")).await.unwrap().status, 200);
    let seen = up.last();
    assert_eq!(seen.line, "GET /next HTTP/1.1");
    // Expect is kept (it is not a hop-by-hop header the proxy strips).
    let post = up.seen.lock().unwrap()[0].clone();
    assert_eq!(
        (post.body.as_slice(), post.header("expect")),
        (&b"hello"[..], Some("100-continue"))
    );
}

/// No `Connection` line is written on a keep-alive HTTP/1.1 answer (Pingora's own writer always
/// adds one), `Connection: close` when the connection ends and `keep-alive` for HTTP/1.0;
/// pipelined requests are all answered.
#[tokio::test]
async fn connection_header_by_answer_kind() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let mut c = Client::connect(proxy).await.unwrap();
    let r = c.send(&get("/a")).await.unwrap();
    assert_eq!((r.status, r.header("connection")), (200, None));
    assert!(
        r.header("date").is_some_and(|d| d.ends_with(" GMT")),
        "{:?}",
        r.headers
    );
    // A blocked request (policy page) is answered the same way.
    let r = c.send(&get("/search?q=wafio-test-sql")).await.unwrap();
    assert_eq!((r.status, r.header("connection")), (403, None));
    use tokio::io::AsyncWriteExt;
    c.0.get_mut()
        .write_all(&[get("/b"), get("/c")].concat())
        .await
        .unwrap();
    for path in ["/b", "/c"] {
        let r = read_reply(&mut c.0).await.unwrap();
        assert_eq!(r.status, 200, "pipelined {path}");
    }
    assert_eq!(up.accepts(), 1);
    let r = one(
        proxy,
        b"GET /d HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!((r.status, r.header("connection")), (200, Some("close")));
    let r = one(
        proxy,
        b"GET /e HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n",
    )
    .await;
    assert_eq!(
        (r.status, r.header("connection")),
        (200, Some("keep-alive"))
    );
}

/// Every non-close `Connection` line is kept: the hop-by-hop strip reads `peek` (`close` when
/// the close flag is set, else the first line), the analysed headers carry every line, and
/// `Host` is the header as written (an absolute-form target does not validate it).
#[tokio::test]
async fn connection_lines_and_host_header_are_read_as_written() {
    const SQLI: &str = "wafio-test-sql";
    let up = http_upstream().await;
    let port = free_port();
    let (h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    // The first line names X-A, the second X-B: only X-A is hop-by-hop.
    let r = one(
        proxy,
        b"GET /a HTTP/1.1\r\nHost: a\r\nConnection: X-A\r\nConnection: X-B\r\nX-A: 1\r\nX-B: 2\r\n\r\n",
    )
    .await;
    assert_eq!(r.status, 200);
    let seen = up.last();
    assert_eq!((seen.header("x-a"), seen.header("x-b")), (None, Some("2")));
    assert_eq!(seen.header("connection"), None);
    // `keep-alive` first: the names in the second line are not stripped.
    let r = one(
        proxy,
        b"GET /a HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\nConnection: X-A\r\nX-A: 1\r\n\r\n",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(up.last().header("x-a"), Some("1"));
    // A request that is not HTTP/1.1 and lists no keep-alive has the close flag: `peek` is
    // `close`, so the names of its `Connection` line stay.
    let r = one(
        proxy,
        b"GET /a HTTP/1.0\r\nHost: a\r\nConnection: X-A\r\nX-A: 1\r\n\r\n",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(up.last().header("x-a"), Some("1"));
    // Every Connection line is scanned, not only the last one.
    let n = up.count();
    let req = format!(
        "GET /a HTTP/1.1\r\nHost: a\r\nConnection: {SQLI}\r\nConnection: keep-alive\r\n\r\n"
    );
    assert_eq!(one(proxy, req.as_bytes()).await.status, 403);
    assert_eq!(s(&h.last_event().match_source), "header:Connection");
    // The Host header is scanned as written, not the URI host the target names.
    for ver in ["1.1", "1.0"] {
        let req = format!("GET http://a/a HTTP/{ver}\r\nHost: {SQLI}\r\n\r\n");
        assert_eq!(one(proxy, req.as_bytes()).await.status, 403, "HTTP/{ver}");
        assert_eq!(s(&h.last_event().match_source), "header:Host");
    }
    assert_eq!(up.count(), n, "a blocked request reached the upstream");
}

const CT: &str = "Content-Type: text/plain; charset=utf-8";

/// The request protocol is copied to the upstream request and the upstream's protocol and
/// connection state to the answer: an HTTP/1.0 answer without `Connection: keep-alive` is written
/// as `HTTP/1.0` with `Connection: close` (last line) and the connection ends; an upstream that
/// answers HTTP/1.1 to an HTTP/1.0 keep-alive request gets `Connection: keep-alive` among the
/// headers; a body that ends with the upstream connection ends ours too.
#[tokio::test]
async fn http10_request_and_upstream_protocol_are_copied() {
    let up = raw_upstream(|seen| {
        let ok = |proto: &str| {
            format!("{proto} 200 OK\r\nContent-Length: 6\r\nSet-Cookie: b=2\r\n\r\ncookie")
                .into_bytes()
        };
        if seen.line.starts_with("GET /delim") {
            (b"HTTP/1.1 200 OK\r\n\r\nbody".to_vec(), true)
        } else if seen.line.starts_with("GET /old") && seen.line.ends_with("HTTP/1.0") {
            (ok("HTTP/1.0"), true)
        } else {
            (ok("HTTP/1.1"), false)
        }
    })
    .await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    use tokio::io::AsyncWriteExt;
    for req in [
        "GET /old HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n",
        "GET /old HTTP/1.0\r\nHost: a\r\n\r\n",
    ] {
        let mut c = Client::connect(proxy).await.unwrap();
        c.0.get_mut().write_all(req.as_bytes()).await.unwrap();
        let raw = read_raw(&mut c.0, false).await.unwrap();
        assert_eq!(
            raw,
            format!(
                "HTTP/1.0 200 OK\r\nServer: wafio-route-proxy\r\nDate: <date>\r\n{CT}\r\nContent-Length: 6\r\nSet-Cookie: b=2\r\nConnection: close\r\n\r\ncookie"
            )
        );
        assert!(at_eof(&mut c.0).await, "connection kept open");
        let seen = up.last();
        assert_eq!(
            (seen.line.as_str(), seen.header("connection")),
            ("GET /old HTTP/1.0", None)
        );
    }
    // HTTP/1.1 answer to an HTTP/1.0 keep-alive request: open, `Connection: keep-alive` before the cookies.
    let mut c = Client::connect(proxy).await.unwrap();
    for _ in 0..2 {
        c.0.get_mut()
            .write_all(b"GET /new HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n")
            .await
            .unwrap();
        let raw = read_raw(&mut c.0, false).await.unwrap();
        assert_eq!(
            raw,
            format!(
                "HTTP/1.1 200 OK\r\nServer: wafio-route-proxy\r\nDate: <date>\r\n{CT}\r\nContent-Length: 6\r\nConnection: keep-alive\r\nSet-Cookie: b=2\r\n\r\ncookie"
            )
        );
    }
    assert_eq!(up.last().line, "GET /new HTTP/1.0");
    // HTTP/1.1 request, answer delimited by the upstream closing: relayed the same way, with no length.
    let mut c = Client::connect(proxy).await.unwrap();
    c.0.get_mut().write_all(&get("/delim")).await.unwrap();
    let raw = read_raw(&mut c.0, false).await.unwrap();
    assert_eq!(
        raw,
        format!(
            "HTTP/1.1 200 OK\r\nServer: wafio-route-proxy\r\nDate: <date>\r\n{CT}\r\nConnection: close\r\n\r\nbody"
        )
    );
    assert!(at_eof(&mut c.0).await);
}

/// `Content-Length` is never written for 1xx/204/304 but the default `Content-Type` still is (the
/// upstream's length state is not 0); a HEAD answer keeps the upstream's `Content-Length`.
#[tokio::test]
async fn no_body_statuses_and_head_keep_the_upstream_length_state() {
    let up = raw_upstream(|seen| {
        let r: &[u8] = match seen.line.split(' ').nth(1) {
            Some("/204") => b"HTTP/1.1 204 No Content\r\n\r\n",
            Some("/304") => b"HTTP/1.1 304 Not Modified\r\nEtag: x\r\n\r\n",
            _ => b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12\r\n\r\n",
        };
        (r.to_vec(), false)
    })
    .await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let mut c = Client::connect(proxy).await.unwrap();
    use tokio::io::AsyncWriteExt;
    let head = "Server: wafio-route-proxy\r\nDate: <date>\r\n";
    let cases = [
        (
            "GET /204 HTTP/1.1",
            format!("HTTP/1.1 204 No Content\r\n{head}{CT}\r\n\r\n"),
        ),
        (
            "GET /304 HTTP/1.1",
            format!("HTTP/1.1 304 Not Modified\r\n{head}{CT}\r\nEtag: x\r\n\r\n"),
        ),
        (
            "HEAD /h HTTP/1.1",
            format!(
                "HTTP/1.1 200 OK\r\n{head}Content-Type: text/html\r\nContent-Length: 12\r\n\r\n"
            ),
        ),
    ];
    for (line, want) in cases {
        c.0.get_mut()
            .write_all(format!("{line}\r\nHost: a\r\n\r\n").as_bytes())
            .await
            .unwrap();
        assert_eq!(read_raw(&mut c.0, true).await.unwrap(), want, "{line}");
    }
    assert_eq!(up.accepts(), 1);
}

/// The header map the handler builds after the body read (the analysed headers, the decision's
/// `request_headers`): `Transfer-Encoding: chunked` stays (lower-cased) for a chunked body and
/// goes, with `Content-Length: 0` set, when it was empty (the swap-delete reorders the lines
/// behind it); a request without length that is not GET/HEAD has `Content-Length: 0`; the
/// upstream always gets the length of the body it is sent and never the `Transfer-Encoding`.
#[tokio::test]
async fn header_map_after_the_body_read() {
    let up = http_upstream().await;
    let port = free_port();
    let (h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let ev = |h: &Harness, k: &str| {
        let e = h.last_event();
        e.request_headers
            .get(k.as_bytes())
            .map(|v| String::from_utf8_lossy(v).into_owned())
    };
    let send =
        |tail: &'static str| format!("POST /h HTTP/1.1\r\nHost: app.test\r\n{tail}").into_bytes();
    // Chunked, not empty.
    let t =
        "Transfer-Encoding: CHUNKED\r\nX-A: 1\r\nX-A: 2\r\nX-A: 3\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    assert_eq!(one(proxy, &send(t)).await.status, 200);
    assert_eq!(ev(&h, "Transfer-Encoding").as_deref(), Some("chunked"));
    assert_eq!(ev(&h, "Content-Length"), None);
    assert_eq!(ev(&h, "X-A").as_deref(), Some("1, 2, 3"));
    let seen = up.last();
    assert_eq!(seen.header("content-length"), Some("5"));
    assert_eq!(seen.header("transfer-encoding"), None);
    assert_eq!(seen.body, b"hello");
    // Chunked, empty: no Transfer-Encoding, Content-Length 0, the last line took its place.
    let t = "Transfer-Encoding: chunked\r\nX-A: 1\r\nX-A: 2\r\nX-A: 3\r\n\r\n0\r\n\r\n";
    assert_eq!(one(proxy, &send(t)).await.status, 200);
    assert_eq!(ev(&h, "Transfer-Encoding"), None);
    assert_eq!(ev(&h, "Content-Length").as_deref(), Some("0"));
    assert_eq!(ev(&h, "X-A").as_deref(), Some("3, 1, 2"));
    assert_eq!(up.last().header("content-length"), Some("0"));
    // The cookies are collected after the swap: `c=3; a=1; b=2`.
    let t = "Transfer-Encoding: chunked\r\nCookie: a=1\r\nX-A: v\r\nCookie: b=2\r\nCookie: c=3\r\n\r\n0\r\n\r\n";
    assert_eq!(one(proxy, &send(t)).await.status, 200);
    assert_eq!(ev(&h, "Cookie").as_deref(), Some("c=3; a=1; b=2"));
    // No length at all: POST and PUT have `Content-Length: 0`, GET has none, a chunked empty GET does.
    assert_eq!(one(proxy, &send("\r\n")).await.status, 200);
    assert_eq!(ev(&h, "Content-Length").as_deref(), Some("0"));
    assert_eq!(one(proxy, &get("/h")).await.status, 200);
    assert_eq!(ev(&h, "Content-Length"), None);
    let t = b"GET /h HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    assert_eq!(one(proxy, t).await.status, 200);
    assert_eq!(ev(&h, "Content-Length").as_deref(), Some("0"));
    assert_eq!(ev(&h, "Transfer-Encoding"), None);
    assert_eq!(up.last().header("content-length"), Some("0"));
    // `identity` is not kept.
    let t = "Transfer-Encoding: identity\r\n\r\n";
    assert_eq!(one(proxy, &send(t)).await.status, 200);
    assert_eq!(ev(&h, "Transfer-Encoding"), None);
}

/// `Trailer` is held apart from the header lines: names normalised and joined with `, `, the
/// last line wins, an empty one clears it; the upstream request leaves out every line the names
/// list and carries `Trailer` after the others; the header map has it as one header.
#[tokio::test]
async fn the_trailer_header_is_normalised_and_excludes_the_lines_it_names() {
    let up = http_upstream().await;
    let port = free_port();
    let (h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let ev = |h: &Harness, k: &str| {
        h.last_event()
            .request_headers
            .get(k.as_bytes())
            .map(|v| String::from_utf8_lossy(v).into_owned())
    };
    let send = |tail: &str| {
        format!("POST /t HTTP/1.1\r\nHost: app.test\r\nContent-Length: 3\r\n{tail}\r\nabc")
            .into_bytes()
    };
    let r = one(
        proxy,
        &send("Trailer: x-a, C, ontent-Length\r\nX-A: 1\r\nX-B: 2\r\nC: 3\r\n"),
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(ev(&h, "Trailer").as_deref(), Some("X-A, C, Ontent-Length"));
    // The analysed headers still carry the named lines (only the upstream write leaves them out).
    assert_eq!(ev(&h, "X-A").as_deref(), Some("1"));
    let seen = up.last();
    assert_eq!(seen.header("trailer"), Some("X-A, C, Ontent-Length"));
    assert_eq!(seen.header("x-a"), None);
    assert_eq!(seen.header("c"), None);
    assert_eq!(seen.header("x-b"), Some("2"));
    // The last `Trailer` line wins; an empty one clears the list.
    assert_eq!(
        one(
            proxy,
            &send("Trailer: X-A\r\nTrailer: X-B\r\nX-A: 1\r\nX-B: 2\r\n")
        )
        .await
        .status,
        200
    );
    assert_eq!(ev(&h, "Trailer").as_deref(), Some("X-B"));
    let seen = up.last();
    assert_eq!((seen.header("x-a"), seen.header("x-b")), (Some("1"), None));
    assert_eq!(
        one(proxy, &send("Trailer: X-A\r\nTrailer:\r\nX-A: 1\r\n"))
            .await
            .status,
        200
    );
    assert_eq!(ev(&h, "Trailer"), None);
    let seen = up.last();
    assert_eq!(
        (seen.header("trailer"), seen.header("x-a")),
        (None, Some("1"))
    );
    // `Connection: Trailer` deletes the header (the names `peek("Connection")` returns are deleted).
    let r = one(
        proxy,
        &send("Connection: Trailer\r\nTrailer: X-A\r\nX-A: 1\r\n"),
    )
    .await;
    assert_eq!(r.status, 200);
    let seen = up.last();
    assert_eq!(
        (seen.header("trailer"), seen.header("x-a")),
        (None, Some("1"))
    );
    // A name `AddTrailerBytes` refuses is a bad request.
    assert_eq!(one(proxy, &send("Trailer: X-A,,X-B\r\n")).await.status, 400);
}

/// The status message of an upstream answer is copied byte for byte, obs-text and invalid UTF-8
/// included, and the standard text is written only when it said none; httparse (Pingora's parser)
/// drops one that holds obs-text.
#[tokio::test]
async fn upstream_status_message_bytes_are_kept() {
    let up = raw_upstream(|seen: &Seen| {
        let status: &[u8] = match seen.line.split(' ').nth(1).unwrap() {
            "/utf8" => b"200 Caf\xc3\xa9",
            "/bytes" => b"201 \xe9\xff\xfe",
            "/mixed" => b"202 Fine \xe9 thanks",
            "/empty" => b"200 ",
            "/none" => b"200",
            _ => b"200   spaced  out ",
        };
        let mut out = b"HTTP/1.1 ".to_vec();
        out.extend_from_slice(status);
        out.extend_from_slice(b"\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        (out, true)
    })
    .await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let cases: [(&str, &[u8]); 6] = [
        ("/utf8", b"HTTP/1.1 200 Caf\xc3\xa9\r\n"),
        ("/bytes", b"HTTP/1.1 201 \xe9\xff\xfe\r\n"),
        ("/mixed", b"HTTP/1.1 202 Fine \xe9 thanks\r\n"),
        ("/empty", b"HTTP/1.1 200 OK\r\n"),
        ("/none", b"HTTP/1.1 200 OK\r\n"),
        ("/spaced", b"HTTP/1.1 200   spaced  out \r\n"),
    ];
    for (path, want) in cases {
        let mut c = Client::connect(proxy).await.unwrap();
        c.0.get_mut().write_all(&get(path)).await.unwrap();
        let mut line = Vec::new();
        c.0.read_until(b'\n', &mut line).await.unwrap();
        assert_eq!(line, want, "{path}: {:?}", String::from_utf8_lossy(&line));
    }
}

/// A raw `"`, `<` or `>` in the query: the upstream client refuses such a target, so an allowed
/// request used to end in a 502. The three bytes go out escaped, the rest of the query as written,
/// and what the analysis sees does not change: the marker next to them is still found.
#[tokio::test]
async fn raw_quote_and_angle_brackets_in_the_query_reach_the_upstream_escaped() {
    let up = http_upstream().await;
    let port = free_port();
    let (h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);

    let resp = one(proxy, &get("/search?q=<b>\"hi\"</b>&n=%3C1")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(
        up.last().line,
        "GET /search?q=%3Cb%3E%22hi%22%3C/b%3E&n=%3C1 HTTP/1.1"
    );
    let ev = h.last_event();
    assert_eq!(s(&ev.action), "allow");
    // The event keeps the target the client sent.
    assert_eq!(s(&ev.uri), "/search?q=<b>\"hi\"</b>&n=%3C1");

    let seen = up.count();
    let resp = one(proxy, &get("/search?q=<b>wafio-test-xss</b>")).await;
    assert_eq!(resp.status, 403);
    assert_eq!(
        up.count(),
        seen,
        "a blocked request never contacts the upstream"
    );
    assert_eq!(s(&h.last_event().action), "block");
}
