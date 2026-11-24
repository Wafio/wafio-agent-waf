//! The edge parts that need no TLS, through the public API: the path prefix an app lives under,
//! as the HTTP upstream, a FastCGI upstream and the decision event see it, and compression of
//! the answers (what is negotiated, what is skipped, the BREACH rule, counters). The main host
//! redirect is in `https.rs`.

mod common;

use std::io::Read;
use std::net::SocketAddr;

use common::*;
use wafio_proxy::{AppSpec, CompressionSpec, MAX_MIN_COMPRESS_BYTES};

fn url(up: &TestUpstream) -> String {
    format!("http://{}", up.addr)
}

fn prefixed(port: u16, up: &TestUpstream, prefix: &str) -> AppSpec {
    let mut a = app("shop", port, &url(up));
    a.proxy_config = format!(r#"{{"strip_path_prefix":"{prefix}"}}"#).into_bytes();
    a
}

#[tokio::test]
async fn the_upstream_sees_the_path_without_the_prefix_and_the_decision_keeps_the_public_one() {
    let up = http_upstream().await;
    let port = free_port();
    let (h, addr) = Harness::serve(vec![prefixed(port, &up, "/shop")]);
    let mut c = Client::connect(addr).await.unwrap();
    for (sent, seen) in [
        ("/shop", "/"),
        ("/shop/", "/"),
        ("/shop?a=1", "/?a=1"),
        ("/shop/cart", "/cart"),
        ("/shop/cart?a=1&b=%20", "/cart?a=1&b=%20"),
        ("/shop/a%20b/%e2%82%ac", "/a%20b/%E2%82%AC"),
        ("/a/../shop/x", "/x"),
    ] {
        let r = c.send(&get(sent)).await.unwrap();
        assert_eq!(r.status, 200, "{sent}");
        assert_eq!(up.last().line, format!("GET {seen} HTTP/1.1"), "{sent}");
        assert_eq!(
            s(&h.last_event().uri),
            sent,
            "the event keeps the public target"
        );
    }
    // A request that asks for an upgrade is sent as it came.
    let h2c = "GET /shop/x HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n";
    let r = c.send(h2c.as_bytes()).await.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(up.last().line, "GET /shop/x HTTP/1.1");
}

/// A path outside the prefix is not the application's. Forwarded, it would reach a page that is
/// public at `/shop/admin` as `/admin`, past every rule written for the public path.
#[tokio::test]
async fn a_path_outside_the_prefix_is_answered_404_and_never_reaches_the_upstream() {
    let up = http_upstream().await;
    let port = free_port();
    let (h, addr) = Harness::serve(vec![prefixed(port, &up, "/shop")]);
    let mut c = Client::connect(addr).await.unwrap();
    assert_eq!(c.send(&get("/shop/admin")).await.unwrap().status, 200);
    let reached = up.count();
    for sent in [
        "/admin",
        "/",
        "/shopping",
        "/shop2/x",
        "/other/shop",
        "/Shop/admin",
        "/shop/../admin",
        "/shop/%2e%2e/admin",
        "/admin?next=/shop/admin",
    ] {
        let r = c.send(&get(sent)).await.unwrap();
        assert_eq!(r.status, 404, "{sent}");
        assert_eq!(up.count(), reached, "{sent} reached the upstream");
        let event = h.last_event();
        assert_eq!(
            (s(&event.uri), event.status),
            (sent, 404),
            "the event keeps the public target"
        );
    }
    // The same for a request that asks for an upgrade.
    let h2c = "GET /admin HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n";
    assert_eq!(c.send(h2c.as_bytes()).await.unwrap().status, 404);
    assert_eq!(up.count(), reached);
    // And the path under it still goes through.
    assert_eq!(c.send(&get("/shop/admin")).await.unwrap().status, 200);
    assert_eq!(up.last().line, "GET /admin HTTP/1.1");
}

#[tokio::test]
async fn an_app_without_a_prefix_forwards_the_path_as_before() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, addr) = Harness::serve(vec![app("shop", port, &url(&up))]);
    assert_eq!(one(addr, &get("/shop/cart?a=1")).await.status, 200);
    assert_eq!(up.last().line, "GET /shop/cart?a=1 HTTP/1.1");
}

#[tokio::test]
async fn fastcgi_gets_the_short_path_in_its_variables() {
    let (fcgi, fake) = fake_fcgi().await;
    let port = free_port();
    let (_h, addr) = Harness::serve(vec![fcgi_app(
        port,
        format!("fcgi://{fcgi}"),
        "/var/www",
        r#"{"strip_path_prefix":"/shop"}"#,
    )]);
    let mut c = Client::connect(addr).await.unwrap();
    assert_eq!(c.send(&get("/shop/app.php?x=1")).await.unwrap().status, 201);
    assert_eq!(c.send(&get("/shop")).await.unwrap().status, 201);
    let params = fake.params.lock().unwrap().clone();
    let pick = |i: usize| {
        let p = &params[i];
        (
            p["REQUEST_URI"].as_str(),
            p["SCRIPT_NAME"].as_str(),
            p["SCRIPT_FILENAME"].as_str(),
            p["QUERY_STRING"].as_str(),
        )
    };
    assert_eq!(
        pick(0),
        ("/app.php?x=1", "/app.php", "/var/www/app.php", "x=1")
    );
    assert_eq!(pick(1).0, "/");
    // A name that only starts with the prefix is not under it: answered 404 without a FastCGI call.
    assert_eq!(c.send(&get("/shopping/app.php")).await.unwrap().status, 404);
    assert_eq!(c.send(&get("/app.php")).await.unwrap().status, 404);
    assert_eq!(fake.params.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_prefix_that_is_not_valid_refuses_the_apply() {
    let up = http_upstream().await;
    let h = Harness::new();
    for bad in ["shop", "/shop/", "/a/../b", "/a//b"] {
        let port = free_port();
        assert!(
            h.proxy.apply(vec![prefixed(port, &up, bad)]).is_err(),
            "{bad}"
        );
    }
    let port = free_port();
    h.proxy.apply(vec![prefixed(port, &up, "/shop")]).unwrap();
}

// Compression.

const HTML: &str = "<p>the quick brown fox jumps over the lazy dog</p>\n";

fn page(times: usize) -> Vec<u8> {
    HTML.repeat(times).into_bytes()
}

/// A whole upstream answer: `headers` are lines without the end of line.
fn whole(content_type: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for h in headers {
        out.push_str(h);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

async fn compressing(
    reply: impl Fn(&Seen) -> (Vec<u8>, bool) + Send + Sync + 'static,
    min_bytes: usize,
) -> (Harness, SocketAddr, TestUpstream) {
    let up = raw_upstream(reply).await;
    let mut a = app("shop", free_port(), &url(&up));
    a.compression = Some(CompressionSpec { min_bytes });
    let (h, addr) = Harness::serve(vec![a]);
    (h, addr, up)
}

fn request(path: &str, extra: &[&str]) -> Vec<u8> {
    let mut raw = format!("GET {path} HTTP/1.1\r\nHost: app.test\r\n");
    for line in extra {
        raw.push_str(line);
        raw.push_str("\r\n");
    }
    raw.push_str("\r\n");
    raw.into_bytes()
}

/// The body of `reply` with its `Content-Encoding` taken off.
fn decoded(reply: &ReplyParts) -> Vec<u8> {
    let mut out = Vec::new();
    match reply.header("content-encoding") {
        Some("gzip") => {
            flate2::read::GzDecoder::new(&reply.body[..])
                .read_to_end(&mut out)
                .unwrap();
        }
        Some("br") => {
            brotli::Decompressor::new(&reply.body[..], 4096)
                .read_to_end(&mut out)
                .unwrap();
        }
        None => out = reply.body.clone(),
        Some(other) => panic!("encoding {other}"),
    }
    out
}

fn varies_by_encoding(r: &ReplyParts) -> bool {
    r.header("vary")
        .is_some_and(|v| v.to_ascii_lowercase().contains("accept-encoding"))
}

#[tokio::test]
async fn an_answer_is_compressed_by_what_the_visitor_takes() {
    let body = page(100);
    let reply = body.clone();
    let (_h, addr, _up) = compressing(
        move |_| {
            let h = whole(
                "text/html; charset=utf-8",
                &["ETag: \"abc\"", "Accept-Ranges: bytes"],
                &reply,
            );
            (h, false)
        },
        1024,
    )
    .await;
    let mut c = Client::connect(addr).await.unwrap();
    for (accept, want) in [
        (None, None),
        (Some("gzip"), Some("gzip")),
        (Some("br"), Some("br")),
        (Some("gzip, br"), Some("br")),
        (Some("br, gzip"), Some("br")),
        (Some("gzip;q=1.0, br;q=0.5"), Some("gzip")),
        (Some("gzip;q=0.5, br;q=0.5"), Some("br")),
        (Some("br;q=0, gzip"), Some("gzip")),
        (Some("*"), Some("br")),
        (Some("*;q=0, gzip"), Some("gzip")),
        (Some("GZIP"), Some("gzip")),
        (Some("deflate, identity"), None),
        (Some("gzip;q=0"), None),
        (Some("identity"), None),
    ] {
        let line = accept.map(|a| format!("Accept-Encoding: {a}"));
        let extra: Vec<&str> = line.iter().map(String::as_str).collect();
        let r = c.send(&request("/p", &extra)).await.unwrap();
        assert_eq!(r.status, 200, "{accept:?}");
        assert_eq!(r.header("content-encoding"), want, "{accept:?}");
        assert_eq!(decoded(&r), body, "{accept:?}: the round trip");
        assert_eq!(
            r.header("content-length"),
            Some(r.body.len().to_string().as_str()),
            "{accept:?}: the length is the body that is sent"
        );
        assert!(
            varies_by_encoding(&r),
            "{accept:?}: a CDN must see the Vary"
        );
        if want.is_some() {
            assert!(r.body.len() < body.len() / 3, "{accept:?}");
            assert_eq!(r.header("etag"), Some("W/\"abc\""), "{accept:?}");
            assert_eq!(r.header("accept-ranges"), None, "{accept:?}");
        } else {
            assert_eq!(r.header("etag"), Some("\"abc\""), "{accept:?}");
            assert_eq!(r.header("accept-ranges"), Some("bytes"), "{accept:?}");
        }
        assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
    }
}

#[tokio::test]
async fn vary_is_merged_into_what_the_answer_already_varies_by() {
    for (upstream, want) in [
        (None, Some("Accept-Encoding")),
        (Some("Vary: Cookie"), Some("Cookie, Accept-Encoding")),
        (
            Some("Vary: Accept-Language, accept-encoding"),
            Some("Accept-Language, accept-encoding"),
        ),
        (Some("Vary: *"), Some("*")),
    ] {
        let body = page(100);
        let line = upstream.map(str::to_owned);
        let (_h, addr, _up) = compressing(
            move |_| {
                let extra: Vec<&str> = line.iter().map(String::as_str).collect();
                (whole("text/css", &extra, &body), false)
            },
            1024,
        )
        .await;
        let r = one(addr, &request("/", &["Accept-Encoding: gzip"])).await;
        assert_eq!(r.header("vary"), want, "{upstream:?}");
        assert_eq!(r.header("content-encoding"), Some("gzip"));
    }
}

#[tokio::test]
async fn only_the_types_worth_compressing_are() {
    let body = page(100);
    let reply = body.clone();
    let (_h, addr, up) = compressing(
        move |seen| {
            let ct = seen.line.split(' ').nth(1).unwrap().trim_start_matches('/');
            (whole(&ct.replace('~', "/"), &[], &reply), false)
        },
        1024,
    )
    .await;
    let mut c = Client::connect(addr).await.unwrap();
    for (ct, compressed) in [
        ("text~html", true),
        ("text~plain", true),
        ("text~css", true),
        ("text~javascript", true),
        ("application~javascript", true),
        ("application~json", true),
        ("application~ld+json", true),
        ("application~xml", true),
        ("image~svg+xml", true),
        ("application~atom+xml", true),
        ("application~wasm", true),
        ("font~ttf", true),
        ("application~vnd.ms-fontobject", true),
        ("text~event-stream", false),
        ("image~png", false),
        ("image~jpeg", false),
        ("video~mp4", false),
        ("application~zip", false),
        ("application~pdf", false),
        ("application~octet-stream", false),
        ("font~woff2", false),
    ] {
        let r = c
            .send(&request(&format!("/{ct}"), &["Accept-Encoding: gzip"]))
            .await
            .unwrap();
        assert_eq!(r.header("content-encoding").is_some(), compressed, "{ct}");
        assert_eq!(varies_by_encoding(&r), compressed, "{ct}");
        assert_eq!(decoded(&r), body, "{ct}");
    }
    assert_eq!(up.count(), 21);
}

#[tokio::test]
async fn an_answer_that_cannot_or_should_not_be_compressed_is_sent_as_it_is() {
    let body = page(100);
    let small = page(2);
    let reply = (body.clone(), small.clone());
    let (_h, addr, _up) = compressing(
        move |seen| {
            let (big, small) = &reply;
            let path = seen.line.split(' ').nth(1).unwrap();
            let out = match path {
                "/small" => whole("text/html", &[], small),
                "/encoded" => whole("text/html", &["Content-Encoding: br"], big),
                "/identity" => whole("text/html", &["Content-Encoding: identity"], big),
                "/notransform" => whole("text/html", &["Cache-Control: public, No-Transform"], big),
                "/range" => whole("text/html", &["Content-Range: bytes 0-99/5000"], big),
                _ => whole("text/html", &[], big),
            };
            (out, false)
        },
        1024,
    )
    .await;
    let mut c = Client::connect(addr).await.unwrap();
    let accept = ["Accept-Encoding: gzip, br"];
    // Under the smallest size: as it is, and nothing to vary by.
    let r = c.send(&request("/small", &accept)).await.unwrap();
    assert_eq!(
        (r.header("content-encoding"), varies_by_encoding(&r)),
        (None, false)
    );
    assert_eq!(r.body, small);
    // The upstream encoded it: its own encoding stays, untouched.
    let r = c.send(&request("/encoded", &accept)).await.unwrap();
    assert_eq!(r.header("content-encoding"), Some("br"));
    assert_eq!(r.body, body);
    // `identity` is no encoding.
    let r = c.send(&request("/identity", &accept)).await.unwrap();
    assert_eq!(r.header("content-encoding"), Some("br"));
    assert_eq!(
        c.send(&request("/notransform", &accept))
            .await
            .unwrap()
            .header("content-encoding"),
        None
    );
    assert_eq!(
        c.send(&request("/range", &accept))
            .await
            .unwrap()
            .header("content-encoding"),
        None
    );
}

#[tokio::test]
async fn the_smallest_size_is_the_size_of_the_answer_that_is_still_compressed() {
    for (len, compressed) in [(999usize, false), (1000, true), (1001, true)] {
        let body = vec![b'a'; len];
        let (_h, addr, _up) =
            compressing(move |_| (whole("text/plain", &[], &body), false), 1000).await;
        let r = one(addr, &request("/", &["Accept-Encoding: gzip"])).await;
        assert_eq!(r.header("content-encoding").is_some(), compressed, "{len}");
    }
    // No smallest size: any answer with a body.
    let (_h, addr, _up) = compressing(|_| (whole("text/plain", &[], &[b'a'; 50]), false), 0).await;
    let r = one(addr, &request("/", &["Accept-Encoding: gzip"])).await;
    assert_eq!(r.header("content-encoding"), Some("gzip"));
    let (_h, addr, _up) = compressing(|_| (whole("text/plain", &[], b""), false), 0).await;
    let r = one(addr, &request("/", &["Accept-Encoding: gzip"])).await;
    assert_eq!(r.header("content-encoding"), None, "nothing to compress");
}

#[tokio::test]
async fn a_signed_in_visitor_gets_no_html_or_json_compressed_but_everything_else_is() {
    let body = page(100);
    let reply = body.clone();
    let (_h, addr, _up) = compressing(
        move |seen| {
            let path = seen.line.split(' ').nth(1).unwrap();
            let ct = match path {
                "/page" => "text/html",
                "/xhtml" => "application/xhtml+xml",
                "/api" => "application/json",
                "/hal" => "application/hal+json",
                "/style.css" => "text/css",
                "/app.js" => "application/javascript",
                _ => "image/svg+xml",
            };
            (whole(ct, &[], &reply), false)
        },
        1024,
    )
    .await;
    let mut c = Client::connect(addr).await.unwrap();
    let signed_in = [
        "Cookie: PHPSESSID=abc",
        "Cookie: theme=dark; laravel_session=x",
        "Cookie: wordpress_logged_in_0a1b=u",
        "Cookie: .AspNetCore.Identity.Application=x",
        "Cookie: JSESSIONID=1",
        "Cookie: remember_web_59ba=1",
        "Authorization: Bearer token",
        "Authorization: Basic eDp5",
    ];
    for who in signed_in {
        for (path, plain) in [
            ("/page", true),
            ("/xhtml", true),
            ("/api", true),
            ("/hal", true),
            ("/style.css", false),
            ("/app.js", false),
            ("/logo.svg", false),
        ] {
            let r = c
                .send(&request(path, &["Accept-Encoding: gzip", who]))
                .await
                .unwrap();
            assert_eq!(
                r.header("content-encoding").is_none(),
                plain,
                "{who} {path}"
            );
            assert_eq!(decoded(&r), body, "{who} {path}");
            assert!(varies_by_encoding(&r), "{who} {path}: it varies either way");
        }
    }
    // A cookie that is no session, and no credential at all.
    for who in [
        "Cookie: theme=dark; _ga=GA1.2",
        "Cookie: wordpress_test_cookie=WP+Cookie+check",
        "X-Session: 1",
    ] {
        for path in ["/page", "/api"] {
            let r = c
                .send(&request(path, &["Accept-Encoding: gzip", who]))
                .await
                .unwrap();
            assert_eq!(r.header("content-encoding"), Some("gzip"), "{who} {path}");
        }
    }
    // The userinfo of an absolute-form target is a credential too.
    let absolute =
        b"GET http://u:p@app.test/page HTTP/1.1\r\nHost: app.test\r\nAccept-Encoding: gzip\r\n\r\n";
    let r = c.send(absolute).await.unwrap();
    assert_eq!(r.header("content-encoding"), None);
}

#[tokio::test]
async fn an_answer_without_a_length_is_not_compressed_and_is_counted() {
    let body = page(100);
    // Chunked and closing, so the client reads it to the end.
    let chunked = {
        let mut out = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        for piece in body.chunks(700) {
            out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
            out.extend_from_slice(piece);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    };
    let (h, addr, _up) = compressing(move |_| (chunked.clone(), true), 1024).await;
    assert!(h.proxy.compression_counters("shop").is_none());

    let r = one(addr, &request("/", &["Accept-Encoding: gzip"])).await;
    assert_eq!((r.status, r.header("content-encoding")), (200, None));
    assert_eq!(r.header("transfer-encoding"), Some("chunked"));
    assert!(
        String::from_utf8_lossy(&r.body).contains("<p>the quick brown fox"),
        "the pieces went out as the upstream sent them"
    );
    let counted = h.proxy.compression_counters("shop").unwrap();
    assert_eq!(
        (
            counted.responses,
            counted.skipped_streamed,
            counted.bytes_saved
        ),
        (0, 1, 0)
    );
    // The visitor takes no encoding: nothing was lost, so nothing is counted.
    let r = one(addr, &request("/", &[])).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        h.proxy
            .compression_counters("shop")
            .unwrap()
            .skipped_streamed,
        1
    );
}

#[tokio::test]
async fn the_counters_of_an_app_follow_what_it_sent_compressed() {
    let body = page(100);
    let reply = body.clone();
    let (h, addr, _up) = compressing(move |_| (whole("text/html", &[], &reply), false), 1024).await;
    let mut c = Client::connect(addr).await.unwrap();
    let before = wafio_proxy::metrics::COMPRESSED_GZIP.load(std::sync::atomic::Ordering::Relaxed);
    let mut saved = 0;
    for _ in 0..3 {
        let r = c
            .send(&request("/", &["Accept-Encoding: gzip"]))
            .await
            .unwrap();
        saved += body.len() - r.body.len();
    }
    let counted = h.proxy.compression_counters("shop").unwrap();
    assert_eq!(
        (
            counted.responses,
            counted.skipped_streamed,
            counted.bytes_saved
        ),
        (3, 0, saved as u64)
    );
    let after = wafio_proxy::metrics::COMPRESSED_GZIP.load(std::sync::atomic::Ordering::Relaxed);
    assert!(after >= before + 3, "the process-wide count moves too");
    assert!(h.proxy.compression_counters("nobody").is_none());
}

#[tokio::test]
async fn an_app_with_compression_off_sends_its_answers_as_they_are() {
    let body = page(100);
    let reply = body.clone();
    let up = raw_upstream(move |_| (whole("text/html", &[], &reply), false)).await;
    let (_h, addr) = Harness::serve(vec![app("shop", free_port(), &url(&up))]);
    let r = one(addr, &request("/", &["Accept-Encoding: gzip, br"])).await;
    assert_eq!(r.header("content-encoding"), None);
    assert_eq!(r.header("vary"), None);
    assert_eq!(r.body, body);
}

#[tokio::test]
async fn an_upgrade_request_is_answered_as_it_is() {
    let body = page(100);
    let reply = body.clone();
    let (_h, addr, _up) =
        compressing(move |_| (whole("text/html", &[], &reply), false), 1024).await;
    let h2c = "GET / HTTP/1.1\r\nHost: app.test\r\nAccept-Encoding: gzip\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n";
    let r = one(addr, h2c.as_bytes()).await;
    assert_eq!((r.status, r.header("content-encoding")), (200, None));
}

#[tokio::test]
async fn a_big_answer_is_compressed_and_comes_out_whole() {
    let body = page(5000);
    assert!(body.len() > 200_000);
    let reply = body.clone();
    let (_h, addr, _up) =
        compressing(move |_| (whole("text/html", &[], &reply), false), 1024).await;
    let mut c = Client::connect(addr).await.unwrap();
    for enc in ["gzip", "br"] {
        let r = c
            .send(&request("/", &[&format!("Accept-Encoding: {enc}")]))
            .await
            .unwrap();
        assert_eq!(r.header("content-encoding"), Some(enc));
        assert!(r.body.len() < body.len() / 10);
        assert_eq!(decoded(&r), body, "{enc}");
    }
}

#[tokio::test]
async fn a_fastcgi_answer_is_compressed_too() {
    let (fcgi, _fake) = fake_fcgi().await;
    let port = free_port();
    let mut a = fcgi_app(port, format!("fcgi://{fcgi}"), "/var/www", "");
    a.compression = Some(CompressionSpec { min_bytes: 1024 });
    let (_h, addr) = Harness::serve(vec![a]);
    // The test responder echoes the request body as text/plain, status 201.
    let body = page(100);
    let mut raw = format!(
        "POST /a.php HTTP/1.1\r\nHost: app.test\r\nAccept-Encoding: gzip\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(&body);
    let r = one(addr, &raw).await;
    assert_eq!(
        (r.status, r.header("content-encoding")),
        (201, Some("gzip"))
    );
    assert_eq!(decoded(&r), body);
}

#[tokio::test]
async fn a_size_over_one_mebibyte_refuses_the_apply() {
    let up = http_upstream().await;
    let h = Harness::new();
    let mut a = app("shop", free_port(), &url(&up));
    a.compression = Some(CompressionSpec {
        min_bytes: MAX_MIN_COMPRESS_BYTES + 1,
    });
    assert!(h.proxy.apply(vec![a]).is_err());
    let mut a = app("shop", free_port(), &url(&up));
    a.compression = Some(CompressionSpec {
        min_bytes: MAX_MIN_COMPRESS_BYTES,
    });
    h.proxy.apply(vec![a]).unwrap();
}

#[tokio::test]
async fn the_counters_of_an_app_that_a_bundle_drops_are_forgotten() {
    let body = page(100);
    let reply = body.clone();
    let up = raw_upstream(move |_| (whole("text/html", &[], &reply), false)).await;
    let port = free_port();
    let make = |id: &str| {
        let mut a = app(id, port, &url(&up));
        a.compression = Some(CompressionSpec { min_bytes: 1024 });
        a
    };
    let h = Harness::new();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    h.proxy.apply(vec![make("one")]).unwrap();
    one(addr, &request("/", &["Accept-Encoding: gzip"])).await;
    assert_eq!(h.proxy.compression_counters("one").unwrap().responses, 1);
    h.proxy.apply(vec![make("two")]).unwrap();
    assert!(h.proxy.compression_counters("one").is_none());
    // The same app in the next bundle keeps its numbers.
    one(addr, &request("/", &["Accept-Encoding: gzip"])).await;
    h.proxy.apply(vec![make("two")]).unwrap();
    assert_eq!(h.proxy.compression_counters("two").unwrap().responses, 1);
}
