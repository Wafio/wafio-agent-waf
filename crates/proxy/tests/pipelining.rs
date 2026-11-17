//! HTTP/1 pipelining: the requests that arrive back to back on one
//! connection are read, handled and answered one at a time, in order (a slow one holds the later
//! ones back; none is lost at any cut of the byte stream), and a request that ends the connection
//! (`Connection: close`, a limit error) is the last one answered.

mod common;
#[path = "common/fake_engine.rs"]
mod fake_engine;

use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SQLI: &str = "/search?q=wafio-test-sql";

/// An upstream whose answer body is the request line's path; `/slow/…` answers after 40 ms.
async fn echo_upstream() -> TestUpstream {
    raw_upstream(|seen: &Seen| {
        let path = seen.line.split(' ').nth(1).unwrap().to_string();
        if path.starts_with("/slow") {
            std::thread::sleep(Duration::from_millis(40));
        }
        let body = format!("{path}|{}", String::from_utf8_lossy(&seen.body));
        // A HEAD answer has the length but no body.
        let sent = if seen.line.starts_with("HEAD ") {
            ""
        } else {
            body.as_str()
        };
        (
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{sent}",
                body.len()
            )
            .into_bytes(),
            false,
        )
    })
    .await
}

/// The requests and what each must be answered with: (raw request, head only, status, body).
fn queue() -> Vec<(Vec<u8>, bool, u16, String)> {
    let head = |m: &str, p: &str| format!("{m} {p} HTTP/1.1\r\nHost: a\r\n\r\n").into_bytes();
    vec![
        (get("/a"), false, 200, "/a|".into()),
        (
            post("/b", "text/plain", b"hello"),
            false,
            200,
            "/b|hello".into(),
        ),
        (get(SQLI), false, 403, String::new()),
        (head("HEAD", "/c"), true, 200, String::new()),
        (get("/slow/d"), false, 200, "/slow/d|".into()),
        (
            post("/e", "application/json", br#"{"k":"v"}"#),
            false,
            200,
            r#"/e|{"k":"v"}"#.into(),
        ),
        (get("/f"), false, 200, "/f|".into()),
    ]
}

/// Reads one answer exactly as `read_raw` returns it; (status, body).
async fn answer(c: &mut Client, head_only: bool) -> (u16, String) {
    let raw = read_raw(&mut c.0, head_only).await.expect("an answer");
    let status = raw.split(' ').nth(1).unwrap().parse().unwrap();
    (
        status,
        raw.split_once("\r\n\r\n")
            .map_or(String::new(), |(_, b)| b.to_string()),
    )
}

async fn check_in_order(c: &mut Client) {
    for (i, (_, head_only, status, body)) in queue().into_iter().enumerate() {
        let (st, b) = answer(c, head_only).await;
        assert_eq!(st, status, "answer {i}");
        if status == 403 {
            assert!(!b.is_empty(), "answer {i}: block page");
        } else {
            assert_eq!(b, body, "answer {i}");
        }
    }
}

#[tokio::test]
async fn pipelined_requests_are_answered_in_order() {
    let up = echo_upstream().await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let mut c = Client::connect(proxy).await.unwrap();
    // Everything in one write: a GET, a POST with a body, a blocked request, a HEAD, a slow
    // upstream and more behind it.
    let all: Vec<u8> = queue().into_iter().flat_map(|q| q.0).collect();
    c.0.get_mut().write_all(&all).await.unwrap();
    check_in_order(&mut c).await;
    // Six requests reached the upstream (the blocked one never), in order, on one connection.
    let paths: Vec<String> = up
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.line.split(' ').nth(1).unwrap().to_string())
        .collect();
    assert_eq!(paths, ["/a", "/b", "/c", "/slow/d", "/e", "/f"]);
    assert_eq!(up.accepts(), 1);
    // The connection is still good.
    let r = c.send(&get("/after")).await.unwrap();
    assert_eq!((r.status, r.text()), (200, "/after|".into()));
}

#[tokio::test]
async fn pipelined_bytes_survive_any_cut_of_the_stream() {
    let up = echo_upstream().await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let all: Vec<u8> = queue().into_iter().flat_map(|q| q.0).collect();
    // Cut sizes 1 (byte by byte), 7, 64 and one that is not a divisor of anything.
    for cut in [1usize, 7, 64, 211] {
        // Write from a thread on a second handle, so answers are read while the tail is still
        // being sent and the head guard sees every cut.
        let std_stream = std::net::TcpStream::connect(proxy).unwrap();
        let mut w = std_stream.try_clone().unwrap();
        std_stream.set_nonblocking(true).unwrap();
        let mut c = Client(tokio::io::BufReader::new(
            tokio::net::TcpStream::from_std(std_stream).unwrap(),
        ));
        let all = all.clone();
        let writer = std::thread::spawn(move || {
            use std::io::Write;
            for piece in all.chunks(cut) {
                w.write_all(piece).unwrap();
                if cut < 64 {
                    std::thread::sleep(Duration::from_micros(200));
                }
            }
        });
        check_in_order(&mut c).await;
        writer.join().unwrap();
    }
}

/// `Connection: close` on a request in the middle: it is answered with `Connection: close`, the
/// connection ends, and what was pipelined behind it is never answered.
#[tokio::test]
async fn connection_close_ends_the_pipeline() {
    let up = echo_upstream().await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let mut c = Client::connect(proxy).await.unwrap();
    let raw = [
        get("/a"),
        b"GET /b HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n".to_vec(),
        get("/c"),
    ]
    .concat();
    c.0.get_mut().write_all(&raw).await.unwrap();
    assert_eq!(read_reply(&mut c.0).await.unwrap().text(), "/a|");
    let b = read_reply(&mut c.0).await.unwrap();
    assert_eq!(
        (b.text(), b.header("connection")),
        ("/b|".into(), Some("close"))
    );
    assert!(
        at_eof(&mut c.0).await,
        "the connection ends after the close request"
    );
    assert_eq!(up.count(), 2, "/c is never read");
}

/// A request the listener refuses (body over `max_body_bytes`: 400) ends the pipeline.
#[tokio::test]
async fn a_limit_error_ends_the_pipeline_after_the_requests_before_it() {
    let up = echo_upstream().await;
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{}", up.addr));
    a.proxy_config = br#"{"max_body_bytes":1024}"#.to_vec();
    let (_h, proxy) = Harness::serve_with_fake_engine(vec![a]);
    let mut c = Client::connect(proxy).await.unwrap();
    let big = post("/big", "text/plain", &[b'x'; 2048]);
    c.0.get_mut()
        .write_all(&[get("/a"), big, get("/c")].concat())
        .await
        .unwrap();
    assert_eq!(read_reply(&mut c.0).await.unwrap().text(), "/a|");
    let r = read_reply(&mut c.0).await.unwrap();
    assert_eq!(r.status, 400);
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), c.0.read_to_end(&mut rest)).await;
    assert!(
        rest.is_empty(),
        "nothing is answered after the error: {:?}",
        String::from_utf8_lossy(&rest)
    );
    assert_eq!(up.count(), 1);
}

/// The Rust agent writes each answer as soon as it has it: when the next pipelined request has a
/// complete head and an incomplete body, the first answer is not held until that body ends or
/// fails (a client that waits for the first answer before sending the rest of the second request
/// is not deadlocked). Documented deviation, proxy.md "Deviations".
/// suite records both sides.
#[tokio::test]
async fn the_first_answer_is_not_held_for_an_incomplete_next_body() {
    let up = echo_upstream().await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let mut c = Client::connect(proxy).await.unwrap();
    let raw = [
        get("/a"),
        b"POST /b HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nabc".to_vec(),
    ]
    .concat();
    c.0.get_mut().write_all(&raw).await.unwrap();
    assert_eq!(answer(&mut c, false).await, (200, "/a|".into()));
    c.0.get_mut().write_all(b"defghij").await.unwrap();
    assert_eq!(answer(&mut c, false).await, (200, "/b|abcdefghij".into()));
}

/// A pipelined request whose chunked body ends (the client half-closes) where a chunk size should
/// start ends the connection silently. The first request is answered already (a valid request
/// deserves its answer); the connection then ends without a second answer.
#[tokio::test]
async fn a_silent_close_after_a_pipelined_request_still_answers_the_first() {
    let up = echo_upstream().await;
    let port = free_port();
    let (_h, proxy) =
        Harness::serve_with_fake_engine(vec![app("a1", port, &format!("http://{}", up.addr))]);
    for tail in ["", "5\r\nhello\r\n"] {
        let mut c = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let raw = [
            get("/a"),
            format!("POST /b HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n{tail}")
                .into_bytes(),
        ]
        .concat();
        c.write_all(&raw).await.unwrap();
        c.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut got))
            .await
            .expect("closed")
            .ok();
        let text = String::from_utf8_lossy(&got);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{tail:?}: {text}");
        assert_eq!(text.matches("HTTP/1.1 ").count(), 1, "{tail:?}: {text}");
        assert!(text.ends_with("/a|"), "{tail:?}: {text}");
    }
}
