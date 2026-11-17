//! The request limits on the listener (security review): the read timeout is one deadline for
//! the whole request (head and body, trickled bytes do not extend it), the read buffer size
//! bounds what is buffered before the head ends (431 at the full buffer, not after 1 MiB), and
//! an idle keep-alive connection ends after the read timeout.

mod common;

use std::time::{Duration, Instant};

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn slow_app(port: u16, upstream: &str) -> wafio_proxy::AppSpec {
    let mut a = app("slow", port, upstream);
    a.proxy_config = br#"{"timeouts":{"read_ms":1000}}"#.to_vec();
    a
}

/// Reads until EOF (or a reset) within `max`; the time it took.
async fn closed_after(c: &mut TcpStream, max: Duration) -> Option<Duration> {
    let t = Instant::now();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(max.saturating_sub(t.elapsed()), c.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {}
            Ok(_) => return Some(t.elapsed()),
            Err(_) => return None,
        }
    }
}

/// Slowloris: one header byte every 300 ms, each inside `read_ms`, used to keep the request
/// alive for ever; the proxy closes at `read_ms`.
#[tokio::test]
async fn trickled_head_is_cut_at_the_read_timeout() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![slow_app(port, &format!("http://{}", up.addr))]);
    let (mut rd, mut wr) = TcpStream::connect(proxy).await.unwrap().into_split();
    let writer = tokio::spawn(async move {
        let _ = wr.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nX-Slow: ").await;
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if wr.write_all(b"a").await.is_err() {
                return;
            }
        }
    });
    let t = Instant::now();
    // A head the read timeout cut off is answered as a parse error, then the connection closes.
    let mut got = Vec::new();
    let first = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0u8; 256];
        let n = rd.read(&mut buf).await.unwrap_or(0);
        got.extend_from_slice(&buf[..n]);
    })
    .await;
    assert!(first.is_ok(), "answered within 5 s");
    let text = String::from_utf8_lossy(&got).into_owned();
    assert!(text.starts_with("HTTP/1.1 400 "), "{text}");
    assert!(text.contains("Error when parsing request") && text.contains("Connection: close"));
    let took = t.elapsed();
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_millis(2500),
        "{took:?}"
    );
    writer.abort();
    assert_eq!(up.accepts(), 0);
}

/// A first request that never starts is answered `408 Request timeout` at `read_ms`.
#[tokio::test]
async fn silent_first_request_is_408_at_the_read_timeout() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![slow_app(port, &format!("http://{}", up.addr))]);
    let mut c = TcpStream::connect(proxy).await.unwrap();
    let t = Instant::now();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut got))
        .await
        .expect("answered and closed within 5 s")
        .ok();
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 408 "), "{text}");
    assert!(
        text.contains("Request timeout") && text.contains("Connection: close"),
        "{text}"
    );
    let took = t.elapsed();
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_millis(2500),
        "{took:?}"
    );
    assert_eq!(up.accepts(), 0);
}

/// The same deadline covers the body: a declared body trickled in is cut too.
#[tokio::test]
async fn trickled_body_is_cut_at_the_same_deadline() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![slow_app(port, &format!("http://{}", up.addr))]);
    let (mut rd, mut wr) = TcpStream::connect(proxy).await.unwrap().into_split();
    let writer = tokio::spawn(async move {
        let _ = wr
            .write_all(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\n")
            .await;
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if wr.write_all(b"a").await.is_err() {
                return;
            }
        }
    });
    let t = Instant::now();
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), rd.read(&mut buf))
        .await
        .expect("closed within 5 s");
    // A fixed-length body cut off by the deadline is answered `408 Request timeout`.
    let n = n.unwrap();
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 408 "), "{text}");
    assert!(text.contains("Request timeout"), "{text}");
    assert!(
        t.elapsed() < Duration::from_millis(2500),
        "{:?}",
        t.elapsed()
    );
    writer.abort();
    assert_eq!(up.accepts(), 0);
}

/// A ~1 MB head without its end was buffered whole (Pingora's own limit) before
/// the read-buffer size was looked at. Now the 431 comes when the buffer is full, with most of
/// the head still unsent.
#[tokio::test]
async fn head_past_the_read_buffer_is_431_before_the_rest_is_read() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let (mut rd, mut wr) = TcpStream::connect(proxy).await.unwrap().into_split();
    let t = Instant::now();
    let writer = tokio::spawn(async move {
        let mut head = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
        for i in 0..120 {
            head.extend_from_slice(format!("X-{i}: {}\r\n", "h".repeat(8000)).as_bytes());
        }
        // No final CRLF: the head never ends. The server answers long before this is all sent.
        let _ = wr.write_all(&head).await;
        wr
    });
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), rd.read_to_end(&mut got))
        .await
        .expect("answer and close")
        .ok();
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 431 "), "{text}");
    assert!(
        text.contains("Too big request header") && text.contains("Connection: close"),
        "{text}"
    );
    assert!(t.elapsed() < Duration::from_secs(2));
    writer.abort();
    assert_eq!(up.accepts(), 0);
}

/// A head that fits keeps working across the guard: pipelined requests in one packet, a body in
/// the same packet as the head, leading empty lines, a bare-LF head end.
#[tokio::test]
async fn heads_around_the_guard_still_parse() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let mut c = Client::connect(proxy).await.unwrap();
    let mut two = get("/one");
    two.extend_from_slice(&post("/two", "text/plain", b"hello"));
    c.0.get_mut().write_all(&two).await.unwrap();
    assert_eq!(read_reply(&mut c.0).await.unwrap().status, 200);
    assert_eq!(read_reply(&mut c.0).await.unwrap().status, 200);
    assert_eq!(up.last().body, b"hello");
    assert_eq!(
        c.send(b"\r\n\r\nGET /lead HTTP/1.1\r\nHost: a\r\n\r\n")
            .await
            .unwrap()
            .status,
        200
    );
    // A bare-LF head is complete only once a CRLF CRLF follows somewhere: until one arrives the
    // request is not answered.
    c.0.get_mut()
        .write_all(b"GET /lf HTTP/1.1\nHost: a\n\n")
        .await
        .unwrap();
    let early = tokio::time::timeout(Duration::from_millis(300), read_reply(&mut c.0)).await;
    assert!(early.is_err(), "answered a bare-LF head: {early:?}");
    c.0.get_mut().write_all(b"\r\n\r\n").await.unwrap();
    assert_eq!(read_reply(&mut c.0).await.unwrap().status, 200);
    assert_eq!(up.last().line, "GET /lf HTTP/1.1");
}

/// An idle keep-alive connection ends after the read timeout.
#[tokio::test]
async fn idle_keepalive_connection_ends_after_the_read_timeout() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![slow_app(port, &format!("http://{}", up.addr))]);
    let mut c = Client::connect(proxy).await.unwrap();
    assert_eq!(c.send(&get("/")).await.unwrap().status, 200);
    let took = closed_after(c.0.get_mut(), Duration::from_secs(5))
        .await
        .expect("closed");
    assert!(
        took >= Duration::from_millis(800) && took < Duration::from_millis(2500),
        "{took:?}"
    );
}

/// A head that is only CR and LF bytes ends the connection without an answer, whether the
/// buffer fills, the client half-closes or the read timeout passes; a head cut off by the end of
/// the stream is answered 400 to a peer that still reads; a trailer block that does not fit the
/// read buffer is 431.
#[tokio::test]
async fn crlf_only_heads_end_silently_and_a_cut_off_head_is_400() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![slow_app(port, &format!("http://{}", up.addr))]);
    let drained = |mut s: TcpStream| async move {
        let mut got = Vec::new();
        let r = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut got)).await;
        (r.is_ok(), String::from_utf8_lossy(&got).into_owned())
    };
    // The buffer fills with CR/LF.
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(&b"\r\n".repeat(8192)).await.unwrap();
    assert_eq!(drained(c).await, (true, String::new()));
    // The client half-closes after CR/LF.
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(b"\r\n\n").await.unwrap();
    c.shutdown().await.unwrap();
    assert_eq!(drained(c).await, (true, String::new()));
    // The read timeout passes after CR/LF.
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(b"\r\n").await.unwrap();
    assert_eq!(drained(c).await, (true, String::new()));
    // The client half-closes in the middle of a head: answered 400.
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: a").await.unwrap();
    c.shutdown().await.unwrap();
    let (ok, text) = drained(c).await;
    assert!(ok && text.starts_with("HTTP/1.1 400 "), "{text}");
    // A trailer block of 16,385 bytes (the buffer holds 16,384).
    for (pad, status) in [(16384 - 9, "200"), (16384 - 8, "431")] {
        let mut c = TcpStream::connect(proxy).await.unwrap();
        let mut req = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-T: ".to_vec();
        req.extend_from_slice(&vec![b'a'; pad]);
        req.extend_from_slice(b"\r\n\r\n");
        c.write_all(&req).await.unwrap();
        let mut got = vec![0u8; 12];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got[9..], status.as_bytes(), "{}", s(&got));
    }
}

/// The end of the stream where a chunk size should start (no chunk yet, or between two chunks) is a
/// closed connection: no answer. Inside a chunk size, a chunk or the trailer it is a broken
/// chunk, 400.
#[tokio::test]
async fn eof_at_a_chunk_boundary_closes_without_an_answer() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let head = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n";
    for (tail, answered) in [
        ("", false),
        ("5\r\nhello\r\n", false),
        ("5", true),
        ("5\r\nhel", true),
        ("3\r\nabc\r\n0\r\n", true),
    ] {
        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(format!("{head}{tail}").as_bytes())
            .await
            .unwrap();
        c.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut got))
            .await
            .expect("closed")
            .ok();
        let text = String::from_utf8_lossy(&got);
        assert_eq!(!got.is_empty(), answered, "{tail:?} answered {text:?}");
        if answered {
            assert!(text.starts_with("HTTP/1.1 400 "), "{tail:?}: {text}");
        }
    }
    assert_eq!(up.accepts(), 0);
}

/// The same end of the stream after `Expect: 100-continue`: every error of that body is answered
/// 400 after the 100.
#[tokio::test]
async fn eof_at_a_chunk_boundary_after_expect_is_answered() {
    let up = http_upstream().await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let head =
        "POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n";
    for tail in ["", "5\r\nhello\r\n"] {
        let mut c = TcpStream::connect(proxy).await.unwrap();
        c.write_all(format!("{head}{tail}").as_bytes())
            .await
            .unwrap();
        c.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut got))
            .await
            .expect("closed")
            .ok();
        let text = String::from_utf8_lossy(&got);
        assert!(
            text.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 400 Bad Request\r\n"),
            "{tail:?}: {text}"
        );
    }
    assert_eq!(up.accepts(), 0);
}
