//! A response with no length up front (chunked, or ended by the upstream closing) reaches the
//! client piece by piece while the upstream is still sending it.

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

enum Step {
    Send(Vec<u8>),
    /// Holds the answer until the test has seen what came before.
    Wait(Arc<Notify>),
    Sleep(u64),
}

/// An upstream that plays `steps` for every request. After them it closes the connection
/// (`close`) or reads the next request.
async fn scripted_upstream(steps: Vec<Step>, close: bool) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let steps = Arc::new(steps);
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let steps = steps.clone();
            tokio::spawn(async move {
                let mut r = BufReader::new(s);
                while let Ok(Some(_)) = read_head(&mut r).await {
                    for step in steps.iter() {
                        match step {
                            Step::Send(b) => {
                                if r.get_mut().write_all(b).await.is_err() {
                                    return;
                                }
                            }
                            Step::Wait(n) => n.notified().await,
                            Step::Sleep(ms) => tokio::time::sleep(Duration::from_millis(*ms)).await,
                        }
                    }
                    if close {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn chunk(data: &str) -> Vec<u8> {
    format!("{:x}\r\n{data}\r\n", data.len()).into_bytes()
}

const END: &[u8] = b"0\r\n\r\n";

async fn within<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), f)
        .await
        .unwrap_or_else(|_| panic!("{what} did not arrive in time"))
}

/// The data of the next chunk; `None` at the closing chunk.
async fn read_chunk(r: &mut BufReader<TcpStream>) -> io::Result<Option<String>> {
    let mut line = String::new();
    if r.read_line(&mut line).await? == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let n = usize::from_str_radix(line.trim(), 16).unwrap();
    let mut data = vec![0; n + 2];
    r.read_exact(&mut data).await?;
    Ok((n > 0).then(|| String::from_utf8(data[..n].to_vec()).unwrap()))
}

async fn start(upstream: SocketAddr, proxy_config: &str) -> (Harness, TcpStream) {
    let port = free_port();
    let mut a = app("a1", port, &format!("http://{upstream}"));
    a.proxy_config = proxy_config.as_bytes().to_vec();
    let (h, proxy) = Harness::serve(vec![a]);
    (h, TcpStream::connect(proxy).await.unwrap())
}

/// Sends the head and one chunk, then waits for the test; the connection stays open.
async fn chunked_case(head: &'static str) -> Vec<(String, String)> {
    let release = Arc::new(Notify::new());
    let up = scripted_upstream(
        vec![
            Step::Send([head.as_bytes(), &chunk("one")].concat()),
            Step::Wait(release.clone()),
            Step::Send([chunk("two"), END.to_vec()].concat()),
        ],
        false,
    )
    .await;
    let (_h, s) = start(up, "").await;
    let mut c = BufReader::new(s);
    c.get_mut().write_all(&get("/stream")).await.unwrap();
    let (line, headers) = within("the head", read_head(&mut c))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line.split(' ').nth(1), Some("200"));
    assert_eq!(header(&headers, "transfer-encoding"), Some("chunked"));
    assert_eq!(header(&headers, "content-length"), None);
    let first = within("the first piece", read_chunk(&mut c)).await.unwrap();
    assert_eq!(first.as_deref(), Some("one"));
    // The upstream sends the rest only now.
    release.notify_one();
    let second = within("the second piece", read_chunk(&mut c))
        .await
        .unwrap();
    assert_eq!(second.as_deref(), Some("two"));
    assert_eq!(within("the end", read_chunk(&mut c)).await.unwrap(), None);
    // The connection stays open for the next request, which is answered the same way.
    release.notify_one();
    c.get_mut().write_all(&get("/again")).await.unwrap();
    within("the next head", read_head(&mut c))
        .await
        .unwrap()
        .unwrap();
    for want in [Some("one"), Some("two"), None] {
        let got = within("a piece", read_chunk(&mut c)).await.unwrap();
        assert_eq!(got.as_deref(), want);
    }
    headers
}

#[tokio::test]
async fn an_event_stream_in_chunks_is_relayed_as_it_arrives() {
    let headers = chunked_case(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nTransfer-Encoding: chunked\r\n\r\n",
    )
    .await;
    assert_eq!(header(&headers, "content-type"), Some("text/event-stream"));
    assert_eq!(header(&headers, "cache-control"), Some("no-cache"));
    assert_eq!(header(&headers, "x-accel-buffering"), Some("no"));
}

#[tokio::test]
async fn a_plain_chunked_response_that_trickles_is_relayed_as_it_arrives() {
    chunked_case(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn an_event_stream_ended_by_the_close_is_relayed_as_it_arrives() {
    let release = Arc::new(Notify::new());
    let up = scripted_upstream(
        vec![
            Step::Send(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\n\r\ndata: one\n\n"
                    .to_vec(),
            ),
            Step::Wait(release.clone()),
            Step::Send(b"data: two\n\n".to_vec()),
        ],
        true,
    )
    .await;
    let (_h, s) = start(up, "").await;
    let mut c = BufReader::new(s);
    c.get_mut().write_all(&get("/stream")).await.unwrap();
    let (line, headers) = within("the head", read_head(&mut c))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line.split(' ').nth(1), Some("200"));
    assert_eq!(header(&headers, "content-length"), None);
    assert_eq!(header(&headers, "transfer-encoding"), None);
    assert_eq!(header(&headers, "connection"), Some("close"));
    assert_eq!(header(&headers, "cache-control"), Some("no-cache"));
    assert_eq!(header(&headers, "x-accel-buffering"), Some("no"));
    let mut first = [0; 11];
    within("the first event", c.read_exact(&mut first))
        .await
        .unwrap();
    assert_eq!(&first, b"data: one\n\n");
    release.notify_one();
    let mut rest = Vec::new();
    within("the end", c.read_to_end(&mut rest)).await.unwrap();
    assert_eq!(rest, b"data: two\n\n");
}

/// `upstream_ms` bounds the wait for the head and then each wait for more of the body, not the
/// whole stream: a stream that keeps sending outlives it, a quiet one is cut.
#[tokio::test]
async fn the_upstream_timeout_is_an_idle_one_once_the_body_flows() {
    const HEAD: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut steps = vec![Step::Send(HEAD.to_vec())];
    for i in 0..6 {
        steps.push(Step::Send(chunk(&format!("tick {i}"))));
        steps.push(Step::Sleep(250));
    }
    steps.push(Step::Send(END.to_vec()));
    let up = scripted_upstream(steps, false).await;
    let (_h, s) = start(up, r#"{"timeouts":{"upstream_ms":600}}"#).await;
    let mut c = BufReader::new(s);
    c.get_mut().write_all(&get("/ticks")).await.unwrap();
    let (line, _) = within("the head", read_head(&mut c))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line.split(' ').nth(1), Some("200"));
    for i in 0..6 {
        let got = within("a tick", read_chunk(&mut c)).await.unwrap();
        assert_eq!(got, Some(format!("tick {i}")));
    }
    assert_eq!(within("the end", read_chunk(&mut c)).await.unwrap(), None);

    // One piece, then silence for longer than `upstream_ms`: the connection is dropped.
    let up = scripted_upstream(
        vec![
            Step::Send([HEAD, &chunk("only")].concat()),
            Step::Sleep(3000),
        ],
        true,
    )
    .await;
    let (_h, s) = start(up, r#"{"timeouts":{"upstream_ms":600}}"#).await;
    let mut c = BufReader::new(s);
    c.get_mut().write_all(&get("/quiet")).await.unwrap();
    within("the head", read_head(&mut c))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        within("the piece", read_chunk(&mut c))
            .await
            .unwrap()
            .as_deref(),
        Some("only")
    );
    let cut = within("the cut", read_chunk(&mut c)).await;
    assert!(cut.is_err(), "the closing chunk came: {cut:?}");
}
