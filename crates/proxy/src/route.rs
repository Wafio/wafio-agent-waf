//! One app listener's connection handler: the request read on the raw stream (read buffer size
//! and read timeout, the head parsed by `head_parser`, the body framed and read by `body_reader`),
//! the whole body read before anything is decided, then the pipeline. Nothing of Pingora's
//! HTTP/1 session is used: the stream is read and written here. The route is swapped in place on
//! a bundle apply; a running request keeps the route it loaded.

use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::{Buf, BufMut, BytesMut};
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use crate::body_reader::{self, BodyState};
use crate::config::Route;
use crate::head_parser::{self, HeadError};
use crate::pipeline::{self, Done};
use crate::proxy::Shared;
use crate::request::InboundRequest;
use crate::response::OutboundResponse;
use crate::upstream::ms;

pub struct RouteApp {
    route: RwLock<Arc<Route>>,
    shared: Arc<Shared>,
}

/// Aborts a spawned task when dropped (a drained connection takes its WebSocket relay along).
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The answer for everything that cannot be parsed: 400.
fn malformed_request_response() -> OutboundResponse {
    OutboundResponse::error(400, "Error when parsing request")
}

/// A head or trailer block that does not fit the read buffer: 431.
fn too_big_request() -> OutboundResponse {
    OutboundResponse::error(431, "Too big request header")
}

/// Whether `b` is CR and LF bytes only. An unfinished head like that (whatever ended the read: a
/// full buffer, the end of the stream, a timeout) closes the connection without an answer.
fn only_crlf(b: &[u8]) -> bool {
    b.iter().all(|&c| c == b'\r' || c == b'\n')
}

impl RouteApp {
    pub(crate) fn new(route: Arc<Route>, shared: Arc<Shared>) -> Self {
        RouteApp {
            route: RwLock::new(route),
            shared,
        }
    }

    pub fn route(&self) -> Arc<Route> {
        self.route.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub(crate) fn set_route(&self, route: Arc<Route>) {
        *self.route.write().unwrap_or_else(|e| e.into_inner()) = route;
    }

    /// One request whose head `read_head` parsed: `buf` holds the head and whatever followed it.
    /// `Some`: the connection stays open for the next request (its stream and the bytes read past
    /// this one).
    async fn serve_one(
        self: Arc<Self>,
        mut stream: Stream,
        mut buf: BytesMut,
        head: head_parser::Head,
        deadline: Option<Instant>,
        peer_ip: Option<IpAddr>,
        shutdown: &ShutdownWatch,
    ) -> Option<(Stream, BytesMut)> {
        let route = self.route();
        let write_ms = route.proxy_config.timeouts.write_ms;
        buf.advance(head.len);
        // The request target is parsed before the body is read.
        let Ok(parts) = head_parser::uri_parts(&head.host, &head.request_target) else {
            reject(stream, malformed_request_response(), write_ms).await;
            return None;
        };
        // `Expect: 100-continue` (the exact value) is answered before the body is read.
        if head.expect_continue {
            let send = async {
                stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
                stream.flush().await
            };
            if !matches!(
                run_until_deadline(ms(write_ms).map(|d| Instant::now() + d), send).await,
                Ok(Ok(()))
            ) {
                return None;
            }
        }
        // Body size limit (0 = the 4 MiB default).
        let limit = usize::try_from(route.proxy_config.max_body_bytes)
            .ok()
            .filter(|&n| n > 0)
            .unwrap_or(4 << 20);
        let st = BodyState::default();
        let body = match run_until_deadline(
            deadline,
            body_reader::read_framed_body(
                &mut stream,
                &mut buf,
                head.content_length,
                limit,
                route.header_buffer_size(),
                &st,
            ),
        )
        .await
        {
            Ok(Ok(b)) => b,
            // A bare EOF at a chunk boundary ends the connection silently, except after `Expect:
            // 100-continue`: every error of that body gets the 400.
            Ok(Err(())) if st.closed_silently() && !head.expect_continue => return None,
            Ok(Err(())) => {
                let r = if st.too_big() {
                    too_big_request()
                } else {
                    malformed_request_response()
                };
                reject(stream, r, write_ms).await;
                return None;
            }
            Err(_) => {
                let r = if st.timeout_is_408() {
                    OutboundResponse::error(408, "Request timeout")
                } else {
                    malformed_request_response()
                };
                reject(stream, r, write_ms).await;
                return None;
            }
        };
        let req = InboundRequest::from_parsed(&head, parts, &body.trailers, body.data.is_empty());
        let r = match pipeline::handle(&self.shared, &route, req, body.data, peer_ip).await {
            Ok(Done::Respond(r)) => r,
            Ok(Done::Stream(s)) => {
                let close = head.connection_close || *shutdown.borrow();
                return relay(&self.shared, stream, buf, &head, *s, close, write_ms).await;
            }
            Err(_) => return None,
            Ok(Done::Upgrade(plan)) => {
                // The client stream (and the bytes read past the handshake) become the relay's.
                let task = tokio::spawn(crate::websocket::serve(
                    self.shared.clone(),
                    plan,
                    stream,
                    buf.to_vec(),
                ));
                let _guard = AbortOnDrop(task.abort_handle());
                if let Err(e) = task.await
                    && e.is_panic()
                {
                    crate::metrics::count_agent_panic();
                    tracing::warn!("[ws-proxy] app={} relay panic", route.app_id);
                }
                return None;
            }
        };
        // The connection ends with this answer when the response says so (`Connection: close`,
        // an upstream HTTP/1.0 answer, a close-delimited body) or the request / the draining
        // server does.
        let close = r.close || head.connection_close || *shutdown.borrow();
        let no_body = head.method == b"HEAD"
            || (100..200).contains(&r.status)
            || r.status == 204
            || r.status == 304;
        let wire = r.wire(head.http10, no_body, close, now_unix());
        if close {
            finish_close(stream, wire, write_ms).await;
            return None;
        }
        let send = async {
            stream.write_all(&wire).await?;
            stream.flush().await
        };
        match run_until_deadline(ms(write_ms).map(|d| Instant::now() + d), send).await {
            Ok(Ok(())) => Some((stream, buf)),
            _ => None,
        }
    }
}

/// Writes `parts` and flushes them within the write deadline; false when that fails.
async fn send(stream: &mut Stream, parts: &[&[u8]], write_ms: i64) -> bool {
    let write = async {
        for p in parts {
            stream.write_all(p).await?;
        }
        stream.flush().await
    };
    matches!(
        run_until_deadline(ms(write_ms).map(|d| Instant::now() + d), write).await,
        Ok(Ok(()))
    )
}

/// A response whose body has no length up front: the head goes out at once, then every piece the
/// upstream sends, flushed as it comes, chunked for an HTTP/1.1 client and delimited by the
/// connection's close otherwise. `closing`: the request or the draining server ends the
/// connection with this answer. A failure on either side drops the connection with no closing
/// chunk, which is how the client learns the body is cut.
async fn relay(
    shared: &Shared,
    mut stream: Stream,
    buf: BytesMut,
    req: &head_parser::Head,
    mut up: crate::upstream::Streamed,
    closing: bool,
    write_ms: i64,
) -> Option<(Stream, BytesMut)> {
    let chunked = up.head.upstream_chunked() && !req.http10;
    up.head.chunked = chunked;
    let close = up.head.close || closing || !chunked;
    let wire = up.head.wire(req.http10, true, close, now_unix());
    if !send(&mut stream, &[&wire], write_ms).await {
        return None;
    }
    loop {
        match up.next().await {
            Ok(Some(piece)) if piece.is_empty() => {}
            Ok(Some(piece)) => {
                let size = format!("{:x}\r\n", piece.len());
                let sent = if chunked {
                    send(&mut stream, &[size.as_bytes(), &piece, b"\r\n"], write_ms).await
                } else {
                    send(&mut stream, &[&piece], write_ms).await
                };
                if !sent {
                    return None;
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("[inline-proxy] streamed response ended early: {e}");
                return None;
            }
        }
    }
    if chunked && !send(&mut stream, &[b"0\r\n\r\n"], write_ms).await {
        return None;
    }
    up.finish(shared).await;
    if close {
        finish_close(stream, Vec::new(), write_ms).await;
        return None;
    }
    Some((stream, buf))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Connections one listener serves at once.
pub(crate) const CONNECTION_LIMIT: usize = 256 * 1024;

/// Runs `f` until `deadline` (none = unbounded); `Err` = the deadline passed.
async fn run_until_deadline<F: Future>(
    deadline: Option<Instant>,
    f: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    match deadline {
        Some(t) => tokio::time::timeout_at(t, f).await,
        None => Ok(f.await),
    }
}

/// What the head read found.
enum Head {
    /// The complete head (and whatever followed it, at most the read buffer) is in `buf`.
    Ready {
        buffer: BytesMut,
        head: head_parser::Head,
        deadline: Option<Instant>,
    },
    /// An answer is written and the connection ends: a head that cannot be parsed (400), one that
    /// does not fit the read buffer (431), a first request that never started (408), a head cut
    /// off by the read timeout (400).
    Answer(OutboundResponse),
    /// Closed, timed out idle or draining before a request started.
    Close,
}

/// The request-head read for one connection: at most `cap` bytes (the read buffer size) until
/// the head parses, within one read timeout that also covers the body (the returned deadline).
/// The first request's clock starts at accept; a kept-alive connection waits `read_to` for its
/// first byte (the idle timeout equals the read timeout) and starts the clock there. The head is
/// parsed again whenever a line may have completed, over at most the first `cap` bytes; an
/// error in the request line is answered before the headers end.
async fn read_head(
    stream: &mut Stream,
    mut buf: BytesMut,
    cap: usize,
    first: bool,
    read_to: Option<Duration>,
    stop: &mut ShutdownWatch,
) -> Head {
    let clock = |from: Instant| read_to.map(|d| from + d);
    let mut idle = !first && buf.is_empty();
    let mut deadline = clock(Instant::now());
    // Bytes pipelined behind the previous request are parsed at once.
    let mut dirty = !buf.is_empty();
    loop {
        if dirty {
            match head_parser::parse_head(&buf[..buf.len().min(cap)]) {
                Ok(head) => {
                    return Head::Ready {
                        buffer: buf,
                        head,
                        deadline,
                    };
                }
                Err(HeadError::Bad) => return Head::Answer(malformed_request_response()),
                Err(HeadError::NeedMore) => {}
            }
        }
        if buf.len() >= cap {
            return if only_crlf(&buf[..cap]) {
                Head::Close
            } else {
                Head::Answer(too_big_request())
            };
        }
        let room = cap - buf.len();
        buf.reserve(room.min(4096));
        let mut window = (&mut buf).limit(room);
        let read = run_until_deadline(deadline, stream.read_buf(&mut window));
        let n = if idle {
            tokio::select! {
                biased;
                _ = async { let _ = stop.wait_for(|v| *v).await; } => return Head::Close,
                r = read => r,
            }
        } else {
            read.await
        };
        match n {
            Ok(Ok(n)) if n > 0 => {
                if idle {
                    idle = false;
                    deadline = clock(Instant::now());
                }
                dirty = buf[buf.len() - n..].contains(&b'\n');
            }
            // The end of the stream: nothing read (or CR/LF only) ends silently, a head cut off is
            // a parse error answered to a peer that may still read (it half-closed).
            Ok(_) if buf.is_empty() || only_crlf(&buf) => return Head::Close,
            Ok(_) => return Head::Answer(malformed_request_response()),
            // The read timeout: nothing read of the very first request is a 408, a head cut off is
            // a parse error, an idle kept-alive connection (or CR/LF only) ends silently.
            Err(_) if buf.is_empty() && first => {
                return Head::Answer(OutboundResponse::error(408, "Request timeout"));
            }
            Err(_) if buf.is_empty() || only_crlf(&buf) => return Head::Close,
            Err(_) => return Head::Answer(malformed_request_response()),
        }
    }
}

/// Writes `wire` (a `Connection: close` answer), then closes the way nginx's lingering close does:
/// FIN first and a bounded drain of what the client is still sending, since closing with unread
/// data resets the connection and the client may lose the answer.
async fn finish_close(mut stream: Stream, wire: Vec<u8>, write_ms: i64) {
    let send = async {
        stream.write_all(&wire).await?;
        stream.flush().await?;
        stream.shutdown().await
    };
    if !matches!(
        run_until_deadline(ms(write_ms).map(|d| Instant::now() + d), send).await,
        Ok(Ok(()))
    ) {
        return;
    }
    let drain = async {
        let (mut sink, mut left) = ([0u8; 4096], 256 * 1024usize);
        while left > 0 {
            match stream.read(&mut sink).await {
                Ok(n) if n > 0 => left = left.saturating_sub(n),
                _ => break,
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(1), drain).await;
}

/// An error answer written with `Connection: close`, then the lingering close.
async fn reject(stream: Stream, r: OutboundResponse, write_ms: i64) {
    let wire = r.wire(false, false, true, now_unix());
    finish_close(stream, wire, write_ms).await;
}

/// The connection loop for plain HTTP/1 (no TLS, no h2c): the requests are read, bounded and
/// answered one at a time.
pub(crate) async fn serve_connection(app: Arc<RouteApp>, stream: Stream, mut stop: ShutdownWatch) {
    let peer_ip = stream
        .get_socket_digest()
        .and_then(|d| d.peer_addr().and_then(|a| a.as_inet()).map(|a| a.ip()));
    let mut stream = stream;
    let (mut prefix, mut first) = (BytesMut::new(), true);
    loop {
        let route = app.route();
        let read_to = ms(route.proxy_config.timeouts.read_ms);
        let write_ms = route.proxy_config.timeouts.write_ms;
        let head = read_head(
            &mut stream,
            prefix,
            route.header_buffer_size(),
            first,
            read_to,
            &mut stop,
        )
        .await;
        drop(route);
        match head {
            Head::Close => return,
            Head::Answer(r) => return reject(stream, r, write_ms).await,
            Head::Ready {
                buffer: buf,
                head,
                deadline,
            } => match app
                .clone()
                .serve_one(stream, buf, head, deadline, peer_ip, &stop)
                .await
            {
                Some((s, rest)) => (stream, prefix, first) = (s, rest, false),
                None => return,
            },
        }
    }
}
