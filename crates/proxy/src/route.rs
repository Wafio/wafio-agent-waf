//! A listener's connection handler, for the plain listener of one app and for an HTTPS listener
//! shared by several: the request read on the raw stream (read buffer size
//! and read timeout, the head parsed by `head_parser`, the body framed and read by `body_reader`),
//! the maintenance gate at the head, the whole body read before anything else is decided, then
//! the pipeline. Nothing of Pingora's HTTP/1 session is used: the stream is read and written
//! here. The route is swapped in place on a bundle apply; a running request keeps the route it
//! loaded, and a WebSocket session or event stream follows later swaps through a subscription.

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BufMut, BytesMut};
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::body_reader::{self, BodyState};
use crate::config::Route;
use crate::head_parser::{self, HeadError, UriParts};
use crate::https::RedirectTable;
use crate::maintenance::{self, Watch};
use crate::pipeline::{self, Done};
use crate::proxy::Shared;
use crate::request::{InboundRequest, TlsClient};
use crate::response::OutboundResponse;
use crate::upstream::ms;

pub struct RouteApp {
    route: watch::Sender<Arc<Route>>,
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
            route: watch::Sender::new(route),
            shared,
        }
    }

    pub fn route(&self) -> Arc<Route> {
        self.route.borrow().clone()
    }

    pub(crate) fn set_route(&self, route: Arc<Route>) {
        self.route.send_replace(route);
    }

    /// Follows the swaps of this app's route, and no other app's.
    fn subscribe(&self) -> watch::Receiver<Arc<Route>> {
        self.route.subscribe()
    }

    /// One request whose head `read_head` parsed (`parts` is its request target): `buf` holds the
    /// head and whatever followed it. `Some`: the connection stays open for the next request (its
    /// stream and the bytes read past this one).
    #[allow(clippy::too_many_arguments)]
    async fn serve_one(
        self: Arc<Self>,
        mut stream: Stream,
        mut buf: BytesMut,
        head: head_parser::Head,
        parts: head_parser::UriParts,
        deadline: Option<Instant>,
        peer: &Peer,
        shutdown: &ShutdownWatch,
    ) -> Option<(Stream, BytesMut)> {
        let route = self.route();
        let write_ms = route.proxy_config.timeouts.write_ms;
        buf.advance(head.len);
        // An app in maintenance mode answers from the head: no `100 Continue`, no body read.
        if let Some(r) = maintenance::gate(&route, &head, peer.ip) {
            return write_answer(stream, buf, &head, r, head.len, write_ms, shutdown).await;
        }
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
        let consumed = head.len + body.data.len();
        let mut req =
            InboundRequest::from_parsed(&head, parts, &body.trailers, body.data.is_empty());
        req.tls = peer.tls.clone();
        let r = match pipeline::handle(&self.shared, &route, req, body.data, peer.ip).await {
            Ok(Done::Respond(r)) => r,
            Ok(Done::Stream(s)) => {
                let close = head.connection_close || *shutdown.borrow();
                // An event stream has no end of its own: it stops when maintenance turns on.
                let watch = maintenance::is_event_stream(s.head.content_type())
                    .then(|| Watch::for_request(self.subscribe(), &route, &head, peer.ip));
                return relay(&self.shared, stream, buf, &head, *s, close, write_ms, watch)
                    .await
                    .map(|(stream, rest)| (stream, shrink_idle_buffer(rest, consumed)));
            }
            Ok(Done::File(f)) => {
                let close = head.connection_close || *shutdown.borrow();
                return relay_file(stream, buf, &head, *f, close, write_ms)
                    .await
                    .map(|(stream, rest)| (stream, shrink_idle_buffer(rest, consumed)));
            }
            Err(_) => return None,
            Ok(Done::Upgrade(plan)) => {
                // The client stream (and the bytes read past the handshake) become the relay's.
                let task = tokio::spawn(crate::websocket::serve(
                    self.shared.clone(),
                    plan,
                    stream,
                    buf.to_vec(),
                    self.subscribe(),
                    shutdown.clone(),
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
        write_answer(stream, buf, &head, r, consumed, write_ms, shutdown).await
    }
}

/// Writes the answer. The connection ends with it when the response says so (`Connection:
/// close`, an upstream HTTP/1.0 answer, a close-delimited body) or the request / the draining
/// server does; else it stays open for the next request. `consumed` is what the request took
/// off the front of `buf`.
async fn write_answer(
    mut stream: Stream,
    buf: BytesMut,
    head: &head_parser::Head,
    r: OutboundResponse,
    consumed: usize,
    write_ms: i64,
    shutdown: &ShutdownWatch,
) -> Option<(Stream, BytesMut)> {
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
        Ok(Ok(())) => Some((stream, shrink_idle_buffer(buf, consumed))),
        _ => None,
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
/// chunk, which is how the client learns the body is cut. `watch`: an event stream, which ends
/// with the closing chunk and the connection when maintenance turns on for its client; the
/// upstream connection is dropped, not pooled.
#[allow(clippy::too_many_arguments)]
async fn relay(
    shared: &Shared,
    mut stream: Stream,
    buf: BytesMut,
    req: &head_parser::Head,
    mut up: crate::upstream::Streamed,
    closing: bool,
    write_ms: i64,
    mut watch: Option<Watch>,
) -> Option<(Stream, BytesMut)> {
    let chunked = up.head.upstream_chunked() && !req.http10;
    up.head.chunked = chunked;
    let close = up.head.close || closing || !chunked;
    let wire = up.head.wire(req.http10, true, close, now_unix());
    if !send(&mut stream, &[&wire], write_ms).await {
        return None;
    }
    loop {
        let next = match watch.as_mut() {
            Some(w) => tokio::select! {
                biased;
                () = w.maintenance_on() => {
                    if chunked {
                        send(&mut stream, &[b"0\r\n\r\n"], write_ms).await;
                    }
                    finish_close(stream, Vec::new(), write_ms).await;
                    return None;
                }
                next = up.next() => next,
            },
            None => up.next().await,
        };
        match next {
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

/// A file answer: the head goes out, then the span of the file in reads of
/// [`crate::static_files::CHUNK`] bytes, each written within the write deadline. The length in the
/// head was the file's size when it was opened and nothing is sent past it, so a file that grew is
/// cut at that size. A file that is cut short (or cannot be read) ends the connection with no more
/// bytes, which is how the client learns the body is incomplete. The connection stays open for the
/// next request when the answer, the request and the draining server allow it.
async fn relay_file(
    mut stream: Stream,
    buf: BytesMut,
    req: &head_parser::Head,
    file: crate::static_files::FileAnswer,
    closing: bool,
    write_ms: i64,
) -> Option<(Stream, BytesMut)> {
    let close = file.head.close || closing;
    let wire = file.head.wire(req.http10, true, close, now_unix());
    if !send(&mut stream, &[&wire], write_ms).await {
        return None;
    }
    let (mut at, end) = (file.offset, file.offset + file.len);
    let mut chunk = Vec::new();
    while at < end {
        let want = usize::try_from(end - at).map_or(crate::static_files::CHUNK, |n| {
            n.min(crate::static_files::CHUNK)
        });
        let source = file.file.clone();
        let read = tokio::task::spawn_blocking(move || {
            chunk.resize(want, 0);
            let got = crate::static_files::read_at_full(&source, &mut chunk, at);
            (chunk, got)
        })
        .await;
        let (piece, got) = match read {
            Ok((piece, Ok(got))) if got > 0 => (piece, got),
            Ok(_) => return None,
            Err(_) => {
                crate::metrics::count_agent_panic();
                return None;
            }
        };
        if !send(&mut stream, &[&piece[..got]], write_ms).await {
            return None;
        }
        crate::metrics::count_static_bytes(got as u64);
        at += got as u64;
        chunk = piece;
    }
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
        /// When the head's clock started: the accept, or the first byte of a kept-alive request.
        started: Instant,
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
    let mut started = Instant::now();
    let mut deadline = clock(started);
    // Bytes pipelined behind the previous request are parsed at once.
    let mut dirty = !buf.is_empty();
    loop {
        if dirty {
            match head_parser::parse_head(&buf[..buf.len().min(cap)]) {
                Ok(head) => {
                    return Head::Ready {
                        buffer: buf,
                        head,
                        started,
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
                    started = Instant::now();
                    deadline = clock(started);
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

/// Largest read buffer a kept-alive connection holds while it waits for its next request.
const IDLE_BUFFER_MAX: usize = 64 << 10;

/// The read buffer a connection keeps for its next request. A body read leaves the buffer as big as the
/// body (and a growth step beyond it); with hundreds of connections that is memory held for nothing, so a
/// request that filled a big buffer leaves the connection a fresh one holding only the bytes already
/// read past it.
///
/// `consumed` is what the request took off the front of `buf`: that prefix is still part of the
/// allocation, but `capacity()` of what is left does not count it, so it is added back here.
fn shrink_idle_buffer(buf: BytesMut, consumed: usize) -> BytesMut {
    if consumed + buf.capacity() <= IDLE_BUFFER_MAX {
        return buf;
    }
    BytesMut::from(&buf[..])
}

/// What the head read of a connection is bounded by.
#[derive(Clone, Copy)]
pub(crate) struct HeadLimits {
    /// The read buffer size: the longest head.
    pub cap: usize,
    pub read_to: Option<Duration>,
    /// The write timeout of an answer made before an app serves the request.
    pub write_ms: i64,
}

/// What a connection asks of its listener, so that one loop serves the plain listener of an app
/// and an HTTPS listener shared by several. A type parameter, not a trait object: the plain path
/// pays for none of it.
pub(crate) trait Site {
    /// The limits for the next head, read afresh each time because the route can be swapped.
    fn limits(&self) -> HeadLimits;
    /// The app for a request to `host` (lower case, as `head_parser::uri_parts` gives it); `None`
    /// when this connection must not serve it.
    fn app(&self, host: &[u8]) -> Option<Arc<RouteApp>>;
    /// What the handshake of the connection told, if the agent terminated TLS.
    fn tls(&self) -> Option<Arc<TlsClient>>;

    /// An answer that is made before the request is routed, and ends the connection: a certificate
    /// validation, or the refusal to serve a connection that was set up for a placeholder
    /// certificate. `None`: route the request.
    fn early_answer(&self, _method: &[u8], _parts: &UriParts) -> Option<OutboundResponse> {
        None
    }

    /// Whether a head of `len` bytes fits `app`'s read buffer, for a listener whose head read
    /// used the largest buffer of its apps.
    fn head_fits(&self, _app: &RouteApp, _len: usize) -> bool {
        true
    }

    /// The deadline of the body of a request routed to `app`; `started` is when the head's clock
    /// began and `head_deadline` the one the head was read under.
    fn body_deadline(
        &self,
        _app: &RouteApp,
        _started: Instant,
        head_deadline: Option<Instant>,
    ) -> Option<Instant> {
        head_deadline
    }
}

/// The plain listener of one app.
pub(crate) struct PlainSite(pub Arc<RouteApp>);

impl Site for PlainSite {
    fn limits(&self) -> HeadLimits {
        let route = self.0.route();
        HeadLimits {
            cap: route.header_buffer_size(),
            read_to: ms(route.proxy_config.timeouts.read_ms),
            write_ms: route.proxy_config.timeouts.write_ms,
        }
    }

    fn app(&self, _host: &[u8]) -> Option<Arc<RouteApp>> {
        Some(self.0.clone())
    }

    fn tls(&self) -> Option<Arc<TlsClient>> {
        None
    }
}

/// The client side of one connection.
struct Peer {
    ip: Option<IpAddr>,
    tls: Option<Arc<TlsClient>>,
}

/// The connection loop for HTTP/1 (no h2c): the requests are read, bounded and answered one at a
/// time.
pub(crate) async fn serve_connection<S: Site>(site: S, stream: Stream, mut stop: ShutdownWatch) {
    let peer = Peer {
        ip: stream
            .get_socket_digest()
            .and_then(|d| d.peer_addr().and_then(|a| a.as_inet()).map(|a| a.ip())),
        tls: site.tls(),
    };
    let mut stream = stream;
    let (mut prefix, mut first) = (BytesMut::new(), true);
    loop {
        let limits = site.limits();
        let head = read_head(
            &mut stream,
            prefix,
            limits.cap,
            first,
            limits.read_to,
            &mut stop,
        )
        .await;
        match head {
            Head::Close => return,
            Head::Answer(r) => return reject(stream, r, limits.write_ms).await,
            Head::Ready {
                buffer: buf,
                head,
                started,
                deadline,
            } => {
                // The request target is parsed before the body is read.
                let Ok(parts) = head_parser::uri_parts(&head.host, &head.request_target) else {
                    return reject(stream, malformed_request_response(), limits.write_ms).await;
                };
                if let Some(r) = site.early_answer(&head.method, &parts) {
                    return reject(stream, r, limits.write_ms).await;
                }
                let Some(app) = site.app(&parts.host) else {
                    let r = OutboundResponse::error(421, "Misdirected Request");
                    return reject(stream, r, limits.write_ms).await;
                };
                if !site.head_fits(&app, head.len) {
                    // The app is chosen: its own write timeout holds, not the listener's.
                    let write_ms = app.route().proxy_config.timeouts.write_ms;
                    return reject(stream, too_big_request(), write_ms).await;
                }
                let deadline = site.body_deadline(&app, started, deadline);
                match app
                    .serve_one(stream, buf, head, parts, deadline, &peer, &stop)
                    .await
                {
                    Some((s, rest)) => (stream, prefix, first) = (s, rest, false),
                    None => return,
                }
            }
        }
    }
}

/// The connection of a plain listener that redirects to HTTPS: one answer (a certificate
/// validation, the redirect, or the wait for a certificate), then the connection closes. It has
/// no route, so the head is read with fixed limits.
pub(crate) async fn serve_redirect(
    table: Arc<RedirectTable>,
    mut stream: Stream,
    mut stop: ShutdownWatch,
) {
    const HEAD_LIMIT: usize = 16 * 1024;
    const READ_TIMEOUT: Duration = Duration::from_secs(10);
    const WRITE_MS: i64 = 10_000;
    let head = read_head(
        &mut stream,
        BytesMut::new(),
        HEAD_LIMIT,
        true,
        Some(READ_TIMEOUT),
        &mut stop,
    )
    .await;
    let answer = match head {
        Head::Close => return,
        Head::Answer(r) => r,
        Head::Ready { head, .. } => {
            match head_parser::uri_parts(&head.host, &head.request_target) {
                Ok(parts) => table.answer(&head.method, &parts),
                Err(()) => malformed_request_response(),
            }
        }
    };
    reject(stream, answer, WRITE_MS).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_buffer_shrinks_only_when_big_and_keeps_the_pending_bytes() {
        let mut big = BytesMut::with_capacity(IDLE_BUFFER_MAX * 2);
        big.extend_from_slice(b"GET /");
        let kept = shrink_idle_buffer(big, 0);
        assert_eq!(&kept[..], b"GET /");
        assert!(kept.capacity() <= IDLE_BUFFER_MAX);
        assert_eq!(
            shrink_idle_buffer(BytesMut::with_capacity(4096), 300).capacity(),
            4096
        );
    }

    /// A body that ends near the end of a big allocation leaves a small view of it; the request
    /// still read a big buffer, so the next request must not inherit it.
    #[test]
    fn idle_buffer_shrinks_after_a_body_that_ended_near_the_allocation_end() {
        let mut big = BytesMut::with_capacity(IDLE_BUFFER_MAX * 3);
        big.resize(IDLE_BUFFER_MAX * 2 + 1000, 0);
        big.extend_from_slice(b"GET /");
        let consumed = big.len() - 5;
        big.advance(consumed);
        assert!(
            big.capacity() <= IDLE_BUFFER_MAX,
            "the view hides the allocation"
        );
        let kept = shrink_idle_buffer(big, consumed);
        assert_eq!(&kept[..], b"GET /");
        assert!(kept.capacity() < 1024);
    }
}
