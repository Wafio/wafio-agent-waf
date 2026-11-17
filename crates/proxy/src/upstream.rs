//! HTTP upstream forwarding (the allow path of the pipeline): the upstream request is a copy of
//! the client request plus the hop-by-hop strip, the body (field rules applied), the Host mode,
//! client headers, `X-Forwarded-Host/Proto` and the route's request-header rules; sent with
//! Pingora's `Connector` after analysis, with the route's connection cap and wait, the upstream
//! timeout and the one retry on a stale connection. The response is read whole into an
//! [`OutboundResponse`], except a body with no length up front (chunked, or ended by the
//! upstream closing): that one is a [`Streamed`] answer, relayed piece by piece as it arrives.

use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use pingora::http::{Method, RequestHeader, Version};
use pingora::protocols::http::client::HttpSession;
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType};
use tokio::sync::OwnedSemaphorePermit;
use wafio_agent_io::client_ip::{is_client_address_header, outgoing_forwarded_for};
use wafio_bytetext::strings::trim_whitespace;
use wafio_domain::ip_address::IpAddress;

use crate::config::{HttpTarget, Route};
use crate::proxy::Shared;
use crate::request::{InboundRequest, title_case_header_key};
use crate::response::OutboundResponse;

/// The upstream request header: the special headers apart from the other lines.
#[derive(Debug, Default)]
pub(crate) struct UpstreamHeaders {
    pub user_agent: Vec<u8>,
    /// What the wire `Host` line says (it overwrites the header's host, an empty one included:
    /// no `Host` line then).
    pub host: Vec<u8>,
    /// The header's own host, which only decides whether the client refuses a request with no
    /// host at all.
    pub host_header_value: Vec<u8>,
    pub content_type: Vec<u8>,
    /// The `Content-Length` text as copied from the request (what a bodyless GET/HEAD writes).
    pub content_length: Option<Vec<u8>>,
    /// The `Trailer` names, written as one `Trailer` line after the header lines; the lines they
    /// name are left out.
    pub trailer: Vec<Vec<u8>>,
    pub cookies: Vec<(Vec<u8>, Vec<u8>)>,
    pub header_lines: Vec<(Vec<u8>, Vec<u8>)>,
}

impl UpstreamHeaders {
    /// A copy of the request's headers: the header lines (`Transfer-Encoding: chunked` of a
    /// non-empty chunked body included until the length is set), the `Trailer` names and the
    /// special headers; a `Connection: close` is dropped with the Connection header below.
    pub fn copy_of(req: &InboundRequest) -> UpstreamHeaders {
        UpstreamHeaders {
            user_agent: req.user_agent.clone(),
            host: req.host.clone(),
            host_header_value: req.host_header_value.clone(),
            content_type: req.content_type.clone(),
            content_length: req
                .headers
                .get(&b"Content-Length"[..])
                .and_then(|v| v.first())
                .cloned(),
            trailer: req.trailer.clone(),
            cookies: req.cookies.clone(),
            header_lines: req.lines.clone(),
        }
    }

    /// A deleted line swaps places with the last one, so every delete permutes the lines that
    /// follow it (two lines of one name come out in the other order).
    fn del_all(h: &mut Vec<(Vec<u8>, Vec<u8>)>, key: &[u8]) {
        crate::request::remove_all_lines_named(h, key);
    }

    pub fn del(&mut self, k: &[u8]) {
        let k = title_case_header_key(k);
        match k.as_slice() {
            b"Host" => self.host_header_value.clear(),
            b"Content-Type" => self.content_type.clear(),
            b"User-Agent" => self.user_agent.clear(),
            b"Cookie" => self.cookies.clear(),
            b"Content-Length" => self.content_length = None,
            b"Trailer" => self.trailer.clear(),
            _ => {}
        }
        Self::del_all(&mut self.header_lines, &k);
    }

    /// Sets a header: specials are replaced, else the first line of that name.
    pub fn set(&mut self, k: &[u8], v: &[u8]) {
        let k = title_case_header_key(k);
        match k.as_slice() {
            b"Host" => self.host_header_value = v.to_vec(),
            b"Content-Type" => self.content_type = v.to_vec(),
            b"User-Agent" => self.user_agent = v.to_vec(),
            // A valid length is kept as written, Transfer-Encoding is managed.
            b"Content-Length" => {
                if crate::head_parser::parse_length_header(v).is_ok() {
                    self.content_length = Some(v.to_vec());
                }
            }
            b"Transfer-Encoding" => {}
            b"Trailer" => {
                // A value with a refused name keeps the names before it.
                self.trailer = crate::head_parser::trailer_names_lenient(v);
            }
            b"Cookie" => crate::request::parse_cookie_header(&mut self.cookies, v),
            _ => match self
                .header_lines
                .iter_mut()
                .find(|(n, _)| n.eq_ignore_ascii_case(&k))
            {
                Some(kv) => kv.1 = v.to_vec(),
                None => self.header_lines.push((k, v.to_vec())),
            },
        }
    }

    /// The request header to write: `content_length` is the `Content-Length` text to write,
    /// `body_len` the body it frames.
    fn build(
        &self,
        method: &[u8],
        request_uri: &[u8],
        content_length: Option<&[u8]>,
        body_len: usize,
    ) -> pingora::Result<RequestHeader> {
        let mut r = RequestHeader::build(method, request_uri, Some(self.header_lines.len() + 6))?;
        // The proxy names itself when the request carries no User-Agent.
        let ua: &[u8] = if self.user_agent.is_empty() {
            b"wafio-inline-proxy"
        } else {
            self.user_agent.as_slice()
        };
        r.append_header("User-Agent", ua)?;
        if !self.host.is_empty() {
            r.append_header("Host", self.host.as_slice())?;
        }
        let mut ct = self.content_type.as_slice();
        if ct.is_empty() && body_len > 0 {
            ct = b"application/octet-stream";
        }
        if !ct.is_empty() {
            r.append_header("Content-Type", ct)?;
        }
        if let Some(n) = content_length {
            r.append_header("Content-Length", n)?;
        }
        for (k, v) in &self.header_lines {
            // Exclude the lines `Trailer` names (they follow the body in a chunked request).
            if self.trailer.iter().any(|t| t == k) {
                continue;
            }
            // shortcut: a name or value http refuses is dropped.
            let _ = r.append_header(String::from_utf8_lossy(k).into_owned(), v.as_slice());
        }
        if !self.trailer.is_empty() {
            r.append_header("Trailer", self.trailer.join(&b", "[..]))?;
        }
        if !self.cookies.is_empty() {
            let mut c = Vec::new();
            for (i, (k, v)) in self.cookies.iter().enumerate() {
                if !k.is_empty() {
                    c.extend_from_slice(k);
                    c.push(b'=');
                }
                c.extend_from_slice(v);
                if i + 1 < self.cookies.len() {
                    c.extend_from_slice(b"; ");
                }
            }
            r.append_header("Cookie", c)?;
        }
        Ok(r)
    }
}

/// Builds the upstream request of the HTTP path. `forward_ct` replaces the Content-Type when
/// encrypt rules rewrote the body.
pub(crate) fn upstream_request(
    route: &Route,
    t: &HttpTarget,
    req: &InboundRequest,
    peer: &IpAddress,
    remote: &str,
    body: &[u8],
    forward_ct: Option<&[u8]>,
) -> pingora::Result<RequestHeader> {
    let mut u = UpstreamHeaders::copy_of(req);
    // RFC 7230 §6.1: the names the first Connection value lists (`peek`: `close` when the close
    // flag is set), then Connection and Upgrade.
    for name in req.peek("Connection").split(|&c| c == b',') {
        u.del(trim_whitespace(name));
    }
    u.del(b"Connection");
    u.del(b"Upgrade");
    if let Some(ct) = forward_ct {
        u.content_type = ct.to_vec();
    }
    match route.proxy_config.host_header.mode.as_str() {
        "upstream" => u.host = t.host.as_bytes().to_vec(),
        "custom" if !route.proxy_config.host_header.value.is_empty() => {
            u.host = route.proxy_config.host_header.value.as_bytes().to_vec()
        }
        _ => {}
    }
    // X-Real-IP = resolved client; X-Forwarded-For = trusted chain + peer, or the peer.
    // The names of every X-Real-IP / X-Forwarded-For line (any case, `_` for `-`) and of `Proxy`
    // (httpoxy) are collected first, deleted one by one (each delete swaps the line with the last
    // one, so the other lines move), then X-Real-IP and X-Forwarded-For are appended. The
    // operator's `request_headers` come after.
    let forwarded_for = outgoing_forwarded_for(peer, &req.lines, &route.proxy_config);
    let drop: Vec<Vec<u8>> = u
        .header_lines
        .iter()
        .map(|(n, _)| n)
        .filter(|n| is_client_address_header(n) || n.eq_ignore_ascii_case(b"Proxy"))
        .cloned()
        .collect();
    for name in drop {
        u.del(&name);
    }
    for (name, value) in [
        (&b"X-Real-Ip"[..], remote.as_bytes().to_vec()),
        (&b"X-Forwarded-For"[..], forwarded_for),
    ] {
        u.header_lines.push((name.to_vec(), value));
    }
    u.set(b"X-Forwarded-Host", &req.host);
    let proto = req.peek("X-Forwarded-Proto");
    u.set(
        b"X-Forwarded-Proto",
        if proto.is_empty() { b"http" } else { proto },
    );
    for name in &route.proxy_config.request_headers.remove {
        u.del(name.as_bytes());
    }
    for (name, val) in route.proxy_config.request_headers.add.iter().flatten() {
        u.set(name.as_bytes(), val.as_bytes());
    }
    // The userinfo of an absolute-form target becomes the Authorization header, after the header
    // rules and over any Authorization the client sent.
    if let Some((user, pass)) = &req.userinfo {
        let mut cred = user.clone();
        cred.push(b':');
        cred.extend_from_slice(pass);
        u.set(
            b"Authorization",
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(cred)
            )
            .as_bytes(),
        );
    }
    // The upstream client refuses a request without a Host: an HTTP/1.0 request that sent none
    // (host mode `preserve`) never reaches the upstream, the client answers 502 (conformance
    // scenario `rl-http10-nohost`).
    // With a `Host` header but no host in the URI (`GET ftp:////y`) the request goes out without a
    // `Host` line and the upstream decides.
    if u.host.is_empty() && u.host_header_value.is_empty() {
        return Err(Error::explain(
            ErrorType::InvalidHTTPHeader,
            "missing required Host header in request",
        ));
    }
    // The length is set from the body for every method but GET/HEAD and for any body, which also
    // swap-deletes the `Transfer-Encoding` line of a chunked request (the lines after it move). A
    // bodyless GET/HEAD keeps what the header carried: the `Content-Length` text as the client
    // wrote it (`Content-Length: 00` goes out as `00`), or 0 for a chunked body that came out
    // empty.
    if !body.is_empty() || !(req.method == b"GET" || req.method == b"HEAD") {
        u.content_length = Some(body.len().to_string().into_bytes());
        UpstreamHeaders::del_all(&mut u.header_lines, b"Transfer-Encoding");
    }
    let cl = u.content_length.clone();
    let mut head = u.build(
        &req.method,
        &req.forward_request_target,
        cl.as_deref(),
        body.len(),
    )?;
    if req.proto_pre11 {
        // The request protocol is kept: an HTTP/1.0 request goes to the upstream as HTTP/1.0.
        head.set_version(Version::HTTP_10);
    }
    Ok(head)
}

async fn peer_for(route: &Route, t: &HttpTarget) -> pingora::Result<HttpPeer> {
    let mut peer = match &t.unix {
        Some(path) => HttpPeer::new_uds(path, false, String::new())?,
        None => {
            let addr = t
                .resolve()
                .await
                .map_err(|e| Error::because(ErrorType::ConnectError, "resolve upstream", e))?;
            let sni = t
                .host
                .rsplit_once(':')
                .map_or(t.host.as_str(), |(h, _)| h)
                .trim_matches(['[', ']'])
                .to_string();
            HttpPeer::new(addr, t.scheme == "https", sni)
        }
    };
    peer.options.connection_timeout = Some(route.connect_deadline);
    if !route.upstream_unlimited {
        peer.options.read_timeout = Some(route.upstream_timeout);
        peer.options.write_timeout = Some(route.upstream_timeout);
    }
    Ok(peer)
}

fn retryable(e: &Error) -> bool {
    // A refused or unroutable connection, a bad header and a failed TLS handshake are not retried.
    !matches!(
        e.etype(),
        ErrorType::ConnectRefused
            | ErrorType::ConnectNoRoute
            | ErrorType::InvalidHTTPHeader
            | ErrorType::TLSHandshakeFailure
    )
}

/// Informational responses accepted in front of the final one.
const INTERIM_RESPONSE_LIMIT: usize = 100;

/// A 1xx the client skips: 101 Switching Protocols is the final response.
fn is_interim(status: u16) -> bool {
    (100..200).contains(&status) && status != 101
}

/// The status message of a raw response head: what follows the first space after the status
/// code, byte for byte (`None` when there is none).
fn status_message_of(raw: &[u8]) -> Option<Vec<u8>> {
    let end = memchr::memchr(b'\n', raw)?;
    let line = &raw[..end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut rest = &line[memchr::memchr(b' ', line)? + 1..];
    while let [b' ', r @ ..] = rest {
        rest = r;
    }
    let msg = &rest[memchr::memchr(b' ', rest)? + 1..];
    Some(msg.to_vec())
}

/// What one exchange hands back.
enum Exchange {
    Whole(OutboundResponse),
    /// The head only, with the upstream connection the body is still on.
    Open(OutboundResponse, Box<HttpSession>),
}

/// A response whose head is read and whose body is still on the upstream connection.
pub(crate) struct Streamed {
    pub head: OutboundResponse,
    up: Box<HttpSession>,
    peer: HttpPeer,
    keep: Duration,
    /// The route's upstream connection slot, held until the body ends.
    _slot: OwnedSemaphorePermit,
}

impl Streamed {
    /// The next piece of the body as the upstream sent it; `None` at its end. A quiet upstream
    /// is an error after the route's upstream timeout.
    pub async fn next(&mut self) -> pingora::Result<Option<Bytes>> {
        self.up.read_response_body().await
    }

    /// A connection whose body ended cleanly goes back to the pool; any other closes.
    pub async fn finish(mut self, shared: &Shared) {
        if self.up.response_done() {
            shared
                .connector
                .release_http_session(*self.up, &self.peer, Some(self.keep))
                .await;
        }
    }
}

/// What the HTTP path got back from the upstream.
pub(crate) enum Forwarded {
    Whole(OutboundResponse),
    Stream(Box<Streamed>),
}

/// One exchange: the response read whole, or with `stream` its head only when the body has no
/// length up front.
async fn exchange(
    shared: &Shared,
    route: &Route,
    peer: &HttpPeer,
    head: &RequestHeader,
    body: &[u8],
    stream: bool,
) -> pingora::Result<Exchange> {
    let (mut up, _reused) = shared.connector.get_http_session(peer).await?;
    up.write_request_header(Box::new(head.clone())).await?;
    if !body.is_empty() {
        up.write_request_body(body.to_vec().into(), true).await?;
    }
    up.finish_request_body().await?;
    up.read_response_header().await?;
    // Every 1xx but 101 (100 Continue, 103 Early Hints, …) is skipped, up to the interim response
    // limit; the next one is an error.
    let mut interim = 0;
    while up
        .response_header()
        .is_some_and(|r| is_interim(r.status.as_u16()))
    {
        if interim >= INTERIM_RESPONSE_LIMIT {
            return Err(Error::explain(
                ErrorType::InvalidHTTPHeader,
                "too many 1xx informational responses received",
            ));
        }
        interim += 1;
        up.read_response_header().await?;
    }
    let Some(resp) = up.response_header().cloned() else {
        return Err(Error::explain(
            ErrorType::ReadError,
            "no upstream response header",
        ));
    };
    let mut out = OutboundResponse::from_upstream(
        resp.status.as_u16(),
        resp.version == Version::HTTP_10,
        resp.headers
            .iter()
            .map(|(k, v)| (k.as_str().as_bytes(), v.as_bytes())),
    )
    .with_reason(
        // Pingora's parser (httparse) drops a reason phrase that holds obs-text; the raw head it kept
        // has the message bytes.
        up.as_http1()
            .and_then(|h1| status_message_of(&h1.get_headers_raw_bytes()))
            .or_else(|| resp.get_reason_phrase().map(|r| r.as_bytes().to_vec())),
    );
    if resp.status.as_u16() == 101 {
        // The answer of a 101 has no body; the connection is no longer HTTP.
        return Ok(Exchange::Whole(out));
    }
    if stream && out.body_unframed() && head.method != Method::HEAD {
        // The whole-exchange deadline ends here; from now on only the idle one applies, per read.
        if !route.upstream_unlimited {
            up.set_read_timeout(Some(route.upstream_timeout));
        }
        return Ok(Exchange::Open(out, Box::new(up)));
    }
    while let Some(chunk) = up.read_response_body().await? {
        out.body.extend_from_slice(&chunk);
    }
    if up.response_done() {
        shared
            .connector
            .release_http_session(up, peer, Some(route.idle_connection_timeout))
            .await;
    }
    Ok(Exchange::Whole(out))
}

/// Sends the request and reads the response, retried once. `stream`: a body with no length up
/// front is not read here.
pub(crate) async fn forward_http(
    shared: &Shared,
    route: &Route,
    t: &HttpTarget,
    head: RequestHeader,
    body: &[u8],
    stream: bool,
) -> Result<Forwarded, String> {
    // The connection cap and the wait for a free slot (0 = no wait): no slot is an error.
    let permit = match route.connection_slots.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) if route.connection_wait.is_zero() => {
            return Err("no free connections available to host".into());
        }
        Err(_) => {
            match tokio::time::timeout(
                route.connection_wait,
                route.connection_slots.clone().acquire_owned(),
            )
            .await
            {
                Ok(Ok(p)) => p,
                _ => return Err("timeout while waiting for a free connection to host".into()),
            }
        }
    };
    let peer = peer_for(route, t).await.map_err(|e| e.to_string())?;
    let attempt = || async {
        if route.upstream_unlimited {
            exchange(shared, route, &peer, &head, body, stream).await
        } else {
            match tokio::time::timeout(
                route.upstream_timeout,
                exchange(shared, route, &peer, &head, body, stream),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => Err(Error::explain(ErrorType::ReadTimedout, "timeout")),
            }
        }
    };
    let res = match attempt().await {
        Err(e) if retryable(&e) => attempt().await,
        r => r,
    };
    match res {
        Ok(Exchange::Whole(r)) => Ok(Forwarded::Whole(r)),
        Ok(Exchange::Open(head, up)) => Ok(Forwarded::Stream(Box::new(Streamed {
            head,
            up,
            peer,
            keep: route.idle_connection_timeout,
            _slot: permit,
        }))),
        Err(e) => Err(e.to_string()),
    }
}

/// The `response_headers` rules: remove, then add.
pub(crate) fn apply_response_header_rules(route: &Route, resp: &mut OutboundResponse) {
    for name in &route.proxy_config.response_headers.remove {
        resp.del(name.as_bytes());
    }
    for (name, val) in route.proxy_config.response_headers.add.iter().flatten() {
        resp.set(name.as_bytes(), val.as_bytes());
    }
}

/// Whether the path's rules rewrite the response body, which is then read whole.
pub(crate) fn rewrites_response_body(route: &Route, fwd_path: &[u8]) -> bool {
    let excs = &route.analysis.analyze.path_exceptions;
    !excs.is_empty()
        && wafio_engine_rules::find_exception_for_forwarded_path(fwd_path, excs).is_some_and(|e| {
            !e.response_decrypt_aes.is_empty() || !e.response_field_rules.is_empty()
        })
}

/// The response rules of the HTTP path: `response_headers` remove/add, then the path's
/// `response_decrypt_aes` and `response_field_rules`.
pub(crate) fn apply_response_rules(
    route: &Route,
    fwd_path: &[u8],
    uri: &[u8],
    resp: &mut OutboundResponse,
) {
    apply_response_header_rules(route, resp);
    let excs = &route.analysis.analyze.path_exceptions;
    if excs.is_empty() {
        return;
    }
    let Some(exc) = wafio_engine_rules::find_exception_for_forwarded_path(fwd_path, excs) else {
        return;
    };
    if !exc.response_decrypt_aes.is_empty() && !resp.body.is_empty() {
        match wafio_agent_pages::field_paths::decrypt_response_payload(
            &resp.body,
            &exc.response_decrypt_aes,
        ) {
            Ok(dec) => {
                resp.assign_content_type(crate::sniff::sniff_content_type(&dec).as_bytes());
                resp.body = dec;
            }
            Err(e) => tracing::warn!(
                "[inline-proxy] response decrypt error for {}: {e}",
                String::from_utf8_lossy(uri)
            ),
        }
    }
    if !exc.response_field_rules.is_empty()
        && !resp.body.is_empty()
        && wafio_bytetext::strings::contains(resp.content_type(), b"application/json")
    {
        let rules: Vec<_> = exc
            .response_field_rules
            .iter()
            .map(crate::pipeline::response_field_rule_from_engine)
            .collect();
        match wafio_agent_pages::field_paths::decrypt_json_response_fields(&resp.body, &rules) {
            Ok(dec) => resp.body = dec,
            Err(e) => tracing::warn!(
                "[inline-proxy] response JSON field decrypt error for {}: {e}",
                String::from_utf8_lossy(uri)
            ),
        }
    }
}

/// `Duration` of a positive `read_ms`/`write_ms` (0 or negative = no deadline).
pub(crate) fn ms(v: i64) -> Option<Duration> {
    (v > 0).then(|| Duration::from_millis(v as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(v: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        v.iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect()
    }

    /// The lines `Trailer` names are left out and `Trailer` itself is written after the others.
    #[test]
    fn trailer_lines_are_left_out_and_trailer_follows_the_others() {
        let req = InboundRequest::from_head(
            b"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTrailer: x-a, X-B\r\nX-A: 1\r\nX-C: 3\r\nX-B: 2\r\n\r\n",
        );
        let head = UpstreamHeaders::copy_of(&req)
            .build(b"POST", b"/p", Some(b"3"), 3)
            .unwrap();
        let got: Vec<(String, String)> = head
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
            .collect();
        assert!(
            got.contains(&("trailer".into(), "X-A, X-B".into())),
            "{got:?}"
        );
        assert!(got.contains(&("x-c".into(), "3".into())), "{got:?}");
        assert!(got.iter().all(|(k, _)| k != "x-a" && k != "x-b"), "{got:?}");
        // Deleting `Trailer` clears the names; the lines come back.
        let mut u = UpstreamHeaders::copy_of(&req);
        u.del(b"Trailer");
        assert!(u.trailer.is_empty());
    }

    /// The chunked request's `Transfer-Encoding` line stays in the copy (so the deletes before it
    /// permute the lines) until the length is set: its swap-delete moves the last line into its
    /// place.
    #[test]
    fn a_chunked_requests_transfer_encoding_leaves_with_the_length() {
        let raw = b"POST /p HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\nX-A: 2\r\nX-A: 3\r\n\r\n";
        let head = crate::head_parser::parse_head(raw).unwrap();
        let parts = crate::head_parser::uri_parts(&head.host, &head.request_target).unwrap();
        let req = InboundRequest::from_parsed(&head, parts, &[], false);
        let mut u = UpstreamHeaders::copy_of(&req);
        assert_eq!(
            u.header_lines[0],
            (b"Transfer-Encoding".to_vec(), b"chunked".to_vec())
        );
        UpstreamHeaders::del_all(&mut u.header_lines, b"Transfer-Encoding");
        assert_eq!(
            u.header_lines,
            lines(&[("X-A", "3"), ("X-A", "1"), ("X-A", "2")])
        );
        // A `Content-Length` header rule is kept as set; a bad one is ignored.
        u.set(b"Content-Length", b"7");
        assert_eq!(u.content_length, Some(b"7".to_vec()));
        u.set(b"Content-Length", b"x");
        assert_eq!(u.content_length, Some(b"7".to_vec()));
        u.del(b"Content-Length");
        assert_eq!(u.content_length, None);
    }

    #[test]
    fn the_status_message_is_what_follows_the_code() {
        let m = |l: &[u8]| status_message_of(l).map(|v| String::from_utf8_lossy(&v).into_owned());
        assert_eq!(m(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\n").as_deref(), Some("OK"));
        assert_eq!(
            m(b"HTTP/1.1 200   two  \r\n\r\n").as_deref(),
            Some("  two  ")
        );
        assert_eq!(m(b"HTTP/1.1 200 \r\n\r\n").as_deref(), Some(""));
        assert_eq!(m(b"HTTP/1.1 200\r\n\r\n"), None);
        assert_eq!(
            status_message_of(b"HTTP/1.1 201 \xe9\xff\r\n\r\n"),
            Some(b"\xe9\xff".to_vec())
        );
    }

    /// A deleted line swaps places with the last one: two lines of one name that follow a
    /// deleted header come out in the other order (found by the head fuzz: `Upgrade` before
    /// `X-A: 1`, `x-a: 2` forwarded `X-A: 2, 1`).
    #[test]
    fn deleting_a_header_permutes_the_lines_after_it() {
        let mut h = lines(&[("Upgrade", "websocket"), ("X-A", "1"), ("X-A", "2")]);
        UpstreamHeaders::del_all(&mut h, b"Upgrade");
        assert_eq!(h, lines(&[("X-A", "2"), ("X-A", "1")]));
        // Several matches, one of them last.
        let mut h = lines(&[("A", "1"), ("B", "x"), ("A", "2"), ("C", "y"), ("A", "3")]);
        UpstreamHeaders::del_all(&mut h, b"A");
        assert_eq!(h, lines(&[("C", "y"), ("B", "x")]));
        // Nothing to delete: the order stays.
        let mut h = lines(&[("A", "1"), ("B", "2")]);
        UpstreamHeaders::del_all(&mut h, b"Z");
        assert_eq!(h, lines(&[("A", "1"), ("B", "2")]));
    }
}
