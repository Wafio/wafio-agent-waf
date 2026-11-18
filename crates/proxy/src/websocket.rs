//! WebSocket takeover of the inline proxy. After Analyze allowed the handshake, the client
//! connection is taken from Pingora's session, the upstream is dialled and upgraded (agent-io
//! `WsConnection::client`), the client gets its 101 (echoing the upstream's subprotocol) and
//! messages are relayed: client→upstream rate-limited, size-capped and scanned (`ws_scanner`),
//! upstream→client only with `scan_server_frames`.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use pingora::server::ShutdownWatch;
use pingora::upstreams::peer::HttpPeer;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::watch;
use tokio::time::Instant;
use wafio_agent_io::client_ip::outgoing_forwarded_for;
use wafio_agent_io::ws_frame::{
    OP_BINARY, WS_CLOSE_GOING_AWAY, WS_CLOSE_MESSAGE_TOO_BIG, WS_CLOSE_NORMAL_CLOSURE,
    WS_CLOSE_POLICY_VIOLATION, WsConnection, WsError, WsRequestHead, WsStream,
};
use wafio_agent_io::ws_scanner::{
    WsContentScan, WsDetailed, WsFieldCoverage, WsMessageRateLimiter, WsScanBudget, WsScanField,
    WsScanVerdict, WsSemantic, build_scan_input, default_scan_budget, incomplete_frame_action,
    scan_frame_payload, scan_printable_runs,
};
use wafio_bytetext::strings::{eq_ignore_case, trim_whitespace};
use wafio_domain::AnalysisResult;
use wafio_domain::ip_address::IpAddress;
use wafio_engine_api::{SemanticConfig, Tier, decision_score, disabled_key_from_reason, engine};

use crate::config::{Route, Target};
use crate::decision::{DecisionEvent, DecisionSink, now_unix};
use crate::maintenance::Watch;
use crate::proxy::Shared;
use crate::request::{InboundRequest, title_case_header_key};
use crate::response::OutboundResponse;

/// How long the upstream dial may take.
const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The idle timeout when the route sets none.
const WS_FALLBACK_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// Longest preview of a frame payload, in bytes.
const WS_PREVIEW_BYTE_CAP: usize = 256;
/// How long the close frames of a session that must end may take before the connections are cut.
const WS_END_TIMEOUT: Duration = Duration::from_secs(2);
/// The answer when the upstream cannot be reached.
const WS_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
/// The body of the answer to a refused origin.
const ORIGIN_REJECTED_BODY: &str =
    r#"{"error":"websocket origin not allowed","code":"ws_origin_rejected"}"#;

// Standard base64: padding required, non-zero trailing bits accepted.
const STANDARD_BASE64_PADDED: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
        .with_decode_allow_trailing_bits(true),
);

/// Whether a comma-separated list holds `token` (ASCII case-insensitive).
fn list_has_token(v: &[u8], token: &[u8]) -> bool {
    v.split(|&c| c == b',')
        .any(|p| eq_ignore_case(trim_whitespace(p), token))
}

/// Whether the request is a valid WebSocket handshake: GET, `Upgrade: websocket`, a `Connection`
/// that lists `upgrade`, version 13 and a 16-byte base64 key.
pub fn is_websocket_upgrade_request(req: &InboundRequest) -> bool {
    if !req.is_get_method() || !eq_ignore_case(req.peek("Upgrade"), b"websocket") {
        return false;
    }
    if !list_has_token(req.peek("Connection"), b"upgrade")
        || trim_whitespace(req.peek("Sec-WebSocket-Version")) != b"13"
    {
        return false;
    }
    STANDARD_BASE64_PADDED
        .decode(trim_whitespace(req.peek("Sec-WebSocket-Key")))
        .is_ok_and(|k| k.len() == 16)
}

/// WebSocket enabled, not FastCGI, a valid GET handshake.
pub fn route_accepts_websocket(route: &Route, req: &InboundRequest) -> bool {
    route.fcgi().is_none() && route.ws.enabled && is_websocket_upgrade_request(req)
}

/// The engine calls of the scanner, bound to one semantic config.
struct Sem<'a>(&'a SemanticConfig);

impl WsSemantic for Sem<'_> {
    fn extract_scan_fields(&self, payload: &[u8]) -> (Vec<WsScanField>, WsFieldCoverage) {
        let (fields, cov) = engine().frame_fields(payload);
        let fields = fields
            .into_iter()
            .map(|f| WsScanField {
                value: f.value,
                source: f.source,
                summary: f.summary,
            })
            .collect();
        (
            fields,
            WsFieldCoverage {
                field_capped: cov.field_capped,
                skipped: cov.skipped,
                binary_text: cov.binary_text,
            },
        )
    }

    fn scan_semantics_detailed(&self, value: &[u8]) -> WsDetailed {
        let r = engine().scan_value(value, self.0);
        let mut out = WsDetailed {
            tier: r.tier,
            reason: r.reason.to_string(),
            engines: r.engines,
            truncated: r.truncated,
            ..Default::default()
        };
        if self.0.log_only_engines.is_some()
            && r.tier == Tier::Strong
            && self.0.is_log_only(&disabled_key_from_reason(r.reason))
        {
            // The block is what the other engines find: the scan again, as if the log-only ones were off.
            let rest = engine().scan_value(value, &self.0.without_log_only());
            out.held_reason = std::mem::take(&mut out.reason);
            (out.tier, out.reason) = (rest.tier, rest.reason.to_string());
        }
        out
    }
}

/// Everything captured before the takeover: the session and the relay options.
pub(crate) struct WsPlan {
    app_id: String,
    mode: String,
    host: Vec<u8>,
    uri: Vec<u8>,
    remote: String,
    /// The decoded path of the handshake: with `remote`, what maintenance mode lets a session stay for.
    forward_path: Vec<u8>,
    sem: Arc<SemanticConfig>,
    scan_upstream_frames: bool,
    /// The route executor's malware engine over a binary frame; `None` when
    /// `websocket.scan_binary_hashes` is off or the executor has no engine.
    binary_scanner: Option<BinaryScanner>,
    /// A weak detection in a frame is logged (the project's `record_weak_detections`).
    records_weak: bool,
    on_incomplete: String,
    /// Upstream: unix socket or "host:port" + TLS, the client's Host and request-target.
    peer_host: String,
    unix: Option<String>,
    tls: bool,
    ws_host: String,
    request_target: String,
    header: Vec<(String, String)>,
    head: WsRequestHead,
    limits: WsScanBudget,
    idle: Duration,
    sink: DecisionSink,
    resolve: Arc<Route>,
}

static SCAN_BINARY_NO_ENGINE: Once = Once::new();

/// Hashes a binary frame against the malware database.
type BinaryScanner = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// What the upgrade hook decided before the takeover.
pub(crate) enum Hook {
    /// Origin refused: answer this (plain HTTP), no takeover.
    Respond(OutboundResponse),
    Takeover(Box<WsPlan>),
}

/// The upgrade hook, up to the takeover. `action` is the pipeline verdict ("allow",
/// "log" or the remapped "monitor"); `v` carries the merged verdict fields.
pub(crate) fn hook(
    shared: &Shared,
    route: &Arc<Route>,
    req: &InboundRequest,
    peer: &IpAddress,
    remote: &str,
    action: &str,
    v: &AnalysisResult,
) -> Hook {
    let exec = &route.analysis;
    let sem = match exec.analyze.base_semantic_config() {
        Some(s) => Arc::new(s.clone()),
        None => Arc::new(SemanticConfig::default()),
    };
    let cs = exec.analyze.content_scan.as_ref().map(|c| WsContentScan {
        enabled: c.enabled,
        mode: c.mode.clone(),
        on_incomplete: c.on_incomplete.clone(),
    });
    let base = DecisionEvent {
        app_id: route.app_id.as_bytes().to_vec(),
        host: req.host.clone(),
        method: b"WEBSOCKET".to_vec(),
        uri: req.request_target.clone(),
        remote_addr: remote.as_bytes().to_vec(),
        mode: route.mode.as_bytes().to_vec(),
        match_source: b"ws:handshake".to_vec(),
        ..Default::default()
    };
    // CSWSH defense, before any takeover: a disallowed (or missing) Origin gets 403.
    if route.ws.origin_check.enabled && !route.ws.origin_check.permits_origin(req.peek("Origin")) {
        (shared.decisions)(DecisionEvent {
            action: b"block".to_vec(),
            categories: vec![b"WebSocket".to_vec()],
            match_detail: b"ws_origin_rejected".to_vec(),
            analyze_method: b"ws_origin_check".to_vec(),
            event_time_unix: now_unix(),
            status: 403,
            ..base
        });
        return Hook::Respond(OutboundResponse::with(
            403,
            "application/json",
            ORIGIN_REJECTED_BODY,
        ));
    }
    // scan_binary_hashes: binary frames hashed against the route executor's malware engine.
    let mut scan_bin: Option<BinaryScanner> = None;
    if route.ws.scan_binary_hashes {
        match exec.analyze.malware_hash_engine.clone() {
            Some(eng) => scan_bin = Some(Arc::new(move |b: &[u8]| eng.match_bytes(b).0)),
            None => SCAN_BINARY_NO_ENGINE.call_once(|| {
                tracing::warn!("[ws-proxy] app={}: websocket.scan_binary_hashes enabled but no malware engine loaded (content_scan off?); binary frames are not hashed", route.app_id)
            }),
        }
    }
    if action == "monitor" || action == "log" {
        (shared.decisions)(DecisionEvent {
            action: action.as_bytes().to_vec(),
            score: v.score,
            categories: v.categories.iter().map(|c| c.as_bytes().to_vec()).collect(),
            cwe: v.cwe.as_bytes().to_vec(),
            match_detail: v.match_detail.clone(),
            analyze_method: b"handshake".to_vec(),
            event_time_unix: now_unix(),
            coverage: crate::decision::event_coverage(v).into_bytes(),
            ..base.clone()
        });
    }
    let Target::Http(t) = &route.target else {
        unreachable!("ws_handshake_for_route excludes FastCGI")
    };
    // The dial target: the forwarded path and the raw query.
    let mut request_uri = Vec::new();
    crate::request::push_escaped_path(&mut request_uri, &req.forward_path);
    if !req.query.is_empty() {
        request_uri.push(b'?');
        request_uri.extend_from_slice(&req.query);
    }
    let mut limits = default_scan_budget();
    if route.ws.limits.max_text_bytes > 0 {
        limits.max_text_size = route.ws.limits.max_text_bytes as usize;
    }
    if route.ws.limits.max_binary_bytes > 0 {
        limits.max_binary_size = route.ws.limits.max_binary_bytes as usize;
    }
    if route.ws.limits.max_msgs_per_min > 0 {
        limits.max_msgs_per_min = route.ws.limits.max_msgs_per_min;
    }
    let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    Hook::Takeover(Box::new(WsPlan {
        app_id: route.app_id.clone(),
        mode: route.mode.clone(),
        host: req.host.clone(),
        uri: req.request_target.clone(),
        remote: remote.to_string(),
        forward_path: req.forward_path.clone(),
        sem,
        scan_upstream_frames: route.ws.scan_server_frames,
        binary_scanner: scan_bin,
        records_weak: exec.analyze.records_weak_detections(),
        on_incomplete: incomplete_frame_action(cs.as_ref()),
        peer_host: t.host.clone(),
        unix: t.unix.clone(),
        tls: t.scheme == "https",
        ws_host: t.host.clone(),
        request_target: lossy(&request_uri),
        header: build_upstream_handshake_headers(route, req, peer, remote),
        head: WsRequestHead {
            method: lossy(&req.method),
            request_target: lossy(&req.request_target),
            headers: req
                .headers
                .iter()
                .flat_map(|(k, vs)| vs.iter().map(move |v| (lossy(k), lossy(v))))
                .collect(),
        },
        limits,
        idle: WS_FALLBACK_IDLE_TIMEOUT,
        sink: shared.decisions.clone(),
        resolve: route.clone(),
    }))
}

/// The headers of the upstream handshake (canonical names, a set replaces every value).
fn build_upstream_handshake_headers(
    route: &Route,
    req: &InboundRequest,
    peer: &IpAddress,
    remote: &str,
) -> Vec<(String, String)> {
    let mut h: Vec<(String, String)> = Vec::new();
    let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    for (k, vs) in &req.headers {
        if matches!(
            k.to_ascii_lowercase().as_slice(),
            b"origin" | b"cookie" | b"authorization" | b"sec-websocket-protocol" | b"user-agent"
        ) {
            for v in vs {
                h.push((lossy(&title_case_header_key(k)), lossy(v)));
            }
        }
    }
    let set = |h: &mut Vec<(String, String)>, k: &str, v: String| {
        let k = lossy(&title_case_header_key(k.as_bytes()));
        h.retain(|(n, _)| *n != k);
        h.push((k, v));
    };
    set(&mut h, "X-Real-IP", remote.to_string());
    set(
        &mut h,
        "X-Forwarded-For",
        lossy(&outgoing_forwarded_for(
            peer,
            &req.lines,
            &route.proxy_config,
        )),
    );
    match route.proxy_config.host_header.mode.as_str() {
        "upstream" => {
            if let Target::Http(t) = &route.target {
                set(&mut h, "Host", t.host.clone())
            }
        }
        "custom" if !route.proxy_config.host_header.value.is_empty() => {
            set(&mut h, "Host", route.proxy_config.host_header.value.clone())
        }
        "custom" => {}
        _ if !req.host.is_empty() => set(&mut h, "Host", lossy(&req.host)),
        _ => {}
    }
    for name in &route.proxy_config.request_headers.remove {
        let k = lossy(&title_case_header_key(name.as_bytes()));
        h.retain(|(n, _)| *n != k);
    }
    for (name, val) in route.proxy_config.request_headers.add.iter().flatten() {
        set(&mut h, name, val.clone());
    }
    h
}

/// A stream whose first reads return bytes the HTTP parser already consumed.
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.pos);
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl WsPlan {
    fn emit_scan_event(
        &self,
        source: &[u8],
        action: &str,
        detail: &str,
        score: i64,
        payload: &[u8],
    ) {
        self.emit_event(source, action, detail, score, payload, "");
    }

    fn emit_event(
        &self,
        source: &[u8],
        action: &str,
        detail: &str,
        score: i64,
        payload: &[u8],
        coverage: &str,
    ) {
        (self.sink)(DecisionEvent {
            app_id: self.app_id.as_bytes().to_vec(),
            host: self.host.clone(),
            method: b"WEBSOCKET".to_vec(),
            uri: self.uri.clone(),
            remote_addr: self.remote.as_bytes().to_vec(),
            action: action.as_bytes().to_vec(),
            score,
            categories: vec![b"WebSocket".to_vec()],
            match_detail: detail.as_bytes().to_vec(),
            analyze_method: b"ws_frame_scan".to_vec(),
            body_preview: payload[..payload.len().min(WS_PREVIEW_BYTE_CAP)].to_vec(),
            mode: self.mode.as_bytes().to_vec(),
            event_time_unix: now_unix(),
            match_source: source.to_vec(),
            coverage: coverage.as_bytes().to_vec(),
            // A frame travels on an upgraded connection.
            status: 101,
            ..Default::default()
        });
    }

    /// Block tier: closes in block mode, reports "monitor" (frame relayed) otherwise.
    async fn apply_block_action(
        &self,
        source: &[u8],
        close_to: &WsConnection,
        detail: &str,
        score: i64,
        text: &[u8],
    ) -> bool {
        if self.mode == "block" {
            self.emit_scan_event(source, "block", detail, score, text);
            let _ = close_to
                .send_close(WS_CLOSE_POLICY_VIOLATION, "Blocked by WAF")
                .await;
            return true;
        }
        self.emit_scan_event(source, "monitor", detail, score, text);
        false
    }

    /// Size cap and scan of one data frame; true = the relay stops.
    async fn evaluate_frame(
        &self,
        source: &[u8],
        close_to: &WsConnection,
        kind: u8,
        payload: &[u8],
        max_text: usize,
    ) -> bool {
        let view = build_scan_input(kind, payload, max_text);
        if view.oversize {
            self.emit_scan_event(
                source,
                "block",
                "ws_text_oversize",
                0,
                view.text.as_deref().unwrap_or_default(),
            );
            let _ = close_to
                .send_close(WS_CLOSE_MESSAGE_TOO_BIG, "Message too large")
                .await;
            return true;
        }
        let Some(text) = view.text else { return false };
        let sem = self.sem.clone();
        let runs = view.runs;
        // A big frame is scanned under `block_in_place` like a big request body (lib.rs).
        let res: WsScanVerdict = crate::run_detection_async(text.len(), || {
            if runs {
                scan_printable_runs(&Sem(&sem), &text)
            } else {
                scan_frame_payload(&Sem(&sem), &text)
            }
        })
        .await;
        let mut incomplete = format!("ws_scan_incomplete:{}", res.incomplete);
        if !res.reason.is_empty() {
            incomplete = format!("{incomplete}; {}", res.reason);
        }
        let score = decision_score(&res.reason, res.tier);
        if res.tier == Tier::Strong {
            return self
                .apply_block_action(source, close_to, &res.reason, score, &text)
                .await;
        }
        if !res.incomplete.is_empty() && self.on_incomplete == "block" {
            return self
                .apply_block_action(source, close_to, &incomplete, score, &text)
                .await;
        }
        if !res.held_reason.is_empty() {
            // A log-only engine's block: the frame passes and the event says which engine held it.
            let mark = format!(
                "engine_log_only:{}",
                disabled_key_from_reason(&res.held_reason)
            );
            self.emit_event(
                source,
                "log",
                &res.held_reason,
                decision_score(&res.held_reason, Tier::Strong),
                &text,
                &mark,
            );
        } else if !res.incomplete.is_empty() && self.on_incomplete == "log" {
            self.emit_scan_event(source, "log", &incomplete, score, &text);
        } else if res.tier == Tier::Weak && self.records_weak {
            self.emit_scan_event(source, "log", &res.reason, score, &text);
        }
        false
    }
}

/// Forwards a close frame to `dst`, with an invalid code replaced by a normal closure.
async fn relay_close_frame(dst: &WsConnection, err: &WsError) {
    let WsError::Close { code, text } = err else {
        return;
    };
    let code = if *code < 1000 || *code > 4999 || matches!(code, 1005 | 1006 | 1015) {
        WS_CLOSE_NORMAL_CLOSURE
    } else {
        *code
    };
    let _ = dst.send_close(code, text).await;
}

async fn bad_gateway(mut client: impl AsyncWrite + Unpin) {
    let _ = tokio::time::timeout(WS_CONNECT_TIMEOUT, client.write_all(WS_BAD_GATEWAY)).await;
    let _ = client.shutdown().await;
}

/// Serves the takeover: runs on its own task. `route` follows the app's route swaps and `stop`
/// the draining of the listener: the session ends with a close frame when maintenance turns on
/// for its client or the listener stops (a reload, a shutdown, the app removed).
pub(crate) async fn serve(
    shared: Arc<Shared>,
    plan: Box<WsPlan>,
    client: pingora::protocols::Stream,
    prefix: Vec<u8>,
    route: watch::Receiver<Arc<Route>>,
    stop: ShutdownWatch,
) {
    let client = PrefixedStream {
        prefix,
        pos: 0,
        inner: client,
    };
    let peer = match &plan.unix {
        Some(p) => HttpPeer::new_uds(p, false, String::new()).ok(),
        None => match plan.resolve.target_address().await {
            Ok(a) => Some(HttpPeer::new(
                a,
                plan.tls,
                plan.peer_host
                    .rsplit_once(':')
                    .map_or("", |(h, _)| h)
                    .trim_matches(['[', ']'])
                    .to_string(),
            )),
            Err(_) => None,
        },
    };
    let Some(mut peer) = peer else {
        tracing::warn!(
            "[ws-proxy] app={} upstream {} dial: cannot resolve",
            plan.app_id,
            plan.peer_host
        );
        return bad_gateway(client).await;
    };
    peer.options.connection_timeout = Some(WS_CONNECT_TIMEOUT);
    let up = match shared.transport.new_stream(&peer).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "[ws-proxy] app={} upstream {} dial: {e}",
                plan.app_id,
                plan.peer_host
            );
            return bad_gateway(client).await;
        }
    };
    let (upstream, subprotocol) = match WsConnection::client(
        Box::new(up),
        &plan.ws_host,
        &plan.request_target,
        &plan.header,
    )
    .await
    {
        Ok(r) => r,
        Err((e, _)) => {
            tracing::warn!(
                "[ws-proxy] app={} upstream {} handshake: {e}",
                plan.app_id,
                plan.peer_host
            );
            return bad_gateway(client).await;
        }
    };
    let client = match WsConnection::server_from_request(
        Box::new(client) as Box<dyn WsStream>,
        &plan.head,
        &subprotocol,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("[ws-proxy] app={} client upgrade: {e}", plan.app_id);
            upstream.close().await;
            return;
        }
    };
    let watch = Watch::new(route, plan.remote.clone(), plan.forward_path.clone());
    relay(
        Arc::new(client),
        Arc::new(upstream),
        Arc::new(*plan),
        watch,
        stop,
    )
    .await;
}

/// Relays messages between the client and the upstream until one side ends, or until `watch`
/// says maintenance mode applies to this client or `stop` says the listener is going away: then
/// both sides get a close frame (1001) and the connections are cut, without waiting for a reply.
async fn relay(
    client: Arc<WsConnection>,
    upstream: Arc<WsConnection>,
    s: Arc<WsPlan>,
    mut watch: Watch,
    mut stop: ShutdownWatch,
) {
    let limits = s.limits;
    client.set_max_message_bytes(limits.max_binary_size as i64);
    upstream.set_max_message_bytes(limits.max_binary_size as i64);
    let limiter = Arc::new(WsMessageRateLimiter::new(limits.max_msgs_per_min));
    let closed = Arc::new(AtomicBool::new(false));
    let close_both = {
        let (c, u, closed) = (client.clone(), upstream.clone(), closed.clone());
        move || {
            let (c, u, closed) = (c.clone(), u.clone(), closed.clone());
            async move {
                if closed.swap(true, Ordering::AcqRel) {
                    return;
                }
                let now = Instant::now();
                for x in [&c, &u] {
                    x.set_read_expiry(Some(now));
                    x.set_write_expiry(Some(now));
                }
                c.close().await;
                u.close().await;
            }
        }
    };
    let server = {
        let (client, upstream, s, limiter, close_both) = (
            client.clone(),
            upstream.clone(),
            s.clone(),
            limiter.clone(),
            close_both.clone(),
        );
        tokio::spawn(async move {
            loop {
                upstream.set_read_expiry(Some(Instant::now() + s.idle));
                match upstream.next_data_message().await {
                    Err(e) => {
                        if s.scan_upstream_frames && e == WsError::ReadLimit {
                            s.emit_scan_event(b"ws:server", "block", "ws_binary_oversize", 0, b"");
                            let _ = client
                                .send_close(WS_CLOSE_MESSAGE_TOO_BIG, "Message too large")
                                .await;
                        } else {
                            relay_close_frame(&client, &e).await;
                        }
                        break;
                    }
                    Ok((kind, payload)) => {
                        if s.scan_upstream_frames {
                            if !limiter.allow() {
                                s.emit_scan_event(b"ws:server", "block", "ws_rate_limited", 0, b"");
                                let _ = client
                                    .send_close(WS_CLOSE_POLICY_VIOLATION, "Rate limit exceeded")
                                    .await;
                                break;
                            }
                            if s.evaluate_frame(
                                b"ws:server",
                                &client,
                                kind,
                                &payload,
                                limits.max_text_size,
                            )
                            .await
                            {
                                break;
                            }
                        }
                        client.set_write_expiry(Some(Instant::now() + s.idle));
                        if client.send_data_message(kind, &payload).await.is_err() {
                            break;
                        }
                    }
                }
            }
            close_both().await;
        })
    };
    let client_loop = async {
        loop {
            client.set_read_expiry(Some(Instant::now() + s.idle));
            let (kind, payload) = match client.next_data_message().await {
                Ok(m) => m,
                Err(WsError::ReadLimit) => {
                    s.emit_scan_event(b"ws:client", "block", "ws_binary_oversize", 0, b"");
                    break;
                }
                Err(e) => {
                    relay_close_frame(&upstream, &e).await;
                    break;
                }
            };
            if !limiter.allow() {
                s.emit_scan_event(b"ws:client", "block", "ws_rate_limited", 0, b"");
                let _ = client
                    .send_close(WS_CLOSE_POLICY_VIOLATION, "Rate limit exceeded")
                    .await;
                break;
            }
            // Binary malware hashing: unconditional block tier, like the rate limit; the payload
            // never reaches the upstream.
            if kind == OP_BINARY && s.binary_scanner.as_ref().is_some_and(|scan| scan(&payload)) {
                s.emit_scan_event(b"ws:client", "block", "ws_binary_malware", 0, &payload);
                let _ = client
                    .send_close(WS_CLOSE_POLICY_VIOLATION, "Blocked by WAF")
                    .await;
                break;
            }
            if s.evaluate_frame(b"ws:client", &client, kind, &payload, limits.max_text_size)
                .await
            {
                break;
            }
            upstream.set_write_expiry(Some(Instant::now() + s.idle));
            if upstream.send_data_message(kind, &payload).await.is_err() {
                break;
            }
        }
    };
    let ended = async {
        tokio::select! {
            () = watch.maintenance_on() => "Maintenance",
            () = async { let _ = stop.wait_for(|v| *v).await; } => "Going away",
        }
    };
    tokio::select! {
        biased;
        reason = ended => {
            // The client's frame goes first. A peer that does not answer is cut after the timeout.
            let _ = tokio::time::timeout(WS_END_TIMEOUT, async {
                tokio::join!(
                    client.send_close(WS_CLOSE_GOING_AWAY, reason),
                    upstream.send_close(WS_CLOSE_GOING_AWAY, reason),
                )
            })
            .await;
        }
        () = client_loop => {}
    }
    close_both().await;
    let _ = server.await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake(connection: &str) -> bool {
        let head = format!(
            "GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n{connection}Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        );
        is_websocket_upgrade_request(&InboundRequest::from_head(head.as_bytes()))
    }

    /// The handshake check reads `peek("Connection")`: `close` when the close flag is set (the
    /// last line is `close`), else the first line that is not `close`.
    #[test]
    fn handshake_reads_the_connection_peek() {
        assert!(handshake("Connection: Upgrade\r\n"));
        assert!(handshake("Connection: keep-alive, Upgrade\r\n"));
        assert!(!handshake("Connection: close\r\n"));
        // `close` last sets the flag: peek says `close`, the Upgrade line is hidden.
        assert!(!handshake("Connection: Upgrade\r\nConnection: close\r\n"));
        // `close` first is cleared by a later line: peek is that line.
        assert!(handshake("Connection: close\r\nConnection: Upgrade\r\n"));
        // Only the first kept line counts.
        assert!(!handshake(
            "Connection: keep-alive\r\nConnection: Upgrade\r\n"
        ));
        assert!(handshake(
            "Connection: Upgrade\r\nConnection: keep-alive\r\n"
        ));
    }
}
