//! The WebSocket frame connection: RFC 6455 framing,
//! fragmented messages assembled, ping answered with pong, a peer close
//! answered and surfaced as [`WsError::Close`], the read limit (close 1009 +
//! [`WsError::ReadLimit`]), protocol errors (close 1002), sticky read and
//! write errors and per-direction deadlines that also wake in-flight calls.
//! The handshake helpers cover the relay's two sides; TLS to a `wss://`
//! upstream is the caller's stream (wrap it before [`WsConnection::client`]).

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, watch};
use tokio::time::Instant;

/// Close codes used by the relay.
pub const WS_CLOSE_NORMAL_CLOSURE: u16 = 1000;
pub const WS_CLOSE_PROTOCOL_ERROR: u16 = 1002;
pub const WS_CLOSE_NO_STATUS_RECEIVED: u16 = 1005;
pub const WS_CLOSE_ABNORMAL_CLOSURE: u16 = 1006;
pub const WS_CLOSE_POLICY_VIOLATION: u16 = 1008;
pub const WS_CLOSE_MESSAGE_TOO_BIG: u16 = 1009;

/// Bounds close/ping control-frame writes of the relay.
pub const CONTROL_FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounds the connection's own control replies.
const REPLY_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Upstream dial and handshake bound.
pub const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const OP_CONTINUATION: u8 = 0;
pub const OP_TEXT: u8 = 1;
pub const OP_BINARY: u8 = 2;
const OP_CLOSE: u8 = 8;
const OP_PING: u8 = 9;
const OP_PONG: u8 = 10;
const MAX_CONTROL_PAYLOAD: usize = 125;
const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A byte stream carrying one WebSocket connection.
pub trait WsStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> WsStream for T {}

/// Errors of the frame connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WsError {
    /// A close frame from the peer; a peer that
    /// disconnects without one is code 1006 "unexpected EOF".
    Close { code: u16, text: String },
    /// The message exceeded the read limit.
    ReadLimit,
    /// A close frame was already sent.
    CloseSent,
    /// The wrapper was closed.
    Closed,
    /// A deadline passed.
    Timeout,
    /// A protocol violation ("websocket: ...").
    Protocol(String),
    /// A control frame over 125 bytes.
    InvalidControlFrame,
    /// The handshake failed ("websocket: bad handshake", ...).
    Handshake(String),
    /// Any other I/O error.
    Io(String),
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsError::Close { code, text } => write!(f, "websocket: close {code} {text}"),
            WsError::ReadLimit => f.write_str("websocket: read limit exceeded"),
            WsError::CloseSent => f.write_str("websocket: close sent"),
            WsError::Closed => f.write_str("connection closed"),
            WsError::Timeout => f.write_str("timed out"),
            WsError::Protocol(m) => write!(f, "websocket: {m}"),
            WsError::InvalidControlFrame => f.write_str("websocket: invalid control frame"),
            WsError::Handshake(m) | WsError::Io(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for WsError {}

fn wrap_io_error(e: std::io::Error) -> WsError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        return unexpected_eof();
    }
    WsError::Io(e.to_string())
}

fn unexpected_eof() -> WsError {
    WsError::Close {
        code: WS_CLOSE_ABNORMAL_CLOSURE,
        text: "unexpected EOF".into(),
    }
}

/// Close frame payload: empty for 1005.
pub fn encode_close_payload(code: u16, text: &str) -> Vec<u8> {
    if code == WS_CLOSE_NO_STATUS_RECEIVED {
        return Vec::new();
    }
    let mut b = code.to_be_bytes().to_vec();
    b.extend_from_slice(text.as_bytes());
    b
}

fn is_acceptable_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014) || (3000..=4999).contains(&code)
}

/// A settable deadline whose waiters wake when it passes or moves.
struct Deadline(watch::Sender<Option<Instant>>);

impl Deadline {
    fn new() -> Deadline {
        Deadline(watch::Sender::new(None))
    }

    fn set(&self, t: Option<Instant>) {
        self.0.send_replace(t);
    }

    /// Resolves once the current deadline passes (re-armed when it changes).
    async fn expired(&self) {
        let mut rx = self.0.subscribe();
        loop {
            let d = *rx.borrow_and_update();
            match d {
                None => {
                    if rx.changed().await.is_err() {
                        std::future::pending::<()>().await;
                    }
                }
                Some(t) => {
                    tokio::select! {
                        _ = tokio::time::sleep_until(t) => return,
                        r = rx.changed() => if r.is_err() { std::future::pending::<()>().await },
                    }
                }
            }
        }
    }

    async fn run<T>(
        &self,
        fut: impl std::future::Future<Output = Result<T, WsError>>,
    ) -> Result<T, WsError> {
        tokio::select! {
            biased;
            _ = self.expired() => Err(WsError::Timeout),
            r = fut => r,
        }
    }
}

struct Reader {
    rd: ReadHalf<Box<dyn WsStream>>,
    buffer: Vec<u8>,
    pos: usize,
    pending_read_error: Option<WsError>,
    final_fragment_seen: bool,
    remaining: i64,
    mask_key: [u8; 4],
    mask_pos: usize,
}

impl Reader {
    async fn fill(&mut self) -> Result<(), WsError> {
        if self.pos == self.buffer.len() {
            self.buffer.clear();
            self.pos = 0;
        }
        let mut tmp = [0u8; 8192];
        let n = self.rd.read(&mut tmp).await.map_err(wrap_io_error)?;
        if n == 0 {
            return Err(unexpected_eof());
        }
        self.buffer.extend_from_slice(&tmp[..n]);
        Ok(())
    }

    async fn take_bytes(&mut self, n: usize) -> Result<Vec<u8>, WsError> {
        while self.buffer.len() - self.pos < n {
            self.fill().await?;
        }
        let out = self.buffer[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }

    /// Reads up to `max` buffered or fresh bytes (at least one).
    async fn read_some(&mut self, max: usize) -> Result<Vec<u8>, WsError> {
        if self.pos == self.buffer.len() {
            self.fill().await?;
        }
        let n = max.min(self.buffer.len() - self.pos);
        let out = self.buffer[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }
}

struct Writer {
    wr: WriteHalf<Box<dyn WsStream>>,
    pending_write_error: Option<WsError>,
}

enum Frame {
    Data(u8),
    Continuation,
    Control,
}

/// A WebSocket frame connection over a byte stream.
pub struct WsConnection {
    is_server: bool,
    reader: Mutex<Reader>,
    writer: Mutex<Writer>,
    read_deadline: Deadline,
    write_deadline: Deadline,
    write_deadline_at: std::sync::Mutex<Option<Instant>>,
    read_limit: AtomicI64,
    closed: AtomicBool,
    close_lock: Mutex<()>,
}

fn random_u64() -> u64 {
    let mut h = RandomState::new().build_hasher();
    h.write_u64(Instant::now().elapsed().as_nanos() as u64);
    h.finish()
}

pub fn derive_accept_key(challenge_key: &[u8]) -> String {
    let mut data = challenge_key.to_vec();
    data.extend_from_slice(ACCEPT_GUID);
    base64::engine::general_purpose::STANDARD.encode(crate::sha1::sha1(&data))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map_or("", |(_, v)| v.as_str())
}

/// Whether a comma-separated header list holds `value`.
fn token_list_contains(headers: &[(String, String)], name: &str, value: &str) -> bool {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .any(|(_, v)| {
            v.split(',')
                .any(|t| t.trim_matches([' ', '\t']).eq_ignore_ascii_case(value))
        })
}

/// Whether `s` is a base64 key of 16 bytes.
fn is_valid_handshake_key(s: &str) -> bool {
    !s.is_empty()
        && base64::engine::general_purpose::STANDARD
            .decode(s)
            .is_ok_and(|b| b.len() == 16)
}

/// The parts of an HTTP request head the handshake reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsRequestHead {
    pub method: String,
    pub request_target: String,
    pub headers: Vec<(String, String)>,
}

/// Parses an HTTP/1.x head ("\r\n\r\n" terminated); returns it and the
/// bytes after it.
/// Request/status line words, header lines, then the head length or the bytes after it.
type ParsedHead<T> = (Vec<String>, Vec<(String, String)>, T);

fn parse_head(raw: &[u8]) -> Option<ParsedHead<usize>> {
    let end = memchr::memmem::find(raw, b"\r\n\r\n")? + 4;
    let text = String::from_utf8_lossy(&raw[..end - 4]).into_owned();
    let mut lines = text.split("\r\n");
    let first: Vec<String> = lines.next()?.splitn(3, ' ').map(str::to_string).collect();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Some((first, headers, end))
}

async fn read_head(stream: &mut Box<dyn WsStream>) -> Result<ParsedHead<Vec<u8>>, WsError> {
    let mut raw = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some((first, headers, end)) = parse_head(&raw) {
            return Ok((first, headers, raw[end..].to_vec()));
        }
        if raw.len() > 1 << 20 {
            return Err(WsError::Handshake(
                "websocket: handshake head too large".into(),
            ));
        }
        let n = stream.read(&mut tmp).await.map_err(wrap_io_error)?;
        if n == 0 {
            return Err(WsError::Io("unexpected EOF".into()));
        }
        raw.extend_from_slice(&tmp[..n]);
    }
}

impl WsConnection {
    /// Wraps an upgraded stream; `prefix` holds bytes already read past the
    /// handshake.
    pub fn new(stream: Box<dyn WsStream>, is_server: bool, prefix: Vec<u8>) -> WsConnection {
        let (rd, wr) = tokio::io::split(stream);
        WsConnection {
            is_server,
            reader: Mutex::new(Reader {
                rd,
                buffer: prefix,
                pos: 0,
                pending_read_error: None,
                final_fragment_seen: true,
                remaining: 0,
                mask_key: [0; 4],
                mask_pos: 0,
            }),
            writer: Mutex::new(Writer {
                wr,
                pending_write_error: None,
            }),
            read_deadline: Deadline::new(),
            write_deadline: Deadline::new(),
            write_deadline_at: std::sync::Mutex::new(None),
            read_limit: AtomicI64::new(0),
            closed: AtomicBool::new(false),
            close_lock: Mutex::new(()),
        }
    }

    /// The client handshake over `stream` (the upstream
    /// side of a relay), bounded by [`WS_CONNECT_TIMEOUT`]. Returns the
    /// subprotocol the upstream selected ("" when none) also on failure.
    pub async fn client(
        stream: Box<dyn WsStream>,
        host: &str,
        request_uri: &str,
        headers: &[(String, String)],
    ) -> Result<(WsConnection, String), (WsError, String)> {
        match tokio::time::timeout(
            WS_CONNECT_TIMEOUT,
            Self::client_handshake(stream, host, request_uri, headers),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => Err((WsError::Timeout, String::new())),
        }
    }

    async fn client_handshake(
        mut stream: Box<dyn WsStream>,
        host: &str,
        request_uri: &str,
        headers: &[(String, String)],
    ) -> Result<(WsConnection, String), (WsError, String)> {
        let mut key_bytes = [0u8; 16];
        key_bytes[..8].copy_from_slice(&random_u64().to_le_bytes());
        key_bytes[8..].copy_from_slice(&random_u64().to_le_bytes());
        let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        let mut host = host.to_string();
        let mut extra = String::new();
        // Unless the header carries a User-Agent the request names itself with the agent's own,
        // and an empty one writes none.
        let mut user_agent = false;
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("Host") {
                host = v.clone();
                continue;
            }
            if k.eq_ignore_ascii_case("User-Agent") {
                if !std::mem::replace(&mut user_agent, true) && !v.is_empty() {
                    extra.push_str(&format!("User-Agent: {v}\r\n"));
                }
                continue;
            }
            for dup in [
                "Upgrade",
                "Connection",
                "Sec-Websocket-Key",
                "Sec-Websocket-Version",
                "Sec-Websocket-Extensions",
            ] {
                if k.eq_ignore_ascii_case(dup) {
                    return Err((
                        WsError::Handshake(format!(
                            "websocket: duplicate header not allowed: {dup}"
                        )),
                        String::new(),
                    ));
                }
            }
            extra.push_str(&format!("{k}: {v}\r\n"));
        }
        if !user_agent {
            extra.push_str(&format!("User-Agent: {}\r\n", crate::user_agent()));
        }
        let req = format!(
            "GET {request_uri} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
        );
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| (wrap_io_error(e), String::new()))?;
        let (first, resp_headers, rest) = read_head(&mut stream)
            .await
            .map_err(|e| (e, String::new()))?;
        let subprotocol = header(&resp_headers, "Sec-WebSocket-Protocol").to_string();
        let status_ok = first.get(1).map(String::as_str) == Some("101");
        if !status_ok
            || !header(&resp_headers, "Upgrade").eq_ignore_ascii_case("websocket")
            || !token_list_contains(&resp_headers, "Connection", "upgrade")
            || header(&resp_headers, "Sec-WebSocket-Accept") != derive_accept_key(key.as_bytes())
        {
            return Err((
                WsError::Handshake("websocket: bad handshake".into()),
                subprotocol,
            ));
        }
        Ok((WsConnection::new(stream, false, rest), subprotocol))
    }

    /// Reads the client's handshake request from
    /// `stream`, then completes it.
    pub async fn server(mut stream: Box<dyn WsStream>) -> Result<WsConnection, WsError> {
        let (first, headers, rest) = read_head(&mut stream).await?;
        let req = WsRequestHead {
            method: first.first().cloned().unwrap_or_default(),
            request_target: first.get(1).cloned().unwrap_or_default(),
            headers,
        };
        let conn = Self::server_from_request(stream, &req, "").await?;
        conn.reader.lock().await.buffer = rest;
        Ok(conn)
    }

    /// The server side of the handshake for
    /// a request whose head was already read; echoes `subprotocol` ("" omits
    /// it). A failed handshake writes nothing (the caller reports it).
    pub async fn server_from_request(
        mut stream: Box<dyn WsStream>,
        req: &WsRequestHead,
        subprotocol: &str,
    ) -> Result<WsConnection, WsError> {
        let h = &req.headers;
        let refuse = |m: &str| {
            Err(WsError::Handshake(format!(
                "websocket: the client is not using the websocket protocol: {m}"
            )))
        };
        if !token_list_contains(h, "Connection", "upgrade") {
            return refuse("'upgrade' token not found in 'Connection' header");
        }
        if !token_list_contains(h, "Upgrade", "websocket") {
            return refuse("'websocket' token not found in 'Upgrade' header");
        }
        if req.method != "GET" {
            return refuse("request method is not GET");
        }
        if header(h, "Sec-Websocket-Version") != "13" {
            return Err(WsError::Handshake(
                "websocket: unsupported version: 13 not found in 'Sec-Websocket-Version' header"
                    .into(),
            ));
        }
        let key = header(h, "Sec-Websocket-Key");
        if !is_valid_handshake_key(key) {
            return Err(WsError::Handshake("websocket: not a websocket handshake: 'Sec-WebSocket-Key' header must be Base64 encoded value of 16-byte in length".into()));
        }
        let mut resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
            derive_accept_key(key.as_bytes())
        );
        if !subprotocol.is_empty() {
            resp.push_str(&format!("Sec-WebSocket-Protocol: {subprotocol}\r\n"));
        }
        resp.push_str("\r\n");
        stream
            .write_all(resp.as_bytes())
            .await
            .map_err(wrap_io_error)?;
        Ok(WsConnection::new(stream, true, Vec::new()))
    }

    /// Caps one received message; a larger one closes 1009 and returns
    /// [`WsError::ReadLimit`]. 0 = no limit.
    pub fn set_max_message_bytes(&self, limit: i64) {
        self.read_limit.store(limit, Ordering::Relaxed);
    }

    /// Bounds subsequent reads (`None` = none). A passed deadline also wakes
    /// a read in progress; after a timeout the connection is unusable.
    pub fn set_read_expiry(&self, t: Option<Instant>) {
        self.read_deadline.set(t);
    }

    /// Bounds subsequent data writes; also wakes a write in progress.
    pub fn set_write_expiry(&self, t: Option<Instant>) {
        *self
            .write_deadline_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = t;
        self.write_deadline.set(t);
    }

    /// One complete data message (kind, payload). Pings are
    /// answered; a peer close returns [`WsError::Close`]. Errors are sticky.
    pub async fn next_data_message(&self) -> Result<(u8, Vec<u8>), WsError> {
        let mut r = self.reader.lock().await;
        if let Some(e) = &r.pending_read_error {
            return Err(e.clone());
        }
        let res = self.read_deadline.run(self.assemble_message(&mut r)).await;
        if let Err(e) = &res {
            r.pending_read_error = Some(e.clone());
        }
        res
    }

    async fn assemble_message(&self, r: &mut Reader) -> Result<(u8, Vec<u8>), WsError> {
        let mut read_length: i64 = 0;
        let kind = loop {
            if let Frame::Data(k) = self.next_frame(r, &mut read_length).await? {
                break k;
            }
        };
        let mut msg = Vec::new();
        loop {
            while r.remaining > 0 {
                let mut chunk = r.read_some(r.remaining.min(64 << 10) as usize).await?;
                if self.is_server {
                    for b in chunk.iter_mut() {
                        *b ^= r.mask_key[r.mask_pos & 3];
                        r.mask_pos += 1;
                    }
                }
                r.remaining -= chunk.len() as i64;
                msg.extend_from_slice(&chunk);
            }
            if r.final_fragment_seen {
                return Ok((kind, msg));
            }
            if let Frame::Data(_) = self.next_frame(r, &mut read_length).await? {
                return Err(WsError::Protocol(
                    "internal error, unexpected text or binary in Reader".into(),
                ));
            }
        }
    }

    /// Reads one frame header and handles control frames.
    async fn next_frame(&self, r: &mut Reader, read_length: &mut i64) -> Result<Frame, WsError> {
        let p = r.take_bytes(2).await?;
        let fin = p[0] & 0x80 != 0;
        let frame_type = p[0] & 0x0f;
        let mask = p[1] & 0x80 != 0;
        r.remaining = i64::from(p[1] & 0x7f);
        let mut errors: Vec<String> = Vec::new();
        if p[0] & 0x40 != 0 {
            errors.push("RSV1 set".into());
        }
        if p[0] & 0x20 != 0 {
            errors.push("RSV2 set".into());
        }
        if p[0] & 0x10 != 0 {
            errors.push("RSV3 set".into());
        }
        match frame_type {
            OP_CLOSE | OP_PING | OP_PONG => {
                if r.remaining > MAX_CONTROL_PAYLOAD as i64 {
                    errors.push("len > 125 for control".into());
                }
                if !fin {
                    errors.push("FIN not set on control".into());
                }
            }
            OP_TEXT | OP_BINARY => {
                if !r.final_fragment_seen {
                    errors.push("data before FIN".into());
                }
                r.final_fragment_seen = fin;
            }
            OP_CONTINUATION => {
                if r.final_fragment_seen {
                    errors.push("continuation after FIN".into());
                }
                r.final_fragment_seen = fin;
            }
            other => errors.push(format!("bad opcode {other}")),
        }
        if mask != self.is_server {
            errors.push("bad MASK".into());
        }
        if !errors.is_empty() {
            return Err(self.protocol_error(&errors.join(", ")).await);
        }
        match r.remaining {
            126 => {
                let b = r.take_bytes(2).await?;
                r.remaining = i64::from(u16::from_be_bytes([b[0], b[1]]));
            }
            127 => {
                let b = r.take_bytes(8).await?;
                let n = u64::from_be_bytes(b.try_into().expect("8 bytes"));
                if n > i64::MAX as u64 {
                    return Err(WsError::ReadLimit);
                }
                r.remaining = n as i64;
            }
            _ => {}
        }
        if mask {
            r.mask_pos = 0;
            let key = r.take_bytes(4).await?;
            r.mask_key.copy_from_slice(&key);
        }
        if matches!(frame_type, OP_CONTINUATION | OP_TEXT | OP_BINARY) {
            *read_length = read_length.saturating_add(r.remaining);
            let limit = self.read_limit.load(Ordering::Relaxed);
            if limit > 0 && *read_length > limit {
                self.send_control_frame(
                    OP_CLOSE,
                    &encode_close_payload(WS_CLOSE_MESSAGE_TOO_BIG, ""),
                    Instant::now() + REPLY_WRITE_TIMEOUT,
                )
                .await?;
                return Err(WsError::ReadLimit);
            }
            return Ok(if frame_type == OP_CONTINUATION {
                Frame::Continuation
            } else {
                Frame::Data(frame_type)
            });
        }
        let mut payload = Vec::new();
        if r.remaining > 0 {
            payload = r.take_bytes(r.remaining as usize).await?;
            r.remaining = 0;
            if self.is_server {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= r.mask_key[i & 3];
                }
            }
        }
        match frame_type {
            // Ping handler: best-effort pong, every error ignored.
            OP_PING => {
                let _ = self
                    .send_control_frame(OP_PONG, &payload, Instant::now() + REPLY_WRITE_TIMEOUT)
                    .await;
            }
            OP_CLOSE => {
                let mut code = WS_CLOSE_NO_STATUS_RECEIVED;
                let mut text = String::new();
                if payload.len() >= 2 {
                    code = u16::from_be_bytes([payload[0], payload[1]]);
                    if !is_acceptable_close_code(code) {
                        return Err(self.protocol_error(&format!("bad close code {code}")).await);
                    }
                    match String::from_utf8(payload[2..].to_vec()) {
                        Ok(t) => text = t,
                        Err(_) => {
                            return Err(self
                                .protocol_error("invalid utf8 payload in close frame")
                                .await);
                        }
                    }
                }
                let _ = self
                    .send_control_frame(
                        OP_CLOSE,
                        &encode_close_payload(code, ""),
                        Instant::now() + REPLY_WRITE_TIMEOUT,
                    )
                    .await;
                return Err(WsError::Close { code, text });
            }
            _ => {}
        }
        Ok(Frame::Control)
    }

    async fn protocol_error(&self, message: &str) -> WsError {
        let mut data = encode_close_payload(WS_CLOSE_PROTOCOL_ERROR, message);
        data.truncate(MAX_CONTROL_PAYLOAD);
        let _ = self
            .send_control_frame(OP_CLOSE, &data, Instant::now() + REPLY_WRITE_TIMEOUT)
            .await;
        WsError::Protocol(message.to_string())
    }

    fn encode_frame(&self, op: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(payload.len() + 14);
        f.push(0x80 | op);
        let mask_bit = if self.is_server { 0 } else { 0x80 };
        match payload.len() {
            n if n <= 125 => f.push(mask_bit | n as u8),
            n if n <= 0xffff => {
                f.push(mask_bit | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                f.push(mask_bit | 127);
                f.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        if self.is_server {
            f.extend_from_slice(payload);
        } else {
            let key = (random_u64() as u32).to_be_bytes();
            f.extend_from_slice(&key);
            f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
        }
        f
    }

    /// Writes a control frame bounded by `deadline`; after a
    /// close frame every later write fails with [`WsError::CloseSent`].
    async fn send_control_frame(
        &self,
        op: u8,
        data: &[u8],
        deadline: Instant,
    ) -> Result<(), WsError> {
        if data.len() > MAX_CONTROL_PAYLOAD {
            return Err(WsError::InvalidControlFrame);
        }
        let frame = self.encode_frame(op, data);
        // Waiting for the writer past the deadline times out without being sticky; a write that
        // times out is sticky via `pending_write_error` (no torn frame is reused).
        let mut w = tokio::time::timeout_at(deadline, self.writer.lock())
            .await
            .map_err(|_| WsError::Timeout)?;
        if let Some(e) = &w.pending_write_error {
            return Err(e.clone());
        }
        let res = match tokio::time::timeout_at(deadline, w.wr.write_all(&frame)).await {
            Ok(r) => r.map_err(wrap_io_error),
            Err(_) => Err(WsError::Timeout),
        };
        if let Err(e) = res {
            w.pending_write_error.get_or_insert(e.clone());
            return Err(e);
        }
        if op == OP_CLOSE {
            w.pending_write_error.get_or_insert(WsError::CloseSent);
        }
        Ok(())
    }

    /// Sends one complete data message (text or binary) in one frame.
    pub async fn send_data_message(&self, kind: u8, payload: &[u8]) -> Result<(), WsError> {
        let frame = self.encode_frame(kind, payload);
        let at = *self
            .write_deadline_at
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut w = self.writer.lock().await;
        if let Some(e) = &w.pending_write_error {
            return Err(e.clone());
        }
        if at.is_some_and(|d| d <= Instant::now()) {
            w.pending_write_error = Some(WsError::Timeout);
            return Err(WsError::Timeout);
        }
        let res = self
            .write_deadline
            .run(async { w.wr.write_all(&frame).await.map_err(wrap_io_error) })
            .await;
        if let Err(e) = &res {
            w.pending_write_error.get_or_insert(e.clone());
        }
        res
    }

    /// Sends a close frame with `code` and `reason`, waiting up to
    /// [`CONTROL_FRAME_WRITE_TIMEOUT`] for it to flush. [`WsError::Closed`] after `close`.
    pub async fn send_close(&self, code: u16, reason: &str) -> Result<(), WsError> {
        let _g = self.close_lock.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(WsError::Closed);
        }
        self.send_control_frame(
            OP_CLOSE,
            &encode_close_payload(code, reason),
            Instant::now() + CONTROL_FRAME_WRITE_TIMEOUT,
        )
        .await
    }

    /// Tears the connection down without a close frame; reads and
    /// writes in progress are woken. Safe to call more than once.
    pub async fn close(&self) {
        let _g = self.close_lock.lock().await;
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let now = Instant::now();
        self.read_deadline.set(Some(now));
        self.write_deadline.set(Some(now));
        if let Ok(mut w) = self.writer.try_lock() {
            let _ = w.wr.shutdown().await;
            w.pending_write_error.get_or_insert(WsError::Closed);
        }
    }
}

#[cfg(test)]
mod tests;
