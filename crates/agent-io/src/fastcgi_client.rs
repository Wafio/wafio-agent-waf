//! FastCGI client with connection pooling for PHP-FPM over a Unix socket or TCP.
//!
//! ```text
//! fcgi:unix:/run/php/php-fpm.sock?root=/var/www/html&index=index.php
//! fcgi://127.0.0.1:9000?root=/var/www/html&index=index.php
//! ```
//!
//! Pool semantics (customer OOM incident, 2026-11-02): every open connection keeps
//! FCGI_KEEP_CONN and so pins one PHP-FPM worker. Idle connections are a LIFO
//! stack; one past its idle TTL is closed with its slot released (never
//! re-dialled in its place); a reaper closes idle ones without traffic; a
//! closed pool closes connections as they come back. Request headers are
//! `(name, value)` lines, grouped by exact name in first-appearance order.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout_at;

use wafio_bytetext::strings::{to_lowercase, to_uppercase, trim_whitespace};

// FastCGI record types.
pub const FCGI_BEGIN_REQUEST: u8 = 1;
pub const FCGI_END_REQUEST: u8 = 3;
pub const FCGI_PARAMS: u8 = 4;
pub const FCGI_STDIN: u8 = 5;
pub const FCGI_STDOUT: u8 = 6;
pub const FCGI_STDERR: u8 = 7;

/// FCGI_RESPONDER role.
pub const FCGI_RESPONDER: u8 = 1;
/// Reuse the connection after the request.
pub const FCGI_KEEP_CONN: u8 = 1;
pub const FCGI_VERSION: u8 = 1;
pub const FCGI_HEADER_SIZE: usize = 8;
pub const FCGI_MAX_CONTENT: usize = 65535;

/// Single request per connection: always ID 1.
const FCGI_REQUEST_ID: u16 = 1;

/// A byte stream to PHP-FPM.
pub trait FcgiStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> FcgiStream for T {}

type DialFuture = Pin<Box<dyn Future<Output = io::Result<Box<dyn FcgiStream>>> + Send>>;
type DialFn = Box<dyn Fn() -> DialFuture + Send + Sync>;

/// Header lines as `(name, value)`.
pub type HeaderLines = [(Vec<u8>, Vec<u8>)];

/// One connection to PHP-FPM, owned by one request at a time. Dropping it
/// closes the socket and releases its pool slot.
pub struct FastCgiConnection {
    /// Unique per dial; tests compare identities with it.
    pub id: u64,
    buffered_stream: BufReader<Box<dyn FcgiStream>>,
    last_used_at: Instant,
    _slot: OwnedSemaphorePermit,
}

/// Per-app deadlines; zero fields take the defaults.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FastCgiDeadlines {
    /// Waiting for PHP-FPM to produce a response.
    pub read: Duration,
    /// Sending the request to PHP-FPM.
    pub write: Duration,
    /// Opening the socket.
    pub dial: Duration,
    /// Waiting for a free slot when connection_limit is reached.
    pub slot_wait: Duration,
    /// How long a pooled connection may sit idle.
    pub max_idle_age: Duration,
    /// No read/write deadlines; dial, pool wait and idle TTL stay bounded.
    pub unlimited: bool,
}

impl FastCgiDeadlines {
    pub fn fill_default_deadlines(&mut self) {
        if self.unlimited {
            self.read = Duration::ZERO;
            self.write = Duration::ZERO;
        } else {
            if self.read.is_zero() {
                self.read = Duration::from_secs(30);
            }
            if self.write.is_zero() {
                self.write = Duration::from_secs(30);
            }
        }
        if self.dial.is_zero() {
            self.dial = Duration::from_secs(5);
        }
        if self.slot_wait.is_zero() {
            self.slot_wait = Duration::from_secs(5);
        }
        if self.max_idle_age.is_zero() {
            self.max_idle_age = Duration::from_secs(60);
        }
    }
}

struct PoolState {
    /// LIFO stack, newest last (so oldest first).
    idle: Vec<FastCgiConnection>,
    closed: bool,
    idle_reaper: Option<tokio::task::JoinHandle<()>>,
}

/// The connection pool of one FastCGI upstream.
pub struct FastCgiConnectionPool {
    network: String,
    address: String,
    pub site_root: Vec<u8>,
    pub index: Vec<u8>,
    connection_limit: usize,
    dial: DialFn,
    timeouts: FastCgiDeadlines,
    sem: Arc<Semaphore>,
    state: Mutex<PoolState>,
    next_connection_id: AtomicU64,
}

/// The parsed response from PHP-FPM. Headers are grouped
/// by exact name in first-appearance order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FastCgiReply {
    pub status: i64,
    pub headers: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
    pub body: Vec<u8>,
}

impl FastCgiConnectionPool {
    /// `network` "unix" or "tcp"; `max_conns` ≤ 0 → 256.
    pub fn new(
        network: &str,
        addr: &str,
        max_conns: i64,
        mut to: FastCgiDeadlines,
    ) -> Arc<FastCgiConnectionPool> {
        to.fill_default_deadlines();
        let max_conns = if max_conns <= 0 {
            256
        } else {
            max_conns as usize
        };
        let (net, ad, dial_to) = (network.to_string(), addr.to_string(), to.dial);
        let dial: DialFn = Box::new(move || {
            let (net, ad) = (net.clone(), ad.clone());
            Box::pin(async move {
                let fut = async {
                    let s: Box<dyn FcgiStream> = if net == "unix" {
                        Box::new(tokio::net::UnixStream::connect(&ad).await?)
                    } else {
                        Box::new(tokio::net::TcpStream::connect(ad.as_str()).await?)
                    };
                    Ok::<Box<dyn FcgiStream>, io::Error>(s)
                };
                match tokio::time::timeout(dial_to, fut).await {
                    Ok(r) => r,
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("dial {net} {ad}: i/o timeout"),
                    )),
                }
            }) as DialFuture
        });
        Arc::new(FastCgiConnectionPool {
            network: network.to_string(),
            address: addr.to_string(),
            site_root: Vec::new(),
            index: Vec::new(),
            connection_limit: max_conns,
            dial,
            timeouts: to,
            sem: Arc::new(Semaphore::new(max_conns)),
            state: Mutex::new(PoolState {
                idle: Vec::new(),
                closed: false,
                idle_reaper: None,
            }),
            next_connection_id: AtomicU64::new(1),
        })
    }

    /// Replaces the dialer; tests only.
    pub fn with_dial(
        mut self: Arc<Self>,
        dial: impl Fn() -> DialFuture + Send + Sync + 'static,
    ) -> Arc<FastCgiConnectionPool> {
        Arc::get_mut(&mut self)
            .expect("with_dial before sharing the pool")
            .dial = Box::new(dial);
        self
    }

    /// "unix" or "tcp".
    pub fn network(&self) -> &str {
        &self.network
    }

    /// Socket path or host:port.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The resolved deadlines.
    pub fn timeouts(&self) -> FastCgiDeadlines {
        self.timeouts
    }

    /// Open connections (slots in use).
    pub fn open_connection_count(&self) -> usize {
        self.connection_limit - self.sem.available_permits()
    }

    /// Idle connections waiting in the pool.
    pub fn idle_count(&self) -> usize {
        self.lock().idle.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The most recently used idle connection, or a new dial.
    /// Stale idle connections are closed and give their slot back.
    pub async fn get(self: &Arc<Self>) -> Result<FastCgiConnection, String> {
        let mut stale = Vec::new();
        let found = {
            let mut st = self.lock();
            let mut found = None;
            while let Some(top) = st.idle.pop() {
                if top.last_used_at.elapsed() > self.timeouts.max_idle_age {
                    stale.push(top);
                    continue;
                }
                found = Some(top);
                break;
            }
            found
        };
        drop(stale);
        if let Some(c) = found {
            return Ok(c);
        }
        let slot = match self.sem.clone().try_acquire_owned() {
            Ok(s) => s,
            Err(_) => match tokio::time::timeout(
                self.timeouts.slot_wait,
                self.sem.clone().acquire_owned(),
            )
            .await
            {
                Ok(Ok(s)) => s,
                _ => {
                    return Err(format!(
                        "fcgi pool exhausted (max {} conns)",
                        self.connection_limit
                    ));
                }
            },
        };
        let conn = (self.dial)()
            .await
            .map_err(|e| format!("fcgi dial {}:{}: {e}", self.network, self.address))?;
        Ok(FastCgiConnection {
            id: self.next_connection_id.fetch_add(1, Ordering::Relaxed),
            buffered_stream: BufReader::with_capacity(16384, conn),
            last_used_at: Instant::now(),
            _slot: slot,
        })
    }

    /// Returns a healthy connection to the idle stack (closed when
    /// the pool is closed or full) and arms the reaper.
    pub fn put(self: &Arc<Self>, mut c: FastCgiConnection) {
        c.last_used_at = Instant::now();
        let mut st = self.lock();
        if st.closed || st.idle.len() >= self.connection_limit {
            drop(st);
            drop(c);
            return;
        }
        st.idle.push(c);
        if st.idle_reaper.is_none() {
            st.idle_reaper = self.schedule_reap(self.timeouts.max_idle_age);
        }
    }

    fn schedule_reap(self: &Arc<Self>, after: Duration) -> Option<tokio::task::JoinHandle<()>> {
        let handle = tokio::runtime::Handle::try_current().ok()?;
        let pool = self.clone();
        Some(handle.spawn(async move {
            tokio::time::sleep(after).await;
            pool.reap();
        }))
    }

    /// Closes idle connections past the idle TTL (a prefix: the
    /// stack is oldest first) and re-arms for the oldest remaining one.
    fn reap(self: &Arc<Self>) {
        let stale: Vec<FastCgiConnection> = {
            let mut st = self.lock();
            let now = Instant::now();
            let n = st
                .idle
                .iter()
                .take_while(|c| {
                    now.saturating_duration_since(c.last_used_at) >= self.timeouts.max_idle_age
                })
                .count();
            let stale = st.idle.drain(..n).collect();
            st.idle_reaper = None;
            if !st.closed && !st.idle.is_empty() {
                let due = (st.idle[0].last_used_at + self.timeouts.max_idle_age)
                    .saturating_duration_since(now);
                st.idle_reaper = self.schedule_reap(due);
            }
            stale
        };
        drop(stale);
    }

    /// Closes a broken connection and releases its slot.
    pub fn discard(&self, c: FastCgiConnection) {
        drop(c);
    }

    /// Closes idle connections; ones still serving a request are
    /// closed when they come back. Safe to call more than once.
    pub fn close(&self) {
        let idle = {
            let mut st = self.lock();
            st.closed = true;
            if let Some(t) = st.idle_reaper.take() {
                t.abort();
            }
            std::mem::take(&mut st.idle)
        };
        drop(idle);
    }

    /// The CGI/1.1 environment of one request.
    #[allow(clippy::too_many_arguments)]
    pub fn build_cgi_variables(
        &self,
        method: &[u8],
        request_uri: &[u8],
        host: &[u8],
        remote_addr: &[u8],
        headers: &HeaderLines,
        content_type: &[u8],
        content_length: usize,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let q = request_uri.iter().position(|&c| c == b'?');
        let path_part = match q {
            Some(i) => &request_uri[..i],
            None => request_uri,
        };
        let query_string: &[u8] = match q {
            Some(i) => &request_uri[i + 1..],
            None => b"",
        };
        let script_filename;
        let script_name;
        if !self.site_root.is_empty() {
            let mut candidate = join_paths(&[
                self.site_root.as_slice(),
                normalize_path(path_part).as_slice(),
            ]);
            if !candidate.ends_with(b".php") {
                candidate = join_paths(&[self.site_root.as_slice(), self.index.as_slice()]);
                script_name = [b"/".as_slice(), self.index.as_slice()].concat();
            } else {
                script_name = path_part.to_vec();
            }
            script_filename = candidate;
        } else {
            script_filename = b"/index.php".to_vec();
            script_name = path_part.to_vec();
        }
        let (mut server_name, mut server_port) = (host.to_vec(), b"80".to_vec());
        if let Ok((h, p)) = crate::url_parse::split_host_and_port(host) {
            server_name = h;
            server_port = p;
        }
        let grouped = group_headers(headers);
        let mut https_on: &[u8] = b"";
        let forwarded_proto = grouped
            .iter()
            .find(|(k, vs)| {
                wafio_domain::text_helpers::eq_ignore_case(k, b"X-Forwarded-Proto")
                    && !vs.is_empty()
            })
            .map(|(_, vs)| to_lowercase(vs[0]))
            .unwrap_or_default();
        if forwarded_proto == b"https" {
            https_on = b"on";
            if server_port == b"80" {
                server_port = b"443".to_vec();
            }
        }
        let p = |k: &str, v: &[u8]| (k.as_bytes().to_vec(), v.to_vec());
        let mut params = vec![
            p("SCRIPT_FILENAME", &script_filename),
            p("SCRIPT_NAME", &script_name),
            p("REQUEST_URI", request_uri),
            p("DOCUMENT_ROOT", &self.site_root),
            p("REQUEST_METHOD", method),
            p("QUERY_STRING", query_string),
            p("HTTP_HOST", host),
            p("SERVER_NAME", &server_name),
            p("SERVER_PORT", &server_port),
            p("SERVER_PROTOCOL", b"HTTP/1.1"),
            p("SERVER_SOFTWARE", b"wafio-waf-agent"),
            p("GATEWAY_INTERFACE", b"CGI/1.1"),
            p("REDIRECT_STATUS", b"200"),
            p("REMOTE_ADDR", remote_addr),
            p("REMOTE_PORT", b"0"),
        ];
        if !https_on.is_empty() {
            params.push(p("HTTPS", https_on));
        }
        if !content_type.is_empty() {
            params.push(p("CONTENT_TYPE", content_type));
        }
        if content_length > 0 {
            params.push(p("CONTENT_LENGTH", content_length.to_string().as_bytes()));
        }
        for (k, vs) in &grouped {
            let upper = cgi_header_param(k);
            // Skip headers already mapped to CGI vars. `HTTP_PROXY` is httpoxy (CVE-2016-5385:
            // a `Proxy:` header becomes the HTTP client library's proxy setting); nginx's
            // fastcgi_params clears it too.
            if matches!(
                upper.as_slice(),
                b"HTTP_CONTENT_TYPE" | b"HTTP_CONTENT_LENGTH" | b"HTTP_HOST" | b"HTTP_PROXY"
            ) {
                continue;
            }
            params.push((upper, vs.join(&b", "[..])));
        }
        params
    }

    /// One request over FastCGI; a failed write is retried once on a
    /// fresh connection.
    pub async fn send_request(
        self: &Arc<Self>,
        method: &[u8],
        request_uri: &[u8],
        host: &[u8],
        remote_addr: &[u8],
        headers: &HeaderLines,
        body: &[u8],
    ) -> Result<FastCgiReply, String> {
        let mut c = self.get().await?;
        if let Err(err) = self
            .execute(
                &mut c,
                method,
                request_uri,
                host,
                remote_addr,
                headers,
                body,
            )
            .await
        {
            self.discard(c);
            let Ok(mut c2) = self.get().await else {
                return Err(err);
            };
            if let Err(e3) = self
                .execute(
                    &mut c2,
                    method,
                    request_uri,
                    host,
                    remote_addr,
                    headers,
                    body,
                )
                .await
            {
                self.discard(c2);
                return Err(e3);
            }
            return match self.collect_reply(&mut c2).await {
                Ok(resp) => {
                    self.put(c2);
                    Ok(resp)
                }
                Err(e4) => {
                    self.discard(c2);
                    Err(e4)
                }
            };
        }
        match self.collect_reply(&mut c).await {
            Ok(resp) => {
                self.put(c);
                Ok(resp)
            }
            Err(e) => {
                self.discard(c);
                Err(e)
            }
        }
    }

    fn deadline(&self, d: Duration) -> Option<tokio::time::Instant> {
        if self.timeouts.unlimited {
            None
        } else {
            Some(tokio::time::Instant::now() + d)
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        c: &mut FastCgiConnection,
        method: &[u8],
        request_uri: &[u8],
        host: &[u8],
        remote_addr: &[u8],
        headers: &HeaderLines,
        body: &[u8],
    ) -> Result<(), String> {
        let deadline = self.deadline(self.timeouts.write);
        let joined = |name: &[u8]| -> Vec<u8> {
            headers
                .iter()
                .filter(|(k, _)| k == name)
                .flat_map(|(_, v)| v.iter().copied())
                .collect()
        };
        let mut content_type = joined(b"Content-Type");
        if content_type.is_empty() {
            content_type = joined(b"content-type");
        }
        let w = c.buffered_stream.get_mut();
        let begin = [0, FCGI_RESPONDER, FCGI_KEEP_CONN, 0, 0, 0, 0, 0];
        send_record(w, deadline, FCGI_REQUEST_ID, FCGI_BEGIN_REQUEST, &begin).await?;
        let params = self.build_cgi_variables(
            method,
            request_uri,
            host,
            remote_addr,
            headers,
            &content_type,
            body.len(),
        );
        send_record(
            w,
            deadline,
            FCGI_REQUEST_ID,
            FCGI_PARAMS,
            &encode_name_value_pairs(&params),
        )
        .await?;
        send_empty_record(w, deadline, FCGI_REQUEST_ID, FCGI_PARAMS).await?;
        if !body.is_empty() {
            send_record(w, deadline, FCGI_REQUEST_ID, FCGI_STDIN, body).await?;
        }
        send_empty_record(w, deadline, FCGI_REQUEST_ID, FCGI_STDIN).await
    }

    /// Reads STDOUT / STDERR / END_REQUEST records.
    async fn collect_reply(&self, c: &mut FastCgiConnection) -> Result<FastCgiReply, String> {
        let deadline = self.deadline(self.timeouts.read);
        let mut stdout = Vec::new();
        let mut hdr = [0u8; FCGI_HEADER_SIZE];
        loop {
            read_exact(&mut c.buffered_stream, deadline, &mut hdr)
                .await
                .map_err(|e| format!("fcgi: read header: {e}"))?;
            let record_type = hdr[1];
            let content_len = usize::from(hdr[4]) << 8 | usize::from(hdr[5]);
            let padding_len = usize::from(hdr[6]);
            let mut content = vec![0u8; content_len];
            if content_len > 0 {
                read_exact(&mut c.buffered_stream, deadline, &mut content)
                    .await
                    .map_err(|e| format!("fcgi: read content: {e}"))?;
            }
            if padding_len > 0 {
                let mut pad = vec![0u8; padding_len];
                read_exact(&mut c.buffered_stream, deadline, &mut pad)
                    .await
                    .map_err(|e| format!("fcgi: discard padding: {e}"))?;
            }
            match record_type {
                FCGI_STDOUT => stdout.extend_from_slice(&content),
                FCGI_STDERR => {} // PHP errors go to the PHP-FPM log
                FCGI_END_REQUEST => return Ok(parse_cgi_reply(&stdout)),
                _ => {}
            }
        }
    }
}

fn io_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

async fn read_exact<R: AsyncRead + Unpin>(
    r: &mut R,
    deadline: Option<tokio::time::Instant>,
    buf: &mut [u8],
) -> io::Result<()> {
    let res = match deadline {
        None => r.read_exact(buf).await,
        Some(d) => timeout_at(d, r.read_exact(buf))
            .await
            .map_err(|_| io_timeout())?,
    };
    match res {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "unexpected EOF",
        )),
        Err(e) => Err(e),
    }
}

async fn write_all<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    deadline: Option<tokio::time::Instant>,
    buf: &[u8],
) -> Result<(), String> {
    let res = match deadline {
        None => w.write_all(buf).await,
        Some(d) => timeout_at(d, w.write_all(buf))
            .await
            .map_err(|_| io_timeout().to_string())?,
    };
    res.map_err(|e| e.to_string())
}

/// Writes `body` as records of at most 65535 bytes, each padded
/// to a multiple of 8. An empty body writes nothing.
pub async fn send_record<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    deadline: Option<tokio::time::Instant>,
    req_id: u16,
    typ: u8,
    mut body: &[u8],
) -> Result<(), String> {
    while !body.is_empty() {
        let chunk = &body[..body.len().min(FCGI_MAX_CONTENT)];
        let pad = (8 - chunk.len() % 8) % 8;
        let hdr = [
            FCGI_VERSION,
            typ,
            (req_id >> 8) as u8,
            req_id as u8,
            (chunk.len() >> 8) as u8,
            chunk.len() as u8,
            pad as u8,
            0,
        ];
        write_all(w, deadline, &hdr).await?;
        write_all(w, deadline, chunk).await?;
        if pad > 0 {
            write_all(w, deadline, &[0u8; 8][..pad]).await?;
        }
        body = &body[chunk.len()..];
    }
    Ok(())
}

/// Writes a stream terminator (zero content length).
pub async fn send_empty_record<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    deadline: Option<tokio::time::Instant>,
    req_id: u16,
    typ: u8,
) -> Result<(), String> {
    write_all(
        w,
        deadline,
        &[
            FCGI_VERSION,
            typ,
            (req_id >> 8) as u8,
            req_id as u8,
            0,
            0,
            0,
            0,
        ],
    )
    .await
}

/// FastCGI name-value pair encoding.
pub fn encode_name_value_pairs(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::new();
    let len = |buf: &mut Vec<u8>, n: usize| {
        if n < 128 {
            buf.push(n as u8);
        } else {
            buf.extend_from_slice(&((n as u32) | 0x8000_0000).to_be_bytes());
        }
    };
    for (k, v) in pairs {
        len(&mut buf, k.len());
        len(&mut buf, v.len());
        buf.extend_from_slice(k);
        buf.extend_from_slice(v);
    }
    buf
}

/// Parses CGI headers + body. `Status:` sets the status.
pub fn parse_cgi_reply(data: &[u8]) -> FastCgiReply {
    let (header_part, body): (&[u8], &[u8]) = if let Some(i) = find(data, b"\r\n\r\n") {
        (&data[..i], &data[i + 4..])
    } else if let Some(i) = find(data, b"\n\n") {
        (&data[..i], &data[i + 2..])
    } else {
        (b"", data)
    };
    let mut resp = FastCgiReply {
        status: 200,
        headers: Vec::new(),
        body: body.to_vec(),
    };
    for raw in header_part.split(|&c| c == b'\n') {
        let mut end = raw.len();
        while end > 0 && (raw[end - 1] == b'\r' || raw[end - 1] == b'\n') {
            end -= 1;
        }
        let line = &raw[..end];
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&c| c == b':') else {
            continue;
        };
        let k = trim_whitespace(&line[..colon]);
        let v = trim_whitespace(&line[colon + 1..]);
        if wafio_domain::text_helpers::eq_ignore_case(k, b"Status") {
            let code = v.split(|&c| c == b' ').next().unwrap_or(b"");
            if let Some(code) = std::str::from_utf8(code)
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
            {
                resp.status = code;
            }
            continue;
        }
        match resp.headers.iter_mut().find(|(hk, _)| hk == k) {
            Some((_, vs)) => vs.push(v.to_vec()),
            None => resp.headers.push((k.to_vec(), vec![v.to_vec()])),
        }
    }
    resp
}

fn find(s: &[u8], sub: &[u8]) -> Option<usize> {
    memchr::memmem::find(s, sub)
}

/// The CGI parameter a request header becomes: `HTTP_` + upper-cased name, `-` turned into `_`
/// (`X-Real-IP`, `x_real_ip` and `X-Real_IP` all give `HTTP_X_REAL_IP`).
pub fn cgi_header_param(name: &[u8]) -> Vec<u8> {
    let dashed: Vec<u8> = name
        .iter()
        .map(|&c| if c == b'-' { b'_' } else { c })
        .collect();
    [b"HTTP_".as_slice(), &to_uppercase(&dashed)].concat()
}

fn group_headers(lines: &HeaderLines) -> Vec<(&[u8], Vec<&[u8]>)> {
    let mut out: Vec<(&[u8], Vec<&[u8]>)> = Vec::new();
    for (k, v) in lines {
        match out.iter_mut().find(|(ok, _)| *ok == k.as_slice()) {
            Some((_, vs)) => vs.push(v),
            None => out.push((k, vec![v])),
        }
    }
    out
}

/// Parses `fcgi:unix:/path.sock` or `fcgi://host[:port]`
/// (default port 9000). Explicit `doc_root` / `index` win over the legacy
/// `?root=` / `?index=` query; the index defaults to `index.php`.
pub fn parse_upstream_spec(
    upstream: &str,
    doc_root: &str,
    index: &str,
    max_conns: i64,
    to: FastCgiDeadlines,
) -> Result<Arc<FastCgiConnectionPool>, String> {
    let Some(rest) = upstream.strip_prefix("fcgi:") else {
        return Err(format!(
            "not a FastCGI upstream: {}",
            wafio_domain::text_helpers::quote(upstream.as_bytes())
        ));
    };
    let network;
    let addr;
    let raw_query;
    if let Some(sock) = rest.strip_prefix("unix:") {
        let (mut sock_part, q) = match sock.find('?') {
            Some(i) => (&sock[..i], &sock[i + 1..]),
            None => (sock, ""),
        };
        sock_part = sock_part.trim_end_matches(':');
        if sock_part.is_empty() {
            return Err("fcgi unix: empty socket path".into());
        }
        network = "unix";
        addr = sock_part.to_string();
        raw_query = q.as_bytes().to_vec();
    } else {
        let u = crate::url_parse::parse(format!("fcgi:{rest}").as_bytes())
            .map_err(|e| format!("fcgi upstream parse: {e}"))?;
        if u.host.is_empty() {
            return Err("fcgi upstream: missing host".into());
        }
        let mut h = String::from_utf8_lossy(&u.host).into_owned();
        if !h.contains(':') {
            h.push_str(":9000");
        }
        network = "tcp";
        addr = h;
        raw_query = u.raw_query;
    }
    let mut pool = FastCgiConnectionPool::new(network, &addr, max_conns, to);
    let p = Arc::get_mut(&mut pool).expect("fresh pool");
    let q = || wafio_bytetext::url::parse_query(&raw_query).0;
    if !doc_root.is_empty() {
        p.site_root = doc_root.as_bytes().to_vec();
    } else if !raw_query.is_empty() {
        p.site_root = wafio_bytetext::url::first_query_value(&q(), b"root").to_vec();
    }
    if !index.is_empty() {
        p.index = index.as_bytes().to_vec();
    } else if !raw_query.is_empty() {
        let v = wafio_bytetext::url::first_query_value(&q(), b"index").to_vec();
        if !v.is_empty() {
            p.index = v;
        }
    }
    if p.index.is_empty() {
        p.index = b"index.php".to_vec();
    }
    Ok(pool)
}

/// Lexically cleans a Unix path: collapses repeated slashes, `.` and `..`.
pub fn normalize_path(path: &[u8]) -> Vec<u8> {
    if path.is_empty() {
        return b".".to_vec();
    }
    let rooted = path[0] == b'/';
    let n = path.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let (mut r, mut dotdot) = (0, 0);
    if rooted {
        out.push(b'/');
        r = 1;
        dotdot = 1;
    }
    while r < n {
        if path[r] == b'/' || (path[r] == b'.' && (r + 1 == n || path[r + 1] == b'/')) {
            r += 1;
        } else if path[r] == b'.' && path[r + 1] == b'.' && (r + 2 == n || path[r + 2] == b'/') {
            r += 2;
            if out.len() > dotdot {
                let mut w = out.len() - 1;
                while w > dotdot && out[w] != b'/' {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(b"..");
                dotdot = out.len();
            }
        } else {
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && path[r] != b'/' {
                out.push(path[r]);
                r += 1;
            }
        }
    }
    if out.is_empty() {
        return b".".to_vec();
    }
    out
}

/// Joins the non-empty elements of a Unix path with '/' and cleans the result.
pub fn join_paths(elems: &[&[u8]]) -> Vec<u8> {
    let parts: Vec<&[u8]> = elems.iter().copied().filter(|e| !e.is_empty()).collect();
    if parts.is_empty() {
        return Vec::new();
    }
    normalize_path(&parts.join(&b'/'))
}

#[cfg(test)]
mod tests;
