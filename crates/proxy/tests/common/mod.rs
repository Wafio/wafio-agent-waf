//! Fake upstreams, a raw HTTP/1.1 client (no HTTP client crate in the workspace) and a proxy
//! harness built through the public API (`Proxy::apply` with `AppSpec`s).
#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use wafio_proxy::{AppAnalysisSetup, AppSpec, DecisionEvent, Proxy, ProxyOptions};

/// What an upstream received: request line, headers (lower-cased names, arrival order), body.
#[derive(Clone, Debug)]
pub struct Seen {
    pub line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }
    pub fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

#[derive(Clone)]
pub struct TestUpstream {
    pub addr: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl TestUpstream {
    pub fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
    pub fn last(&self) -> Seen {
        self.seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("upstream saw a request")
    }
    pub fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

/// HTTP/1.1 keep-alive upstream answering `200` with `extra` header lines and `body`.
pub async fn http_upstream_with(extra: &'static str, body: &'static [u8]) -> TestUpstream {
    http_upstream_delayed(extra, body, Duration::ZERO).await
}

/// As `http_upstream_with`, answering after `delay`.
pub async fn http_upstream_delayed(
    extra: &'static str,
    body: &'static [u8],
    delay: Duration,
) -> TestUpstream {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = TestUpstream {
        addr: l.local_addr().unwrap(),
        accepts: Arc::default(),
        seen: Arc::default(),
    };
    let u = up.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            u.accepts.fetch_add(1, Ordering::SeqCst);
            let seen = u.seen.clone();
            tokio::spawn(async move {
                let mut r = BufReader::new(s);
                while let Ok(Some((line, headers))) = read_head(&mut r).await {
                    let n = header(&headers, "content-length").map_or(0, |v| v.parse().unwrap());
                    let mut b = vec![0; n];
                    if r.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    seen.lock().unwrap().push(Seen {
                        line,
                        headers,
                        body: b,
                    });
                    tokio::time::sleep(delay).await;
                    let mut resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Up: 1\r\n{extra}\r\n",
                        body.len()
                    )
                    .into_bytes();
                    resp.extend_from_slice(body);
                    if r.get_mut().write_all(&resp).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    up
}

/// An upstream that answers each request with the raw bytes `reply` returns for it (`true` =
/// close the connection afterwards): for answers `http_upstream_with` cannot make (HTTP/1.0,
/// 204, close-delimited bodies).
pub async fn raw_upstream(
    reply: impl Fn(&Seen) -> (Vec<u8>, bool) + Send + Sync + 'static,
) -> TestUpstream {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = TestUpstream {
        addr: l.local_addr().unwrap(),
        accepts: Arc::default(),
        seen: Arc::default(),
    };
    let (u, reply) = (up.clone(), Arc::new(reply));
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            u.accepts.fetch_add(1, Ordering::SeqCst);
            let (seen, reply) = (u.seen.clone(), reply.clone());
            tokio::spawn(async move {
                let mut r = BufReader::new(s);
                while let Ok(Some((line, headers))) = read_head(&mut r).await {
                    let n = header(&headers, "content-length").map_or(0, |v| v.parse().unwrap());
                    let mut b = vec![0; n];
                    if r.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    let sn = Seen {
                        line,
                        headers,
                        body: b,
                    };
                    let (bytes, close) = reply(&sn);
                    seen.lock().unwrap().push(sn);
                    if r.get_mut().write_all(&bytes).await.is_err() || close {
                        return;
                    }
                }
            });
        }
    });
    up
}

pub async fn http_upstream() -> TestUpstream {
    http_upstream_with("", b"ok").await
}

pub fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Reads a request or response head: (first line, headers). `None` on clean EOF.
pub async fn read_head<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
) -> io::Result<Option<(String, Vec<(String, String)>)>> {
    let mut line = String::new();
    if r.read_line(&mut line).await? == 0 {
        return Ok(None);
    }
    let first = line.trim_end().to_string();
    let mut headers = Vec::new();
    loop {
        line.clear();
        if r.read_line(&mut line).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let l = line.trim_end();
        if l.is_empty() {
            return Ok(Some((first, headers)));
        }
        let (k, v) = l.split_once(':').unwrap();
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
}

#[derive(Debug)]
pub struct ReplyParts {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ReplyParts {
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub async fn read_reply<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> io::Result<ReplyParts> {
    let (first, headers) = read_head(r).await?.ok_or(io::ErrorKind::UnexpectedEof)?;
    let status = first.split(' ').nth(1).unwrap().parse().unwrap();
    let mut body = Vec::new();
    if let Some(n) = header(&headers, "content-length") {
        body.resize(n.parse().unwrap(), 0);
        r.read_exact(&mut body).await?;
    } else if status != 101 && status != 100 && status != 204 && status != 304 {
        r.read_to_end(&mut body).await?;
    }
    Ok(ReplyParts {
        status,
        headers,
        body,
    })
}

/// One response exactly as it came, with the `Date` value blanked (`Date: <date>`): the head, then
/// the body by `Content-Length`, to EOF without one, nothing when `head_only` (HEAD, 204, 304).
pub async fn read_raw(r: &mut BufReader<TcpStream>, head_only: bool) -> io::Result<String> {
    let read = async {
        let (mut raw, mut len) = (Vec::new(), None);
        loop {
            let mut line = Vec::new();
            if r.read_until(b'\n', &mut line).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if line.len() > 5 && line[..5].eq_ignore_ascii_case(b"date:") {
                line = b"Date: <date>\r\n".to_vec();
            }
            if line.len() > 15 && line[..15].eq_ignore_ascii_case(b"content-length:") {
                len = String::from_utf8_lossy(&line[15..])
                    .trim()
                    .parse::<usize>()
                    .ok();
            }
            let end = line == b"\r\n";
            raw.extend_from_slice(&line);
            if end {
                break;
            }
        }
        match (head_only, len) {
            (true, _) => {}
            (false, Some(n)) => {
                let at = raw.len();
                raw.resize(at + n, 0);
                r.read_exact(&mut raw[at..]).await?;
            }
            (false, None) => {
                r.read_to_end(&mut raw).await?;
            }
        }
        Ok(String::from_utf8_lossy(&raw).into_owned())
    };
    tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "response"))?
}

/// The server closed the connection (EOF within two seconds).
pub async fn at_eof(r: &mut BufReader<TcpStream>) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(2), r.read(&mut [0u8; 1])).await,
        Ok(Ok(0))
    )
}

/// A client connection (keep-alive).
pub struct Client(pub BufReader<TcpStream>);

impl Client {
    pub async fn connect(addr: SocketAddr) -> io::Result<Client> {
        Ok(Client(BufReader::new(TcpStream::connect(addr).await?)))
    }

    pub async fn send(&mut self, raw: &[u8]) -> io::Result<ReplyParts> {
        self.0.get_mut().write_all(raw).await?;
        read_reply(&mut self.0).await
    }
}

pub async fn one(addr: SocketAddr, raw: &[u8]) -> ReplyParts {
    Client::connect(addr)
        .await
        .unwrap()
        .send(raw)
        .await
        .unwrap()
}

pub fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: app.test\r\n\r\n").into_bytes()
}

pub fn post(path: &str, ct: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!("POST {path} HTTP/1.1\r\nHost: app.test\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    r.extend_from_slice(body);
    r
}

/// Rules JSON of every test app: the defaults.
pub const RULES: &str = r#"{}"#;

pub fn analysis_setup(rules: &str) -> Arc<AppAnalysisSetup> {
    Arc::new(wafio_proxy::testing::analysis_setup(rules.as_bytes()))
}

/// A free local port (bound and released).
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn app(id: &str, port: u16, upstream: &str) -> AppSpec {
    AppSpec {
        app_id: id.into(),
        listen_host: "127.0.0.1".into(),
        listen_port: port,
        upstream: upstream.into(),
        mode: "block".into(),
        proxy_config: Vec::new(),
        rules_json: Vec::new(),
        fcgi_doc_root: String::new(),
        fcgi_index: String::new(),
        maintenance: Vec::new(),
        analysis: analysis_setup(RULES),
        tls: None,
    }
}

pub type Events = Arc<Mutex<Vec<DecisionEvent>>>;

pub struct Harness {
    pub proxy: Proxy,
    pub events: Events,
}

impl Harness {
    pub fn new() -> Harness {
        let events: Events = Arc::default();
        let ev = events.clone();
        let proxy = Proxy::new(ProxyOptions::new(Arc::new(move |e| {
            ev.lock().unwrap().push(e)
        })));
        Harness { proxy, events }
    }

    /// Serves `apps`; returns the address of the first.
    pub fn serve(apps: Vec<AppSpec>) -> (Harness, SocketAddr) {
        let h = Harness::new();
        let addr = format!("127.0.0.1:{}", apps[0].listen_port)
            .parse()
            .unwrap();
        h.proxy.apply(apps).unwrap();
        (h, addr)
    }

    pub fn events(&self) -> Vec<DecisionEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn last_event(&self) -> DecisionEvent {
        self.events().last().cloned().expect("a decision event")
    }
}

pub fn s(b: &[u8]) -> &str {
    std::str::from_utf8(b).unwrap()
}

pub async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}
