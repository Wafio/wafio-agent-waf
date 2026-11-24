//! What the response cache tests share: a scratch cache directory, an app with a cache in front of a
//! programmable upstream, and a few raw requests. Included by the test files that need it.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use wafio_proxy::{AppSpec, CacheHost, CacheSpec, Proxy, ProxyOptions};

use crate::common::*;

/// A scratch directory, removed at the end of the test.
pub struct Dir(pub PathBuf);

impl Dir {
    pub fn new(tag: &str) -> Dir {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("wafio-cache-it-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir.canonicalize().unwrap())
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The user the tests run as, who owns the scratch directories.
pub fn uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

/// A response of an upstream: the status line text, header lines and the body, with the length.
pub fn http(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// A response of an upstream to `seen`: as [`http`], without the body for `HEAD`.
pub fn reply_to(seen: &Seen, status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = http(status, headers, body);
    if seen.line.starts_with("HEAD ") {
        out.truncate(out.len() - body.len());
    }
    out
}

/// An upstream that answers every request with `status` and `headers` and a body that says how many
/// requests it has had: `answer 1`, `answer 2`.
pub async fn counting(status: &'static str, headers: &'static str) -> TestUpstream {
    let n = Arc::new(AtomicUsize::new(0));
    raw_upstream(move |seen| {
        let i = n.fetch_add(1, Ordering::SeqCst) + 1;
        (
            reply_to(seen, status, headers, format!("answer {i}").as_bytes()),
            false,
        )
    })
    .await
}

/// The answer of a page that every visitor gets and that may be kept ten minutes.
pub const PUBLIC: &str =
    "Content-Type: text/html\r\nCache-Control: public, max-age=600\r\nX-Up: 1\r\n";

pub fn spec() -> CacheSpec {
    CacheSpec::default()
}

/// A proxy with one app, `shop`, whose cache is `spec`, with the directory and its store.
pub struct Site {
    pub h: Harness,
    pub addr: SocketAddr,
    pub up: TestUpstream,
    pub host: Arc<CacheHost>,
    pub dir: Dir,
}

pub fn app_for(up: &TestUpstream, port: u16, spec: Option<CacheSpec>) -> AppSpec {
    let mut a = app("shop", port, &format!("http://{}", up.addr));
    a.cache = spec;
    a
}

/// Opens a cache directory of its own, applies the app and waits until answers are stored.
pub async fn site(up: TestUpstream, spec: CacheSpec, edit: impl FnOnce(&mut AppSpec)) -> Site {
    let dir = Dir::new("site");
    let host = CacheHost::open(&dir.0, uid()).unwrap();
    let port = free_port();
    let mut a = app_for(&up, port, Some(spec));
    edit(&mut a);
    let (h, addr) = serve_with(&host, a);
    assert!(
        host.wait_writable(Duration::from_secs(10)),
        "the cache is ready to store"
    );
    Site {
        h,
        addr,
        up,
        host,
        dir,
    }
}

/// A proxy over `host` that serves `app`.
pub fn serve_with(host: &Arc<CacheHost>, app: AppSpec) -> (Harness, SocketAddr) {
    let events: Events = Arc::default();
    let ev = events.clone();
    let mut opts = ProxyOptions::new(Arc::new(move |e| ev.lock().unwrap().push(e)));
    opts.cache = Some(host.clone());
    let addr = format!("127.0.0.1:{}", app.listen_port).parse().unwrap();
    let proxy = Proxy::new(opts);
    proxy.apply(vec![app]).unwrap();
    (Harness { proxy, events }, addr)
}

/// The same proxy with the app replaced (a new bundle).
pub fn apply(h: &Harness, app: AppSpec) {
    h.proxy.apply(vec![app]).unwrap();
}

/// The files of the answers below a cache directory (not the lock, not `tmp/`).
pub fn answer_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(apps) = std::fs::read_dir(dir) else {
        return out;
    };
    for app in apps.flatten().filter(|a| a.path().is_dir()) {
        for shard in std::fs::read_dir(app.path()).unwrap().flatten() {
            let name = shard.file_name();
            if name == "tmp" || !shard.path().is_dir() {
                continue;
            }
            for file in std::fs::read_dir(shard.path()).unwrap().flatten() {
                out.push(file.path());
            }
        }
    }
    out.sort();
    out
}

pub fn x_cache(r: &ReplyParts) -> &str {
    r.header("x-cache").unwrap_or("")
}

/// A request with extra header lines.
pub fn request(method: &str, path: &str, extra: &[&str]) -> Vec<u8> {
    let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: app.test\r\n");
    for line in extra {
        raw.push_str(line);
        raw.push_str("\r\n");
    }
    raw.push_str("\r\n");
    raw.into_bytes()
}

pub fn with(path: &str, extra: &[&str]) -> Vec<u8> {
    request("GET", path, extra)
}

/// A `HEAD` request and the head that answers it (nothing follows).
pub async fn head_of(addr: SocketAddr, path: &str, extra: &[&str]) -> ReplyParts {
    let mut c = BufReader::new(TcpStream::connect(addr).await.unwrap());
    c.get_mut()
        .write_all(&request("HEAD", path, extra))
        .await
        .unwrap();
    let (first, headers) = read_head(&mut c).await.unwrap().unwrap();
    ReplyParts {
        status: first.split(' ').nth(1).unwrap().parse().unwrap(),
        headers,
        body: Vec::new(),
    }
}

/// What an upstream saw, by request line.
pub fn lines(up: &TestUpstream) -> Vec<String> {
    up.seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.line.clone())
        .collect()
}
