//! FastCGI routes through the public API (pool semantics themselves are agent-io's tests):
//! CGI params from the forwarded request-target, client headers, FCGI_KEEP_CONN
//! reuse, idle connections reaped after `idle_conn_ms`, the pool closed when the route goes,
//! PHP-FPM end to end when `php-fpm8.3` (or $WAFIO_TEST_PHP_FPM) exists.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
struct Fake {
    accepts: Arc<AtomicUsize>,
    open: Arc<AtomicUsize>,
    params: Arc<Mutex<Vec<HashMap<String, String>>>>,
}

/// Minimal FastCGI responder: echoes stdin, `X-Conn: <connection number>`, honours KEEP_CONN.
async fn fake_fcgi() -> (SocketAddr, Fake) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let f = Fake::default();
    let f2 = f.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let id = f2.accepts.fetch_add(1, Ordering::SeqCst) + 1;
            f2.open.fetch_add(1, Ordering::SeqCst);
            let f3 = f2.clone();
            tokio::spawn(async move {
                'conn: loop {
                    let (mut keep, mut params, mut stdin) = (false, Vec::new(), Vec::new());
                    loop {
                        let mut h = [0u8; 8];
                        if s.read_exact(&mut h).await.is_err() {
                            break 'conn;
                        }
                        let len = (h[4] as usize) << 8 | h[5] as usize;
                        let mut c = vec![0; len + h[6] as usize];
                        s.read_exact(&mut c).await.unwrap();
                        c.truncate(len);
                        match (h[1], len) {
                            (1, _) => keep = c[2] & 1 == 1,
                            (4, _) => params.extend_from_slice(&c),
                            (5, 0) => break,
                            (5, _) => stdin.extend_from_slice(&c),
                            _ => {}
                        }
                    }
                    f3.params.lock().unwrap().push(decode_params(&params));
                    let mut out = format!(
                        "Status: 201 Created\r\nX-Conn: {id}\r\nContent-Type: text/plain\r\n\r\n"
                    )
                    .into_bytes();
                    out.extend_from_slice(&stdin);
                    let mut w = Vec::new();
                    for chunk in out.chunks(65535) {
                        w.extend_from_slice(&[
                            1,
                            6,
                            0,
                            1,
                            (chunk.len() >> 8) as u8,
                            chunk.len() as u8,
                            0,
                            0,
                        ]);
                        w.extend_from_slice(chunk);
                    }
                    w.extend_from_slice(&[
                        1, 6, 0, 1, 0, 0, 0, 0, 1, 3, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]);
                    if s.write_all(&w).await.is_err() || !keep {
                        break;
                    }
                }
                f3.open.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, f)
}

fn decode_params(mut b: &[u8]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let len = |b: &mut &[u8]| {
        if b[0] < 128 {
            let n = b[0] as usize;
            *b = &b[1..];
            n
        } else {
            let n = (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x7fff_ffff) as usize;
            *b = &b[4..];
            n
        }
    };
    while !b.is_empty() {
        let (k, v) = (len(&mut b), len(&mut b));
        m.insert(
            String::from_utf8_lossy(&b[..k]).into(),
            String::from_utf8_lossy(&b[k..k + v]).into(),
        );
        b = &b[k + v..];
    }
    m
}

fn fcgi_app(
    port: u16,
    upstream: String,
    doc_root: &str,
    proxy_config: &str,
) -> wafio_proxy::AppSpec {
    let mut a = app("php", port, &upstream);
    a.fcgi_doc_root = doc_root.into();
    a.proxy_config = proxy_config.as_bytes().to_vec();
    a
}

#[tokio::test]
async fn route_answers_over_fastcgi_with_cgi_params() {
    let (addr, fake) = fake_fcgi().await;
    let port = free_port();
    let (h, proxy) = Harness::serve(vec![fcgi_app(
        port,
        format!("fcgi://{addr}"),
        "/var/www",
        "",
    )]);
    let mut c = Client::connect(proxy).await.unwrap();
    let body = vec![b'q'; 200_000]; // > one 65535-byte record
    let raw = format!(
        "POST /a//./b%20c.php?x=1 HTTP/1.1\r\nHost: App.Test:8080\r\nX-Forwarded-For: 6.6.6.6\r\nX-Dup: a\r\nX-Dup: b\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut req = raw.into_bytes();
    req.extend_from_slice(&body);
    let resp = c.send(&req).await.unwrap();
    assert_eq!(
        (resp.status, resp.header("x-conn"), resp.body.len()),
        (201, Some("1"), body.len())
    );
    assert_eq!(resp.header("server"), Some("wafio-route-proxy"));
    let resp = c.send(&get("/index.php")).await.unwrap();
    assert_eq!(
        (resp.status, resp.header("x-conn")),
        (201, Some("1")),
        "FCGI_KEEP_CONN connection reused"
    );
    let p = fake.params.lock().unwrap()[0].clone();
    // PHP routes on the forwarded (decoded, dot-resolved, re-quoted) target.
    assert_eq!(p["REQUEST_URI"], "/a/b%20c.php?x=1");
    assert_eq!(p["SCRIPT_FILENAME"], "/var/www/a/b%20c.php");
    assert_eq!(p["QUERY_STRING"], "x=1");
    assert_eq!(p["HTTP_X_DUP"], "a, b");
    // An untrusted peer's forwarded headers replaced, as for HTTP upstreams.
    assert_eq!(
        (
            p["HTTP_X_FORWARDED_FOR"].as_str(),
            p["HTTP_X_REAL_IP"].as_str()
        ),
        ("127.0.0.1", "127.0.0.1")
    );
    assert_eq!(p["REMOTE_ADDR"], "127.0.0.1");
    assert_eq!(p["CONTENT_LENGTH"], body.len().to_string());
    assert_eq!(s(&h.last_event().action), "allow");
}

/// `X_Forwarded_For` / `X-Real_IP` become the same CGI params as the
/// agent's own client headers and sorted after them (PHP-FPM keeps the last of a repeated
/// param), and `Proxy:` becomes `HTTP_PROXY` (httpoxy). None of them reaches PHP.
#[tokio::test]
async fn client_spelling_of_agent_headers_and_proxy_never_reach_php() {
    let (addr, fake) = fake_fcgi().await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![fcgi_app(
        port,
        format!("fcgi://{addr}"),
        "/var/www",
        "",
    )]);
    let raw = "GET /index.php HTTP/1.1\r\nHost: app.test\r\nX_Forwarded_For: 6.6.6.6\r\nX-Real_IP: 6.6.6.6\r\nx-REAL-ip: 7.7.7.7\r\nProxy: http://evil.example:8080\r\nX-Other: kept\r\n\r\n";
    assert_eq!(one(proxy, raw.as_bytes()).await.status, 201);
    let p = fake.params.lock().unwrap()[0].clone();
    assert_eq!(
        (
            p["HTTP_X_FORWARDED_FOR"].as_str(),
            p["HTTP_X_REAL_IP"].as_str()
        ),
        ("127.0.0.1", "127.0.0.1")
    );
    assert!(!p.contains_key("HTTP_PROXY"), "{p:?}");
    assert_eq!(p["HTTP_X_OTHER"], "kept");
}

#[tokio::test]
async fn idle_connection_is_reaped_and_route_removal_closes_the_pool() {
    let (addr, fake) = fake_fcgi().await;
    let (p1, p2) = (free_port(), free_port());
    let (h, proxy) = Harness::serve(vec![fcgi_app(
        p1,
        format!("fcgi://{addr}"),
        "/srv",
        r#"{"idle_conn_ms":200}"#,
    )]);
    assert_eq!(one(proxy, &get("/")).await.status, 201);
    assert_eq!(fake.open.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        fake.open.load(Ordering::SeqCst),
        0,
        "reaper closed the idle connection (slot released)"
    );

    // A long-lived pool: its kept connection pins a PHP-FPM worker until the route goes.
    h.proxy
        .apply(vec![fcgi_app(p2, format!("fcgi://{addr}"), "/srv", "")])
        .unwrap();
    let p2: SocketAddr = format!("127.0.0.1:{p2}").parse().unwrap();
    assert_eq!(one(p2, &get("/")).await.status, 201);
    assert_eq!(fake.open.load(Ordering::SeqCst), 1);
    h.proxy.apply(vec![]).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        fake.open.load(Ordering::SeqCst),
        0,
        "pooled FastCGI connection of the removed route closed"
    );
}

#[tokio::test]
async fn fastcgi_down_is_502() {
    let port = free_port();
    let (h, proxy) = Harness::serve(vec![fcgi_app(
        port,
        format!("fcgi://127.0.0.1:{}", free_port()),
        "/srv",
        "",
    )]);
    assert_eq!(one(proxy, &get("/")).await.status, 502);
    assert_eq!(s(&h.last_event().action), "upstream_error");
}

// ---- real PHP-FPM ----

fn php_fpm() -> Option<String> {
    let p = std::env::var("WAFIO_TEST_PHP_FPM").unwrap_or_else(|_| "/usr/sbin/php-fpm8.3".into());
    std::path::Path::new(&p).exists().then_some(p)
}

struct Fpm {
    child: std::process::Child,
    addr: String,
    root: std::path::PathBuf,
}

impl Drop for Fpm {
    fn drop(&mut self) {
        // SIGTERM: the master stops its workers (SIGKILL would orphan them).
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
    }
}

fn start_fpm(bin: &str, max_children: usize) -> Fpm {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("fpm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("www")).unwrap();
    std::fs::write(
        dir.join("www/index.php"),
        "<?php http_response_code(201); header('X-Worker: '.getmypid()); echo $_SERVER['REQUEST_METHOD'], ' ', $_SERVER['SCRIPT_FILENAME'], ' ', file_get_contents('php://input');",
    )
    .unwrap();
    let addr = format!("127.0.0.1:{}", free_port());
    let conf = format!(
        "[global]\npid = {d}/fpm.pid\nerror_log = {d}/fpm.log\ndaemonize = no\n[www]\nlisten = {addr}\npm = static\npm.max_children = {max_children}\nclear_env = no\n",
        d = dir.display()
    );
    std::fs::write(dir.join("fpm.conf"), conf).unwrap();
    let child = std::process::Command::new(bin)
        .args(["-n", "-y"])
        .arg(dir.join("fpm.conf"))
        .arg("-F")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let t = Instant::now();
    while std::net::TcpStream::connect(&addr).is_err() {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "php-fpm did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Fpm {
        child,
        addr,
        root: dir.join("www"),
    }
}

#[tokio::test]
async fn php_fpm_end_to_end_and_keep_conn() {
    let Some(bin) = php_fpm() else {
        return eprintln!("skipped: no php-fpm");
    };
    let fpm = start_fpm(&bin, 2);
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![fcgi_app(
        port,
        format!("fcgi://{}", fpm.addr),
        &fpm.root.display().to_string(),
        "",
    )]);
    let mut c = Client::connect(proxy).await.unwrap();
    let r1 = c
        .send(&post("/app/route", "text/plain", b"hello"))
        .await
        .unwrap();
    assert_eq!(r1.status, 201, "{:?}", r1.text());
    assert_eq!(
        r1.text(),
        format!("POST {}/index.php hello", fpm.root.display())
    );
    let worker = r1.header("x-worker").unwrap().to_string();
    for _ in 0..5 {
        let r = c.send(&get("/")).await.unwrap();
        assert_eq!(
            r.header("x-worker"),
            Some(worker.as_str()),
            "same kept connection, same worker"
        );
    }
}
