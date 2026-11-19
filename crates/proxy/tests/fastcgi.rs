//! FastCGI routes through the public API (the client's own protocol tests are agent-io's):
//! CGI params from the forwarded request-target, client headers, one connection for each
//! request with no FCGI_KEEP_CONN by default, connections kept and reused when the app asks
//! for it, idle connections reaped after `idle_conn_ms`, the pool closed when the route goes,
//! PHP-FPM end to end when `php-fpm8.3` (or $WAFIO_TEST_PHP_FPM) exists.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::*;

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
        (201, Some("2")),
        "a new connection for the second request"
    );
    assert_eq!(*fake.begin_flags.lock().unwrap(), [0, 0]);
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
async fn no_connection_stays_open_after_a_request() {
    let (addr, fake) = fake_fcgi().await;
    let (_h, proxy) = Harness::serve(vec![fcgi_app(
        free_port(),
        format!("fcgi://{addr}"),
        "/srv",
        "",
    )]);
    for _ in 0..3 {
        assert_eq!(one(proxy, &get("/")).await.status, 201);
    }
    let end = Instant::now() + Duration::from_secs(5);
    while fake.open.load(Ordering::SeqCst) != 0 && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(fake.accepts.load(Ordering::SeqCst), 3);
    assert_eq!(
        fake.open.load(Ordering::SeqCst),
        0,
        "the agent closed each connection (slot released)"
    );
}

#[tokio::test]
async fn an_app_that_keeps_connections_reuses_one_with_keep_conn_set() {
    let (addr, fake) = fake_fcgi().await;
    let (_h, proxy) = Harness::serve(vec![keeping_connections(fcgi_app(
        free_port(),
        format!("fcgi://{addr}"),
        "/srv",
        "",
    ))]);
    let mut c = Client::connect(proxy).await.unwrap();
    for _ in 0..3 {
        let resp = c.send(&get("/")).await.unwrap();
        assert_eq!((resp.status, resp.header("x-conn")), (201, Some("1")));
    }
    assert_eq!(fake.accepts.load(Ordering::SeqCst), 1);
    assert_eq!(*fake.begin_flags.lock().unwrap(), [1, 1, 1]);
    assert_eq!(fake.open.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn idle_connection_is_reaped_and_route_removal_closes_the_pool() {
    let (addr, fake) = fake_fcgi().await;
    let (p1, p2) = (free_port(), free_port());
    let (h, proxy) = Harness::serve(vec![keeping_connections(fcgi_app(
        p1,
        format!("fcgi://{addr}"),
        "/srv",
        r#"{"idle_conn_ms":200}"#,
    ))]);
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
        .apply(vec![keeping_connections(fcgi_app(
            p2,
            format!("fcgi://{addr}"),
            "/srv",
            "",
        ))])
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
async fn php_fpm_end_to_end() {
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
    for _ in 0..5 {
        let r = c.send(&get("/")).await.unwrap();
        assert_eq!(r.status, 201, "{:?}", r.text());
    }
}

#[tokio::test]
async fn php_fpm_with_keep_conn_serves_every_request_from_one_worker() {
    let Some(bin) = php_fpm() else {
        return eprintln!("skipped: no php-fpm");
    };
    let fpm = start_fpm(&bin, 2);
    let (_h, proxy) = Harness::serve(vec![keeping_connections(fcgi_app(
        free_port(),
        format!("fcgi://{}", fpm.addr),
        &fpm.root.display().to_string(),
        "",
    ))]);
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
            "the kept connection stays on one worker"
        );
    }
}
