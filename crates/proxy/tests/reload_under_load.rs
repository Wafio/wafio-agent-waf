//! SIGUSR2 reload under load without failed requests; READY=1 (+ MAINPID) to systemd
//! only after the first configuration was applied; the open WebSocket sessions of the process
//! that hands over end with a close frame. Runs examples/reload_demo.

mod common;

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use tokio::net::{TcpListener, TcpStream};
use wafio_agent_io::ws_frame::{WsConnection, WsError};

/// Built by `cargo test -p wafio-proxy` (examples are built with the tests; cargo holds the
/// target-dir lock while tests run, so a test cannot build it itself).
fn demo_exe() -> PathBuf {
    let deps = std::env::current_exe().unwrap();
    let exe = deps
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/reload_demo");
    assert!(
        exe.exists(),
        "{} missing: run `cargo test -p wafio-proxy` without --test",
        exe.display()
    );
    exe
}

/// Next `READY=1` datagram; returns its MAINPID.
fn wait_ready(sock: &UnixDatagram) -> u32 {
    let mut buf = [0u8; 512];
    loop {
        let n = sock.recv(&mut buf).expect("READY within the timeout");
        let msg = String::from_utf8_lossy(&buf[..n]).to_string();
        if msg.lines().any(|l| l == "READY=1") {
            return msg
                .lines()
                .find_map(|l| l.strip_prefix("MAINPID="))
                .unwrap()
                .parse()
                .unwrap();
        }
    }
}

/// The tests copy the demo and start the copy. A process another test forks while a copy is being
/// written holds the file open, and starting the copy then fails with "text file busy", so the
/// tests of this file run one at a time.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| !s.contains(") Z "))
}

#[derive(Default)]
struct Stats {
    ok: AtomicUsize,
    errors: AtomicUsize,
    retried: AtomicUsize,
    by_pid: Mutex<Vec<(Instant, String)>>,
}

async fn load(proxy: std::net::SocketAddr, stats: Arc<Stats>, stop: Arc<AtomicBool>) {
    let mut conn: Option<Client> = None;
    let mut on_conn = 0;
    let mut retry = false;
    while !stop.load(Ordering::Relaxed) {
        if conn.is_none() {
            match Client::connect(proxy).await {
                Ok(c) => conn = Some(c),
                Err(e) => {
                    eprintln!("connect error: {e}");
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            on_conn = 0;
        }
        let reused = on_conn > 0;
        match conn.as_mut().unwrap().send(&get("/")).await {
            Ok(r) if r.status == 200 => {
                stats.ok.fetch_add(1, Ordering::Relaxed);
                stats
                    .by_pid
                    .lock()
                    .unwrap()
                    .push((Instant::now(), r.header("x-served-by").unwrap().to_string()));
                on_conn += 1;
                retry = false;
                if r.header("connection") == Some("close") || on_conn >= 8 {
                    conn = None;
                }
            }
            Ok(r) => {
                eprintln!("status {}", r.status);
                stats.errors.fetch_add(1, Ordering::Relaxed);
                conn = None;
            }
            // What every HTTP client does with a keep-alive connection the server closed
            // between requests: resend an idempotent request once on a new connection.
            Err(_) if reused && !retry => {
                stats.retried.fetch_add(1, Ordering::Relaxed);
                retry = true;
                conn = None;
            }
            Err(e) => {
                eprintln!("request error: {e}");
                stats.errors.fetch_add(1, Ordering::Relaxed);
                conn = None;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigusr2_reload_under_load() {
    let _one = ONE_AT_A_TIME.lock().await;
    // Under the system temp directory, not the cargo one: the Unix sockets in it must fit sun_path (108 bytes),
    // and a checkout several folders deep does not leave room.
    let dir = std::env::temp_dir().join(format!("wafio-reload-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Run from a copy so the "package upgrade" below can replace the file under it.
    let exe = dir.join("reload-demo");
    std::fs::copy(demo_exe(), &exe).unwrap();
    let notify = UnixDatagram::bind(dir.join("notify.sock")).unwrap();
    notify
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();

    let up = http_upstream().await;
    let listen = format!("127.0.0.1:{}", free_port());
    let proxy: std::net::SocketAddr = listen.parse().unwrap();
    let mut first = std::process::Command::new(&exe)
        .args([
            "--listen",
            &listen,
            "--upstream",
            &up.addr.to_string(),
            "--run-dir",
        ])
        .arg(&dir)
        .args(["--apply-delay-ms", "300"])
        .env("NOTIFY_SOCKET", dir.join("notify.sock"))
        .spawn()
        .unwrap();
    let pid1 = tokio::task::block_in_place(|| wait_ready(&notify));
    assert_eq!(pid1, first.id());

    let stats = Arc::new(Stats::default());
    let stop = Arc::new(AtomicBool::new(false));
    let workers: Vec<_> = (0..16)
        .map(|_| tokio::spawn(load(proxy, stats.clone(), stop.clone())))
        .collect();
    tokio::time::sleep(Duration::from_millis(700)).await;

    // Package upgrade: a new file at the same path, then `systemctl reload` = SIGUSR2.
    std::fs::copy(&exe, dir.join("reload-demo.new")).unwrap();
    std::fs::rename(dir.join("reload-demo.new"), &exe).unwrap();
    let usr2_at = Instant::now();
    assert!(
        std::process::Command::new("kill")
            .args(["-USR2", &pid1.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let pid2 = tokio::task::block_in_place(|| wait_ready(&notify));
    let ready_after = usr2_at.elapsed();
    assert_ne!(pid2, pid1);
    tokio::time::sleep(Duration::from_millis(700)).await;
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        w.await.unwrap();
    }
    let t = Instant::now();
    while first.try_wait().unwrap().is_none() {
        assert!(
            t.elapsed() < Duration::from_secs(35),
            "predecessor did not exit"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let pred_exit = usr2_at.elapsed();

    let by_pid = stats.by_pid.lock().unwrap().clone();
    let (p1, p2) = (pid1.to_string(), pid2.to_string());
    let old_after_usr2 = by_pid
        .iter()
        .filter(|(t, p)| *p == p1 && *t > usr2_at)
        .count();
    let last_old = by_pid
        .iter()
        .filter(|(_, p)| *p == p1)
        .map(|(t, _)| t.duration_since(usr2_at))
        .max();
    let new = by_pid.iter().filter(|(_, p)| *p == p2).count();
    eprintln!(
        "reload: ok={} errors={} retried={} | old pid served {} after SIGUSR2 (last at {:?}), new pid served {} | READY from successor after {:?}, predecessor exited after {:?}",
        stats.ok.load(Ordering::Relaxed),
        stats.errors.load(Ordering::Relaxed),
        stats.retried.load(Ordering::Relaxed),
        old_after_usr2,
        last_old,
        new,
        ready_after,
        pred_exit
    );
    assert_eq!(
        stats.errors.load(Ordering::Relaxed),
        0,
        "failed requests during reload"
    );
    assert!(
        ready_after >= Duration::from_millis(300),
        "READY only after the successor applied its configuration"
    );
    assert!(old_after_usr2 > 0 && new > 0);
    assert!(
        by_pid.iter().rev().take(50).all(|(_, p)| *p == p2),
        "only the successor serves at the end"
    );

    let _ = std::process::Command::new("kill")
        .args(["-TERM", &p2])
        .status();
    let t = Instant::now();
    while alive(pid2) {
        assert!(
            t.elapsed() < Duration::from_secs(35),
            "successor did not stop on SIGTERM"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        Client::connect(proxy).await.is_err(),
        "port closed after SIGTERM"
    );
}

/// A WebSocket echo server; its address.
async fn ws_echo() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(async move {
                let Ok(c) = WsConnection::server(Box::new(s)).await else {
                    return;
                };
                while let Ok((kind, msg)) = c.next_data_message().await {
                    if c.send_data_message(kind, &msg).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

async fn ws_open(proxy: std::net::SocketAddr, path: &str) -> Result<WsConnection, WsError> {
    let s = TcpStream::connect(proxy).await.unwrap();
    WsConnection::client(Box::new(s), "app.test", path, &[])
        .await
        .map(|(c, _)| c)
        .map_err(|(e, _)| e)
}

async fn ws_echoes(c: &WsConnection) {
    c.send_data_message(1, b"ping").await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), c.next_data_message())
        .await
        .expect("an echo")
        .unwrap();
    assert_eq!(got, (1, b"ping".to_vec()));
}

/// The sessions the predecessor holds get close 1001 once the successor is ready, long before
/// the drain timeout would cut them. The successor reads the current maintenance setting: it
/// answers a new handshake of a blocked client with 503 and lets an allowed path in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigusr2_reload_closes_open_websocket_sessions() {
    let _one = ONE_AT_A_TIME.lock().await;
    let dir = std::env::temp_dir().join(format!("wafio-reload-ws-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join("reload-demo");
    std::fs::copy(demo_exe(), &exe).unwrap();
    let notify = UnixDatagram::bind(dir.join("notify.sock")).unwrap();
    notify
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();

    let upstream = ws_echo().await;
    let listen = format!("127.0.0.1:{}", free_port());
    let proxy: std::net::SocketAddr = listen.parse().unwrap();
    let maintenance = dir.join("maintenance.json");
    let mut first = std::process::Command::new(&exe)
        .args(["--listen", &listen, "--upstream", &upstream.to_string()])
        .arg("--run-dir")
        .arg(&dir)
        .arg("--maintenance-file")
        .arg(&maintenance)
        .env("NOTIFY_SOCKET", dir.join("notify.sock"))
        .spawn()
        .unwrap();
    let pid1 = tokio::task::block_in_place(|| wait_ready(&notify));
    assert_eq!(pid1, first.id());

    let chat = ws_open(proxy, "/chat").await.unwrap();
    let safe = ws_open(proxy, "/safe/room").await.unwrap();
    ws_echoes(&chat).await;
    ws_echoes(&safe).await;

    // The successor starts with maintenance mode on; the predecessor never learns of it.
    std::fs::write(&maintenance, br#"{"enabled":true,"allow_paths":["/safe"]}"#).unwrap();
    let usr2_at = Instant::now();
    assert!(
        std::process::Command::new("kill")
            .args(["-USR2", &pid1.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let pid2 = tokio::task::block_in_place(|| wait_ready(&notify));
    assert_ne!(pid2, pid1);
    for c in [&chat, &safe] {
        match tokio::time::timeout(Duration::from_secs(5), c.next_data_message()).await {
            Ok(Err(WsError::Close { code, text })) => {
                assert_eq!((code, text.as_str()), (1001, "Going away"));
            }
            other => panic!("expected close 1001, got {other:?}"),
        }
    }
    assert!(
        usr2_at.elapsed() < Duration::from_secs(10),
        "closed {:?} after the reload, the drain timeout is 30 s",
        usr2_at.elapsed()
    );

    // Clients that reconnect reach the successor: the blocked one gets the maintenance page.
    assert!(matches!(
        ws_open(proxy, "/chat").await.err(),
        Some(WsError::Handshake(_))
    ));
    let again = ws_open(proxy, "/safe/room").await.unwrap();
    ws_echoes(&again).await;

    let t = Instant::now();
    while first.try_wait().unwrap().is_none() {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "the predecessor exits once its sessions are closed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &pid2.to_string()])
        .status();
    let t = Instant::now();
    while alive(pid2) {
        assert!(t.elapsed() < Duration::from_secs(35), "successor stops");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
