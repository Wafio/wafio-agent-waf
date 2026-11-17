//! Operations with the real binary: start from the bundle cache while the control plane is
//! unreachable, `READY=1` only once the cached bundle's listener serves, PID file, the request
//! proxied, the metrics listener, SIGUSR2 handover to a successor (new MAINPID, same socket, old
//! process exits) and SIGTERM. Everything listens on 127.0.0.1 and lives for seconds.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A one-thread HTTP upstream answering every request `200 ok` (Content-Length, keep-alive).
fn upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        return;
                    }
                    seen.extend_from_slice(&buf[..n]);
                    while let Some(i) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                        seen.drain(..i + 4);
                        if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            });
        }
    });
    port
}

/// A fake Googlebot range source: one IPv4 and one IPv6 prefix for every request.
fn bot_source() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let body = r#"{"prefixes":[{"ipv4Prefix":"66.249.64.0/27"},{"ipv6Prefix":"2001:4860:4801::/48"}]}"#;
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    port
}

fn get(port: u16, path: &str) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

fn ready_message(sock: &UnixDatagram, timeout: Duration) -> String {
    sock.set_read_timeout(Some(timeout)).unwrap();
    let mut buf = [0u8; 256];
    let n = sock.recv(&mut buf).expect("no READY within the timeout");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn signal(pid: u32, sig: &str) {
    assert!(
        Command::new("kill")
            .args([sig, &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
        && !std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .unwrap_or_default()
            .contains(") Z ")
}

fn wait_gone(pid: u32, timeout: Duration) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if !alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

struct Kill(Vec<u32>, Option<Child>);

impl Drop for Kill {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = Command::new("kill").args(["-9", &p.to_string()]).status();
        }
        if let Some(c) = &mut self.1 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[test]
fn starts_from_cache_signals_ready_and_hands_over_on_sigusr2() {
    let dir: PathBuf = std::env::temp_dir().join(format!("wafio-ops-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let data = dir.join("data.txt");
    std::fs::write(&data, "x\n").unwrap();
    let (listen, up, metrics, bots) = (free_port(), upstream(), free_port(), bot_source());
    let bundle = format!(
        r#"{{"agent_id":"ops","project_id":"p","apps":[{{"app_id":"c","listen_host":"127.0.0.1","listen_port":{listen},"upstream":"http://127.0.0.1:{up}","mode":"block"}}]}}"#
    );
    wafio_control::save_bundle_cache(
        &dir.join("state"),
        bundle.as_bytes(),
        7,
        std::time::SystemTime::now(),
    )
    .unwrap();
    let notify_path = dir.join("notify.sock");
    let notify = UnixDatagram::bind(&notify_path).unwrap();
    let fx = concat!(env!("CARGO_MANIFEST_DIR"), "/../control/tests/fixtures");
    let pid_file = dir.join("agent.pid");
    let d = data.to_str().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_wafio-waf-agent-open"))
        .args(["--grpc-server", "127.0.0.1:1", "--agent-name", "ops"])
        .args([
            "--client-cert",
            &format!("{fx}/client.crt"),
            "--client-key",
            &format!("{fx}/client.key"),
            "--ca-cert",
            &format!("{fx}/ca.crt"),
        ])
        .args([
            "--geo-country-db",
            d,
            "--geo-city-db",
            d,
            "--geo-asn-db",
            d,
            "--bot-ua-file",
            d,
            "--bot-ja4-file",
            d,
        ])
        .args([
            "--crs-default-dir",
            "/etc/wafio/security-data/crs",
            "--jail-threshold",
            "0",
        ])
        .args(["--iprep-level1-file", d, "--iprep-level2-file", d])
        .args([
            "--state-dir",
            dir.join("state").to_str().unwrap(),
            "--pid-file",
            pid_file.to_str().unwrap(),
        ])
        .env("NOTIFY_SOCKET", &notify_path)
        .env("RUNTIME_DIRECTORY", &dir)
        .env("WAFIO_METRICS_ADDR", format!("127.0.0.1:{metrics}"))
        // A library installed on this host must not give the agent an engine: name one that does not exist.
        .env("WAFIO_ENGINE_LIB", dir.join("no-engine.so"))
        // The good-bot ranges come from the local fake, never from Google and Bing.
        .env(
            "WAFIO_TEST_GOODBOT_SOURCES",
            format!("Googlebot=http://127.0.0.1:{bots}/googlebot.json"),
        )
        .stderr(Stdio::from(
            std::fs::File::create(dir.join("agent.log")).unwrap(),
        ))
        .spawn()
        .unwrap();
    let first = child.id();
    let mut guard = Kill(vec![first], Some(child));

    // READY comes from the cached bundle, after its listener is up.
    let msg = ready_message(&notify, Duration::from_secs(60));
    assert_eq!(msg, format!("READY=1\nMAINPID={first}\n"));
    assert!(
        TcpStream::connect(("127.0.0.1", listen)).is_ok(),
        "READY before the listener served"
    );
    assert_eq!(
        std::fs::read_to_string(&pid_file).unwrap(),
        first.to_string()
    );
    let resp = get(listen, "/hello").expect("proxied request");
    assert!(
        resp.starts_with("HTTP/1.1 200") && resp.ends_with("ok"),
        "{resp}"
    );
    let end = Instant::now() + Duration::from_secs(20);
    while !std::fs::read_to_string(dir.join("agent.log"))
        .unwrap_or_default()
        .contains("[goodbot] loaded Googlebot: 1 IPv4 ranges")
    {
        assert!(
            Instant::now() < end,
            "good-bot ranges not loaded from the fake source: {}",
            std::fs::read_to_string(dir.join("agent.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let m = get(metrics, "/metrics").expect("metrics");
    assert!(m.contains("wafio_waf_control_plane_connected 0"), "{m}");
    assert!(!m.contains("wafio_waf_crs_"));
    assert!(!m.contains("wafio_waf_apps_without_rule_engine"));

    // SIGUSR2: a successor takes the sockets, reports READY with its own pid, the old one exits.
    signal(first, "-USR2");
    let msg = ready_message(&notify, Duration::from_secs(60));
    let second: u32 = msg
        .strip_prefix("READY=1\nMAINPID=")
        .and_then(|r| r.trim_end().parse().ok())
        .expect(&msg);
    guard.0.push(second);
    assert_ne!(second, first);
    let mut c = guard.1.take().unwrap();
    let status = c.wait().unwrap();
    assert!(status.success(), "predecessor exit: {status:?}");
    // Both processes write to the same log file (the successor inherits stderr).
    let err = std::fs::read_to_string(dir.join("agent.log")).unwrap();
    assert!(err.contains("starting from cached bundle"), "{err}");
    let warning = "are deprecated: using /etc/wafio/security-data as the security-data directory";
    assert!(
        err.contains(warning),
        "the old flag gets one warning: {err}"
    );
    assert_eq!(
        err.matches("are deprecated").count(),
        1,
        "the successor does not warn again: {err}"
    );
    assert!(
        err.contains("[tableflip] upgrade requested (SIGUSR2)"),
        "{err}"
    );
    assert_eq!(
        std::fs::read_to_string(&pid_file).unwrap(),
        second.to_string()
    );
    let resp = get(listen, "/after").expect("successor serves the inherited socket");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(
        get(metrics, "/metrics").is_some(),
        "metrics socket handed over"
    );

    // SIGTERM: drains and exits; the port is closed.
    signal(second, "-TERM");
    assert!(
        wait_gone(second, Duration::from_secs(40)),
        "successor did not exit on SIGTERM"
    );
    assert!(TcpStream::connect(("127.0.0.1", listen)).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn refuses_to_start_without_cache_or_control_plane() {
    let dir = std::env::temp_dir().join(format!("wafio-ops-nocache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let data = dir.join("data.txt");
    std::fs::write(&data, "x\n").unwrap();
    let d = data.to_str().unwrap();
    let fx = concat!(env!("CARGO_MANIFEST_DIR"), "/../control/tests/fixtures");
    let out = Command::new(env!("CARGO_BIN_EXE_wafio-waf-agent-open"))
        .args(["--grpc-server", "127.0.0.1:1", "--agent-name", "ops"])
        .args([
            "--client-cert",
            &format!("{fx}/client.crt"),
            "--client-key",
            &format!("{fx}/client.key"),
            "--ca-cert",
            &format!("{fx}/ca.crt"),
        ])
        .args([
            "--geo-country-db",
            d,
            "--geo-city-db",
            d,
            "--geo-asn-db",
            d,
            "--bot-ua-file",
            d,
            "--bot-ja4-file",
            d,
        ])
        .args(["--state-dir", dir.join("state").to_str().unwrap()])
        .env_remove("NOTIFY_SOCKET")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("wafio-waf-agent: initial handshake failed: "),
        "{err}"
    );

    let out = Command::new(env!("CARGO_BIN_EXE_wafio-waf-agent-open"))
        .args(["--agent-name", "x"])
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("wafio-waf-agent: missing required flag(s): --grpc-server, --client-cert")
    );

    let out = Command::new(env!("CARGO_BIN_EXE_wafio-waf-agent-open"))
        .args([
            "--grpc-server",
            "h:1",
            "--agent-name",
            "a",
            "--client-cert",
            d,
            "--client-key",
            d,
            "--ca-cert",
            d,
        ])
        .args([
            "--geo-country-db",
            d,
            "--geo-city-db",
            d,
            "--geo-asn-db",
            d,
            "--bot-ua-file",
            d,
            "--bot-ja4-file",
            d,
        ])
        .env_clear()
        .env("WAFIO_METRICS_ADDR", "0.0.0.0:9100")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(
            "WAFIO_METRICS_ADDR: address \"0.0.0.0:9100\": must bind a loopback IP literal"
        ),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A path in a fresh directory that holds no library: naming it keeps a library installed on this host out of the probe.
fn absent_library(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wafio-ops-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("no-engine.so")
}

/// `--features` of the open agent with a clean environment plus `env`.
fn features(env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wafio-waf-agent-open"));
    cmd.arg("--features").env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// `--features` is a hidden flag: the release script and operators read it, `--help` does not list it.
#[test]
fn features_names_the_engine_and_help_does_not_list_the_flag() {
    let lib = absent_library("features");
    let out = features(&[("WAFIO_ENGINE_LIB", lib.to_str().unwrap())]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("version: "), "{text}");
    assert!(text.lines().any(|l| l == "engine: none"), "{text}");
    let help = Command::new(env!("CARGO_BIN_EXE_wafio-waf-agent-open"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&help.stdout).contains("--features"));
    let _ = std::fs::remove_dir_all(lib.parent().unwrap());
}

/// A probe that names nothing looks at the default path, as a start does. Where nothing is installed there, it still
/// prints and exits 0, and says nothing on stderr: the report says `engine: none` itself.
#[test]
fn features_with_nothing_named_and_nothing_at_the_default_path_prints_none() {
    if Path::new(wafio_engine_loader::DEFAULT_LIBRARY_PATH).exists() {
        return;
    }
    let out = features(&[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("engine: none"));
    assert!(out.stderr.is_empty(), "{out:?}");
}

/// A required library that is absent stops a probe as it stops a start, and the line names the variable. Only a
/// successor of a reload has a process it replaces.
#[test]
fn features_with_a_required_library_that_is_absent_says_why_for_a_cold_start_and_for_a_successor() {
    let lib = absent_library("required");
    let named = ("WAFIO_ENGINE_LIB", lib.to_str().unwrap());
    let cold = features(&[named, ("WAFIO_ENGINE_LIB_REQUIRED", "1")]);
    assert_eq!(cold.status.code(), Some(1), "{cold:?}");
    let err = String::from_utf8_lossy(&cold.stderr);
    assert!(
        err.contains("WAFIO_ENGINE_LIB_REQUIRED=1 is set, so the agent does not start without it"),
        "{err}"
    );
    assert!(!err.contains("replaces"), "{err}");
    let successor = features(&[
        named,
        ("WAFIO_ENGINE_LIB_REQUIRED", "1"),
        ("WAFIO_UPGRADE_READY", "/nonexistent/ready.sock"),
    ]);
    assert_eq!(successor.status.code(), Some(1), "{successor:?}");
    let err = String::from_utf8_lossy(&successor.stderr);
    assert!(
        err.contains(
            "the process this one replaces runs with it, so this one does not start without it"
        ),
        "{err}"
    );
    assert!(!err.contains("WAFIO_ENGINE_LIB_REQUIRED"), "{err}");
    let _ = std::fs::remove_dir_all(lib.parent().unwrap());
}
