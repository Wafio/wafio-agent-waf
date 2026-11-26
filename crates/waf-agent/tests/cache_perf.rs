//! A measurement of the response cache, run by hand: the real agent binary behind a load generator and
//! in front of an upstream, with the cache off, with copies served from memory and with copies served
//! from disk (memory 0). It says how many requests a second the agent answers, how much CPU it spends
//! on one, the latency, and how many requests the upstream saw. It asserts only what is not a matter
//! of speed: a key is asked of the upstream once while the cache is on.
//!
//! ```text
//! cargo test --release --features test-tls,test-response-cache --test cache_perf -- --ignored --nocapture
//! ```
//!
//! The L7 flood limit and the block policy are off in the bundle, as a single address would trip them.
//! `WAFIO_PERF_AGENT_CPUS` (for example `2,3`) pins the agent with `taskset`; run the test itself
//! under `taskset` on other cores. `WAFIO_PERF_BODY` is the size of an answer in bytes (default
//! 4096), `WAFIO_PERF_STEP_SECS` the length of each step (default 6), `WAFIO_PERF_ROUNDS` the rounds
//! (default 2; every round runs each variant once, the order reversed in the next one).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};
use wafio_proto::v1::agent_control_server::{AgentControl, AgentControlServer};
use wafio_proto::v1::agent_message::Kind as Out;
use wafio_proto::v1::server_message::Kind as In;
use wafio_proto::v1::*;

const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../control/tests/fixtures");
const KEYS: usize = 64;

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(FX).join(name)).unwrap()
}

fn env_number(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Conn {
    inbound: Streaming<AgentMessage>,
    out: mpsc::Sender<Result<ServerMessage, Status>>,
}

impl Conn {
    async fn next(&mut self) -> AgentMessage {
        tokio::time::timeout(Duration::from_secs(60), self.inbound.message())
            .await
            .expect("agent message")
            .unwrap()
            .expect("stream open")
    }
}

struct Fake {
    conns: mpsc::UnboundedSender<Conn>,
}

#[tonic::codegen::async_trait]
impl AgentControl for Fake {
    type StreamStream = ReceiverStream<Result<ServerMessage, Status>>;
    async fn stream(
        &self,
        req: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        let (tx, rx) = mpsc::channel(16);
        tx.send(Ok(ServerMessage {
            kind: Some(In::Welcome(Welcome {
                agent_id: "agent-uuid".into(),
                server_time_unix: 1,
                heartbeat_seconds: 30,
            })),
        }))
        .await
        .unwrap();
        let _ = self.conns.send(Conn {
            inbound: req.into_inner(),
            out: tx,
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type DownloadMalwareDatabaseStream = tonic::codegen::tokio_stream::Iter<
        std::vec::IntoIter<Result<MalwareDatabaseChunk, Status>>,
    >;
    async fn download_malware_database(
        &self,
        _: Request<MalwareDatabaseRequest>,
    ) -> Result<Response<Self::DownloadMalwareDatabaseStream>, Status> {
        Err(Status::unavailable("no malware database in this test"))
    }
}

struct KillOnDrop(u32);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-KILL", &self.0.to_string()])
            .status();
    }
}

/// An upstream that answers `GET /p/<n>` with a page that may be kept ten minutes and `GET /c/<n>`
/// with one that sets a cookie, `body` bytes each, and counts the requests.
async fn upstream(body: usize) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let page = vec![b'x'; body];
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (seen, page) = (seen.clone(), page.clone());
            tokio::spawn(async move {
                stream.set_nodelay(true).unwrap();
                let mut reader = BufReader::new(stream);
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    loop {
                        let mut header = String::new();
                        if reader.read_line(&mut header).await.unwrap_or(0) == 0 {
                            return;
                        }
                        if header == "\r\n" {
                            break;
                        }
                    }
                    seen.fetch_add(1, Ordering::Relaxed);
                    let extra = if line.starts_with("GET /c/") {
                        "Set-Cookie: visit=1\r\n"
                    } else {
                        "Cache-Control: public, max-age=600\r\n"
                    };
                    let mut answer = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\n{extra}\r\n",
                        page.len()
                    )
                    .into_bytes();
                    answer.extend_from_slice(&page);
                    // One write, or the delayed acknowledgement of the client holds the body back.
                    if reader.get_mut().write_all(&answer).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, count)
}

/// CPU the process has used, in clock ticks (user and system).
fn cpu_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    // The command name is in parentheses and may hold spaces: the fields count from the last one.
    let rest = &stat[stat.rfind(')').unwrap() + 2..];
    let field = |n: usize| -> u64 { rest.split(' ').nth(n).unwrap().parse().unwrap() };
    field(11) + field(12)
}

#[derive(Default)]
struct Step {
    requests: u64,
    seconds: f64,
    cpu_us: f64,
    p50_us: u64,
    p99_us: u64,
    upstream: usize,
}

/// `c` keep-alive clients ask for `/<prefix>/<n>` in turn for `secs` seconds.
async fn drive(port: u16, prefix: &'static str, c: usize, secs: u64) -> (u64, Vec<u64>) {
    let stop = Instant::now() + Duration::from_secs(secs);
    let next = Arc::new(AtomicU64::new(0));
    let tasks: Vec<_> = (0..c)
        .map(|_| {
            let next = next.clone();
            tokio::spawn(async move {
                let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                stream.set_nodelay(true).unwrap();
                let mut latencies = Vec::new();
                let mut buf = vec![0u8; 1 << 17];
                while Instant::now() < stop {
                    let n = next.fetch_add(1, Ordering::Relaxed) % KEYS as u64;
                    let started = Instant::now();
                    let request = format!("GET /{prefix}/{n} HTTP/1.1\r\nHost: app.test\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n");
                    stream.write_all(request.as_bytes()).await.unwrap();
                    // The head, then the body by its length.
                    let (mut filled, mut head_end) = (0, None);
                    while head_end.is_none() {
                        let read = stream.read(&mut buf[filled..]).await.unwrap();
                        assert!(read > 0, "the agent closed the connection");
                        filled += read;
                        head_end = buf[..filled].windows(4).position(|w| w == b"\r\n\r\n");
                    }
                    let head_end = head_end.unwrap() + 4;
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    assert!(head.starts_with("http/1.1 200"), "{head}");
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    while filled < head_end + length {
                        let read = stream.read(&mut buf[filled..]).await.unwrap();
                        assert!(read > 0);
                        filled += read;
                    }
                    latencies.push(started.elapsed().as_micros() as u64);
                }
                latencies
            })
        })
        .collect();
    let mut all = Vec::new();
    for t in tasks {
        all.extend(t.await.unwrap());
    }
    (all.len() as u64, all)
}

async fn step(
    pid: u32,
    port: u16,
    seen: &AtomicUsize,
    prefix: &'static str,
    c: usize,
    secs: u64,
) -> Step {
    // A second to fill the copies and settle the connections, not counted.
    drive(port, prefix, c, 1).await;
    let (before, up_before, t0) = (cpu_ticks(pid), seen.load(Ordering::Relaxed), Instant::now());
    let (requests, mut latencies) = drive(port, prefix, c, secs).await;
    let seconds = t0.elapsed().as_secs_f64();
    let ticks = cpu_ticks(pid) - before;
    latencies.sort_unstable();
    let at = |p: f64| latencies[((latencies.len() as f64 * p) as usize).min(latencies.len() - 1)];
    Step {
        requests,
        seconds,
        // 100 clock ticks a second.
        cpu_us: ticks as f64 * 10_000.0 / requests.max(1) as f64,
        p50_us: at(0.50),
        p99_us: at(0.99),
        upstream: seen.load(Ordering::Relaxed) - up_before,
    }
}

fn cache_part(variant: &str) -> String {
    match variant {
        "off" => String::new(),
        "memory" => {
            r#","cache":{"enabled":true,"disk_bytes":268435456,"memory_bytes":134217728}"#.into()
        }
        "disk" => r#","cache":{"enabled":true,"disk_bytes":268435456,"memory_bytes":0}"#.into(),
        other => panic!("{other}"),
    }
}

fn agent(dir: &Path, cp: &str, notify: &Path) -> Command {
    let data = dir.join("data.txt");
    let d = data.to_str().unwrap();
    let bin = env!("CARGO_BIN_EXE_wafio-waf-agent-open");
    let mut cmd = match std::env::var("WAFIO_PERF_AGENT_CPUS") {
        Ok(cpus) if !cpus.is_empty() => {
            let mut c = Command::new("taskset");
            c.args(["-c", &cpus, bin]);
            c
        }
        _ => Command::new(bin),
    };
    let cache = dir.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    cmd.args(["--grpc-server", cp, "--agent-name", "perf"])
        .env("WAFIO_HOST_KEY", "wafh_test")
        .env("WAFIO_TEST_GOODBOT_SOURCES", "")
        .args([
            "--client-cert",
            &format!("{FX}/client.crt"),
            "--client-key",
            &format!("{FX}/client.key"),
            "--ca-cert",
            &format!("{FX}/ca.crt"),
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
            "--iprep-level1-file",
            d,
            "--iprep-level2-file",
            d,
            "--jail-threshold",
            "0",
            "--security-data-dir",
            dir.to_str().unwrap(),
            "--state-dir",
        ])
        .arg(dir.join("state"))
        .env("NOTIFY_SOCKET", notify)
        .env("RUNTIME_DIRECTORY", dir)
        .env("WAFIO_TEST_TLS_DIR", dir.join("tls"))
        .env("WAFIO_TEST_CACHE_DIR", &cache)
        .env("WAFIO_ENGINE_LIB", dir.join("no-engine.so"))
        .stderr(Stdio::from(
            std::fs::File::create(dir.join("agent.log")).unwrap(),
        ));
    cmd
}

fn print(variant: &str, what: &str, c: usize, s: &Step) {
    eprintln!(
        "{variant:<7} {what:<7} c={c:<3} {:>9.0} req/s  {:>7.1} us cpu/req  p50 {:>6} us  p99 {:>7} us  upstream {}",
        s.requests as f64 / s.seconds,
        s.cpu_us,
        s.p50_us,
        s.p99_us,
        s.upstream
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, run by hand"]
async fn what_the_cache_costs_and_saves_per_request() {
    let body = env_number("WAFIO_PERF_BODY", 4096) as usize;
    let secs = env_number("WAFIO_PERF_STEP_SECS", 6);
    let rounds = env_number("WAFIO_PERF_ROUNDS", 2);
    let dir: PathBuf = std::env::temp_dir().join(format!("wafio-perf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    std::fs::write(dir.join("data.txt"), "x\n").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cp = listener.local_addr().unwrap().to_string();
    let (tx, mut conns) = mpsc::unbounded_channel();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(fx("server.crt"), fx("server.key")))
        .client_ca_root(Certificate::from_pem(fx("ca.crt")));
    tokio::spawn(
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(AgentControlServer::new(Fake { conns: tx }))
            .serve_with_incoming(TcpIncoming::from(listener)),
    );
    let notify_path = dir.join("notify.sock");
    let _notify = std::os::unix::net::UnixDatagram::bind(&notify_path).unwrap();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (up_port, seen) = upstream(body).await;
    let mut child = agent(&dir, &cp, &notify_path).spawn().unwrap();
    let _stop = KillOnDrop(child.id());
    let pid = child.id();
    // The start probe, then the stream the bundles go on.
    let mut probe = tokio::time::timeout(Duration::from_secs(60), conns.recv())
        .await
        .unwrap()
        .unwrap();
    let _ = probe.next().await;
    let mut stream = tokio::time::timeout(Duration::from_secs(60), conns.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(Out::Hello(_)) = stream.next().await.kind else {
        panic!("no Hello")
    };
    // Every decision the agent reports is read and dropped, so the stream never holds it back; the
    // acks of the bundles are kept.
    let Conn { mut inbound, out } = stream;
    let (ack_tx, mut acks) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok(Some(message)) = inbound.message().await {
            if let Some(Out::Ack(ack)) = message.kind {
                let _ = ack_tx.send(ack);
            }
        }
    });

    let mut generation = 0;
    let mut apply = |variant: &str| {
        generation += 1;
        let bundle = format!(
            r#"{{"agent_id":"perf","project_id":"p","generation":{generation},"apps":[{{"app_id":"web","listen_host":"127.0.0.1","listen_port":{port},"upstream":"http://127.0.0.1:{up_port}","mode":"block","rules_json":{{"l7_flood":{{"enabled":false}},"block_policy":{{"enabled":false}}}}{}}}]}}"#,
            cache_part(variant)
        );
        (
            generation,
            ServerMessage {
                kind: Some(In::Bundle(BundleUpdate {
                    command_id: format!("b{generation}"),
                    generation,
                    bundle_json: bundle.into_bytes(),
                })),
            },
        )
    };

    let order = ["off", "memory", "disk"];
    let mut summary: Vec<(String, &'static str, usize, Step)> = Vec::new();
    for round in 0..rounds {
        let mut variants: Vec<&str> = order.to_vec();
        if round % 2 == 1 {
            variants.reverse();
        }
        for variant in variants {
            let (generation, message) = apply(variant);
            out.send(Ok(message)).await.unwrap();
            loop {
                let a = tokio::time::timeout(Duration::from_secs(60), acks.recv())
                    .await
                    .expect("an ack")
                    .expect("stream open");
                if a.command_id == format!("b{generation}") {
                    assert!(a.ok, "{}", a.error);
                    break;
                }
            }
            // The cache is ready to store a moment after the bundle.
            tokio::time::sleep(Duration::from_millis(1500)).await;
            eprintln!("round {} {variant}", round + 1);
            for c in [1usize, 8, 32] {
                let before = seen.load(Ordering::Relaxed);
                let s = step(pid, port, &seen, "p", c, secs).await;
                print(variant, "pages", c, &s);
                if variant != "off" && c == 1 {
                    // A key is asked of the upstream once while the cache is on, however many
                    // clients and steps follow.
                    let total = seen.load(Ordering::Relaxed) - before;
                    assert!(
                        total <= KEYS * 2,
                        "{variant}: {total} requests for {KEYS} keys"
                    );
                }
                summary.push((variant.to_owned(), "pages", c, s));
            }
            // A page that sets a cookie is never kept: the cache must add no latency to it.
            let s = step(pid, port, &seen, "c", 32, secs).await;
            print(variant, "cookie", 32, &s);
            summary.push((variant.to_owned(), "cookie", 32, s));
        }
    }
    eprintln!("\nbody {body} bytes, {rounds} rounds, steps of {secs} s, {KEYS} keys");
    eprintln!("median of the rounds:");
    for what in ["pages", "cookie"] {
        for c in [1usize, 8, 32] {
            for variant in order {
                let mut rows: Vec<&Step> = summary
                    .iter()
                    .filter(|(v, w, cc, _)| v == variant && *w == what && *cc == c)
                    .map(|(_, _, _, s)| s)
                    .collect();
                if rows.is_empty() {
                    continue;
                }
                let mut median = |f: &dyn Fn(&Step) -> f64| {
                    rows.sort_by(|a, b| f(a).partial_cmp(&f(b)).unwrap());
                    f(rows[rows.len() / 2])
                };
                eprintln!(
                    "{variant:<7} {what:<7} c={c:<3} {:>9.0} req/s  {:>7.1} us cpu/req  p50 {:>6.0} us  p99 {:>7.0} us",
                    median(&|s| s.requests as f64 / s.seconds),
                    median(&|s| s.cpu_us),
                    median(&|s| s.p50_us as f64),
                    median(&|s| s.p99_us as f64),
                );
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::io::stderr().flush();
    let _ = std::fs::remove_dir_all(&dir);
}
