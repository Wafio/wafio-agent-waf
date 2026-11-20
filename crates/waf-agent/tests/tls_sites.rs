//! The real binary started with `--tls-sites-file`: an app served over HTTPS, which opens no
//! plain listener of its own, the redirect listener, a reload while connections are open, a
//! settings file that stops the start, and an agent without the flag. The control plane is
//! unreachable and the app comes from the bundle cache, as in `operations.rs`. Keys are made by
//! `openssl` at test time into a scratch directory that is removed when the test ends.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use pingora::tls::{
    CertificateDer, ClientConfig, ClientTlsStream, RootCertStore, ServerName, TlsConnector,
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../control/tests/fixtures");
const HOST: &str = "shop.test";

/// `N` free ports, all held until every one is chosen so that two of them cannot be the same.
fn free_ports<const N: usize>() -> [u16; N] {
    let held: Vec<TcpListener> = (0..N)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let mut ports = [0; N];
    for (port, listener) in ports.iter_mut().zip(&held) {
        *port = listener.local_addr().unwrap().port();
    }
    ports
}

/// An HTTP/1.1 upstream that answers `200 ok` and keeps every request head it is sent. A request
/// for `/slow` is held until `release`.
struct Upstream {
    port: u16,
    heads: Arc<Mutex<Vec<String>>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
}

impl Upstream {
    fn start() -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let heads: Arc<Mutex<Vec<String>>> = Arc::default();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (seen, held) = (heads.clone(), gate.clone());
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let (seen, held) = (seen.clone(), held.clone());
                std::thread::spawn(move || answer_requests(conn, &seen, &held));
            }
        });
        Upstream { port, heads, gate }
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }

    fn release(&self) {
        *self.gate.0.lock().unwrap() = true;
        self.gate.1.notify_all();
    }
}

fn answer_requests(
    mut conn: std::net::TcpStream,
    seen: &Mutex<Vec<String>>,
    gate: &(Mutex<bool>, Condvar),
) {
    use std::io::{Read, Write};
    let mut buf = [0u8; 4096];
    let mut pending = Vec::new();
    while let Ok(n) = conn.read(&mut buf) {
        if n == 0 {
            return;
        }
        pending.extend_from_slice(&buf[..n]);
        while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&pending[..end]).into_owned();
            pending.drain(..end + 4);
            let slow = head.starts_with("GET /slow ");
            seen.lock().unwrap().push(head);
            if slow {
                let open = gate.0.lock().unwrap();
                let _ = gate
                    .1
                    .wait_timeout_while(open, Duration::from_secs(60), |open| !*open);
            }
            if conn
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .is_err()
            {
                return;
            }
        }
    }
}

fn openssl(args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl is installed");
    assert!(out.status.success(), "openssl {} failed", args[0]);
}

/// A certificate authority and a certificate for `HOST` that it signs, in `dir`. Returns the
/// certificate file, the key file and the authority's certificate in DER form.
fn make_pki(dir: &Path) -> (PathBuf, PathBuf, Vec<u8>) {
    let path = |name: &str| dir.join(name).to_str().unwrap().to_owned();
    let (ca_key, ca_crt) = (path("ca.key"), path("ca.crt"));
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-keyout",
        &ca_key,
        "-out",
        &ca_crt,
    ]);
    let (key, csr, ext, crt) = (
        path("shop.key"),
        path("shop.csr"),
        path("shop.ext"),
        path("shop.crt"),
    );
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-subj",
        &format!("/CN={HOST}"),
        "-keyout",
        &key,
        "-out",
        &csr,
    ]);
    fs::write(
        &ext,
        format!("subjectAltName=DNS:{HOST}\nbasicConstraints=CA:FALSE\n"),
    )
    .unwrap();
    openssl(&[
        "x509",
        "-req",
        "-in",
        &csr,
        "-CA",
        &ca_crt,
        "-CAkey",
        &ca_key,
        "-CAcreateserial",
        "-days",
        "2",
        "-extfile",
        &ext,
        "-out",
        &crt,
    ]);
    let der = Command::new("openssl")
        .args(["x509", "-in", &ca_crt, "-outform", "DER"])
        .output()
        .expect("openssl is installed")
        .stdout;
    (crt.into(), key.into(), der)
}

/// A client that trusts the test authority and offers `http/1.1`.
fn client_config(authority: Vec<u8>) -> Arc<ClientConfig> {
    pingora::tls::install_default_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(authority)).unwrap();
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        let found = self
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name));
        found.map(|(_, v)| v.as_str())
    }
}

async fn read_reply<R: AsyncBufRead + Unpin>(r: &mut R) -> io::Result<Reply> {
    let eof = || io::Error::from(io::ErrorKind::UnexpectedEof);
    let mut line = String::new();
    if r.read_line(&mut line).await? == 0 {
        return Err(eof());
    }
    let status = line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("status line {line:?}"))
        })?;
    let mut headers = Vec::new();
    loop {
        line.clear();
        if r.read_line(&mut line).await? == 0 {
            return Err(eof());
        }
        let text = line.trim_end();
        if text.is_empty() {
            break;
        }
        if let Some((name, value)) = text.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok());
    let mut body = Vec::new();
    match length {
        Some(n) => {
            body.resize(n, 0);
            r.read_exact(&mut body).await?;
        }
        // The body runs to the end of the connection, however that end comes.
        None => {
            let _ = r.read_to_end(&mut body).await;
        }
    }
    Ok(Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn timed_out() -> io::Error {
    io::Error::from(io::ErrorKind::TimedOut)
}

/// A keep-alive HTTPS client connection.
struct Https(BufReader<ClientTlsStream<TcpStream>>);

impl Https {
    async fn connect(port: u16, config: &Arc<ClientConfig>, sni: &str) -> io::Result<Https> {
        let handshake = async {
            let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
            let name = ServerName::try_from(sni.to_owned()).unwrap();
            TlsConnector::from(config.clone()).connect(name, tcp).await
        };
        let tls = tokio::time::timeout(Duration::from_secs(20), handshake)
            .await
            .map_err(|_| timed_out())??;
        Ok(Https(BufReader::new(tls)))
    }

    async fn write(&mut self, raw: &[u8]) -> io::Result<()> {
        self.0.get_mut().write_all(raw).await
    }

    async fn read(&mut self) -> io::Result<Reply> {
        tokio::time::timeout(Duration::from_secs(30), read_reply(&mut self.0))
            .await
            .map_err(|_| timed_out())?
    }

    async fn send(&mut self, raw: &[u8]) -> io::Result<Reply> {
        self.write(raw).await?;
        self.read().await
    }

    fn alpn(&self) -> Option<Vec<u8>> {
        let (_, session) = self.0.get_ref().get_ref();
        session.alpn_protocol().map(<[u8]>::to_vec)
    }
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {HOST}\r\n\r\n").into_bytes()
}

/// One request over plain HTTP that asks the server to close afterwards.
async fn plain(port: u16, host: &str, path: &str) -> io::Result<Reply> {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tcp.write_all(request.as_bytes()).await?;
    tokio::time::timeout(
        Duration::from_secs(20),
        read_reply(&mut BufReader::new(tcp)),
    )
    .await
    .map_err(|_| timed_out())?
}

/// The TCP ports `pid` listens on: its socket inodes looked up in the kernel's tables.
fn listening_ports(pid: u32) -> BTreeSet<u16> {
    let inodes: BTreeSet<String> = fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .flatten()
        .filter_map(|fd| {
            let target = fs::read_link(fd.path()).ok()?;
            let inode = target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?;
            Some(inode.to_owned())
        })
        .collect();
    let mut ports = BTreeSet::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        for line in fs::read_to_string(table)
            .unwrap_or_default()
            .lines()
            .skip(1)
        {
            let columns: Vec<&str> = line.split_whitespace().collect();
            // Column 3 is the state (0A is LISTEN), column 9 the socket inode.
            if columns.len() > 9 && columns[3] == "0A" && inodes.contains(columns[9]) {
                let (_, port) = columns[1].rsplit_once(':').unwrap();
                ports.insert(u16::from_str_radix(port, 16).unwrap());
            }
        }
    }
    ports
}

fn signal(pid: u32, sig: &str) {
    let status = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

fn alive(pid: u32) -> bool {
    !fs::read_to_string(format!("/proc/{pid}/stat"))
        .unwrap_or_default()
        .contains(") Z ")
        && Path::new(&format!("/proc/{pid}")).exists()
}

fn ready_message(sock: &UnixDatagram, timeout: Duration) -> String {
    sock.set_read_timeout(Some(timeout)).unwrap();
    let mut buf = [0u8; 256];
    let n = sock.recv(&mut buf).expect("no READY within the timeout");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

async fn until(what: &str, mut ready: impl FnMut() -> bool) {
    for _ in 0..200 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}: not seen within ten seconds");
}

async fn exit_of(child: &mut Child, timeout: Duration) -> ExitStatus {
    let end = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < end, "process {} still runs", child.id());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A scratch directory with an app, its upstream, the certificate for its host and the bundle
/// cache the agent starts from. Removed when dropped, and the agent log is printed first when the
/// test is failing.
struct Setup {
    dir: PathBuf,
    upstream: Upstream,
    client: Arc<ClientConfig>,
    certificate: PathBuf,
    key: PathBuf,
    plain: u16,
    https: u16,
    redirect: u16,
}

impl Setup {
    fn new(tag: &str) -> Setup {
        let dir =
            std::env::temp_dir().join(format!("wafio-tls-sites-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("state")).unwrap();
        fs::write(dir.join("data.txt"), "x\n").unwrap();
        let (certificate, key, authority) = make_pki(&dir);
        let upstream = Upstream::start();
        let [plain, https, redirect] = free_ports();
        let bundle = format!(
            r#"{{"agent_id":"tls","project_id":"p","apps":[{{"app_id":"shop","listen_host":"127.0.0.1","listen_port":{plain},"upstream":"http://127.0.0.1:{}","mode":"block"}}]}}"#,
            upstream.port
        );
        wafio_control::save_bundle_cache(
            &dir.join("state"),
            bundle.as_bytes(),
            7,
            SystemTime::now(),
        )
        .unwrap();
        let setup = Setup {
            dir,
            upstream,
            client: client_config(authority),
            certificate,
            key,
            plain,
            https,
            redirect,
        };
        fs::write(setup.sites_file(), setup.sites().to_string()).unwrap();
        setup
    }

    fn sites_file(&self) -> PathBuf {
        self.dir.join("tls-sites.json")
    }

    fn log(&self) -> PathBuf {
        self.dir.join("agent.log")
    }

    /// The settings of the file: the app of the bundle also served over HTTPS and redirected from
    /// its own plain address.
    fn sites(&self) -> serde_json::Value {
        serde_json::json!({"apps": {"shop": {
            "tls": true,
            "listen": format!("127.0.0.1:{}", self.https),
            "hosts": [HOST],
            "certificate": self.certificate,
            "key": self.key,
            "redirect_listen": format!("127.0.0.1:{}", self.redirect),
        }}})
    }

    /// The agent with every flag but the sites file, no engine and no good-bot lookups.
    fn command(&self) -> Command {
        let data = self.dir.join("data.txt");
        let d = data.to_str().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_wafio-waf-agent-open"));
        cmd.args(["--grpc-server", "127.0.0.1:1", "--agent-name", "tls-sites"])
            .args([
                "--client-cert",
                &format!("{FIXTURES}/client.crt"),
                "--client-key",
                &format!("{FIXTURES}/client.key"),
                "--ca-cert",
                &format!("{FIXTURES}/ca.crt"),
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
            .args(["--iprep-level1-file", d, "--iprep-level2-file", d])
            .args(["--jail-threshold", "0"])
            .args(["--state-dir", self.dir.join("state").to_str().unwrap()])
            .env("RUNTIME_DIRECTORY", &self.dir)
            // A library installed on this host must not give the agent an engine.
            .env("WAFIO_ENGINE_LIB", self.dir.join("no-engine.so"))
            .env("WAFIO_TEST_GOODBOT_SOURCES", "")
            .env_remove("WAFIO_TLS_SITES_FILE")
            .env_remove("WAFIO_METRICS_ADDR")
            .env_remove("NOTIFY_SOCKET")
            .stdout(Stdio::null());
        cmd
    }

    /// Runs the agent with `file` as its sites file until it exits: the exit code and what it
    /// wrote to stderr. An agent that keeps running fails the test.
    fn exit_with(&self, file: &Path) -> (Option<i32>, String) {
        let log = self.dir.join("exit.log");
        let mut child = self
            .command()
            .arg("--tls-sites-file")
            .arg(file)
            .stderr(Stdio::from(fs::File::create(&log).unwrap()))
            .spawn()
            .unwrap();
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return (status.code(), fs::read_to_string(&log).unwrap_or_default());
            }
            if Instant::now() > end {
                let _ = child.kill();
                let _ = child.wait();
                let text = fs::read_to_string(&log).unwrap_or_default();
                panic!("the agent kept running with a sites file it cannot use:\n{text}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Ok(log) = fs::read_to_string(self.log())
        {
            eprintln!("agent log:\n{log}");
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A running agent: its processes are killed when it is dropped.
struct Agent {
    first: u32,
    /// The scratch directory, which every process of this agent has in its arguments.
    dir: PathBuf,
    child: Option<Child>,
    notify: UnixDatagram,
}

impl Agent {
    /// Starts the agent, with the sites file when `flag` is set, and waits for READY.
    fn start(setup: &Setup, flag: bool) -> Agent {
        let notify_path = setup.dir.join("notify.sock");
        let notify = UnixDatagram::bind(&notify_path).unwrap();
        let mut cmd = setup.command();
        if flag {
            cmd.arg("--tls-sites-file").arg(setup.sites_file());
        }
        let child = cmd
            .env("NOTIFY_SOCKET", &notify_path)
            .stderr(Stdio::from(fs::File::create(setup.log()).unwrap()))
            .spawn()
            .unwrap();
        let first = child.id();
        let agent = Agent {
            first,
            dir: setup.dir.clone(),
            child: Some(child),
            notify,
        };
        let message = ready_message(&agent.notify, Duration::from_secs(60));
        assert_eq!(message, format!("READY=1\nMAINPID={first}\n"));
        agent
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        // By arguments, so a reload's successor goes too when the test failed before it was known.
        let _ = Command::new("pkill")
            .args(["-9", "-f"])
            .arg(&self.dir)
            .status();
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[tokio::test]
async fn an_app_named_in_the_sites_file_is_served_over_https_and_opens_no_plain_listener() {
    let s = Setup::new("https");
    let agent = Agent::start(&s, true);
    assert_eq!(
        listening_ports(agent.first),
        BTreeSet::from([s.https, s.redirect])
    );
    assert!(TcpStream::connect(("127.0.0.1", s.plain)).await.is_err());

    let mut client = Https::connect(s.https, &s.client, HOST).await.unwrap();
    assert_eq!(client.alpn().as_deref(), Some(&b"http/1.1"[..]));
    for _ in 0..2 {
        let r = client.send(&get("/cart?a=1")).await.unwrap();
        assert_eq!((r.status, r.body.as_str()), (200, "ok"));
    }
    let heads = s.upstream.heads();
    assert_eq!(heads.len(), 2, "{heads:?}");
    assert!(
        heads[0].starts_with("GET /cart?a=1 HTTP/1.1"),
        "{}",
        heads[0]
    );
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("x-forwarded-proto: https"),
        "the upstream is told the request came over HTTPS: {}",
        heads[0]
    );
}

#[tokio::test]
async fn the_redirect_listener_answers_308_to_the_https_address_and_proxies_nothing() {
    let s = Setup::new("redirect");
    let _agent = Agent::start(&s, true);

    let host = format!("{HOST}:{}", s.redirect);
    let r = plain(s.redirect, &host, "/cart?a=1").await.unwrap();
    assert_eq!(r.status, 308);
    assert_eq!(
        r.header("location"),
        Some(format!("https://{HOST}:{}/cart?a=1", s.https).as_str())
    );
    let r = plain(s.redirect, "other.test", "/").await.unwrap();
    assert_eq!(r.status, 404);
    assert!(s.upstream.heads().is_empty());
}

/// Connects, asks for `/probe` and closes, over and over, and reports how many tries were made and
/// how each failed try failed.
async fn probe_until(
    port: u16,
    config: Arc<ClientConfig>,
    stop: Arc<AtomicBool>,
) -> (usize, Vec<String>) {
    let (mut tries, mut failures) = (0, Vec::new());
    while !stop.load(Ordering::Relaxed) {
        tries += 1;
        let request = b"GET /probe HTTP/1.1\r\nHost: shop.test\r\nConnection: close\r\n\r\n";
        let outcome = async {
            let mut client = Https::connect(port, &config, HOST).await?;
            let r = client.send(request).await?;
            match (r.status, r.body.as_str()) {
                (200, "ok") => Ok(()),
                _ => Err(io::Error::other(format!("status {}", r.status))),
            }
        };
        if let Err(e) = outcome.await {
            failures.push(e.to_string());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (tries, failures)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_reload_hands_over_the_https_listeners_without_a_refused_connection_and_finishes_the_request_in_flight()
 {
    let s = Setup::new("reload");
    let mut agent = Agent::start(&s, true);
    let first = agent.first;

    let mut idle = Https::connect(s.https, &s.client, HOST).await.unwrap();
    assert_eq!(idle.send(&get("/idle")).await.unwrap().status, 200);
    let mut busy = Https::connect(s.https, &s.client, HOST).await.unwrap();
    busy.write(&get("/slow")).await.unwrap();
    until("the slow request at the upstream", || {
        s.upstream
            .heads()
            .iter()
            .any(|h| h.starts_with("GET /slow "))
    })
    .await;

    signal(first, "-USR2");
    let stop = Arc::new(AtomicBool::new(false));
    let probe = tokio::spawn(probe_until(s.https, s.client.clone(), stop.clone()));
    let notify = agent.notify.try_clone().unwrap();
    let message =
        tokio::task::spawn_blocking(move || ready_message(&notify, Duration::from_secs(60)))
            .await
            .unwrap();
    let second: u32 = message
        .strip_prefix("READY=1\nMAINPID=")
        .and_then(|rest| rest.trim_end().parse().ok())
        .expect(&message);
    assert_ne!(second, first);
    // The predecessor learns of the successor a moment after the successor reports ready.
    until("the predecessor to start draining", || {
        let log = fs::read_to_string(s.log()).unwrap_or_default();
        log.contains("took over; draining")
    })
    .await;
    assert!(alive(first), "the predecessor drains the request in flight");

    s.upstream.release();
    let r = busy.read().await.unwrap();
    assert_eq!((r.status, r.body.as_str()), (200, "ok"));
    assert_eq!(r.header("connection"), Some("close"));
    // Well inside the 30 second drain grace: an idle connection must not hold the predecessor.
    let status = exit_of(agent.child.as_mut().unwrap(), Duration::from_secs(10)).await;
    assert!(status.success(), "predecessor exit: {status:?}");
    assert!(
        idle.send(&get("/after")).await.is_err(),
        "a connection that is idle when the predecessor drains is closed"
    );

    let mut fresh = Https::connect(s.https, &s.client, HOST).await.unwrap();
    let r = fresh.send(&get("/fresh")).await.unwrap();
    assert_eq!((r.status, r.body.as_str()), (200, "ok"));
    let r = plain(s.redirect, HOST, "/").await.unwrap();
    assert_eq!(r.status, 308);
    assert_eq!(
        listening_ports(second),
        BTreeSet::from([s.https, s.redirect]),
        "the successor holds both sockets"
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    stop.store(true, Ordering::Relaxed);
    let (tries, failures) = probe.await.unwrap();
    assert!(
        tries >= 20,
        "the probe ran across the handover: {tries} tries"
    );
    assert!(
        failures.is_empty(),
        "{} of {tries} tries failed: {failures:?}",
        failures.len()
    );
}

#[test]
fn a_sites_file_that_cannot_be_used_stops_the_start_and_says_why_without_key_material() {
    let s = Setup::new("bad-file");
    let key_text = fs::read_to_string(&s.key).unwrap();
    // A line of the key's own body: if the message holds this, it holds the key.
    let key_body = key_text.lines().nth(1).unwrap().to_owned();
    let file = s.dir.join("bad-sites.json");
    let with = |change: &dyn Fn(&mut serde_json::Value)| {
        let mut sites = s.sites();
        change(&mut sites["apps"]["shop"]);
        sites.to_string()
    };
    let missing = s.dir.join("missing.crt");
    let cases = [
        (
            "not JSON",
            r#"{"apps": {"#.to_owned(),
            vec!["EOF while parsing".to_owned()],
        ),
        (
            "a wildcard host",
            with(&|app| app["hosts"] = serde_json::json!(["*.shop.test"])),
            vec!["app shop".to_owned(), "wildcard".to_owned()],
        ),
        (
            "a certificate file that is not there",
            with(&|app| app["certificate"] = missing.to_str().unwrap().into()),
            vec![
                "app shop".to_owned(),
                missing.to_str().unwrap().to_owned(),
                "cannot read".to_owned(),
            ],
        ),
        (
            "the key written into the file in place of its name",
            with(&|app| app["key"] = key_text.clone().into()),
            vec![
                "app shop".to_owned(),
                "key must be the name of a file".to_owned(),
            ],
        ),
    ];
    for (what, content, expected) in cases {
        fs::write(&file, content).unwrap();
        let (code, stderr) = s.exit_with(&file);
        assert_eq!(code, Some(1), "{what}: {stderr}");
        let line = stderr
            .lines()
            .find(|l| l.starts_with("wafio-waf-agent: "))
            .unwrap_or_else(|| panic!("{what}: no message from the agent: {stderr}"));
        assert!(
            line.contains(&format!("--tls-sites-file {}", file.display())),
            "{what}: {line}"
        );
        for part in expected {
            assert!(line.contains(&part), "{what}: {part:?} not in {line}");
        }
        assert!(
            !stderr.contains(&key_body) && !stderr.contains("PRIVATE KEY"),
            "{what}: key material in the output: {stderr}"
        );
    }
}

#[tokio::test]
async fn an_agent_started_without_the_flag_opens_only_the_listener_its_bundle_names() {
    let s = Setup::new("no-flag");
    let agent = Agent::start(&s, false);
    assert_eq!(listening_ports(agent.first), BTreeSet::from([s.plain]));
    for port in [s.https, s.redirect] {
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }
    let r = plain(s.plain, HOST, "/").await.unwrap();
    assert_eq!((r.status, r.body.as_str()), (200, "ok"));
}
