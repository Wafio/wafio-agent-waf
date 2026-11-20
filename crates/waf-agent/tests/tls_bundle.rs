//! The real binary with a key directory (`WAFIO_TEST_TLS_DIR`): an app whose bundle entry has a
//! `tls` object is served over HTTPS from a certificate file, with no plain listener of its own,
//! from a cached bundle with no control plane and from live bundles of a fake one. A reload hands
//! the sockets and the directory lock over while connections go on, a process that finds the lock
//! taken writes nothing in the directory until it is free, and an entry that fails a check refuses
//! the whole bundle. Keys are made by `openssl` at test time into a scratch directory that is
//! removed when the test ends.

use std::fs;
use std::io;
use std::net::TcpListener;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use nix::fcntl::{Flock, FlockArg};
use pingora::tls::{
    CertificateDer, ClientConfig, ClientTlsStream, RootCertStore, ServerName, TlsConnector,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};
use wafio_proto::v1::agent_control_server::{AgentControl, AgentControlServer};
use wafio_proto::v1::agent_message::Kind as Out;
use wafio_proto::v1::server_message::Kind as In;
use wafio_proto::v1::{
    AgentMessage, BundleUpdate, MalwareDatabaseChunk, MalwareDatabaseRequest, ServerMessage,
    Welcome,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../control/tests/fixtures");
const HOST: &str = "shop.test";
const SHOP: &str = "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11";
const BLOG: &str = "6f1c0c64-4f7e-4a06-8cf3-0b7c2a6d1e90";
const CERT: &str = "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77";
const ORPHAN: &str = "7e1f3a90-2c1d-4b8e-9a55-1d3c4f6a8b02";

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

/// The names in a directory, sorted.
fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// A scratch directory with an app, its upstream, the certificate for its host as a key file in
/// the key directory, and the bundle cache the agent can start from. Removed when dropped, and the
/// agent log is printed first when the test is failing.
struct Setup {
    dir: PathBuf,
    /// The key directory the test puts files in.
    keys: PathBuf,
    /// The key directory the agent is told to use.
    keys_env: PathBuf,
    upstream: Upstream,
    client: Arc<ClientConfig>,
    /// The key and the certificate, as one key file holds them.
    pem: String,
    /// A line of the key's own body: if any output holds this, it holds the key.
    key_body: String,
    leaf: String,
    plain: u16,
    https: u16,
    redirect: u16,
}

impl Setup {
    fn new(tag: &str) -> Setup {
        let dir =
            std::env::temp_dir().join(format!("wafio-tls-bundle-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("state")).unwrap();
        fs::write(dir.join("data.txt"), "x\n").unwrap();
        let keys = dir.join("keys");
        fs::DirBuilder::new().mode(0o700).create(&keys).unwrap();
        let (certificate, key, authority) = make_pki(&dir);
        let key_text = fs::read_to_string(key).unwrap();
        let der = Command::new("openssl")
            .args(["x509", "-outform", "DER", "-in"])
            .arg(&certificate)
            .output()
            .expect("openssl is installed")
            .stdout;
        let [plain, https, redirect] = free_ports();
        let setup = Setup {
            keys_env: keys.clone(),
            keys,
            upstream: Upstream::start(),
            client: client_config(authority),
            key_body: key_text.lines().nth(1).unwrap().to_owned(),
            pem: key_text + &fs::read_to_string(certificate).unwrap(),
            leaf: Sha256::digest(der)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            dir,
            plain,
            https,
            redirect,
        };
        setup.install_key();
        setup
    }

    /// The certificate where the bundle says it is.
    fn install_key(&self) {
        let path = self.keys.join(format!("{CERT}.pem"));
        fs::write(&path, &self.pem).unwrap();
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    }

    fn log(&self) -> PathBuf {
        self.dir.join("agent.log")
    }

    /// The `tls` object of the shop: HTTPS and redirect listeners of its own.
    fn tls_object(&self) -> String {
        format!(
            r#"{{"listen":"127.0.0.1:{}","hosts":["{HOST}"],"redirect_listen":"127.0.0.1:{}","source":"uploaded","certificate_id":"{CERT}","leaf_sha256":"{}"}}"#,
            self.https, self.redirect, self.leaf
        )
    }

    fn shop(&self, tls: &str) -> String {
        format!(
            r#"{{"app_id":"{SHOP}","listen_host":"127.0.0.1","listen_port":{},"upstream":"http://127.0.0.1:{}","mode":"block","tls":{tls}}}"#,
            self.plain, self.upstream.port
        )
    }

    fn bundle(&self, apps: &[String]) -> String {
        format!(
            r#"{{"agent_id":"tls","project_id":"p","apps":[{}]}}"#,
            apps.join(",")
        )
    }

    /// The bundle the agent starts from when no control plane answers.
    fn cache(&self, bundle: &str) {
        wafio_control::save_bundle_cache(
            &self.dir.join("state"),
            bundle.as_bytes(),
            7,
            SystemTime::now(),
        )
        .unwrap();
    }

    fn log_text(&self) -> String {
        fs::read_to_string(self.log()).unwrap_or_default()
    }

    /// No byte of the key reached the log.
    fn assert_log_has_no_key(&self) {
        let log = self.log_text();
        assert!(
            !log.contains(&self.key_body) && !log.contains("PRIVATE KEY"),
            "key material in the log: {log}"
        );
    }

    /// The agent with every flag, no engine and no good-bot lookups, a key directory of its own and
    /// the control plane at `grpc`.
    fn command(&self, grpc: &str) -> Command {
        let data = self.dir.join("data.txt");
        let d = data.to_str().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_wafio-waf-agent-open"));
        cmd.args(["--grpc-server", grpc, "--agent-name", "tls-bundle"])
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
            .env("WAFIO_TEST_TLS_DIR", &self.keys_env)
            // A library installed on this host must not give the agent an engine.
            .env("WAFIO_ENGINE_LIB", self.dir.join("no-engine.so"))
            .env("WAFIO_TEST_GOODBOT_SOURCES", "")
            .env_remove("WAFIO_TLS_SITES_FILE")
            .env_remove("WAFIO_METRICS_ADDR")
            .env_remove("NOTIFY_SOCKET")
            .stdout(Stdio::null());
        cmd
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
    /// Starts the agent against the control plane at `grpc`; it has not said READY yet.
    fn spawn(setup: &Setup, grpc: &str, tweak: impl FnOnce(&mut Command)) -> Agent {
        let notify_path = setup.dir.join("notify.sock");
        let notify = UnixDatagram::bind(&notify_path).unwrap();
        let mut cmd = setup.command(grpc);
        tweak(&mut cmd);
        let child = cmd
            .env("NOTIFY_SOCKET", &notify_path)
            .stderr(Stdio::from(fs::File::create(setup.log()).unwrap()))
            .spawn()
            .unwrap();
        Agent {
            first: child.id(),
            dir: setup.dir.clone(),
            child: Some(child),
            notify,
        }
    }

    async fn ready(&self) {
        let notify = self.notify.try_clone().unwrap();
        let message =
            tokio::task::spawn_blocking(move || ready_message(&notify, Duration::from_secs(60)))
                .await
                .unwrap();
        assert_eq!(message, format!("READY=1\nMAINPID={}\n", self.first));
    }

    /// Starts the agent from its bundle cache, with no control plane, and waits for READY.
    async fn start(setup: &Setup) -> Agent {
        let agent = Agent::spawn(setup, "127.0.0.1:1", |_| {});
        agent.ready().await;
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
async fn an_app_with_a_tls_object_is_served_over_https_from_a_cached_bundle_and_a_key_file() {
    let s = Setup::new("start");
    s.cache(&s.bundle(&[s.shop(&s.tls_object())]));
    let agent = Agent::spawn(&s, "127.0.0.1:1", |cmd| {
        cmd.env("WAFIO_TLS_SITES_FILE", "/etc/wafio/tls-sites.json");
    });
    agent.ready().await;

    // The app opens no plain listener of its own; its HTTPS and redirect listeners are up.
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
        heads[0]
            .to_ascii_lowercase()
            .contains("x-forwarded-proto: https"),
        "the upstream is told the request came over HTTPS: {}",
        heads[0]
    );
    let host = format!("{HOST}:{}", s.redirect);
    let r = plain(s.redirect, &host, "/cart?a=1").await.unwrap();
    assert_eq!(r.status, 308);
    assert_eq!(
        r.header("location"),
        Some(format!("https://{HOST}:{}/cart?a=1", s.https).as_str())
    );

    // The directory holds the certificate, what the agent remembers about it, and the lock.
    assert_eq!(
        files(&s.keys),
        [
            format!("{CERT}.pem"),
            "state.json".into(),
            "tls.lock".into()
        ]
    );
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(s.keys.join("state.json")).unwrap()).unwrap();
    assert_eq!(state["apps"][SHOP]["served"], format!("{CERT}.pem"));
    assert!(
        !String::from_utf8_lossy(&fs::read(s.keys.join("state.json")).unwrap())
            .contains(&s.key_body)
    );
    // The old settings file is no longer read, and says so.
    let log = s.log_text();
    assert_eq!(
        log.matches("WAFIO_TLS_SITES_FILE is no longer read")
            .count(),
        1,
        "{log}"
    );
    s.assert_log_has_no_key();
}

#[tokio::test]
async fn an_agent_without_a_usable_key_directory_serves_the_app_as_its_bundle_says() {
    let mut s = Setup::new("no-dir");
    // The parent of the directory is not there, and the agent does not make it.
    s.keys_env = s.dir.join("missing/tls");
    s.cache(&s.bundle(&[s.shop(&s.tls_object())]));
    let _agent = Agent::start(&s).await;

    let r = plain(s.plain, HOST, "/").await.unwrap();
    assert_eq!((r.status, r.body.as_str()), (200, "ok"));
    for port in [s.https, s.redirect] {
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }
    let log = s.log_text();
    assert!(
        log.contains("does not serve apps over HTTPS") && log.contains("missing/tls"),
        "{log}"
    );
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
async fn a_reload_hands_over_the_sockets_and_the_key_directory_while_connections_go_on() {
    let s = Setup::new("reload");
    s.cache(&s.bundle(&[s.shop(&s.tls_object())]));
    let mut agent = Agent::start(&s).await;
    let first = agent.first;
    // A file no app of the bundle names, put there after the first process applied it: only the
    // process that holds the lock removes it.
    let orphan = s.keys.join(format!("{ORPHAN}.pem"));
    fs::write(&orphan, "not a certificate anyone wants").unwrap();

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
        s.log_text().contains("took over; draining")
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
    assert_eq!(plain(s.redirect, HOST, "/").await.unwrap().status, 308);
    assert!(TcpStream::connect(("127.0.0.1", s.plain)).await.is_err());

    // The successor served from the files it read while the predecessor held the lock, left the
    // orphan alone until the lock was handed over, and then removed it.
    until("the successor to remove the orphan", || !orphan.exists()).await;
    let log = s.log_text();
    let at = |line: &str| {
        log.find(line)
            .unwrap_or_else(|| panic!("{line:?} not in the log:\n{log}"))
    };
    let waits = at("[tls] another process holds the key directory lock");
    let handed = at("[tls] key directory lock handed over");
    let took = at("[tls] this process writes in the key directory now");
    assert!(
        waits < handed && handed < took,
        "{waits} {handed} {took}\n{log}"
    );
    assert_eq!(
        files(&s.keys),
        [
            format!("{CERT}.pem"),
            "state.json".into(),
            "tls.lock".into()
        ]
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
    s.assert_log_has_no_key();
    signal(second, "-TERM");
}

#[tokio::test]
async fn a_process_that_finds_the_key_directory_locked_serves_what_it_reads_and_writes_nothing() {
    let s = Setup::new("locked");
    s.cache(&s.bundle(&[s.shop(&s.tls_object())]));
    let orphan = s.keys.join(format!("{ORPHAN}.pem"));
    fs::write(&orphan, "not a certificate anyone wants").unwrap();
    // The process this one replaces holds the lock.
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(s.keys.join("tls.lock"))
        .unwrap();
    let lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock).unwrap();
    let before = files(&s.keys);

    let _agent = Agent::start(&s).await;
    let mut client = Https::connect(s.https, &s.client, HOST).await.unwrap();
    let r = client.send(&get("/")).await.unwrap();
    assert_eq!(
        (r.status, r.body.as_str()),
        (200, "ok"),
        "it serves the file it read"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(files(&s.keys), before, "it made, removed and wrote nothing");
    assert!(orphan.exists());

    drop(lock);
    until("the agent to take the lock and clean up", || {
        !orphan.exists()
    })
    .await;
    assert_eq!(
        files(&s.keys),
        [
            format!("{CERT}.pem"),
            "state.json".into(),
            "tls.lock".into()
        ]
    );
    assert!(
        s.log_text()
            .contains("[tls] this process writes in the key directory now")
    );
    let r = client.send(&get("/again")).await.unwrap();
    assert_eq!(r.status, 200, "the connection that was open goes on");
    s.assert_log_has_no_key();
}

/// A control plane that hands every connection of the agent to the test.
struct Conn {
    inbound: Streaming<AgentMessage>,
    out: mpsc::Sender<Result<ServerMessage, Status>>,
}

impl Conn {
    async fn next(&mut self) -> AgentMessage {
        tokio::time::timeout(Duration::from_secs(30), self.inbound.message())
            .await
            .expect("agent message")
            .unwrap()
            .expect("stream open")
    }

    /// Sends `bundle` and returns the ack the agent answers it with.
    async fn bundle(&mut self, id: &str, generation: i64, bundle: String) -> (bool, String) {
        let bu = BundleUpdate {
            command_id: id.into(),
            generation,
            bundle_json: bundle.into_bytes(),
        };
        self.out
            .send(Ok(ServerMessage {
                kind: Some(In::Bundle(bu)),
            }))
            .await
            .unwrap();
        loop {
            if let Some(Out::Ack(a)) = self.next().await.kind
                && a.command_id == id
            {
                return (a.ok, a.error);
            }
        }
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
        let w = Welcome {
            agent_id: "agent-uuid".into(),
            server_time_unix: 1,
            heartbeat_seconds: 30,
        };
        tx.send(Ok(ServerMessage {
            kind: Some(In::Welcome(w)),
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
        Err(Status::unimplemented("not part of this test"))
    }
}

fn fx(name: &str) -> Vec<u8> {
    fs::read(Path::new(FIXTURES).join(name)).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_entry_that_fails_a_check_refuses_the_whole_bundle_and_the_previous_one_serves_on() {
    let s = Setup::new("refused");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
    let agent = Agent::spawn(&s, &cp, |_| {});

    // The start probe, then the stream.
    let mut probe = tokio::time::timeout(Duration::from_secs(30), conns.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(Out::Hello(_)) = probe.next().await.kind else {
        panic!("probe: no Hello")
    };
    let mut c = tokio::time::timeout(Duration::from_secs(30), conns.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(Out::Hello(_)) = c.next().await.kind else {
        panic!("stream: no Hello")
    };

    let shop = s.shop(&s.tls_object());
    let (ok, error) = c
        .bundle("b1", 1, s.bundle(std::slice::from_ref(&shop)))
        .await;
    assert!(ok, "the first bundle was refused: {error}");
    agent.ready().await;
    let mut client = Https::connect(s.https, &s.client, HOST).await.unwrap();
    assert_eq!(client.send(&get("/one")).await.unwrap().status, 200);

    // A second app whose entry names a wildcard: the whole bundle is refused.
    let bad = format!(
        r#"{{"app_id":"{BLOG}","listen_host":"127.0.0.1","listen_port":1,"upstream":"http://127.0.0.1:1","mode":"block","tls":{{"listen":"0.0.0.0:443","hosts":["*.shop.test"],"source":"acme"}}}}"#
    );
    let (ok, error) = c.bundle("b2", 2, s.bundle(&[shop.clone(), bad])).await;
    assert_eq!((ok, error.as_str()), (false, "invalid TLS site settings"));
    let log = s.log_text();
    assert!(log.contains(BLOG) && log.contains("wildcard"), "{log}");
    // The first bundle serves on: the open connection and a new one.
    assert_eq!(client.send(&get("/two")).await.unwrap().status, 200);
    let mut fresh = Https::connect(s.https, &s.client, HOST).await.unwrap();
    assert_eq!(fresh.send(&get("/three")).await.unwrap().status, 200);
    let cache = fs::read_to_string(s.dir.join("state/last-bundle.json")).unwrap();
    assert!(
        cache.contains("\"generation\":1,"),
        "the cache still has the first bundle: {cache}"
    );
    assert!(!cache.contains(BLOG));

    // A bundle without the bad entry applies.
    let (ok, error) = c.bundle("b3", 3, s.bundle(&[shop])).await;
    assert!(ok, "{error}");
    assert_eq!(fresh.send(&get("/four")).await.unwrap().status, 200);
    s.assert_log_has_no_key();
}
