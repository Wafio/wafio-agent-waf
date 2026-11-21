//! The real binary with a key directory (`WAFIO_TEST_TLS_DIR`): an app whose bundle entry has a
//! `tls` object is served over HTTPS from a certificate file, with no plain listener of its own,
//! from a cached bundle with no control plane and from live bundles of a fake one. A reload hands
//! the sockets and the directory lock over while connections go on, a process that finds the lock
//! taken writes nothing in the directory until it is free, and an entry that fails a check refuses
//! the whole bundle. Keys are made by `openssl` at test time into a scratch directory that is
//! removed when the test ends.
//!
//! The last tests order certificates from Pebble, the ACME test server of Let's Encrypt. They run
//! when `WAFIO_PEBBLE_DIRECTORY` is set, which `eval "$(scripts/pebble.sh up)"` does, and print that
//! they are skipped when it is not.

use std::collections::VecDeque;
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
    AgentMessage, BundleUpdate, CertificateInstall, CertificateStatus, MalwareDatabaseChunk,
    MalwareDatabaseRequest, ServerMessage, Welcome,
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

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
    // A resumed session skips the server's certificate, so a test that asks which one a new
    // handshake gets must not resume.
    config.resumption = rustls::client::Resumption::disabled();
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

    /// The SHA-256 of the leaf the server presented in the handshake.
    fn peer_leaf(&self) -> String {
        let (_, session) = self.0.get_ref().get_ref();
        let chain = session
            .peer_certificates()
            .expect("the server sent a chain");
        sha256_hex(chain[0].as_ref())
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
    /// The chain and the key as the control plane sends them.
    chain: String,
    key: String,
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
            pem: key_text.clone() + &fs::read_to_string(&certificate).unwrap(),
            chain: fs::read_to_string(&certificate).unwrap(),
            key: key_text,
            leaf: sha256_hex(&der),
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
    /// Messages read while waiting for another one, in the order they came.
    backlog: VecDeque<AgentMessage>,
    /// Every message the agent sent on this connection, as Rust prints it: a byte field is a list
    /// of numbers, a text field is text.
    received: Vec<String>,
}

impl Conn {
    fn new(
        inbound: Streaming<AgentMessage>,
        out: mpsc::Sender<Result<ServerMessage, Status>>,
    ) -> Conn {
        Conn {
            inbound,
            out,
            backlog: VecDeque::new(),
            received: Vec::new(),
        }
    }

    async fn read(&mut self) -> AgentMessage {
        let message = tokio::time::timeout(Duration::from_secs(30), self.inbound.message())
            .await
            .expect("agent message")
            .unwrap()
            .expect("stream open");
        self.received.push(format!("{message:?}"));
        message
    }

    async fn next(&mut self) -> AgentMessage {
        match self.backlog.pop_front() {
            Some(message) => message,
            None => self.read().await,
        }
    }

    /// Reads what the agent sends for `wait`, and keeps it.
    async fn drain_for(&mut self, wait: Duration) {
        let end = tokio::time::Instant::now() + wait;
        while let Ok(read) = tokio::time::timeout_at(end, self.inbound.message()).await {
            let message = read.unwrap().expect("stream open");
            self.received.push(format!("{message:?}"));
            self.backlog.push_back(message);
        }
    }

    /// The first message `pick` takes. What comes before it waits for the next call.
    async fn wait_for<T>(&mut self, pick: impl Fn(&AgentMessage) -> Option<T>) -> T {
        if let Some(at) = self.backlog.iter().position(|m| pick(m).is_some()) {
            let message = self.backlog.remove(at).unwrap();
            return pick(&message).unwrap();
        }
        loop {
            let message = self.read().await;
            match pick(&message) {
                Some(found) => return found,
                None => self.backlog.push_back(message),
            }
        }
    }

    async fn send(&mut self, kind: In) {
        self.out
            .send(Ok(ServerMessage { kind: Some(kind) }))
            .await
            .unwrap();
    }

    async fn ack(&mut self, id: &str) -> (bool, String) {
        self.wait_for(|m| match &m.kind {
            Some(Out::Ack(a)) if a.command_id == id => Some((a.ok, a.error.clone())),
            _ => None,
        })
        .await
    }

    /// Sends `bundle` and returns the ack the agent answers it with.
    async fn bundle(&mut self, id: &str, generation: i64, bundle: String) -> (bool, String) {
        let bu = BundleUpdate {
            command_id: id.into(),
            generation,
            bundle_json: bundle.into_bytes(),
        };
        self.send(In::Bundle(bu)).await;
        self.ack(id).await
    }

    /// Sends a `CertificateInstall` and returns the ack the agent answers it with.
    async fn install(
        &mut self,
        id: &str,
        app: &str,
        cert: &str,
        chain: &str,
        key: &str,
        leaf: &str,
    ) -> (bool, String) {
        let install = CertificateInstall {
            command_id: id.into(),
            app_id: app.into(),
            certificate_id: cert.into(),
            chain_pem: chain.as_bytes().to_vec(),
            key_pem: key.as_bytes().to_vec(),
            leaf_sha256: leaf.into(),
        };
        self.send(In::CertificateInstall(install)).await;
        self.ack(id).await
    }

    /// The next status of `app` in `state`.
    async fn status(&mut self, app: &str, state: &str) -> CertificateStatus {
        self.wait_for(|m| match &m.kind {
            Some(Out::CertificateStatus(s)) if s.app_id == app && s.state == state => {
                Some(s.clone())
            }
            _ => None,
        })
        .await
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
        let _ = self.conns.send(Conn::new(req.into_inner(), tx));
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

/// A control plane the agent connects to, with mutual TLS as the real one has. Every connection
/// the agent makes comes out of the channel.
async fn serve_fake() -> (String, mpsc::UnboundedReceiver<Conn>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (tx, conns) = mpsc::unbounded_channel();
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
    (address, conns)
}

/// The two connections an agent makes at start, the probe and the stream, each past its Hello.
/// Returns the features both said and the stream.
async fn connect_agent(conns: &mut mpsc::UnboundedReceiver<Conn>) -> (Vec<String>, Conn) {
    let mut probe = tokio::time::timeout(Duration::from_secs(30), conns.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(Out::Hello(first)) = probe.next().await.kind else {
        panic!("probe: no Hello")
    };
    let mut stream = tokio::time::timeout(Duration::from_secs(30), conns.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(Out::Hello(second)) = stream.next().await.kind else {
        panic!("stream: no Hello")
    };
    assert_eq!(first.features, second.features);
    (second.features, stream)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_entry_that_fails_a_check_refuses_the_whole_bundle_and_the_previous_one_serves_on() {
    let s = Setup::new("refused");
    let (cp, mut conns) = serve_fake().await;
    let agent = Agent::spawn(&s, &cp, |_| {});
    let (_, mut c) = connect_agent(&mut conns).await;

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

const CERT2: &str = "9c2d4e11-5a7b-4c3d-8e6f-0a1b2c3d4e5f";

/// A second certificate for `HOST` from the authority `make_pki` left in `dir`: the certificate
/// text, the key text and the SHA-256 of the leaf.
fn sign_again(dir: &Path, name: &str) -> (String, String, String) {
    let path = |ext: &str| {
        dir.join(format!("{name}.{ext}"))
            .to_str()
            .unwrap()
            .to_owned()
    };
    let (key, csr, crt) = (path("key"), path("csr"), path("crt"));
    let (ca_crt, ca_key, ext) = (
        dir.join("ca.crt").to_str().unwrap().to_owned(),
        dir.join("ca.key").to_str().unwrap().to_owned(),
        dir.join("shop.ext").to_str().unwrap().to_owned(),
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
        .args(["x509", "-in", &crt, "-outform", "DER"])
        .output()
        .expect("openssl is installed")
        .stdout;
    (
        fs::read_to_string(&crt).unwrap(),
        fs::read_to_string(&key).unwrap(),
        sha256_hex(&der),
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The numbers Rust prints for a byte field.
fn as_numbers(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// What would give a key away: the lines of its base64 and the bytes they encode.
struct KeyNeedles {
    lines: Vec<String>,
    der: Vec<u8>,
}

impl KeyNeedles {
    fn of(key_text: &str) -> KeyNeedles {
        use std::io::Write;
        let mut child = Command::new("openssl")
            .args(["pkey", "-outform", "DER"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("openssl is installed");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(key_text.as_bytes())
            .unwrap();
        let der = child.wait_with_output().unwrap().stdout;
        assert!(der.len() > 30, "the key was read");
        KeyNeedles {
            lines: key_text
                .lines()
                .filter(|l| !l.starts_with("-----") && l.len() >= 16)
                .map(str::to_owned)
                .collect(),
            der,
        }
    }

    /// The key is where a key is kept: the lines of its text are in `file`.
    fn assert_in_file(&self, file: &[u8]) {
        assert!(self.lines.iter().all(|l| contains(file, l.as_bytes())));
    }

    fn assert_absent(&self, what: &str, bytes: &[u8]) {
        for line in &self.lines {
            assert!(
                !contains(bytes, line.as_bytes()),
                "a line of the key is in {what}"
            );
        }
        assert!(
            !contains(bytes, &self.der),
            "the DER of the key is in {what}"
        );
        assert!(!contains(bytes, b"PRIVATE KEY"), "a key block is in {what}");
    }

    /// Absent from messages as Rust prints them: as text, or as the numbers of a byte field.
    fn assert_absent_from_messages(&self, messages: &[String]) {
        for shown in messages {
            for line in &self.lines {
                assert!(
                    !shown.contains(line.as_str()) && !shown.contains(&as_numbers(line.as_bytes())),
                    "a line of the key is in a message: {shown}"
                );
            }
            assert!(
                !shown.contains(&as_numbers(&self.der)),
                "the DER of the key is in a message: {shown}"
            );
            assert!(
                !shown.contains("PRIVATE KEY") && !shown.contains(&as_numbers(b"PRIVATE KEY")),
                "a key block is in a message: {shown}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uploaded_certificate_is_installed_acked_reported_and_replaced_without_a_restart() {
    let s = Setup::new("install");
    // The directory starts with no certificate: the control plane has to send it.
    let first_file = s.keys.join(format!("{CERT}.pem"));
    fs::remove_file(&first_file).unwrap();
    let (cp, mut conns) = serve_fake().await;
    let agent = Agent::spawn(&s, &cp, |_| {});
    let (features, mut c) = connect_agent(&mut conns).await;
    assert!(
        features.iter().any(|f| f == "tls_certificates"),
        "an agent with a key directory takes certificates: {features:?}"
    );

    // A bundle that names a certificate the agent does not hold: it says so, asking for it, and
    // serves nothing for the app.
    let (ok, error) = c
        .bundle("b1", 1, s.bundle(&[s.shop(&s.tls_object())]))
        .await;
    assert!(ok, "{error}");
    agent.ready().await;
    let missing = c.status(SHOP, "missing").await;
    assert_eq!(
        (
            missing.source.as_str(),
            missing.certificate_id.as_str(),
            missing.request_id.as_str()
        ),
        ("uploaded", CERT, "")
    );
    assert!(
        missing.chain_pem.is_empty() && missing.leaf_sha256.is_empty() && missing.unix_time > 0
    );
    assert!(Https::connect(s.https, &s.client, HOST).await.is_err());

    // What the bundle does not name is not installed, and nothing is written for it.
    let refused = c
        .install("i0", SHOP, ORPHAN, &s.chain, &s.key, &s.leaf)
        .await;
    assert_eq!(refused, (false, "not_in_bundle".to_owned()));
    let wrong_leaf = "ab".repeat(32);
    let refused = c
        .install("i0b", SHOP, CERT, &s.chain, &s.key, &wrong_leaf)
        .await;
    assert_eq!(refused, (false, "not_in_bundle".to_owned()));
    assert!(!first_file.exists());

    // The pair the bundle names: acked ok, then `active` with the chain in use.
    let acked = c.install("i1", SHOP, CERT, &s.chain, &s.key, &s.leaf).await;
    assert_eq!(acked, (true, String::new()));
    let active = c.status(SHOP, "active").await;
    assert_eq!(
        (active.certificate_id.as_str(), active.leaf_sha256.as_str()),
        (CERT, s.leaf.as_str())
    );
    assert_eq!(
        active.chain_pem,
        s.chain.as_bytes(),
        "the chain as the certificate is served"
    );
    let mut open = Https::connect(s.https, &s.client, HOST).await.unwrap();
    assert_eq!(open.peer_leaf(), s.leaf);
    assert_eq!(open.send(&get("/one")).await.unwrap().status, 200);
    let needles = KeyNeedles::of(&s.key);
    needles.assert_in_file(&fs::read(&first_file).unwrap());
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&first_file).unwrap().permissions())
            & 0o777,
        0o600
    );
    assert_eq!(
        files(&s.keys),
        [
            format!("{CERT}.pem"),
            "state.json".into(),
            "tls.lock".into()
        ]
    );

    // A replace: the bundle names another certificate. The one in use is served until it arrives,
    // the status says so with the chain in use, and the install changes what the next handshake
    // gets, with no restart and an open connection going on.
    let (chain2, key2, leaf2) = sign_again(&s.dir, "second");
    let (ok, error) = c
        .bundle(
            "b2",
            2,
            s.bundle(&[s.shop(&s.tls_object().replace(CERT, CERT2).replace(&s.leaf, &leaf2))]),
        )
        .await;
    assert!(ok, "{error}");
    let waiting = c.status(SHOP, "missing").await;
    assert_eq!(waiting.certificate_id, CERT2);
    assert_eq!(
        (waiting.chain_pem.as_slice(), waiting.leaf_sha256.as_str()),
        (s.chain.as_bytes(), s.leaf.as_str()),
        "the certificate that is still served"
    );
    let mut during = Https::connect(s.https, &s.client, HOST).await.unwrap();
    assert_eq!(during.peer_leaf(), s.leaf);
    let acked = c.install("i2", SHOP, CERT2, &chain2, &key2, &leaf2).await;
    assert_eq!(acked, (true, String::new()));
    let replaced = c.status(SHOP, "active").await;
    assert_eq!(
        (
            replaced.certificate_id.as_str(),
            replaced.leaf_sha256.as_str()
        ),
        (CERT2, leaf2.as_str())
    );
    let mut fresh = Https::connect(s.https, &s.client, HOST).await.unwrap();
    assert_eq!(
        fresh.peer_leaf(),
        leaf2,
        "a new handshake gets the new certificate"
    );
    assert_eq!(fresh.send(&get("/two")).await.unwrap().status, 200);
    assert_eq!(
        open.peer_leaf(),
        s.leaf,
        "an open connection keeps what it was given"
    );
    assert_eq!(open.send(&get("/three")).await.unwrap().status, 200);
    assert_eq!(during.send(&get("/four")).await.unwrap().status, 200);
    assert!(alive(agent.first), "the agent did not restart");
    assert_eq!(
        files(&s.keys),
        [
            format!("{CERT2}.pem"),
            "state.json".into(),
            "tls.lock".into()
        ]
    );

    // No byte of either key left the process but in its file: not in a message the control plane
    // got, not in the bundle cache, not in the log.
    c.drain_for(Duration::from_millis(500)).await;
    let second = KeyNeedles::of(&key2);
    // The check sees a key where a message holds bytes: the numbers it looks for are the ones
    // Rust prints.
    let leaked = format!(
        "{:?}",
        CertificateStatus {
            chain_pem: needles.der.clone(),
            ..Default::default()
        }
    );
    assert!(leaked.contains(&as_numbers(&needles.der)));
    for keys in [&needles, &second] {
        keys.assert_absent_from_messages(&c.received);
        keys.assert_absent(
            "the bundle cache",
            &fs::read(s.dir.join("state/last-bundle.json")).unwrap(),
        );
        keys.assert_absent("the log", s.log_text().as_bytes());
    }
    second.assert_in_file(&fs::read(s.keys.join(format!("{CERT2}.pem"))).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_that_cannot_bind_its_https_address_is_refused_and_its_gateway_apps_are_failed() {
    let s = Setup::new("unbound");
    let (cp, mut conns) = serve_fake().await;
    let _agent = Agent::spawn(&s, &cp, |_| {});
    let (_, mut c) = connect_agent(&mut conns).await;

    // Something else listens on the HTTPS address.
    let _taken = TcpListener::bind(("127.0.0.1", s.https)).unwrap();
    let (ok, error) = c
        .bundle("b1", 1, s.bundle(&[s.shop(&s.tls_object())]))
        .await;
    assert_eq!(
        (ok, error.as_str()),
        (false, "failed to bind WAF route listener")
    );
    let failed = c.status(SHOP, "failed").await;
    assert_eq!(
        failed.error,
        format!("cannot listen on 127.0.0.1:{}: address in use", s.https)
    );
    assert_eq!(
        (failed.source.as_str(), failed.certificate_id.as_str()),
        ("uploaded", CERT)
    );
    assert!(failed.chain_pem.is_empty(), "no certificate was served");
    // The bundle is tried again a minute after it was refused, for as long as it takes.
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    assert!(
        (now + 30..=now + 60).contains(&failed.next_attempt_unix),
        "{} against {now}",
        failed.next_attempt_unix
    );
    // The plain address of the app was never opened either.
    assert!(TcpStream::connect(("127.0.0.1", s.plain)).await.is_err());
    s.assert_log_has_no_key();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_without_a_usable_key_directory_leaves_the_feature_out_and_takes_no_certificate() {
    let mut s = Setup::new("no-dir-hello");
    s.keys_env = s.dir.join("missing/tls");
    let (cp, mut conns) = serve_fake().await;
    let _agent = Agent::spawn(&s, &cp, |_| {});
    let (features, mut c) = connect_agent(&mut conns).await;
    assert!(
        !features.iter().any(|f| f == "tls_certificates"),
        "the control plane must not send a key to this agent: {features:?}"
    );
    assert!(features.iter().any(|f| f == "script_rules"));

    // The warning names the directory and the cause, once, however often the agent connects.
    let log = s.log_text();
    assert_eq!(
        log.matches("does not serve apps over HTTPS").count(),
        1,
        "{log}"
    );
    assert!(
        log.contains("missing/tls") && log.contains("cannot create"),
        "{log}"
    );

    // The `tls` object is ignored: the app is served as its bundle says, and no status is sent.
    let (ok, error) = c
        .bundle("b1", 1, s.bundle(&[s.shop(&s.tls_object())]))
        .await;
    assert!(ok, "{error}");
    let r = plain(s.plain, HOST, "/").await.unwrap();
    assert_eq!((r.status, r.body.as_str()), (200, "ok"));
    let refused = c.install("i1", SHOP, CERT, &s.chain, &s.key, &s.leaf).await;
    assert_eq!(refused, (false, "not_in_bundle".to_owned()));
    c.drain_for(Duration::from_secs(1)).await;
    assert!(
        !c.received.iter().any(|m| m.contains("CertificateStatus")),
        "{:?}",
        c.received
    );
    KeyNeedles::of(&s.key).assert_absent_from_messages(&c.received);
}

// ── certificates ordered from Pebble ─────────────────────────────────────────────────────────

/// Pebble, from the settings `scripts/pebble.sh up` printed. Pebble connects to the ports it names
/// for a validation, so the tests that use it run one at a time.
struct Pebble {
    directory: String,
    root: String,
    /// The port Pebble connects to for HTTP-01, and for TLS-ALPN-01.
    http: u16,
    tls: u16,
}

static PEBBLE_IN_USE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

impl Pebble {
    fn from_env() -> Option<Pebble> {
        let directory = std::env::var("WAFIO_PEBBLE_DIRECTORY").ok()?;
        let port = |name: &str| {
            std::env::var(name)
                .unwrap_or_else(|_| panic!("{name} is not set"))
                .parse()
                .unwrap()
        };
        Some(Pebble {
            directory,
            root: std::env::var("WAFIO_PEBBLE_ROOT").expect("WAFIO_PEBBLE_ROOT is not set"),
            http: port("WAFIO_PEBBLE_HTTP_PORT"),
            tls: port("WAFIO_PEBBLE_TLS_PORT"),
        })
    }

    /// The agent orders from Pebble, which the platform's roots do not know: it is given Pebble's
    /// root the way any root is added to them.
    fn set(&self, cmd: &mut Command) {
        cmd.env("SSL_CERT_FILE", &self.root)
            .env("WAFIO_ACME_DIRECTORY", &self.directory);
        for name in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
        ] {
            cmd.env_remove(name);
        }
    }
}

macro_rules! pebble {
    () => {
        match Pebble::from_env() {
            Some(pebble) => pebble,
            None => {
                eprintln!("WAFIO_PEBBLE_DIRECTORY is not set: this test is skipped");
                return;
            }
        }
    };
}

/// The `tls` object of an app whose certificate is ordered.
fn acme_object(listen: u16, redirect: Option<u16>, request_id: &str) -> String {
    let redirect = redirect.map_or(String::new(), |p| {
        format!(r#""redirect_listen":"127.0.0.1:{p}","#)
    });
    format!(
        r#"{{"listen":"127.0.0.1:{listen}","hosts":["{HOST}"],{redirect}"source":"acme","acme_request_id":"{request_id}"}}"#
    )
}

/// A client that takes any certificate: what Pebble issues is signed by a root of its own.
#[derive(Debug)]
struct TakesAny;

impl rustls::client::danger::ServerCertVerifier for TakesAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_taking_any() -> Arc<ClientConfig> {
    pingora::tls::install_default_crypto_provider();
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TakesAny))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Arc::new(config)
}

/// The state file with a record of the shop, which `Setup::new` has not made yet: a hold that lets
/// a test look at the app while it has nothing but its placeholder.
fn seed_state(s: &Setup, record: &str) {
    fs::write(
        s.keys.join("state.json"),
        format!(r#"{{"apps":{{"{SHOP}":{record}}}}}"#),
    )
    .unwrap();
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// What would give away what the agent keeps secret about its orders: the account's key, as the
/// file holds it, and the key of the certificate it was issued for.
fn assert_orders_keep_their_keys(s: &Setup, stream: &Conn, issued: &str) {
    let account = fs::read_to_string(s.keys.join("acme-account.json")).unwrap();
    let key = account
        .split("\"key_pkcs8\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the account file holds the account key");
    let log = s.log_text();
    assert!(!log.contains(key), "the account key is in the log");
    assert!(
        !stream.received.iter().any(|m| m.contains(key)),
        "the account key is in a message"
    );
    let state = fs::read_to_string(s.keys.join("state.json")).unwrap();
    assert!(
        !state.contains(key) && !state.contains("PRIVATE KEY"),
        "{state}"
    );
    let cache = fs::read_to_string(s.dir.join("state/last-bundle.json")).unwrap_or_default();
    assert!(!cache.contains(key));
    // The key of the issued certificate is in its file and nowhere else.
    let end = "-----END PRIVATE KEY-----";
    let key_block = &issued[..issued.find(end).expect("the file holds the key") + end.len()];
    let needles = KeyNeedles::of(key_block);
    needles.assert_in_file(issued.as_bytes());
    needles.assert_absent("the log", log.as_bytes());
    needles.assert_absent("the state", state.as_bytes());
    needles.assert_absent_from_messages(&stream.received);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pebble_issues_by_tls_alpn_on_the_tls_listener_and_a_placeholder_connection_goes_on() {
    let pebble = pebble!();
    let _only = PEBBLE_IN_USE.lock().await;
    let s = Setup::new("pebble-alpn");
    // The app has been waiting for a few seconds: it has nothing but the placeholder meanwhile.
    seed_state(
        &s,
        &format!(
            r#"{{"request_id":"r1","next_attempt_unix":{}}}"#,
            unix_now() + 6
        ),
    );
    let (cp, mut conns) = serve_fake().await;
    let agent = Agent::spawn(&s, &cp, |cmd| pebble.set(cmd));
    let (_, mut stream) = connect_agent(&mut conns).await;
    let tls = acme_object(pebble.tls, Some(pebble.http), "r1");
    let (ok, error) = stream.bundle("b1", 1, s.bundle(&[s.shop(&tls)])).await;
    assert!(ok, "{error}");
    agent.ready().await;
    let pending = stream.status(SHOP, "pending").await;
    assert_eq!(
        (
            pending.source.as_str(),
            pending.request_id.as_str(),
            pending.certificate_id.as_str()
        ),
        ("acme", "r1", "")
    );
    assert!(pending.chain_pem.is_empty());

    // Nothing but the placeholder: the handshake succeeds with it and the app is not reached, and
    // the redirect listener does not send anyone to HTTPS yet.
    let any = client_taking_any();
    let mut old = Https::connect(pebble.tls, &any, HOST).await.unwrap();
    let placeholder = old.peer_leaf();
    let mut fresh = Https::connect(pebble.tls, &any, HOST).await.unwrap();
    let r = fresh.send(&get("/cart")).await.unwrap();
    assert_eq!(r.status, 503);
    assert_eq!(r.header("retry-after"), Some("60"));
    let r = plain(pebble.http, HOST, "/cart").await.unwrap();
    assert_eq!((r.status, r.header("location")), (503, None));
    assert!(s.upstream.heads().is_empty(), "the app was not reached");

    // The order runs once its wait is over, with TLS-ALPN-01 on the TLS listener.
    let active = stream.status(SHOP, "active").await;
    assert_eq!(
        (active.source.as_str(), active.request_id.as_str()),
        ("acme", "r1")
    );
    assert!(!active.chain_pem.is_empty() && active.leaf_sha256.len() == 64);
    assert_ne!(active.leaf_sha256, placeholder);
    assert_eq!((active.error.as_str(), active.next_attempt_unix), ("", 0));
    let mut served = Https::connect(pebble.tls, &any, HOST).await.unwrap();
    assert_eq!(
        served.peer_leaf(),
        active.leaf_sha256,
        "the issued certificate is served, no restart"
    );
    assert_eq!(served.send(&get("/cart")).await.unwrap().status, 200);
    // The connection that was open across the switch goes on: it is answered, not cut.
    let r = old.send(&get("/cart")).await.unwrap();
    assert_eq!(
        r.status, 503,
        "a connection made for the placeholder is answered 503 only"
    );
    let r = plain(pebble.http, HOST, "/cart?a=1").await.unwrap();
    assert_eq!(r.status, 308);
    assert_eq!(
        r.header("location"),
        Some(format!("https://{HOST}:{}/cart?a=1", pebble.tls).as_str())
    );

    // What the agent keeps: the certificate and the account in files only the agent reads, and the
    // state that says how it was made.
    let file = format!("acme-{SHOP}.pem");
    for name in [file.as_str(), "acme-account.json"] {
        let mode = fs::metadata(s.keys.join(name)).unwrap().permissions();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
            0o600,
            "{name}"
        );
    }
    let state = fs::read_to_string(s.keys.join("state.json")).unwrap();
    assert!(
        state.contains(&pebble.directory) && state.contains("tls-alpn-01"),
        "{state}"
    );
    assert!(state.contains(r#""request_id":"r1""#), "{state}");
    assert!(!files(&s.keys).contains(&format!("{CERT}.pem")));
    assert_orders_keep_their_keys(
        &s,
        &stream,
        &fs::read_to_string(s.keys.join(&file)).unwrap(),
    );
    let log = s.log_text();
    assert!(
        log.contains("[acme] made an account at") && log.contains("issued, served from"),
        "{log}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pebble_validates_by_http_on_the_redirect_listener_when_tls_alpn_cannot_reach() {
    let pebble = pebble!();
    let _only = PEBBLE_IN_USE.lock().await;
    let s = Setup::new("pebble-http");
    let (cp, mut conns) = serve_fake().await;
    let agent = Agent::spawn(&s, &cp, |cmd| pebble.set(cmd));
    let (_, mut stream) = connect_agent(&mut conns).await;
    // The TLS listener is not where Pebble connects for TLS-ALPN-01; the redirect listener is
    // where it connects for HTTP-01.
    let [elsewhere] = free_ports::<1>();
    let tls = acme_object(elsewhere, Some(pebble.http), "r1");
    let (ok, error) = stream.bundle("b1", 1, s.bundle(&[s.shop(&tls)])).await;
    assert!(ok, "{error}");
    agent.ready().await;

    // The first order answers TLS-ALPN-01, which Pebble cannot reach: it fails, and says why.
    let failed = stream.status(SHOP, "failed").await;
    assert_eq!(failed.request_id, "r1");
    assert!(failed.error.contains("tls-alpn-01"), "{}", failed.error);
    assert!(
        i64::try_from(unix_now()).unwrap() + 300 < failed.next_attempt_unix,
        "the next attempt is minutes away: {}",
        failed.next_attempt_unix
    );
    // A new request id orders at once, with the other challenge.
    let tls = acme_object(elsewhere, Some(pebble.http), "r2");
    let (ok, error) = stream.bundle("b2", 2, s.bundle(&[s.shop(&tls)])).await;
    assert!(ok, "{error}");
    let active = stream.status(SHOP, "active").await;
    assert_eq!(
        (active.request_id.as_str(), active.error.as_str()),
        ("r2", "")
    );
    let served = Https::connect(elsewhere, &client_taking_any(), HOST)
        .await
        .unwrap();
    assert_eq!(served.peer_leaf(), active.leaf_sha256);
    assert_eq!(plain(pebble.http, HOST, "/").await.unwrap().status, 308);
    let state = fs::read_to_string(s.keys.join("state.json")).unwrap();
    assert!(state.contains(r#""worked":"http-01""#), "{state}");
    let file = fs::read_to_string(s.keys.join(format!("acme-{SHOP}.pem"))).unwrap();
    assert_orders_keep_their_keys(&s, &stream, &file);
}

/// What a CDN does that turns port 80 into HTTPS: every plain request is sent to the same
/// path over HTTPS, on the port of the TLS listener.
async fn redirecting_to_https(port: u16, https: u16) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !contains(&head, b"\r\n\r\n") {
                    match tcp.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let path = text.split(' ').nth(1).unwrap_or("/").to_owned();
                let reply = format!(
                    "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{HOST}:{https}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = tcp.write_all(reply.as_bytes()).await;
            });
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pebble_validates_by_http_on_the_tls_listener_behind_a_redirect_to_https() {
    let pebble = pebble!();
    let _only = PEBBLE_IN_USE.lock().await;
    let s = Setup::new("pebble-cdn");
    // The challenge that worked last is HTTP-01, and the app has no listener on plain HTTP: only
    // the TLS listener, which something in front sends port 80 to.
    seed_state(&s, r#"{"worked":"http-01"}"#);
    redirecting_to_https(pebble.http, pebble.tls).await;
    let (cp, mut conns) = serve_fake().await;
    let agent = Agent::spawn(&s, &cp, |cmd| pebble.set(cmd));
    let (_, mut stream) = connect_agent(&mut conns).await;
    let tls = acme_object(pebble.tls, None, "r1");
    let (ok, error) = stream.bundle("b1", 1, s.bundle(&[s.shop(&tls)])).await;
    assert!(ok, "{error}");
    agent.ready().await;
    let active = stream.status(SHOP, "active").await;
    assert_eq!(
        (active.request_id.as_str(), active.error.as_str()),
        ("r1", "")
    );
    let mut served = Https::connect(pebble.tls, &client_taking_any(), HOST)
        .await
        .unwrap();
    assert_eq!(served.peer_leaf(), active.leaf_sha256);
    assert_eq!(served.send(&get("/")).await.unwrap().status, 200);
    let state = fs::read_to_string(s.keys.join("state.json")).unwrap();
    assert!(state.contains(r#""worked":"http-01""#), "{state}");
    let file = fs::read_to_string(s.keys.join(format!("acme-{SHOP}.pem"))).unwrap();
    assert_orders_keep_their_keys(&s, &stream, &file);
}
