//! HTTPS listeners through the public API: the certificate chosen by SNI and the book, the app
//! chosen by `Host`, the redirect listener, certificate validation (HTTP-01 on both listeners,
//! every ALPN case of TLS-ALPN-01), the placeholder certificate, an address that changes kind, the
//! limits of apps that share a listener, the JA4 of the handshake, the scheme a FastCGI app is
//! told, and what bounds a client that is slow or many. Keys are made by `openssl` into a
//! temporary directory and never leave it.

mod common;

use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use pingora::tls::sign::CertifiedKey;
use pingora::tls::{
    CertificateDer, ClientConfig, ClientTlsStream, RootCertStore, ServerName, TlsConnector,
};
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;
use wafio_proxy::cert_store::{BookChange, BookEntry, certified_key_from_pem};
use wafio_proxy::{AppSpec, Proxy, ProxyOptions, TlsSite};

use common::*;

/// A certificate chain (leaf first) and its private key, both PEM files.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CertFiles {
    certificate: PathBuf,
    key: PathBuf,
}

/// A certificate authority in a scratch directory, removed on drop, and the certificates it signs.
struct Pki(PathBuf);

impl Pki {
    fn new() -> Pki {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "wafio-https-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        let pki = Pki(dir);
        pki.openssl(&[
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
            &pki.path("ca.key"),
            "-out",
            &pki.path("ca.crt"),
        ]);
        pki
    }

    fn path(&self, file: &str) -> String {
        self.0.join(file).to_str().unwrap().to_owned()
    }

    fn openssl(&self, args: &[&str]) {
        let out = Command::new("openssl")
            .args(args)
            .output()
            .expect("openssl is installed");
        assert!(out.status.success(), "openssl {} failed", args[0]);
    }

    /// A new certificate for `hosts`, with its own key, signed by this authority.
    fn leaf(&self, name: &str, hosts: &[&str]) -> CertFiles {
        let (key, csr, ext, crt) = (
            self.path(&format!("{name}.key")),
            self.path(&format!("{name}.csr")),
            self.path(&format!("{name}.ext")),
            self.path(&format!("{name}.crt")),
        );
        self.openssl(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-subj",
            &format!("/CN={name}"),
            "-keyout",
            &key,
            "-out",
            &csr,
        ]);
        let names: Vec<_> = hosts.iter().map(|h| format!("DNS:{h}")).collect();
        fs::write(
            &ext,
            format!(
                "subjectAltName={}\nbasicConstraints=CA:FALSE\n",
                names.join(",")
            ),
        )
        .unwrap();
        self.openssl(&[
            "x509",
            "-req",
            "-in",
            &csr,
            "-CA",
            &self.path("ca.crt"),
            "-CAkey",
            &self.path("ca.key"),
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            &ext,
            "-out",
            &crt,
        ]);
        CertFiles {
            certificate: crt.into(),
            key: key.into(),
        }
    }

    /// A client that trusts this authority and offers `http/1.1`. Every call gives a client with
    /// no session to resume, so its ClientHello is the same each time.
    fn client_config(&self) -> Arc<ClientConfig> {
        pingora::tls::install_default_crypto_provider();
        let mut roots = RootCertStore::empty();
        let ca = CertificateDer::from_pem_slice(&fs::read(self.path("ca.crt")).unwrap()).unwrap();
        roots.add(ca).unwrap();
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
}

impl Pki {
    /// As `client_config`, offering `alpn` in the ClientHello (none: no ALPN extension).
    fn client_config_alpn(&self, alpn: &[&[u8]]) -> Arc<ClientConfig> {
        let mut config = Arc::unwrap_or_clone(self.client_config());
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A TCP stream that keeps what is written to it: the first bytes are the ClientHello.
struct Tap {
    inner: TcpStream,
    written: Arc<Mutex<Vec<u8>>>,
    /// Splits the first write: `at` bytes go out at once, the rest once `pause` has run.
    cut: Option<(usize, Pin<Box<tokio::time::Sleep>>)>,
}

impl AsyncRead for Tap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tap {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let mut data = data;
        if let Some((at, pause)) = &mut this.cut {
            if this.written.lock().unwrap().is_empty() {
                data = &data[..data.len().min(*at)];
            } else if pause.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
        let polled = Pin::new(&mut this.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &polled {
            this.written.lock().unwrap().extend_from_slice(&data[..*n]);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A keep-alive HTTPS client connection.
struct Https(BufReader<ClientTlsStream<Tap>>);

impl Https {
    /// Connects to `port` with `sni` as the server name; an error when the handshake fails.
    async fn connect(port: u16, pki: &Pki, sni: &str) -> io::Result<Https> {
        Https::connect_cut(port, pki, sni, None).await
    }

    /// As `connect`; with `cut` = `(at, pause)` the ClientHello goes out in two TCP writes, `at`
    /// bytes in and the rest `pause` after connecting.
    async fn connect_cut(
        port: u16,
        pki: &Pki,
        sni: &str,
        cut: Option<(usize, Duration)>,
    ) -> io::Result<Https> {
        Https::connect_as(port, pki.client_config(), sni, cut).await
    }

    /// As `connect_cut` for any client config. With `cut` = `(usize::MAX, pause)` the whole
    /// ClientHello goes out at once and everything after it, the client's `Finished`, waits until
    /// `pause` has passed since connecting: the server is mid-handshake meanwhile.
    async fn connect_as(
        port: u16,
        config: Arc<ClientConfig>,
        sni: &str,
        cut: Option<(usize, Duration)>,
    ) -> io::Result<Https> {
        let tap = Tap {
            inner: TcpStream::connect(("127.0.0.1", port)).await?,
            written: Arc::default(),
            cut: cut.map(|(at, pause)| (at, Box::pin(tokio::time::sleep(pause)))),
        };
        let name = ServerName::try_from(sni.to_owned()).unwrap();
        let tls = TlsConnector::from(config).connect(name, tap).await?;
        Ok(Https(BufReader::new(tls)))
    }

    /// How long until the server ends the connection (a close or a reset), `None` when it is
    /// still open after `max`.
    async fn closed_within(&mut self, max: Duration) -> Option<Duration> {
        let start = Instant::now();
        let mut sink = [0u8; 256];
        let end = async { while matches!(self.0.read(&mut sink).await, Ok(n) if n > 0) {} };
        tokio::time::timeout(max, end).await.ok()?;
        Some(start.elapsed())
    }

    async fn send(&mut self, raw: &[u8]) -> io::Result<ReplyParts> {
        self.0.get_mut().write_all(raw).await?;
        read_reply(&mut self.0).await
    }

    fn certificate(&self) -> Vec<u8> {
        let (_, session) = self.0.get_ref().get_ref();
        session.peer_certificates().unwrap()[0].as_ref().to_vec()
    }

    fn alpn(&self) -> Option<Vec<u8>> {
        let (_, session) = self.0.get_ref().get_ref();
        session.alpn_protocol().map(<[u8]>::to_vec)
    }

    /// The JA4 of the ClientHello this client sent.
    fn ja4(&self) -> String {
        let (tap, _) = self.0.get_ref().get_ref();
        let sent = tap.written.lock().unwrap();
        wafio_proxy::client_hello::parse(&sent)
            .expect("the first bytes are a ClientHello")
            .ja4
    }
}

fn get_host(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
}

fn url(upstream: &TestUpstream) -> String {
    format!("http://{}", upstream.addr)
}

/// `a` also served over HTTPS on `port` for `hosts`.
fn with_tls(mut a: AppSpec, port: u16, hosts: &[&str], files: &CertFiles) -> AppSpec {
    a.tls = Some(TlsSite {
        listen: format!("127.0.0.1:{port}"),
        hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
        certificate: BookChange::Set(BookEntry {
            key: key_of(files),
            placeholder: false,
        }),
        redirect_listen: None,
        canonical_host: None,
    });
    a
}

/// An app served over HTTPS on `port` for `hosts` and not on any bundle listener.
fn tls_app(
    id: &str,
    upstream: &TestUpstream,
    port: u16,
    hosts: &[&str],
    files: &CertFiles,
) -> AppSpec {
    with_tls(app(id, 0, &url(upstream)), port, hosts, files)
}

/// A proxy whose options `configure` changes.
fn harness_with(configure: impl FnOnce(&mut ProxyOptions)) -> Harness {
    let events: Events = Arc::default();
    let sink = events.clone();
    let mut opts = ProxyOptions::new(Arc::new(move |e| sink.lock().unwrap().push(e)));
    configure(&mut opts);
    Harness {
        proxy: Proxy::new(opts),
        events,
    }
}

/// Runs `attempt` until it gives a value.
async fn until<T, F: Future<Output = Option<T>>>(what: &str, mut attempt: impl FnMut() -> F) -> T {
    for _ in 0..100 {
        if let Some(value) = attempt().await {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}: not seen within five seconds");
}

#[tokio::test]
async fn an_https_request_reaches_the_upstream_on_a_connection_that_stays_open() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();

    let mut client = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(client.alpn().as_deref(), Some(&b"http/1.1"[..]));
    for _ in 0..3 {
        let r = client
            .send(&get_host("shop.test", "/cart?a=1"))
            .await
            .unwrap();
        assert_eq!((r.status, r.text()), (200, "ok".to_owned()));
    }
    let seen = up.last();
    assert_eq!(seen.line, "GET /cart?a=1 HTTP/1.1");
    assert_eq!(seen.header("x-forwarded-proto"), Some("https"));
    assert_eq!(seen.header("x-forwarded-host"), Some("shop.test"));
    assert_eq!(
        seen.header("x-real-ip"),
        Some("127.0.0.1"),
        "the peer address is found through the TLS stream"
    );
    assert_eq!(up.count(), 3);
    assert_eq!(h.proxy.addresses(), vec![format!("127.0.0.1:{port}")]);
}

#[tokio::test]
async fn a_client_that_does_not_speak_tls_is_closed_without_an_http_answer() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();

    let mut plain = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    plain.write_all(&get_host("shop.test", "/")).await.unwrap();
    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), plain.read_to_end(&mut answer));
    assert!(read.await.is_ok(), "the connection is closed");
    assert!(
        !answer.starts_with(b"HTTP/"),
        "no HTTP answer on a TLS port"
    );
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn apps_on_one_listener_are_told_apart_by_host_and_each_has_its_own_certificate() {
    let (ua, ub) = (
        http_upstream_with("X-Tag: a\r\n", b"ok").await,
        http_upstream_with("X-Tag: b\r\n", b"ok").await,
    );
    let pki = Pki::new();
    let fa = pki.leaf("a", &["a.test"]);
    let fb = pki.leaf("b", &["b.test", "www.b.test"]);
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![
            tls_app("a", &ua, port, &["a.test"], &fa),
            tls_app("b", &ub, port, &["b.test", "www.b.test"], &fb),
        ])
        .unwrap();

    let mut ca = Https::connect(port, &pki, "a.test").await.unwrap();
    let mut cb = Https::connect(port, &pki, "b.test").await.unwrap();
    let mut cw = Https::connect(port, &pki, "www.b.test").await.unwrap();
    assert_eq!(
        ca.send(&get_host("a.test", "/"))
            .await
            .unwrap()
            .header("x-tag"),
        Some("a")
    );
    assert_eq!(
        cb.send(&get_host("b.test", "/"))
            .await
            .unwrap()
            .header("x-tag"),
        Some("b")
    );
    assert_eq!(
        cw.send(&get_host("WWW.b.test:443", "/"))
            .await
            .unwrap()
            .header("x-tag"),
        Some("b"),
        "the host is matched without case and port"
    );
    assert_ne!(ca.certificate(), cb.certificate());
    assert_eq!(cb.certificate(), cw.certificate());
    assert_eq!((ua.count(), ub.count()), (1, 2));
}

#[tokio::test]
async fn a_host_that_differs_from_the_sni_name_gets_421_and_reaches_no_app() {
    let (ua, ub) = (http_upstream().await, http_upstream().await);
    let pki = Pki::new();
    let (fa, fb) = (pki.leaf("a", &["a.test"]), pki.leaf("b", &["b.test"]));
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![
            tls_app("a", &ua, port, &["a.test"], &fa),
            tls_app("b", &ub, port, &["b.test"], &fb),
        ])
        .unwrap();

    // The other app's host over a connection made for this one's certificate.
    let mut c = Https::connect(port, &pki, "a.test").await.unwrap();
    let r = c.send(&get_host("b.test", "/")).await.unwrap();
    assert_eq!(r.status, 421);
    assert_eq!(r.header("connection"), Some("close"));
    // A name no app serves is not routed to the first app either.
    let mut c = Https::connect(port, &pki, "a.test").await.unwrap();
    assert_eq!(
        c.send(&get_host("nobody.test", "/")).await.unwrap().status,
        421
    );
    // No Host header at all (HTTP/1.1 requires one, HTTP/1.0 does not).
    let mut c = Https::connect(port, &pki, "a.test").await.unwrap();
    assert_eq!(c.send(b"GET / HTTP/1.0\r\n\r\n").await.unwrap().status, 421);
    assert_eq!((ua.count(), ub.count()), (0, 0));
    // No certificate fits a name that no app serves, so the handshake ends before any request.
    assert!(Https::connect(port, &pki, "nobody.test").await.is_err());
}

#[tokio::test]
async fn the_plain_listener_redirects_every_method_to_https_and_keeps_host_path_and_query() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let (port, plain) = (free_port(), free_port());
    let mut a = tls_app("shop", &up, port, &["shop.test"], &files);
    a.tls.as_mut().unwrap().redirect_listen = Some(format!("127.0.0.1:{plain}"));
    let h = Harness::new();
    h.proxy.apply(vec![a]).unwrap();
    let to = format!("127.0.0.1:{plain}").parse().unwrap();

    let r = one(to, &get_host("shop.test:80", "/a/b?c=d")).await;
    assert_eq!(r.status, 308);
    assert_eq!(
        r.header("location"),
        Some(format!("https://shop.test:{port}/a/b?c=d").as_str())
    );
    assert_eq!(r.header("connection"), Some("close"));
    let post = b"POST /pay HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 3\r\n\r\nabc";
    let r = one(to, post).await;
    assert_eq!(r.status, 308);
    assert_eq!(
        r.header("location"),
        Some(format!("https://shop.test:{port}/pay").as_str())
    );
    assert_eq!(one(to, &get_host("other.test", "/")).await.status, 404);
    assert_eq!(up.count(), 0, "nothing is proxied by the redirect listener");
}

/// The key of a pair of files, as the book holds it.
fn key_of(files: &CertFiles) -> Arc<CertifiedKey> {
    let pem = [
        fs::read(&files.key).unwrap(),
        fs::read(&files.certificate).unwrap(),
    ]
    .concat();
    Arc::new(certified_key_from_pem(&pem).unwrap())
}

/// The DER of the leaf of a pair of files.
fn leaf_of(files: &CertFiles) -> Vec<u8> {
    key_of(files).cert[0].as_ref().to_vec()
}

#[tokio::test]
async fn an_apply_that_names_a_certificate_switches_it_and_one_that_names_none_leaves_it() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    let mut open = Https::connect(port, &pki, "shop.test").await.unwrap();
    let before = open.certificate();
    assert_eq!(
        open.send(&get_host("shop.test", "/")).await.unwrap().status,
        200
    );

    // An app that brings no certificate keeps the one the book holds.
    let mut keeps = tls_app("shop", &up, port, &["shop.test"], &files);
    keeps.tls.as_mut().unwrap().certificate = BookChange::Keep;
    h.proxy.apply(vec![keeps]).unwrap();
    let unchanged = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(unchanged.certificate(), before);

    let renewed = pki.leaf("renewed", &["shop.test"]);
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &renewed)])
        .unwrap();
    let mut fresh = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_ne!(fresh.certificate(), before);
    assert_eq!(fresh.certificate(), leaf_of(&renewed));
    assert_eq!(
        fresh
            .send(&get_host("shop.test", "/"))
            .await
            .unwrap()
            .status,
        200
    );
    assert_eq!(
        open.send(&get_host("shop.test", "/")).await.unwrap().status,
        200
    );
    assert_eq!(
        open.certificate(),
        before,
        "an open connection keeps its handshake"
    );
}

#[tokio::test]
async fn an_apply_that_clears_the_certificate_stops_serving_it_until_one_is_named_again() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    assert!(Https::connect(port, &pki, "shop.test").await.is_ok());

    let mut cleared = tls_app("shop", &up, port, &["shop.test"], &files);
    cleared.tls.as_mut().unwrap().certificate = BookChange::Clear;
    h.proxy.apply(vec![cleared]).unwrap();
    assert!(h.proxy.certificates().get("shop").is_none());
    assert!(
        Https::connect(port, &pki, "shop.test").await.is_err(),
        "the certificate the bundle no longer names is not served"
    );

    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    assert!(Https::connect(port, &pki, "shop.test").await.is_ok());
}

#[tokio::test]
async fn the_book_switches_one_apps_certificate_and_an_apply_follows_the_bundle() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let (files, installed) = (
        pki.leaf("shop", &["shop.test"]),
        pki.leaf("installed", &["shop.test"]),
    );
    let port = free_port();
    let h = Harness::new();
    let book = h.proxy.certificates();
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    let held = book.get("shop").unwrap();
    assert!(!held.placeholder);
    assert_eq!(held.key.cert, key_of(&files).cert);

    let mut open = Https::connect(port, &pki, "shop.test").await.unwrap();
    let before = open.certificate();
    assert!(book.set("shop", key_of(&installed), false));
    let fresh = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(fresh.certificate(), leaf_of(&installed));
    assert_eq!(open.certificate(), before);
    assert_eq!(
        open.send(&get_host("shop.test", "/")).await.unwrap().status,
        200
    );

    // The book holds the apps of the bundle and no others, and takes nothing for an app that left:
    // a certificate that finishes after its app was dropped is refused.
    h.proxy.apply(vec![]).unwrap();
    assert!(book.get("shop").is_none());
    assert!(!book.set("shop", key_of(&installed), false));
    assert!(book.get("shop").is_none());
}

#[tokio::test]
async fn a_reload_keeps_the_https_listener_and_changes_what_it_serves() {
    let (u1, u2, ub) = (
        http_upstream_with("X-Tag: u1\r\n", b"ok").await,
        http_upstream_with("X-Tag: u2\r\n", b"ok").await,
        http_upstream_with("X-Tag: b\r\n", b"ok").await,
    );
    let pki = Pki::new();
    let (fa, fb) = (pki.leaf("a", &["a.test"]), pki.leaf("b", &["b.test"]));
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![tls_app("a", &u1, port, &["a.test"], &fa)])
        .unwrap();
    let mut open = Https::connect(port, &pki, "a.test").await.unwrap();
    assert_eq!(
        open.send(&get_host("a.test", "/"))
            .await
            .unwrap()
            .header("x-tag"),
        Some("u1")
    );
    assert!(Https::connect(port, &pki, "b.test").await.is_err());

    // A new upstream for the app and a second app on the same listener.
    h.proxy
        .apply(vec![
            tls_app("a", &u2, port, &["a.test"], &fa),
            tls_app("b", &ub, port, &["b.test"], &fb),
        ])
        .unwrap();
    assert_eq!(
        open.send(&get_host("a.test", "/"))
            .await
            .unwrap()
            .header("x-tag"),
        Some("u2"),
        "the open connection follows the new route"
    );
    let mut b = Https::connect(port, &pki, "b.test").await.unwrap();
    assert_eq!(
        b.send(&get_host("b.test", "/"))
            .await
            .unwrap()
            .header("x-tag"),
        Some("b")
    );

    // A host that two apps claim, and a plain app on the address of an HTTPS one, are refused.
    let twice = vec![
        tls_app("a", &u1, port, &["a.test"], &fa),
        tls_app("b", &ub, port, &["a.test"], &fb),
    ];
    assert_eq!(
        h.proxy.apply(twice),
        Err("invalid TLS site settings".into())
    );
    assert_eq!(
        h.proxy.apply(vec![
            tls_app("a", &u1, port, &["a.test"], &fa),
            app("plain", port, &url(&u1))
        ]),
        Err("duplicate listener in WAF bundle".into())
    );
    assert_eq!(
        open.send(&get_host("a.test", "/"))
            .await
            .unwrap()
            .header("x-tag"),
        Some("u2")
    );

    // Dropping the HTTPS apps closes the port.
    h.proxy.apply(vec![]).unwrap();
    assert!(Https::connect(port, &pki, "a.test").await.is_err());
}

/// Rules that block the clients whose JA4 is listed.
fn block_ja4(ja4: &str) -> String {
    format!(
        r#"{{"bot_protection":{{"enabled":true,"mode":"block","base_score":100,"ja4_blocklist":["{ja4}"]}}}}"#
    )
}

#[tokio::test]
async fn the_ja4_of_the_handshake_reaches_the_analysis_and_a_header_cannot_replace_it() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = Harness::new();
    let site = |rules: &str| {
        let mut a = tls_app("shop", &up, port, &["shop.test"], &files);
        a.analysis = analysis_setup(rules);
        a
    };
    h.proxy.apply(vec![site(RULES)]).unwrap();

    let mut probe = Https::connect(port, &pki, "shop.test").await.unwrap();
    let ja4 = probe.ja4();
    assert!(ja4.starts_with("t13d"), "{ja4}");
    assert_eq!(
        probe
            .send(&get_host("shop.test", "/"))
            .await
            .unwrap()
            .status,
        200
    );

    // The same hello is now on the block list: the agent computed it, no header named it.
    h.proxy.apply(vec![site(&block_ja4(&ja4))]).unwrap();
    let mut blocked = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(blocked.ja4(), ja4);
    assert_eq!(
        blocked
            .send(&get_host("shop.test", "/"))
            .await
            .unwrap()
            .status,
        403
    );
    assert!(s(&h.last_event().match_detail).contains(&format!("ja4:{ja4}")));

    // A listed value in a header is not what this client's JA4 is.
    let spoof = "t13d0000h2_000000000000_000000000000";
    // The peer is a trusted proxy here, so only the computed value keeps the header out.
    let mut trusting = site(&block_ja4(spoof));
    trusting.proxy_config = br#"{"trust_forwarded":true}"#.to_vec();
    h.proxy.apply(vec![trusting]).unwrap();
    let mut c = Https::connect(port, &pki, "shop.test").await.unwrap();
    let raw = format!("GET / HTTP/1.1\r\nHost: shop.test\r\nX-JA4: {spoof}\r\n\r\n");
    assert_eq!(c.send(raw.as_bytes()).await.unwrap().status, 200);
}

#[tokio::test]
async fn an_app_served_over_tls_opens_no_listener_at_its_bundle_address() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let (port, plain) = (free_port(), free_port());
    let mut a = tls_app("shop", &up, port, &["shop.test"], &files);
    a.listen_port = plain;
    let h = Harness::new();
    h.proxy.apply(vec![a]).unwrap();

    assert_eq!(h.proxy.addresses(), vec![format!("127.0.0.1:{port}")]);
    assert!(TcpStream::connect(("127.0.0.1", plain)).await.is_err());
    let mut c = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(
        c.send(&get_host("shop.test", "/")).await.unwrap().status,
        200
    );

    // An app the agent does not serve over TLS keeps its listener and reads a client's JA4 header.
    let spoof = "t13d0000h2_000000000000_000000000000";
    let other = free_port();
    let mut b = app("plain", other, &url(&up));
    b.analysis = analysis_setup(&block_ja4(spoof));
    h.proxy.apply(vec![b]).unwrap();
    let raw = format!("GET / HTTP/1.1\r\nHost: shop.test\r\nX-JA4: {spoof}\r\n\r\n");
    let to: SocketAddr = format!("127.0.0.1:{other}").parse().unwrap();
    assert_eq!(one(to, raw.as_bytes()).await.status, 403);
}

#[tokio::test]
async fn a_client_hello_sent_in_two_tcp_writes_still_handshakes_and_gets_its_ja4() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = Harness::new();
    let site = |rules: &str| {
        let mut a = tls_app("shop", &up, port, &["shop.test"], &files);
        a.analysis = analysis_setup(rules);
        a
    };
    h.proxy.apply(vec![site(RULES)]).unwrap();
    let ja4 = Https::connect(port, &pki, "shop.test").await.unwrap().ja4();

    // Only a JA4 the agent computed from the whole hello can match the one listed here.
    h.proxy.apply(vec![site(&block_ja4(&ja4))]).unwrap();
    let pause = Duration::from_millis(150);
    // Inside the record header, between header and payload, inside the hello.
    for at in [3, 5, 40] {
        let mut c = Https::connect_cut(port, &pki, "shop.test", Some((at, pause)))
            .await
            .unwrap_or_else(|e| panic!("cut at {at}: {e}"));
        assert_eq!(c.ja4(), ja4, "cut at {at}: the client sent the same hello");
        let r = c.send(&get_host("shop.test", "/")).await.unwrap();
        assert_eq!(r.status, 403, "cut at {at}");
        let detail = h.last_event().match_detail;
        assert!(s(&detail).contains(&format!("ja4:{ja4}")), "cut at {at}");
    }
}

/// A client that sent `sent` to an HTTPS port and nothing more holds the port's only connection
/// slot until the handshake deadline, when the agent closes it without an answer.
async fn stalled_handshake_is_closed_at_the_deadline(sent: &[u8]) {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let deadline = Duration::from_millis(500);
    let h = harness_with(|opts| {
        opts.tls_handshake_timeout = deadline;
        opts.connection_limit = 1;
    });
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();

    let mut stalled = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stalled.write_all(sent).await.unwrap();
    let start = Instant::now();
    assert!(
        Https::connect(port, &pki, "shop.test").await.is_err(),
        "the stalled client holds the only slot"
    );
    let mut answer = Vec::new();
    let read = stalled.read_to_end(&mut answer);
    let closed = tokio::time::timeout(Duration::from_secs(5), read).await;
    assert!(
        matches!(closed, Ok(Ok(_))),
        "closed by the agent: {closed:?}"
    );
    assert!(
        start.elapsed() >= deadline / 2,
        "closed at the deadline, not before: {:?}",
        start.elapsed()
    );
    assert!(answer.is_empty(), "no answer");

    let mut c = until("the slot of the stalled client", || async {
        Https::connect(port, &pki, "shop.test").await.ok()
    })
    .await;
    assert_eq!(
        c.send(&get_host("shop.test", "/")).await.unwrap().status,
        200
    );
}

#[tokio::test]
async fn a_client_that_sends_nothing_is_closed_at_the_handshake_deadline_and_its_slot_is_free_again()
 {
    stalled_handshake_is_closed_at_the_deadline(b"").await;
}

#[tokio::test]
async fn a_client_that_announces_the_largest_record_and_sends_none_of_it_is_closed_at_the_handshake_deadline()
 {
    // The header of a handshake record whose payload is 16384 bytes long.
    stalled_handshake_is_closed_at_the_deadline(&[0x16, 0x03, 0x01, 0x40, 0x00]).await;
}

#[tokio::test]
async fn past_the_connection_limit_a_tls_client_is_closed_unanswered_and_a_freed_slot_is_usable_again()
 {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = harness_with(|opts| opts.connection_limit = 2);
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    let ask = get_host("shop.test", "/");
    let mut a = Https::connect(port, &pki, "shop.test").await.unwrap();
    let mut b = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(a.send(&ask).await.unwrap().status, 200);
    assert_eq!(b.send(&ask).await.unwrap().status, 200);

    // Neither a handshake nor an HTTP answer: the connection is closed as it is accepted.
    let mut third = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut answer = Vec::new();
    let read = third.read_to_end(&mut answer);
    let closed = tokio::time::timeout(Duration::from_secs(5), read).await;
    assert!(
        matches!(closed, Ok(Ok(_))),
        "closed by the agent: {closed:?}"
    );
    assert!(answer.is_empty(), "no answer");
    assert!(Https::connect(port, &pki, "shop.test").await.is_err());
    assert_eq!(a.send(&ask).await.unwrap().status, 200);
    assert_eq!(b.send(&ask).await.unwrap().status, 200);

    drop(a);
    let mut c = until("the slot of the closed connection", || async {
        Https::connect(port, &pki, "shop.test").await.ok()
    })
    .await;
    assert_eq!(c.send(&ask).await.unwrap().status, 200);
    assert_eq!(b.send(&ask).await.unwrap().status, 200);
    assert!(
        Https::connect(port, &pki, "shop.test").await.is_err(),
        "the limit still holds with the freed slot taken"
    );
}

/// A FastCGI app served over HTTPS on `port` and on no bundle listener.
fn php_app(fcgi: SocketAddr, port: u16, files: &CertFiles) -> AppSpec {
    let a = fcgi_app(0, format!("fcgi://{fcgi}"), "/var/www", "");
    with_tls(a, port, &["shop.test"], files)
}

/// The params of the last request the fake FastCGI responder got.
fn last_params(fake: &Fake) -> HashMap<String, String> {
    fake.params.lock().unwrap().last().cloned().unwrap()
}

#[tokio::test]
async fn a_fastcgi_app_over_tls_is_told_https_and_the_https_port() {
    let (fcgi, fake) = fake_fcgi().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = Harness::new();
    h.proxy.apply(vec![php_app(fcgi, port, &files)]).unwrap();

    let mut c = Https::connect(port, &pki, "shop.test").await.unwrap();
    let r = c.send(&get_host("shop.test", "/index.php")).await.unwrap();
    assert_eq!(r.status, 201);
    let p = last_params(&fake);
    assert_eq!(
        (p["HTTPS"].as_str(), p["SERVER_PORT"].as_str()),
        ("on", "443")
    );
    assert_eq!(p["HTTP_X_FORWARDED_PROTO"], "https");

    // A Host that names the port keeps it: the app is on that port.
    let named = get_host(&format!("shop.test:{port}"), "/index.php");
    assert_eq!(c.send(&named).await.unwrap().status, 201);
    let p = last_params(&fake);
    assert_eq!(
        (p["HTTPS"].as_str(), p["SERVER_PORT"].as_str()),
        ("on", port.to_string().as_str())
    );
}

#[tokio::test]
async fn a_client_header_in_any_spelling_cannot_turn_https_off_for_a_fastcgi_app_over_tls() {
    let (fcgi, fake) = fake_fcgi().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = Harness::new();
    h.proxy.apply(vec![php_app(fcgi, port, &files)]).unwrap();

    let mut c = Https::connect(port, &pki, "shop.test").await.unwrap();
    // Each spelling becomes HTTP_X_FORWARDED_PROTO; the last of a repeated param wins in PHP-FPM.
    for headers in [
        "X-Forwarded-Proto: http",
        "x-forwarded-proto: http",
        "X_Forwarded_Proto: http",
        "x-forwarded_proto: http",
        "X-FORWARDED-PROTO: HTTP",
        "X-Forwarded-Proto: http\r\nX_Forwarded_Proto: http\r\nx-forwarded_proto: http",
    ] {
        let raw = format!("GET /index.php HTTP/1.1\r\nHost: shop.test\r\n{headers}\r\n\r\n");
        assert_eq!(c.send(raw.as_bytes()).await.unwrap().status, 201);
        let p = last_params(&fake);
        assert_eq!(
            (
                p.get("HTTPS").map(String::as_str),
                p["SERVER_PORT"].as_str(),
                p["HTTP_X_FORWARDED_PROTO"].as_str()
            ),
            (Some("on"), "443", "https"),
            "{headers:?}"
        );
    }
}

/// `a` with its `proxy_config` set.
fn configured(mut a: AppSpec, proxy_config: &str) -> AppSpec {
    a.proxy_config = proxy_config.as_bytes().to_vec();
    a
}

/// The inode of the socket behind a listening address: the same inode is the same socket.
fn socket_of(h: &Harness, address: &str) -> u64 {
    let fd = h
        .proxy
        .handover_fds()
        .into_iter()
        .find(|(a, _)| a == address)
        .expect("a listener at the address")
        .1;
    fs::metadata(format!("/proc/self/fd/{fd}")).unwrap().ino()
}

/// Connects to `to` over and over until `stop`; how many tries were made and how the failed ones
/// failed.
async fn connect_until(to: SocketAddr, stop: Arc<AtomicBool>) -> (usize, Vec<String>) {
    let (mut tries, mut failures) = (0, Vec::new());
    while !stop.load(Ordering::Relaxed) {
        tries += 1;
        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(to)).await {
            Ok(Ok(_)) => {}
            other => failures.push(format!("{other:?}")),
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    (tries, failures)
}

#[tokio::test]
async fn an_address_changes_from_a_plain_app_to_a_redirect_on_the_same_socket() {
    let up = http_upstream_delayed("", b"ok", Duration::from_millis(400)).await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let (plain, tls) = (free_port(), free_port());
    let (address, to) = (
        format!("127.0.0.1:{plain}"),
        format!("127.0.0.1:{plain}").parse::<SocketAddr>().unwrap(),
    );
    let h = Harness::new();
    h.proxy.apply(vec![app("shop", plain, &url(&up))]).unwrap();
    let socket = socket_of(&h, &address);

    // A request is in flight on the plain app, and clients keep connecting, while the address
    // becomes the redirect listener of an app served over TLS.
    let in_flight = tokio::spawn(async move {
        Client::connect(to)
            .await
            .unwrap()
            .send(&get_host("shop.test", "/"))
            .await
    });
    let stop = Arc::new(AtomicBool::new(false));
    let probe = tokio::spawn(connect_until(to, stop.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut redirect = tls_app("shop", &up, tls, &["shop.test"], &files);
    redirect.tls.as_mut().unwrap().redirect_listen = Some(address.clone());
    h.proxy.apply(vec![redirect]).unwrap();
    assert_eq!(socket_of(&h, &address), socket, "bound again");

    let r = in_flight.await.unwrap().unwrap();
    assert_eq!((r.status, r.text()), (200, "ok".to_owned()));
    let r = one(to, &get_host("shop.test", "/cart?a=1")).await;
    assert_eq!(r.status, 308);
    assert_eq!(
        r.header("location"),
        Some(format!("https://shop.test:{tls}/cart?a=1").as_str())
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop.store(true, Ordering::Relaxed);
    let (tries, failures) = probe.await.unwrap();
    assert!(tries >= 20, "{tries} tries");
    assert!(failures.is_empty(), "{failures:?}");
    let mut live = h.proxy.addresses();
    let mut wanted = vec![address, format!("127.0.0.1:{tls}")];
    live.sort();
    wanted.sort();
    assert_eq!(live, wanted);
}

#[tokio::test]
async fn an_address_changes_from_https_to_a_plain_app_on_the_same_socket() {
    let up = http_upstream_delayed("", b"ok", Duration::from_millis(400)).await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let (address, to) = (
        format!("127.0.0.1:{port}"),
        format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap(),
    );
    let h = Harness::new();
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    let socket = socket_of(&h, &address);
    let mut open = Https::connect(port, &pki, "shop.test").await.unwrap();
    let in_flight = tokio::spawn(async move { open.send(&get_host("shop.test", "/")).await });
    let stop = Arc::new(AtomicBool::new(false));
    let probe = tokio::spawn(connect_until(to, stop.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    h.proxy.apply(vec![app("shop", port, &url(&up))]).unwrap();
    assert_eq!(socket_of(&h, &address), socket, "bound again");
    let r = in_flight.await.unwrap().unwrap();
    assert_eq!((r.status, r.text()), (200, "ok".to_owned()));
    let r = one(to, &get_host("shop.test", "/")).await;
    assert_eq!((r.status, r.text()), (200, "ok".to_owned()));
    assert!(Https::connect(port, &pki, "shop.test").await.is_err());
    stop.store(true, Ordering::Relaxed);
    let (tries, failures) = probe.await.unwrap();
    assert!(tries >= 20, "{tries} tries");
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(h.proxy.addresses(), vec![address]);
}

/// A request whose head is exactly `len` bytes.
fn head_of_len(host: &str, len: usize) -> Vec<u8> {
    let (start, end) = (
        format!("GET /pad HTTP/1.1\r\nHost: {host}\r\nX-Pad: "),
        "\r\n\r\n",
    );
    let pad = "a".repeat(len - start.len() - end.len());
    format!("{start}{pad}{end}").into_bytes()
}

/// A request with a body of `len` bytes, whose head is sent at once and whose body is not.
fn post_head(host: &str, len: usize) -> Vec<u8> {
    format!("POST /up HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len}\r\n\r\n").into_bytes()
}

/// Two apps, `a.test` and `b.test`, that share one HTTPS listener.
struct Pair {
    h: Harness,
    pki: Pki,
    port: u16,
    ua: TestUpstream,
    ub: TestUpstream,
    files: (CertFiles, CertFiles),
}

impl Pair {
    async fn new(a: &str, b: &str) -> Pair {
        let pki = Pki::new();
        let files = (pki.leaf("a", &["a.test"]), pki.leaf("b", &["b.test"]));
        let pair = Pair {
            h: Harness::new(),
            port: free_port(),
            ua: http_upstream().await,
            ub: http_upstream().await,
            pki,
            files,
        };
        pair.apply(a, b).unwrap();
        pair
    }

    fn apply(&self, a: &str, b: &str) -> Result<(), String> {
        self.h.proxy.apply(vec![
            configured(
                tls_app("a", &self.ua, self.port, &["a.test"], &self.files.0),
                a,
            ),
            configured(
                tls_app("b", &self.ub, self.port, &["b.test"], &self.files.1),
                b,
            ),
        ])
    }

    async fn connect(&self, name: &str) -> Https {
        Https::connect(self.port, &self.pki, name).await.unwrap()
    }
}

#[tokio::test]
async fn on_a_shared_listener_the_head_is_read_with_the_largest_buffer_and_held_to_the_apps_own() {
    let pair = Pair::new("", r#"{"read_buf":65536}"#).await;
    // a's buffer holds 16384 bytes, b's 65536; the listener reads with the larger.
    for (name, len, status) in [
        ("a.test", 16384, 200),
        ("a.test", 16385, 431),
        ("a.test", 40000, 431),
        ("b.test", 16385, 200),
        ("b.test", 65536, 200),
        ("b.test", 65537, 431),
    ] {
        let mut c = pair.connect(name).await;
        let r = c.send(&head_of_len(name, len)).await.unwrap();
        assert_eq!(r.status, status, "{name} {len}");
        if status == 431 {
            assert_eq!(r.header("connection"), Some("close"), "{name} {len}");
        }
    }
    assert_eq!(
        (pair.ua.count(), pair.ub.count()),
        (1, 2),
        "431 reaches no app"
    );
}

#[tokio::test]
async fn on_a_shared_listener_the_head_may_take_the_largest_finite_timeout_and_the_body_the_apps_own()
 {
    let pair = Pair::new(
        r#"{"timeouts":{"read_ms":800}}"#,
        r#"{"timeouts":{"read_ms":2400}}"#,
    )
    .await;

    // A head that takes longer than a's timeout reaches a: a has no body to wait for.
    let mut slow = pair.connect("a.test").await;
    let head = get_host("a.test", "/slow-head");
    slow.0.get_mut().write_all(&head[..12]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    slow.0.get_mut().write_all(&head[12..]).await.unwrap();
    assert_eq!(read_reply(&mut slow.0).await.unwrap().status, 200);

    // A body that comes 1.2 s after its head is late for a and in time for b.
    let late_body = |name: &'static str| {
        let c = pair.connect(name);
        async move {
            let mut c = c.await;
            c.0.get_mut().write_all(&post_head(name, 4)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(1200)).await;
            let _ = c.0.get_mut().write_all(b"abcd").await;
            read_reply(&mut c.0).await.unwrap().status
        }
    };
    let (a, b) = tokio::join!(late_body("a.test"), late_body("b.test"));
    assert_eq!((a, b), (408, 200));
}

#[tokio::test]
async fn on_a_shared_listener_with_an_unlimited_app_an_idle_connection_closes_at_the_finite_deadline()
 {
    let pair = Pair::new(
        r#"{"timeouts":{"read_ms":800}}"#,
        r#"{"timeouts":{"read_ms":-1}}"#,
    )
    .await;

    // Nothing sent: the first request never starts, whichever app it was meant for.
    let mut idle = pair.connect("b.test").await;
    let start = Instant::now();
    let r = read_reply(&mut idle.0).await.unwrap();
    assert_eq!(r.status, 408);
    assert!(
        (Duration::from_millis(700)..Duration::from_secs(3)).contains(&start.elapsed()),
        "{:?}",
        start.elapsed()
    );

    // After a request to the unlimited app the connection waits for the next one as long as the
    // finite deadline, and then ends without an answer.
    let mut kept = pair.connect("b.test").await;
    assert_eq!(
        kept.send(&get_host("b.test", "/")).await.unwrap().status,
        200
    );
    let closed = kept.closed_within(Duration::from_secs(5)).await;
    assert!(
        closed.is_some_and(|t| t >= Duration::from_millis(700) && t < Duration::from_secs(3)),
        "{closed:?}"
    );

    // Once the request is routed the unlimited app has no deadline at all, where a's applies.
    let late_body = |name: &'static str| {
        let c = pair.connect(name);
        async move {
            let mut c = c.await;
            c.0.get_mut().write_all(&post_head(name, 4)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let _ = c.0.get_mut().write_all(b"abcd").await;
            read_reply(&mut c.0).await.unwrap().status
        }
    };
    let (a, b) = tokio::join!(late_body("a.test"), late_body("b.test"));
    assert_eq!((a, b), (408, 200));
}

#[tokio::test]
async fn on_a_shared_listener_each_app_has_its_own_body_limit_and_limits_change_in_place() {
    let pair = Pair::new(r#"{"max_body_bytes":2048}"#, "").await;
    let upload = |host: &str, len: usize| {
        let mut raw = post_head(host, len);
        raw.extend(std::iter::repeat_n(b'x', len));
        raw
    };
    for (name, len, status) in [
        ("a.test", 1000, 200),
        ("a.test", 4096, 400),
        ("b.test", 4096, 200),
    ] {
        let r = pair
            .connect(name)
            .await
            .send(&upload(name, len))
            .await
            .unwrap();
        assert_eq!(r.status, status, "{name} {len}");
    }

    // A connection that is open when the limits change follows them; the apply is not refused.
    let mut open = pair.connect("a.test").await;
    assert_eq!(open.send(&upload("a.test", 100)).await.unwrap().status, 200);
    pair.apply(r#"{"max_body_bytes":8192,"read_buf":65536}"#, "")
        .unwrap();
    assert_eq!(
        open.send(&upload("a.test", 4096)).await.unwrap().status,
        200
    );
    assert_eq!(
        open.send(&head_of_len("a.test", 30000))
            .await
            .unwrap()
            .status,
        200
    );
}

#[tokio::test]
async fn a_connection_made_for_the_placeholder_is_answered_validations_and_503_only() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let (files, stand_in) = (
        pki.leaf("shop", &["shop.test"]),
        pki.leaf("stand-in", &["shop.test"]),
    );
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    let book = h.proxy.certificates();
    let _pending = book.offer_http01("shop.test", "tok-1", "tok-1.thumb");

    // The app has only its placeholder: the handshake succeeds, the app is not reached.
    assert!(book.set("shop", key_of(&stand_in), true));
    let mut c = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(c.certificate(), leaf_of(&stand_in));
    let r = c.send(&get_host("shop.test", "/cart")).await.unwrap();
    assert_eq!(r.status, 503);
    assert_eq!(r.header("retry-after"), Some("60"));
    assert_eq!(r.header("connection"), Some("close"));
    let mut c = Https::connect(port, &pki, "shop.test").await.unwrap();
    let r = c
        .send(&get_host("shop.test", "/.well-known/acme-challenge/tok-1"))
        .await
        .unwrap();
    assert_eq!((r.status, r.text()), (200, "tok-1.thumb".to_owned()));
    assert_eq!(up.count(), 0);

    // The real certificate arrives: new connections reach the app.
    assert!(book.set("shop", key_of(&files), false));
    let mut c = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(c.certificate(), leaf_of(&files));
    assert_eq!(
        c.send(&get_host("shop.test", "/cart"))
            .await
            .unwrap()
            .status,
        200
    );
    assert_eq!(up.count(), 1);
}

/// What a connection gets whose handshake is held half way (the client's `Finished` waits), while
/// the book changes under it: `before` is what the book holds for the app when the hello arrives,
/// `after` what it holds when the handshake ends.
async fn status_of_a_connection_that_sees_the_book_change(
    placeholder_before: bool,
    placeholder_after: bool,
) -> (u16, usize) {
    let up = http_upstream().await;
    let pki = Pki::new();
    let (files, stand_in) = (
        pki.leaf("shop", &["shop.test"]),
        pki.leaf("stand-in", &["shop.test"]),
    );
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    let book = h.proxy.certificates();
    let hold = |placeholder| {
        if placeholder {
            (key_of(&stand_in), true)
        } else {
            (key_of(&files), false)
        }
    };
    let (key, flag) = hold(placeholder_before);
    assert!(book.set("shop", key, flag));

    let connecting = tokio::spawn(Https::connect_as(
        port,
        pki.client_config(),
        "shop.test",
        Some((usize::MAX, Duration::from_millis(1200))),
    ));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (key, flag) = hold(placeholder_after);
    assert!(book.set("shop", key, flag));
    let mut c = connecting.await.unwrap().unwrap();
    let status = c
        .send(&get_host("shop.test", "/cart"))
        .await
        .unwrap()
        .status;
    (status, up.count())
}

#[tokio::test]
async fn the_placeholder_is_read_before_the_handshake_from_the_name_in_the_hello() {
    // The hello arrives while the app has the placeholder; it is the real certificate by the end.
    assert_eq!(
        status_of_a_connection_that_sees_the_book_change(true, false).await,
        (503, 0)
    );
}

#[tokio::test]
async fn the_placeholder_is_read_after_the_handshake_from_the_name_it_ended_with() {
    // The hello arrives while the app has its real certificate; the placeholder is back by the end.
    assert_eq!(
        status_of_a_connection_that_sees_the_book_change(false, true).await,
        (503, 0)
    );
    // And a connection that sees the real certificate on both sides reaches the app.
    assert_eq!(
        status_of_a_connection_that_sees_the_book_change(false, false).await,
        (200, 1)
    );
}

#[tokio::test]
async fn every_alpn_case_gets_the_certificate_and_the_ending_it_is_meant_for() {
    const ACME: &[u8] = b"acme-tls/1";
    const HTTP: &[u8] = b"http/1.1";
    let up = http_upstream().await;
    let pki = Pki::new();
    let (files, challenge) = (
        pki.leaf("shop", &["shop.test"]),
        pki.leaf("challenge", &["shop.test"]),
    );
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    let book = h.proxy.certificates();
    let connect = |name: &'static str, offered: &[&[u8]]| {
        Https::connect_as(port, pki.client_config_alpn(offered), name, None)
    };

    // A client that offers http/1.1, h2 and http/1.1, or no protocol, is served the app, with or
    // without a validation pending: the challenge key never goes to an ordinary client.
    let mut served = 0;
    for pending in [false, true] {
        let _offered = pending.then(|| book.offer_tls_alpn("shop.test", key_of(&challenge)));
        for (offered, chosen) in [
            (vec![HTTP], Some(HTTP)),
            (vec![&b"h2"[..], HTTP], Some(HTTP)),
            (vec![], None),
        ] {
            let mut c = connect("shop.test", &offered).await.unwrap();
            assert_eq!(c.alpn().as_deref(), chosen, "{offered:?} pending {pending}");
            assert_eq!(c.certificate(), leaf_of(&files));
            let r = c.send(&get_host("shop.test", "/")).await.unwrap();
            assert_eq!(r.status, 200);
            served += 1;
        }
    }

    // acme-tls/1 with no validation pending gets no handshake, also next to http/1.1.
    for offered in [vec![ACME], vec![ACME, HTTP], vec![HTTP, ACME]] {
        assert!(connect("shop.test", &offered).await.is_err(), "{offered:?}");
    }

    // With one pending it gets the challenge key, negotiates acme-tls/1 and is closed after the
    // handshake without a request being read.
    let _offered = book.offer_tls_alpn("shop.test", key_of(&challenge));
    for offered in [vec![ACME], vec![ACME, HTTP], vec![HTTP, ACME]] {
        let mut c = connect("shop.test", &offered).await.unwrap();
        assert_eq!(c.alpn().as_deref(), Some(ACME), "{offered:?}");
        assert_eq!(c.certificate(), leaf_of(&challenge));
        let closed = c.closed_within(Duration::from_secs(3)).await;
        assert!(closed.is_some(), "{offered:?}: still open");
    }

    // A name the listener does not serve is not validated even when a key is offered for it.
    let _other = book.offer_tls_alpn("nobody.test", key_of(&challenge));
    assert!(connect("nobody.test", &[ACME]).await.is_err());
    assert_eq!(up.count(), served);
}

/// The path of the HTTP-01 resource of `token`.
fn challenge_path(token: &str) -> String {
    format!("/.well-known/acme-challenge/{token}")
}

#[tokio::test]
async fn http01_is_answered_on_the_tls_listener_before_routing_and_only_for_the_pending_name() {
    let (ua, ub) = (http_upstream().await, http_upstream().await);
    let pki = Pki::new();
    let (fa, fb) = (pki.leaf("a", &["a.test"]), pki.leaf("b", &["b.test"]));
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![
            tls_app("a", &ua, port, &["a.test"], &fa),
            tls_app("b", &ub, port, &["b.test"], &fb),
        ])
        .unwrap();
    let book = h.proxy.certificates();
    let long = "t".repeat(129);
    let pending = [
        book.offer_http01("a.test", "tok-1", "tok-1.thumb"),
        book.offer_http01("a.test", &long, "too-long.thumb"),
        book.offer_http01("a.test", "tok_2", "tok_2.thumb"),
    ];
    let mut c = Https::connect(port, &pki, "a.test").await.unwrap();

    // The pending name, with a port and in any case, gets the key authorization.
    for host in ["a.test", "a.test:8443", "A.Test", "a.test."] {
        let r = c
            .send(&get_host(host, &challenge_path("tok-1")))
            .await
            .unwrap();
        assert_eq!(
            (r.status, r.text()),
            (200, "tok-1.thumb".to_owned()),
            "{host}"
        );
        assert_eq!(r.header("content-type"), Some("application/octet-stream"));
        assert_eq!(r.header("connection"), Some("close"));
        c = Https::connect(port, &pki, "a.test").await.unwrap();
    }
    assert_eq!((ua.count(), ub.count()), (0, 0), "no app is reached");

    // Before routing: a connection made for the name `a.test` is answered for any pending name.
    let _b = book.offer_http01("b.test", "tok-b", "tok-b.thumb");
    let r = c
        .send(&get_host("b.test", &challenge_path("tok-b")))
        .await
        .unwrap();
    assert_eq!((r.status, r.text()), (200, "tok-b.thumb".to_owned()));

    // What is not a validation goes on to routing, which answers as it always does: the app for a
    // path it knows, 421 for a name the connection was not set up for.
    let not_answered = [
        ("a.test", challenge_path("tok-3"), "GET"),
        ("a.test", challenge_path(&long), "GET"),
        ("a.test", challenge_path("tok-1/"), "GET"),
        ("a.test", challenge_path("tok-1?x=1"), "GET"),
        ("a.test", challenge_path("tok%2D1"), "GET"),
        ("a.test", challenge_path("tok-1."), "GET"),
        ("a.test", challenge_path(""), "GET"),
        ("a.test", "/.well-known/acme-challenge".to_owned(), "GET"),
        ("a.test", challenge_path("TOK-1"), "GET"),
        ("a.test", challenge_path("tok-1"), "POST"),
    ];
    let mut routed = 0;
    for (host, path, method) in not_answered {
        let mut c = Https::connect(port, &pki, "a.test").await.unwrap();
        let raw = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n");
        c.0.get_mut().write_all(raw.as_bytes()).await.unwrap();
        let r = read_reply(&mut c.0).await;
        // The upstream answers 200 `ok`: the app was reached, not the validation answer.
        assert!(
            r.is_ok_and(|r| (r.status, r.text()) == (200, "ok".to_owned())),
            "{method} {path}"
        );
        routed += 1;
    }
    assert_eq!(ua.count(), routed);
    // The name of another app on this connection is not served by a.test's SNI, and has no answer.
    let mut c = Https::connect(port, &pki, "a.test").await.unwrap();
    let r = c
        .send(&get_host("nobody.test", &challenge_path("tok-1")))
        .await
        .unwrap();
    assert_eq!(r.status, 421);

    // Once the order is over there is no answer.
    drop(pending);
    let mut c = Https::connect(port, &pki, "a.test").await.unwrap();
    let r = c
        .send(&get_host("a.test", &challenge_path("tok-1")))
        .await
        .unwrap();
    assert_eq!(r.text(), "ok");
}

/// An app served over TLS on `port` with the redirect listener at `plain`.
fn redirected_app(up: &TestUpstream, port: u16, plain: u16, files: &CertFiles) -> AppSpec {
    let mut a = tls_app("shop", up, port, &["shop.test"], files);
    a.tls.as_mut().unwrap().redirect_listen = Some(format!("127.0.0.1:{plain}"));
    a
}

#[tokio::test]
async fn http01_is_answered_on_the_redirect_listener_and_only_for_the_pending_name() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let (port, plain) = (free_port(), free_port());
    let h = Harness::new();
    h.proxy
        .apply(vec![redirected_app(&up, port, plain, &files)])
        .unwrap();
    let to: SocketAddr = format!("127.0.0.1:{plain}").parse().unwrap();
    let book = h.proxy.certificates();
    let long = "t".repeat(129);
    let pending = [
        book.offer_http01("shop.test", "tok-1", "tok-1.thumb"),
        book.offer_http01("shop.test", &long, "too-long.thumb"),
    ];
    let status = |host: &str, path: &str, method: &str| {
        let raw = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n");
        async move { one(to, raw.as_bytes()).await }
    };

    for host in ["shop.test", "shop.test:80", "SHOP.test", "shop.test."] {
        let r = status(host, &challenge_path("tok-1"), "GET").await;
        assert_eq!(
            (r.status, r.text()),
            (200, "tok-1.thumb".to_owned()),
            "{host}"
        );
        assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    }
    // Not a validation: the redirect that every other request gets (the certificate is real), or
    // 404 for a name the listener does not know.
    for (host, path, method, expected) in [
        ("shop.test", challenge_path("tok-2"), "GET", 308),
        ("shop.test", challenge_path(&long), "GET", 308),
        ("shop.test", challenge_path("tok-1/"), "GET", 308),
        ("shop.test", challenge_path("tok-1?x=1"), "GET", 308),
        ("shop.test", challenge_path("tok%2D1"), "GET", 308),
        ("shop.test", challenge_path(""), "GET", 308),
        ("shop.test", challenge_path("TOK-1"), "GET", 308),
        ("shop.test", challenge_path("tok-1"), "POST", 308),
        ("shop.test", challenge_path("tok-1"), "HEAD", 308),
        ("other.test", challenge_path("tok-1"), "GET", 404),
    ] {
        let r = status(host, &path, method).await;
        assert_eq!(r.status, expected, "{method} {host} {path}");
    }
    assert_eq!(up.count(), 0);

    drop(pending);
    assert_eq!(
        status("shop.test", &challenge_path("tok-1"), "GET")
            .await
            .status,
        308
    );
}

#[tokio::test]
async fn the_redirect_listener_answers_503_until_the_app_has_a_real_certificate_then_308() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let (files, stand_in) = (
        pki.leaf("shop", &["shop.test"]),
        pki.leaf("stand-in", &["shop.test"]),
    );
    let (port, plain) = (free_port(), free_port());
    let h = Harness::new();
    h.proxy
        .apply(vec![redirected_app(&up, port, plain, &files)])
        .unwrap();
    let to: SocketAddr = format!("127.0.0.1:{plain}").parse().unwrap();
    let book = h.proxy.certificates();
    let ask = |host: &'static str| async move { one(to, &get_host(host, "/cart?a=1")).await };
    let waiting = |r: &ReplyParts| {
        assert_eq!(r.status, 503);
        assert_eq!(r.header("retry-after"), Some("60"));
        assert_eq!(r.header("connection"), Some("close"));
        assert!(r.header("location").is_none());
        let text = r.text();
        assert!(
            !text.trim().is_empty() && text.trim().lines().count() == 1,
            "{text}"
        );
    };

    assert_eq!(ask("shop.test").await.status, 308);
    // Only the placeholder, then nothing at all: the app's hosts wait, others are still unknown.
    assert!(book.set("shop", key_of(&stand_in), true));
    waiting(&ask("shop.test").await);
    assert_eq!(ask("other.test").await.status, 404);
    book.follow(HashMap::new());
    waiting(&ask("shop.test").await);
    // A real certificate: the redirect, as before.
    book.follow(HashMap::from([(
        "shop".to_owned(),
        BookChange::Set(BookEntry {
            key: key_of(&files),
            placeholder: false,
        }),
    )]));
    let r = ask("shop.test").await;
    assert_eq!(r.status, 308);
    assert_eq!(
        r.header("location"),
        Some(format!("https://shop.test:{port}/cart?a=1").as_str())
    );
    assert_eq!(ask("other.test").await.status, 404);
    assert_eq!(up.count(), 0);
}

/// `a` with `canonical` as its main host name.
fn with_main_host(mut a: AppSpec, canonical: &str) -> AppSpec {
    a.tls.as_mut().unwrap().canonical_host = Some(canonical.to_owned());
    a
}

/// A shop that answers on `shop.test` and `www.shop.test`, with `shop.test` as its main host.
fn shop_with_main_host(up: &TestUpstream, port: u16, files: &CertFiles) -> AppSpec {
    with_main_host(
        tls_app("shop", up, port, &["shop.test", "www.shop.test"], files),
        "shop.test",
    )
}

#[tokio::test]
async fn another_host_of_an_app_is_sent_to_its_main_host_and_the_main_host_is_served() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test", "www.shop.test"]);
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![shop_with_main_host(&up, port, &files)])
        .unwrap();

    let mut www = Https::connect(port, &pki, "www.shop.test").await.unwrap();
    let r = www
        .send(&get_host("www.shop.test", "/cart?a=1&b=%20"))
        .await
        .unwrap();
    assert_eq!(r.status, 308);
    assert_eq!(
        r.header("location"),
        Some(format!("https://shop.test:{port}/cart?a=1&b=%20").as_str())
    );
    assert_eq!(up.count(), 0, "a redirect never reaches the upstream");
    let ev = h.last_event();
    assert_eq!(
        (s(&ev.action), ev.status, s(&ev.host), s(&ev.uri)),
        ("allow", 308, "www.shop.test", "/cart?a=1&b=%20"),
        "the answer is recorded like a forwarded one, with the status the client got"
    );

    // The same connection may carry the other host name: the name of the request decides.
    let r = www
        .send(&get_host("WWW.Shop.TEST:8443", "/x"))
        .await
        .unwrap();
    assert_eq!(r.status, 308);
    // 308 keeps the method: a POST is repeated as a POST, and its body went nowhere.
    let body = b"a=1";
    let post = format!(
        "POST /order HTTP/1.1\r\nHost: www.shop.test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut raw = post.into_bytes();
    raw.extend_from_slice(body);
    let r = www.send(&raw).await.unwrap();
    assert_eq!(r.status, 308);
    assert_eq!(
        r.header("location"),
        Some(format!("https://shop.test:{port}/order").as_str())
    );
    assert_eq!(up.count(), 0);

    let mut main = Https::connect(port, &pki, "shop.test").await.unwrap();
    let r = main
        .send(&get_host("shop.test", "/cart?a=1"))
        .await
        .unwrap();
    assert_eq!((r.status, r.text()), (200, "ok".to_owned()));
    assert_eq!(up.last().line, "GET /cart?a=1 HTTP/1.1");
    // An app with no main host serves each name as before.
    let plain = Harness::new();
    let port = free_port();
    plain
        .proxy
        .apply(vec![tls_app(
            "shop",
            &up,
            port,
            &["shop.test", "www.shop.test"],
            &files,
        )])
        .unwrap();
    let mut c = Https::connect(port, &pki, "www.shop.test").await.unwrap();
    let r = c.send(&get_host("www.shop.test", "/")).await.unwrap();
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn a_request_that_is_blocked_is_blocked_whatever_host_it_names() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test", "www.shop.test"]);
    let port = free_port();
    let mut a = shop_with_main_host(&up, port, &files);
    // The flood limit decides without an engine: the second request in a minute is blocked.
    a.analysis =
        analysis_setup(r#"{"l7_flood":{"enabled":true,"max_requests":1,"window_sec":60}}"#);
    let h = Harness::new();
    h.proxy.apply(vec![a]).unwrap();

    let mut c = Https::connect(port, &pki, "www.shop.test").await.unwrap();
    let first = c.send(&get_host("www.shop.test", "/a")).await.unwrap();
    assert_eq!(first.status, 308, "within the limit it is sent on");
    let second = c.send(&get_host("www.shop.test", "/a")).await.unwrap();
    assert_ne!(second.status, 308, "a block is not redirected");
    assert!(second.header("location").is_none());
    let ev = h.last_event();
    assert_eq!(s(&ev.action), "block", "{ev:?}");
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn an_upgrade_request_to_another_host_goes_upstream_and_is_not_redirected() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test", "www.shop.test"]);
    let port = free_port();
    let mut a = shop_with_main_host(&up, port, &files);
    // A handshake without an allowed Origin is refused by the WebSocket takeover, which comes
    // before the redirect.
    a.rules_json =
        br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://good.test"]}}}"#
            .to_vec();
    let h = Harness::new();
    h.proxy.apply(vec![a]).unwrap();

    let mut c = Https::connect(port, &pki, "www.shop.test").await.unwrap();
    let h2c = "GET /x HTTP/1.1\r\nHost: www.shop.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n";
    let r = c.send(h2c.as_bytes()).await.unwrap();
    assert_eq!((r.status, r.text()), (200, "ok".to_owned()));
    assert_eq!(up.last().line, "GET /x HTTP/1.1");

    let mut ws = Https::connect(port, &pki, "www.shop.test").await.unwrap();
    let handshake = "GET /socket HTTP/1.1\r\nHost: www.shop.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    let r = ws.send(handshake.as_bytes()).await.unwrap();
    assert_eq!(r.status, 403, "the takeover answered, not the redirect");
    assert!(r.header("location").is_none());
    assert_eq!(up.count(), 1);
    drop(h);
}

#[tokio::test]
async fn the_http_listener_sends_every_host_of_the_app_to_its_main_host_in_one_hop() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test", "www.shop.test"]);
    let (port, plain) = (free_port(), free_port());
    let mut a = shop_with_main_host(&up, port, &files);
    a.tls.as_mut().unwrap().redirect_listen = Some(format!("127.0.0.1:{plain}"));
    let h = Harness::new();
    h.proxy.apply(vec![a]).unwrap();
    let to: SocketAddr = format!("127.0.0.1:{plain}").parse().unwrap();
    let ask = |host: &str, target: &str| {
        let raw = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n");
        async move { one(to, raw.as_bytes()).await }
    };

    for host in ["www.shop.test", "WWW.shop.test:80", "shop.test"] {
        let r = ask(host, "/a/b?c=d").await;
        assert_eq!(r.status, 308, "{host}");
        assert_eq!(
            r.header("location"),
            Some(format!("https://shop.test:{port}/a/b?c=d").as_str()),
            "{host}: one hop, straight to the main host"
        );
    }
    assert_eq!(ask("other.test", "/").await.status, 404);

    // Without a main host the name of the request is kept.
    let (port, plain) = (free_port(), free_port());
    let mut a = tls_app("shop", &up, port, &["shop.test", "www.shop.test"], &files);
    a.tls.as_mut().unwrap().redirect_listen = Some(format!("127.0.0.1:{plain}"));
    let h2 = Harness::new();
    h2.proxy.apply(vec![a]).unwrap();
    let to: SocketAddr = format!("127.0.0.1:{plain}").parse().unwrap();
    let raw = "GET /a HTTP/1.1\r\nHost: www.shop.test\r\n\r\n";
    let r = one(to, raw.as_bytes()).await;
    assert_eq!(
        r.header("location"),
        Some(format!("https://www.shop.test:{port}/a").as_str())
    );
    assert_eq!(up.count(), 0);
    drop(h);
}

#[tokio::test]
async fn a_new_main_host_replaces_the_old_one_on_the_next_apply_without_a_restart() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test", "www.shop.test"]);
    let (port, plain) = (free_port(), free_port());
    let make = |canonical: Option<&str>| {
        let mut a = tls_app("shop", &up, port, &["shop.test", "www.shop.test"], &files);
        a.tls.as_mut().unwrap().redirect_listen = Some(format!("127.0.0.1:{plain}"));
        match canonical {
            Some(c) => with_main_host(a, c),
            None => a,
        }
    };
    let h = Harness::new();
    h.proxy.apply(vec![make(Some("shop.test"))]).unwrap();
    let mut c = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(
        c.send(&get_host("shop.test", "/")).await.unwrap().status,
        200
    );

    // The main host moves to www: the same connection now gets the redirect for shop.test.
    h.proxy.apply(vec![make(Some("www.shop.test"))]).unwrap();
    let r = c.send(&get_host("shop.test", "/p?q=1")).await.unwrap();
    assert_eq!(r.status, 308);
    assert_eq!(
        r.header("location"),
        Some(format!("https://www.shop.test:{port}/p?q=1").as_str())
    );
    let to: SocketAddr = format!("127.0.0.1:{plain}").parse().unwrap();
    let r = one(to, b"GET / HTTP/1.1\r\nHost: shop.test\r\n\r\n").await;
    assert_eq!(
        r.header("location"),
        Some(format!("https://www.shop.test:{port}/").as_str())
    );

    // Cleared: back to serving every name.
    h.proxy.apply(vec![make(None)]).unwrap();
    assert_eq!(
        c.send(&get_host("shop.test", "/")).await.unwrap().status,
        200
    );
}
