//! HTTPS listeners through the public API: the certificate chosen by SNI, the app chosen by
//! `Host`, the redirect listener, certificate files swapped under a running listener, the JA4
//! of the handshake, the scheme a FastCGI app is told, and what bounds a client that is slow or
//! many. Keys are made by `openssl` into a temporary directory and never leave it.

mod common;

use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use pingora::tls::{
    CertificateDer, ClientConfig, ClientTlsStream, RootCertStore, ServerName, TlsConnector,
};
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;
use wafio_proxy::cert_store::CertFiles;
use wafio_proxy::{AppSpec, Proxy, ProxyOptions, TlsSite};

use common::*;

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
        let tap = Tap {
            inner: TcpStream::connect(("127.0.0.1", port)).await?,
            written: Arc::default(),
            cut: cut.map(|(at, pause)| (at, Box::pin(tokio::time::sleep(pause)))),
        };
        let name = ServerName::try_from(sni.to_owned()).unwrap();
        let tls = TlsConnector::from(pki.client_config())
            .connect(name, tap)
            .await?;
        Ok(Https(BufReader::new(tls)))
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
        cert: files.clone(),
        redirect_listen: None,
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

/// A proxy that looks at certificate files every `poll`.
fn harness_polling(poll: Duration) -> Harness {
    harness_with(|opts| opts.cert_poll_interval = poll)
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

#[tokio::test]
async fn a_swapped_certificate_file_is_served_to_new_connections_and_open_ones_go_on() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = harness_polling(Duration::from_millis(100));
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    let mut open = Https::connect(port, &pki, "shop.test").await.unwrap();
    let before = open.certificate();
    assert_eq!(
        open.send(&get_host("shop.test", "/")).await.unwrap().status,
        200
    );

    // The way a renewal tool does it: write the new pair aside, then move it over the old one.
    let renewed = pki.leaf("renewed", &["shop.test"]);
    fs::rename(&renewed.key, &files.key).unwrap();
    fs::rename(&renewed.certificate, &files.certificate).unwrap();
    let after = until("the renewed certificate", || async {
        let c = Https::connect(port, &pki, "shop.test").await.ok()?;
        (c.certificate() != before).then(|| c.certificate())
    })
    .await;
    assert_ne!(after, before);

    assert_eq!(
        open.send(&get_host("shop.test", "/")).await.unwrap().status,
        200
    );
    assert_eq!(
        open.certificate(),
        before,
        "an open connection keeps its handshake"
    );
    let mut fresh = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(fresh.certificate(), after);
    assert_eq!(
        fresh
            .send(&get_host("shop.test", "/"))
            .await
            .unwrap()
            .status,
        200
    );
}

#[tokio::test]
async fn a_pair_that_cannot_be_read_keeps_the_old_certificate() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = harness_polling(Duration::from_millis(100));
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    let before = Https::connect(port, &pki, "shop.test")
        .await
        .unwrap()
        .certificate();

    fs::write(&files.certificate, b"half a copy").unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mut c = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(c.certificate(), before);
    assert_eq!(
        c.send(&get_host("shop.test", "/")).await.unwrap().status,
        200
    );
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

    // An apply that cannot load a certificate changes nothing.
    let mut missing = fb.clone();
    missing.key = "/nonexistent/b.key".into();
    assert_eq!(
        h.proxy
            .apply(vec![tls_app("a", &u1, port, &["a.test"], &missing)]),
        Err("invalid TLS site settings".into())
    );
    assert_eq!(
        open.send(&get_host("a.test", "/"))
            .await
            .unwrap()
            .header("x-tag"),
        Some("u2")
    );
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

#[tokio::test]
async fn a_listener_cannot_change_kind_and_apps_on_it_must_share_their_limits() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let port = free_port();
    let h = Harness::new();
    h.proxy
        .apply(vec![tls_app("shop", &up, port, &["shop.test"], &files)])
        .unwrap();
    assert_eq!(
        h.proxy.apply(vec![app("shop", port, &url(&up))]),
        Err("listener kind changed; agent restart required".into())
    );
    let mut other = tls_app("other", &up, port, &["other.test"], &files);
    other.proxy_config = br#"{"max_body_bytes":2048}"#.to_vec();
    assert_eq!(
        h.proxy.apply(vec![
            tls_app("shop", &up, port, &["shop.test"], &files),
            other
        ]),
        Err("apps sharing a TLS listener differ in timeouts or limits".into())
    );
    let mut c = Https::connect(port, &pki, "shop.test").await.unwrap();
    assert_eq!(
        c.send(&get_host("shop.test", "/")).await.unwrap().status,
        200
    );
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
async fn an_app_served_by_the_agent_reads_fingerprint_headers_only_from_a_trusted_proxy() {
    let up = http_upstream().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let trusting = br#"{"trust_forwarded":true}"#;
    // As before for an app the file does not name: the header is read.
    assert_eq!(plain_listener_status(&up, &files, false, b"").await, 403);
    // An app the agent serves itself: a client may not name its own fingerprint ...
    assert_eq!(plain_listener_status(&up, &files, true, b"").await, 200);
    // ... but a proxy in front of it may.
    assert_eq!(
        plain_listener_status(&up, &files, true, trusting).await,
        403
    );
}

/// The status of a request that names a listed JA4 in a header, to the bundle listener of an app
/// that is also served over HTTPS by the agent (`edge`) or is not.
async fn plain_listener_status(
    up: &TestUpstream,
    files: &CertFiles,
    edge: bool,
    proxy_config: &[u8],
) -> u16 {
    let spoof = "t13d0000h2_000000000000_000000000000";
    let plain = free_port();
    let mut a = if edge {
        tls_app("shop", up, free_port(), &["shop.test"], files)
    } else {
        app("shop", 0, &url(up))
    };
    a.listen_port = plain;
    a.proxy_config = proxy_config.to_vec();
    a.analysis = analysis_setup(&block_ja4(spoof));
    let h = Harness::new();
    h.proxy.apply(vec![a]).unwrap();
    let raw = format!("GET / HTTP/1.1\r\nHost: shop.test\r\nX-JA4: {spoof}\r\n\r\n");
    one(
        format!("127.0.0.1:{plain}").parse().unwrap(),
        raw.as_bytes(),
    )
    .await
    .status
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

#[tokio::test]
async fn the_plain_listener_of_an_app_served_over_tls_still_passes_the_clients_forwarded_proto() {
    let (fcgi, fake) = fake_fcgi().await;
    let pki = Pki::new();
    let files = pki.leaf("shop", &["shop.test"]);
    let (port, plain) = (free_port(), free_port());
    let mut a = php_app(fcgi, port, &files);
    a.listen_port = plain;
    let h = Harness::new();
    h.proxy.apply(vec![a]).unwrap();
    let to: SocketAddr = format!("127.0.0.1:{plain}").parse().unwrap();

    for (header, https, server_port, proto) in [
        (
            "X-Forwarded-Proto: https\r\n",
            Some("on"),
            "443",
            Some("https"),
        ),
        ("X-Forwarded-Proto: http\r\n", None, "80", Some("http")),
        ("", None, "80", None),
    ] {
        let raw = format!("GET /index.php HTTP/1.1\r\nHost: shop.test\r\n{header}\r\n");
        assert_eq!(one(to, raw.as_bytes()).await.status, 201);
        let p = last_params(&fake);
        assert_eq!(
            (
                p.get("HTTPS").map(String::as_str),
                p["SERVER_PORT"].as_str(),
                p.get("HTTP_X_FORWARDED_PROTO").map(String::as_str)
            ),
            (https, server_port, proto),
            "{header:?}"
        );
    }
}
