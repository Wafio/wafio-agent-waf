//! The paths of the HTTP client that need a TLS server: an https URL through a `CONNECT` tunnel
//! of an http proxy, and through an `https://` proxy (TLS to the proxy, `CONNECT` inside it, TLS to
//! the target inside that). Loopback is never proxied and the check is exact-case, so the target is
//! spelled `LOCALHOST`; the fake proxies ignore the name and tunnel to the TLS server on 127.0.0.1.
//! The certificate is the control crate's fixture (`localhost`, 127.0.0.1), trusted through
//! `SSL_CERT_FILE` like any platform root.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pingora::tls::{ServerConfig, TlsAcceptor};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wafio_control::proxy_env::ProxyConfig;
use wafio_waf_agent::httpclient::{RequestOptions, request_via};

const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../control/tests/fixtures");

fn acceptor() -> TlsAcceptor {
    pingora::tls::install_default_crypto_provider();
    let (certs, key) = pingora::tls::load_certs_and_key_files(
        Path::new(FX).join("server.crt").to_str().unwrap(),
        Path::new(FX).join("server.key").to_str().unwrap(),
    )
    .unwrap()
    .expect("fixture certificate and key");
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

/// Reads a request head (no body) byte by byte.
async fn head<S: AsyncRead + Unpin>(s: &mut S) -> Option<String> {
    let mut h = Vec::new();
    let mut b = [0u8; 1];
    while !h.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.ok()? == 0 {
            return None;
        }
        h.push(b[0]);
    }
    Some(String::from_utf8_lossy(&h).into_owned())
}

type Log = Arc<Mutex<Vec<String>>>;

/// An HTTPS server answering `ok` to everything; the request heads it saw.
async fn target(acceptor: TlsAcceptor) -> (u16, Log) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let log = Log::default();
    let seen = log.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let (acceptor, seen) = (acceptor.clone(), seen.clone());
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
                if let Some(h) = head(&mut s).await {
                    seen.lock().unwrap().push(h);
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });
    (port, log)
}

/// A CONNECT proxy (`tls`: reached over TLS); every CONNECT goes to `127.0.0.1:target_port`.
async fn proxy(tls: Option<TlsAcceptor>, target_port: u16) -> (u16, Log) {
    async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut c: S, port: u16, log: Log) {
        let Some(h) = head(&mut c).await else { return };
        log.lock().unwrap().push(h);
        let Ok(mut up) = TcpStream::connect(("127.0.0.1", port)).await else {
            return;
        };
        let _ = c
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await;
        let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
    }
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let log = Log::default();
    let seen = log.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = l.accept().await {
            let (tls, seen) = (tls.clone(), seen.clone());
            tokio::spawn(async move {
                match tls {
                    Some(a) => {
                        if let Ok(s) = a.accept(tcp).await {
                            serve(s, target_port, seen).await;
                        }
                    }
                    None => serve(tcp, target_port, seen).await,
                }
            });
        }
    });
    (port, log)
}

async fn get(url: &str, pc: &ProxyConfig) -> Result<(u16, Vec<u8>), String> {
    request_via(
        "GET",
        url,
        "t/1",
        &RequestOptions {
            body: None,
            headers: &[],
            follow: true,
            cap: 1 << 20,
            truncate: false,
            timeout: Duration::from_secs(10),
        },
        pc,
    )
    .await
    .map(|r| (r.status, r.body))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_goes_through_connect_tunnels() {
    // Single test in this process: nothing else reads the environment meanwhile.
    unsafe { std::env::set_var("SSL_CERT_FILE", Path::new(FX).join("ca.crt")) };
    let acceptor = acceptor();
    let (tp, served) = target(acceptor.clone()).await;

    // The harness itself: a direct https request (no proxy configured).
    let none = ProxyConfig::default();
    let (status, body) = get(&format!("https://127.0.0.1:{tp}/direct"), &none)
        .await
        .unwrap();
    assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));

    // HTTPS_PROXY = an http proxy: CONNECT, then TLS to the target inside the tunnel.
    let (pp, seen) = proxy(None, tp).await;
    let pc = ProxyConfig::from_parts("", &format!("http://u:p@127.0.0.1:{pp}"), "", false);
    let (status, body) = get(&format!("https://LOCALHOST:{tp}/secure?x=1#f"), &pc)
        .await
        .unwrap();
    assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));
    let h = seen.lock().unwrap()[0].clone();
    assert!(
        h.starts_with(&format!("CONNECT LOCALHOST:{tp} HTTP/1.1\r\n")),
        "{h}"
    );
    assert!(h.contains("\r\nProxy-Authorization: Basic dTpw\r\n"), "{h}");
    let inside = served.lock().unwrap().last().unwrap().clone();
    assert!(
        inside.starts_with("GET /secure?x=1 HTTP/1.1\r\n"),
        "origin form inside the tunnel: {inside}"
    );
    assert!(
        inside.contains(&format!("\r\nHost: LOCALHOST:{tp}\r\n")),
        "{inside}"
    );
    assert!(
        !inside.contains("Proxy-Authorization"),
        "the target never sees the proxy's credentials: {inside}"
    );

    // HTTPS_PROXY = an https proxy: TLS to the proxy, CONNECT inside it, TLS to the target inside that.
    let (sp, seen) = proxy(Some(acceptor), tp).await;
    let pc = ProxyConfig::from_parts("", &format!("https://LOCALHOST:{sp}"), "", false);
    let (status, body) = get(&format!("https://LOCALHOST:{tp}/double"), &pc)
        .await
        .unwrap();
    assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));
    let h = seen.lock().unwrap()[0].clone();
    assert!(
        h.starts_with(&format!("CONNECT LOCALHOST:{tp} HTTP/1.1\r\n")),
        "{h}"
    );
    assert!(
        served
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .starts_with("GET /double HTTP/1.1\r\n")
    );
}
