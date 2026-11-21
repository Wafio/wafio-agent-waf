//! The HTTP side of the ACME client: the requests of `instant-acme` go out over the agent's own
//! client, so they use the platform's root certificates and `HTTPS_PROXY` like every other
//! request the agent makes, and no second HTTP stack is linked.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body::Body;
use instant_acme::{BodyWrapper, BytesResponse, Error, HttpClient};
use wafio_control::proxy_env::{self, ProxyConfig};

use crate::httpclient::{RequestOptions, request_via};

/// The longest answer read: a chain of certificates is a few kilobytes.
pub const RESPONSE_CAP: usize = 256 << 10;
/// The time one request may take, redirects and body included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Default)]
pub struct Http {
    /// `None` reads the proxies from the environment, as every other request does.
    proxies: Option<Arc<ProxyConfig>>,
}

impl Http {
    pub fn new() -> Http {
        Http::default()
    }

    /// With proxy settings of its own, for a test.
    #[cfg(test)]
    pub fn with_proxies(proxies: ProxyConfig) -> Http {
        Http {
            proxies: Some(Arc::new(proxies)),
        }
    }
}

fn user_agent() -> String {
    format!("wafio-waf-agent/{}", crate::hostinfo::AGENT_VERSION)
}

/// The whole body of a request, which `instant-acme` hands over in one piece.
async fn body_bytes(mut body: BodyWrapper<Bytes>) -> Result<Bytes, Error> {
    let mut out = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let Ok(frame) = frame;
        if let Ok(data) = frame.into_data() {
            out.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(out))
}

fn other(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Error {
    Error::Other(e.into())
}

impl HttpClient for Http {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let proxies = self.proxies.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = body_bytes(body).await?;
            let url = parts.uri.to_string();
            // The agent names itself; the client's own name is dropped.
            let headers: Vec<(String, String)> = parts
                .headers
                .iter()
                .filter(|(name, _)| *name != http::header::USER_AGENT)
                .filter_map(|(name, value)| {
                    Some((name.to_string(), value.to_str().ok()?.to_owned()))
                })
                .collect();
            let headers: Vec<(&str, &str)> = headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            let content_type = parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream");
            let options = RequestOptions {
                body: (!body.is_empty()).then_some((content_type, &body[..])),
                headers: &headers,
                // The authority's answers are read as they are: a redirect is not followed with a
                // signed request.
                follow: false,
                cap: RESPONSE_CAP,
                truncate: false,
                timeout: REQUEST_TIMEOUT,
            };
            let proxies = proxies.as_deref().unwrap_or_else(|| proxy_env::global());
            let answer = request_via(
                parts.method.as_str(),
                &url,
                &user_agent(),
                &options,
                proxies,
            )
            .await
            .map_err(other)?;
            let mut response = http::Response::new(());
            *response.status_mut() = http::StatusCode::from_u16(answer.status).map_err(other)?;
            *response.headers_mut() = answer.headers;
            let (parts, ()) = response.into_parts();
            Ok(BytesResponse {
                parts,
                body: Box::new(Bytes::from(answer.body)),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    use super::*;

    /// A server that answers one request with `reply` and sends what it read to the channel.
    fn serve(reply: Vec<u8>) -> (u16, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            // The head, then as much body as it announces.
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                got.extend_from_slice(&buf[..n]);
                let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
                    if n == 0 {
                        break;
                    }
                    continue;
                };
                let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if got.len() >= end + 4 + length || n == 0 {
                    break;
                }
            }
            let _ = tx.send(got);
            let _ = stream.write_all(&reply);
        });
        (port, rx)
    }

    fn request(
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> http::Request<BodyWrapper<Bytes>> {
        let mut request = http::Request::builder().method(method).uri(url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let body = if body.is_empty() {
            BodyWrapper::default()
        } else {
            BodyWrapper::from(body.to_vec())
        };
        request.body(body).unwrap()
    }

    #[tokio::test]
    async fn a_signed_request_goes_out_as_the_agent_with_its_headers_and_the_answer_comes_back_whole()
     {
        let (port, seen) = serve(
            b"HTTP/1.1 201 Created\r\nReplay-Nonce: nonce-1\r\nLocation: https://ca.test/acct/7\r\nContent-Length: 11\r\n\r\n{\"ok\":true}"
                .to_vec(),
        );
        let url = format!("http://127.0.0.1:{port}/new-order");
        let answer = Http::new()
            .request(request(
                "POST",
                &url,
                &[
                    ("content-type", "application/jose+json"),
                    ("user-agent", "instant-acme/0.8.5"),
                ],
                br#"{"payload":"x"}"#,
            ))
            .await
            .unwrap();
        let sent = String::from_utf8(seen.recv().unwrap()).unwrap();
        let head = sent.to_ascii_lowercase();
        assert!(sent.starts_with("POST /new-order HTTP/1.1\r\n"), "{sent}");
        assert!(
            head.contains("\r\ncontent-type: application/jose+json\r\n"),
            "{sent}"
        );
        assert!(head.contains("\r\ncontent-length: 15\r\n"), "{sent}");
        assert!(sent.ends_with(r#"{"payload":"x"}"#), "{sent}");
        assert!(
            head.contains("\r\nuser-agent: wafio-waf-agent/") && !head.contains("instant-acme"),
            "the agent names itself: {sent}"
        );
        // Status, headers and body are there for the client to read.
        assert_eq!(answer.parts.status, 201);
        assert_eq!(answer.parts.headers["replay-nonce"], "nonce-1");
        assert_eq!(answer.parts.headers["location"], "https://ca.test/acct/7");
        let mut body = answer.body;
        assert_eq!(body.into_bytes().await.unwrap(), &br#"{"ok":true}"#[..]);
    }

    #[tokio::test]
    async fn a_request_without_a_body_sends_none_and_a_redirect_is_returned_as_it_is() {
        let (port, seen) = serve(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nReplay-Nonce: n2\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        );
        let url = format!("http://127.0.0.1:{port}/nonce");
        let answer = Http::new()
            .request(request("HEAD", &url, &[], b""))
            .await
            .unwrap();
        let sent = String::from_utf8(seen.recv().unwrap())
            .unwrap()
            .to_ascii_lowercase();
        assert!(sent.starts_with("head /nonce http/1.1\r\n"), "{sent}");
        assert!(
            !sent.contains("content-length") && !sent.contains("content-type"),
            "{sent}"
        );
        assert_eq!(answer.parts.status, 302, "signed requests are not sent on");
        assert_eq!(answer.parts.headers["replay-nonce"], "n2");
    }

    #[tokio::test]
    async fn an_answer_over_the_size_cap_is_an_error() {
        let mut reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            RESPONSE_CAP + 1
        )
        .into_bytes();
        reply.extend(std::iter::repeat_n(b'x', RESPONSE_CAP + 1));
        let (port, _seen) = serve(reply);
        let url = format!("http://127.0.0.1:{port}/big");
        let e = Http::new()
            .request(request("GET", &url, &[], b""))
            .await
            .err()
            .expect("an error");
        assert!(e.to_string().contains("larger than"), "{e}");
    }

    /// `HTTPS_PROXY`: the request to an https address asks the proxy for a tunnel, with the
    /// credentials of the proxy, and what the proxy says is the error.
    #[tokio::test]
    async fn an_https_request_goes_through_the_proxy_the_environment_names() {
        let (port, seen) = serve(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec());
        let proxies =
            ProxyConfig::from_parts("", &format!("http://user:pass@127.0.0.1:{port}"), "", false);
        let e = Http::with_proxies(proxies)
            .request(request("GET", "https://acme.invalid/directory", &[], b""))
            .await
            .err()
            .expect("the proxy refuses");
        assert_eq!(e.to_string(), "Forbidden");
        let sent = String::from_utf8(seen.recv().unwrap()).unwrap();
        assert!(
            sent.starts_with("CONNECT acme.invalid:443 HTTP/1.1\r\n"),
            "{sent}"
        );
        assert!(
            sent.to_ascii_lowercase()
                .contains("proxy-authorization: basic dxnlcjpwyxnz"),
            "{sent}"
        );
    }
}
