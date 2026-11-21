//! The ACME client of the agent: `instant-acme` over the agent's HTTP client.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use instant_acme::{
    AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use zeroize::Zeroizing;

use super::Kind;
use super::ca::{Account, Answer, Authorization, CREDENTIALS_UNUSABLE, Ca, CaError, Order};
use super::http::Http;

/// How long the authority may take to validate the names, and then to issue the certificate. The
/// attempt as a whole has its own, shorter cap.
const POLL_TIMEOUT: Duration = Duration::from_secs(150);

fn policy() -> RetryPolicy {
    RetryPolicy::new()
        .initial_delay(Duration::from_millis(500))
        .backoff(1.5)
        .timeout(POLL_TIMEOUT)
}

impl From<instant_acme::Error> for CaError {
    fn from(e: instant_acme::Error) -> CaError {
        match e {
            instant_acme::Error::Api(problem) => CaError {
                problem: problem.r#type.clone(),
                text: problem
                    .detail
                    .clone()
                    .unwrap_or_else(|| problem.to_string()),
            },
            other => CaError::new(other.to_string()),
        }
    }
}

fn challenge_type(kind: Kind) -> ChallengeType {
    match kind {
        Kind::TlsAlpn01 => ChallengeType::TlsAlpn01,
        Kind::Http01 => ChallengeType::Http01,
    }
}

pub struct InstantAcme {
    http: Http,
}

impl InstantAcme {
    pub fn new(http: Http) -> InstantAcme {
        InstantAcme { http }
    }
}

#[async_trait]
impl Ca for InstantAcme {
    async fn create_account(
        &self,
        directory: &str,
    ) -> Result<(Arc<dyn Account>, Zeroizing<Vec<u8>>), CaError> {
        // No contact address, and the terms are agreed to: the dashboard's request button is the
        // acceptance.
        let new = NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let (account, credentials) =
            instant_acme::Account::builder_with_http(Box::new(self.http.clone()))
                .create(&new, directory.to_owned(), None)
                .await?;
        // Room for the whole text from the start, so no growth leaves a copy of the key behind.
        let mut text = Zeroizing::new(Vec::with_capacity(1024));
        serde_json::to_writer(&mut *text, &credentials).map_err(|e| CaError::new(e.to_string()))?;
        Ok((Arc::new(CaAccount(account)), text))
    }

    async fn restore_account(&self, credentials: &[u8]) -> Result<Arc<dyn Account>, CaError> {
        // The texts are fixed: what the parser says may quote the credentials.
        let unusable = || CaError {
            problem: Some(CREDENTIALS_UNUSABLE.to_owned()),
            text: "the kept account cannot be used".to_owned(),
        };
        let credentials: AccountCredentials =
            serde_json::from_slice(credentials).map_err(|_| unusable())?;
        let account = instant_acme::Account::builder_with_http(Box::new(self.http.clone()))
            .from_credentials(credentials)
            .await
            .map_err(|e| match e {
                instant_acme::Error::KeyRejected
                | instant_acme::Error::Crypto
                | instant_acme::Error::Str(_) => unusable(),
                other => CaError::from(other),
            })?;
        Ok(Arc::new(CaAccount(account)))
    }
}

struct CaAccount(instant_acme::Account);

#[async_trait]
impl Account for CaAccount {
    async fn new_order(&self, hosts: &[String]) -> Result<Box<dyn Order>, CaError> {
        let identifiers: Vec<Identifier> = hosts.iter().cloned().map(Identifier::Dns).collect();
        let order = self.0.new_order(&NewOrder::new(&identifiers)).await?;
        Ok(Box::new(CaOrder {
            order,
            names: hosts.len(),
        }))
    }
}

struct CaOrder {
    order: instant_acme::Order,
    /// How many names the order is for, which is as many authorizations as the authority may list.
    names: usize,
}

#[async_trait]
impl Order for CaOrder {
    async fn authorizations(&mut self) -> Result<Vec<Authorization>, CaError> {
        let mut found = Vec::new();
        let mut authorizations = self.order.authorizations();
        while let Some(next) = authorizations.next().await {
            let authorization = next?;
            if found.len() == self.names {
                return Err(CaError::new(
                    "the authority lists more authorizations than the order has names",
                ));
            }
            found.push(Authorization {
                host: authorization.identifier().to_string().to_ascii_lowercase(),
                valid: authorization.status == AuthorizationStatus::Valid,
                offered: authorization
                    .challenges
                    .iter()
                    .filter_map(|c| match c.r#type {
                        ChallengeType::TlsAlpn01 => Some(Kind::TlsAlpn01),
                        ChallengeType::Http01 => Some(Kind::Http01),
                        _ => None,
                    })
                    .collect(),
            });
        }
        Ok(found)
    }

    async fn answer(&mut self, host: &str, kind: Kind) -> Result<Answer, CaError> {
        let mut authorizations = self.order.authorizations();
        while let Some(next) = authorizations.next().await {
            let mut authorization = next?;
            if authorization.identifier().to_string().to_ascii_lowercase() != host {
                continue;
            }
            let challenge = authorization
                .challenge(challenge_type(kind))
                .ok_or_else(|| {
                    CaError::new(format!("no {} challenge offered for {host}", kind.as_str()))
                })?;
            let key_authorization = challenge.key_authorization();
            let digest: [u8; 32] = key_authorization
                .digest()
                .as_ref()
                .try_into()
                .map_err(|_| CaError::new("the key authorization digest is not 32 bytes"))?;
            return Ok(Answer {
                token: challenge.token.clone(),
                key_authorization: key_authorization.as_str().to_owned(),
                digest,
            });
        }
        Err(CaError::new(format!("no authorization for {host}")))
    }

    async fn ready(&mut self, host: &str, kind: Kind) -> Result<(), CaError> {
        let mut authorizations = self.order.authorizations();
        while let Some(next) = authorizations.next().await {
            let mut authorization = next?;
            if authorization.identifier().to_string().to_ascii_lowercase() != host {
                continue;
            }
            let mut challenge = authorization
                .challenge(challenge_type(kind))
                .ok_or_else(|| {
                    CaError::new(format!("no {} challenge offered for {host}", kind.as_str()))
                })?;
            return Ok(challenge.set_ready().await?);
        }
        Err(CaError::new(format!("no authorization for {host}")))
    }

    async fn wait_ready(&mut self) -> Result<(), CaError> {
        match self.order.poll_ready(&policy()).await? {
            OrderStatus::Invalid => Err(self.why_invalid().await),
            _ => Ok(()),
        }
    }

    async fn finalize(&mut self, csr: &[u8]) -> Result<(), CaError> {
        Ok(self.order.finalize_csr(csr).await?)
    }

    async fn certificate(&mut self) -> Result<String, CaError> {
        Ok(self.order.poll_certificate(&policy()).await?)
    }
}

impl CaOrder {
    /// What the authority says of the first challenge that failed, for an order it made invalid.
    async fn why_invalid(&mut self) -> CaError {
        let mut authorizations = self.order.authorizations();
        let mut seen = 0;
        while let Some(Ok(mut authorization)) = authorizations.next().await {
            // The list is the authority's: look at no more than the order has names.
            seen += 1;
            if seen > self.names {
                break;
            }
            let Ok(state) = authorization.refresh().await else {
                continue;
            };
            if let Some(problem) = state.challenges.iter().find_map(|c| c.error.as_ref()) {
                return CaError {
                    problem: problem.r#type.clone(),
                    text: problem.detail.clone().unwrap_or_default(),
                };
            }
        }
        CaError::new("the authority made the order invalid")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::tls::acme::mock::ACCOUNT_KEY;

    /// An ACME server over plain HTTP that checks no signature: the directory, a nonce, an
    /// account, and an order that lists as many authorization addresses as the test says, which
    /// may be more than the order has names. It keeps a line for each request it gets.
    struct Fake {
        base: String,
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl Fake {
        /// `listed`: the authorization addresses an order lists. `order`: the status a refresh of
        /// the order gives.
        async fn start(listed: usize, order: &'static str) -> Fake {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let nonces = Arc::new(AtomicUsize::new(0));
            let (b, s) = (base.clone(), seen.clone());
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let (b, s, n) = (b.clone(), s.clone(), nonces.clone());
                    tokio::spawn(answer(stream, b, listed, order, s, n));
                }
            });
            Fake { base, seen }
        }

        fn directory(&self) -> String {
            format!("{}/directory", self.base)
        }

        fn count(&self, prefix: &str) -> usize {
            let seen = self.seen.lock().unwrap();
            seen.iter().filter(|line| line.starts_with(prefix)).count()
        }
    }

    async fn answer(
        mut stream: TcpStream,
        base: String,
        listed: usize,
        order: &'static str,
        seen: Arc<Mutex<Vec<String>>>,
        nonces: Arc<AtomicUsize>,
    ) {
        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        let end = loop {
            let Ok(n @ 1..) = stream.read(&mut chunk).await else {
                return;
            };
            got.extend_from_slice(&chunk[..n]);
            if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let head = String::from_utf8_lossy(&got[..end]).into_owned();
        let length = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")?
                    .trim()
                    .parse()
                    .ok()
            })
            .unwrap_or(0usize);
        while got.len() < end + length {
            let Ok(n @ 1..) = stream.read(&mut chunk).await else {
                return;
            };
            got.extend_from_slice(&chunk[..n]);
        }
        let mut line = head.lines().next().unwrap_or_default().split(' ');
        let (method, path) = (line.next().unwrap_or(""), line.next().unwrap_or(""));
        seen.lock().unwrap().push(format!("{method} {path}"));

        let urls: Vec<String> = (0..listed)
            .map(|i| format!("\"{base}/authz/{i}\""))
            .collect();
        let order_state = |status: &str| {
            format!(
                r#"{{"status":"{status}","authorizations":[{}],"finalize":"{base}/finalize/1"}}"#,
                urls.join(",")
            )
        };
        let challenge = |kind: &str, i: &str| {
            format!(
                r#"{{"type":"{kind}","url":"{base}/{kind}/{i}","token":"token-{i}","status":"pending"}}"#
            )
        };
        let (status, extra, body) = match (method, path) {
            ("GET", "/directory") => (
                "200 OK",
                String::new(),
                format!(
                    r#"{{"newNonce":"{base}/nonce","newAccount":"{base}/account","newOrder":"{base}/order"}}"#
                ),
            ),
            ("HEAD", "/nonce") => ("200 OK", String::new(), String::new()),
            ("POST", "/account") => (
                "201 Created",
                format!("Location: {base}/account/1\r\n"),
                r#"{"status":"valid"}"#.to_owned(),
            ),
            ("POST", "/order") => (
                "201 Created",
                format!("Location: {base}/order/1\r\n"),
                order_state("pending"),
            ),
            ("POST", "/order/1") => ("200 OK", String::new(), order_state(order)),
            ("POST", p) if p.starts_with("/authz/") => {
                let i = &p["/authz/".len()..];
                (
                    "200 OK",
                    String::new(),
                    format!(
                        r#"{{"status":"pending","identifier":{{"type":"dns","value":"Host{i}.example.com"}},"challenges":[{},{}]}}"#,
                        challenge("tls-alpn-01", i),
                        challenge("http-01", i)
                    ),
                )
            }
            _ => (
                "404 Not Found",
                String::new(),
                r#"{"type":"urn:ietf:params:acme:error:malformed","detail":"no such address"}"#
                    .to_owned(),
            ),
        };
        let body = if method == "HEAD" {
            String::new()
        } else {
            body
        };
        let nonce = nonces.fetch_add(1, Ordering::Relaxed);
        let reply = format!(
            "HTTP/1.1 {status}\r\nReplay-Nonce: nonce-{nonce}\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(reply.as_bytes()).await;
    }

    fn names(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("host{i}.example.com")).collect()
    }

    /// An order for `n` names at the fake server.
    async fn order_at(fake: &Fake, n: usize) -> Box<dyn Order> {
        let (account, _) = InstantAcme::new(Http::allowing_plain())
            .create_account(&fake.directory())
            .await
            .unwrap();
        account.new_order(&names(n)).await.unwrap()
    }

    #[tokio::test]
    async fn the_authorizations_of_an_order_are_one_for_each_name() {
        let fake = Fake::start(2, "pending").await;
        let found = order_at(&fake, 2).await.authorizations().await.unwrap();
        let hosts: Vec<&str> = found.iter().map(|a| a.host.as_str()).collect();
        assert_eq!(hosts, ["host0.example.com", "host1.example.com"]);
        assert!(found.iter().all(|a| !a.valid));
        assert_eq!(found[0].offered, [Kind::TlsAlpn01, Kind::Http01]);
        assert_eq!(fake.count("POST /authz/"), 2);
    }

    /// The list is the authority's to make and every entry costs a request: the one entry over the
    /// names ends it, and the rest are not asked for.
    #[tokio::test]
    async fn an_order_that_lists_more_authorizations_than_names_is_refused_at_the_first_extra_one()
    {
        let fake = Fake::start(1_000, "pending").await;
        let e = order_at(&fake, 2)
            .await
            .authorizations()
            .await
            .expect_err("an error");
        assert!(e.text.contains("more authorizations than"), "{}", e.text);
        assert_eq!(fake.count("POST /authz/"), 3, "the two names and one over");
    }

    #[tokio::test]
    async fn the_reason_an_order_is_invalid_is_looked_up_for_no_more_authorizations_than_names() {
        let fake = Fake::start(1_000, "invalid").await;
        let e = order_at(&fake, 2)
            .await
            .wait_ready()
            .await
            .expect_err("an error");
        assert_eq!(e.text, "the authority made the order invalid");
        // For each name one fetch and one refresh, and the fetch of the first one over.
        let asked = fake.count("POST /authz/");
        assert!(asked <= 2 * 2 + 1, "{asked} requests");
    }

    fn unusable(e: &CaError) -> bool {
        e.problem.as_deref() == Some(CREDENTIALS_UNUSABLE)
    }

    /// An address nothing listens on.
    fn closed() -> String {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        format!("http://127.0.0.1:{port}/directory")
    }

    fn credentials(key: &str, directory: Option<&str>) -> Vec<u8> {
        let mut text = serde_json::json!({"id": "http://127.0.0.1:9/account/1", "key_pkcs8": key});
        if let Some(directory) = directory {
            text["directory"] = directory.into();
        }
        text.to_string().into_bytes()
    }

    #[tokio::test]
    async fn credentials_that_cannot_be_used_whatever_the_authority_is_are_told_from_a_failed_request()
     {
        let ca = InstantAcme::new(Http::allowing_plain());
        let fake = Fake::start(1, "pending").await;
        let (_, made) = ca.create_account(&fake.directory()).await.unwrap();
        let made: serde_json::Value = serde_json::from_slice(&made).unwrap();
        let key = made["key_pkcs8"].as_str().unwrap().to_owned();
        let nothing_listens = closed();

        // A key that is no P-256 key is refused before the directory is asked, so no failure of
        // the network comes out.
        let e = ca
            .restore_account(&credentials(ACCOUNT_KEY, Some(&nothing_listens)))
            .await
            .err()
            .expect("an error");
        assert!(unusable(&e), "{e:?}");
        // The text is fixed: what the parser says may quote the credentials.
        assert_eq!(e.text, "the kept account cannot be used");

        // Text that is no credentials, and credentials that name no directory.
        for text in [
            b"not json".to_vec(),
            br#"{"directory":"http://127.0.0.1:9/directory"}"#.to_vec(),
            credentials(&key, None),
            credentials("not base64!", Some(&nothing_listens)),
        ] {
            let e = ca.restore_account(&text).await.err().expect("an error");
            assert!(unusable(&e), "{e:?}");
        }

        // A usable key and a directory that cannot be reached: the network failed, not the file.
        let e = ca
            .restore_account(&credentials(&key, Some(&nothing_listens)))
            .await
            .err()
            .expect("an error");
        assert!(!unusable(&e), "{e:?}");
        assert!(!e.text.is_empty());

        // And with the directory there, the account comes back.
        let restored = ca
            .restore_account(&credentials(&key, Some(&fake.directory())))
            .await
            .unwrap();
        assert!(restored.new_order(&names(1)).await.is_ok());
    }
}
