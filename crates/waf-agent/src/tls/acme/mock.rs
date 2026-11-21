//! An ACME authority for tests: it answers the traits of `ca` and signs what an order asks for
//! with a root of its own, so an order can be run with no network, and made to fail, hang or
//! panic at any step.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256, PublicKeyData, SignatureAlgorithm,
};
use wafio_proxy::cert_store::{CertBook, push_pem_block};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::prelude::FromDer;
use zeroize::Zeroizing;

use super::Kind;
use super::ca::{Account, Answer, Authorization, Ca, CaError, Order};

/// The steps of an order, for a test to make one fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    NewOrder,
    Authorizations,
    Answer,
    Ready,
    WaitReady,
    Finalize,
    Certificate,
}

/// What the authority issues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Issue {
    /// A certificate for the names and the key of the request.
    Good,
    /// A certificate for the names of the request and another key.
    OtherKey,
    /// A certificate for the first name only.
    FirstNameOnly,
    /// Text that is no certificate chain.
    Garbage,
}

pub struct Script {
    /// The directory of each account made.
    pub created: Vec<String>,
    /// The credentials of each account restored.
    pub restored: Vec<String>,
    /// The names of each order.
    pub orders: Vec<Vec<String>>,
    /// What happened, in order: `new order`, `answer a.example.com http-01`, `ready ...`.
    pub events: Vec<String>,
    pub running: usize,
    pub most_running: usize,
    /// Names the authority holds a proof for already.
    pub valid: HashSet<String>,
    /// The challenges it offers.
    pub offered: Vec<Kind>,
    pub fail: Option<(Step, CaError)>,
    pub hang: Option<Step>,
    /// Stops at the step until the notification is given, after telling `MockCa::reached`.
    pub pause: Option<(Step, Arc<tokio::sync::Notify>)>,
    pub panic: Option<Step>,
    pub issue: Issue,
    /// While an order waits to be validated: for each name it is up for, whether the book holds the
    /// challenge entry of the kind that was answered.
    pub up_while_waiting: Vec<(String, Kind, bool)>,
    /// The certificate (DER) the book held for each TLS-ALPN-01 answer while the authority looked.
    pub alpn_certs: Vec<Vec<u8>>,
    /// The token of the HTTP-01 answer each name got, and the authorization.
    pub http_answers: Vec<(String, String, String)>,
}

impl Default for Script {
    fn default() -> Script {
        Script {
            created: Vec::new(),
            restored: Vec::new(),
            orders: Vec::new(),
            events: Vec::new(),
            running: 0,
            most_running: 0,
            valid: HashSet::new(),
            offered: vec![Kind::TlsAlpn01, Kind::Http01],
            fail: None,
            hang: None,
            pause: None,
            panic: None,
            issue: Issue::Good,
            up_while_waiting: Vec::new(),
            alpn_certs: Vec::new(),
            http_answers: Vec::new(),
        }
    }
}

struct Root {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

/// The authority. Clones share what is scripted and what happened.
#[derive(Clone)]
pub struct MockCa {
    pub script: Arc<Mutex<Script>>,
    /// The book of the listeners, which the authority looks into while it waits for the answers to
    /// be up.
    pub book: Arc<CertBook>,
    /// Notified when an order stops at the step of `Script::pause`.
    pub reached: Arc<tokio::sync::Notify>,
    root: Arc<Root>,
}

impl MockCa {
    pub fn new(book: Arc<CertBook>) -> MockCa {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        MockCa {
            script: Arc::default(),
            book,
            reached: Arc::default(),
            root: Arc::new(Root { issuer }),
        }
    }

    /// The same authority and script, looking into another book: another process of the agent that
    /// orders from it.
    pub fn with_book(&self, book: Arc<CertBook>) -> MockCa {
        MockCa {
            book,
            reached: Arc::default(),
            ..self.clone()
        }
    }

    pub fn script(&self) -> std::sync::MutexGuard<'_, Script> {
        self.script.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl Ca for MockCa {
    async fn create_account(
        &self,
        directory: &str,
    ) -> Result<(Arc<dyn Account>, Zeroizing<Vec<u8>>), CaError> {
        let id = {
            let mut script = self.script();
            script.created.push(directory.to_owned());
            script.created.len()
        };
        // The shape of the client's credentials; the key is a marker the tests look for.
        let credentials = format!(
            r#"{{"id":"https://ca.test/acct/{id}","key_pkcs8":"{ACCOUNT_KEY}","directory":"{directory}"}}"#
        );
        Ok((
            Arc::new(MockAccount(self.clone())),
            Zeroizing::new(credentials.into_bytes()),
        ))
    }

    async fn restore_account(&self, credentials: &[u8]) -> Result<Arc<dyn Account>, CaError> {
        self.script()
            .restored
            .push(String::from_utf8_lossy(credentials).into_owned());
        Ok(Arc::new(MockAccount(self.clone())))
    }
}

/// What the credentials of the mock account hold as their key.
pub const ACCOUNT_KEY: &str = "bW9jayBhY2NvdW50IGtleSBieXRlcw";

struct MockAccount(MockCa);

#[async_trait]
impl Account for MockAccount {
    async fn new_order(&self, hosts: &[String]) -> Result<Box<dyn Order>, CaError> {
        let ca = self.0.clone();
        {
            let mut script = ca.script();
            script.orders.push(hosts.to_vec());
            script.events.push("new order".into());
            script.running += 1;
            script.most_running = script.most_running.max(script.running);
        }
        let order = MockOrder {
            ca,
            hosts: hosts.to_vec(),
            answered: Vec::new(),
            csr: None,
        };
        order.step(Step::NewOrder).await?;
        Ok(Box::new(order))
    }
}

struct MockOrder {
    ca: MockCa,
    hosts: Vec<String>,
    answered: Vec<(String, Kind)>,
    csr: Option<Vec<u8>>,
}

impl Drop for MockOrder {
    fn drop(&mut self) {
        self.ca.script().running -= 1;
    }
}

struct Spki(Vec<u8>);

impl PublicKeyData for Spki {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl MockOrder {
    /// What the script says to do at `step`.
    async fn step(&self, step: Step) -> Result<(), CaError> {
        let (fail, hang, panic, pause) = {
            let script = self.ca.script();
            (
                script.fail.clone(),
                script.hang,
                script.panic,
                script.pause.clone(),
            )
        };
        assert_ne!(panic, Some(step), "the authority panics at {step:?}");
        if let Some((at, go)) = pause
            && at == step
        {
            self.ca.reached.notify_one();
            go.notified().await;
        }
        if hang == Some(step) {
            std::future::pending::<()>().await;
        }
        match fail {
            Some((at, error)) if at == step => Err(error),
            _ => Ok(()),
        }
    }

    fn sign(&self, issue: Issue) -> Result<String, CaError> {
        let csr = self.csr.as_ref().expect("finalized before");
        let (_, request) = X509CertificationRequest::from_der(csr).expect("a request");
        let key = request
            .certification_request_info
            .subject_pki
            .subject_public_key
            .data
            .to_vec();
        let names: Vec<String> = match issue {
            Issue::FirstNameOnly => self.hosts[..1].to_vec(),
            _ => self.hosts.clone(),
        };
        let params = CertificateParams::new(names).unwrap();
        let issuer: &Issuer<'_, KeyPair> = &self.ca.root.issuer;
        let leaf = match issue {
            Issue::OtherKey => params
                .signed_by(&KeyPair::generate().unwrap(), issuer)
                .unwrap(),
            _ => params.signed_by(&Spki(key), issuer).unwrap(),
        };
        let mut text = Vec::new();
        push_pem_block("CERTIFICATE", leaf.der(), &mut text);
        push_pem_block("CERTIFICATE", self.ca.root.issuer.der(), &mut text);
        Ok(String::from_utf8(text).unwrap())
    }
}

#[async_trait]
impl Order for MockOrder {
    async fn authorizations(&mut self) -> Result<Vec<Authorization>, CaError> {
        self.step(Step::Authorizations).await?;
        let script = self.ca.script();
        Ok(self
            .hosts
            .iter()
            .map(|host| Authorization {
                host: host.clone(),
                valid: script.valid.contains(host),
                offered: script.offered.clone(),
            })
            .collect())
    }

    async fn answer(&mut self, host: &str, kind: Kind) -> Result<Answer, CaError> {
        self.step(Step::Answer).await?;
        let token = format!("token-{host}");
        let key_authorization = format!("{token}.thumbprint");
        let digest = [7u8; 32];
        let mut script = self.ca.script();
        script
            .events
            .push(format!("answer {host} {}", kind.as_str()));
        script
            .http_answers
            .push((host.to_owned(), token.clone(), key_authorization.clone()));
        self.answered.push((host.to_owned(), kind));
        Ok(Answer {
            token,
            key_authorization,
            digest,
        })
    }

    async fn ready(&mut self, host: &str, kind: Kind) -> Result<(), CaError> {
        self.step(Step::Ready).await?;
        self.ca
            .script()
            .events
            .push(format!("ready {host} {}", kind.as_str()));
        Ok(())
    }

    async fn wait_ready(&mut self) -> Result<(), CaError> {
        // The authority validates now: it looks at the book as a validator would.
        let up: Vec<(String, Kind, bool, Option<Vec<u8>>)> = self
            .answered
            .iter()
            .map(|(host, kind)| match kind {
                Kind::TlsAlpn01 => {
                    let key = self.ca.book.alpn_challenge(host);
                    let der = key.as_ref().map(|k| k.cert[0].as_ref().to_vec());
                    (host.clone(), *kind, key.is_some(), der)
                }
                Kind::Http01 => {
                    let present = self
                        .ca
                        .book
                        .http01_authorization(host, &format!("token-{host}"))
                        .is_some_and(|a| a == format!("token-{host}.thumbprint"));
                    (host.clone(), *kind, present, None)
                }
            })
            .collect();
        {
            let mut script = self.ca.script();
            for (host, kind, present, der) in up {
                script.up_while_waiting.push((host, kind, present));
                script.alpn_certs.extend(der);
            }
            script.events.push("validated".into());
        }
        self.step(Step::WaitReady).await
    }

    async fn finalize(&mut self, csr: &[u8]) -> Result<(), CaError> {
        self.step(Step::Finalize).await?;
        self.csr = Some(csr.to_vec());
        self.ca.script().events.push("finalize".into());
        Ok(())
    }

    async fn certificate(&mut self) -> Result<String, CaError> {
        self.step(Step::Certificate).await?;
        let issue = self.ca.script().issue;
        if issue == Issue::Garbage {
            return Ok("this is not a certificate".into());
        }
        self.sign(issue)
    }
}
