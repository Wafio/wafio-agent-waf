//! What an order needs of an ACME client, as a small set of traits. `instant` implements them over
//! `instant-acme`; a test implements them with a certificate authority of its own, so the rules of
//! an order (which challenge, what is put up and taken down, what is checked, what is kept) are
//! tested without a network.

use std::sync::Arc;

use async_trait::async_trait;
use zeroize::Zeroizing;

use super::Kind;

/// Why a request to the authority failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaError {
    /// The ACME problem type (`urn:ietf:params:acme:error:...`), when the authority sent one.
    pub problem: Option<String>,
    /// What the authority or the transport said.
    pub text: String,
}

impl CaError {
    pub fn new(text: impl Into<String>) -> CaError {
        CaError {
            problem: None,
            text: text.into(),
        }
    }

    /// The error as a line of a status: the problem type, when there is one, then what was said.
    pub fn line(&self) -> String {
        match &self.problem {
            Some(problem) => format!("{problem}: {}", self.text),
            None => self.text.clone(),
        }
    }
}

/// An authorization of an order: one name the authority wants proved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    /// The name, lower case.
    pub host: String,
    /// The authority holds a proof for it already, which no challenge is needed for.
    pub valid: bool,
    /// The challenges it offers that this agent can answer.
    pub offered: Vec<Kind>,
}

/// What a challenge is answered with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub token: String,
    /// The token and the account key's thumbprint: the body of an HTTP-01 answer.
    pub key_authorization: String,
    /// The SHA-256 of `key_authorization`: the value of the TLS-ALPN-01 certificate's extension.
    pub digest: [u8; 32],
}

/// The authority.
#[async_trait]
pub trait Ca: Send + Sync + 'static {
    /// Makes an account at `directory` with a key of its own, and gives the credentials to keep:
    /// text that holds the account key and names the directory (`"directory"` member).
    async fn create_account(
        &self,
        directory: &str,
    ) -> Result<(Arc<dyn Account>, Zeroizing<Vec<u8>>), CaError>;

    /// The account that kept credentials stand for.
    async fn restore_account(&self, credentials: &[u8]) -> Result<Arc<dyn Account>, CaError>;
}

#[async_trait]
pub trait Account: Send + Sync {
    /// Starts an order for the names `hosts`.
    async fn new_order(&self, hosts: &[String]) -> Result<Box<dyn Order>, CaError>;
}

/// One order, from its authorizations to its certificate. The calls come in this order.
#[async_trait]
pub trait Order: Send {
    /// The authorizations of the order, one for each name.
    async fn authorizations(&mut self) -> Result<Vec<Authorization>, CaError>;

    /// What the challenge of `kind` for `host` is answered with.
    async fn answer(&mut self, host: &str, kind: Kind) -> Result<Answer, CaError>;

    /// Tells the authority that the answer for `host` is up.
    async fn ready(&mut self, host: &str, kind: Kind) -> Result<(), CaError>;

    /// Waits until the authority has validated every name, or says it could not.
    async fn wait_ready(&mut self) -> Result<(), CaError>;

    /// Asks for the certificate for the request `csr` (DER).
    async fn finalize(&mut self, csr: &[u8]) -> Result<(), CaError>;

    /// Waits for the certificate and returns its chain as PEM text, leaf first.
    async fn certificate(&mut self) -> Result<String, CaError>;
}
