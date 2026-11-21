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
