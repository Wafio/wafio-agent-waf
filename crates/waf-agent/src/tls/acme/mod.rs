//! Certificates the agent orders itself from an ACME certificate authority, for apps whose bundle
//! entry has the source `acme`.
//!
//! The parts, from the bottom: `http` carries the client's requests over the agent's own HTTP
//! client; `ca` is the small interface an order needs of an ACME client and `instant` is its one
//! implementation; `schedule` decides, as a function of what `state.json` remembers, the bundle
//! entry and the clock, which app is due and which challenge to answer, and `wait` how long a
//! failed order holds the next one back; `order` runs one order and checks what comes out of it;
//! `account` keeps the one account per directory; `placeholder` is what an app is served until
//! its first certificate; `worker` runs the orders one at a time in the process that holds the
//! key directory lock.

pub mod account;
pub mod ca;
pub mod http;
pub mod instant;
pub mod names;
pub mod order;
pub mod placeholder;
pub mod schedule;
pub mod wait;
pub mod worker;

#[cfg(test)]
pub(crate) mod mock;

/// The directory of the certificate authority an agent orders from when none is configured.
pub const DEFAULT_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// The file of the key directory that holds the account.
pub const ACCOUNT_FILE: &str = "acme-account.json";

/// How long one attempt, account and order together, may take.
pub const ATTEMPT_CAP: std::time::Duration = std::time::Duration::from_secs(3 * 60);

/// The way a certificate authority checks that an app answers for a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A TLS handshake with the ALPN protocol `acme-tls/1`, on port 443.
    TlsAlpn01,
    /// A plain GET of a well-known path, on port 80.
    Http01,
}

impl Kind {
    /// The name the protocol and `state.json` use.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::TlsAlpn01 => "tls-alpn-01",
            Kind::Http01 => "http-01",
        }
    }

    pub fn parse(text: &str) -> Option<Kind> {
        [Kind::TlsAlpn01, Kind::Http01]
            .into_iter()
            .find(|k| k.as_str() == text)
    }

    pub fn other(self) -> Kind {
        match self {
            Kind::TlsAlpn01 => Kind::Http01,
            Kind::Http01 => Kind::TlsAlpn01,
        }
    }
}
