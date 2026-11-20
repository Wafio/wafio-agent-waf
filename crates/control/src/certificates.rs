//! The install side of the link: the sink the agent supplies and the codes of a refused install.

use std::sync::Arc;
use wafio_proto::v1::CertificateInstall;

/// Why an install was refused. `as_str` is the whole `CommandAck.error` of a refusal: the control
/// plane stores any other text as `invalid_ack`, so a code never carries parser output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckCode {
    /// The chain has a block that is not a certificate or none at all, or the key is not exactly
    /// one unencrypted private key block.
    BadPem,
    /// The chain or the key is over its size limit, or the chain has too many certificates.
    TooLarge,
    /// The key does not belong to the leaf.
    KeyMismatch,
    /// `leaf_sha256` is not the digest of the chain's leaf.
    LeafMismatch,
    /// The key type is one the agent's TLS library cannot sign with.
    UnsupportedKey,
    /// The latest applied bundle does not name this app, certificate and leaf.
    NotInBundle,
    /// The pair could not be stored. Worth sending again.
    WriteFailed,
}

impl AckCode {
    pub fn as_str(self) -> &'static str {
        match self {
            AckCode::BadPem => "bad_pem",
            AckCode::TooLarge => "too_large",
            AckCode::KeyMismatch => "key_mismatch",
            AckCode::LeafMismatch => "leaf_mismatch",
            AckCode::UnsupportedKey => "unsupported_key",
            AckCode::NotInBundle => "not_in_bundle",
            AckCode::WriteFailed => "write_failed",
        }
    }
}

/// The agent's side of a `CertificateInstall`: checks the pair and keeps it.
///
/// Called on a blocking thread, and the receive loop waits for it, so an install is handled in
/// stream order with the bundles around it. The message zeroes `key_pem` when it is dropped, which
/// the link does once this returns, also after a panic. So the sink must not log the message,
/// keep a copy of the key it does not need, or take, replace, grow or shrink `key_pem`: a
/// reallocation frees the old block unzeroed. It parses the key from the slice.
pub trait CertificateSink: Send + Sync + 'static {
    fn install(&self, install: &mut CertificateInstall) -> Result<(), AckCode>;
}

/// Hands the install to the sink on a blocking thread. A panic in the sink is a refusal that may
/// succeed when repeated, as for a bundle. The message owns the wipe of its key, so it holds on
/// this path, on a panic and when the closure is dropped without running.
pub(crate) async fn run_install(
    sink: Arc<dyn CertificateSink>,
    mut install: CertificateInstall,
) -> Result<(), AckCode> {
    tokio::task::spawn_blocking(move || sink.install(&mut install))
        .await
        .unwrap_or(Err(AckCode::WriteFailed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install() -> CertificateInstall {
        CertificateInstall {
            command_id: "c".into(),
            app_id: "a".into(),
            certificate_id: "i".into(),
            chain_pem: b"public chain".to_vec(),
            key_pem: b"bytes the sink may read".to_vec(),
            leaf_sha256: "d".into(),
        }
    }

    enum Outcome {
        Ok,
        Refuse(AckCode),
        Panic,
    }

    /// Checks the key is whole while it runs, then ends as told.
    struct Sink(Outcome);
    impl CertificateSink for Sink {
        fn install(&self, install: &mut CertificateInstall) -> Result<(), AckCode> {
            assert!(
                install.key_pem.starts_with(b"bytes the sink"),
                "the sink gets the key before it is zeroed"
            );
            match self.0 {
                Outcome::Ok => Ok(()),
                Outcome::Refuse(c) => Err(c),
                Outcome::Panic => panic!("sink failed"),
            }
        }
    }

    /// The string of the contract for each code. The match is exhaustive, so a new code does not
    /// compile here until it has one; add it to `ALL` too.
    fn contract(code: AckCode) -> &'static str {
        match code {
            AckCode::BadPem => "bad_pem",
            AckCode::TooLarge => "too_large",
            AckCode::KeyMismatch => "key_mismatch",
            AckCode::LeafMismatch => "leaf_mismatch",
            AckCode::UnsupportedKey => "unsupported_key",
            AckCode::NotInBundle => "not_in_bundle",
            AckCode::WriteFailed => "write_failed",
        }
    }

    const ALL: [AckCode; 7] = [
        AckCode::BadPem,
        AckCode::TooLarge,
        AckCode::KeyMismatch,
        AckCode::LeafMismatch,
        AckCode::UnsupportedKey,
        AckCode::NotInBundle,
        AckCode::WriteFailed,
    ];

    #[test]
    fn every_ack_code_is_the_string_of_the_contract() {
        for code in ALL {
            assert_eq!(code.as_str(), contract(code));
        }
        let mut names = ALL.map(AckCode::as_str);
        names.sort_unstable();
        assert!(names.windows(2).all(|w| w[0] != w[1]), "{names:?}");
    }

    #[tokio::test]
    async fn the_sink_decides_and_a_panic_is_a_refusal_that_may_succeed_when_repeated() {
        let run = |outcome| run_install(Arc::new(Sink(outcome)), install());
        assert_eq!(run(Outcome::Ok).await, Ok(()));
        assert_eq!(
            run(Outcome::Refuse(AckCode::TooLarge)).await,
            Err(AckCode::TooLarge)
        );
        assert_eq!(run(Outcome::Panic).await, Err(AckCode::WriteFailed));
    }
}
