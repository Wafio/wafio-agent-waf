//! The install side of the link: the sink the agent supplies, the codes of a refused install and
//! the wipe of the private key the message carries.

use std::borrow::BorrowMut;
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
/// stream order with the bundles around it. The link zeroes `key_pem` once this returns, also
/// after a panic; the sink must not log the message or keep a copy of the key it does not need.
pub trait CertificateSink: Send + Sync + 'static {
    fn install(&self, install: &mut CertificateInstall) -> Result<(), AckCode>;
}

/// Owns a `CertificateInstall` and zeroes its key when dropped, whichever way the install ends,
/// and also when the closure that holds it is dropped without ever running. `T` is the message or
/// a mutable borrow of it.
pub(crate) struct KeyWipe<T: BorrowMut<CertificateInstall>>(pub(crate) T);

impl<T: BorrowMut<CertificateInstall>> Drop for KeyWipe<T> {
    fn drop(&mut self) {
        let key = &mut BorrowMut::<CertificateInstall>::borrow_mut(&mut self.0).key_pem;
        key.fill(0);
        // Without this the compiler may drop the writes, as the buffer is freed right after.
        std::hint::black_box(&key[..]);
    }
}

/// Hands the install to the sink on a blocking thread. A panic in the sink is a refusal that may
/// succeed when repeated, as for a bundle.
pub(crate) async fn run_install(
    sink: Arc<dyn CertificateSink>,
    install: CertificateInstall,
) -> Result<(), AckCode> {
    let held = KeyWipe(install);
    tokio::task::spawn_blocking(move || install_with_wipe(&*sink, held))
        .await
        .unwrap_or(Err(AckCode::WriteFailed))
}

fn install_with_wipe<T: BorrowMut<CertificateInstall>>(
    sink: &dyn CertificateSink,
    mut held: KeyWipe<T>,
) -> Result<(), AckCode> {
    sink.install(BorrowMut::<CertificateInstall>::borrow_mut(&mut held.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn install() -> CertificateInstall {
        CertificateInstall {
            command_id: "c".into(),
            app_id: "a".into(),
            certificate_id: "i".into(),
            chain_pem: b"public chain".to_vec(),
            key_pem: b"bytes the sink may read and the link must zero".to_vec(),
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

    fn assert_wiped(m: &CertificateInstall, key_len: usize) {
        assert_eq!(
            m.key_pem.len(),
            key_len,
            "the length stays, only the bytes go"
        );
        assert!(m.key_pem.iter().all(|b| *b == 0), "{:?}", m.key_pem);
        assert_eq!(m.chain_pem, b"public chain", "only the key is zeroed");
    }

    #[test]
    fn every_ack_code_is_the_string_of_the_contract() {
        let table = [
            (AckCode::BadPem, "bad_pem"),
            (AckCode::TooLarge, "too_large"),
            (AckCode::KeyMismatch, "key_mismatch"),
            (AckCode::LeafMismatch, "leaf_mismatch"),
            (AckCode::UnsupportedKey, "unsupported_key"),
            (AckCode::NotInBundle, "not_in_bundle"),
            (AckCode::WriteFailed, "write_failed"),
        ];
        // Written as a match so a code added to the enum fails here until the table has it.
        for (code, _) in table {
            match code {
                AckCode::BadPem
                | AckCode::TooLarge
                | AckCode::KeyMismatch
                | AckCode::LeafMismatch
                | AckCode::UnsupportedKey
                | AckCode::NotInBundle
                | AckCode::WriteFailed => {}
            }
        }
        for (code, want) in table {
            assert_eq!(code.as_str(), want);
        }
        let mut names: Vec<_> = table.iter().map(|(c, _)| c.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 7);
    }

    #[test]
    fn the_key_is_zeroed_after_the_sink_returns_ok() {
        let mut m = install();
        let key_len = m.key_pem.len();
        assert_eq!(
            install_with_wipe(&Sink(Outcome::Ok), KeyWipe(&mut m)),
            Ok(())
        );
        assert_wiped(&m, key_len);
    }

    #[test]
    fn the_key_is_zeroed_after_the_sink_returns_an_error() {
        let mut m = install();
        let key_len = m.key_pem.len();
        let r = install_with_wipe(
            &Sink(Outcome::Refuse(AckCode::KeyMismatch)),
            KeyWipe(&mut m),
        );
        assert_eq!(r, Err(AckCode::KeyMismatch));
        assert_wiped(&m, key_len);
    }

    #[test]
    fn the_key_is_zeroed_when_the_sink_panics() {
        let mut m = install();
        let key_len = m.key_pem.len();
        let r = catch_unwind(AssertUnwindSafe(|| {
            install_with_wipe(&Sink(Outcome::Panic), KeyWipe(&mut m))
        }));
        assert!(r.is_err(), "the panic reaches the caller");
        assert_wiped(&m, key_len);
    }

    // The closure that holds the wrapper can be dropped unrun, as at runtime shutdown.
    #[test]
    fn the_key_is_zeroed_when_the_install_is_never_handed_to_the_sink() {
        let mut m = install();
        let key_len = m.key_pem.len();
        drop(KeyWipe(&mut m));
        assert_wiped(&m, key_len);
    }

    #[tokio::test]
    async fn a_panicking_sink_is_a_refusal_that_may_succeed_when_repeated() {
        let sink: Arc<dyn CertificateSink> = Arc::new(Sink(Outcome::Panic));
        assert_eq!(
            run_install(sink, install()).await,
            Err(AckCode::WriteFailed)
        );
        let sink: Arc<dyn CertificateSink> = Arc::new(Sink(Outcome::Refuse(AckCode::TooLarge)));
        assert_eq!(run_install(sink, install()).await, Err(AckCode::TooLarge));
        let sink: Arc<dyn CertificateSink> = Arc::new(Sink(Outcome::Ok));
        assert_eq!(run_install(sink, install()).await, Ok(()));
    }
}
