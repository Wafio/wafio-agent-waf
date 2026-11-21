//! The ACME account: one for the agent and the directory it orders from, kept in the key
//! directory (`acme-account.json`, the credentials of the client: the account's key and the
//! directory). It is made the first time an order needs it and again when the directory is not the
//! one the file names. Its key never leaves the file: it is in no status, no log line and not in
//! `state.json`.

use std::sync::Arc;

use serde::Deserialize;
use serde::de::IgnoredAny;
use zeroize::Zeroizing;

use super::ca::{Account, Ca, CaError};

/// The problem type of an authority that does not know the account any more.
pub const ACCOUNT_UNKNOWN: &str = "urn:ietf:params:acme:error:accountDoesNotExist";

/// Where the account is kept. Blocking: the key directory is written under its lock.
pub trait AccountFile: Send + Sync + 'static {
    /// The file, or `None` when there is none or it cannot be read.
    fn read(&self) -> Option<Zeroizing<Vec<u8>>>;
    fn write(&self, text: &[u8]) -> Result<(), String>;
    fn remove(&self);
}

/// What the credentials say about themselves, without keeping the key.
#[derive(Deserialize)]
struct Peek {
    #[allow(dead_code)]
    id: IgnoredAny,
    #[allow(dead_code)]
    key_pkcs8: IgnoredAny,
    directory: Option<String>,
}

/// The directory the kept credentials are for, if they are credentials at all.
fn directory_of(text: &[u8]) -> Option<String> {
    serde_json::from_slice::<Peek>(text).ok()?.directory
}

/// The account of one directory, as far as the process has got with it.
pub struct Accounts {
    ca: Arc<dyn Ca>,
    file: Arc<dyn AccountFile>,
    directory: String,
    current: Option<Arc<dyn Account>>,
}

impl Accounts {
    pub fn new(ca: Arc<dyn Ca>, file: Arc<dyn AccountFile>, directory: String) -> Accounts {
        Accounts {
            ca,
            file,
            directory,
            current: None,
        }
    }

    /// The account: the one in use, else the one the file keeps for this directory, else a new
    /// one, which is kept. A file that holds another directory's account, or none that can be
    /// read, is replaced.
    pub async fn get(&mut self) -> Result<Arc<dyn Account>, CaError> {
        if let Some(account) = &self.current {
            return Ok(account.clone());
        }
        let file = self.file.clone();
        let kept = tokio::task::spawn_blocking(move || file.read())
            .await
            .ok()
            .flatten();
        let account = match kept {
            Some(text) if directory_of(&text).as_deref() == Some(self.directory.as_str()) => {
                self.ca.restore_account(&text).await?
            }
            _ => {
                let (account, credentials) = self.ca.create_account(&self.directory).await?;
                let file = self.file.clone();
                let written = tokio::task::spawn_blocking(move || file.write(&credentials)).await;
                match written {
                    Ok(Ok(())) => tracing::info!("[acme] made an account at {}", self.directory),
                    Ok(Err(e)) => tracing::info!(
                        "[acme] made an account at {} but cannot keep it: {e}",
                        self.directory
                    ),
                    Err(_) => {}
                }
                account
            }
        };
        self.current = Some(account.clone());
        Ok(account)
    }

    /// The authority does not know the account: it is made again by the next order.
    pub async fn forget(&mut self) {
        self.current = None;
        let file = self.file.clone();
        let _ = tokio::task::spawn_blocking(move || file.remove()).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::tls::acme::mock::MockCa;
    use wafio_proxy::cert_store::CertBook;

    /// The account file, in memory.
    #[derive(Default)]
    struct Memory(Mutex<Option<Vec<u8>>>);

    impl AccountFile for Memory {
        fn read(&self) -> Option<Zeroizing<Vec<u8>>> {
            self.0.lock().unwrap().clone().map(Zeroizing::new)
        }

        fn write(&self, text: &[u8]) -> Result<(), String> {
            *self.0.lock().unwrap() = Some(text.to_vec());
            Ok(())
        }

        fn remove(&self) {
            *self.0.lock().unwrap() = None;
        }
    }

    const ONE: &str = "https://ca.test/one";
    const TWO: &str = "https://ca.test/two";

    fn rig() -> (MockCa, Arc<Memory>) {
        (MockCa::new(Arc::new(CertBook::default())), Arc::default())
    }

    fn accounts(ca: &MockCa, file: &Arc<Memory>, directory: &str) -> Accounts {
        Accounts::new(Arc::new(ca.clone()), file.clone(), directory.to_owned())
    }

    #[tokio::test]
    async fn the_account_is_made_once_for_a_directory_and_kept() {
        let (ca, file) = rig();
        let mut accounts = accounts(&ca, &file, ONE);
        accounts.get().await.unwrap();
        accounts.get().await.unwrap();
        assert_eq!(
            ca.script().created,
            [ONE],
            "one account for any number of orders"
        );
        let kept = file.read().expect("the credentials are kept");
        assert_eq!(directory_of(&kept).as_deref(), Some(ONE));

        // A new process with the same directory takes the one that is kept.
        let mut restarted = self::accounts(&ca, &file, ONE);
        restarted.get().await.unwrap();
        let script = ca.script();
        assert_eq!(script.created, [ONE]);
        assert_eq!(script.restored.len(), 1);
        assert_eq!(
            script.restored[0].as_bytes(),
            &kept[..],
            "the kept credentials as they were"
        );
    }

    #[tokio::test]
    async fn the_account_is_made_again_when_the_directory_changes_and_the_file_follows() {
        let (ca, file) = rig();
        accounts(&ca, &file, ONE).get().await.unwrap();
        accounts(&ca, &file, TWO).get().await.unwrap();
        assert_eq!(ca.script().created, [ONE, TWO]);
        assert_eq!(directory_of(&file.read().unwrap()).as_deref(), Some(TWO));
        // Back to the first directory: its account was replaced, so a new one is made.
        accounts(&ca, &file, ONE).get().await.unwrap();
        assert_eq!(ca.script().created, [ONE, TWO, ONE]);
        assert!(ca.script().restored.is_empty());
    }

    #[tokio::test]
    async fn a_file_that_holds_no_credentials_is_replaced() {
        for junk in [
            &b""[..],
            b"not json",
            br#"{"directory":"https://ca.test/one"}"#,
            br#"{"id":"a","key_pkcs8":"b"}"#,
        ] {
            let (ca, file) = rig();
            file.write(junk).unwrap();
            accounts(&ca, &file, ONE).get().await.unwrap();
            assert_eq!(ca.script().created, [ONE], "{junk:?}");
            assert!(ca.script().restored.is_empty());
            assert_eq!(directory_of(&file.read().unwrap()).as_deref(), Some(ONE));
        }
    }

    #[tokio::test]
    async fn an_account_the_authority_does_not_know_is_forgotten_and_made_again() {
        let (ca, file) = rig();
        let mut accounts = accounts(&ca, &file, ONE);
        accounts.get().await.unwrap();
        accounts.forget().await;
        assert!(file.read().is_none());
        accounts.get().await.unwrap();
        assert_eq!(ca.script().created, [ONE, ONE]);
    }
}
