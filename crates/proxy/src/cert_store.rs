//! The certificates every TLS listener serves: one book keyed by app id, and the challenge entries
//! a certificate order puts up while a certificate authority validates a name.
//!
//! A listener finds the app of an SNI name in its own host table and then asks the book what that
//! app serves. Whoever obtains a certificate (a bundle apply, an upload, an order) switches one
//! app with [`CertBook::set`] or the whole book with [`CertBook::follow`]; a handshake sees the old
//! or the new entry, never a mix. Private keys are never logged.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak};

use pingora::tls::sign::CertifiedKey;
use pingora::tls::{CryptoProvider, ResolvesServerCert, RusTlsError, ServerConfig, version};
use rustls_pki_types::pem::{Error as PemError, PemObject};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

/// The ALPN protocol of a TLS-ALPN-01 validation.
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// A certificate chain (leaf first) and its private key, both PEM files.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertFiles {
    pub certificate: PathBuf,
    pub key: PathBuf,
}

/// What the book serves for one app.
#[derive(Clone)]
pub struct BookEntry {
    pub key: Arc<CertifiedKey>,
    /// The self-signed stand-in of an app that has no certificate yet. A connection that got it
    /// is answered HTTP-01 challenges and `503`, and the redirect listener does not send the
    /// app's hosts to HTTPS.
    pub placeholder: bool,
}

#[derive(Default)]
struct State {
    /// App id to what its listener serves.
    apps: HashMap<String, BookEntry>,
    /// Host name (lower case) to the key of a pending TLS-ALPN-01 validation.
    tls_alpn: HashMap<String, Arc<CertifiedKey>>,
    /// Host name (lower case) to token to the key authorization of a pending HTTP-01 validation.
    http01: HashMap<String, HashMap<String, String>>,
}

/// The leaf of a chain: SHA-256 of its DER.
type LeafHash = [u8; 32];

/// The book of all TLS listeners of the process.
#[derive(Default)]
pub struct CertBook {
    state: RwLock<State>,
    /// Keys read from files that something still holds: a pair is parsed once per file and leaf.
    /// Weak, so a replaced certificate frees its key.
    loaded: Mutex<HashMap<(CertFiles, LeafHash), Weak<CertifiedKey>>>,
}

/// Prints no field: the book holds private keys.
impl fmt::Debug for CertBook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertBook").finish_non_exhaustive()
    }
}

impl CertBook {
    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// What `app_id` serves.
    pub fn get(&self, app_id: &str) -> Option<BookEntry> {
        self.read().apps.get(app_id).cloned()
    }

    /// Serves `key` for one app from the next handshake on: an installed certificate, an issued
    /// one, or the placeholder.
    pub fn set(&self, app_id: &str, key: Arc<CertifiedKey>, placeholder: bool) {
        self.write()
            .apps
            .insert(app_id.to_owned(), BookEntry { key, placeholder });
    }

    /// Makes the book hold exactly the apps of `wanted`. `Some` switches the app to that entry;
    /// `None` keeps what it holds now (the previous certificate while the wanted one is not ready).
    /// An app that is not in `wanted` is dropped. Challenge entries stay.
    pub fn follow(&self, wanted: HashMap<String, Option<BookEntry>>) {
        let mut state = self.write();
        let mut next = HashMap::with_capacity(wanted.len());
        for (app, entry) in wanted {
            let entry = entry.or_else(|| state.apps.remove(&app));
            if let Some(entry) = entry {
                next.insert(app, entry);
            }
        }
        state.apps = next;
    }

    /// The key to answer a TLS-ALPN-01 validation of `host` with.
    pub fn alpn_challenge(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        self.read()
            .tls_alpn
            .get(&host.to_ascii_lowercase())
            .cloned()
    }

    /// The key authorization of the pending HTTP-01 validation of `host` with `token`.
    pub fn http01_authorization(&self, host: &str, token: &str) -> Option<String> {
        self.read()
            .http01
            .get(&host.to_ascii_lowercase())?
            .get(token)
            .cloned()
    }

    /// Answers TLS-ALPN-01 validations of `host` with `key` until the guard drops.
    pub fn offer_tls_alpn(self: &Arc<Self>, host: &str, key: Arc<CertifiedKey>) -> ChallengeGuard {
        let host = host.to_ascii_lowercase();
        self.write().tls_alpn.insert(host.clone(), key);
        ChallengeGuard {
            book: self.clone(),
            entry: Offered::TlsAlpn(host),
        }
    }

    /// Answers an HTTP-01 validation of `host` at `token` with `authorization` until the guard drops.
    pub fn offer_http01(
        self: &Arc<Self>,
        host: &str,
        token: &str,
        authorization: &str,
    ) -> ChallengeGuard {
        let host = host.to_ascii_lowercase();
        self.write()
            .http01
            .entry(host.clone())
            .or_default()
            .insert(token.to_owned(), authorization.to_owned());
        ChallengeGuard {
            book: self.clone(),
            entry: Offered::Http01(host, token.to_owned()),
        }
    }

    /// The key of a pair of files. A pair whose leaf is already loaded is not parsed again, and
    /// its key file is not read. The error names the file, never key bytes.
    pub fn load(&self, files: &CertFiles) -> Result<Arc<CertifiedKey>, String> {
        let chain = read_chain(files)?;
        let leaf: LeafHash = Sha256::digest(chain[0].as_ref()).into();
        let mut loaded = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
        loaded.retain(|_, key| key.strong_count() > 0);
        let slot = (files.clone(), leaf);
        if let Some(key) = loaded.get(&slot).and_then(Weak::upgrade) {
            return Ok(key);
        }
        let key = Arc::new(certified_key(chain, files)?);
        loaded.insert(slot, Arc::downgrade(&key));
        Ok(key)
    }
}

enum Offered {
    TlsAlpn(String),
    Http01(String, String),
}

/// A challenge entry of the book; it is taken down when the guard drops, on every way out of an order.
#[must_use = "the challenge entry is removed when the guard drops"]
pub struct ChallengeGuard {
    book: Arc<CertBook>,
    entry: Offered,
}

impl Drop for ChallengeGuard {
    fn drop(&mut self) {
        let mut state = self.book.write();
        match &self.entry {
            Offered::TlsAlpn(host) => {
                state.tls_alpn.remove(host);
            }
            Offered::Http01(host, token) => {
                if let Some(tokens) = state.http01.get_mut(host) {
                    tokens.remove(token);
                    if tokens.is_empty() {
                        state.http01.remove(host);
                    }
                }
            }
        }
    }
}

/// The certificate chain of a pair of files, leaf first.
fn read_chain(files: &CertFiles) -> Result<Vec<CertificateDer<'static>>, String> {
    let bytes = fs::read(&files.certificate).map_err(|e| read_error(&files.certificate, &e))?;
    let chain = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("{}: not valid PEM", files.certificate.display()))?;
    if chain.is_empty() {
        return Err(format!("{}: no certificate", files.certificate.display()));
    }
    Ok(chain)
}

fn read_error(path: &Path, e: &std::io::Error) -> String {
    format!("{}: cannot read ({})", path.display(), e.kind())
}

/// The chain with the one PKCS#8, PKCS#1 or SEC1 key of `files.key`, which must match its leaf.
fn certified_key(
    chain: Vec<CertificateDer<'static>>,
    files: &CertFiles,
) -> Result<CertifiedKey, String> {
    let bytes = fs::read(&files.key).map_err(|e| read_error(&files.key, &e))?;
    let key = PrivateKeyDer::from_pem_slice(&bytes).map_err(|e| match e {
        PemError::NoItemsFound => format!("{}: no private key", files.key.display()),
        _ => format!("{}: not valid PEM", files.key.display()),
    })?;
    pingora::tls::install_default_crypto_provider();
    let Some(provider) = CryptoProvider::get_default() else {
        return Err("no TLS crypto provider installed".to_owned());
    };
    // `from_der` also checks that the key belongs to the leaf, which a half-copied pair fails.
    CertifiedKey::from_der(chain, key, provider).map_err(|e| match e {
        RusTlsError::InconsistentKeys(_) => format!(
            "{}: key does not match {}",
            files.key.display(),
            files.certificate.display()
        ),
        _ => format!("{}: private key not usable", files.key.display()),
    })
}

/// Reads a certificate chain and one PKCS#8, PKCS#1 or SEC1 key that matches its leaf. The error
/// names the file and the kind of failure, never key bytes.
pub fn load_certified_key(files: &CertFiles) -> Result<CertifiedKey, String> {
    certified_key(read_chain(files)?, files)
}

/// The rustls config of a TLS listener: TLS 1.2 and 1.3, certificates from `resolver`. ALPN lists
/// `acme-tls/1` first because rustls takes the first of this list that the client offers; a
/// browser never offers it, a certificate authority validating a name offers only it.
pub fn server_config(resolver: Arc<dyn ResolvesServerCert>) -> Arc<ServerConfig> {
    pingora::tls::install_default_crypto_provider();
    let mut config =
        ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(resolver);
    config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pingora::tls::SignatureScheme;

    /// A scratch directory in the system temp dir, removed on drop. The keys never leave it.
    pub(crate) struct Scratch(PathBuf);

    impl Scratch {
        pub(crate) fn new() -> Scratch {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "wafio-cert-store-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        /// A new self-signed pair, `<name>.crt` and `<name>.key`.
        pub(crate) fn pair(&self, name: &str) -> CertFiles {
            let files = CertFiles {
                certificate: self.0.join(format!("{name}.crt")),
                key: self.0.join(format!("{name}.key")),
            };
            let out = Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:prime256v1",
                ])
                .args([
                    "-nodes",
                    "-days",
                    "2",
                    "-subj",
                    &format!("/CN={name}"),
                    "-keyout",
                ])
                .arg(&files.key)
                .arg("-out")
                .arg(&files.certificate)
                .output()
                .expect("openssl is installed");
            assert!(out.status.success(), "openssl req failed");
            files
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn chain_of(files: &CertFiles) -> Vec<CertificateDer<'static>> {
        load_certified_key(files).unwrap().cert
    }

    fn entry(key: &Arc<CertifiedKey>) -> Option<BookEntry> {
        Some(BookEntry {
            key: key.clone(),
            placeholder: false,
        })
    }

    #[test]
    fn a_pair_is_parsed_once_per_file_and_leaf_and_a_new_leaf_is_read() {
        let dir = Scratch::new();
        let (live, next) = (dir.pair("live"), dir.pair("next"));
        let book = CertBook::default();
        let first = book.load(&live).unwrap();
        assert!(Arc::ptr_eq(&first, &book.load(&live).unwrap()));

        // A hit does not read the key file: it can be gone.
        let key_text = fs::read(&live.key).unwrap();
        fs::remove_file(&live.key).unwrap();
        assert!(Arc::ptr_eq(&first, &book.load(&live).unwrap()));
        fs::write(&live.key, key_text).unwrap();

        // The same names with another leaf (a renewal written over the files) is a new key.
        fs::rename(&next.certificate, &live.certificate).unwrap();
        fs::rename(&next.key, &live.key).unwrap();
        let renewed = book.load(&live).unwrap();
        assert!(!Arc::ptr_eq(&first, &renewed));
        assert_eq!(renewed.cert, chain_of(&live));
        assert_ne!(first.cert, renewed.cert);
    }

    #[test]
    fn a_key_nothing_holds_is_dropped_from_the_cache() {
        let dir = Scratch::new();
        let live = dir.pair("live");
        let book = CertBook::default();
        let first = book.load(&live).unwrap();
        let weak = Arc::downgrade(&first);
        drop(first);
        assert!(weak.upgrade().is_none());
        // The next load reads it again and prunes the dead slot.
        let again = book.load(&live).unwrap();
        assert_eq!(book.loaded.lock().unwrap().len(), 1);
        drop(again);
    }

    #[test]
    fn load_names_the_file_that_fails_and_never_the_key() {
        let dir = Scratch::new();
        let (live, next) = (dir.pair("live"), dir.pair("next"));
        let book = CertBook::default();

        fs::write(&live.certificate, "not a certificate").unwrap();
        let err = book.load(&live).err().unwrap();
        assert!(
            err.contains("live.crt") && err.contains("no certificate"),
            "{err}"
        );

        // A half-copied pair: the new certificate, the old key.
        fs::rename(&next.certificate, &live.certificate).unwrap();
        let err = book.load(&live).err().unwrap();
        assert!(
            err.contains("does not match") && err.contains("live.key"),
            "{err}"
        );
        assert!(!err.contains("PRIVATE KEY"), "{err}");

        let absent = CertFiles {
            certificate: dir.0.join("absent.crt"),
            key: dir.0.join("absent.key"),
        };
        let err = book.load(&absent).err().unwrap();
        assert!(err.contains("absent.crt"), "{err}");
    }

    #[test]
    fn set_switches_one_app_and_leaves_the_others() {
        let dir = Scratch::new();
        let book = CertBook::default();
        let (a, b, c) = (
            Arc::new(load_certified_key(&dir.pair("a")).unwrap()),
            Arc::new(load_certified_key(&dir.pair("b")).unwrap()),
            Arc::new(load_certified_key(&dir.pair("c")).unwrap()),
        );
        book.set("one", a.clone(), true);
        book.set("two", b.clone(), false);
        let held = book.get("one").unwrap();
        assert!(Arc::ptr_eq(&held.key, &a) && held.placeholder);

        book.set("one", c.clone(), false);
        let (one, two) = (book.get("one").unwrap(), book.get("two").unwrap());
        assert!(Arc::ptr_eq(&one.key, &c) && !one.placeholder);
        assert!(Arc::ptr_eq(&two.key, &b));
        assert!(book.get("three").is_none());
        // A key an open handshake holds stays valid after the switch.
        assert!(
            held.key
                .key
                .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_some()
        );
    }

    #[test]
    fn follow_sets_keeps_and_drops() {
        let dir = Scratch::new();
        let book = CertBook::default();
        let key = |name: &str| Arc::new(load_certified_key(&dir.pair(name)).unwrap());
        let (kept, replaced, dropped, added) =
            (key("kept"), key("replaced"), key("dropped"), key("added"));
        let replacement = key("replacement");
        book.set("kept", kept.clone(), false);
        book.set("replaced", replaced, false);
        book.set("dropped", dropped, false);

        book.follow(HashMap::from([
            ("kept".to_owned(), None),
            ("replaced".to_owned(), entry(&replacement)),
            ("added".to_owned(), entry(&added)),
            // Nothing held and nothing wanted yet: stays out.
            ("waiting".to_owned(), None),
        ]));

        assert!(Arc::ptr_eq(&book.get("kept").unwrap().key, &kept));
        assert!(Arc::ptr_eq(
            &book.get("replaced").unwrap().key,
            &replacement
        ));
        assert!(Arc::ptr_eq(&book.get("added").unwrap().key, &added));
        assert!(book.get("dropped").is_none());
        assert!(book.get("waiting").is_none());
    }

    #[test]
    fn challenge_entries_exist_while_their_guard_does() {
        let dir = Scratch::new();
        let book = Arc::new(CertBook::default());
        let key = Arc::new(load_certified_key(&dir.pair("challenge")).unwrap());

        let alpn = book.offer_tls_alpn("Shop.Example.com", key.clone());
        let (first, second) = (
            book.offer_http01("shop.example.com", "tok-1", "tok-1.thumb"),
            book.offer_http01("SHOP.example.com", "tok_2", "tok_2.thumb"),
        );
        assert!(Arc::ptr_eq(
            &book.alpn_challenge("shop.EXAMPLE.com").unwrap(),
            &key
        ));
        assert_eq!(
            book.http01_authorization("shop.example.com", "tok-1")
                .as_deref(),
            Some("tok-1.thumb")
        );
        // The token is case sensitive, the host is not; the token belongs to its host.
        assert_eq!(book.http01_authorization("shop.example.com", "TOK-1"), None);
        assert_eq!(
            book.http01_authorization("Shop.Example.com", "tok_2")
                .as_deref(),
            Some("tok_2.thumb")
        );
        assert_eq!(
            book.http01_authorization("other.example.com", "tok-1"),
            None
        );

        drop(first);
        assert_eq!(book.http01_authorization("shop.example.com", "tok-1"), None);
        assert!(
            book.http01_authorization("shop.example.com", "tok_2")
                .is_some()
        );
        drop(second);
        assert!(book.read().http01.is_empty(), "no empty host table is left");
        assert!(book.alpn_challenge("shop.example.com").is_some());
        drop(alpn);
        assert!(book.alpn_challenge("shop.example.com").is_none());
    }

    #[test]
    fn the_server_offers_acme_tls_first_and_http_1_1() {
        struct Nothing;
        impl fmt::Debug for Nothing {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("Nothing")
            }
        }
        impl ResolvesServerCert for Nothing {
            fn resolve(&self, _: pingora::tls::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
                None
            }
        }
        let config = server_config(Arc::new(Nothing));
        assert_eq!(
            config.alpn_protocols,
            vec![b"acme-tls/1".to_vec(), b"http/1.1".to_vec()]
        );
    }
}
