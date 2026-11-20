//! The certificates every TLS listener serves: one book keyed by app id, and the challenge entries
//! a certificate order puts up while a certificate authority validates a name.
//!
//! A listener finds the app of an SNI name in its own host table and then asks the book what that
//! app serves. Whoever obtains a certificate (a bundle apply, an upload, an order) switches one
//! app with [`CertBook::set`] or the whole book with [`CertBook::follow`]; a handshake sees the old
//! or the new entry, never a mix. The book holds no app that the last `follow` did not name, and
//! `set` refuses one, so whoever finishes late (an upload, an order) cannot put back an app that
//! left the bundle.
//! Private keys are never logged.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

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

/// What is offered under one name, oldest first, each with the id of its offer. The newest answers
/// a validation; when it is withdrawn the one before it answers again.
type Offers<T> = Vec<(u64, T)>;

#[derive(Default)]
struct State {
    /// App id to what its listener serves.
    apps: HashMap<String, BookEntry>,
    /// The apps the last `follow` named, held or not. Only these can be switched.
    wanted: HashSet<String>,
    /// Host name (lower case) to the keys of the pending TLS-ALPN-01 validations.
    tls_alpn: HashMap<String, Offers<Arc<CertifiedKey>>>,
    /// Host name (lower case) and token to the key authorizations of the pending HTTP-01 validations.
    http01: HashMap<(String, String), Offers<String>>,
    /// The id of the last offer made.
    last_offer: u64,
}

impl State {
    fn next_offer(&mut self) -> u64 {
        self.last_offer += 1;
        self.last_offer
    }
}

/// The book of all TLS listeners of the process.
#[derive(Default)]
pub struct CertBook {
    state: RwLock<State>,
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
    /// one, or the placeholder. Only while the last `follow` named the app, which is checked under
    /// the lock of the switch: `false` means the app has left the bundle and the book is unchanged.
    #[must_use = "false means the certificate was not put into the book"]
    pub fn set(&self, app_id: &str, key: Arc<CertifiedKey>, placeholder: bool) -> bool {
        let mut state = self.write();
        if !state.wanted.contains(app_id) {
            return false;
        }
        state
            .apps
            .insert(app_id.to_owned(), BookEntry { key, placeholder });
        true
    }

    /// Makes the book hold exactly the apps of `wanted`. `Some` switches the app to that entry;
    /// `None` keeps what it holds now (the previous certificate while the wanted one is not ready).
    /// An app that is not in `wanted` is dropped, and `set` refuses it until a later `follow` names
    /// it again. Challenge entries stay.
    pub fn follow(&self, wanted: HashMap<String, Option<BookEntry>>) {
        let mut state = self.write();
        let names: HashSet<String> = wanted.keys().cloned().collect();
        let mut next = HashMap::with_capacity(wanted.len());
        for (app, entry) in wanted {
            let entry = entry.or_else(|| state.apps.remove(&app));
            if let Some(entry) = entry {
                next.insert(app, entry);
            }
        }
        state.apps = next;
        state.wanted = names;
    }

    /// The key to answer a TLS-ALPN-01 validation of `host` with.
    pub fn alpn_challenge(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let state = self.read();
        let (_, key) = state.tls_alpn.get(&host.to_ascii_lowercase())?.last()?;
        Some(key.clone())
    }

    /// The key authorization of the pending HTTP-01 validation of `host` with `token`.
    pub fn http01_authorization(&self, host: &str, token: &str) -> Option<String> {
        let state = self.read();
        let name = (host.to_ascii_lowercase(), token.to_owned());
        let (_, authorization) = state.http01.get(&name)?.last()?;
        Some(authorization.clone())
    }

    /// Answers TLS-ALPN-01 validations of `host` with `key` until the guard drops. An offer for a
    /// host that already has one is answered first; the guard of either takes down its own only.
    pub fn offer_tls_alpn(self: &Arc<Self>, host: &str, key: Arc<CertifiedKey>) -> ChallengeGuard {
        let host = host.to_ascii_lowercase();
        let mut state = self.write();
        let id = state.next_offer();
        state
            .tls_alpn
            .entry(host.clone())
            .or_default()
            .push((id, key));
        ChallengeGuard {
            book: self.clone(),
            id,
            entry: Offered::TlsAlpn(host),
        }
    }

    /// Answers an HTTP-01 validation of `host` at `token` with `authorization` until the guard
    /// drops. Offers for the same host and token stack as for TLS-ALPN-01.
    pub fn offer_http01(
        self: &Arc<Self>,
        host: &str,
        token: &str,
        authorization: &str,
    ) -> ChallengeGuard {
        let name = (host.to_ascii_lowercase(), token.to_owned());
        let mut state = self.write();
        let id = state.next_offer();
        state
            .http01
            .entry(name.clone())
            .or_default()
            .push((id, authorization.to_owned()));
        ChallengeGuard {
            book: self.clone(),
            id,
            entry: Offered::Http01(name),
        }
    }
}

enum Offered {
    TlsAlpn(String),
    Http01((String, String)),
}

/// A challenge entry of the book; it is taken down when the guard drops, on every way out of an
/// order. A guard takes down the offer it made and no other: an order that is retried puts its new
/// entry up before the old guard drops.
#[must_use = "the challenge entry is removed when the guard drops"]
pub struct ChallengeGuard {
    book: Arc<CertBook>,
    id: u64,
    entry: Offered,
}

impl Drop for ChallengeGuard {
    fn drop(&mut self) {
        let mut state = self.book.write();
        match &self.entry {
            Offered::TlsAlpn(host) => withdraw(&mut state.tls_alpn, host, self.id),
            Offered::Http01(name) => withdraw(&mut state.http01, name, self.id),
        }
    }
}

/// Takes offer `id` out of what is offered under `name`, and the name out of the map once nothing
/// is left.
fn withdraw<K: Hash + Eq, T>(offers: &mut HashMap<K, Offers<T>>, name: &K, id: u64) {
    if let Some(list) = offers.get_mut(name) {
        list.retain(|(offered, _)| *offered != id);
        if list.is_empty() {
            offers.remove(name);
        }
    }
}

/// Why a PEM text is not a usable certificate chain with its key. The texts say nothing of the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairFault {
    NotPem,
    NoCertificate,
    NoKey,
    KeyUnusable,
    KeyMismatch,
}

impl fmt::Display for PairFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PairFault::NotPem => "not valid PEM",
            PairFault::NoCertificate => "no certificate",
            PairFault::NoKey => "no private key",
            PairFault::KeyUnusable => "private key not usable",
            PairFault::KeyMismatch => "key does not match the certificate",
        })
    }
}

/// The certificate blocks of a PEM text, leaf first. Other blocks are skipped.
fn parse_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, PairFault> {
    let chain = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PairFault::NotPem)?;
    if chain.is_empty() {
        return Err(PairFault::NoCertificate);
    }
    Ok(chain)
}

/// `chain` with the first PKCS#8, PKCS#1 or SEC1 key block of `pem`, which must match the leaf.
fn parse_key(chain: Vec<CertificateDer<'static>>, pem: &[u8]) -> Result<CertifiedKey, PairFault> {
    let key = PrivateKeyDer::from_pem_slice(pem).map_err(|e| match e {
        PemError::NoItemsFound => PairFault::NoKey,
        _ => PairFault::NotPem,
    })?;
    pingora::tls::install_default_crypto_provider();
    let Some(provider) = CryptoProvider::get_default() else {
        return Err(PairFault::KeyUnusable);
    };
    // `from_der` also checks that the key belongs to the leaf, which a half-copied pair fails.
    CertifiedKey::from_der(chain, key, provider).map_err(|e| match e {
        RusTlsError::InconsistentKeys(_) => PairFault::KeyMismatch,
        _ => PairFault::KeyUnusable,
    })
}

/// The key and chain of one PEM text: a private key block and the certificate blocks, leaf first,
/// in any order. The key must match the leaf.
pub fn certified_key_from_pem(pem: &[u8]) -> Result<CertifiedKey, PairFault> {
    parse_key(parse_chain(pem)?, pem)
}

/// Lower case hex SHA-256 of the DER of the leaf of the chain of `key`, which is how the control
/// plane names a certificate.
pub fn leaf_sha256(key: &CertifiedKey) -> String {
    Sha256::digest(key.cert[0].as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn read_error(path: &Path, e: &std::io::Error) -> String {
    format!("{}: cannot read ({})", path.display(), e.kind())
}

/// Reads a certificate chain and one PKCS#8, PKCS#1 or SEC1 key that matches its leaf. The error
/// names the file and the kind of failure, never key bytes.
pub fn load_certified_key(files: &CertFiles) -> Result<CertifiedKey, String> {
    let cert = fs::read(&files.certificate).map_err(|e| read_error(&files.certificate, &e))?;
    let chain = parse_chain(&cert).map_err(|f| format!("{}: {f}", files.certificate.display()))?;
    let key = fs::read(&files.key).map_err(|e| read_error(&files.key, &e))?;
    parse_key(chain, &key).map_err(|f| match f {
        PairFault::KeyMismatch => format!(
            "{}: key does not match {}",
            files.key.display(),
            files.certificate.display()
        ),
        f => format!("{}: {f}", files.key.display()),
    })
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
    fn load_names_the_file_that_fails_and_never_the_key() {
        let dir = Scratch::new();
        let (live, next) = (dir.pair("live"), dir.pair("next"));

        fs::write(&live.certificate, "not a certificate").unwrap();
        let err = load_certified_key(&live).err().unwrap();
        assert!(
            err.contains("live.crt") && err.contains("no certificate"),
            "{err}"
        );

        // A half-copied pair: the new certificate, the old key.
        fs::rename(&next.certificate, &live.certificate).unwrap();
        let err = load_certified_key(&live).err().unwrap();
        assert!(
            err.contains("does not match") && err.contains("live.key"),
            "{err}"
        );
        assert!(!err.contains("PRIVATE KEY"), "{err}");

        let absent = CertFiles {
            certificate: dir.0.join("absent.crt"),
            key: dir.0.join("absent.key"),
        };
        let err = load_certified_key(&absent).err().unwrap();
        assert!(err.contains("absent.crt"), "{err}");
    }

    #[test]
    fn one_pem_text_holds_a_key_and_its_chain_in_either_order() {
        let dir = Scratch::new();
        let (live, other) = (dir.pair("live"), dir.pair("other"));
        let (cert, key) = (
            fs::read(&live.certificate).unwrap(),
            fs::read(&live.key).unwrap(),
        );
        let expected = chain_of(&live);
        for pem in [
            [key.clone(), cert.clone()].concat(),
            [cert.clone(), key.clone()].concat(),
        ] {
            assert_eq!(certified_key_from_pem(&pem).unwrap().cert, expected);
        }
        let both = [
            key.clone(),
            cert.clone(),
            fs::read(&other.certificate).unwrap(),
        ]
        .concat();
        assert_eq!(certified_key_from_pem(&both).unwrap().cert.len(), 2);

        let fault = |pem: &[u8]| certified_key_from_pem(pem).err().unwrap();
        assert_eq!(fault(b"nothing here"), PairFault::NoCertificate);
        assert_eq!(fault(&cert), PairFault::NoKey);
        assert_eq!(fault(&key), PairFault::NoCertificate);
        let swapped = [fs::read(&other.key).unwrap(), cert.clone()].concat();
        assert_eq!(fault(&swapped), PairFault::KeyMismatch);
        let torn = [key, b"-----BEGIN CERTIFICATE-----\nMIIB".to_vec()].concat();
        assert_eq!(fault(&torn), PairFault::NotPem);
        for f in [PairFault::NotPem, PairFault::KeyMismatch, PairFault::NoKey] {
            assert!(!f.to_string().contains("PRIVATE"), "{f}");
        }
    }

    fn wants(book: &CertBook, apps: &[&str]) {
        book.follow(apps.iter().map(|a| ((*a).to_owned(), None)).collect());
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
        wants(&book, &["one", "two"]);
        assert!(book.set("one", a.clone(), true));
        assert!(book.set("two", b.clone(), false));
        let held = book.get("one").unwrap();
        assert!(Arc::ptr_eq(&held.key, &a) && held.placeholder);

        assert!(book.set("one", c.clone(), false));
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
    fn set_refuses_an_app_the_bundle_does_not_have() {
        let dir = Scratch::new();
        let book = CertBook::default();
        let (old, late) = (
            Arc::new(load_certified_key(&dir.pair("old")).unwrap()),
            Arc::new(load_certified_key(&dir.pair("late")).unwrap()),
        );
        // Before any bundle nothing is wanted.
        assert!(!book.set("shop", old.clone(), false));
        assert!(book.get("shop").is_none());

        // An app the bundle has, with nothing held yet, can be switched.
        wants(&book, &["shop", "other"]);
        assert!(book.set("shop", old.clone(), false));

        // The app leaves the bundle while its certificate is being made: the finished work cannot
        // put it back.
        wants(&book, &["other"]);
        assert!(book.get("shop").is_none());
        assert!(!book.set("shop", late.clone(), false));
        assert!(book.get("shop").is_none());

        // It joins again with nothing wanted yet: nothing of its old life is served.
        wants(&book, &["shop", "other"]);
        assert!(book.get("shop").is_none());
        assert!(book.set("shop", late.clone(), false));
        assert!(Arc::ptr_eq(&book.get("shop").unwrap().key, &late));
    }

    #[test]
    fn follow_sets_keeps_and_drops() {
        let dir = Scratch::new();
        let book = CertBook::default();
        let key = |name: &str| Arc::new(load_certified_key(&dir.pair(name)).unwrap());
        let (kept, replaced, dropped, added) =
            (key("kept"), key("replaced"), key("dropped"), key("added"));
        let replacement = key("replacement");
        wants(&book, &["kept", "replaced", "dropped"]);
        assert!(book.set("kept", kept.clone(), false));
        assert!(book.set("replaced", replaced, false));
        assert!(book.set("dropped", dropped, false));

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
    fn a_guard_takes_down_its_own_offer_and_not_a_later_one() {
        let dir = Scratch::new();
        let book = Arc::new(CertBook::default());
        let (first, second) = (
            Arc::new(load_certified_key(&dir.pair("first")).unwrap()),
            Arc::new(load_certified_key(&dir.pair("second")).unwrap()),
        );
        let answer = |host: &str| book.alpn_challenge(host);

        // An order is retried: the new offer goes up before the old guard drops.
        let g1 = book.offer_tls_alpn("shop.test", first.clone());
        let g2 = book.offer_tls_alpn("shop.test", second.clone());
        assert!(Arc::ptr_eq(&answer("shop.test").unwrap(), &second));
        drop(g1);
        assert!(Arc::ptr_eq(&answer("shop.test").unwrap(), &second));
        drop(g2);
        assert!(answer("shop.test").is_none());
        assert!(book.read().tls_alpn.is_empty(), "no empty list is left");

        // An order that keeps its guard in a field and puts a new one in: the new offer is made
        // before the old guard drops.
        struct Order {
            guard: Option<ChallengeGuard>,
        }
        let mut order = Order {
            guard: Some(book.offer_tls_alpn("shop.test", first.clone())),
        };
        order.guard = Some(book.offer_tls_alpn("shop.test", second.clone()));
        assert!(Arc::ptr_eq(&answer("shop.test").unwrap(), &second));

        // The newer offer ends first: the older one answers again while its guard lives.
        let older = order.guard.take().unwrap();
        let newer = book.offer_tls_alpn("shop.test", first.clone());
        assert!(Arc::ptr_eq(&answer("shop.test").unwrap(), &first));
        drop(newer);
        assert!(Arc::ptr_eq(&answer("shop.test").unwrap(), &second));
        drop(older);
        assert!(answer("shop.test").is_none());

        // Another host is not touched.
        let (_one, other) = (
            book.offer_tls_alpn("one.test", first.clone()),
            book.offer_tls_alpn("other.test", second.clone()),
        );
        drop(other);
        assert!(Arc::ptr_eq(&answer("one.test").unwrap(), &first));
        assert!(answer("other.test").is_none());
    }

    #[test]
    fn http01_offers_for_one_token_stack_and_each_guard_takes_down_its_own() {
        let book = Arc::new(CertBook::default());
        let answer = || book.http01_authorization("shop.test", "tok");

        let g1 = book.offer_http01("shop.test", "tok", "tok.old");
        let g2 = book.offer_http01("Shop.Test", "tok", "tok.new");
        assert_eq!(answer().as_deref(), Some("tok.new"));
        drop(g1);
        assert_eq!(answer().as_deref(), Some("tok.new"));
        // The same authorization offered twice: the first guard to drop does not end the other.
        let g3 = book.offer_http01("shop.test", "tok", "tok.new");
        drop(g2);
        assert_eq!(answer().as_deref(), Some("tok.new"));
        drop(g3);
        assert_eq!(answer(), None);
        assert!(book.read().http01.is_empty());
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
