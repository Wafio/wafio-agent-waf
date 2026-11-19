//! The certificates of one TLS listener, chosen by SNI name and reloaded when their files change.
//!
//! The store is the rustls certificate resolver of the listener's `ServerConfig`. A bundle apply
//! builds the next name table with [`CertStore::prepare`] and switches with [`CertStore::install`];
//! [`CertStore::refresh`] reloads a changed pair of files in place. Private keys are never logged.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use pingora::tls::sign::CertifiedKey;
use pingora::tls::{
    ClientHello, CryptoProvider, ResolvesServerCert, RusTlsError, ServerConfig, version,
};
use rustls_pki_types::pem::{Error as PemError, PemObject};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// How often the certificate and key files are checked for a change.
pub const CERT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// A certificate chain (leaf first) and its private key, both PEM files.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertFiles {
    pub certificate: PathBuf,
    pub key: PathBuf,
}

/// Modification time, size and inode of a file; `None` when it cannot be read. A copy changes the
/// time or size, a symlink swap (certbot) the inode.
type FileStamp = Option<(SystemTime, u64, u64)>;

fn file_stamp(path: &Path) -> FileStamp {
    let meta = fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len(), meta.ino()))
}

/// One pair of files and the certificate read from it.
#[derive(Clone)]
struct Pair {
    files: CertFiles,
    /// The files as they were when `key` was read.
    stamp: (FileStamp, FileStamp),
    /// The files as they were at the last failed read, so a failure is logged once per change
    /// while every poll still retries (a `chmod` that fixes the read changes no stamp).
    failed: Option<(FileStamp, FileStamp)>,
    key: Arc<CertifiedKey>,
}

impl Pair {
    fn read(files: &CertFiles) -> Result<Pair, String> {
        // Stamped before reading: a file replaced in between is read again on the next poll.
        let stamp = (file_stamp(&files.certificate), file_stamp(&files.key));
        Ok(Pair {
            files: files.clone(),
            stamp,
            failed: None,
            key: Arc::new(load_certified_key(files)?),
        })
    }
}

/// The certificate of every served host name, with what each pair of files was read as.
#[derive(Clone, Default)]
pub struct CertTable {
    pairs: Vec<Pair>,
    /// Lower case host name to its index in `pairs`.
    names: HashMap<String, usize>,
    /// `*.example.com` is kept as `example.com`: it matches one label in front of it.
    wildcards: HashMap<String, usize>,
}

impl CertTable {
    fn lookup(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        let index = match self.names.get(name) {
            Some(index) => index,
            None => self.wildcards.get(name.split_once('.')?.1)?,
        };
        Some(Arc::clone(&self.pairs[*index].key))
    }
}

/// The certificates one TLS listener serves.
#[derive(Default)]
pub struct CertStore {
    /// Swapped whole, so a handshake sees one consistent table.
    table: RwLock<Arc<CertTable>>,
    /// Held by `install` and `refresh`, so a refresh never swaps in a table built on an older one.
    writer: Mutex<()>,
}

impl CertStore {
    /// The table for `sites` (host names without port; `*.example.com` for a wildcard): pairs this
    /// store already serves are reused, the others are read. Nothing changes on error; the error
    /// names the file.
    pub fn prepare(&self, sites: &[(Vec<String>, CertFiles)]) -> Result<CertTable, String> {
        let served = self.current();
        let mut table = CertTable::default();
        for (hosts, files) in sites {
            let index = match table.pairs.iter().position(|p| p.files == *files) {
                Some(index) => index,
                None => {
                    let pair = match served.pairs.iter().find(|p| p.files == *files) {
                        Some(pair) => pair.clone(),
                        None => Pair::read(files)?,
                    };
                    table.pairs.push(pair);
                    table.pairs.len() - 1
                }
            };
            for host in hosts {
                let host = host.to_ascii_lowercase();
                let (map, name) = match host.strip_prefix("*.") {
                    Some(parent) => (&mut table.wildcards, parent),
                    None => (&mut table.names, host.as_str()),
                };
                if map
                    .insert(name.to_owned(), index)
                    .is_some_and(|other| other != index)
                {
                    return Err(format!("host name {host} has two certificates"));
                }
            }
        }
        Ok(table)
    }

    /// Serves `table` from the next handshake on.
    pub fn install(&self, mut table: CertTable) {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        // A refresh may have reloaded a pair since `prepare` copied it: the served one is newer.
        let served = self.current();
        for pair in &mut table.pairs {
            if let Some(newer) = served.pairs.iter().find(|p| p.files == pair.files) {
                *pair = newer.clone();
            }
        }
        *self.table.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(table);
    }

    /// Reloads every pair whose modification time, size or inode changed since it was read. A
    /// pair that fails to load keeps its previous certificate, is logged once per change and is
    /// tried again on every call.
    pub fn refresh(&self) {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = (*self.current()).clone();
        let mut changed = false;
        for pair in &mut next.pairs {
            let stamp = (
                file_stamp(&pair.files.certificate),
                file_stamp(&pair.files.key),
            );
            if stamp == pair.stamp {
                continue;
            }
            match load_certified_key(&pair.files) {
                Ok(key) => {
                    (pair.key, pair.stamp, pair.failed) = (Arc::new(key), stamp, None);
                    changed = true;
                    tracing::info!("certificate reloaded: {}", pair.files.certificate.display());
                }
                Err(e) if pair.failed != Some(stamp) => {
                    pair.failed = Some(stamp);
                    changed = true;
                    tracing::warn!("certificate reload failed, keeping the previous one: {e}")
                }
                Err(_) => {}
            }
        }
        if changed {
            *self.table.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
        }
    }

    fn current(&self) -> Arc<CertTable> {
        Arc::clone(&self.table.read().unwrap_or_else(PoisonError::into_inner))
    }

    fn lookup(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        // A client may send any case; the table holds lower case.
        self.current().lookup(&name.to_ascii_lowercase())
    }
}

/// Prints no field: the table holds private keys.
impl fmt::Debug for CertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertStore").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for CertStore {
    /// The certificate of the SNI name; `None` (no SNI, unknown name) refuses the handshake.
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(hello.server_name()?)
    }
}

/// Reads a certificate chain and one PKCS#8, PKCS#1 or SEC1 key that matches its leaf. The error
/// names the file and the kind of failure, never key bytes.
pub fn load_certified_key(files: &CertFiles) -> Result<CertifiedKey, String> {
    let read = |path: &Path| {
        fs::read(path).map_err(|e| format!("{}: cannot read ({})", path.display(), e.kind()))
    };
    let chain = CertificateDer::pem_slice_iter(&read(&files.certificate)?)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("{}: not valid PEM", files.certificate.display()))?;
    if chain.is_empty() {
        return Err(format!("{}: no certificate", files.certificate.display()));
    }
    let key = PrivateKeyDer::from_pem_slice(&read(&files.key)?).map_err(|e| match e {
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

/// The rustls config of a TLS listener: TLS 1.2 and 1.3, ALPN `http/1.1` only, certificates
/// from `store`.
pub fn server_config(store: Arc<CertStore>) -> Arc<ServerConfig> {
    pingora::tls::install_default_crypto_provider();
    let mut config =
        ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(store);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use pingora::tls::SignatureScheme;

    /// A scratch directory in the system temp dir, removed on drop. The keys never leave it.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Scratch {
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
        fn pair(&self, name: &str) -> CertFiles {
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

    /// Moves `from` over `to` the way certbot swaps a renewed pair: a new inode, an atomic switch.
    fn replace(from: &CertFiles, to: &CertFiles) {
        fs::rename(&from.certificate, &to.certificate).unwrap();
        fs::rename(&from.key, &to.key).unwrap();
    }

    fn site(hosts: &[&str], files: &CertFiles) -> (Vec<String>, CertFiles) {
        (
            hosts.iter().map(|h| (*h).to_owned()).collect(),
            files.clone(),
        )
    }

    fn served_chain(store: &CertStore, name: &str) -> Option<Vec<CertificateDer<'static>>> {
        store.lookup(name).map(|key| key.cert.clone())
    }

    fn chain_of(files: &CertFiles) -> Vec<CertificateDer<'static>> {
        load_certified_key(files).unwrap().cert
    }

    #[test]
    fn lookup_by_name_wildcard_and_unknown() {
        let dir = Scratch::new();
        let (shop, wild) = (dir.pair("shop"), dir.pair("wild"));
        let store = CertStore::default();
        let table = store
            .prepare(&[
                site(&["shop.example.com", "www.example.com"], &shop),
                site(&["*.wild.example.com"], &wild),
            ])
            .unwrap();
        store.install(table);

        let shop_chain = chain_of(&shop);
        assert_eq!(
            served_chain(&store, "shop.example.com"),
            Some(shop_chain.clone())
        );
        assert_eq!(served_chain(&store, "www.example.com"), Some(shop_chain));
        assert_eq!(
            served_chain(&store, "SHOP.Example.com"),
            served_chain(&store, "shop.example.com")
        );

        let wild_chain = Some(chain_of(&wild));
        assert_eq!(served_chain(&store, "a.wild.example.com"), wild_chain);
        // One label only, and never the bare parent.
        assert_eq!(served_chain(&store, "a.b.wild.example.com"), None);
        assert_eq!(served_chain(&store, "wild.example.com"), None);

        assert_eq!(served_chain(&store, "other.example.com"), None);
        assert_eq!(served_chain(&store, ""), None);
    }

    #[test]
    fn a_host_name_has_one_certificate() {
        let dir = Scratch::new();
        let (a, b) = (dir.pair("a"), dir.pair("b"));
        let store = CertStore::default();
        let err = store
            .prepare(&[site(&["x.example.com"], &a), site(&["x.example.com"], &b)])
            .err()
            .unwrap();
        assert!(err.contains("x.example.com"), "{err}");
        // The same name twice for the same pair is not a conflict.
        assert!(
            store
                .prepare(&[site(&["x.example.com"], &a), site(&["x.example.com"], &a)])
                .is_ok()
        );
    }

    #[test]
    fn swap_is_seen_by_new_lookups_and_the_old_arc_stays_valid() {
        let dir = Scratch::new();
        let (old, new) = (dir.pair("old"), dir.pair("new"));
        let store = CertStore::default();
        store.install(store.prepare(&[site(&["x.example.com"], &old)]).unwrap());
        let held = store.lookup("x.example.com").unwrap();

        store.install(store.prepare(&[site(&["x.example.com"], &new)]).unwrap());

        assert_eq!(served_chain(&store, "x.example.com"), Some(chain_of(&new)));
        assert_eq!(held.cert, chain_of(&old));
        assert!(
            held.key
                .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_some()
        );
    }

    #[test]
    fn refresh_serves_a_replaced_pair_and_leaves_an_unchanged_one() {
        let dir = Scratch::new();
        let (live, renewed) = (dir.pair("live"), dir.pair("renewed"));
        let renewed_chain = chain_of(&renewed);
        let store = CertStore::default();
        store.install(store.prepare(&[site(&["x.example.com"], &live)]).unwrap());
        let before = store.lookup("x.example.com").unwrap();

        store.refresh();
        assert!(Arc::ptr_eq(
            &before,
            &store.lookup("x.example.com").unwrap()
        ));

        replace(&renewed, &live);
        store.refresh();
        assert_eq!(served_chain(&store, "x.example.com"), Some(renewed_chain));
    }

    #[test]
    fn a_bad_file_keeps_the_previous_certificate() {
        let dir = Scratch::new();
        let (live, next) = (dir.pair("live"), dir.pair("next"));
        let next_chain = chain_of(&next);
        let store = CertStore::default();
        store.install(store.prepare(&[site(&["x.example.com"], &live)]).unwrap());
        let before = store.lookup("x.example.com").unwrap();
        let still_served = || Arc::ptr_eq(&before, &store.lookup("x.example.com").unwrap());

        // Not PEM at all.
        fs::write(&live.certificate, "not a certificate").unwrap();
        store.refresh();
        assert!(still_served());

        // A half-copied pair: the new certificate, the old key.
        fs::rename(&next.certificate, &live.certificate).unwrap();
        store.refresh();
        assert!(still_served());
        let err = load_certified_key(&live).err().unwrap();
        assert!(
            err.contains("does not match") && err.contains("live.key"),
            "{err}"
        );
        assert!(!err.contains("PRIVATE KEY"), "{err}");

        // The key arrives: the next poll serves the new pair.
        fs::rename(&next.key, &live.key).unwrap();
        store.refresh();
        assert_eq!(served_chain(&store, "x.example.com"), Some(next_chain));
    }

    #[test]
    fn a_pair_made_readable_without_a_new_stamp_is_loaded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = Scratch::new();
        let (live, next) = (dir.pair("live"), dir.pair("next"));
        let next_chain = chain_of(&next);
        let store = CertStore::default();
        store.install(store.prepare(&[site(&["x.example.com"], &live)]).unwrap());

        fs::rename(&next.certificate, &live.certificate).unwrap();
        fs::rename(&next.key, &live.key).unwrap();
        fs::set_permissions(&live.key, fs::Permissions::from_mode(0o000)).unwrap();
        store.refresh();
        // A mode change moves neither the modification time, the size nor the inode.
        fs::set_permissions(&live.key, fs::Permissions::from_mode(0o600)).unwrap();
        store.refresh();
        assert_eq!(served_chain(&store, "x.example.com"), Some(next_chain));
    }

    #[test]
    fn prepare_names_a_missing_file_and_changes_nothing() {
        let dir = Scratch::new();
        let live = dir.pair("live");
        let store = CertStore::default();
        store.install(store.prepare(&[site(&["x.example.com"], &live)]).unwrap());

        let absent = CertFiles {
            certificate: dir.0.join("absent.crt"),
            key: dir.0.join("absent.key"),
        };
        let err = store
            .prepare(&[site(&["y.example.com"], &absent)])
            .err()
            .unwrap();
        assert!(err.contains("absent.crt"), "{err}");
        assert_eq!(served_chain(&store, "y.example.com"), None);
        assert!(served_chain(&store, "x.example.com").is_some());
    }

    #[test]
    fn server_config_offers_http_1_1_only() {
        let config = server_config(Arc::new(CertStore::default()));
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
