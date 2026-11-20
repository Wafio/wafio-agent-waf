//! Apps the agent serves over HTTPS itself: the `tls` object of a bundle app, and the key
//! directory that holds the certificate each one is served from.
//!
//! `Keys` is the state of that part of the agent. It lives in the agent's apply state, so every
//! change of what is served and every write in the directory happens under the apply lock, one at
//! a time, in the order the bundles and installs arrive.

pub mod dir;
pub mod entry;
pub(crate) mod install;
pub mod pacer;
pub mod state_file;
pub mod status;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pingora::tls::sign::CertifiedKey;
use wafio_control::{AckCode, CertificateInstall};
use wafio_proxy::cert_store::{BookEntry, CertBook, certified_key_from_pem, leaf_sha256};
use zeroize::Zeroizing;

use crate::bundle::BundleApp;
use dir::{KeyDir, MAX_KEY_FILE, ReadError};
use entry::{Refusal, Settings, Source, check, is_known_source};
use install::{LoadKey, Secrets, verify_and_store};
use state_file::{AppRecord, STATE_FILE, StateFile, is_key_file};

/// The certificate an app is served with, and where it came from.
#[derive(Clone)]
pub struct Served {
    /// The file of the key directory it was read from.
    pub file: String,
    /// Lower case hex SHA-256 of the DER of the leaf.
    pub leaf_sha256: String,
    pub key: Arc<CertifiedKey>,
}

/// Prints no key.
impl std::fmt::Debug for Served {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Served")
            .field("file", &self.file)
            .field("leaf_sha256", &self.leaf_sha256)
            .finish_non_exhaustive()
    }
}

/// An app of the bundle in force that has a `tls` object.
#[derive(Clone, Debug)]
pub struct Applied {
    pub settings: Settings,
    /// What the app is served with; `None` while there is no certificate for it.
    pub served: Option<Served>,
}

/// The entry of an app that failed a check, which refuses the bundle.
#[derive(Debug)]
pub struct Rejected {
    pub app_id: String,
    pub refusal: Refusal,
}

/// The key directory and what the bundle in force serves from it.
pub struct Keys {
    dir: KeyDir,
    /// What `state.json` is to say. Until a bundle is applied it is what was read.
    state: StateFile,
    /// What the file says now; `None` when it could not be read, so the next write replaces it.
    written: Option<StateFile>,
    applied: HashMap<String, Applied>,
    /// A bundle has been applied. Before that the directory says nothing about which files are
    /// wanted, so none is removed.
    bundle_seen: bool,
}

impl Keys {
    pub fn new(dir: KeyDir) -> Keys {
        let (state, intact) = StateFile::load(&dir);
        Keys {
            dir,
            written: intact.then(|| state.clone()),
            state,
            applied: HashMap::new(),
            bundle_seen: false,
        }
    }

    /// Whether this process is the one that writes in the directory.
    pub fn holds_lock(&self) -> bool {
        self.dir.holds_lock()
    }

    /// The apps of the bundle in force that have a `tls` object.
    pub fn applied(&self) -> &HashMap<String, Applied> {
        &self.applied
    }

    /// Checks the `tls` object of every app of a bundle and finds the certificate each is served
    /// with. Changes nothing: `commit` makes it so once the proxy has taken the bundle.
    pub fn prepare(&self, apps: &[BundleApp]) -> Result<HashMap<String, Applied>, Rejected> {
        let mut next = HashMap::new();
        let mut unknown_source_logged = false;
        for app in apps {
            let Some(entry) = &app.tls else { continue };
            let settings = check(&app.app_id, entry).map_err(|refusal| Rejected {
                app_id: app.app_id.clone(),
                refusal,
            })?;
            if !is_known_source(&entry.source) && !unknown_source_logged {
                unknown_source_logged = true;
                tracing::info!(
                    "[waf-bundle] app {}: TLS source {:?} is not known to this agent; no certificate is served for it",
                    app.app_id,
                    entry.source.chars().take(32).collect::<String>()
                );
            }
            let served = self.resolve(&app.app_id, &settings);
            next.insert(app.app_id.clone(), Applied { settings, served });
        }
        Ok(next)
    }

    /// What the app is served with: the certificate its settings want if the directory has it;
    /// else the one it is served with now (a replaced certificate, a changed source or host list
    /// keeps serving the previous one until the new one arrives); else, after a restart, the file
    /// the state remembers. Settings that name no file (no source, one this agent does not know,
    /// uploaded with no certificate) serve nothing, so a certificate the bundle dropped is not
    /// served on.
    fn resolve(&self, app_id: &str, settings: &Settings) -> Option<Served> {
        let file = settings.wanted_file(app_id)?;
        let previous = self.applied.get(app_id).and_then(|a| a.served.as_ref());
        let leaf = settings
            .certificate
            .as_ref()
            .map(|c| c.leaf_sha256.as_str());
        if let Some(held) = previous
            && held.file == file
            && leaf.is_none_or(|leaf| leaf == held.leaf_sha256)
        {
            return Some(held.clone());
        }
        match self.load(&file, leaf) {
            Ok(served) => return Some(served),
            Err(Fault::Read(ReadError::Missing)) => {}
            Err(e) => tracing::info!("[tls] app {app_id}: {file}: {e}"),
        }
        if let Some(held) = previous {
            return Some(held.clone());
        }
        // The wanted file was tried with its leaf above; reading it again without one would serve
        // a certificate the bundle does not name.
        let remembered = self
            .state
            .apps
            .get(app_id)?
            .served
            .as_deref()
            .filter(|remembered| *remembered != file)?;
        match self.load(remembered, None) {
            Ok(served) => Some(served),
            Err(e) => {
                tracing::info!("[tls] app {app_id}: {remembered}: {e}");
                None
            }
        }
    }

    /// Reads `file` and builds its key. With `leaf` the certificate must be that one.
    fn load(&self, file: &str, leaf: Option<&str>) -> Result<Served, Fault> {
        // The file holds the key, so the text is wiped once the key is read from it.
        let pem = Zeroizing::new(self.dir.read(file, MAX_KEY_FILE).map_err(Fault::Read)?);
        let key = certified_key_from_pem(&pem).map_err(Fault::Pem)?;
        let leaf_sha256 = leaf_sha256(&key);
        if leaf.is_some_and(|want| want != leaf_sha256) {
            return Err(Fault::OtherLeaf);
        }
        Ok(Served {
            file: file.to_owned(),
            leaf_sha256,
            key: Arc::new(key),
        })
    }

    /// Installs an uploaded certificate for an app of the bundle in force: checks it, writes its
    /// file, serves it from the next handshake on and drops the file it replaces. The caller holds
    /// the apply lock for all of it, so the bundle the checks read is the one in force when the
    /// certificate is switched in.
    ///
    /// The checks, first failure wins: the bundle names this app, certificate and leaf for an
    /// uploaded source; the certificate is not held already (then there is nothing to do); then
    /// those of `install::verify_and_store`; then the write.
    pub(crate) fn install(
        &mut self,
        install: &CertificateInstall,
        book: &CertBook,
        secrets: &mut Secrets,
        load: LoadKey,
    ) -> Result<(), AckCode> {
        let app = self
            .applied
            .get(&install.app_id)
            .ok_or(AckCode::NotInBundle)?;
        let named = app
            .settings
            .certificate
            .as_ref()
            .filter(|c| {
                app.settings.source == Source::Uploaded
                    && c.id == install.certificate_id
                    && c.leaf_sha256 == install.leaf_sha256
            })
            .ok_or(AckCode::NotInBundle)?;
        let file = format!("{}.pem", named.id);
        if app
            .served
            .as_ref()
            .is_some_and(|s| s.file == file && s.leaf_sha256 == named.leaf_sha256)
        {
            return Ok(());
        }
        let leaf = named.leaf_sha256.clone();
        let mut written = None;
        verify_and_store(install, secrets, load, |key, text| {
            self.dir.write(&file, text).map_err(|e| {
                tracing::info!("[tls] cannot write {file}: {}", e.kind());
                AckCode::WriteFailed
            })?;
            written = Some(Served {
                file: file.clone(),
                leaf_sha256: leaf,
                key,
            });
            Ok(())
        })?;
        let served = written.expect("the write ran");
        if !book.set(&install.app_id, served.key.clone(), false) {
            // The book does not hold the app: it is not in the bundle that is in force.
            let _ = self.dir.remove(&file);
            return Err(AckCode::NotInBundle);
        }
        self.serve(&install.app_id, served);
        Ok(())
    }

    /// Records that `app_id` is served `served` now, in the state file too, and drops the files
    /// that nothing needs any more: the certificate it replaced.
    fn serve(&mut self, app_id: &str, served: Served) {
        self.state.apps.insert(
            app_id.to_owned(),
            AppRecord {
                served: Some(served.file.clone()),
            },
        );
        if let Some(app) = self.applied.get_mut(app_id) {
            app.served = Some(served);
        }
        self.settle(&HashSet::new());
    }

    /// The bundle is in force: `next` is what is applied now. The state and the directory follow,
    /// if this process holds the lock; if not, they follow when it takes the lock over.
    pub fn commit(&mut self, next: HashMap<String, Applied>) {
        self.applied = next;
        self.bundle_seen = true;
        self.state = StateFile {
            apps: self
                .applied
                .iter()
                .filter_map(|(id, a)| {
                    let served = a.served.as_ref()?.file.clone();
                    Some((
                        id.clone(),
                        AppRecord {
                            served: Some(served),
                        },
                    ))
                })
                .collect(),
        };
        self.settle(&HashSet::new());
    }

    /// Takes the lock if the process that held it let go, and then does what it could not do
    /// before. Returns whether this process holds it.
    pub fn take_over(&mut self) -> bool {
        if self.dir.holds_lock() {
            return true;
        }
        if !self.dir.try_lock() {
            return false;
        }
        tracing::info!("[tls] this process writes in the key directory now");
        // The process that let go may have got a newer bundle than the one this process applied
        // and written its certificates since: those are files this process does not know about.
        let known: HashSet<&str> = self
            .written
            .iter()
            .flat_map(StateFile::served_files)
            .collect();
        let newer: HashSet<String> = StateFile::load(&self.dir)
            .0
            .served_files()
            .filter(|file| !known.contains(file))
            .map(str::to_owned)
            .collect();
        self.settle(&newer);
        true
    }

    /// Lets go of the lock for the process that takes over.
    pub fn release(&mut self) {
        if self.dir.holds_lock() {
            self.dir.release_lock();
            tracing::info!("[tls] key directory lock handed over");
        }
    }

    /// Writes the state if it changed and removes the files nothing needs, when this process may
    /// write and a bundle has said what is wanted. `keep` names files to leave in place besides
    /// the ones the bundle uses.
    fn settle(&mut self, keep: &HashSet<String>) {
        if !self.dir.holds_lock() || !self.bundle_seen {
            return;
        }
        if self.written.as_ref() != Some(&self.state) {
            match self.dir.write(STATE_FILE, &self.state.to_bytes()) {
                Ok(()) => self.written = Some(self.state.clone()),
                Err(e) => tracing::info!("[tls] cannot write {STATE_FILE}: {}", e.kind()),
            }
        }
        self.remove_unused(keep);
    }

    /// Removes each certificate file of the agent (`<uuid>.pem`, `acme-<uuid>.pem`) that no app of
    /// the bundle names and none serves: the certificate an app was served with goes once the one
    /// that replaces it is served. Any other file is none of the agent's and stays.
    fn remove_unused(&self, keep: &HashSet<String>) {
        let needed: HashSet<String> = self
            .applied
            .iter()
            .flat_map(|(id, a)| {
                a.settings
                    .wanted_file(id)
                    .into_iter()
                    .chain(a.served.iter().map(|s| s.file.clone()))
            })
            .collect();
        let files = match self.dir.pem_files() {
            Ok(files) => files,
            Err(e) => {
                tracing::info!("[tls] cannot list the key directory: {}", e.kind());
                return;
            }
        };
        for file in files
            .iter()
            .filter(|f| is_key_file(f) && !needed.contains(*f) && !keep.contains(*f))
        {
            match self.dir.remove(file) {
                Ok(()) => tracing::info!("[tls] removed {file}: no app of the bundle uses it"),
                Err(e) => tracing::info!("[tls] cannot remove {file}: {}", e.kind()),
            }
        }
    }
}

/// The book entry that serves `served`.
pub fn book_entry(served: &Served) -> BookEntry {
    BookEntry {
        key: served.key.clone(),
        placeholder: false,
    }
}

enum Fault {
    Read(ReadError),
    Pem(wafio_proxy::cert_store::PairFault),
    OtherLeaf,
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::Read(e) => write!(f, "cannot read: {e}"),
            Fault::Pem(e) => write!(f, "{e}"),
            Fault::OtherLeaf => f.write_str("holds another certificate than the bundle names"),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::install::tests::{Made, fixture, install_for};
    use super::*;
    use crate::bundle::decode_bundle;
    use dir::tests::{Scratch, my_uid};
    use install::load_key;
    use std::path::Path;
    use std::process::Command;
    use wafio_proxy::cert_store::BookChange;

    const APP: &str = "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11";
    const OTHER_APP: &str = "6f1c0c64-4f7e-4a06-8cf3-0b7c2a6d1e90";
    const X: &str = "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77";
    const Y: &str = "7e1f3a90-2c1d-4b8e-9a55-1d3c4f6a8b02";

    /// A new self-signed key and certificate for `name`: the text of one key file, and the
    /// SHA-256 of the leaf.
    pub(crate) fn make_pem(work: &Path, name: &str) -> (Vec<u8>, String) {
        let (key, crt) = (
            work.join(format!("{name}.key")),
            work.join(format!("{name}.crt")),
        );
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
            .arg(&key)
            .arg("-out")
            .arg(&crt)
            .output()
            .expect("openssl is installed");
        assert!(out.status.success(), "openssl req failed");
        let pem = [std::fs::read(&key).unwrap(), std::fs::read(&crt).unwrap()].concat();
        let leaf = leaf_sha256(&certified_key_from_pem(&pem).unwrap());
        (pem, leaf)
    }

    /// The apps of a bundle: each `(app id, tls object)`.
    fn apps(entries: &[(&str, String)]) -> Vec<BundleApp> {
        let list: Vec<String> = entries
            .iter()
            .map(|(id, tls)| format!(r#"{{"app_id":"{id}","tls":{tls}}}"#))
            .collect();
        decode_bundle(format!(r#"{{"apps":[{}]}}"#, list.join(",")).as_bytes())
            .unwrap()
            .apps
    }

    fn uploaded(cert: &str, leaf: &str) -> String {
        format!(
            r#"{{"listen":"0.0.0.0:443","hosts":["shop.example.com"],"source":"uploaded","certificate_id":"{cert}","leaf_sha256":"{leaf}"}}"#
        )
    }

    fn apply(keys: &mut Keys, entries: &[(&str, String)]) -> HashMap<String, Applied> {
        let next = keys.prepare(&apps(entries)).unwrap();
        keys.commit(next.clone());
        next
    }

    fn served(applied: &HashMap<String, Applied>, app: &str) -> Option<String> {
        applied[app].served.as_ref().map(|s| s.file.clone())
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn state_on_disk(dir: &Path) -> StateFile {
        serde_json::from_slice(&std::fs::read(dir.join(STATE_FILE)).unwrap()).unwrap()
    }

    fn keys(s: &Scratch) -> Keys {
        Keys::new(KeyDir::open(&s.dir(), my_uid()).unwrap())
    }

    #[test]
    fn a_certificate_is_served_from_the_file_the_bundle_names_and_the_one_it_replaces_goes() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let ((x_pem, x_leaf), (y_pem, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let (x_file, y_file) = (format!("{X}.pem"), format!("{Y}.pem"));

        // The bundle names X, which is not there: nothing is served, and nothing is written for it.
        let first = apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        assert_eq!(served(&first, APP), None);

        k.dir.write(&x_file, &x_pem).unwrap();
        let second = apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        assert_eq!(served(&second, APP), Some(x_file.clone()));
        assert_eq!(
            second[APP].served.as_ref().unwrap().leaf_sha256,
            x_leaf,
            "the leaf is the digest of the certificate in the file"
        );
        assert_eq!(
            state_on_disk(&s.dir()).apps[APP].served.as_deref(),
            Some(x_file.as_str())
        );

        // The bundle names Y before its file is there: X stays served, and X.pem stays.
        let third = apply(&mut k, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&third, APP), Some(x_file.clone()));
        assert_eq!(files(&s.dir()), [x_file.as_str(), STATE_FILE, "tls.lock"]);

        // Y arrives: it is served and X.pem is gone, in the same apply.
        k.dir.write(&y_file, &y_pem).unwrap();
        let fourth = apply(&mut k, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&fourth, APP), Some(y_file.clone()));
        assert_eq!(files(&s.dir()), [y_file.as_str(), STATE_FILE, "tls.lock"]);
        assert_eq!(
            state_on_disk(&s.dir()).apps[APP].served.as_deref(),
            Some(y_file.as_str())
        );
    }

    #[test]
    fn a_file_with_another_certificate_than_the_bundle_names_is_not_served() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let ((x_pem, _), (_, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        k.dir.write(&format!("{X}.pem"), &x_pem).unwrap();
        let applied = apply(&mut k, &[(APP, uploaded(X, &y_leaf))]);
        assert_eq!(served(&applied, APP), None);
        for bad in [&b"not a key file"[..], b"", &x_pem[..x_pem.len() / 2]] {
            k.dir.write(&format!("{X}.pem"), bad).unwrap();
            assert_eq!(
                served(&apply(&mut k, &[(APP, uploaded(X, &y_leaf))]), APP),
                None
            );
        }
    }

    #[test]
    fn a_damaged_file_keeps_the_certificate_in_use() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let ((x_pem, x_leaf), (_, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let x_file = format!("{X}.pem");
        k.dir.write(&x_file, &x_pem).unwrap();
        apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        k.dir.write(&format!("{Y}.pem"), b"half a file").unwrap();
        let applied = apply(&mut k, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&applied, APP), Some(x_file));
    }

    #[test]
    fn the_state_drops_apps_that_left_the_bundle_with_their_files() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let ((x_pem, x_leaf), (y_pem, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        k.dir.write(&format!("{X}.pem"), &x_pem).unwrap();
        k.dir.write(&format!("{Y}.pem"), &y_pem).unwrap();
        // A file that is none of the agent's stays, whatever the bundle says.
        std::fs::write(s.dir().join("notes.pem"), "an operator's file").unwrap();
        apply(
            &mut k,
            &[
                (APP, uploaded(X, &x_leaf)),
                (OTHER_APP, uploaded(Y, &y_leaf)),
            ],
        );
        assert_eq!(state_on_disk(&s.dir()).apps.len(), 2);

        // An app without a `tls` object is not served and not remembered.
        let plain = decode_bundle(
            format!(
                r#"{{"apps":[{{"app_id":"{OTHER_APP}"}},{{"app_id":"{APP}","tls":{}}}]}}"#,
                uploaded(X, &x_leaf)
            )
            .as_bytes(),
        )
        .unwrap()
        .apps;
        let next = k.prepare(&plain).unwrap();
        k.commit(next);
        let state = state_on_disk(&s.dir());
        assert_eq!(state.apps.keys().collect::<Vec<_>>(), [APP]);
        assert_eq!(
            files(&s.dir()),
            [
                format!("{X}.pem").as_str(),
                "notes.pem",
                STATE_FILE,
                "tls.lock"
            ]
        );

        let none = k.prepare(&[]).unwrap();
        k.commit(none);
        assert!(state_on_disk(&s.dir()).apps.is_empty());
        assert_eq!(files(&s.dir()), ["notes.pem", STATE_FILE, "tls.lock"]);
    }

    /// Source `""`, one the agent does not know, and `uploaded` with no certificate named.
    fn entries_that_name_no_file() -> [String; 3] {
        let entry = |source: &str| {
            format!(
                r#"{{"listen":"0.0.0.0:443","hosts":["shop.example.com"],"source":"{source}"}}"#
            )
        };
        [entry(""), entry("mystery"), entry("uploaded")]
    }

    #[test]
    fn an_app_whose_settings_name_no_file_is_served_nothing_and_the_certificate_it_had_goes() {
        let s = Scratch::new();
        let (x_pem, x_leaf) = make_pem(&s.0, "x");
        let x_file = format!("{X}.pem");
        for restart in [false, true] {
            for none in entries_that_name_no_file() {
                let mut k = keys(&s);
                k.dir.write(&x_file, &x_pem).unwrap();
                let first = apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
                assert_eq!(served(&first, APP), Some(x_file.clone()));
                if restart {
                    // The state remembers X.pem, and must not bring it back.
                    drop(k);
                    k = keys(&s);
                }
                let applied = apply(&mut k, &[(APP, none.clone())]);
                assert_eq!(served(&applied, APP), None, "{none}, restart {restart}");
                assert_eq!(files(&s.dir()), [STATE_FILE, "tls.lock"], "{none}");
                assert!(state_on_disk(&s.dir()).apps.is_empty());
            }
        }
    }

    #[test]
    fn a_restart_before_the_new_certificate_arrives_serves_the_one_the_state_remembers() {
        let s = Scratch::new();
        let ((x_pem, x_leaf), (y_pem, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let (x_file, y_file) = (format!("{X}.pem"), format!("{Y}.pem"));
        {
            let mut k = keys(&s);
            k.dir.write(&x_file, &x_pem).unwrap();
            apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        }
        // A new process, and a bundle that names Y, which has not arrived.
        let mut k = keys(&s);
        let applied = apply(&mut k, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&applied, APP), Some(x_file.clone()));
        assert!(files(&s.dir()).contains(&x_file));
        k.dir.write(&y_file, &y_pem).unwrap();
        let applied = apply(&mut k, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&applied, APP), Some(y_file));
        assert!(!files(&s.dir()).contains(&x_file));
    }

    #[test]
    fn after_a_restart_a_file_with_another_certificate_than_the_bundle_names_is_not_served() {
        let s = Scratch::new();
        let ((x_pem, x_leaf), (y_pem, _)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let x_file = format!("{X}.pem");
        {
            let mut k = keys(&s);
            k.dir.write(&x_file, &x_pem).unwrap();
            apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        }
        // Another pair under the name of X: the state remembers X.pem, but the leaf is not X's.
        std::fs::write(s.dir().join(&x_file), &y_pem).unwrap();
        let mut k = keys(&s);
        let applied = apply(&mut k, &[(APP, uploaded(X, &x_leaf))]);
        assert_eq!(served(&applied, APP), None);
    }

    #[test]
    fn a_process_that_does_not_hold_the_lock_serves_what_it_reads_and_writes_nothing_until_it_does()
    {
        let s = Scratch::new();
        let ((x_pem, x_leaf), (y_pem, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let (x_file, y_file) = (format!("{X}.pem"), format!("{Y}.pem"));
        let mut first = keys(&s);
        first.dir.write(&x_file, &x_pem).unwrap();
        apply(&mut first, &[(APP, uploaded(X, &x_leaf))]);
        std::fs::write(s.dir().join(format!("{OTHER_APP}.pem")), "an orphan").unwrap();
        let before = (
            files(&s.dir()),
            std::fs::read(s.dir().join(STATE_FILE)).unwrap(),
        );
        assert_eq!(before.0.len(), 4);

        // The successor: it reads X and serves it, and the bundle that names Y changes nothing on disk.
        let mut second = keys(&s);
        assert!(!second.holds_lock() && !second.take_over());
        let applied = apply(&mut second, &[(APP, uploaded(X, &x_leaf))]);
        assert_eq!(served(&applied, APP), Some(x_file.clone()));
        std::fs::write(s.dir().join(&y_file), &y_pem).unwrap();
        let applied = apply(&mut second, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&applied, APP), Some(y_file.clone()));
        let after = (
            files(&s.dir()),
            std::fs::read(s.dir().join(STATE_FILE)).unwrap(),
        );
        let orphan = format!("{OTHER_APP}.pem");
        let mut everything = [
            x_file.as_str(),
            orphan.as_str(),
            y_file.as_str(),
            STATE_FILE,
            "tls.lock",
        ];
        everything.sort_unstable();
        assert_eq!(after.0, everything, "nothing was removed or made");
        assert_eq!(after.1, before.1, "the state was not written");

        // The first lets go: the second takes the lock and does what it put off.
        first.release();
        assert!(second.take_over() && second.holds_lock());
        assert_eq!(files(&s.dir()), [y_file.as_str(), STATE_FILE, "tls.lock"]);
        assert_eq!(
            state_on_disk(&s.dir()).apps[APP].served.as_deref(),
            Some(y_file.as_str())
        );
    }

    #[test]
    fn a_file_the_process_it_replaces_wrote_after_this_one_started_stays_when_it_takes_over() {
        let s = Scratch::new();
        let ((x_pem, x_leaf), (y_pem, y_leaf)) = (make_pem(&s.0, "x"), make_pem(&s.0, "y"));
        let (x_file, y_file) = (format!("{X}.pem"), format!("{Y}.pem"));
        let mut first = keys(&s);
        first.dir.write(&x_file, &x_pem).unwrap();
        apply(&mut first, &[(APP, uploaded(X, &x_leaf))]);

        // The successor starts from the bundle that names X, and the first gets a newer one that
        // names Y, writes it and records it.
        let mut second = keys(&s);
        apply(&mut second, &[(APP, uploaded(X, &x_leaf))]);
        first.dir.write(&y_file, &y_pem).unwrap();
        apply(&mut first, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(files(&s.dir()), [y_file.as_str(), STATE_FILE, "tls.lock"]);

        first.release();
        assert!(second.take_over());
        assert_eq!(
            files(&s.dir()),
            [y_file.as_str(), STATE_FILE, "tls.lock"],
            "Y.pem is not in the bundle this process applied, and it is the one in use"
        );
        let applied = apply(&mut second, &[(APP, uploaded(Y, &y_leaf))]);
        assert_eq!(served(&applied, APP), Some(y_file));
    }

    #[test]
    fn no_file_is_removed_before_a_bundle_has_said_which_are_wanted() {
        let s = Scratch::new();
        let (x_pem, _) = make_pem(&s.0, "x");
        let mut first = keys(&s);
        first.dir.write(&format!("{X}.pem"), &x_pem).unwrap();
        let mut second = keys(&s);
        first.release();
        assert!(second.take_over());
        assert!(files(&s.dir()).contains(&format!("{X}.pem")));
        let none = second.prepare(&[]).unwrap();
        second.commit(none);
        assert!(!files(&s.dir()).contains(&format!("{X}.pem")));
    }

    #[test]
    fn a_damaged_state_file_is_replaced_by_the_next_write() {
        let s = Scratch::new();
        {
            let k = keys(&s);
            k.dir.write(STATE_FILE, b"{\"apps\":{\"a\"").unwrap();
        }
        let mut k = keys(&s);
        let none = k.prepare(&[]).unwrap();
        k.commit(none);
        assert!(state_on_disk(&s.dir()).apps.is_empty());
    }

    #[test]
    fn an_entry_that_fails_a_check_names_its_app_and_changes_nothing() {
        let s = Scratch::new();
        let k = keys(&s);
        let good = uploaded(X, &"ab".repeat(32));
        let bad = good.replace("shop.example.com", "*.example.com");
        let rejected = k
            .prepare(&apps(&[(APP, good), (OTHER_APP, bad)]))
            .unwrap_err();
        assert_eq!(
            (rejected.app_id.as_str(), rejected.refusal.field),
            (OTHER_APP, "hosts")
        );
        assert!(k.applied().is_empty());
        let rejected = k
            .prepare(&apps(&[("shop", uploaded(X, &"ab".repeat(32)))]))
            .unwrap_err();
        assert_eq!(rejected.refusal.field, "app_id");
    }

    /// The book of an agent whose bundle has these apps and no certificate in it yet.
    fn book_of(apps: &[&str]) -> CertBook {
        let book = CertBook::default();
        book.follow(
            apps.iter()
                .map(|a| ((*a).to_owned(), BookChange::Keep))
                .collect(),
        );
        book
    }

    fn install_pair(
        k: &mut Keys,
        book: &CertBook,
        made: &Made,
        cert_id: &str,
    ) -> Result<(), AckCode> {
        let mut install = install_for(made);
        install.app_id = APP.to_owned();
        install.certificate_id = cert_id.to_owned();
        k.install(&install, book, &mut Secrets::default(), load_key)
    }

    fn held_leaf(book: &CertBook, app: &str) -> Option<String> {
        Some(leaf_sha256(&book.get(app)?.key))
    }

    #[test]
    fn an_installed_certificate_is_written_served_and_the_one_it_replaces_goes() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let book = book_of(&[APP]);
        let f = fixture();
        let (x_file, y_file) = (format!("{X}.pem"), format!("{Y}.pem"));

        apply(&mut k, &[(APP, uploaded(X, &f.ec.leaf))]);
        assert_eq!(served(k.applied(), APP), None);
        assert_eq!(install_pair(&mut k, &book, &f.ec, X), Ok(()));
        assert_eq!(served(k.applied(), APP), Some(x_file.clone()));
        assert_eq!(held_leaf(&book, APP), Some(f.ec.leaf.clone()));
        assert_eq!(files(&s.dir()), [x_file.as_str(), STATE_FILE, "tls.lock"]);
        let mode = std::fs::metadata(s.dir().join(&x_file)).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
            0o600
        );
        assert_eq!(
            state_on_disk(&s.dir()).apps[APP].served.as_deref(),
            Some(x_file.as_str())
        );

        // The bundle names Y: X stays served until Y is installed, and then X.pem goes.
        apply(&mut k, &[(APP, uploaded(Y, &f.rsa.leaf))]);
        assert_eq!(held_leaf(&book, APP), Some(f.ec.leaf.clone()));
        assert_eq!(install_pair(&mut k, &book, &f.rsa, Y), Ok(()));
        assert_eq!(held_leaf(&book, APP), Some(f.rsa.leaf.clone()));
        assert_eq!(served(k.applied(), APP), Some(y_file.clone()));
        assert_eq!(files(&s.dir()), [y_file.as_str(), STATE_FILE, "tls.lock"]);
        assert_eq!(
            state_on_disk(&s.dir()).apps[APP].served.as_deref(),
            Some(y_file.as_str())
        );
        // What is on disk reads back as the pair that was installed.
        let on_disk = std::fs::read(s.dir().join(&y_file)).unwrap();
        assert_eq!(
            leaf_sha256(&certified_key_from_pem(&on_disk).unwrap()),
            f.rsa.leaf
        );
    }

    fn install_with(made: &Made, app: &str, cert_id: &str) -> CertificateInstall {
        let mut install = install_for(made);
        install.app_id = app.to_owned();
        install.certificate_id = cert_id.to_owned();
        install
    }

    #[test]
    fn an_install_the_bundle_does_not_name_is_refused_and_changes_nothing() {
        let s = Scratch::new();
        let mut k = keys(&s);
        let book = book_of(&[APP]);
        let f = fixture();
        apply(&mut k, &[(APP, uploaded(X, &f.ec.leaf))]);
        let before = files(&s.dir());
        assert!(!before.iter().any(|f| f.ends_with(".pem")));

        for (what, install) in [
            (
                "an app the bundle does not have",
                install_with(&f.ec, OTHER_APP, X),
            ),
            (
                "a leaf the bundle does not name",
                install_with(&f.rsa, APP, X),
            ),
            (
                "a certificate id the bundle does not name",
                install_with(&f.ec, APP, Y),
            ),
        ] {
            let got = k.install(&install, &book, &mut Secrets::default(), load_key);
            assert_eq!(got, Err(AckCode::NotInBundle), "{what}");
            assert_eq!(files(&s.dir()), before, "{what}");
        }

        // A source that is not uploaded, and one with no certificate named.
        let acme = r#"{"listen":"0.0.0.0:443","hosts":["shop.example.com"],"source":"acme"}"#;
        let bare = r#"{"listen":"0.0.0.0:443","hosts":["shop.example.com"],"source":"uploaded"}"#;
        for (what, tls) in [("acme", acme), ("no certificate", bare)] {
            apply(&mut k, &[(APP, tls.to_owned())]);
            let got = install_pair(&mut k, &book, &f.ec, X);
            assert_eq!(got, Err(AckCode::NotInBundle), "{what}");
            assert!(
                !files(&s.dir()).iter().any(|f| f.ends_with(".pem")),
                "{what}"
            );
        }

        // An app that left the bundle: the install that was sent for it is refused, and the app
        // is not put back into the book.
        apply(&mut k, &[(APP, uploaded(X, &f.ec.leaf))]);
        let none = k.prepare(&[]).unwrap();
        k.commit(none);
        book.follow(HashMap::new());
        assert_eq!(
            install_pair(&mut k, &book, &f.ec, X),
            Err(AckCode::NotInBundle)
        );
        assert!(book.get(APP).is_none());
        assert!(!files(&s.dir()).iter().any(|f| f.ends_with(".pem")));
    }

    #[test]
    fn a_certificate_that_is_held_is_acked_without_a_write_and_a_refused_one_leaves_no_trace() {
        let s = Scratch::new();
        let mut first = keys(&s);
        let book = book_of(&[APP]);
        let f = fixture();
        apply(&mut first, &[(APP, uploaded(X, &f.ec.leaf))]);
        assert_eq!(install_pair(&mut first, &book, &f.ec, X), Ok(()));

        // A process that holds no lock cannot write: for what it holds the install is still
        // acked, and for anything else it is the retryable refusal, with nothing left behind.
        let mut second = keys(&s);
        assert!(!second.holds_lock());
        let book2 = book_of(&[APP]);
        apply(&mut second, &[(APP, uploaded(X, &f.ec.leaf))]);
        let before = files(&s.dir());
        assert_eq!(install_pair(&mut second, &book2, &f.ec, X), Ok(()), "held");
        assert_eq!(files(&s.dir()), before);

        apply(&mut second, &[(APP, uploaded(Y, &f.rsa.leaf))]);
        assert_eq!(
            install_pair(&mut second, &book2, &f.rsa, Y),
            Err(AckCode::WriteFailed)
        );
        assert_eq!(files(&s.dir()), before, "no file and no temporary file");
        assert_eq!(served(second.applied(), APP), Some(format!("{X}.pem")));
        assert_eq!(
            held_leaf(&book2, APP),
            None,
            "and the book is as the bundle left it"
        );

        // A pair the checks refuse leaves the directory and the book as they were.
        apply(&mut first, &[(APP, uploaded(Y, &f.rsa.leaf))]);
        let before = files(&s.dir());
        let mut bad = install_with(&f.rsa, APP, Y);
        bad.key_pem = f.ec.key.clone();
        let got = first.install(&bad, &book, &mut Secrets::default(), load_key);
        assert_eq!(got, Err(AckCode::KeyMismatch));
        assert_eq!(files(&s.dir()), before);
        assert_eq!(held_leaf(&book, APP), Some(f.ec.leaf.clone()));
        assert_eq!(served(first.applied(), APP), Some(format!("{X}.pem")));
    }
}
