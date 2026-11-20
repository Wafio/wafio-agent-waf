//! Apps the agent serves over HTTPS itself: the `tls` object of a bundle app, and the key
//! directory that holds the certificate each one is served from.
//!
//! `Keys` is the state of that part of the agent. It lives in the agent's apply state, so every
//! change of what is served and every write in the directory happens under the apply lock, one at
//! a time, in the order the bundles and installs arrive.

pub mod dir;
pub mod entry;
pub mod state_file;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pingora::tls::sign::CertifiedKey;
use wafio_proxy::cert_store::{BookEntry, certified_key_from_pem, leaf_sha256};

use crate::bundle::BundleApp;
use dir::{KeyDir, MAX_KEY_FILE, ReadError};
use entry::{Refusal, Settings, check, is_known_source};
use state_file::{AppRecord, STATE_FILE, StateFile};

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
    /// the state remembers.
    fn resolve(&self, app_id: &str, settings: &Settings) -> Option<Served> {
        let previous = self.applied.get(app_id).and_then(|a| a.served.as_ref());
        let leaf = settings
            .certificate
            .as_ref()
            .map(|c| c.leaf_sha256.as_str());
        if let Some(file) = settings.wanted_file(app_id) {
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
        }
        if let Some(held) = previous {
            return Some(held.clone());
        }
        let file = self.state.apps.get(app_id)?.served.as_deref()?;
        match self.load(file, None) {
            Ok(served) => Some(served),
            Err(e) => {
                tracing::info!("[tls] app {app_id}: {file}: {e}");
                None
            }
        }
    }

    /// Reads `file` and builds its key. With `leaf` the certificate must be that one.
    fn load(&self, file: &str, leaf: Option<&str>) -> Result<Served, Fault> {
        let pem = self.dir.read(file, MAX_KEY_FILE).map_err(Fault::Read)?;
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
        self.settle();
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
        self.settle();
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
    /// write and a bundle has said what is wanted.
    fn settle(&mut self) {
        if !self.dir.holds_lock() || !self.bundle_seen {
            return;
        }
        if self.written.as_ref() != Some(&self.state) {
            match self.dir.write(STATE_FILE, &self.state.to_bytes()) {
                Ok(()) => self.written = Some(self.state.clone()),
                Err(e) => tracing::info!("[tls] cannot write {STATE_FILE}: {}", e.kind()),
            }
        }
        self.remove_unused();
    }

    /// Removes each `*.pem` that no app of the bundle names and none serves: the certificate an
    /// app was served with goes once the one that replaces it is served.
    fn remove_unused(&self) {
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
        for file in files.iter().filter(|f| !needed.contains(*f)) {
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
    use super::*;
    use crate::bundle::decode_bundle;
    use dir::tests::{Scratch, my_uid};
    use std::path::Path;
    use std::process::Command;

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
            [format!("{X}.pem").as_str(), STATE_FILE, "tls.lock"]
        );

        let none = k.prepare(&[]).unwrap();
        k.commit(none);
        assert!(state_on_disk(&s.dir()).apps.is_empty());
        assert_eq!(files(&s.dir()), [STATE_FILE, "tls.lock"]);
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
}
