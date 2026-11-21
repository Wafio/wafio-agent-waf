//! What the agent remembers about the certificates it serves, in `state.json` of the key
//! directory: per app, the file it was served from and, for an ordered certificate, how the last
//! orders went. It holds no key material. A restart that comes before the certificate a bundle
//! names has arrived serves the file it remembers, and does not order again before its time.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::dir::{KeyDir, ReadError};

pub const STATE_FILE: &str = "state.json";
/// A record is short, and the control plane serves at most 512 apps to one agent.
const MAX_STATE_FILE: usize = 1 << 20;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateFile {
    #[serde(default)]
    pub apps: BTreeMap<String, AppRecord>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRecord {
    /// The file of the key directory the app was served from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served: Option<String>,
    /// The directory of the certificate authority that issued the certificate in `served`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub directory: String,
    /// The request id of the last order that ended, whatever it ended in.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    /// The challenge type that last got a certificate.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub worked: String,
    /// The challenge type of the last order, while it failed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tried: String,
    /// The hosts the last order asked for, while it failed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tried_hosts: Vec<String>,
    /// Orders that failed in a row.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub failures: u32,
    /// When the next order may start after a failure, in seconds since the epoch.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub next_attempt_unix: i64,
    /// Why the last order failed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

fn is_zero<T: Default + PartialEq>(n: &T) -> bool {
    *n == T::default()
}

impl AppRecord {
    /// Whether the record holds anything about orders.
    pub fn has_orders(&self) -> bool {
        *self
            != AppRecord {
                served: self.served.clone(),
                ..AppRecord::default()
            }
    }

    /// Takes over everything `other` says of the orders, and leaves the file served as it is.
    pub fn take_orders_from(&mut self, other: &AppRecord) {
        *self = AppRecord {
            served: self.served.take(),
            ..other.clone()
        };
    }

    /// Whether every host the failed order asked for is among `hosts`, the ones the app has now.
    /// An order for a host the app has dropped since asks for nothing the app wants.
    pub fn tried_only(&self, hosts: &[String]) -> bool {
        self.tried_hosts.iter().all(|h| hosts.contains(h))
    }

    /// Forgets the failures, so the next order is not held back by them.
    pub fn forget_failures(&mut self) {
        self.tried.clear();
        self.tried_hosts.clear();
        self.failures = 0;
        self.next_attempt_unix = 0;
        self.error.clear();
    }
}

/// Whether `name` is a file the agent writes certificates to: `<uuid>.pem` for an uploaded
/// certificate, `acme-<uuid>.pem` for one it ordered.
pub fn is_key_file(name: &str) -> bool {
    let id = name.strip_prefix("acme-").unwrap_or(name);
    id.strip_suffix(".pem").is_some_and(super::entry::is_uuid)
}

impl StateFile {
    /// The state on disk, and whether the file was usable. A file that is missing is an empty
    /// state; one that is torn, corrupt or too large is an empty state too, which the next write
    /// replaces. A name that is no file of the agent is dropped, so a damaged record cannot make
    /// the agent read another file.
    pub fn load(dir: &KeyDir) -> (StateFile, bool) {
        let bytes = match dir.read(STATE_FILE, MAX_STATE_FILE) {
            Ok(bytes) => bytes,
            Err(ReadError::Missing) => return (StateFile::default(), true),
            Err(e) => {
                tracing::info!("[tls] {STATE_FILE}: {e}; starting without it");
                return (StateFile::default(), false);
            }
        };
        match serde_json::from_slice::<StateFile>(&bytes) {
            Ok(mut state) => {
                for record in state.apps.values_mut() {
                    record.served.take_if(|file| !is_key_file(file));
                }
                (state, true)
            }
            Err(e) => {
                tracing::info!("[tls] {STATE_FILE}: {e}; starting without it");
                (StateFile::default(), false)
            }
        }
    }

    /// The files the state says apps are served from.
    pub fn served_files(&self) -> impl Iterator<Item = &str> {
        self.apps.values().filter_map(|r| r.served.as_deref())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::dir::tests::{Scratch, my_uid};

    const APP: &str = "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11";
    const CERT: &str = "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77";

    fn dir(s: &Scratch) -> KeyDir {
        KeyDir::open(&s.dir(), my_uid()).unwrap()
    }

    #[test]
    fn the_file_names_a_certificate_file_of_the_agent_or_nothing() {
        assert!(is_key_file(&format!("{CERT}.pem")));
        assert!(is_key_file(&format!("acme-{APP}.pem")));
        for bad in [
            "",
            "state.json",
            ".pem",
            "../x.pem",
            "a/b.pem",
            &format!("{CERT}.pem.bak"),
            &format!("{}.pem", CERT.to_uppercase()),
            &format!("other-{APP}.pem"),
            &format!("acme-acme-{APP}.pem"),
        ] {
            assert!(!is_key_file(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_state_round_trips_and_a_missing_file_is_an_empty_state() {
        let s = Scratch::new();
        let d = dir(&s);
        assert_eq!(StateFile::load(&d), (StateFile::default(), true));
        let state = StateFile {
            apps: BTreeMap::from([
                (
                    APP.to_owned(),
                    AppRecord {
                        served: Some(format!("{CERT}.pem")),
                        ..AppRecord::default()
                    },
                ),
                ("none".to_owned(), AppRecord::default()),
            ]),
        };
        d.write(STATE_FILE, &state.to_bytes()).unwrap();
        assert_eq!(StateFile::load(&d), (state, true));
    }

    #[test]
    fn the_orders_of_an_app_are_kept_and_a_record_without_any_is_written_short() {
        let s = Scratch::new();
        let d = dir(&s);
        let ordered = AppRecord {
            served: Some(format!("acme-{APP}.pem")),
            directory: "https://ca.example/dir".into(),
            request_id: "r1".into(),
            worked: "http-01".into(),
            tried: "tls-alpn-01".into(),
            tried_hosts: vec!["shop.example.com".into(), "www.example.com".into()],
            failures: 2,
            next_attempt_unix: 1_800_000_600,
            error: "the CA said no".into(),
        };
        assert!(ordered.has_orders());
        let plain = AppRecord {
            served: Some(format!("{CERT}.pem")),
            ..AppRecord::default()
        };
        assert!(!plain.has_orders());
        assert!(!AppRecord::default().has_orders());
        let state = StateFile {
            apps: BTreeMap::from([(APP.to_owned(), ordered.clone()), ("p".to_owned(), plain)]),
        };
        let text = String::from_utf8(state.to_bytes()).unwrap();
        assert_eq!(
            text.matches("failures").count(),
            1,
            "a field that is empty is left out: {text}"
        );
        d.write(STATE_FILE, text.as_bytes()).unwrap();
        assert_eq!(StateFile::load(&d), (state, true));
        let mut forgotten = ordered;
        forgotten.forget_failures();
        assert_eq!(
            (
                forgotten.failures,
                forgotten.next_attempt_unix,
                forgotten.error.as_str(),
                forgotten.tried.as_str()
            ),
            (0, 0, "", "")
        );
        assert!(forgotten.tried_hosts.is_empty());
        assert_eq!(forgotten.request_id, "r1", "what the CA answered is kept");
    }

    #[test]
    fn a_failed_order_is_only_for_the_hosts_the_app_still_has_when_every_one_it_asked_for_is_among_them()
     {
        let hosts =
            |names: &[&str]| -> Vec<String> { names.iter().map(|n| (*n).to_owned()).collect() };
        let record = AppRecord {
            tried_hosts: hosts(&["a.example.com", "b.example.com"]),
            ..AppRecord::default()
        };
        assert!(record.tried_only(&hosts(&["b.example.com", "a.example.com"])));
        assert!(record.tried_only(&hosts(&["a.example.com", "b.example.com", "c.example.com"])));
        assert!(!record.tried_only(&hosts(&["a.example.com"])));
        assert!(!record.tried_only(&[]));
        // Nothing asked for, nothing dropped.
        assert!(AppRecord::default().tried_only(&hosts(&["a.example.com"])));
    }

    #[test]
    fn a_torn_or_corrupt_file_is_an_empty_state_and_not_an_error() {
        let s = Scratch::new();
        let d = dir(&s);
        let whole = StateFile {
            apps: BTreeMap::from([(
                APP.to_owned(),
                AppRecord {
                    served: Some(format!("{CERT}.pem")),
                    ..AppRecord::default()
                },
            )]),
        }
        .to_bytes();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("torn", whole[..whole.len() / 2].to_vec()),
            ("empty", Vec::new()),
            ("not JSON", b"\0\0\0\0".to_vec()),
            ("the wrong shape", b"[1,2]".to_vec()),
            ("the wrong type", br#"{"apps":{"a":{"served":7}}}"#.to_vec()),
            ("too large", vec![b' '; MAX_STATE_FILE + 1]),
        ];
        for (what, bytes) in cases {
            d.write(STATE_FILE, &bytes).unwrap();
            assert_eq!(StateFile::load(&d), (StateFile::default(), false), "{what}");
        }
    }

    #[test]
    fn a_record_that_names_another_file_loses_the_name() {
        let s = Scratch::new();
        let d = dir(&s);
        let text = format!(
            r#"{{"apps":{{"{APP}":{{"served":"../../etc/passwd"}},"x":{{"served":"{CERT}.pem"}},"y":{{}},"z":{{"unknown":1}}}}}}"#
        );
        d.write(STATE_FILE, text.as_bytes()).unwrap();
        let (state, intact) = StateFile::load(&d);
        assert!(intact);
        assert_eq!(state.apps[APP].served, None);
        assert_eq!(
            state.apps["x"].served.as_deref(),
            Some(format!("{CERT}.pem").as_str())
        );
        assert_eq!(state.apps.len(), 4);
    }
}
