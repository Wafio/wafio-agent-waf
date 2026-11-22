//! What the agent remembers about the certificates it serves, in `state.json` of the key
//! directory: per app, the file it was served from and, for an ordered certificate, how the last
//! orders went. It holds no key material. A restart that comes before the certificate a bundle
//! names has arrived serves the file it remembers, and does not order again before its time.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::dir::{KeyDir, ReadError};

pub const STATE_FILE: &str = "state.json";
/// The most `load` reads of the file. `StateFile::fit` keeps what is written under it.
pub const MAX_STATE_FILE: usize = 1 << 20;
/// An entry has at most 100 hosts, each at most 253 bytes long, and a request id of at most 128.
const MAX_TRIED_HOSTS: usize = 100;
const MAX_HOST: usize = 253;
const MAX_REQUEST_ID: usize = 128;
/// What an error is cut to when the state is still too long without the hosts.
const SHORT_ERROR: usize = 128;

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
    /// The time before which no order starts because the authority said it limits the rate, in
    /// seconds since the epoch. A new request id does not lift it.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ca_wait_unix: i64,
    /// When the order that is running began, in seconds since the epoch, until it ends. It is
    /// written and synced before the first request of the order to the authority, so a start that
    /// finds it set knows that an order ended with no outcome.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub attempt_started: i64,
    /// The request id that order was for.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub attempt_request_id: String,
    /// How many orders in a row a start has found unfinished.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub interrupted: u32,
}

/// Cuts `text` to at most `max` bytes, on a character boundary.
fn cut(text: &mut String, max: usize) {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
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
        self.ca_wait_unix = 0;
        self.error.clear();
    }

    /// The order that was running ended, however it ended: it is no unfinished attempt, and the
    /// crashes counted before it are forgotten.
    pub fn end_attempt(&mut self) {
        self.drop_attempt();
        self.interrupted = 0;
    }

    /// The note of the order that is running goes, and the crashes counted before it stay.
    pub fn drop_attempt(&mut self) {
        self.attempt_started = 0;
        self.attempt_request_id.clear();
    }

    /// Keeps no more than an entry can have. A file of another build, or one that was edited, may
    /// hold more.
    pub fn bound(&mut self) {
        self.tried_hosts.retain(|host| host.len() <= MAX_HOST);
        self.tried_hosts.truncate(MAX_TRIED_HOSTS);
        cut(&mut self.request_id, MAX_REQUEST_ID);
        cut(&mut self.attempt_request_id, MAX_REQUEST_ID);
        cut(&mut self.error, super::status::MAX_ERROR);
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
                    record.bound();
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

    /// The text of the state for the file, never longer than `load` reads, or `None` when even the
    /// least that can be kept is too long (more apps than a file holds). Each record keeps no more
    /// than an entry can have; if the whole is still too long the hosts of the failed orders go,
    /// then the errors are cut short. The hosts only decide whether a failure still counts after
    /// the app dropped one, and without them it counts, so the app is tried again as before. What
    /// goes is gone from the state in memory too, so it matches the file.
    pub fn fit(&mut self) -> Option<Vec<u8>> {
        self.apps.values_mut().for_each(AppRecord::bound);
        let mut bytes = self.to_bytes();
        if bytes.len() > MAX_STATE_FILE {
            self.apps.values_mut().for_each(|r| r.tried_hosts.clear());
            bytes = self.to_bytes();
        }
        if bytes.len() > MAX_STATE_FILE {
            self.apps
                .values_mut()
                .for_each(|r| cut(&mut r.error, SHORT_ERROR));
            bytes = self.to_bytes();
        }
        (bytes.len() <= MAX_STATE_FILE).then_some(bytes)
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
            ca_wait_unix: 1_800_003_600,
            attempt_started: 1_800_000_000,
            attempt_request_id: "r2".into(),
            interrupted: 1,
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
        assert_eq!(forgotten.ca_wait_unix, 0, "a success lifts the wait");
        assert_eq!(
            (forgotten.attempt_started, forgotten.interrupted),
            (1_800_000_000, 1),
            "an attempt is ended by `end_attempt`, not by forgetting failures"
        );
        forgotten.end_attempt();
        assert_eq!(
            (
                forgotten.attempt_started,
                forgotten.attempt_request_id.as_str(),
                forgotten.interrupted
            ),
            (0, "", 0)
        );
        // A hand-over drops the note of the order and keeps the crashes counted before it.
        let mut handed = AppRecord {
            attempt_started: 1_800_000_000,
            attempt_request_id: "r2".into(),
            interrupted: 1,
            ..AppRecord::default()
        };
        handed.drop_attempt();
        assert_eq!(
            (
                handed.attempt_started,
                handed.attempt_request_id.as_str(),
                handed.interrupted
            ),
            (0, "", 1)
        );
    }

    #[test]
    fn a_state_file_of_the_previous_build_loads_with_the_new_fields_empty() {
        let s = Scratch::new();
        let d = dir(&s);
        // Written before the wait of the authority and the unfinished attempt were kept.
        let old = format!(
            r#"{{"apps":{{"{APP}":{{"served":"acme-{APP}.pem","directory":"https://ca.example/dir","request_id":"r1","worked":"http-01","tried":"tls-alpn-01","tried_hosts":["shop.example.com"],"failures":2,"next_attempt_unix":1800000600,"error":"the CA said no"}}}}}}"#
        );
        d.write(STATE_FILE, old.as_bytes()).unwrap();
        let (state, intact) = StateFile::load(&d);
        assert!(intact);
        let record = &state.apps[APP];
        assert_eq!(
            (
                record.served.as_deref(),
                record.directory.as_str(),
                record.request_id.as_str(),
                record.failures,
                record.next_attempt_unix
            ),
            (
                Some(format!("acme-{APP}.pem").as_str()),
                "https://ca.example/dir",
                "r1",
                2,
                1_800_000_600
            )
        );
        assert_eq!(
            (
                record.ca_wait_unix,
                record.attempt_started,
                record.attempt_request_id.as_str(),
                record.interrupted
            ),
            (0, 0, "", 0)
        );
        // Written again, a field that is empty stays out.
        let text = String::from_utf8(state.to_bytes()).unwrap();
        for name in [
            "ca_wait_unix",
            "attempt_started",
            "attempt_request_id",
            "interrupted",
        ] {
            assert!(!text.contains(name), "{name}: {text}");
        }
    }

    /// A record with every field as long as it can be.
    fn full_record() -> AppRecord {
        AppRecord {
            served: Some(format!("acme-{APP}.pem")),
            directory: format!("https://ca.example/{}", "d".repeat(200)),
            request_id: "r".repeat(MAX_REQUEST_ID),
            worked: "http-01".into(),
            tried: "tls-alpn-01".into(),
            tried_hosts: (0..MAX_TRIED_HOSTS)
                .map(|n| format!("{n:03}{}", "h".repeat(MAX_HOST - 3)))
                .collect(),
            failures: u32::MAX,
            next_attempt_unix: i64::MAX,
            error: "é".repeat(super::super::status::MAX_ERROR / 2),
            ca_wait_unix: i64::MAX,
            attempt_started: i64::MAX,
            attempt_request_id: "a".repeat(MAX_REQUEST_ID),
            interrupted: u32::MAX,
        }
    }

    fn many(apps: usize) -> StateFile {
        StateFile {
            apps: (0..apps)
                .map(|n| {
                    (
                        format!("{n:08x}-0000-4000-8000-000000000000"),
                        full_record(),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn a_state_at_the_caps_is_never_written_larger_than_load_accepts() {
        let s = Scratch::new();
        let d = dir(&s);
        // One app at the caps fits whole, and what is written is what is read back.
        let mut one = many(1);
        let bytes = one.fit().expect("one app fits");
        assert_eq!(one, many(1), "nothing is lost that fits");
        d.write(STATE_FILE, &bytes).unwrap();
        assert_eq!(StateFile::load(&d), (one, true));

        // Many apps with long hosts: the hosts go first. Then the errors are cut short, and
        // whatever is kept is read back whole.
        for apps in [30, 512, 800] {
            let mut state = many(apps);
            let bytes = state.fit().unwrap_or_else(|| panic!("{apps} apps fit"));
            assert!(
                bytes.len() <= MAX_STATE_FILE,
                "{apps} apps: {} bytes",
                bytes.len()
            );
            d.write(STATE_FILE, &bytes).unwrap();
            let (loaded, intact) = StateFile::load(&d);
            assert!(intact, "{apps} apps are read back");
            assert_eq!(
                loaded, state,
                "{apps} apps: the state in memory is the file's"
            );
            assert_eq!(loaded.apps.len(), apps, "no app is dropped");
            let kept = &loaded.apps[&format!("{:08x}-0000-4000-8000-000000000000", 0)];
            assert_eq!(kept.failures, u32::MAX, "what the plan reads is never cut");
            assert_eq!(kept.request_id.len(), MAX_REQUEST_ID);
        }
        let mut mid = many(30);
        mid.fit().unwrap();
        assert_eq!(
            mid.apps.values().next().unwrap().tried_hosts.len(),
            MAX_TRIED_HOSTS,
            "hosts stay while the whole fits"
        );
        let mut more = many(800);
        more.fit().unwrap();
        let record = more.apps.values().next().unwrap();
        assert!(record.tried_hosts.is_empty(), "hosts go when it does not");
        assert_eq!(record.error.len(), SHORT_ERROR, "and the errors are cut");

        // More apps than any file holds: nothing is written, and the file on disk stays.
        let mut absurd = many(20_000);
        assert!(absurd.fit().is_none());
        assert_eq!(StateFile::load(&d).0.apps.len(), 800);
    }

    #[test]
    fn a_record_keeps_no_more_than_an_entry_can_have() {
        let mut record = AppRecord {
            tried_hosts: (0..150).map(|n| format!("h{n}.example.com")).collect(),
            request_id: "r".repeat(500),
            attempt_request_id: "a".repeat(500),
            error: format!("{}é", "e".repeat(super::super::status::MAX_ERROR - 1)),
            ..AppRecord::default()
        };
        record.tried_hosts.push("x".repeat(MAX_HOST + 1));
        record.tried_hosts.insert(0, "y".repeat(MAX_HOST + 1));
        record.bound();
        assert_eq!(record.tried_hosts.len(), MAX_TRIED_HOSTS);
        assert!(record.tried_hosts.iter().all(|h| h.len() <= MAX_HOST));
        assert_eq!(record.tried_hosts[0], "h0.example.com");
        assert_eq!(record.request_id.len(), MAX_REQUEST_ID);
        assert_eq!(record.attempt_request_id.len(), MAX_REQUEST_ID);
        assert_eq!(
            record.error.len(),
            super::super::status::MAX_ERROR - 1,
            "cut before the character that does not fit"
        );

        // A file that holds more than that is bounded as it is read.
        let s = Scratch::new();
        let d = dir(&s);
        let hosts: Vec<String> = (0..150).map(|n| format!("\"h{n}.example.com\"")).collect();
        let text = format!(
            r#"{{"apps":{{"{APP}":{{"tried_hosts":[{}]}}}}}}"#,
            hosts.join(",")
        );
        d.write(STATE_FILE, text.as_bytes()).unwrap();
        assert_eq!(
            StateFile::load(&d).0.apps[APP].tried_hosts.len(),
            MAX_TRIED_HOSTS
        );
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
