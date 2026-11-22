//! What the agent says about the certificate of each app it serves over HTTPS: the
//! `CertificateStatus` of the contract, made from the bundle in force, and the text of an error
//! that may go in one.
//!
//! This module decides what the status of an app is. When to send it, and how often, is for
//! `pacer`.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use wafio_control::CertificateStatus;
use wafio_proxy::cert_store::chain_pem;

use super::acme::schedule::{Own, failed, held_by_authority, own, retry_at};
use super::entry::{Certificate, Settings, Source, is_uuid};
use super::state_file::AppRecord;
use super::{Applied, Served};
use crate::bundle::BundleApp;

/// The longest `error` the control plane stores.
pub const MAX_ERROR: usize = 1024;
/// Stands for an error text that held what looks like key material.
pub const ERROR_WITHHELD: &str = "error text withheld";
/// Stands for a bundle refused because the `tls` settings of an app failed a check.
pub const REFUSED_SETTINGS: &str = "the bundle was refused: its TLS settings are not valid";

pub const SOURCE_UPLOADED: &str = "uploaded";
pub const SOURCE_ACME: &str = "acme";

/// The states of the contract. An ordered certificate adds `Pending` and `Failed` to the ones an
/// uploaded certificate has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Pending,
    Active,
    Failed,
    Missing,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Active => "active",
            State::Failed => "failed",
            State::Missing => "missing",
        }
    }
}

/// The time now as the control plane takes it, seconds since the epoch.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// A status with the fields every source fills; the caller sets the rest.
fn base(app_id: &str, source: &str, state: State, served: Option<&Served>) -> CertificateStatus {
    CertificateStatus {
        app_id: app_id.to_owned(),
        source: source.to_owned(),
        state: state.as_str().to_owned(),
        // The chain in use, whenever there is one, so the control plane can read its dates.
        chain_pem: served.map_or_else(Vec::new, |s| chain_pem(&s.key.cert)),
        leaf_sha256: served.map_or_else(String::new, |s| s.leaf_sha256.clone()),
        ..Default::default()
    }
}

/// `active` when the app is served the certificate its bundle names, else `missing`, with the
/// certificate it is served meanwhile, if any.
fn uploaded(app_id: &str, wanted: &Certificate, served: Option<&Served>) -> CertificateStatus {
    let held = served
        .filter(|s| s.file == format!("{}.pem", wanted.id) && s.leaf_sha256 == wanted.leaf_sha256);
    let state = if held.is_some() {
        State::Active
    } else {
        State::Missing
    };
    CertificateStatus {
        certificate_id: wanted.id.clone(),
        ..base(app_id, SOURCE_UPLOADED, state, served)
    }
}

/// The status of an app whose certificate is ordered. `pending`: an order is running, or none has
/// answered the request id of the bundle yet (so one is due, and the chain in use, if any, is
/// still the previous one); `failed`: the order that answered the id failed (or gave a certificate
/// that was due for renewal at once), with the time of the next one, or the authority's wait after
/// an order under an earlier id still holds the new one back; `active`: the certificate in use is
/// the ordered one and covers every host. A finished order reports only while the id it started
/// under is the bundle's. A failed order says when the next attempt is by the same rule that makes
/// the worker wait for it. The chain in use is described whatever the state, one that has expired
/// included: a failed renewal keeps serving it.
pub fn ordered(
    app_id: &str,
    settings: &Settings,
    served: Option<&Served>,
    record: Option<&AppRecord>,
    running: bool,
) -> CertificateStatus {
    let answered = record.map_or(settings.request_id.is_empty(), |r| {
        r.request_id == settings.request_id
    });
    let own = own(app_id, settings, served);
    let failure = failed(settings, record, own).or_else(|| held_by_authority(settings, record));
    let state = if running {
        State::Pending
    } else if failure.is_some() {
        State::Failed
    } else if !answered {
        State::Pending
    } else if matches!(own, Own::Whole { .. }) {
        State::Active
    } else {
        State::Pending
    };
    let (error, next_attempt_unix) = match (state, failure) {
        (State::Failed, Some(r)) => (r.error.clone(), retry_at(settings, record, own)),
        _ => (String::new(), 0),
    };
    CertificateStatus {
        request_id: settings.request_id.clone(),
        error,
        next_attempt_unix,
        ..base(app_id, SOURCE_ACME, state, served)
    }
}

/// The status of every app of the bundle in force that has one to report, by app id; `only`
/// narrows it to one app. An app whose source is empty, whose source this agent does not know, or
/// whose uploaded source names no certificate has none: nothing is served for it.
pub fn current(applied: &HashMap<String, Applied>, only: Option<&str>) -> Vec<CertificateStatus> {
    let mut all: Vec<CertificateStatus> = applied
        .iter()
        .filter(|(id, _)| only.is_none_or(|only| only == id.as_str()))
        .filter_map(
            |(id, app)| match (app.settings.source, &app.settings.certificate) {
                (Source::Uploaded, Some(wanted)) => Some(uploaded(id, wanted, app.served.as_ref())),
                // An ordered certificate reports through the order that makes it.
                (Source::Acme, _) | (Source::Uploaded, None) | (Source::None, _) => None,
            },
        )
        .collect();
    all.sort_by(|a, b| a.app_id.cmp(&b.app_id));
    all
}

/// What the control plane hears of a bundle that was refused for a reason that concerns its HTTPS
/// settings.
#[derive(Debug, Default)]
pub struct Refusal {
    /// `failed` for its uploaded apps, as [`refused`] gives them.
    pub failed: Vec<CertificateStatus>,
    /// Its apps that it orders as the bundle in force does, with the same request id. They go on
    /// reporting their order. Any other app would be told under a source or a request id that the
    /// control plane no longer has for it, and it drops such a status.
    pub ordered: HashSet<String>,
}

/// The [`Refusal`] of a bundle with the apps `apps`, `applied` being the bundle in force.
pub fn refusal(
    apps: &[BundleApp],
    applied: &HashMap<String, Applied>,
    why: &str,
    retry_at: i64,
) -> Refusal {
    let ordered = apps
        .iter()
        .filter(|app| {
            let (Some(entry), Some(now)) = (app.tls.as_ref(), applied.get(&app.app_id)) else {
                return false;
            };
            entry.source == SOURCE_ACME
                && now.settings.source == Source::Acme
                && entry.acme_request_id == now.settings.request_id
        })
        .map(|app| app.app_id.clone())
        .collect();
    Refusal {
        failed: refused(apps, applied, why, retry_at),
        ordered,
    }
}

/// `failed` for each app of a bundle that was refused for a reason that concerns its HTTPS
/// settings, `why` being the reason. The apps are those of the refused bundle, read as sent: its
/// settings may be what failed. The certificate each is served meanwhile stays described, from
/// the bundle in force. `retry_at` is when the bundle is tried again, or 0 when nothing is
/// planned. An ordered certificate has none until it reports through its order: a `failed` here
/// would stay on its app after the bundle was taken. An app id that is no UUID names no app of the
/// control plane, so it gets none either.
pub fn refused(
    apps: &[BundleApp],
    applied: &HashMap<String, Applied>,
    why: &str,
    retry_at: i64,
) -> Vec<CertificateStatus> {
    let error = error_text(why);
    let mut all: Vec<CertificateStatus> = apps
        .iter()
        .filter_map(|app| {
            let entry = app.tls.as_ref().filter(|_| is_uuid(&app.app_id))?;
            let served = applied.get(&app.app_id).and_then(|a| a.served.as_ref());
            let status = match entry.source.as_str() {
                SOURCE_UPLOADED if !entry.certificate_id.is_empty() => CertificateStatus {
                    certificate_id: entry.certificate_id.clone(),
                    ..base(&app.app_id, SOURCE_UPLOADED, State::Failed, served)
                },
                _ => return None,
            };
            Some(CertificateStatus {
                error: error.clone(),
                next_attempt_unix: retry_at,
                ..status
            })
        })
        .collect();
    all.sort_by(|a, b| a.app_id.cmp(&b.app_id));
    all
}

/// The text of an error as the control plane takes it: control characters removed, at most
/// `MAX_ERROR` bytes cut on a character boundary, and a fixed phrase for anything that holds a
/// PEM marker or the words of a key block, which no error of the agent should ever hold.
pub fn error_text(raw: &str) -> String {
    let clean: String = raw.chars().filter(|c| !c.is_control()).collect();
    if clean.contains("-----BEGIN") || clean.contains("PRIVATE KEY") {
        return ERROR_WITHHELD.to_owned();
    }
    let mut end = clean.len().min(MAX_ERROR);
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    clean[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::tls::entry::Settings;
    use crate::tls::install::tests::{APP, CERT, fixture};
    use wafio_proxy::cert_store::{certified_key_from_pem, leaf_sha256};

    fn settings(wanted_leaf: &str) -> Settings {
        Settings {
            listen: "0.0.0.0:443".into(),
            redirect_listen: None,
            hosts: vec!["shop.example.com".into()],
            source: Source::Uploaded,
            certificate: Some(Certificate {
                id: CERT.into(),
                leaf_sha256: wanted_leaf.into(),
            }),
            request_id: String::new(),
        }
    }

    #[test]
    fn the_chain_of_a_status_is_the_served_chain_written_from_its_der() {
        let f = fixture();
        let chain = [f.ec.cert.clone(), f.other_ec.cert.clone()].concat();
        let key = certified_key_from_pem(&[f.ec.key.clone(), chain.clone()].concat()).unwrap();
        let served = Served {
            file: format!("{CERT}.pem"),
            leaf_sha256: leaf_sha256(&key),
            key: Arc::new(key),
        };
        let held = HashMap::from([(
            APP.to_owned(),
            Applied {
                settings: settings(&f.ec.leaf),
                served: Some(served.clone()),
            },
        )]);
        let [active] = &current(&held, None)[..] else {
            panic!("one status");
        };
        assert_eq!(active.state, "active");
        assert_eq!(
            active.chain_pem, chain,
            "the same text as the chain that came in"
        );
        assert_eq!(active.leaf_sha256, f.ec.leaf);
        assert_eq!(active.certificate_id, CERT);

        // The bundle names another certificate: the one that is served is described until the
        // named one arrives, and the status asks for it.
        let waiting = HashMap::from([(
            APP.to_owned(),
            Applied {
                settings: settings(&f.rsa.leaf),
                served: Some(served),
            },
        )]);
        let [missing] = &current(&waiting, None)[..] else {
            panic!("one status");
        };
        assert_eq!(missing.state, "missing");
        assert_eq!(
            (missing.chain_pem.clone(), missing.leaf_sha256.clone()),
            (chain, f.ec.leaf.clone())
        );

        // `only` narrows to an app, and an app that is not there has no status.
        assert!(current(&waiting, Some("other")).is_empty());
        assert_eq!(current(&waiting, Some(APP)).len(), 1);
    }

    fn acme_settings(hosts: &[&str], request_id: &str) -> Settings {
        Settings {
            listen: "0.0.0.0:443".into(),
            redirect_listen: None,
            hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
            source: Source::Acme,
            certificate: None,
            request_id: request_id.into(),
        }
    }

    fn acme_record(request_id: &str, failures: u32) -> AppRecord {
        AppRecord {
            request_id: request_id.into(),
            failures,
            next_attempt_unix: if failures > 0 { 1_800_000_600 } else { 0 },
            error: if failures > 0 {
                "it failed".into()
            } else {
                String::new()
            },
            ..AppRecord::default()
        }
    }

    #[test]
    fn an_ordered_certificate_is_pending_active_or_failed_for_the_request_id_of_the_bundle() {
        let file = format!("acme-{APP}.pem");
        let chain =
            crate::tls::acme::placeholder::certificate(&["shop.example.com".to_owned()]).unwrap();
        let served = |file: &str| Served {
            file: file.to_owned(),
            leaf_sha256: leaf_sha256(&chain),
            key: chain.clone(),
        };
        let whole = acme_settings(&["shop.example.com"], "r1");
        let status =
            |settings: &Settings, served: Option<&Served>, record: Option<&AppRecord>, running| {
                let s = ordered(APP, settings, served, record, running);
                (
                    s.state,
                    s.request_id,
                    s.error,
                    s.next_attempt_unix,
                    s.leaf_sha256.is_empty(),
                )
            };
        let show = |state: &str, id: &str, error: &str, at: i64, no_leaf: bool| {
            (
                state.to_owned(),
                id.to_owned(),
                error.to_owned(),
                at,
                no_leaf,
            )
        };
        let own = served(&file);

        // Nothing ordered yet: pending, before the first order and while it runs.
        assert_eq!(
            status(&whole, None, None, false),
            show("pending", "r1", "", 0, true)
        );
        assert_eq!(
            status(&whole, None, Some(&acme_record("r1", 0)), true),
            show("pending", "r1", "", 0, true)
        );
        // The certificate in use is the ordered one and covers the hosts.
        assert_eq!(
            status(&whole, Some(&own), Some(&acme_record("r1", 0)), false),
            show("active", "r1", "", 0, false)
        );
        // The one in use is another (the previous source's): pending, with its chain described.
        let other = served(&format!("{CERT}.pem"));
        assert_eq!(
            status(&whole, Some(&other), Some(&acme_record("r1", 0)), false),
            show("pending", "r1", "", 0, false)
        );
        // A host the certificate does not cover: pending.
        let wider = acme_settings(&["shop.example.com", "more.example.com"], "r1");
        assert_eq!(
            status(&wider, Some(&own), Some(&acme_record("r1", 0)), false),
            show("pending", "r1", "", 0, false)
        );
        // The last order failed: failed, with its text and the time of the next, and the chain
        // in use if there is one.
        assert_eq!(
            status(&whole, None, Some(&acme_record("r1", 2)), false),
            show("failed", "r1", "it failed", 1_800_000_600, true)
        );
        assert_eq!(
            status(&whole, Some(&own), Some(&acme_record("r1", 1)), false),
            show("failed", "r1", "it failed", 1_800_000_600, false)
        );
        // While the next order runs it is pending again, and says nothing of the failure.
        assert_eq!(
            status(&whole, None, Some(&acme_record("r1", 1)), true),
            show("pending", "r1", "", 0, true)
        );
        // An order that answered another id reports nothing for this one: pending for the new id.
        let new_id = acme_settings(&["shop.example.com"], "r2");
        assert_eq!(
            status(&new_id, Some(&own), Some(&acme_record("r1", 0)), false),
            show("pending", "r2", "", 0, false)
        );
        assert_eq!(
            status(&new_id, None, Some(&acme_record("r1", 3)), false),
            show("pending", "r2", "", 0, true)
        );
        // A failure for a host the app has dropped since, with a certificate that covers the rest:
        // the certificate in use is all the app asks for, so it is active. With a gap it is failed.
        let dropped = AppRecord {
            tried_hosts: vec!["shop.example.com".into(), "gone.example.com".into()],
            ..acme_record("r1", 1)
        };
        assert_eq!(
            status(&whole, Some(&own), Some(&dropped), false),
            show("active", "r1", "", 0, false)
        );
        assert_eq!(
            status(&wider, Some(&own), Some(&dropped), false),
            show("failed", "r1", "it failed", 1_800_000_600, false)
        );
        // The source is `acme` and the certificate id is empty.
        let s = ordered(APP, &whole, None, None, false);
        assert_eq!(
            (
                s.source.as_str(),
                s.certificate_id.as_str(),
                s.app_id.as_str()
            ),
            ("acme", "", APP)
        );
    }

    #[test]
    fn a_new_request_id_inside_the_authoritys_wait_is_failed_with_its_time_and_a_failed_renewal_keeps_its_chain()
     {
        let file = format!("acme-{APP}.pem");
        let chain =
            crate::tls::acme::placeholder::certificate(&["shop.example.com".to_owned()]).unwrap();
        let served = Served {
            file,
            leaf_sha256: leaf_sha256(&chain),
            key: chain.clone(),
        };
        let limited = AppRecord {
            ca_wait_unix: 1_800_007_200,
            ..acme_record("r1", 1)
        };
        // The same id: failed, at the later of the agent's backoff and the authority's wait.
        let same = ordered(
            APP,
            &acme_settings(&["shop.example.com"], "r1"),
            Some(&served),
            Some(&limited),
            false,
        );
        assert_eq!(
            (
                same.state.as_str(),
                same.next_attempt_unix,
                same.leaf_sha256.is_empty()
            ),
            ("failed", 1_800_007_200, false)
        );
        assert_eq!(same.chain_pem, chain_pem(&chain.cert), "the chain in use");
        // A new id: the backoff is lifted, the wait is not, and the status says so under the new id.
        let new_id = ordered(
            APP,
            &acme_settings(&["shop.example.com"], "r2"),
            Some(&served),
            Some(&limited),
            false,
        );
        assert_eq!(
            (
                new_id.state.as_str(),
                new_id.request_id.as_str(),
                new_id.next_attempt_unix
            ),
            ("failed", "r2", 1_800_007_200)
        );
        assert_eq!(new_id.error, "it failed");
        assert!(!new_id.chain_pem.is_empty());
        // While its order runs it is pending, and without a wait the new id is pending too.
        let running = ordered(
            APP,
            &acme_settings(&["shop.example.com"], "r2"),
            Some(&served),
            Some(&limited),
            true,
        );
        assert_eq!(
            (running.state.as_str(), running.next_attempt_unix),
            ("pending", 0)
        );
        let free = AppRecord {
            ca_wait_unix: 0,
            ..limited
        };
        let new_id = ordered(
            APP,
            &acme_settings(&["shop.example.com"], "r2"),
            Some(&served),
            Some(&free),
            false,
        );
        assert_eq!(
            (
                new_id.state.as_str(),
                new_id.error.as_str(),
                new_id.next_attempt_unix
            ),
            ("pending", "", 0)
        );
    }

    #[test]
    fn an_error_text_is_made_of_what_the_control_plane_takes() {
        assert_eq!(
            error_text("cannot\nlisten on 0.0.0.0:443\r\u{7}"),
            "cannotlisten on 0.0.0.0:443"
        );
        // Built from parts: a whole key marker in a source file is what the secret scan looks for.
        let marker = |label: &str| format!("-----BEGIN {label}-----");
        for secret in [
            marker("PRIVATE KEY"),
            "the PRIVATE KEY is bad".to_owned(),
            format!("x {}", marker("CERTIFICATE")),
            "PRIV\u{0}ATE KEY".to_owned(),
            marker("RSA PRIVATE KEY").replace('B', "B\u{1b}"),
        ] {
            assert_eq!(error_text(&secret), ERROR_WITHHELD, "{secret:?}");
        }
        // Cut on a character boundary: 1023 letters and then a two-byte one end before it.
        let long = format!("{}é{}", "a".repeat(MAX_ERROR - 1), "b".repeat(100));
        let cut = error_text(&long);
        assert_eq!(cut.len(), MAX_ERROR - 1);
        assert!(cut.chars().all(|c| c == 'a'));
        let exact = "é".repeat(MAX_ERROR / 2);
        assert_eq!(error_text(&exact), exact);
        assert_eq!(error_text(&"x".repeat(5000)).len(), MAX_ERROR);
        assert_eq!(error_text(""), "");
        // The phrase a refusal carries goes through the same cleaning.
        let apps = crate::bundle::decode_bundle(
            format!(
                r#"{{"apps":[{{"app_id":"{APP}","tls":{{"hosts":["a.example.com"],"source":"uploaded","certificate_id":"{CERT}","leaf_sha256":"{}"}}}}]}}"#,
                "ab".repeat(32)
            )
            .as_bytes(),
        )
        .unwrap()
        .apps;
        assert_eq!(
            refused(&apps, &HashMap::new(), "PRIVATE KEY text", 0)[0].error,
            ERROR_WITHHELD
        );
        assert_eq!(
            refused(&apps, &HashMap::new(), "bad\nphrase", 0)[0].error,
            "badphrase"
        );
    }

    #[test]
    fn a_refusal_names_when_the_bundle_is_tried_again_and_skips_what_reports_no_state_yet() {
        let tls = |source: &str, extra: &str| {
            format!(r#"{{"hosts":["a.example.com"],"source":"{source}"{extra}}}"#)
        };
        let uploaded = tls(
            "uploaded",
            &format!(
                r#","certificate_id":"{CERT}","leaf_sha256":"{}""#,
                "ab".repeat(32)
            ),
        );
        let entries = [
            (APP, uploaded.clone()),
            (
                "1a2b3c4d-0000-4000-8000-000000000002",
                tls("acme", r#","acme_request_id":"r1""#),
            ),
            ("1a2b3c4d-0000-4000-8000-000000000003", tls("", "")),
            ("1a2b3c4d-0000-4000-8000-000000000004", tls("uploaded", "")),
            // An id that names no app of the control plane gets nothing, whatever its entry says.
            ("not-an-app-id", uploaded),
        ];
        let list: Vec<String> = entries
            .iter()
            .map(|(id, tls)| format!(r#"{{"app_id":"{id}","tls":{tls}}}"#))
            .collect();
        let apps =
            crate::bundle::decode_bundle(format!(r#"{{"apps":[{}]}}"#, list.join(",")).as_bytes())
                .unwrap()
                .apps;
        let got = refused(
            &apps,
            &HashMap::new(),
            "cannot listen on 0.0.0.0:443: address in use",
            1_800_000_060,
        );
        let [only] = &got[..] else {
            panic!("only an uploaded certificate that the bundle names has a status: {got:?}");
        };
        assert_eq!(
            (
                only.app_id.as_str(),
                only.state.as_str(),
                only.certificate_id.as_str(),
                only.next_attempt_unix
            ),
            (APP, "failed", CERT, 1_800_000_060)
        );
        assert_eq!(only.error, "cannot listen on 0.0.0.0:443: address in use");
        assert_eq!(
            refused(&apps, &HashMap::new(), "x", 0)[0].next_attempt_unix,
            0
        );
    }
}
