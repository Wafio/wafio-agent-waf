//! What the agent says about the certificate of each app it serves over HTTPS: the
//! `CertificateStatus` of the contract, made from the bundle in force, and the text of an error
//! that may go in one.
//!
//! This module decides what the status of an app is. When to send it, and how often, is for
//! `pacer`.

use std::collections::HashMap;

use wafio_control::CertificateStatus;
use wafio_proxy::cert_store::chain_pem;

use super::entry::{Certificate, Source};
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

/// `failed` for each app of a bundle that was refused for a reason that concerns its HTTPS
/// settings, `why` being the reason. The apps are those of the refused bundle, read as sent: its
/// settings may be what failed. The certificate each is served meanwhile stays described, from
/// the bundle in force.
pub fn refused(
    apps: &[BundleApp],
    applied: &HashMap<String, Applied>,
    why: &str,
) -> Vec<CertificateStatus> {
    let error = error_text(why);
    let mut all: Vec<CertificateStatus> = apps
        .iter()
        .filter_map(|app| {
            let entry = app.tls.as_ref()?;
            let served = applied.get(&app.app_id).and_then(|a| a.served.as_ref());
            let status = match entry.source.as_str() {
                SOURCE_UPLOADED if !entry.certificate_id.is_empty() => CertificateStatus {
                    certificate_id: entry.certificate_id.clone(),
                    ..base(&app.app_id, SOURCE_UPLOADED, State::Failed, served)
                },
                SOURCE_ACME => CertificateStatus {
                    request_id: entry.acme_request_id.clone(),
                    ..base(&app.app_id, SOURCE_ACME, State::Failed, served)
                },
                _ => return None,
            };
            Some(CertificateStatus {
                error: error.clone(),
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
            refused(&apps, &HashMap::new(), "PRIVATE KEY text")[0].error,
            ERROR_WITHHELD
        );
        assert_eq!(
            refused(&apps, &HashMap::new(), "bad\nphrase")[0].error,
            "badphrase"
        );
    }
}
