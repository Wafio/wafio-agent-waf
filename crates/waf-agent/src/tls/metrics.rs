//! What the agent counts of its certificates for the metrics listener: how its orders end, how
//! the installs of uploaded certificates are answered, and when the certificate each app is
//! served ends. The only label values are the result of an order or an install, which come from
//! a fixed set, and an app id, which an entry check has made a canonical UUID.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use wafio_agent_io::metrics::{Label, Registry, Sample};
use wafio_control::AckCode;

use super::status::unix_now;

#[derive(Default)]
pub struct TlsMetrics {
    orders_issued: AtomicU64,
    orders_failed: AtomicU64,
    /// Installs by result: `ok`, or the code of the refusal. Only results that happened.
    installs: Mutex<BTreeMap<&'static str, u64>>,
    /// When the certificate each app is served ends, in seconds since the epoch, by app id.
    expiry: Mutex<BTreeMap<String, i64>>,
}

fn sample(label: &str, value: &str, number: f64) -> Sample {
    Sample {
        labels: vec![Label {
            name: label.into(),
            value: value.into(),
        }],
        value: number,
    }
}

/// A count or a number of seconds as the float a sample holds.
fn float(n: impl Into<i128>) -> f64 {
    n.into() as f64
}

impl TlsMetrics {
    /// An order ended with a certificate that was kept and is served.
    pub fn order_issued(&self) {
        self.orders_issued.fetch_add(1, Ordering::Relaxed);
    }

    /// An order ended in a failure, whatever the cause: the authority, the key directory, or an
    /// agent that stopped twice in a row while it ran.
    pub fn order_failed(&self) {
        self.orders_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// An install of an uploaded certificate was answered.
    pub fn install(&self, result: Result<(), AckCode>) {
        let result = result.err().map_or("ok", AckCode::as_str);
        *self
            .installs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(result)
            .or_default() += 1;
    }

    /// Replaces what is known of the end of each app's served certificate: an app that is not in
    /// `expiry` has no series any more.
    pub fn set_expiry(&self, expiry: BTreeMap<String, i64>) {
        *self.expiry.lock().unwrap_or_else(|e| e.into_inner()) = expiry;
    }

    fn order_samples(&self) -> Vec<Sample> {
        let count = |n: &AtomicU64| float(n.load(Ordering::Relaxed));
        vec![
            sample("result", "issued", count(&self.orders_issued)),
            sample("result", "failed", count(&self.orders_failed)),
        ]
    }

    fn install_samples(&self) -> Vec<Sample> {
        let installs = self.installs.lock().unwrap_or_else(|e| e.into_inner());
        let mut samples = vec![sample(
            "result",
            "ok",
            float(installs.get("ok").copied().unwrap_or(0)),
        )];
        samples.extend(
            installs
                .iter()
                .filter(|(result, _)| **result != "ok")
                .map(|(result, n)| sample("result", result, float(*n))),
        );
        samples
    }

    /// Seconds from `now` until each certificate ends; negative once it has.
    fn expiry_samples(&self, now: i64) -> Vec<Sample> {
        let expiry = self.expiry.lock().unwrap_or_else(|e| e.into_inner());
        expiry
            .iter()
            .map(|(app_id, ends)| sample("app_id", app_id, float(ends.saturating_sub(now))))
            .collect()
    }

    pub fn register(self: &Arc<Self>, reg: &Registry) {
        let m = self.clone();
        reg.labeled_counter(
            "wafio_waf_acme_orders",
            "Certificate orders that ended, by result: issued (a certificate was kept and is served) or failed.",
            move || m.order_samples(),
        );
        let m = self.clone();
        reg.labeled_counter(
            "wafio_waf_certificate_installs",
            "Installs of uploaded certificates the control plane sent, by result: ok, or the code the agent refused with.",
            move || m.install_samples(),
        );
        let m = self.clone();
        reg.labeled_gauge(
            "wafio_waf_tls_certificate_expiry_seconds",
            "Seconds until the certificate each app is served over HTTPS ends, negative once it has. An app served no certificate, or the placeholder, has no series.",
            move || m.expiry_samples(unix_now()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11";
    const OTHER: &str = "6f1c0c64-4f7e-4a06-8cf3-0b7c2a6d1e90";

    fn text(m: &Arc<TlsMetrics>) -> String {
        let reg = Registry::new();
        m.register(&reg);
        String::from_utf8(reg.write()).unwrap()
    }

    #[test]
    fn orders_are_counted_by_their_result_and_both_results_are_always_there() {
        let m = Arc::new(TlsMetrics::default());
        let before = text(&m);
        assert!(
            before.contains("wafio_waf_acme_orders_total{result=\"issued\"} 0\n"),
            "{before}"
        );
        assert!(
            before.contains("wafio_waf_acme_orders_total{result=\"failed\"} 0\n"),
            "{before}"
        );
        m.order_issued();
        m.order_failed();
        m.order_failed();
        let after = text(&m);
        assert!(
            after.contains("wafio_waf_acme_orders_total{result=\"issued\"} 1\n"),
            "{after}"
        );
        assert!(
            after.contains("wafio_waf_acme_orders_total{result=\"failed\"} 2\n"),
            "{after}"
        );
    }

    #[test]
    fn installs_are_counted_by_ok_or_the_code_of_the_refusal() {
        let m = Arc::new(TlsMetrics::default());
        assert!(text(&m).contains("wafio_waf_certificate_installs_total{result=\"ok\"} 0\n"));
        m.install(Ok(()));
        m.install(Ok(()));
        m.install(Err(AckCode::KeyMismatch));
        m.install(Err(AckCode::KeyMismatch));
        m.install(Err(AckCode::NotInBundle));
        let t = text(&m);
        for line in [
            "wafio_waf_certificate_installs_total{result=\"ok\"} 2\n",
            "wafio_waf_certificate_installs_total{result=\"key_mismatch\"} 2\n",
            "wafio_waf_certificate_installs_total{result=\"not_in_bundle\"} 1\n",
        ] {
            assert!(t.contains(line), "{line}: {t}");
        }
        assert!(!t.contains("bad_pem"), "only results that happened: {t}");
    }

    #[test]
    fn a_label_is_a_result_from_a_fixed_set_or_the_id_of_an_app_and_nothing_else() {
        let m = Arc::new(TlsMetrics::default());
        for code in [
            AckCode::BadPem,
            AckCode::TooLarge,
            AckCode::KeyMismatch,
            AckCode::LeafMismatch,
            AckCode::UnsupportedKey,
            AckCode::NotInBundle,
            AckCode::WriteFailed,
        ] {
            m.install(Err(code));
        }
        m.install(Ok(()));
        m.order_issued();
        m.order_failed();
        m.set_expiry(BTreeMap::from([(APP.to_owned(), 1_800_000_000)]));
        let allowed = [
            "ok",
            "bad_pem",
            "too_large",
            "key_mismatch",
            "leaf_mismatch",
            "unsupported_key",
            "not_in_bundle",
            "write_failed",
            "issued",
            "failed",
        ];
        let t = text(&m);
        let mut seen = 0;
        for line in t.lines().filter(|l| l.contains('{')) {
            let labels = &line[line.find('{').unwrap() + 1..line.find('}').unwrap()];
            let (name, value) = labels.split_once('=').unwrap();
            let value = value.trim_matches('"');
            match name {
                "result" => assert!(allowed.contains(&value), "{line}"),
                "app_id" => assert!(super::super::entry::is_uuid(value), "{line}"),
                other => panic!("a label named {other}: {line}"),
            }
            assert!(!labels.contains(','), "one label: {line}");
            seen += 1;
        }
        assert_eq!(seen, 2 + 8 + 1, "{t}");
    }

    #[test]
    fn the_expiry_of_an_app_is_the_seconds_left_and_the_series_goes_with_the_app() {
        let m = Arc::new(TlsMetrics::default());
        m.set_expiry(BTreeMap::from([
            (APP.to_owned(), 1_800_000_000 + 3600),
            (OTHER.to_owned(), 1_800_000_000 - 60),
        ]));
        let at = m.expiry_samples(1_800_000_000);
        let value = |id: &str| {
            at.iter()
                .find(|s| {
                    s.labels
                        == [Label {
                            name: "app_id".into(),
                            value: id.into(),
                        }]
                })
                .map(|s| s.value)
        };
        assert_eq!(value(APP), Some(3600.0));
        assert_eq!(value(OTHER), Some(-60.0), "negative once it has ended");
        assert_eq!(m.expiry_samples(1_800_000_100)[0].value, 3500.0);
        // The app leaves the bundle, or stops serving the certificate.
        m.set_expiry(BTreeMap::from([(APP.to_owned(), 1_800_000_000 + 3600)]));
        assert_eq!(m.expiry_samples(1_800_000_000).len(), 1);
        m.set_expiry(BTreeMap::new());
        assert!(m.expiry_samples(1_800_000_000).is_empty());
        let t = text(&m);
        assert!(
            t.contains("# TYPE wafio_waf_tls_certificate_expiry_seconds gauge\n"),
            "{t}"
        );
        assert!(!t.contains("app_id="), "{t}");
    }
}
