//! When an app orders a certificate, and how it answers the authority's challenge. Both are
//! functions of what `state.json` remembers of the app, its bundle entry and the clock, and
//! nothing else, so every rule can be tested without a network or a timer.

use super::Kind;
use crate::tls::Served;
use crate::tls::entry::Settings;
use crate::tls::state_file::AppRecord;

/// How well the certificate an app keeps for itself (the file of its ordered certificate) serves
/// its hosts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Own {
    /// There is none. An app may be served another certificate meanwhile: one it had before its
    /// source changed, or the placeholder.
    Missing,
    /// There is one, and a host of the bundle entry is not among its names.
    Gaps,
    /// There is one, and it covers every host. `renew_at` is the time a third of its lifetime is
    /// left, in seconds since the epoch, or `i64::MAX` when its dates cannot be read.
    Whole { renew_at: i64 },
}

/// The time a certificate valid from `not_before` to `not_after` has a third of its lifetime left:
/// from then on it is renewed. For 90 days that is 30 days before the end, for 2 minutes 40 seconds.
pub fn renew_at(not_before: i64, not_after: i64) -> i64 {
    not_after.saturating_sub(not_after.saturating_sub(not_before).max(0) / 3)
}

/// The certificate `served` as far as `app_id`, whose bundle entry is `settings`, is concerned.
pub fn own(app_id: &str, settings: &Settings, served: Option<&Served>) -> Own {
    let wanted = settings.wanted_file(app_id);
    let Some(served) = served.filter(|s| wanted.as_deref() == Some(s.file.as_str())) else {
        return Own::Missing;
    };
    let hosts = &settings.hosts;
    let der = served.key.cert[0].as_ref();
    if super::names::covers_all(der, hosts) {
        let renew_at =
            super::names::validity(der).map_or(i64::MAX, |(from, to)| renew_at(from, to));
        Own::Whole { renew_at }
    } else {
        Own::Gaps
    }
}

/// What an app does next about its certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Nothing, now or later.
    Idle,
    /// An order may start. `since` is when it became due, which decides who goes first.
    Due { since: i64 },
    /// An order is held back until `until`, seconds since the epoch: a failed one's backoff, the
    /// authority's wait, or the time the certificate is to be renewed.
    Wait { until: i64 },
}

/// Whether a failed order still says something about the app: not when the certificate is whole
/// and the order asked for a host the app has dropped since, which the app no longer wants.
fn still_asks(settings: &Settings, failed: &AppRecord, own: Own) -> bool {
    !matches!(own, Own::Whole { .. }) || failed.tried_only(&settings.hosts)
}

/// The record of the last order when it failed and still counts: it answered the bundle's request
/// id and, for an app with a whole certificate, asked for no host the app has dropped since.
pub fn failed<'a>(
    settings: &Settings,
    record: Option<&'a AppRecord>,
    own: Own,
) -> Option<&'a AppRecord> {
    record.filter(|r| {
        r.request_id == settings.request_id && r.failures > 0 && still_asks(settings, r, own)
    })
}

/// The record of an order that was refused for the authority's rate limit, while its wait stands
/// under a new request id. The new id lifts the agent's own backoff, not the authority's wait.
pub fn held_by_authority<'a>(
    settings: &Settings,
    record: Option<&'a AppRecord>,
) -> Option<&'a AppRecord> {
    record.filter(|r| r.ca_wait_unix > 0 && r.request_id != settings.request_id)
}

/// Whether the certificate in use was issued by another directory than `directory`, the one the
/// agent orders from now. A record that does not say where the certificate came from is no
/// reason to order again.
fn other_directory(record: Option<&AppRecord>, directory: &str) -> bool {
    !directory.is_empty()
        && record.is_some_and(|r| !r.directory.is_empty() && r.directory != directory)
}

/// The plan of an app with the source `acme`, whose certificates are ordered from `directory`. An
/// order is due when the app has no certificate of its own, when a host is not covered by it, when
/// the bundle asks for one with an id that no order has answered, when the certificate has a third
/// of its lifetime left, and when another directory than `directory` issued it (it is served until
/// the new one replaces it). A certificate that was due when it was kept, or within a minute of
/// it, is no endless reason to order: taking it in noted a failure, whose wait holds the next
/// order back. An order that failed under the current id is tried again, whatever the app is
/// served meanwhile: the certificate it asked for is not there yet (but not once a whole
/// certificate is there and the failed order was for a host the app has dropped). A due order
/// waits for the next attempt that the failed order set, and for the authority's wait. A new id
/// lifts the first and never the second.
pub fn plan(
    settings: &Settings,
    record: Option<&AppRecord>,
    own: Own,
    now: i64,
    directory: &str,
) -> Plan {
    let answered = record.map_or("", |r| r.request_id.as_str());
    let (backoff, due_since) = if settings.request_id != answered {
        (0, 0)
    } else {
        let backoff = record.map_or(0, |r| r.next_attempt_unix);
        match own {
            Own::Missing | Own::Gaps => (backoff, 0),
            Own::Whole { .. } if failed(settings, record, own).is_some() => (backoff, 0),
            Own::Whole { renew_at } if renew_at <= now => (0, renew_at),
            Own::Whole { .. } if other_directory(record, directory) => (0, 0),
            Own::Whole { renew_at: i64::MAX } => return Plan::Idle,
            Own::Whole { renew_at } => return Plan::Wait { until: renew_at },
        }
    };
    let until = backoff.max(record.map_or(0, |r| r.ca_wait_unix));
    if until > now {
        return Plan::Wait { until };
    }
    match until.max(due_since) {
        0 => Plan::Due { since: now },
        since => Plan::Due { since },
    }
}

/// When a failed order is tried again, for the status: the time `plan` holds the app back until,
/// or 0 when no attempt is planned. Read with the clock at zero every planned attempt is still
/// ahead, so the status and the worker cannot disagree.
pub fn retry_at(settings: &Settings, record: Option<&AppRecord>, own: Own) -> i64 {
    match plan(settings, record, own, 0, "") {
        Plan::Wait { until } => until,
        Plan::Due { .. } | Plan::Idle => 0,
    }
}

/// The port of an address in the form the settings keep it (`1.2.3.4:443`, `[::1]:443`).
fn port(address: &str) -> Option<u16> {
    address.rsplit_once(':')?.1.parse().ok()
}

/// The challenge to answer: after a failed order the other one than it used, unless the order was
/// for a host the app has dropped once its certificate is whole, which says nothing of the app as
/// it is now; else the one that last worked; else the one whose port the app listens on
/// (TLS-ALPN-01 for `listen` on 443, HTTP-01 for `redirect_listen` on 80); else TLS-ALPN-01. A new
/// request id does not make the last failure forgotten here: it is a second try at the same thing.
pub fn choose(settings: &Settings, record: Option<&AppRecord>, own: Own) -> Kind {
    let tried = record
        .filter(|r| still_asks(settings, r, own))
        .and_then(|r| Kind::parse(&r.tried));
    if let Some(tried) = tried {
        return tried.other();
    }
    if let Some(worked) = record.and_then(|r| Kind::parse(&r.worked)) {
        return worked;
    }
    if port(&settings.listen) == Some(443) {
        Kind::TlsAlpn01
    } else if settings.redirect_listen.as_deref().and_then(port) == Some(80) {
        Kind::Http01
    } else {
        Kind::TlsAlpn01
    }
}

/// What a failed order says about the port the authority connects to for `kind`, when the app
/// does not serve it. A validation by HTTP-01 may still reach an app that listens on 443 only,
/// through a CDN that sends port 80 to HTTPS, so for such an app the text says so and adds the
/// way out.
pub fn missing_listener(settings: &Settings, kind: Kind) -> Option<&'static str> {
    let https = port(&settings.listen) == Some(443);
    let plain = settings.redirect_listen.as_deref().and_then(port) == Some(80);
    match kind {
        Kind::TlsAlpn01 if !https => Some("this app does not listen on port 443"),
        Kind::Http01 if !plain && !https => Some("this app does not listen on port 80"),
        Kind::Http01 if !plain => Some(
            "this app does not listen on port 80 (a check by HTTP-01 reaches it only through something that sends port 80 to HTTPS; a redirect_listen on port 80 answers it)",
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::tls::acme::mock::dated_pair;
    use crate::tls::entry::Source;
    use wafio_proxy::cert_store::leaf_sha256;

    const NOW: i64 = 1_800_000_000;
    const DIRECTORY: &str = "https://ca.test/directory";
    const APP: &str = "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11";
    /// A certificate that covers every host and is never due for renewal.
    const WHOLE: Own = Own::Whole { renew_at: i64::MAX };

    fn plan(s: &Settings, r: Option<&AppRecord>, own: Own, now: i64) -> Plan {
        super::plan(s, r, own, now, DIRECTORY)
    }

    fn choose(s: &Settings, r: Option<&AppRecord>) -> Kind {
        super::choose(s, r, Own::Missing)
    }

    fn settings(listen: &str, redirect: Option<&str>, request_id: &str) -> Settings {
        Settings {
            listen: listen.into(),
            redirect_listen: redirect.map(str::to_owned),
            hosts: vec!["shop.example.com".into()],
            canonical_host: None,
            source: Source::Acme,
            certificate: None,
            request_id: request_id.into(),
        }
    }

    fn record(request_id: &str, next_attempt_unix: i64) -> AppRecord {
        AppRecord {
            request_id: request_id.into(),
            next_attempt_unix,
            ..AppRecord::default()
        }
    }

    #[test]
    fn an_app_with_no_certificate_orders_at_once_and_one_that_is_whole_does_not() {
        let s = settings("0.0.0.0:443", None, "r1");
        let answered = record("r1", 0);
        assert_eq!(
            plan(&s, Some(&answered), Own::Missing, NOW),
            Plan::Due { since: NOW }
        );
        assert_eq!(plan(&s, Some(&answered), WHOLE, NOW), Plan::Idle);
    }

    #[test]
    fn a_host_the_certificate_does_not_cover_makes_an_order_due() {
        let s = settings("0.0.0.0:443", None, "r1");
        assert_eq!(
            plan(&s, Some(&record("r1", 0)), Own::Gaps, NOW),
            Plan::Due { since: NOW }
        );
    }

    #[test]
    fn a_new_request_id_orders_at_once_past_a_wait_and_with_a_whole_certificate() {
        let s = settings("0.0.0.0:443", None, "r2");
        // The last order failed under r1 and waits for ten more minutes.
        let waiting = record("r1", NOW + 600);
        for own in [Own::Missing, Own::Gaps, WHOLE] {
            assert_eq!(
                plan(&s, Some(&waiting), own, NOW),
                Plan::Due { since: NOW },
                "{own:?}"
            );
        }
        // No record at all answers no id: the first order.
        assert_eq!(plan(&s, None, Own::Missing, NOW), Plan::Due { since: NOW });
        // The id the last order answered is not new.
        assert_eq!(plan(&s, Some(&record("r2", 0)), WHOLE, NOW), Plan::Idle);
        // No id at all, answered by nothing: not new either.
        let none = settings("0.0.0.0:443", None, "");
        assert_eq!(plan(&none, None, WHOLE, NOW), Plan::Idle);
    }

    #[test]
    fn a_failed_order_holds_the_next_one_back_until_its_time_and_it_is_due_since_then() {
        let s = settings("0.0.0.0:443", None, "r1");
        let failed = record("r1", NOW + 600);
        assert_eq!(
            plan(&s, Some(&failed), Own::Missing, NOW),
            Plan::Wait { until: NOW + 600 }
        );
        assert_eq!(
            plan(&s, Some(&failed), Own::Gaps, NOW + 599),
            Plan::Wait { until: NOW + 600 }
        );
        assert_eq!(
            plan(&s, Some(&failed), Own::Missing, NOW + 600),
            Plan::Due { since: NOW + 600 }
        );
        assert_eq!(
            plan(&s, Some(&failed), Own::Missing, NOW + 5000),
            Plan::Due { since: NOW + 600 },
            "it has been due since its time, not since now"
        );
        // A certificate that is whole is not ordered again because an old attempt waits.
        assert_eq!(plan(&s, Some(&failed), WHOLE, NOW), Plan::Idle);
    }

    #[test]
    fn a_failed_order_under_the_current_id_is_tried_again_while_the_certificate_is_whole() {
        let s = settings("0.0.0.0:443", None, "r2");
        let failed = AppRecord {
            failures: 1,
            ..record("r2", NOW + 600)
        };
        assert_eq!(
            plan(&s, Some(&failed), WHOLE, NOW),
            Plan::Wait { until: NOW + 600 }
        );
        assert_eq!(
            plan(&s, Some(&failed), WHOLE, NOW + 700),
            Plan::Due { since: NOW + 600 }
        );
        // The same record with the failures forgotten has nothing to try again.
        assert_eq!(plan(&s, Some(&record("r2", 0)), WHOLE, NOW), Plan::Idle);
    }

    #[test]
    fn a_failed_order_for_a_host_the_app_has_dropped_leaves_a_whole_certificate_alone() {
        let s = settings("0.0.0.0:443", None, "r1");
        let failing = |hosts: &[&str]| AppRecord {
            failures: 1,
            tried_hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
            ..record("r1", NOW + 600)
        };
        let dropped = failing(&["shop.example.com", "www.example.com"]);
        // The certificate covers the hosts the app has now: nothing to order, and no attempt to
        // report, at the time of the attempt or later.
        for now in [NOW, NOW + 700, NOW + 100_000] {
            assert_eq!(plan(&s, Some(&dropped), WHOLE, now), Plan::Idle);
        }
        assert_eq!(retry_at(&s, Some(&dropped), WHOLE), 0);
        assert!(failed_of(&s, &dropped, WHOLE).is_none());
        // A certificate that does not cover them is ordered, and after the wait the failure set:
        // dropping a host and adding it again is no way round it.
        assert_eq!(
            plan(&s, Some(&dropped), Own::Gaps, NOW),
            Plan::Wait { until: NOW + 600 }
        );
        assert_eq!(
            plan(&s, Some(&dropped), Own::Missing, NOW + 700),
            Plan::Due { since: NOW + 600 }
        );
        assert!(failed_of(&s, &dropped, Own::Gaps).is_some());
        // An order for hosts the app still has is tried again, whatever else the app has now.
        for hosts in [&["shop.example.com"][..], &[]] {
            assert_eq!(
                plan(&s, Some(&failing(hosts)), WHOLE, NOW),
                Plan::Wait { until: NOW + 600 },
                "{hosts:?}"
            );
        }
        let more = Settings {
            hosts: vec!["shop.example.com".into(), "blog.example.com".into()],
            ..s.clone()
        };
        assert_eq!(
            plan(&more, Some(&failing(&["shop.example.com"])), WHOLE, NOW),
            Plan::Wait { until: NOW + 600 }
        );
    }

    fn failed_of<'a>(s: &Settings, r: &'a AppRecord, own: Own) -> Option<&'a AppRecord> {
        failed(s, Some(r), own)
    }

    #[test]
    fn the_time_a_status_gives_is_the_time_the_plan_waits_until() {
        let s = settings("0.0.0.0:443", None, "r1");
        let failed = AppRecord {
            failures: 1,
            ..record("r1", NOW + 600)
        };
        for own in [Own::Missing, Own::Gaps, WHOLE] {
            assert_eq!(retry_at(&s, Some(&failed), own), NOW + 600, "{own:?}");
            assert_eq!(
                plan(&s, Some(&failed), own, NOW),
                Plan::Wait { until: NOW + 600 },
                "{own:?}"
            );
        }
        // Nothing planned: nothing to say.
        assert_eq!(retry_at(&s, Some(&record("r1", 0)), WHOLE), 0);
        assert_eq!(retry_at(&s, None, WHOLE), 0);
    }

    #[test]
    fn the_challenge_is_the_one_that_worked_else_the_port_the_app_listens_on_else_tls_alpn() {
        let on_443 = settings("0.0.0.0:443", Some("0.0.0.0:80"), "");
        let only_80 = settings("0.0.0.0:8443", Some("0.0.0.0:80"), "");
        let neither = settings("0.0.0.0:8443", Some("0.0.0.0:8080"), "");
        let ipv6 = settings("[::]:443", Some("[::]:80"), "");
        assert_eq!(choose(&on_443, None), Kind::TlsAlpn01);
        assert_eq!(choose(&ipv6, None), Kind::TlsAlpn01);
        assert_eq!(choose(&only_80, None), Kind::Http01);
        assert_eq!(choose(&neither, None), Kind::TlsAlpn01);
        let worked = |kind: &str| AppRecord {
            worked: kind.into(),
            ..AppRecord::default()
        };
        assert_eq!(choose(&on_443, Some(&worked("http-01"))), Kind::Http01);
        assert_eq!(
            choose(&only_80, Some(&worked("tls-alpn-01"))),
            Kind::TlsAlpn01
        );
        assert_eq!(
            choose(&only_80, Some(&worked("something else"))),
            Kind::Http01,
            "a name that is no challenge is not a record of one"
        );
    }

    #[test]
    fn after_a_failed_order_the_other_challenge_is_tried() {
        let s = settings("0.0.0.0:443", None, "");
        let failed = |tried: &str, worked: &str| AppRecord {
            tried: tried.into(),
            worked: worked.into(),
            failures: 1,
            ..AppRecord::default()
        };
        assert_eq!(choose(&s, Some(&failed("tls-alpn-01", ""))), Kind::Http01);
        assert_eq!(choose(&s, Some(&failed("http-01", ""))), Kind::TlsAlpn01);
        // What worked once does not matter: the other one than the failed one is tried.
        assert_eq!(
            choose(&s, Some(&failed("tls-alpn-01", "tls-alpn-01"))),
            Kind::Http01
        );
        assert_eq!(
            choose(&s, Some(&failed("http-01", "tls-alpn-01"))),
            Kind::TlsAlpn01
        );
    }

    #[test]
    fn a_challenge_whose_port_the_app_does_not_serve_names_it() {
        let on_443 = settings("0.0.0.0:443", None, "");
        let only_80 = settings("0.0.0.0:8443", Some("0.0.0.0:80"), "");
        let neither = settings("0.0.0.0:8443", None, "");
        let both = settings("0.0.0.0:443", Some("0.0.0.0:80"), "");
        assert_eq!(missing_listener(&on_443, Kind::TlsAlpn01), None);
        assert_eq!(missing_listener(&only_80, Kind::Http01), None);
        assert_eq!(missing_listener(&both, Kind::Http01), None);
        assert_eq!(
            missing_listener(&only_80, Kind::TlsAlpn01),
            Some("this app does not listen on port 443")
        );
        assert_eq!(
            missing_listener(&neither, Kind::TlsAlpn01),
            Some("this app does not listen on port 443")
        );
        assert_eq!(
            missing_listener(&neither, Kind::Http01),
            Some("this app does not listen on port 80")
        );
        // A CDN may send port 80 to the HTTPS listener, so the text allows for it and names the way
        // out.
        let cdn = missing_listener(&on_443, Kind::Http01).unwrap();
        assert!(
            cdn.starts_with("this app does not listen on port 80 (")
                && cdn.contains("redirect_listen"),
            "{cdn}"
        );
    }

    #[test]
    fn a_certificate_is_renewed_when_a_third_of_its_lifetime_is_left_and_not_a_second_before() {
        let s = settings("0.0.0.0:443", None, "r1");
        let answered = record("r1", 0);
        for (lifetime, third) in [(90 * 86_400, 30 * 86_400), (120, 40)] {
            let (not_before, not_after) = (NOW - 1000, NOW - 1000 + lifetime);
            let at = renew_at(not_before, not_after);
            assert_eq!(at, not_after - third, "{lifetime}");
            let held = Own::Whole { renew_at: at };
            assert_eq!(
                plan(&s, Some(&answered), held, at - 1),
                Plan::Wait { until: at },
                "{lifetime}: a second before, it is planned for its time"
            );
            assert_eq!(
                plan(&s, Some(&answered), held, at),
                Plan::Due { since: at },
                "{lifetime}"
            );
            assert_eq!(
                plan(&s, Some(&answered), held, at + 1),
                Plan::Due { since: at },
                "{lifetime}: due since its time, not since now"
            );
            // One that has expired is still served and still due.
            assert_eq!(
                plan(&s, Some(&answered), held, not_after + 86_400),
                Plan::Due { since: at },
                "{lifetime}: expired"
            );
        }
        // A lifetime that three does not divide rounds the third down: due once three times what
        // is left is no more than the lifetime.
        assert_eq!(renew_at(0, 100), 67);
        for now in [66, 67] {
            let held = Own::Whole {
                renew_at: renew_at(0, 100),
            };
            let due = matches!(plan(&s, Some(&answered), held, now), Plan::Due { .. });
            assert_eq!(due, (100 - now) * 3 <= 100, "{now}");
        }
        // Dates that are backwards or equal give a certificate that is due at its end, and a
        // certificate whose dates cannot be read is never renewed by date.
        assert_eq!(renew_at(500, 400), 400);
        assert_eq!(renew_at(400, 400), 400);
        assert_eq!(
            plan(&s, Some(&answered), Own::Whole { renew_at: i64::MAX }, NOW),
            Plan::Idle
        );
    }

    #[test]
    fn a_certificate_that_was_due_when_it_was_kept_waits_for_the_failure_it_counted_as() {
        let s = settings("0.0.0.0:443", None, "r1");
        let due = Own::Whole {
            renew_at: NOW - 86_400,
        };
        // With no failure on record a due certificate is ordered at once, due since its time.
        assert_eq!(
            plan(&s, Some(&record("r1", 0)), due, NOW),
            Plan::Due {
                since: NOW - 86_400
            }
        );
        // The failure that taking it in counted holds the next order back, and then it is due
        // since the end of the wait, not since the time the certificate was due.
        let kept = AppRecord {
            failures: 1,
            tried_hosts: s.hosts.clone(),
            ..record("r1", NOW + 600)
        };
        for now in [NOW, NOW + 599] {
            assert_eq!(
                plan(&s, Some(&kept), due, now),
                Plan::Wait { until: NOW + 600 }
            );
        }
        assert_eq!(
            plan(&s, Some(&kept), due, NOW + 600),
            Plan::Due { since: NOW + 600 }
        );
        assert_eq!(retry_at(&s, Some(&kept), due), NOW + 600);
    }

    #[test]
    fn the_dates_of_the_served_certificate_set_when_it_is_renewed() {
        let (_, key) = dated_pair(&["shop.example.com"], (2026, 12, 1), (2027, 3, 1));
        let served = Served {
            file: format!("acme-{APP}.pem"),
            leaf_sha256: leaf_sha256(&key),
            key,
        };
        let s = settings("0.0.0.0:443", None, "r1");
        // 90 days from midnight of 2026-12-01: a third is 30 days.
        assert_eq!(
            own(APP, &s, Some(&served)),
            Own::Whole {
                renew_at: 1_803_859_200 - 30 * 86_400
            }
        );
        let wider = Settings {
            hosts: vec!["shop.example.com".into(), "www.example.com".into()],
            ..s.clone()
        };
        assert_eq!(own(APP, &wider, Some(&served)), Own::Gaps);
        let elsewhere = Served {
            file: format!("{APP}.pem"),
            ..served.clone()
        };
        assert_eq!(own(APP, &s, Some(&elsewhere)), Own::Missing);
        assert_eq!(own(APP, &s, None), Own::Missing);
        let placeholder =
            crate::tls::acme::placeholder::certificate(&["shop.example.com".to_owned()]).unwrap();
        let from_placeholder = Served {
            key: Arc::clone(&placeholder),
            leaf_sha256: leaf_sha256(&placeholder),
            ..served
        };
        let (from, to) = crate::tls::acme::names::validity(placeholder.cert[0].as_ref()).unwrap();
        assert_eq!(
            own(APP, &s, Some(&from_placeholder)),
            Own::Whole {
                renew_at: renew_at(from, to)
            }
        );
    }

    #[test]
    fn a_certificate_from_another_directory_is_ordered_again_while_it_is_served() {
        let s = settings("0.0.0.0:443", None, "r1");
        let issued_by = |directory: &str| AppRecord {
            directory: directory.into(),
            ..record("r1", 0)
        };
        let old = "https://staging.test/directory";
        assert_eq!(
            plan(&s, Some(&issued_by(old)), WHOLE, NOW),
            Plan::Due { since: NOW }
        );
        assert_eq!(
            plan(&s, Some(&issued_by(DIRECTORY)), WHOLE, NOW),
            Plan::Idle
        );
        // A record that does not say where the certificate came from is no reason to order.
        assert_eq!(plan(&s, Some(&record("r1", 0)), WHOLE, NOW), Plan::Idle);
        // The status asks without a directory, and no order is due for it.
        assert_eq!(
            super::plan(&s, Some(&issued_by(old)), WHOLE, NOW, ""),
            Plan::Idle
        );
        // The order for the new directory that failed waits for its time, and is tried again then.
        let failing = AppRecord {
            failures: 1,
            ..AppRecord {
                directory: old.into(),
                ..record("r1", NOW + 600)
            }
        };
        assert_eq!(
            plan(&s, Some(&failing), WHOLE, NOW),
            Plan::Wait { until: NOW + 600 }
        );
        assert_eq!(
            plan(&s, Some(&failing), WHOLE, NOW + 600),
            Plan::Due { since: NOW + 600 }
        );
        // A certificate that is missing is ordered whatever directory the record names.
        assert_eq!(
            plan(&s, Some(&issued_by(old)), Own::Missing, NOW),
            Plan::Due { since: NOW }
        );
    }

    #[test]
    fn a_new_request_id_is_due_at_once_inside_a_backoff_and_waits_inside_the_authoritys_wait() {
        let s = settings("0.0.0.0:443", None, "r2");
        let backoff = AppRecord {
            failures: 3,
            ..record("r1", NOW + 4 * 3600)
        };
        let limited = AppRecord {
            ca_wait_unix: NOW + 7200,
            ..backoff.clone()
        };
        for own in [Own::Missing, Own::Gaps, WHOLE] {
            assert_eq!(
                plan(&s, Some(&backoff), own, NOW),
                Plan::Due { since: NOW },
                "{own:?}: a backoff does not hold a new id"
            );
            assert_eq!(
                plan(&s, Some(&limited), own, NOW),
                Plan::Wait { until: NOW + 7200 },
                "{own:?}: the authority's wait does"
            );
            assert_eq!(
                plan(&s, Some(&limited), own, NOW + 7199),
                Plan::Wait { until: NOW + 7200 },
                "{own:?}"
            );
            assert_eq!(
                plan(&s, Some(&limited), own, NOW + 9000),
                Plan::Due { since: NOW + 7200 },
                "{own:?}: due since the wait ended"
            );
        }
        // What the status says for the new id: failed, with the authority's time.
        assert_eq!(retry_at(&s, Some(&limited), WHOLE), NOW + 7200);
        assert_eq!(retry_at(&s, Some(&backoff), WHOLE), 0);
        assert!(held_by_authority(&s, Some(&limited)).is_some());
        assert!(held_by_authority(&s, Some(&backoff)).is_none());
        let same = settings("0.0.0.0:443", None, "r1");
        assert!(
            held_by_authority(&same, Some(&limited)).is_none(),
            "under its own id the order is a failure like any other"
        );
        // Under its own id both hold, the later one longer.
        assert_eq!(
            plan(&same, Some(&limited), Own::Missing, NOW),
            Plan::Wait {
                until: NOW + 4 * 3600
            }
        );
        let short = AppRecord {
            next_attempt_unix: NOW + 600,
            failures: 1,
            ..limited
        };
        assert_eq!(
            plan(&same, Some(&short), Own::Missing, NOW),
            Plan::Wait { until: NOW + 7200 }
        );
        assert_eq!(retry_at(&same, Some(&short), Own::Missing), NOW + 7200);
    }

    #[test]
    fn a_failure_that_no_longer_counts_does_not_decide_the_challenge() {
        let s = settings("0.0.0.0:443", Some("0.0.0.0:80"), "r1");
        let failing = AppRecord {
            tried: "tls-alpn-01".into(),
            tried_hosts: vec!["shop.example.com".into(), "gone.example.com".into()],
            failures: 1,
            ..record("r1", NOW + 600)
        };
        // The certificate has a gap, or there is none: the failure counts and the other is tried.
        for own in [Own::Missing, Own::Gaps] {
            assert_eq!(
                super::choose(&s, Some(&failing), own),
                Kind::Http01,
                "{own:?}"
            );
        }
        // The certificate is whole and the order was for a host the app dropped since: nothing of
        // it counts, so the port decides, or the one that worked.
        assert_eq!(super::choose(&s, Some(&failing), WHOLE), Kind::TlsAlpn01);
        let worked = AppRecord {
            worked: "http-01".into(),
            ..failing.clone()
        };
        assert_eq!(super::choose(&s, Some(&worked), WHOLE), Kind::Http01);
        // An order for the hosts the app still has counts, a whole certificate or not.
        let still = AppRecord {
            tried_hosts: vec!["shop.example.com".into()],
            ..failing.clone()
        };
        assert_eq!(super::choose(&s, Some(&still), WHOLE), Kind::Http01);
        // A new request id is a second try, and goes on from the failure.
        let new_id = settings("0.0.0.0:443", Some("0.0.0.0:80"), "r2");
        assert_eq!(
            super::choose(&new_id, Some(&still), Own::Missing),
            Kind::Http01
        );
    }
}
