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
    Whole,
}

/// The certificate `served` as far as `app_id`, whose bundle entry is `settings`, is concerned.
pub fn own(app_id: &str, settings: &Settings, served: Option<&Served>) -> Own {
    let wanted = settings.wanted_file(app_id);
    let Some(served) = served.filter(|s| wanted.as_deref() == Some(s.file.as_str())) else {
        return Own::Missing;
    };
    let hosts = &settings.hosts;
    if super::names::covers_all(served.key.cert[0].as_ref(), hosts) {
        Own::Whole
    } else {
        Own::Gaps
    }
}

/// What an app does next about its certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Nothing: the certificate is whole and nobody asked for another.
    Idle,
    /// An order may start. `since` is when it became due, which decides who goes first.
    Due { since: i64 },
    /// An order is held back until `until`, seconds since the epoch.
    Wait { until: i64 },
}

/// The record of the last order when it failed and still counts: it answered the bundle's request
/// id and, for an app with a whole certificate, asked for no host the app has dropped since.
pub fn failed<'a>(
    settings: &Settings,
    record: Option<&'a AppRecord>,
    own: Own,
) -> Option<&'a AppRecord> {
    record.filter(|r| {
        r.request_id == settings.request_id
            && r.failures > 0
            && (own != Own::Whole || r.tried_only(&settings.hosts))
    })
}

/// The plan of an app with the source `acme`. An order is due when the app has no certificate of
/// its own, when a host is not covered by it, or when the bundle asks for one with an id that no
/// order has answered. An order that failed under the current id is tried again, whatever the app
/// is served meanwhile: the certificate it asked for is not there yet (but not once a whole
/// certificate is there and the failed order was for a host the app has dropped). Every case but a
/// new id waits for the next attempt that the failed order set.
pub fn plan(settings: &Settings, record: Option<&AppRecord>, own: Own, now: i64) -> Plan {
    let answered = record.map_or("", |r| r.request_id.as_str());
    if settings.request_id != answered {
        return Plan::Due { since: now };
    }
    if own == Own::Whole && failed(settings, record, own).is_none() {
        return Plan::Idle;
    }
    match record.map_or(0, |r| r.next_attempt_unix) {
        until if until > now => Plan::Wait { until },
        0 => Plan::Due { since: now },
        since => Plan::Due { since },
    }
}

/// When a failed order is tried again, for the status: the time `plan` holds the app back until,
/// or 0 when no attempt is planned. Read with the clock at zero every planned attempt is still
/// ahead, so the status and the worker cannot disagree.
pub fn retry_at(settings: &Settings, record: Option<&AppRecord>, own: Own) -> i64 {
    match plan(settings, record, own, 0) {
        Plan::Wait { until } => until,
        Plan::Due { .. } | Plan::Idle => 0,
    }
}

/// The port of an address in the form the settings keep it (`1.2.3.4:443`, `[::1]:443`).
fn port(address: &str) -> Option<u16> {
    address.rsplit_once(':')?.1.parse().ok()
}

/// The challenge to answer: after a failed order the other one than it used; else the one that
/// last worked; else the one whose port the app listens on (TLS-ALPN-01 for `listen` on 443,
/// HTTP-01 for `redirect_listen` on 80); else TLS-ALPN-01.
pub fn choose(settings: &Settings, record: Option<&AppRecord>) -> Kind {
    if let Some(tried) = record.and_then(|r| Kind::parse(&r.tried)) {
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
    use super::*;
    use crate::tls::entry::Source;

    const NOW: i64 = 1_800_000_000;

    fn settings(listen: &str, redirect: Option<&str>, request_id: &str) -> Settings {
        Settings {
            listen: listen.into(),
            redirect_listen: redirect.map(str::to_owned),
            hosts: vec!["shop.example.com".into()],
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
        assert_eq!(plan(&s, Some(&answered), Own::Whole, NOW), Plan::Idle);
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
        for own in [Own::Missing, Own::Gaps, Own::Whole] {
            assert_eq!(
                plan(&s, Some(&waiting), own, NOW),
                Plan::Due { since: NOW },
                "{own:?}"
            );
        }
        // No record at all answers no id: the first order.
        assert_eq!(plan(&s, None, Own::Missing, NOW), Plan::Due { since: NOW });
        // The id the last order answered is not new.
        assert_eq!(
            plan(&s, Some(&record("r2", 0)), Own::Whole, NOW),
            Plan::Idle
        );
        // No id at all, answered by nothing: not new either.
        let none = settings("0.0.0.0:443", None, "");
        assert_eq!(plan(&none, None, Own::Whole, NOW), Plan::Idle);
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
        assert_eq!(plan(&s, Some(&failed), Own::Whole, NOW), Plan::Idle);
    }

    #[test]
    fn a_failed_order_under_the_current_id_is_tried_again_while_the_certificate_is_whole() {
        let s = settings("0.0.0.0:443", None, "r2");
        let failed = AppRecord {
            failures: 1,
            ..record("r2", NOW + 600)
        };
        assert_eq!(
            plan(&s, Some(&failed), Own::Whole, NOW),
            Plan::Wait { until: NOW + 600 }
        );
        assert_eq!(
            plan(&s, Some(&failed), Own::Whole, NOW + 700),
            Plan::Due { since: NOW + 600 }
        );
        // The same record with the failures forgotten has nothing to try again.
        assert_eq!(
            plan(&s, Some(&record("r2", 0)), Own::Whole, NOW),
            Plan::Idle
        );
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
            assert_eq!(plan(&s, Some(&dropped), Own::Whole, now), Plan::Idle);
        }
        assert_eq!(retry_at(&s, Some(&dropped), Own::Whole), 0);
        assert!(failed_of(&s, &dropped, Own::Whole).is_none());
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
                plan(&s, Some(&failing(hosts)), Own::Whole, NOW),
                Plan::Wait { until: NOW + 600 },
                "{hosts:?}"
            );
        }
        let more = Settings {
            hosts: vec!["shop.example.com".into(), "blog.example.com".into()],
            ..s.clone()
        };
        assert_eq!(
            plan(
                &more,
                Some(&failing(&["shop.example.com"])),
                Own::Whole,
                NOW
            ),
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
        for own in [Own::Missing, Own::Gaps, Own::Whole] {
            assert_eq!(retry_at(&s, Some(&failed), own), NOW + 600, "{own:?}");
            assert_eq!(
                plan(&s, Some(&failed), own, NOW),
                Plan::Wait { until: NOW + 600 },
                "{own:?}"
            );
        }
        // Nothing planned: nothing to say.
        assert_eq!(retry_at(&s, Some(&record("r1", 0)), Own::Whole), 0);
        assert_eq!(retry_at(&s, None, Own::Whole), 0);
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
}
