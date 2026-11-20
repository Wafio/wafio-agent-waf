//! The `tls` object of a bundle app and the checks that decide whether its bundle is refused.
//!
//! The control plane checks the same settings before it stores them (wafio-cp-backend
//! `internal/domain/tls_settings.go`), so what it sends passes here. The checks below follow
//! those, and are never stricter: a name or address that the control plane accepts is accepted
//! here too. Where the agent checks more than the control plane, the field names a file (`app_id`,
//! `certificate_id`) or the control plane does not look at it at all (`leaf_sha256`,
//! `acme_request_id`).

use std::collections::HashSet;
use std::net::IpAddr;

use crate::agent::format_host_port;
use crate::bundle::TlsEntry;

/// The most host names one app serves.
pub const MAX_HOSTS: usize = 100;
/// The longest `acme_request_id`.
const MAX_REQUEST_ID: usize = 128;
/// The HTTPS listener of an app that names none.
const DEFAULT_LISTEN: &str = "0.0.0.0:443";

/// Where the certificate of an app comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// None chosen yet, or one this agent does not know: nothing is served.
    None,
    /// The control plane sends the chain and key in a `CertificateInstall`.
    Uploaded,
    /// The agent orders and renews the certificate itself.
    Acme,
}

/// The certificate the bundle names for an uploaded source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub id: String,
    /// Lower case hex SHA-256 of the DER of its leaf.
    pub leaf_sha256: String,
}

/// The `tls` object of an app that passed the checks, in the form the proxy and the key directory
/// use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// `host:port` of the HTTPS listener, written as the bundle listeners are.
    pub listen: String,
    pub redirect_listen: Option<String>,
    /// Lower case, each once, in the order sent.
    pub hosts: Vec<String>,
    pub source: Source,
    /// Uploaded source with a current certificate only.
    pub certificate: Option<Certificate>,
    /// Acme source only; a new one asks for an order now.
    pub request_id: String,
}

impl Settings {
    /// The file of the key directory the app is to be served from, if the settings name one.
    pub fn wanted_file(&self, app_id: &str) -> Option<String> {
        match self.source {
            Source::Uploaded => self.certificate.as_ref().map(|c| format!("{}.pem", c.id)),
            Source::Acme => Some(format!("acme-{app_id}.pem")),
            Source::None => None,
        }
    }
}

/// The first check an entry failed.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The JSON key.
    pub field: &'static str,
    pub reason: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

fn refuse<T>(field: &'static str, reason: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal {
        field,
        reason: reason.into(),
    })
}

/// Whether `source` is one the control plane can send.
pub fn is_known_source(source: &str) -> bool {
    matches!(source, "" | "acme" | "uploaded")
}

/// Checks the entry of the app `app_id` and puts it in its stored form.
pub fn check(app_id: &str, entry: &TlsEntry) -> Result<Settings, Refusal> {
    // The id names files in the key directory.
    if !is_uuid(app_id) {
        return refuse("app_id", "must be a lower-case UUID");
    }
    let hosts = check_hosts(&entry.hosts)?;
    let listen = match entry.listen.trim() {
        "" => DEFAULT_LISTEN,
        listen => listen,
    };
    let listen = parse_listen("listen", listen)?;
    let redirect = match entry.redirect_listen.trim() {
        "" => None,
        redirect => {
            let redirect = parse_listen("redirect_listen", redirect)?;
            if redirect == listen {
                return refuse("redirect_listen", "must differ from listen");
            }
            if overlap(listen, redirect) {
                return refuse(
                    "redirect_listen",
                    "must not use the port of listen on an address that overlaps it",
                );
            }
            Some(redirect)
        }
    };
    let source = match entry.source.as_str() {
        "acme" => Source::Acme,
        "uploaded" => Source::Uploaded,
        _ => Source::None,
    };
    let mut settings = Settings {
        listen: show(listen),
        redirect_listen: redirect.map(show),
        hosts,
        source,
        certificate: None,
        request_id: String::new(),
    };
    match source {
        Source::Uploaded => settings.certificate = check_certificate(entry)?,
        Source::Acme => {
            let id = &entry.acme_request_id;
            if id.len() > MAX_REQUEST_ID || !id.bytes().all(|b| (b' '..=b'~').contains(&b)) {
                return refuse(
                    "acme_request_id",
                    "must be at most 128 printable ASCII characters",
                );
            }
            settings.request_id = id.clone();
        }
        Source::None => {}
    }
    Ok(settings)
}

/// The certificate of an uploaded source: its id and its leaf, both or neither.
fn check_certificate(entry: &TlsEntry) -> Result<Option<Certificate>, Refusal> {
    let (id, leaf) = (&entry.certificate_id, &entry.leaf_sha256);
    match (id.is_empty(), leaf.is_empty()) {
        (true, true) => return Ok(None),
        (true, false) => return refuse("certificate_id", "is required with leaf_sha256"),
        (false, true) => return refuse("leaf_sha256", "is required with certificate_id"),
        (false, false) => {}
    }
    if !is_uuid(id) {
        return refuse("certificate_id", "must be a lower-case UUID");
    }
    if leaf.len() != 64 || !leaf.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return refuse("leaf_sha256", "must be 64 lower-case hex digits");
    }
    Ok(Some(Certificate {
        id: id.clone(),
        leaf_sha256: leaf.clone(),
    }))
}

/// Lower case 8-4-4-4-12 hex: the form Postgres writes and the files are named by.
pub(crate) fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => matches!(b, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// What the control plane does to the names it stores: trimmed, lower case, each once (the first
/// kept); then each is checked. At least one, at most `MAX_HOSTS`.
fn check_hosts(sent: &[String]) -> Result<Vec<String>, Refusal> {
    let mut hosts = Vec::new();
    let mut seen = HashSet::new();
    for h in sent {
        // One lower-case letter per letter, as Go's per-rune mapping (U+0130 becomes a plain i).
        let h: String = h
            .trim()
            .chars()
            .map(|c| c.to_lowercase().next().unwrap_or(c))
            .collect();
        if !seen.insert(h.clone()) {
            continue;
        }
        if let Some(why) = host_fault(&h) {
            return refuse("hosts", format!("{:?} {why}", shorten(&h)));
        }
        hosts.push(h);
    }
    if hosts.len() > MAX_HOSTS {
        return refuse("hosts", format!("at most {MAX_HOSTS} hosts"));
    }
    if hosts.is_empty() {
        return refuse("hosts", "at least one host is required");
    }
    Ok(hosts)
}

/// The start of a value that goes into a log line.
fn shorten(h: &str) -> String {
    h.chars().take(64).collect()
}

/// Why `h` is not a host name the agent serves. The agent matches the name of the handshake and
/// the `Host` header exactly, so only plain lower-case DNS names pass.
fn host_fault(h: &str) -> Option<&'static str> {
    if h.is_empty() {
        return Some("is empty");
    }
    if h.len() > 253 {
        return Some("is longer than 253 bytes");
    }
    if h.contains('*') {
        return Some("must not contain a wildcard");
    }
    if h.contains(':') {
        return Some("must not contain a port or be an IPv6 address");
    }
    if h.ends_with('.') {
        return Some("must not end with a dot");
    }
    if h.parse::<IpAddr>().is_ok() {
        return Some("must be a DNS name, not an IP address");
    }
    if !h.contains('.') {
        return Some("must contain at least one dot");
    }
    let labels: Vec<&str> = h.split('.').collect();
    // A browser reads a name like 10.1.1 as an address.
    let last = labels[labels.len() - 1];
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        return Some("must not end with a label of digits only");
    }
    for label in labels {
        if label.is_empty() {
            return Some("has an empty label");
        }
        if label.len() > 63 {
            return Some("has a label longer than 63 bytes");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Some("has a label that starts or ends with a hyphen");
        }
        if !label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        {
            return Some(
                "must use only letters, digits, hyphens and dots (write an international name in its xn-- form)",
            );
        }
    }
    None
}

/// `ip:port` or `[ipv6]:port` with a port from 1 to 65535, as Go's `netip.ParseAddrPort` reads it
/// (an address without a zone).
fn parse_listen(field: &'static str, text: &str) -> Result<(IpAddr, u16), Refusal> {
    let fault = || {
        refuse(
            field,
            "must be ip:port or [ipv6]:port with a port from 1 to 65535",
        )
    };
    let Some((host, port)) = text.rsplit_once(':') else {
        return fault();
    };
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return fault();
    }
    let (host, bracketed) = match host.strip_prefix('[') {
        Some(inner) => match inner.strip_suffix(']') {
            Some(inner) => (inner, true),
            None => return fault(),
        },
        None => (host, false),
    };
    let (Ok(ip), Ok(port)) = (host.parse::<IpAddr>(), port.parse::<u16>()) else {
        return fault();
    };
    // Square brackets are for IPv6 addresses only, and an IPv6 address needs them.
    if bracketed != ip.is_ipv6() || port == 0 {
        return fault();
    }
    Ok((ip, port))
}

fn show((ip, port): (IpAddr, u16)) -> String {
    format_host_port(&ip.to_string(), i64::from(port))
}

/// Two different addresses that cannot both be bound: the same port, one of them a wildcard that
/// takes the other (`0.0.0.0` takes every IPv4 address, `::` every address).
fn overlap(a: (IpAddr, u16), b: (IpAddr, u16)) -> bool {
    let takes = |wildcard: IpAddr, other: IpAddr| match wildcard {
        IpAddr::V6(v6) if v6.is_unspecified() => true,
        IpAddr::V4(v4) if v4.is_unspecified() => other.is_ipv4(),
        _ => false,
    };
    a != b && a.1 == b.1 && (takes(a.0, b.0) || takes(b.0, a.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11";
    const CERT: &str = "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77";

    fn leaf() -> String {
        "ab".repeat(32)
    }

    /// An uploaded entry that passes, which each case changes.
    fn entry() -> TlsEntry {
        TlsEntry {
            listen: "0.0.0.0:443".into(),
            hosts: vec!["shop.example.com".into()],
            source: "uploaded".into(),
            certificate_id: CERT.into(),
            leaf_sha256: leaf(),
            ..TlsEntry::default()
        }
    }

    fn with(change: impl FnOnce(&mut TlsEntry)) -> TlsEntry {
        let mut e = entry();
        change(&mut e);
        e
    }

    fn hosts(h: &[&str]) -> TlsEntry {
        with(|e| e.hosts = h.iter().map(|h| (*h).to_owned()).collect())
    }

    /// One table for the checks of the control plane's `TestTLSSettingsNormalize` and
    /// `TestTLSSettingsNormalizeRefuses`: the field a refusal names, or `None` for an entry that
    /// passes. The few things the control plane refuses that the agent does not are in
    /// `what_the_agent_leaves_to_the_control_plane`.
    fn cases() -> Vec<(&'static str, TlsEntry, Option<&'static str>)> {
        let label63 = "a".repeat(63);
        let name253 = format!("{label63}.{label63}.{label63}.{}.de", "b".repeat(58));
        let name254 = format!("{label63}.{label63}.{label63}.{}.de", "b".repeat(59));
        let long_label = format!("{label63}.example.com");
        let label64 = format!("{}.example.com", "a".repeat(64));
        let many: Vec<String> = (0..=MAX_HOSTS)
            .map(|i| format!("h{i}.example.com"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        vec![
            ("a gateway with an upload", entry(), None),
            (
                "a gateway with acme",
                with(|e| {
                    e.source = "acme".into();
                    e.certificate_id.clear();
                    e.leaf_sha256.clear();
                    e.acme_request_id = "6f1c0c64-4f7e-4a06-8cf3-0b7c2a6d1e90".into();
                }),
                None,
            ),
            ("no listener named", with(|e| e.listen.clear()), None),
            (
                "names trimmed, lower-cased and kept once",
                hosts(&[" Shop.Example.COM ", "www.example.com", "shop.example.com"]),
                None,
            ),
            (
                "an IPv6 listener and redirect",
                with(|e| {
                    e.listen = "[2001:0db8::0001]:8443".into();
                    e.redirect_listen = " [::]:80 ".into();
                }),
                None,
            ),
            (
                "a redirect listener",
                with(|e| {
                    e.listen = "10.0.0.5:443".into();
                    e.redirect_listen = "10.0.0.5:80".into();
                }),
                None,
            ),
            (
                "labels of 63 bytes and a name of 253",
                hosts(&[long_label.as_str(), name253.as_str()]),
                None,
            ),
            (
                "digits and hyphens",
                hosts(&["123.my-shop-2.example.com", "xn--mnchen-3ya.de"]),
                None,
            ),
            (
                "a port with leading zeros",
                with(|e| e.listen = "0.0.0.0:00443".into()),
                None,
            ),
            (
                "a 4in6 listener",
                with(|e| e.listen = "[::ffff:10.0.0.5]:443".into()),
                None,
            ),
            (
                "a redirect on another port of a wildcard",
                with(|e| e.redirect_listen = "0.0.0.0:80".into()),
                None,
            ),
            (
                "the same port on another address",
                with(|e| {
                    e.listen = "10.0.0.5:443".into();
                    e.redirect_listen = "10.0.0.6:443".into();
                }),
                None,
            ),
            (
                "a wildcard of the other family is no overlap",
                with(|e| {
                    e.listen = "0.0.0.0:443".into();
                    e.redirect_listen = "[2001:db8::1]:443".into();
                }),
                None,
            ),
            ("100 hosts", hosts(&many[..MAX_HOSTS]), None),
            (
                "duplicates do not count",
                with(|e| {
                    e.hosts = many[..MAX_HOSTS]
                        .iter()
                        .chain(&many[..3])
                        .map(|h| (*h).to_owned())
                        .collect()
                }),
                None,
            ),
            ("no hosts", hosts(&[]), Some("hosts")),
            ("blank hosts", hosts(&[" "]), Some("hosts")),
            ("too many hosts", hosts(&many), Some("hosts")),
            ("a wildcard", hosts(&["*.example.com"]), Some("hosts")),
            ("an IP literal", hosts(&["203.0.113.7"]), Some("hosts")),
            ("an IPv6 literal", hosts(&["2001:db8::1"]), Some("hosts")),
            ("a bracketed IPv6", hosts(&["[2001:db8::1]"]), Some("hosts")),
            ("a port", hosts(&["a.example.com:443"]), Some("hosts")),
            ("a trailing dot", hosts(&["a.example.com."]), Some("hosts")),
            ("no dot", hosts(&["localhost"]), Some("hosts")),
            ("an empty label", hosts(&["a..example.com"]), Some("hosts")),
            ("a leading dot", hosts(&[".example.com"]), Some("hosts")),
            (
                "a label of 64 bytes",
                hosts(&[label64.as_str()]),
                Some("hosts"),
            ),
            (
                "a name of 254 bytes",
                hosts(&[name254.as_str()]),
                Some("hosts"),
            ),
            (
                "a leading hyphen",
                hosts(&["-a.example.com"]),
                Some("hosts"),
            ),
            (
                "a trailing hyphen",
                hosts(&["a-.example.com"]),
                Some("hosts"),
            ),
            ("an underscore", hosts(&["a_b.example.com"]), Some("hosts")),
            ("unicode", hosts(&["münchen.de"]), Some("hosts")),
            ("a space inside", hosts(&["a b.example.com"]), Some("hosts")),
            ("a URL", hosts(&["https://a.example.com"]), Some("hosts")),
            ("a path", hosts(&["a.example.com/x"]), Some("hosts")),
            (
                "a newline",
                hosts(&["a.example.com\nb.example.com"]),
                Some("hosts"),
            ),
            ("a last label of digits", hosts(&["10.1.1"]), Some("hosts")),
            (
                "a good name after a bad one",
                hosts(&["a b.example.com", "ok.example.com"]),
                Some("hosts"),
            ),
            (
                "a listener without a port",
                with(|e| e.listen = "0.0.0.0".into()),
                Some("listen"),
            ),
            (
                "a listener with a name",
                with(|e| e.listen = "localhost:443".into()),
                Some("listen"),
            ),
            (
                "a listener without a host",
                with(|e| e.listen = ":443".into()),
                Some("listen"),
            ),
            (
                "port 0",
                with(|e| e.listen = "0.0.0.0:0".into()),
                Some("listen"),
            ),
            (
                "port 65536",
                with(|e| e.listen = "0.0.0.0:65536".into()),
                Some("listen"),
            ),
            (
                "a signed port",
                with(|e| e.listen = "0.0.0.0:+443".into()),
                Some("listen"),
            ),
            (
                "an IPv6 listener without brackets",
                with(|e| e.listen = "::1:443".into()),
                Some("listen"),
            ),
            (
                "an IPv4 listener in brackets",
                with(|e| e.listen = "[10.0.0.5]:443".into()),
                Some("listen"),
            ),
            (
                "a missing closing bracket",
                with(|e| e.listen = "[::1:443".into()),
                Some("listen"),
            ),
            (
                "a listener with a zone",
                with(|e| e.listen = "[fe80::1%eth0]:443".into()),
                Some("listen"),
            ),
            (
                "an address with a leading zero",
                with(|e| e.listen = "010.0.0.5:443".into()),
                Some("listen"),
            ),
            (
                "a redirect equal to listen",
                with(|e| e.redirect_listen = "0.0.0.0:443".into()),
                Some("redirect_listen"),
            ),
            (
                "a redirect equal to a spelled-out listen",
                with(|e| {
                    e.listen = "[::1]:443".into();
                    e.redirect_listen = "[0:0:0:0:0:0:0:1]:443".into();
                }),
                Some("redirect_listen"),
            ),
            (
                "a redirect without a port",
                with(|e| e.redirect_listen = "0.0.0.0".into()),
                Some("redirect_listen"),
            ),
            (
                "a redirect that the wildcard of listen takes",
                with(|e| {
                    e.listen = "0.0.0.0:443".into();
                    e.redirect_listen = "10.0.0.5:443".into();
                }),
                Some("redirect_listen"),
            ),
            (
                "a redirect that takes the listener",
                with(|e| {
                    e.listen = "10.0.0.5:443".into();
                    e.redirect_listen = "[::]:443".into();
                }),
                Some("redirect_listen"),
            ),
        ]
    }

    #[test]
    fn every_entry_check_follows_the_control_plane() {
        for (what, e, field) in cases() {
            match (check(APP, &e), field) {
                (Ok(_), None) => {}
                (Err(r), Some(field)) => assert_eq!(r.field, field, "{what}: {r}"),
                (got, want) => panic!("{what}: got {got:?}, wanted a refusal of {want:?}"),
            }
        }
    }

    #[test]
    fn what_a_good_entry_becomes() {
        let s = check(
            APP,
            &with(|e| {
                e.listen = "[2001:0db8::0001]:8443".into();
                e.redirect_listen = " [::]:80 ".into();
                e.hosts = vec![
                    " Shop.Example.COM ".into(),
                    "www.example.com".into(),
                    "shop.example.com".into(),
                ];
            }),
        )
        .unwrap();
        assert_eq!(s.listen, "[2001:db8::1]:8443");
        assert_eq!(s.redirect_listen.as_deref(), Some("[::]:80"));
        assert_eq!(s.hosts, ["shop.example.com", "www.example.com"]);
        assert_eq!(s.source, Source::Uploaded);
        assert_eq!(
            s.certificate,
            Some(Certificate {
                id: CERT.into(),
                leaf_sha256: leaf()
            })
        );
        assert_eq!(
            s.wanted_file(APP).as_deref(),
            Some(format!("{CERT}.pem").as_str())
        );

        let default = check(APP, &with(|e| e.listen.clear())).unwrap();
        assert_eq!(default.listen, "0.0.0.0:443");
        assert_eq!(default.redirect_listen, None);
        // 0.0.0.0 with a port written with zeros is the same listener as without.
        let zeros = check(APP, &with(|e| e.listen = "0.0.0.0:00443".into())).unwrap();
        assert_eq!(zeros.listen, default.listen);
    }

    #[test]
    fn the_app_id_names_files_so_only_a_canonical_uuid_passes() {
        for id in [
            "",
            "shop",
            "0B7A3F0E-3C47-4A45-9D61-2A1F5F0C8E11",
            "0b7a3f0e3c474a459d612a1f5f0c8e11",
            "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e1",
            "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11a",
            "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e1g",
            "../7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11",
            "{0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11}",
        ] {
            assert_eq!(check(id, &entry()).unwrap_err().field, "app_id", "{id:?}");
        }
        assert!(check(APP, &entry()).is_ok());
    }

    #[test]
    fn the_certificate_of_an_upload_is_named_by_both_its_id_and_its_leaf_or_by_neither() {
        let neither = with(|e| {
            e.certificate_id.clear();
            e.leaf_sha256.clear();
        });
        let s = check(APP, &neither).unwrap();
        let wanted = s.wanted_file(APP);
        assert_eq!(
            (s.source, s.certificate, wanted),
            (Source::Uploaded, None, None)
        );

        let cases = [
            (
                "only the id",
                with(|e| e.leaf_sha256.clear()),
                "leaf_sha256",
            ),
            (
                "only the leaf",
                with(|e| e.certificate_id.clear()),
                "certificate_id",
            ),
            (
                "an id in capitals",
                with(|e| e.certificate_id = CERT.to_uppercase()),
                "certificate_id",
            ),
            (
                "an id that is a path",
                with(|e| e.certificate_id = "../../etc/passwd".into()),
                "certificate_id",
            ),
            (
                "a short leaf",
                with(|e| e.leaf_sha256 = "ab".repeat(31)),
                "leaf_sha256",
            ),
            (
                "a leaf in capitals",
                with(|e| e.leaf_sha256 = "AB".repeat(32)),
                "leaf_sha256",
            ),
            (
                "a leaf that is no hex",
                with(|e| e.leaf_sha256 = "zz".repeat(32)),
                "leaf_sha256",
            ),
        ];
        for (what, e, field) in cases {
            assert_eq!(check(APP, &e).unwrap_err().field, field, "{what}");
        }
        // The other source does not look at them.
        let acme = with(|e| {
            e.source = "acme".into();
            e.certificate_id = "not an id".into();
        });
        assert_eq!(check(APP, &acme).unwrap().certificate, None);
    }

    #[test]
    fn the_request_id_of_an_order_is_printable_ascii_up_to_128_bytes() {
        let acme = |id: &str| {
            with(|e| {
                e.source = "acme".into();
                e.acme_request_id = id.into();
            })
        };
        let ok = |id: &str| check(APP, &acme(id)).map(|s| (s.wanted_file(APP), s.request_id));
        assert_eq!(
            ok("a request id").unwrap(),
            (Some(format!("acme-{APP}.pem")), "a request id".to_owned())
        );
        assert!(
            ok("").is_ok(),
            "the control plane sends one, and none is not a refusal"
        );
        assert!(ok(&"x".repeat(128)).is_ok());
        let too_long = "x".repeat(129);
        for bad in [too_long.as_str(), "tab\there", "new\nline", "é", "del\x7f"] {
            assert_eq!(ok(bad).unwrap_err().field, "acme_request_id", "{bad:?}");
        }
        // The id of another source is not read.
        let uploaded = with(|e| e.acme_request_id = "é".into());
        assert_eq!(check(APP, &uploaded).unwrap().request_id, "");
    }

    #[test]
    fn what_the_agent_leaves_to_the_control_plane() {
        // No source chosen, or one that is not known: not a refusal, and nothing to serve.
        for source in ["", "manual"] {
            let s = check(APP, &with(|e| e.source = source.into())).unwrap();
            assert_eq!(
                (s.source, s.wanted_file(APP)),
                (Source::None, None),
                "{source:?}"
            );
        }
        assert!(is_known_source("") && is_known_source("acme") && is_known_source("uploaded"));
        assert!(!is_known_source("manual") && !is_known_source("ACME"));
    }

    #[test]
    fn a_refusal_names_the_field_and_cuts_a_long_value() {
        let long = format!("{}é", "a".repeat(300));
        let r = check(APP, &hosts(&[long.as_str()])).unwrap_err();
        assert_eq!(r.field, "hosts");
        assert!(r.to_string().starts_with("hosts: \""), "{r}");
        assert!(r.to_string().len() < 200, "{r}");
    }
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    /// Bytes that matter to the checks: separators, brackets, signs, a path, a control character.
    const TOKENS: [&[u8]; 14] = [
        b"..",
        b"../",
        b":",
        b"[",
        b"]",
        b"*",
        b"-",
        b"%",
        b"\0",
        b"\n",
        b" ",
        b"0",
        b"A",
        b"\xc3\xa9",
    ];

    fn mutate_bytes(b: &mut Vec<u8>, rng: &mut XorShift) {
        let at = rng.below(b.len() + 1);
        match rng.below(6) {
            0 if !b.is_empty() => {
                let i = at.min(b.len() - 1);
                b[i] = rng.next() as u8;
            }
            1 if !b.is_empty() => {
                b.remove(at.min(b.len() - 1));
            }
            2 => b.insert(at, rng.next() as u8),
            3 => {
                let token = TOKENS[rng.below(TOKENS.len())];
                b.splice(at..at, token.iter().copied()).for_each(drop);
            }
            4 if b.len() > 2 => b.truncate(at.max(1)),
            _ if !b.is_empty() => {
                let (from, len) = (rng.below(b.len()), 1 + rng.below(8));
                let piece = b[from..(from + len).min(b.len())].to_vec();
                b.splice(at..at, piece).for_each(drop);
            }
            _ => b.push(rng.next() as u8),
        }
    }

    /// What every entry that passes the checks promises, whatever it was made from.
    fn assert_promises(app_id: &str, s: &Settings) {
        let context = format!("{app_id:?} {s:?}");
        // The ids name files: nothing but a canonical UUID reaches a path.
        assert!(is_uuid(app_id), "{context}");
        if let Some(file) = s.wanted_file(app_id) {
            assert!(
                crate::tls::state_file::is_key_file(&file) && !file.contains('/'),
                "{context}"
            );
        }
        assert!((1..=MAX_HOSTS).contains(&s.hosts.len()), "{context}");
        for h in &s.hosts {
            assert!(
                host_fault(h).is_none() && *h == h.to_ascii_lowercase(),
                "{context}"
            );
        }
        let distinct: HashSet<&String> = s.hosts.iter().collect();
        assert_eq!(distinct.len(), s.hosts.len(), "{context}");
        let listen = s.listen.parse::<std::net::SocketAddr>().expect(&context);
        assert!(listen.port() != 0, "{context}");
        if let Some(r) = &s.redirect_listen {
            let r = r.parse::<std::net::SocketAddr>().expect(&context);
            assert!(r.port() != 0 && r != listen, "{context}");
        }
        if let Some(c) = &s.certificate {
            assert!(is_uuid(&c.id) && c.leaf_sha256.len() == 64, "{context}");
            assert_eq!(s.source, Source::Uploaded, "{context}");
        }
        assert!(s.request_id.len() <= MAX_REQUEST_ID, "{context}");
        assert!(
            s.request_id.bytes().all(|b| (b' '..=b'~').contains(&b)),
            "{context}"
        );
    }

    /// Mutated bundles for a bounded time. Whatever the decoder and the checks are given they do
    /// not panic, a refusal names one of the fields of the object, and an entry that passes keeps
    /// the promises of `assert_promises`. Half of the cases mutate the values of an entry and are
    /// decoded as written; the others mutate the bytes of the document. `WAFIO_ENTRY_FUZZ_SECS`
    /// and `WAFIO_ENTRY_FUZZ_SEED` run a longer session by hand.
    #[test]
    fn entry_decode_fuzz_keeps_the_promises_of_the_checks() {
        let fields = [
            "app_id",
            "listen",
            "hosts",
            "redirect_listen",
            "source",
            "certificate_id",
            "leaf_sha256",
            "acme_request_id",
        ];
        let seeds: Vec<[String; 8]> = vec![
            [
                APP,
                "0.0.0.0:443",
                "shop.example.com",
                "",
                "uploaded",
                CERT,
                leaf().as_str(),
                "",
            ]
            .map(String::from),
            [
                APP,
                "[::]:8443",
                "a.example.com",
                "[::]:80",
                "acme",
                "",
                "",
                "6f1c0c64-4f7e-4a06-8cf3-0b7c2a6d1e90",
            ]
            .map(String::from),
            [
                CERT,
                "10.0.0.5:443",
                "xn--mnchen-3ya.de",
                "10.0.0.5:80",
                "",
                "",
                "",
                "",
            ]
            .map(String::from),
        ];
        let document = |v: &[String; 8]| {
            serde_json::json!({"apps": [{"app_id": v[0], "listen_host": "127.0.0.1", "listen_port": 8080, "tls": {
                "listen": v[1], "hosts": [v[2], v[2].to_uppercase()], "redirect_listen": v[3], "source": v[4],
                "certificate_id": v[5], "leaf_sha256": v[6], "acme_request_id": v[7]}}]})
            .to_string()
            .into_bytes()
        };

        let env = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
        let budget = std::time::Duration::from_secs(env("WAFIO_ENTRY_FUZZ_SECS").unwrap_or(3));
        let mut rng = XorShift(env("WAFIO_ENTRY_FUZZ_SEED").unwrap_or(0x5eed_7a11_cafe_0042));
        let start = std::time::Instant::now();
        let (mut cases, mut decoded, mut accepted) = (0u64, 0u64, 0u64);
        'run: for round in 0.. {
            for seed in &seeds {
                if start.elapsed() > budget {
                    break 'run;
                }
                let mut values = seed.clone();
                let mut raw = Vec::new();
                if round > 0 && rng.below(2) == 0 {
                    for _ in 0..1 + rng.below(3) {
                        let v = &mut values[rng.below(8)];
                        let mut bytes = v.clone().into_bytes();
                        mutate_bytes(&mut bytes, &mut rng);
                        *v = String::from_utf8_lossy(&bytes).into_owned();
                    }
                    raw = document(&values);
                } else if round > 0 {
                    raw = document(&values);
                    for _ in 0..1 + rng.below(4) {
                        mutate_bytes(&mut raw, &mut rng);
                    }
                }
                if raw.is_empty() {
                    raw = document(&values);
                }
                cases += 1;
                let Ok(bundle) = crate::bundle::decode_bundle(&raw) else {
                    continue;
                };
                decoded += 1;
                for app in &bundle.apps {
                    let Some(entry) = &app.tls else { continue };
                    match check(&app.app_id, entry) {
                        Ok(settings) => {
                            accepted += 1;
                            assert_promises(&app.app_id, &settings);
                        }
                        Err(r) => assert!(fields.contains(&r.field), "{r:?}"),
                    }
                }
            }
        }
        eprintln!("entry fuzz: {cases} cases, {decoded} decoded, {accepted} entries accepted");
        assert!(
            cases > 2000 && decoded > 1000 && accepted > 300,
            "{cases} {decoded} {accepted}"
        );
    }
}
