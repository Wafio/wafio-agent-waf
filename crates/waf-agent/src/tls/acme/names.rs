//! The names a certificate covers and the time it is valid for.

use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

/// The DNS names in the subject alternative names of the certificate `der`, lower case. A
/// certificate that cannot be read names nothing.
pub fn dns_names(der: &[u8]) -> Vec<String> {
    let Ok((_, cert)) = parse_x509_certificate(der) else {
        return Vec::new();
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(dns.to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

/// The time a certificate is valid for, `(not before, not after)` in seconds since the epoch. `None`
/// for one that cannot be read.
pub fn validity(der: &[u8]) -> Option<(i64, i64)> {
    let (_, cert) = parse_x509_certificate(der).ok()?;
    let valid = cert.validity();
    Some((valid.not_before.timestamp(), valid.not_after.timestamp()))
}

/// Whether the certificate name `name` answers for `host`: the same name, or a wildcard in the
/// first label that stands for exactly one label.
fn covers(name: &str, host: &str) -> bool {
    if name == host {
        return true;
    }
    match (name.strip_prefix("*."), host.split_once('.')) {
        (Some(rest), Some((label, tail))) => !label.is_empty() && rest == tail,
        _ => false,
    }
}

/// Whether the certificate `der` covers every one of `hosts` (lower case).
pub fn covers_all(der: &[u8], hosts: &[String]) -> bool {
    let names = dns_names(der);
    hosts
        .iter()
        .all(|host| names.iter().any(|name| covers(name, host)))
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair, date_time_ymd};

    use super::*;

    fn cert(names: &[&str]) -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        let params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn hosts(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn a_certificate_covers_the_names_it_lists_and_a_wildcard_covers_one_label() {
        let der = cert(&[
            "shop.example.com",
            "*.blog.example.com",
            "UPPER.example.com",
        ]);
        assert_eq!(
            dns_names(&der),
            [
                "shop.example.com",
                "*.blog.example.com",
                "upper.example.com"
            ]
        );
        assert!(covers_all(&der, &hosts(&["shop.example.com"])));
        assert!(covers_all(
            &der,
            &hosts(&["shop.example.com", "a.blog.example.com"])
        ));
        assert!(covers_all(&der, &hosts(&["upper.example.com"])));
        assert!(
            covers_all(&der, &[]),
            "no host is covered by any certificate"
        );
        for lacking in [
            hosts(&["shop.example.com", "www.example.com"]),
            hosts(&["blog.example.com"]),
            hosts(&["a.b.blog.example.com"]),
            hosts(&["example.com"]),
        ] {
            assert!(!covers_all(&der, &lacking), "{lacking:?}");
        }
    }

    #[test]
    fn a_certificate_says_when_it_is_valid() {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["shop.example.com".to_owned()]).unwrap();
        params.not_before = date_time_ymd(2026, 12, 1);
        params.not_after = date_time_ymd(2027, 3, 1);
        let der = params.self_signed(&key).unwrap().der().to_vec();
        // Midnight UTC of the first of December 2026 and of March 2027: 90 days.
        assert_eq!(validity(&der), Some((1_796_083_200, 1_803_859_200)));
        assert_eq!(validity(b"not a certificate"), None);
    }

    #[test]
    fn what_is_not_a_certificate_covers_nothing() {
        assert!(dns_names(b"not a certificate").is_empty());
        assert!(!covers_all(b"", &hosts(&["a.example.com"])));
    }
}
