//! The certificate an app with the source `acme` is served until its first one is issued: self
//! signed, for the hosts of the app, from one key made once for the process. A browser warns
//! instead of the handshake failing, which a certificate authority behind a CDN that redirects
//! to HTTPS needs to reach the app at all. It is never written to the key directory.

use std::sync::{Arc, OnceLock};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SigningKey};
use zeroize::Zeroizing;

struct Key {
    pair: KeyPair,
    signing: Arc<dyn SigningKey>,
}

fn key() -> Result<&'static Key, String> {
    static KEY: OnceLock<Result<Key, String>> = OnceLock::new();
    KEY.get_or_init(|| {
        let pair = KeyPair::generate().map_err(|e| e.to_string())?;
        let der = Zeroizing::new(pair.serialize_der());
        let signing = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            der.as_slice(),
        )))
        .map_err(|e| e.to_string())?;
        Ok(Key { pair, signing })
    })
    .as_ref()
    .map_err(Clone::clone)
}

/// A self-signed certificate for `hosts`.
pub fn certificate(hosts: &[String]) -> Result<Arc<CertifiedKey>, String> {
    let key = key()?;
    let mut params = CertificateParams::new(hosts.to_vec()).map_err(|e| e.to_string())?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "placeholder certificate");
    let certificate = params.self_signed(&key.pair).map_err(|e| e.to_string())?;
    Ok(Arc::new(CertifiedKey::new(
        vec![certificate.der().clone()],
        key.signing.clone(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::acme::names::dns_names;

    #[test]
    fn it_names_the_hosts_and_every_certificate_comes_from_the_one_key() {
        let hosts = vec!["a.example.com".to_owned(), "b.example.com".to_owned()];
        let first = certificate(&hosts).unwrap();
        let second = certificate(&hosts[..1]).unwrap();
        assert_eq!(
            dns_names(first.cert[0].as_ref()),
            ["a.example.com", "b.example.com"]
        );
        assert_eq!(dns_names(second.cert[0].as_ref()), ["a.example.com"]);
        assert_eq!(
            first.keys_match(),
            Ok(()),
            "the key signs for the certificate's public key"
        );
        assert!(Arc::ptr_eq(&first.key, &second.key), "one key per process");
    }

    #[test]
    fn a_name_that_is_no_host_name_makes_no_certificate() {
        assert!(certificate(&["not a host name \u{e9}".to_owned()]).is_err());
    }
}
