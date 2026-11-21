//! One order: asks the authority for a certificate for the hosts of an app, answers its challenge
//! on the agent's own listeners, and checks what comes back before anything is kept.

use std::sync::Arc;

use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use wafio_proxy::cert_store::{CertBook, ChallengeGuard, pem_block_len, push_pem_block};
use zeroize::Zeroizing;

use super::Kind;
use super::ca::{Account, CaError};
use crate::tls::install::{Secrets, check_and_store, load_key};

/// What one order is for.
#[derive(Clone, Debug)]
pub struct Job {
    pub app_id: String,
    /// The names the certificate is to cover.
    pub hosts: Vec<String>,
    /// The `acme_request_id` of the bundle entry when the order started. A status of the order's
    /// result is sent only while it is still the entry's id.
    pub request_id: String,
    /// The challenge to answer.
    pub kind: Kind,
    /// What a failure says about a port the challenge needs that the app does not serve, if there
    /// is one.
    pub missing_listener: Option<&'static str>,
}

/// A certificate that was checked: the key loads with the chain, and the chain covers every name.
pub struct Issued {
    pub key: Arc<CertifiedKey>,
    /// The text of the key file: the order's key, then the chain.
    pub file: Zeroizing<Vec<u8>>,
}

/// The certificate of a TLS-ALPN-01 validation: self signed, for `host`, with the digest of the key
/// authorization in a critical extension (RFC 8737).
fn alpn_key(host: &str, digest: &[u8; 32]) -> Result<Arc<CertifiedKey>, CaError> {
    let fail = |e: &dyn std::fmt::Display| {
        CaError::new(format!("cannot make the challenge certificate: {e}"))
    };
    let pair =
        Zeroizing::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| fail(&e))?);
    let mut params = CertificateParams::new(vec![host.to_owned()]).map_err(|e| fail(&e))?;
    params.distinguished_name = DistinguishedName::new();
    params.custom_extensions = vec![CustomExtension::new_acme_identifier(digest)];
    let certificate = params.self_signed(&*pair).map_err(|e| fail(&e))?;
    let der = Zeroizing::new(pair.serialize_der());
    let signing = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        der.as_slice(),
    )))
    .map_err(|e| fail(&e))?;
    Ok(Arc::new(CertifiedKey::new(
        vec![certificate.der().clone()],
        signing,
    )))
}

/// A new key for the certificate and the request for it, in DER, and the key as the text of a
/// PKCS#8 PEM block.
fn key_and_request(hosts: &[String]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), CaError> {
    let fail = |e: &dyn std::fmt::Display| CaError::new(format!("cannot make the key: {e}"));
    let pair =
        Zeroizing::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| fail(&e))?);
    let mut params = CertificateParams::new(hosts.to_vec()).map_err(|e| fail(&e))?;
    params.distinguished_name = DistinguishedName::new();
    let request = params.serialize_request(&*pair).map_err(|e| fail(&e))?;
    let der = Zeroizing::new(pair.serialize_der());
    // Room for the whole block from the start, so no growth leaves a copy of the key behind.
    let mut text = Zeroizing::new(Vec::with_capacity(pem_block_len("PRIVATE KEY", der.len())));
    push_pem_block("PRIVATE KEY", &der, &mut text);
    Ok((text, request.der().as_ref().to_vec()))
}

/// Checks what the authority issued against the key it was ordered with and the names it was
/// ordered for, with the checks an installed certificate gets.
fn check(chain: &str, key_pem: &[u8], hosts: &[String]) -> Result<Issued, CaError> {
    let mut issued = None;
    check_and_store(
        chain.as_bytes(),
        key_pem,
        None,
        &mut Secrets::default(),
        load_key,
        |key, file| {
            issued = Some(Issued {
                key,
                file: Zeroizing::new(file.to_vec()),
            });
            Ok(())
        },
    )
    .map_err(|code| {
        CaError::new(format!(
            "the certificate the authority issued cannot be used ({})",
            code.as_str()
        ))
    })?;
    let issued = issued.expect("the check stored the certificate");
    if !super::names::covers_all(issued.key.cert[0].as_ref(), hosts) {
        return Err(CaError::new(
            "the certificate the authority issued does not cover every name of the order",
        ));
    }
    Ok(issued)
}

/// Runs the order of `job` on `account`. The challenge entries it puts up in `book` are taken down
/// when this returns, however it returns, and when it is dropped or unwinds. A name the authority
/// already holds a proof for gets no challenge.
pub async fn execute(
    account: &dyn Account,
    book: &Arc<CertBook>,
    job: &Job,
) -> Result<Issued, CaError> {
    let mut order = account.new_order(&job.hosts).await?;
    let authorizations = order.authorizations().await?;
    // The authority is not trusted with which names to answer for: an authorization for a name
    // that is not the order's would put up an answer for it on the agent's listeners.
    if let Some(foreign) = authorizations
        .iter()
        .find(|a| !job.hosts.iter().any(|h| h.eq_ignore_ascii_case(&a.host)))
    {
        return Err(CaError::new(format!(
            "the authority asks for a proof of {}, which is no name of the order",
            foreign.host
        )));
    }
    let mut up: Vec<ChallengeGuard> = Vec::new();
    let mut answered = Vec::new();
    for authorization in authorizations.iter().filter(|a| !a.valid) {
        if !authorization.offered.contains(&job.kind) {
            return Err(CaError::new(format!(
                "the authority offers no {} challenge for {}",
                job.kind.as_str(),
                authorization.host
            )));
        }
        let host = &authorization.host;
        let answer = order.answer(host, job.kind).await?;
        up.push(match job.kind {
            Kind::TlsAlpn01 => book.offer_tls_alpn(host, alpn_key(host, &answer.digest)?),
            Kind::Http01 => book.offer_http01(host, &answer.token, &answer.key_authorization),
        });
        answered.push(host.clone());
    }
    for host in &answered {
        order.ready(host, job.kind).await?;
    }
    order.wait_ready().await?;
    // The authority has looked; nothing needs the answers any more.
    drop(up);
    let (key, request) = key_and_request(&job.hosts)?;
    order.finalize(&request).await?;
    let chain = order.certificate().await?;
    check(&chain, &key, &job.hosts)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::*;
    use crate::tls::acme::ca::Ca;
    use crate::tls::acme::mock::{Issue, MockCa, Step};
    use wafio_proxy::cert_store::certified_key_from_pem;

    const APP: &str = "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11";
    const SHOP: &str = "shop.example.com";
    const WWW: &str = "www.example.com";

    fn job(kind: Kind) -> Job {
        Job {
            app_id: APP.into(),
            hosts: vec![SHOP.into(), WWW.into()],
            request_id: "r1".into(),
            kind,
            missing_listener: None,
        }
    }

    async fn rig() -> (Arc<CertBook>, MockCa, Arc<dyn Account>) {
        let book = Arc::new(CertBook::default());
        let ca = MockCa::new(book.clone());
        let (account, _) = ca.create_account("https://ca.test/dir").await.unwrap();
        (book, ca, account)
    }

    /// Whether the book answers a validation of `host` by either challenge.
    fn answers(book: &CertBook, host: &str) -> bool {
        book.alpn_challenge(host).is_some()
            || book
                .http01_authorization(host, &format!("token-{host}"))
                .is_some()
    }

    #[tokio::test]
    async fn a_tls_alpn_answer_is_up_for_each_name_while_the_authority_looks_and_gone_after() {
        let (book, ca, account) = rig().await;
        let issued = execute(&*account, &book, &job(Kind::TlsAlpn01))
            .await
            .unwrap();
        {
            let script = ca.script();
            assert_eq!(
                script.up_while_waiting,
                [
                    (SHOP.to_owned(), Kind::TlsAlpn01, true),
                    (WWW.to_owned(), Kind::TlsAlpn01, true)
                ]
            );
            // The certificate of the answer names the host and carries the digest of the key
            // authorization in the critical extension of RFC 8737.
            assert_eq!(script.alpn_certs.len(), 2);
            for (der, host) in script.alpn_certs.iter().zip([SHOP, WWW]) {
                assert_eq!(crate::tls::acme::names::dns_names(der), [host]);
                let (_, cert) = X509Certificate::from_der(der).unwrap();
                let ext = cert
                    .extensions()
                    .iter()
                    .find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
                    .expect("the acmeIdentifier extension");
                assert!(ext.critical);
                assert_eq!(ext.value, [&[0x04, 0x20][..], &[7u8; 32][..]].concat());
            }
            assert_eq!(
                script.events,
                [
                    "new order",
                    "answer shop.example.com tls-alpn-01",
                    "answer www.example.com tls-alpn-01",
                    "ready shop.example.com tls-alpn-01",
                    "ready www.example.com tls-alpn-01",
                    "validated",
                    "finalize"
                ]
            );
        }
        assert!(!answers(&book, SHOP) && !answers(&book, WWW), "taken down");
        assert_eq!(
            crate::tls::acme::names::dns_names(issued.key.cert[0].as_ref()),
            [SHOP, WWW]
        );
    }

    #[tokio::test]
    async fn an_http_answer_is_up_for_each_name_while_the_authority_looks_and_gone_after() {
        let (book, ca, account) = rig().await;
        execute(&*account, &book, &job(Kind::Http01)).await.unwrap();
        assert_eq!(
            ca.script().up_while_waiting,
            [
                (SHOP.to_owned(), Kind::Http01, true),
                (WWW.to_owned(), Kind::Http01, true)
            ]
        );
        assert!(!answers(&book, SHOP) && !answers(&book, WWW), "taken down");
    }

    #[tokio::test]
    async fn a_name_the_authority_holds_a_proof_for_gets_no_challenge() {
        let (book, ca, account) = rig().await;
        ca.script().valid.insert(SHOP.into());
        execute(&*account, &book, &job(Kind::Http01)).await.unwrap();
        {
            let script = ca.script();
            assert_eq!(
                script.events,
                [
                    "new order",
                    "answer www.example.com http-01",
                    "ready www.example.com http-01",
                    "validated",
                    "finalize"
                ]
            );
            assert_eq!(script.up_while_waiting.len(), 1);
        }
        // Every name proven already: the order goes straight to the certificate.
        let (book, ca, account) = rig().await;
        ca.script().valid.extend([SHOP.to_owned(), WWW.to_owned()]);
        execute(&*account, &book, &job(Kind::TlsAlpn01))
            .await
            .unwrap();
        assert_eq!(ca.script().events, ["new order", "validated", "finalize"]);
    }

    #[tokio::test]
    async fn a_challenge_the_authority_does_not_offer_fails_the_order_and_puts_nothing_up() {
        let (book, ca, account) = rig().await;
        ca.script().offered = vec![Kind::Http01];
        let e = execute(&*account, &book, &job(Kind::TlsAlpn01))
            .await
            .err()
            .unwrap();
        assert!(
            e.text.contains("tls-alpn-01") && e.text.contains(SHOP),
            "{e:?}"
        );
        assert!(!answers(&book, SHOP));
        assert_eq!(ca.script().events, ["new order"]);
    }

    #[tokio::test]
    async fn an_authority_that_lists_more_authorizations_than_the_order_has_names_is_refused_at_the_first_extra()
     {
        let (book, ca, account) = rig().await;
        // The two names of the order, then a thousand more.
        ca.script().authorizations_for = Some(
            [SHOP.to_owned(), WWW.to_owned()]
                .into_iter()
                .chain((0..1000).map(|i| format!("extra{i}.example.com")))
                .collect(),
        );
        let e = execute(&*account, &book, &job(Kind::Http01))
            .await
            .err()
            .unwrap();
        assert!(e.text.contains("more authorizations"), "{e:?}");
        let script = ca.script();
        assert_eq!(
            script.fetched, 3,
            "the two names and the first extra, no more"
        );
        assert_eq!(script.events, ["new order"], "nothing is answered");
        drop(script);
        assert!(!answers(&book, SHOP) && !answers(&book, WWW));
    }

    #[tokio::test]
    async fn an_authorization_for_a_name_that_is_not_the_orders_puts_nothing_up() {
        let (book, ca, account) = rig().await;
        ca.script().authorizations_for =
            Some(vec![SHOP.to_owned(), "other.example.com".to_owned()]);
        let e = execute(&*account, &book, &job(Kind::TlsAlpn01))
            .await
            .err()
            .unwrap();
        assert!(e.text.contains("other.example.com"), "{e:?}");
        assert_eq!(ca.script().events, ["new order"], "nothing is answered");
        assert!(!answers(&book, SHOP) && !answers(&book, "other.example.com"));
        // The names of an order are matched without regard to case.
        let (book, ca, account) = rig().await;
        ca.script().authorizations_for = Some(vec!["SHOP.example.com".to_owned(), WWW.to_owned()]);
        execute(&*account, &book, &job(Kind::Http01)).await.unwrap();
        assert_eq!(ca.script().orders.len(), 1);
    }

    #[tokio::test]
    async fn the_challenge_entries_go_when_an_order_fails_at_any_step() {
        for step in [
            Step::Authorizations,
            Step::Answer,
            Step::Ready,
            Step::WaitReady,
            Step::Finalize,
            Step::Certificate,
        ] {
            let (book, ca, account) = rig().await;
            ca.script().fail = Some((step, CaError::new(format!("refused at {step:?}"))));
            let e = execute(&*account, &book, &job(Kind::Http01))
                .await
                .err()
                .unwrap();
            assert_eq!(e.text, format!("refused at {step:?}"));
            assert!(!answers(&book, SHOP) && !answers(&book, WWW), "{step:?}");
            assert_eq!(ca.script().running, 0, "the order is dropped at {step:?}");
        }
    }

    #[tokio::test]
    async fn the_challenge_entries_go_when_an_order_panics() {
        for step in [
            Step::Ready,
            Step::WaitReady,
            Step::Finalize,
            Step::Certificate,
        ] {
            let (book, ca, account) = rig().await;
            ca.script().panic = Some(step);
            let (task_book, task_job) = (book.clone(), job(Kind::TlsAlpn01));
            let joined =
                tokio::spawn(async move { execute(&*account, &task_book, &task_job).await }).await;
            assert!(joined.is_err_and(|e| e.is_panic()), "{step:?}");
            assert!(!answers(&book, SHOP) && !answers(&book, WWW), "{step:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_challenge_entries_go_when_an_order_that_waits_is_given_up() {
        let (book, ca, account) = rig().await;
        ca.script().hang = Some(Step::WaitReady);
        let (task_book, task_job) = (book.clone(), job(Kind::Http01));
        let mut task = tokio::spawn(async move { execute(&*account, &task_book, &task_job).await });
        let given_up = tokio::time::timeout(Duration::from_secs(180), &mut task).await;
        assert!(given_up.is_err(), "the order waits for the authority");
        assert!(
            answers(&book, SHOP) && answers(&book, WWW),
            "up while it waits"
        );
        task.abort();
        let _ = task.await;
        assert!(!answers(&book, SHOP) && !answers(&book, WWW));
    }

    #[tokio::test]
    async fn a_certificate_that_does_not_load_with_the_order_key_or_cover_every_name_is_refused() {
        for (issue, said) in [
            (Issue::OtherKey, "key_mismatch"),
            (Issue::Garbage, "bad_pem"),
            (Issue::FirstNameOnly, "does not cover every name"),
        ] {
            let (book, ca, account) = rig().await;
            ca.script().issue = issue;
            let e = execute(&*account, &book, &job(Kind::Http01))
                .await
                .err()
                .unwrap();
            assert!(e.text.contains(said), "{issue:?}: {e:?}");
            assert!(!answers(&book, SHOP));
        }
    }

    #[tokio::test]
    async fn an_issued_certificate_comes_with_the_text_of_its_file_and_a_new_key_each_time() {
        let (book, _ca, account) = rig().await;
        let first = execute(&*account, &book, &job(Kind::Http01)).await.unwrap();
        let second = execute(&*account, &book, &job(Kind::Http01)).await.unwrap();
        let text = String::from_utf8(first.file.to_vec()).unwrap();
        assert!(text.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{text}");
        assert_eq!(
            text.matches("BEGIN CERTIFICATE").count(),
            2,
            "leaf and root"
        );
        // The file is what the directory reader loads, and holds the leaf the key was made for.
        let loaded = certified_key_from_pem(&first.file).unwrap();
        assert_eq!(
            wafio_proxy::cert_store::leaf_sha256(&loaded),
            wafio_proxy::cert_store::leaf_sha256(&first.key)
        );
        assert_ne!(
            first.file.as_slice()[..80],
            second.file.as_slice()[..80],
            "every order makes its own key"
        );
    }
}
