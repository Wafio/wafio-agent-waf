//! The checks of an uploaded certificate, and the care taken with its key while they run.
//!
//! The control plane sends the chain and the key as text and the agent trusts none of it: it
//! decodes both itself, checks them against each other and against the digest the bundle names,
//! and only then writes a file. The file is made from the decoded parts, not from the text that
//! came in, so what lands on disk is one key block and the chain, written the way the reader of
//! the directory expects.
//!
//! Care is taken that the DER of the key and the text of the file are wiped when the work ends,
//! however it ends. It is best effort: the PEM reader keeps the base64 of the key in a buffer that
//! it grows and frees unwiped, the gRPC library keeps its decode buffer, and the TLS library its
//! own copy of the key.

use std::sync::Arc;

use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::{Error as TlsError, InconsistentKeys};
use wafio_control::{AckCode, CertificateInstall};
use wafio_proxy::cert_store::{PairFault, chain_pem, pem_block_len, push_pem_block, sha256_hex};
use zeroize::{Zeroize, Zeroizing};

/// The most the chain text may hold, and the most the key text may.
pub const MAX_CHAIN_PEM: usize = 64 << 10;
pub const MAX_KEY_PEM: usize = 16 << 10;
/// The most certificates a chain may hold.
pub const MAX_CERTIFICATES: usize = 10;

/// Reads a private key into a signing key. A function so a test can put its own in.
pub(crate) type LoadKey = fn(&PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, TlsError>;

/// The signing key of the TLS library the proxy serves with.
pub(crate) fn load_key(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, TlsError> {
    any_supported_type(der)
}

/// The buffers that hold the key while an install runs: the DER as it was decoded, and the text of
/// the file that is written. They are the caller's, so that they are wiped when the install ends
/// by any road, a panic included.
#[derive(Default)]
pub(crate) struct Secrets {
    der: Option<PrivateKeyDer<'static>>,
    file: Vec<u8>,
}

impl Secrets {
    fn wipe(&mut self) {
        if let Some(der) = &mut self.der {
            der.zeroize();
        }
        self.file.zeroize();
    }

    /// What is held: the length of the key's DER (`None` when none was held), the length of the
    /// file text, and the room it has. A buffer that was wiped is empty and keeps its room.
    #[cfg(test)]
    pub(crate) fn sizes(&self) -> (Option<usize>, usize, usize) {
        (
            self.der.as_ref().map(|d| d.secret_der().len()),
            self.file.len(),
            self.file.capacity(),
        )
    }
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Wipes `Secrets` when the install function leaves, however it leaves.
struct WipeOnExit<'a>(&'a mut Secrets);

impl Drop for WipeOnExit<'_> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

/// Checks the pair of an install and hands the checked key and the text of the file to `store`.
/// The first check that fails is the answer, and they run in this order: the size of the chain and
/// of the key (`TooLarge`), the PEM blocks of the chain and of the key (`BadPem`), the number of
/// certificates and the length of the chain written again (`TooLarge`), the digest of the leaf
/// (`LeafMismatch`), the key type (`UnsupportedKey`), the key against the leaf (`KeyMismatch`).
/// Sizes come first so that a large input is never parsed. `store` writes the file and switches
/// what is served; its refusal is the install's. Everything that held the key is wiped when this
/// returns or unwinds.
pub(crate) fn verify_and_store(
    install: &CertificateInstall,
    secrets: &mut Secrets,
    load: LoadKey,
    store: impl FnOnce(Arc<CertifiedKey>, &[u8]) -> Result<(), AckCode>,
) -> Result<(), AckCode> {
    let wipe = WipeOnExit(secrets);
    run(install, &mut *wipe.0, load, store)
}

fn run(
    install: &CertificateInstall,
    secrets: &mut Secrets,
    load: LoadKey,
    store: impl FnOnce(Arc<CertifiedKey>, &[u8]) -> Result<(), AckCode>,
) -> Result<(), AckCode> {
    if install.chain_pem.len() > MAX_CHAIN_PEM || install.key_pem.len() > MAX_KEY_PEM {
        return Err(AckCode::TooLarge);
    }
    let chain = chain_of(&install.chain_pem)?;
    secrets.der = Some(key_of(&install.key_pem)?);
    // The chain is written again with lines of 64 characters, which can make it longer than the
    // text it came in. The control plane drops a status whose chain is over the limit, so a chain
    // that would be is refused here.
    if chain.len() > MAX_CERTIFICATES || written_len(&chain) > MAX_CHAIN_PEM {
        return Err(AckCode::TooLarge);
    }
    if sha256_hex(chain[0].as_ref()) != install.leaf_sha256 {
        return Err(AckCode::LeafMismatch);
    }
    let der = secrets.der.as_ref().expect("set above");
    let certified = certify(chain, der, load)?;
    // The DER has done its work once the file text is made from it.
    secrets.file = file_text(der, &certified.cert)?;
    if let Some(der) = &mut secrets.der {
        der.zeroize();
    }
    store(Arc::new(certified), &secrets.file)
}

/// The signing key of `der` with `chain`, checked against the leaf. `CertifiedKey::from_der`
/// would do the same but drops the owned DER unzeroed, so the caller keeps it and wipes it.
fn certify(
    chain: Vec<CertificateDer<'static>>,
    der: &PrivateKeyDer<'_>,
    load: LoadKey,
) -> Result<CertifiedKey, AckCode> {
    let signing = load(der).map_err(|_| AckCode::UnsupportedKey)?;
    let certified = CertifiedKey::new(chain, signing);
    match certified.keys_match() {
        Ok(()) | Err(TlsError::InconsistentKeys(InconsistentKeys::Unknown)) => Ok(certified),
        Err(_) => Err(AckCode::KeyMismatch),
    }
}

/// The pair in a key file of the directory: the key block and the certificates, in any order. It
/// is read as an install is checked, so the DER of the key is decoded once, is held in `secrets`
/// and is wiped when this returns or unwinds; the reader of the proxy decodes the key block twice
/// and drops both copies unwiped.
pub(crate) fn pair_from_file(
    text: &[u8],
    secrets: &mut Secrets,
    load: LoadKey,
) -> Result<CertifiedKey, PairFault> {
    let wipe = WipeOnExit(secrets);
    let secrets = &mut *wipe.0;
    let found = sections(text, b"-----BEGIN EC PARAMETERS-----").map_err(|_| PairFault::NotPem)?;
    let mut chain = Vec::new();
    for (kind, mut der) in found {
        match kind {
            SectionKind::Certificate => chain.push(CertificateDer::from(der.to_vec())),
            SectionKind::PrivateKey | SectionKind::RsaPrivateKey | SectionKind::EcPrivateKey
                if secrets.der.is_none() =>
            {
                secrets.der = PrivateKeyDer::from_pem(kind, std::mem::take(&mut *der));
                if secrets.der.is_none() {
                    return Err(PairFault::NotPem);
                }
            }
            _ => return Err(PairFault::NotPem),
        }
    }
    if chain.is_empty() {
        return Err(PairFault::NoCertificate);
    }
    let der = secrets.der.as_ref().ok_or(PairFault::NoKey)?;
    certify(chain, der, load).map_err(|code| match code {
        AckCode::KeyMismatch => PairFault::KeyMismatch,
        _ => PairFault::KeyUnusable,
    })
}

/// A section of a PEM text: its kind and the DER it holds, which is wiped on drop.
type Section = (SectionKind, Zeroizing<Vec<u8>>);

/// The sections of a PEM text. The reader skips a block of a kind it does not know without a word,
/// which would let a key under a passphrase in the PKCS#8 form pass as no key at all, so every
/// `-----BEGIN ` of the text must have made a section, except those of the `skipped` kind, which
/// the caller is willing to ignore.
fn sections(pem: &[u8], skipped: &[u8]) -> Result<Vec<Section>, AckCode> {
    let mut found = Vec::new();
    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(pem) {
        let (kind, der) = item.map_err(|_| AckCode::BadPem)?;
        found.push((kind, Zeroizing::new(der)));
    }
    if count(pem, b"-----BEGIN ") != found.len() + count(pem, skipped) {
        return Err(AckCode::BadPem);
    }
    Ok(found)
}

fn count(text: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    text.windows(needle.len()).filter(|w| *w == needle).count()
}

/// The certificates of the chain text, leaf first. Only `CERTIFICATE` blocks, and at least one.
fn chain_of(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, AckCode> {
    let found = sections(pem, b"")?;
    if found.is_empty()
        || found
            .iter()
            .any(|(kind, _)| *kind != SectionKind::Certificate)
    {
        return Err(AckCode::BadPem);
    }
    Ok(found
        .into_iter()
        .map(|(_, der)| CertificateDer::from(der.to_vec()))
        .collect())
}

/// The key of the key text: exactly one unencrypted private key block. An `EC PARAMETERS` block
/// beside it, which `openssl ecparam -genkey` writes, only names the curve and is ignored, as the
/// control plane ignores it.
fn key_of(pem: &[u8]) -> Result<PrivateKeyDer<'static>, AckCode> {
    let mut found = sections(pem, b"-----BEGIN EC PARAMETERS-----")?;
    if found.len() != 1 {
        return Err(AckCode::BadPem);
    }
    let (kind, der) = &mut found[0];
    if !matches!(
        kind,
        SectionKind::PrivateKey | SectionKind::RsaPrivateKey | SectionKind::EcPrivateKey
    ) {
        return Err(AckCode::BadPem);
    }
    PrivateKeyDer::from_pem(*kind, std::mem::take(&mut **der)).ok_or(AckCode::BadPem)
}

/// The label of the block a key is written under.
fn key_label(der: &PrivateKeyDer<'_>) -> Result<&'static str, AckCode> {
    match der {
        PrivateKeyDer::Pkcs8(_) => Ok("PRIVATE KEY"),
        PrivateKeyDer::Pkcs1(_) => Ok("RSA PRIVATE KEY"),
        PrivateKeyDer::Sec1(_) => Ok("EC PRIVATE KEY"),
        _ => Err(AckCode::UnsupportedKey),
    }
}

/// The length of the text of `chain` written again, as the key file and the status carry it.
fn written_len(chain: &[CertificateDer<'_>]) -> usize {
    chain
        .iter()
        .map(|c| pem_block_len("CERTIFICATE", c.as_ref().len()))
        .sum()
}

/// The text of the key file: the key, then the chain, each written again from its DER. The buffer
/// has its full size from the start, so it never grows and leaves no unwiped copy behind.
fn file_text(der: &PrivateKeyDer<'_>, chain: &[CertificateDer<'_>]) -> Result<Vec<u8>, AckCode> {
    let label = key_label(der)?;
    let mut text =
        Vec::with_capacity(pem_block_len(label, der.secret_der().len()) + written_len(chain));
    push_pem_block(label, der.secret_der(), &mut text);
    text.extend_from_slice(&chain_pem(chain));
    debug_assert_eq!(text.capacity(), text.len());
    Ok(text)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::path::Path;
    use std::process::Command;
    use std::sync::OnceLock;

    use super::*;
    use crate::tls::dir::tests::Scratch;
    use crate::tls::entry::tests::XorShift;
    use wafio_proxy::cert_store::{certified_key_from_pem, leaf_sha256};

    pub(crate) const APP: &str = "0b7a3f0e-3c47-4a45-9d61-2a1f5f0c8e11";
    pub(crate) const CERT: &str = "5d0c1e52-8f5b-4c0e-bd0a-6a3a1e2f9b77";

    fn openssl(args: &[&str]) -> Vec<u8> {
        let out = Command::new("openssl")
            .args(args)
            .output()
            .expect("openssl is installed");
        assert!(
            out.status.success(),
            "openssl {} failed: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    /// A self-signed certificate and its key as the tool wrote them, and the digest of the leaf.
    #[derive(Clone)]
    pub(crate) struct Made {
        pub key: Vec<u8>,
        pub cert: Vec<u8>,
        pub leaf: String,
    }

    fn make(work: &Path, name: &str, newkey: &[&str]) -> Made {
        let (key, crt) = (
            work.join(format!("{name}.key")),
            work.join(format!("{name}.crt")),
        );
        let (k, c) = (key.to_str().unwrap(), crt.to_str().unwrap());
        openssl(
            &[
                &["req", "-x509", "-newkey"][..],
                newkey,
                &["-nodes", "-days", "2", "-subj", &format!("/CN={name}")],
                &["-keyout", k, "-out", c],
            ]
            .concat(),
        );
        let der = openssl(&["x509", "-in", c, "-outform", "DER"]);
        Made {
            key: std::fs::read(&key).unwrap(),
            cert: std::fs::read(&crt).unwrap(),
            leaf: sha256_hex(&der),
        }
    }

    /// Every kind of key the tests need, made once and kept in memory only.
    pub(crate) struct Fixture {
        pub ec: Made,
        pub other_ec: Made,
        pub rsa: Made,
        pub p521: Made,
        /// The key of `rsa` as PKCS#1, and of `ec` as SEC1.
        pub rsa_pkcs1: Vec<u8>,
        pub ec_sec1: Vec<u8>,
        /// A SEC1 key with its `EC PARAMETERS` block, and the certificate made for it.
        pub ec_with_params: Made,
        /// The key of `rsa` under a passphrase, as PKCS#8 and as PKCS#1 with its headers.
        pub rsa_encrypted_pkcs8: Vec<u8>,
        pub rsa_encrypted_pkcs1: Vec<u8>,
    }

    pub(crate) fn fixture() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| {
            let s = Scratch::new();
            let p256 = ["ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"];
            let (ec, other_ec) = (make(&s.0, "ec", &p256), make(&s.0, "other", &p256));
            let rsa = make(&s.0, "rsa", &["rsa:2048"]);
            let p521 = make(
                &s.0,
                "p521",
                &["ec", "-pkeyopt", "ec_paramgen_curve:secp521r1"],
            );
            let file = |name: &str, bytes: &[u8]| {
                let path = s.0.join(name);
                std::fs::write(&path, bytes).unwrap();
                path.to_str().unwrap().to_owned()
            };
            let (rsa_key, ec_key) = (file("rsa.pem", &rsa.key), file("ec.pem", &ec.key));
            let rsa_pkcs1 = openssl(&["rsa", "-in", &rsa_key, "-traditional"]);
            let ec_sec1 = openssl(&["ec", "-in", &ec_key]);
            let rsa_encrypted_pkcs8 = openssl(&[
                "pkcs8",
                "-topk8",
                "-in",
                &rsa_key,
                "-v2",
                "aes256",
                "-passout",
                "pass:secret",
            ]);
            let rsa_encrypted_pkcs1 = openssl(&[
                "rsa",
                "-in",
                &rsa_key,
                "-traditional",
                "-aes256",
                "-passout",
                "pass:secret",
            ]);
            // `ecparam -genkey` without `-noout` writes the curve block and then the key.
            let with_params = openssl(&["ecparam", "-genkey", "-name", "prime256v1"]);
            let params_key = file("params.pem", &with_params);
            let crt = s.0.join("params.crt");
            openssl(&[
                "req",
                "-x509",
                "-new",
                "-key",
                &params_key,
                "-days",
                "2",
                "-subj",
                "/CN=params",
                "-out",
                crt.to_str().unwrap(),
            ]);
            let der = openssl(&["x509", "-in", crt.to_str().unwrap(), "-outform", "DER"]);
            Fixture {
                ec,
                other_ec,
                rsa,
                p521,
                rsa_pkcs1,
                ec_sec1,
                ec_with_params: Made {
                    key: with_params,
                    cert: std::fs::read(&crt).unwrap(),
                    leaf: sha256_hex(&der),
                },
                rsa_encrypted_pkcs8,
                rsa_encrypted_pkcs1,
            }
        })
    }

    pub(crate) fn install_of(chain: &[u8], key: &[u8], leaf: &str) -> CertificateInstall {
        CertificateInstall {
            command_id: "c1".into(),
            app_id: APP.into(),
            certificate_id: CERT.into(),
            chain_pem: chain.to_vec(),
            key_pem: key.to_vec(),
            leaf_sha256: leaf.into(),
        }
    }

    /// The install of a pair the way the control plane sends it.
    pub(crate) fn install_for(m: &Made) -> CertificateInstall {
        install_of(&m.cert, &m.key, &m.leaf)
    }

    struct Run {
        result: Result<(), AckCode>,
        secrets: Secrets,
        /// The text `store` was given, if it was called.
        stored: Option<Vec<u8>>,
    }

    fn run_with(install: &CertificateInstall, load: LoadKey) -> Run {
        let mut secrets = Secrets::default();
        let mut stored = None;
        let result = verify_and_store(install, &mut secrets, load, |_, text| {
            stored = Some(text.to_vec());
            Ok(())
        });
        Run {
            result,
            secrets,
            stored,
        }
    }

    fn code(install: &CertificateInstall) -> Result<(), AckCode> {
        run_with(install, load_key).result
    }

    /// `n` copies of the certificate text.
    fn repeated(cert: &[u8], n: usize) -> Vec<u8> {
        cert.repeat(n)
    }

    /// `text` with newlines after it up to `len` bytes.
    fn padded(text: &[u8], len: usize) -> Vec<u8> {
        let mut out = text.to_vec();
        out.resize(len, b'\n');
        out
    }

    #[test]
    fn every_kind_of_key_the_control_plane_accepts_is_accepted_and_written_as_one_pair() {
        let f = fixture();
        let cases: [(&str, Vec<u8>, &Made, &str); 5] = [
            ("pkcs8 ecdsa", f.ec.key.clone(), &f.ec, "PRIVATE KEY"),
            ("pkcs8 rsa", f.rsa.key.clone(), &f.rsa, "PRIVATE KEY"),
            ("pkcs1 rsa", f.rsa_pkcs1.clone(), &f.rsa, "RSA PRIVATE KEY"),
            ("sec1 ecdsa", f.ec_sec1.clone(), &f.ec, "EC PRIVATE KEY"),
            (
                "sec1 with its curve block",
                f.ec_with_params.key.clone(),
                &f.ec_with_params,
                "EC PRIVATE KEY",
            ),
        ];
        for (what, key, made, label) in cases {
            let run = run_with(&install_of(&made.cert, &key, &made.leaf), load_key);
            assert_eq!(run.result, Ok(()), "{what}");
            let text = run.stored.expect("the file text goes to the store");
            let shown = String::from_utf8(text.clone()).unwrap();
            // One key block, under the label of its encoding, then the chain; nothing else.
            assert!(
                shown.starts_with(&format!("-----BEGIN {label}-----\n")),
                "{what}"
            );
            assert_eq!(shown.matches("-----BEGIN ").count(), 2, "{what}");
            assert!(!shown.contains("EC PARAMETERS"), "{what}");
            let read = certified_key_from_pem(&text).unwrap();
            assert_eq!(leaf_sha256(&read), made.leaf, "{what}");
        }
    }

    #[test]
    fn the_chain_keeps_its_order_and_a_chain_of_ten_is_the_longest() {
        let f = fixture();
        let chain = [f.ec.cert.clone(), f.other_ec.cert.clone()].concat();
        let run = run_with(&install_of(&chain, &f.ec.key, &f.ec.leaf), load_key);
        assert_eq!(run.result, Ok(()));
        let read = certified_key_from_pem(&run.stored.unwrap()).unwrap();
        assert_eq!(read.cert.len(), 2);
        assert_eq!(sha256_hex(read.cert[1].as_ref()), f.other_ec.leaf);

        for (n, want) in [(10, Ok(())), (11, Err(AckCode::TooLarge))] {
            let long = repeated(&f.ec.cert, n);
            assert_eq!(code(&install_of(&long, &f.ec.key, &f.ec.leaf)), want, "{n}");
        }
        // Text before and between the blocks is not a block.
        let noted = [
            b"Bag Attributes\n  friendlyName: shop\n".to_vec(),
            f.ec.cert.clone(),
        ]
        .concat();
        assert_eq!(code(&install_of(&noted, &f.ec.key, &f.ec.leaf)), Ok(()));
    }

    #[test]
    fn sizes_are_checked_first_and_the_limit_itself_is_allowed() {
        let f = fixture();
        let chain_at = padded(&f.ec.cert, MAX_CHAIN_PEM);
        let key_at = padded(&f.ec.key, MAX_KEY_PEM);
        assert_eq!(code(&install_of(&chain_at, &f.ec.key, &f.ec.leaf)), Ok(()));
        assert_eq!(code(&install_of(&f.ec.cert, &key_at, &f.ec.leaf)), Ok(()));
        let chain_over = padded(&f.ec.cert, MAX_CHAIN_PEM + 1);
        let key_over = padded(&f.ec.key, MAX_KEY_PEM + 1);
        assert_eq!(
            code(&install_of(&chain_over, &f.ec.key, &f.ec.leaf)),
            Err(AckCode::TooLarge)
        );
        assert_eq!(
            code(&install_of(&f.ec.cert, &key_over, &f.ec.leaf)),
            Err(AckCode::TooLarge)
        );
        // Over the limit wins over every check after it, a text that is no PEM at all included.
        let junk = vec![b'x'; MAX_CHAIN_PEM + 1];
        assert_eq!(
            code(&install_of(&junk, b"", "not a digest")),
            Err(AckCode::TooLarge)
        );
    }

    #[test]
    fn a_chain_or_key_that_is_not_one_pair_of_blocks_is_bad_pem() {
        let f = fixture();
        let combined = [f.ec.cert.clone(), f.ec.key.clone()].concat();
        let two_keys = [f.ec.key.clone(), f.rsa.key.clone()].concat();
        let csr = b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n";
        let unknown = b"-----BEGIN FOO-----\nAAAA\n-----END FOO-----\n";
        let cut = &f.ec.cert[..f.ec.cert.len() - 40];
        let not_base64 = b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        let curve_only =
            b"-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n";
        let chains: [(&str, Vec<u8>); 7] = [
            ("empty", Vec::new()),
            ("text", b"a certificate, please".to_vec()),
            ("a key in the chain", combined),
            (
                "a request in the chain",
                [f.ec.cert.clone(), csr.to_vec()].concat(),
            ),
            (
                "a block of a kind nobody knows",
                [f.ec.cert.clone(), unknown.to_vec()].concat(),
            ),
            ("a block cut short", cut.to_vec()),
            ("a block that is not base64", not_base64.to_vec()),
        ];
        for (what, chain) in chains {
            assert_eq!(
                code(&install_of(&chain, &f.ec.key, &f.ec.leaf)),
                Err(AckCode::BadPem),
                "chain: {what}"
            );
        }
        let keys: [(&str, Vec<u8>); 9] = [
            ("empty", Vec::new()),
            ("two keys", two_keys),
            ("a certificate", f.ec.cert.clone()),
            (
                "a key and a certificate",
                [f.ec.key.clone(), f.ec.cert.clone()].concat(),
            ),
            (
                "a passphrase on a PKCS#8 key",
                f.rsa_encrypted_pkcs8.clone(),
            ),
            (
                "a passphrase on a PKCS#1 key",
                f.rsa_encrypted_pkcs1.clone(),
            ),
            ("a key cut short", f.ec.key[..f.ec.key.len() - 30].to_vec()),
            ("the curve block alone", curve_only.to_vec()),
            (
                "a block of a kind nobody knows",
                [f.ec.key.clone(), unknown.to_vec()].concat(),
            ),
        ];
        for (what, key) in keys {
            assert_eq!(
                code(&install_of(&f.ec.cert, &key, &f.ec.leaf)),
                Err(AckCode::BadPem),
                "key: {what}"
            );
        }
    }

    #[test]
    fn the_first_check_that_fails_is_the_answer_in_a_fixed_order() {
        let f = fixture();
        let wrong_leaf = "ab".repeat(32);
        // Over ten certificates, a wrong leaf and a key of another certificate: the count.
        let long = repeated(&f.ec.cert, 11);
        assert_eq!(
            code(&install_of(&long, &f.other_ec.key, &wrong_leaf)),
            Err(AckCode::TooLarge)
        );
        // A block that is not a certificate comes before the count of them.
        let long_and_odd = [long.clone(), f.ec.key.clone()].concat();
        assert_eq!(
            code(&install_of(&long_and_odd, &f.ec.key, &f.ec.leaf)),
            Err(AckCode::BadPem)
        );
        // A wrong leaf comes before a key that cannot sign, and a key that cannot sign before a
        // key that does not belong to the certificate.
        assert_eq!(
            code(&install_of(&f.p521.cert, &f.p521.key, &wrong_leaf)),
            Err(AckCode::LeafMismatch)
        );
        assert_eq!(
            code(&install_of(&f.ec.cert, &f.p521.key, &f.ec.leaf)),
            Err(AckCode::UnsupportedKey)
        );
        assert_eq!(
            code(&install_of(&f.ec.cert, &f.other_ec.key, &f.ec.leaf)),
            Err(AckCode::KeyMismatch)
        );
        assert_eq!(
            code(&install_of(&f.ec.cert, &f.rsa.key, &f.ec.leaf)),
            Err(AckCode::KeyMismatch)
        );
    }

    /// A certificate block with its base64 on one line, as some tools and people write it.
    fn unwrapped_block(der: &[u8]) -> String {
        let mut wrapped = Vec::new();
        push_pem_block("CERTIFICATE", der, &mut wrapped);
        let text = String::from_utf8(wrapped).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let body = lines[1..lines.len() - 1].concat();
        format!("{}\n{body}\n{}\n", lines[0], lines[lines.len() - 1])
    }

    #[test]
    fn a_chain_that_is_over_the_limit_once_written_again_is_too_large() {
        // Ten blocks with no line breaks fit the limit as they come in. Written again with lines
        // of 64 characters they do not, and the control plane drops a status that carries more
        // than the limit, so the install is refused instead of served and never shown.
        let f = fixture();
        let der = vec![0x30u8; 4824];
        let chain_of_n = |n: usize| unwrapped_block(&der).repeat(n);
        let sent = chain_of_n(10);
        let written =
            wafio_proxy::cert_store::chain_pem(&vec![CertificateDer::from(der.clone()); 10]);
        assert!(sent.len() <= MAX_CHAIN_PEM, "{}", sent.len());
        assert!(written.len() > MAX_CHAIN_PEM, "{}", written.len());
        let leaf = sha256_hex(&der);
        assert_eq!(
            code(&install_of(sent.as_bytes(), &f.ec.key, &leaf)),
            Err(AckCode::TooLarge)
        );
        // Nine of them are under the limit both ways: the check goes on to the key, which is not
        // the key of these made-up certificates.
        let nine = chain_of_n(9);
        assert_eq!(
            code(&install_of(nine.as_bytes(), &f.ec.key, &leaf)),
            Err(AckCode::KeyMismatch)
        );
    }

    fn pair(text: &[u8]) -> (Result<CertifiedKey, PairFault>, Secrets) {
        let mut secrets = Secrets::default();
        (pair_from_file(text, &mut secrets, load_key), secrets)
    }

    #[test]
    fn a_key_file_is_read_in_any_order_and_leaves_no_der_of_the_key_behind() {
        let f = fixture();
        let two = [f.ec.cert.clone(), f.other_ec.cert.clone()].concat();
        let cat = |parts: &[&[u8]]| parts.concat();
        let cases: [(&str, Vec<u8>, &str, usize); 8] = [
            (
                "key then chain",
                cat(&[&f.ec.key, &f.ec.cert]),
                &f.ec.leaf,
                1,
            ),
            (
                "chain then key",
                cat(&[&f.ec.cert, &f.ec.key]),
                &f.ec.leaf,
                1,
            ),
            ("pkcs8 rsa", cat(&[&f.rsa.key, &f.rsa.cert]), &f.rsa.leaf, 1),
            (
                "pkcs1 rsa",
                cat(&[&f.rsa_pkcs1, &f.rsa.cert]),
                &f.rsa.leaf,
                1,
            ),
            ("sec1", cat(&[&f.ec_sec1, &f.ec.cert]), &f.ec.leaf, 1),
            (
                "sec1 with its curve block",
                cat(&[&f.ec_with_params.key, &f.ec_with_params.cert]),
                &f.ec_with_params.leaf,
                1,
            ),
            ("two certificates", cat(&[&f.ec.key, &two]), &f.ec.leaf, 2),
            (
                "text around the blocks",
                cat(&[b"Bag Attributes\n", &f.ec.key, b"\n", &f.ec.cert]),
                &f.ec.leaf,
                1,
            ),
        ];
        for (what, text, leaf, certificates) in cases {
            let (got, secrets) = pair(&text);
            let key = got.unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(leaf_sha256(&key), leaf, "{what}");
            assert_eq!(key.cert.len(), certificates, "{what}");
            let proxy_reading = certified_key_from_pem(&text).unwrap();
            assert_eq!(
                leaf_sha256(&proxy_reading),
                leaf,
                "{what}: as the proxy reads it"
            );
            assert_eq!(
                secrets.sizes(),
                (Some(0), 0, 0),
                "{what}: the DER was wiped"
            );
        }

        let csr = b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n";
        let cut = &f.ec.cert[..f.ec.cert.len() - 40];
        let faults: [(&str, Vec<u8>, PairFault); 11] = [
            ("nothing", Vec::new(), PairFault::NoCertificate),
            (
                "text",
                b"a certificate, please".to_vec(),
                PairFault::NoCertificate,
            ),
            ("a key alone", f.ec.key.clone(), PairFault::NoCertificate),
            ("a chain alone", f.ec.cert.clone(), PairFault::NoKey),
            (
                "two keys",
                cat(&[&f.ec.key, &f.rsa.key, &f.ec.cert]),
                PairFault::NotPem,
            ),
            (
                "a key under a passphrase",
                cat(&[&f.rsa_encrypted_pkcs8, &f.rsa.cert]),
                PairFault::NotPem,
            ),
            (
                "a block that is neither",
                cat(&[&f.ec.key, &f.ec.cert, csr]),
                PairFault::NotPem,
            ),
            (
                "a block cut short",
                cat(&[&f.ec.key, cut]),
                PairFault::NotPem,
            ),
            (
                "a key that cannot sign",
                cat(&[&f.p521.key, &f.p521.cert]),
                PairFault::KeyUnusable,
            ),
            (
                "the key of another certificate",
                cat(&[&f.other_ec.key, &f.ec.cert]),
                PairFault::KeyMismatch,
            ),
            (
                "an RSA key under a certificate of ECDSA",
                cat(&[&f.rsa.key, &f.ec.cert]),
                PairFault::KeyMismatch,
            ),
        ];
        for (what, text, fault) in faults {
            let (got, secrets) = pair(&text);
            assert_eq!(got.err(), Some(fault), "{what}");
            let (der, file, _) = secrets.sizes();
            assert_eq!(
                (der.unwrap_or(0), file),
                (0, 0),
                "{what}: the DER was wiped"
            );
        }

        // A panic while the key is read leaves nothing behind either.
        let text = cat(&[&f.ec.key, &f.ec.cert]);
        let mut secrets = Secrets::default();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            pair_from_file(&text, &mut secrets, panicking)
        }));
        assert!(outcome.is_err());
        assert_eq!(secrets.sizes(), (Some(0), 0, 0));
    }

    #[test]
    fn a_digest_that_is_not_the_leafs_is_refused_whatever_its_form() {
        let f = fixture();
        for leaf in [
            "ab".repeat(32),
            f.other_ec.leaf.clone(),
            f.ec.leaf.to_uppercase(),
            String::new(),
            f.ec.leaf[..63].to_owned(),
        ] {
            assert_eq!(
                code(&install_of(&f.ec.cert, &f.ec.key, &leaf)),
                Err(AckCode::LeafMismatch),
                "{leaf}"
            );
        }
    }

    #[test]
    fn a_key_the_tls_library_cannot_sign_with_is_unsupported_not_mismatched() {
        let f = fixture();
        assert_eq!(code(&install_for(&f.p521)), Err(AckCode::UnsupportedKey));
        // Base64 that decodes but is no key at all.
        let nothing = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert_eq!(
            code(&install_of(&f.ec.cert, nothing, &f.ec.leaf)),
            Err(AckCode::UnsupportedKey)
        );
        let swapped = String::from_utf8(f.ec_sec1.clone())
            .unwrap()
            .replace("EC PRIVATE KEY", "PRIVATE KEY");
        assert_eq!(
            code(&install_of(&f.ec.cert, swapped.as_bytes(), &f.ec.leaf)),
            Err(AckCode::UnsupportedKey),
            "a key under the label of another encoding"
        );
    }

    fn panicking(_: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, TlsError> {
        panic!("the check failed");
    }

    #[test]
    fn the_key_buffers_are_wiped_on_success_on_each_error_and_on_a_panic() {
        let f = fixture();
        // The DER is held once the key text is decoded, and the file text is made once the key is
        // checked; what was made is emptied, and what was not made stays unmade.
        struct Case {
            what: &'static str,
            install: CertificateInstall,
            want: Result<(), AckCode>,
            der_held: bool,
            file_made: bool,
        }
        let case = |what, install, want, der_held, file_made| Case {
            what,
            install,
            want,
            der_held,
            file_made,
        };
        let two_keys = [f.ec.key.clone(), f.rsa.key.clone()].concat();
        let cases = [
            case("ok", install_for(&f.ec), Ok(()), true, true),
            case(
                "ok with a PKCS#1 key",
                install_of(&f.rsa.cert, &f.rsa_pkcs1, &f.rsa.leaf),
                Ok(()),
                true,
                true,
            ),
            case(
                "too large",
                install_of(&f.ec.cert, &padded(&f.ec.key, MAX_KEY_PEM + 1), &f.ec.leaf),
                Err(AckCode::TooLarge),
                false,
                false,
            ),
            case(
                "bad key",
                install_of(&f.ec.cert, &f.rsa_encrypted_pkcs8, &f.ec.leaf),
                Err(AckCode::BadPem),
                false,
                false,
            ),
            case(
                "two keys",
                install_of(&f.ec.cert, &two_keys, &f.ec.leaf),
                Err(AckCode::BadPem),
                false,
                false,
            ),
            case(
                "too many certificates",
                install_of(&repeated(&f.ec.cert, 11), &f.ec.key, &f.ec.leaf),
                Err(AckCode::TooLarge),
                true,
                false,
            ),
            case(
                "wrong leaf",
                install_of(&f.ec.cert, &f.ec.key, &"ab".repeat(32)),
                Err(AckCode::LeafMismatch),
                true,
                false,
            ),
            case(
                "unsupported key",
                install_for(&f.p521),
                Err(AckCode::UnsupportedKey),
                true,
                false,
            ),
            case(
                "other key",
                install_of(&f.ec.cert, &f.other_ec.key, &f.ec.leaf),
                Err(AckCode::KeyMismatch),
                true,
                false,
            ),
        ];
        for c in cases {
            let run = run_with(&c.install, load_key);
            assert_eq!(run.result, c.want, "{}", c.what);
            let (der_len, file_len, file_room) = run.secrets.sizes();
            assert_eq!(
                der_len.is_some(),
                c.der_held,
                "{}: the DER was held",
                c.what
            );
            assert_eq!(der_len.unwrap_or(0), 0, "{}: the DER was emptied", c.what);
            assert_eq!(
                (file_len, file_room > 0),
                (0, c.file_made),
                "{}: the file text",
                c.what
            );
        }

        // A store that refuses, and one that panics: the file text and the DER are wiped too.
        for how in ["refuses", "panics"] {
            let mut secrets = Secrets::default();
            let install = install_for(&f.ec);
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                verify_and_store(&install, &mut secrets, load_key, |_, text| {
                    assert!(!text.is_empty());
                    if how == "panics" {
                        panic!("the write failed");
                    }
                    Err(AckCode::WriteFailed)
                })
            }));
            assert_eq!(outcome.is_err(), how == "panics");
            if let Ok(result) = outcome {
                assert_eq!(result, Err(AckCode::WriteFailed));
            }
            let (der_len, file_len, file_room) = secrets.sizes();
            assert_eq!((der_len, file_len), (Some(0), 0), "{how}");
            assert!(file_room > 0, "{how}: a file text was made");
        }

        // A panic in the check itself, after the DER is held and before the file text is made.
        let mut secrets = Secrets::default();
        let install = install_for(&f.ec);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            verify_and_store(&install, &mut secrets, panicking, |_, _| Ok(()))
        }));
        assert!(outcome.is_err());
        assert_eq!(secrets.sizes(), (Some(0), 0, 0));
    }

    #[test]
    fn nothing_of_the_key_is_in_the_file_text_that_the_checks_did_not_decode() {
        // The file is made from the decoded key, so comments and a curve block that came with it
        // are not written.
        let f = fixture();
        let noisy = [
            b"# my key, keep it safe\n".to_vec(),
            f.ec_with_params.key.clone(),
            b"\n\n".to_vec(),
        ]
        .concat();
        let run = run_with(
            &install_of(&f.ec_with_params.cert, &noisy, &f.ec_with_params.leaf),
            load_key,
        );
        assert_eq!(run.result, Ok(()));
        let text = String::from_utf8(run.stored.unwrap()).unwrap();
        assert!(
            !text.contains("my key") && !text.contains("PARAMETERS"),
            "{text}"
        );
    }

    /// Bytes that matter to a PEM reader.
    const PEM_TOKENS: [&[u8]; 14] = [
        b"-----BEGIN ",
        b"-----END ",
        b"-----",
        b"PRIVATE KEY",
        b"CERTIFICATE",
        b"EC PARAMETERS",
        b"ENCRYPTED ",
        b"\n",
        b"\r\n",
        b"=",
        b"Proc-Type: 4,ENCRYPTED\n",
        b" ",
        b"\0",
        b"\xc3\xa9",
    ];

    fn mutate(bytes: &mut Vec<u8>, rng: &mut XorShift) {
        let at = rng.below(bytes.len() + 1);
        match rng.below(7) {
            0 if !bytes.is_empty() => {
                let i = at.min(bytes.len() - 1);
                bytes[i] = rng.next() as u8;
            }
            1 if !bytes.is_empty() => {
                bytes.remove(at.min(bytes.len() - 1));
            }
            2 => bytes.insert(at, rng.next() as u8),
            3 => {
                let token = PEM_TOKENS[rng.below(PEM_TOKENS.len())];
                bytes.splice(at..at, token.iter().copied()).for_each(drop);
            }
            4 if bytes.len() > 2 => bytes.truncate(at.max(1)),
            5 => bytes.extend_from_slice(PEM_TOKENS[rng.below(PEM_TOKENS.len())]),
            _ if !bytes.is_empty() => {
                // A piece of the text again: a block twice, a line twice.
                let (from, len) = (rng.below(bytes.len()), 1 + rng.below(200));
                let piece = bytes[from..(from + len).min(bytes.len())].to_vec();
                bytes.splice(at..at, piece).for_each(drop);
            }
            _ => bytes.push(rng.next() as u8),
        }
    }

    /// Mutated installs for a bounded time. Whatever the checks are given they do not panic, they
    /// refuse with one of the five codes the checks make (the other two are the bundle's and the
    /// disk's), and the buffers that held the key are wiped. An install that passes is a valid pair
    /// by the reading of the proxy, which is another code: the file text reads back with the leaf
    /// that was sent, one key block and at most ten certificates. `WAFIO_INSTALL_FUZZ_SECS` and
    /// `WAFIO_INSTALL_FUZZ_SEED` run a longer session by hand.
    #[test]
    fn install_mutation_fuzz_keeps_the_promises_of_the_checks() {
        let f = fixture();
        let seeds: Vec<CertificateInstall> = vec![
            install_for(&f.ec),
            install_for(&f.rsa),
            install_of(&f.rsa.cert, &f.rsa_pkcs1, &f.rsa.leaf),
            install_of(&f.ec.cert, &f.ec_sec1, &f.ec.leaf),
            install_of(
                &f.ec_with_params.cert,
                &f.ec_with_params.key,
                &f.ec_with_params.leaf,
            ),
            install_of(
                &[f.ec.cert.clone(), f.other_ec.cert.clone()].concat(),
                &f.ec.key,
                &f.ec.leaf,
            ),
            install_for(&f.p521),
            install_of(&repeated(&f.ec.cert, 10), &f.ec.key, &f.ec.leaf),
            install_of(&f.ec.cert, &f.other_ec.key, &f.ec.leaf),
        ];
        let env = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
        let budget = std::time::Duration::from_secs(env("WAFIO_INSTALL_FUZZ_SECS").unwrap_or(3));
        let mut rng = XorShift(env("WAFIO_INSTALL_FUZZ_SEED").unwrap_or(0x5eed_1157_a11c_0042));
        let start = std::time::Instant::now();
        let (mut cases, mut accepted) = (0u64, 0u64);
        let mut by_code = std::collections::BTreeMap::<&str, u64>::new();
        'run: for round in 0.. {
            for seed in &seeds {
                if start.elapsed() > budget {
                    break 'run;
                }
                let mut install = seed.clone();
                if round > 0 {
                    for _ in 0..1 + rng.below(3) {
                        match rng.below(10) {
                            0..=2 => mutate(&mut install.chain_pem, &mut rng),
                            3..=5 => mutate(&mut install.key_pem, &mut rng),
                            6 => {
                                let mut leaf = install.leaf_sha256.clone().into_bytes();
                                mutate(&mut leaf, &mut rng);
                                install.leaf_sha256 = String::from_utf8_lossy(&leaf).into_owned();
                            }
                            // What a reader is meant to put up with: text around the blocks.
                            7 | 8 => {
                                let text = if rng.below(2) == 0 {
                                    &mut install.chain_pem
                                } else {
                                    &mut install.key_pem
                                };
                                let note: &[u8] =
                                    [&b"# a note\n"[..], b"\n\n", b"  "][rng.below(3)];
                                if rng.below(2) == 0 {
                                    text.splice(0..0, note.iter().copied()).for_each(drop);
                                } else {
                                    text.extend_from_slice(note);
                                }
                            }
                            _ => std::mem::swap(&mut install.chain_pem, &mut install.key_pem),
                        }
                    }
                }
                cases += 1;
                let run = catch_unwind(AssertUnwindSafe(|| run_with(&install, load_key)))
                    .unwrap_or_else(|_| panic!("the checks panicked on case {cases}"));
                // The buffers are wiped whatever the outcome.
                let (der, file, _) = run.secrets.sizes();
                assert_eq!((der.unwrap_or(0), file), (0, 0), "case {cases}");
                match run.result {
                    Ok(()) => {
                        accepted += 1;
                        *by_code.entry("ok").or_default() += 1;
                        let text = run.stored.expect("an install that passes is stored");
                        let read = certified_key_from_pem(&text).unwrap_or_else(|e| {
                            panic!("case {cases}: a pair that passed does not read back: {e}")
                        });
                        assert_eq!(leaf_sha256(&read), install.leaf_sha256, "case {cases}");
                        // The agent's own reading of its file agrees, and wipes the key.
                        let (own, secrets) = pair(&text);
                        let own = own.unwrap_or_else(|e| {
                            panic!("case {cases}: the file is not read by the agent: {e}")
                        });
                        assert_eq!(leaf_sha256(&own), install.leaf_sha256, "case {cases}");
                        assert_eq!(secrets.sizes(), (Some(0), 0, 0), "case {cases}");
                        assert!(
                            (1..=MAX_CERTIFICATES).contains(&read.cert.len()),
                            "case {cases}"
                        );
                        let shown = String::from_utf8(text).expect("PEM is text");
                        assert_eq!(
                            shown.matches("PRIVATE KEY-----").count(),
                            2,
                            "case {cases}: one key block"
                        );
                        assert_eq!(
                            shown.matches("-----BEGIN CERTIFICATE-----").count(),
                            read.cert.len(),
                            "case {cases}"
                        );
                        assert!(install.chain_pem.len() <= MAX_CHAIN_PEM, "case {cases}");
                        assert!(install.key_pem.len() <= MAX_KEY_PEM, "case {cases}");
                    }
                    Err(code) => {
                        assert!(
                            matches!(
                                code,
                                AckCode::BadPem
                                    | AckCode::TooLarge
                                    | AckCode::KeyMismatch
                                    | AckCode::LeafMismatch
                                    | AckCode::UnsupportedKey
                            ),
                            "case {cases}: {code:?}"
                        );
                        assert!(run.stored.is_none(), "case {cases}: refused and stored");
                        *by_code.entry(code.as_str()).or_default() += 1;
                    }
                }
            }
        }
        eprintln!("install fuzz: {cases} cases, {accepted} accepted, {by_code:?}");
        assert!(cases > 500, "{cases}");
        assert!(accepted > 50, "{accepted}");
        for code in [
            "bad_pem",
            "too_large",
            "key_mismatch",
            "leaf_mismatch",
            "unsupported_key",
        ] {
            assert!(
                by_code.get(code).copied().unwrap_or(0) > 0,
                "no case reached {code}"
            );
        }
    }
}
