//! The per-agent challenge secret: with an empty `secret_key` the signing key used to
//! be a public constant, so a `_wafio_ch` cookie could be minted offline. Its own test binary with
//! one test: the secret is process-wide.

use wafio_agent_pages::challenge::*;
use wafio_agent_pages::crypto::{hmac_sha256, sha256};

const NOW: i64 = 1_800_000_000;
const ID: &str = "0123456789abcdef";

/// What an attacker computes without any secret: the cookies of the old derivation (2-part and
/// 3-part) under the key every agent derived from the empty `secret_key`.
fn forged_cookies() -> Vec<Vec<u8>> {
    let key = sha256(b"wafio-challenge-v1:");
    let sign = |m: &str| String::from_utf8(sign_message(&key, m.as_bytes())).unwrap();
    vec![
        format!("9999999999:{}", sign("9999999999")).into_bytes(),
        format!("9999999999:{ID}:{}", sign(&format!("9999999999:{ID}:"))).into_bytes(),
    ]
}

#[test]
fn empty_secret_key_is_keyed_by_the_instance_secret() {
    let public = sha256(b"wafio-challenge-v1:");
    // Unset: a random secret for this process, never the public constant, stable once generated.
    let k1 = derive_signing_key("");
    assert_ne!(k1, public, "the public constant is in use");
    assert_eq!(k1, derive_signing_key(""), "unstable");
    for f in forged_cookies() {
        assert!(
            !verify_challenge_cookie("", b"", &f, NOW),
            "forged cookie accepted"
        );
    }

    // Set: HMAC(instance, "wafio-challenge-v1:instance"); a provider secret keeps its derivation.
    let inst: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    set_instance_secret(inst);
    assert_eq!(
        derive_signing_key(""),
        hmac_sha256(&inst, &[b"wafio-challenge-v1:instance"])
    );
    assert_ne!(derive_signing_key(""), public);
    assert_eq!(derive_signing_key("abc"), sha256(b"wafio-challenge-v1:abc"));
    for f in forged_cookies() {
        assert!(
            !verify_challenge_cookie("", b"", &f, NOW),
            "forged cookie accepted"
        );
    }

    let own = issue_challenge_cookie("", b"", NOW);
    assert!(verify_challenge_cookie("", b"", &own, NOW));
    assert!(
        !verify_challenge_cookie("", b"", &own, NOW + 7200),
        "still expires"
    );
    // Tokens follow the same key.
    let t = issue_pow_token("", b"", 12, NOW).unwrap();
    assert!(check_pow_token("", b"", &t, NOW).is_some());
    // Agents sharing a configured secret still accept each other's cookies; the instance cookie is
    // not valid under it.
    assert!(verify_challenge_cookie(
        "abc",
        b"",
        &issue_challenge_cookie("abc", b"", NOW),
        NOW
    ));
    assert!(!verify_challenge_cookie("abc", b"", &own, NOW));

    // A later set replaces the secret: cookies minted before are refused.
    set_instance_secret([9; 32]);
    assert!(!verify_challenge_cookie("", b"", &own, NOW));
}
