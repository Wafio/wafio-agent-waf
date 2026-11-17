//! Redaction tests (secret names, match sources, JSON unescape, depth cap, markers) and the
//! differential that replays every redaction function over a recorded corpus.

use super::*;
use crate::decision_redact_body::{
    BODY_PREVIEW_LIMIT, is_body_copy_complete, redact_stored_body, redact_stored_body_copy,
    unescape_json_string,
};

#[test]
fn is_secret_field_name_lists() {
    let secret = [
        "X-API-Key",
        "x-api-key",
        "X-Auth-Token",
        "X-CSRF-Token",
        "X-XSRF-TOKEN",
        "X-Access-Token",
        "Api-Key",
        "X-Amz-Security-Token",
        "X-Goog-Api-Key",
        "Authorization",
        "Proxy-Authorization",
        "X-Session-Id",
        "X-Refresh-Token",
        "Private-Token",
        "X-Vault-Token",
        "X-Hasura-Admin-Secret",
        "Ocp-Apim-Subscription-Key",
        "X-Functions-Key",
        "X-Hub-Signature-256",
        "Stripe-Signature",
        "X-Shopify-Hmac-Sha256",
        "X-CSRFToken",
        "X-Client-Secret",
        "X-Auth",
        "auth",
        "api_key",
        "apiKey",
        "apikey",
        "token",
        "access_token",
        "accessToken",
        "id_token",
        "refresh_token",
        "password",
        "new_password",
        "passwd",
        "pwd",
        "user_pwd",
        "pass",
        "client_secret",
        "clientSecret",
        "session",
        "sessionId",
        "PHPSESSID",
        "JSESSIONID",
        "connect.sid",
        "sid",
        "otp",
        "totp",
        "key",
        "sig",
        "ticket",
        "jwt",
        "X-Amz-Signature",
        "X-Amz-Credential",
        "X-Goog-Signature",
        "aws_secret_access_key",
        "user[password]",
        "data.token",
        " Token ",
        "code",
        "CODE",
        "SAMLResponse",
        "SAMLRequest",
        "passcode",
        "user_passcode",
        "pin",
        "card_pin",
        "auth_code",
        "authCode",
    ];
    for n in secret {
        assert!(
            is_sensitive_field_name(n.as_bytes()),
            "{n} should be secret"
        );
    }
    let plain = [
        "",
        "Host",
        "User-Agent",
        "Referer",
        "Origin",
        "Accept",
        "Accept-Encoding",
        "Content-Type",
        "Content-Length",
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Request-ID",
        "Cache-Control",
        "Sec-WebSocket-Key",
        "Sec-Fetch-Mode",
        "Keep-Alive",
        "Traceparent",
        "X-Original-URL",
        "If-None-Match",
        "Upgrade-Insecure-Requests",
        "X-Amz-Date",
        "X-Amz-Content-Sha256",
        "X-Auth-Request-Redirect",
        "Author",
        "Authority",
        "id",
        "q",
        "search",
        "page",
        "redirect",
        "url",
        "next",
        "file",
        "cmd",
        "country_code",
        "error_code",
        "zip-code",
        "pinned",
        "spin",
        "shipping",
        "user",
        "username",
        "email",
        "bypass",
        "passenger",
        "keyword",
        "monkey",
        "x-keyboard",
    ];
    for n in plain {
        assert!(
            !is_sensitive_field_name(n.as_bytes()),
            "{n} should not be secret"
        );
    }
}

#[test]
fn parse_match_source_table() {
    use Kind::*;
    for (input, kind, name) in [
        ("header:X-Api-Key", Header, "X-Api-Key"),
        ("HEADER:Cookie", Header, "Cookie"),
        ("REQUEST_HEADERS:x-auth-token", Header, "x-auth-token"),
        ("query:token", Query, "token"),
        ("query:hpp:token", Query, "token"),
        ("query:name:token", QueryName, "token"),
        ("ARGS_GET:api_key", Query, "api_key"),
        ("ARGS:api_key", Query, "api_key"),
        ("cookie:session", Cookie, "session"),
        ("REQUEST_COOKIES:sid", Cookie, "sid"),
        ("query", None, ""),
        ("query:", None, ""),
        ("body", None, ""),
        ("body:password", Body, "password"),
        ("body.json:password", Body, "password"),
        ("body:hpp:pin", Body, "pin"),
        ("body:f:filename", Body, "f"),
        ("body:name:password", None, ""),
        ("body.json", None, ""),
        ("path:/login", None, ""),
        ("ws:handshake", None, ""),
        (":x", None, ""),
        ("", None, ""),
    ] {
        let (k, n, _) = parse_match_source_targets(input.as_bytes());
        assert_eq!((k, n.as_slice()), (kind, name.as_bytes()), "{input}");
    }
}

#[test]
fn is_redacted_value_only_exact_markers() {
    for (v, want) in [
        (DECISION_REDACTED_MARKER, true),
        ("[redacted:len=24]", true),
        ("[redacted:len=]", false),
        ("[redacted:len=1' or '1'='1-- ]", false),
        ("[redacted:len=12x]", false),
        ("[redacted:len=-1]", false),
    ] {
        assert_eq!(is_redaction_marker(v.as_bytes()), want, "{v}");
    }
}

#[test]
fn control_plane_forged_marker_keeps_no_victim_token() {
    let m = decision_evidence(b"body:token", true, &["SQLi"]);
    let body = b"token=[redacted:len=1'+or+'1'='1--+]&token=VICTIMTOKEN0123456789";
    let got = redact_stored_body_copy(body, b"application/x-www-form-urlencoded", &m, true);
    assert!(
        !got.windows(11).any(|w| w == b"VICTIMTOKEN"),
        "{}",
        String::from_utf8_lossy(&got)
    );
}

#[test]
fn body_copy_complete_table() {
    let p = BODY_PREVIEW_LIMIT as i64;
    let x600 = "x".repeat(600);
    let fffd200 = "\u{FFFD}".repeat(200);
    for (copy, size, limit, want) in [
        (&b"a=1"[..], 3, p, true),
        (b"a=1", 4, p, false),
        (x600.as_bytes(), 600, p, false),
        ("a=\u{FFFD}".as_bytes(), 5, p, true),
        (fffd200.as_bytes(), 600, p, false),
        (b"a=\xff", 3, p, false),
        (b"", 0, p, false),
    ] {
        assert_eq!(
            is_body_copy_complete(copy, size, limit),
            want,
            "{:?}",
            String::from_utf8_lossy(copy)
        );
    }
}

#[test]
fn json_unescape_table() {
    for (input, want, ok) in [
        (&br#"a\"b\\c\/d\n"#[..], &b"a\"b\\c/d\n"[..], true),
        (b"token", b"token", true),
        (&b"\\ud83d\\ude00"[..], "\u{1F600}".as_bytes(), true),
        (br"\ud83dx", "\u{FFFD}x".as_bytes(), true),
        (br"\u12", br"\u12", false),
        (br"\q", br"\q", false),
        (br"x\", br"x\", false),
    ] {
        let got = unescape_json_string(input);
        assert_eq!(got.is_some(), ok, "{:?}", String::from_utf8_lossy(input));
        assert_eq!(got.unwrap_or_else(|| input.to_vec()), want);
    }
}

#[test]
fn redact_json_depth_cap() {
    let d = 64;
    let deep = format!(
        "{}{}{}",
        r#"{"a":"#.repeat(d),
        r#"{"note":"hello","n":5,"ok":true}"#,
        "}".repeat(d)
    );
    let got = redact_stored_body(deep.as_bytes(), b"json", &MatchEvidence::default());
    let s = String::from_utf8(got.clone()).unwrap();
    assert!(
        s.contains(r#"{"note":"[redacted]","n":"[redacted]","ok":true}"#),
        "{}",
        &s[s.len() - 120..]
    );
    assert_eq!(
        redact_stored_body(&got, b"json", &MatchEvidence::default()),
        got,
        "not idempotent past the cap"
    );
    let shallow = format!(
        "{}{}{}",
        r#"{"a":"#.repeat(d - 1),
        r#"{"note":"hello","password":"p"}"#,
        "}".repeat(d - 1)
    );
    let got = String::from_utf8(redact_stored_body(
        shallow.as_bytes(),
        b"json",
        &MatchEvidence::default(),
    ))
    .unwrap();
    assert!(got.contains(r#"{"note":"hello","password":"[redacted]"}"#));
    let mixed = format!(
        r#"{{"x":{}"v"{},"note":"hello","pin":"1"}}"#,
        "[".repeat(d + 3),
        "]".repeat(d + 3)
    );
    let want = mixed.replacen(r#""v""#, r#""[redacted]""#, 1).replacen(
        r#""pin":"1""#,
        r#""pin":"[redacted]""#,
        1,
    );
    assert_eq!(
        String::from_utf8(redact_stored_body(
            mixed.as_bytes(),
            b"json",
            &MatchEvidence::default()
        ))
        .unwrap(),
        want
    );
    let bare = "[".repeat(4096);
    assert_eq!(
        redact_stored_body(bare.as_bytes(), b"json", &MatchEvidence::default()),
        bare.as_bytes()
    );
}
