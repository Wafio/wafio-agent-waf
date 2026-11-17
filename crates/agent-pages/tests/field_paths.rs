//! Field rule tests (the proxy's stored-body mask is not covered here: it needs the proxy).

use wafio_agent_pages::field_paths::*;
use wafio_agent_pages::json_tree::{decode_one, serialize_sorted};
use wafio_agent_pages::multipart::{PartHeaders, Reader, Writer, split_media_type};

const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const FORM: &[u8] = b"application/x-www-form-urlencoded";
const JSON: &[u8] = b"application/json";

fn field_rules(action: &str, fields: &[&str]) -> Vec<RequestFieldRule> {
    fields
        .iter()
        .map(|f| RequestFieldRule {
            field: f.to_string(),
            source: "any".into(),
            action: action.into(),
            cipher_key_hex: KEY.into(),
            methods: vec![],
        })
        .collect()
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn json_of(b: &[u8]) -> String {
    let (doc, rest, _) = parse_json_document(b).expect("json");
    let (v, _) = decode_one(doc).unwrap();
    s(&[serialize_sorted(&v).as_slice(), rest].concat())
}

#[test]
fn json_field_rules_deep_round_trip() {
    let body = br#"{"id":12345678901234567890,"price":1.50,"user":{"email":"a@b.c","name":"Ann"},"employees":[{"photo":"p0","name":"x"},{"photo":"p1"}],"keep":"k"}"#;
    let fields = ["user.email", "employees.photo"];
    let (enc, _) = transform_json_body(body, JSON, &field_rules("encrypt_aes", &fields));
    for plain in ["a@b.c", r#""p0""#, r#""p1""#] {
        assert!(
            !s(&enc).contains(plain),
            "{plain} left in plaintext: {}",
            s(&enc)
        );
    }
    for kept in [
        "12345678901234567890",
        "1.50",
        r#""Ann""#,
        r#""keep":"k""#,
        r#""name":"x""#,
    ] {
        assert!(s(&enc).contains(kept), "{kept} changed: {}", s(&enc));
    }
    let (dec, _) = transform_json_body(&enc, JSON, &field_rules("decrypt_aes", &fields));
    let rr: Vec<ResponseFieldTransformRule> = fields
        .iter()
        .map(|f| ResponseFieldTransformRule {
            field: f.to_string(),
            action: String::new(),
            cipher_key_hex: KEY.into(),
        })
        .collect();
    let resp = decrypt_json_response_fields(&enc, &rr).unwrap();
    assert_eq!(json_of(&dec), json_of(body));
    assert_eq!(json_of(&resp), json_of(body));
}

#[test]
fn json_field_rules_whole_values() {
    let (enc, _) = transform_json_body(
        br#"{"tags":["a","b"],"profile":{"a":1}}"#,
        JSON,
        &field_rules("encrypt_aes", &["tags", "profile"]),
    );
    assert!(
        !s(&enc).contains(r#""a""#) && !s(&enc).contains('['),
        "{}",
        s(&enc)
    );
    let (dec, _) = transform_json_body(
        &enc,
        JSON,
        &field_rules("decrypt_aes", &["tags", "profile"]),
    );
    assert_eq!(
        json_of(&dec),
        r#"{"profile":"{\"a\":1}","tags":"[\"a\",\"b\"]"}"#
    );
    let (one, _) = transform_json_body(br#"{"t":"a"}"#, JSON, &field_rules("encrypt_aes", &["t"]));
    let (two, _) = transform_json_body(br#"{"t":"b"}"#, JSON, &field_rules("encrypt_aes", &["t"]));
    let ct = |b: &[u8]| {
        s(b).trim_start_matches(r#"{"t":"#)
            .trim_end_matches('}')
            .to_string()
    };
    let list = format!(r#"{{"tags":[{},{}]}}"#, ct(&one), ct(&two));
    let (dec, _) = transform_json_body(
        list.as_bytes(),
        JSON,
        &field_rules("decrypt_aes", &["tags"]),
    );
    assert_eq!(json_of(&dec), r#"{"tags":["a","b"]}"#);
}

#[test]
fn json_field_rules_keys_and_document_shape() {
    for (name, body, field) in [
        (
            "root array",
            r#"[{"secret":"s1"},{"secret":"s1"}]"#.to_string(),
            "secret",
        ),
        (
            "literal dotted key",
            r#"{"user.email":"s1"}"#.into(),
            "user.email",
        ),
        (
            "dotted key below an object",
            r#"{"a":{"b.c":"s1"}}"#.into(),
            "a.b.c",
        ),
        (
            "case-insensitive key",
            r#"{"User":{"SSN":"s1"}}"#.into(),
            "user.ssn",
        ),
        ("BOM", "\u{feff}{\"secret\":\"s1\"}".into(), "secret"),
        (
            "trailing data",
            r#"{"secret":"s1"} {"x":1}"#.into(),
            "secret",
        ),
    ] {
        let (enc, _) =
            transform_json_body(body.as_bytes(), JSON, &field_rules("encrypt_aes", &[field]));
        assert!(!s(&enc).contains(r#""s1""#), "{name}: {}", s(&enc));
    }
    let (enc, _) = transform_json_body(
        br#"{"secret":"s1"} {"x":1}"#,
        JSON,
        &field_rules("encrypt_aes", &["secret"]),
    );
    assert!(s(&enc).ends_with(r#" {"x":1}"#));
}

fn multipart_body(fields: &[(&str, &str)]) -> (Vec<u8>, Vec<u8>) {
    let mut w = Writer::with_boundary(b"0123456789abcdef0123456789abcdef");
    for (k, v) in fields {
        let mut h = PartHeaders::new();
        h.insert(
            b"Content-Disposition".to_vec(),
            vec![format!(r#"form-data; name="{k}""#).into_bytes()],
        );
        w.start_part(&h);
        w.write(v.as_bytes());
    }
    let ct = [b"multipart/form-data; boundary=".as_slice(), w.boundary()].concat();
    (w.close(), ct)
}

fn multipart_values(body: &[u8], ct: &[u8]) -> std::collections::BTreeMap<String, String> {
    let (_, p) = split_media_type(ct).unwrap();
    let mut r = Reader::new(body, &p[b"boundary".as_slice()]);
    let mut out = std::collections::BTreeMap::new();
    while let Ok(Some(part)) = r.next_decoded_part() {
        let names = wafio_agent_pages::field_names::collect_multipart_part_names(
            &part.form_field_name(),
            &part.header_field_values(b"Content-Disposition"),
        );
        if let Some(n) = names.last() {
            out.insert(s(n), s(&part.body));
        }
    }
    out
}

#[test]
fn field_rules_transform_each_value_once() {
    let (enc, _) = transform_form_body(
        b"tags[]=a",
        FORM,
        &field_rules("encrypt_aes", &["tags", "tags[]"]),
    );
    let (dec, _) = transform_form_body(&enc, FORM, &field_rules("decrypt_aes", &["tags"]));
    assert_eq!(dec, b"tags[]=a");
    let (enc, _) = transform_json_body(
        br#"{"s":"a"}"#,
        JSON,
        &field_rules("encrypt_aes", &["s", "S"]),
    );
    let (dec, _) = transform_json_body(&enc, JSON, &field_rules("decrypt_aes", &["s"]));
    assert_eq!(dec, br#"{"s":"a"}"#);
    let (body, ct) = multipart_body(&[("photos[]", "p")]);
    let (enc, enc_ct) = transform_multipart_body(
        &body,
        &ct,
        &field_rules("encrypt_aes", &["photos", "photos[]"]),
    );
    let (dec, dec_ct) =
        transform_multipart_body(&enc, &enc_ct, &field_rules("decrypt_aes", &["photos"]));
    assert_eq!(multipart_values(&dec, &dec_ct)["photos[]"], "p");
}

#[test]
fn form_field_rules_arrays_and_brackets() {
    let body = "x=1&tags%5B%5D=a&tags%5B%5D=b&employees[0][photo]=p+0&employees[1][photo]=p1&employees[0][name]=n&ssn=12%zz";
    let fields = ["tags", "employees.photo", "ssn"];
    let (enc, _) = transform_form_body(body.as_bytes(), FORM, &field_rules("encrypt_aes", &fields));
    let enc = s(&enc);
    let pairs: Vec<&str> = enc.split('&').collect();
    assert!(
        pairs.len() == 7 && pairs[0] == "x=1" && pairs[5] == "employees[0][name]=n",
        "{enc}"
    );
    for i in [1, 2, 3, 4, 6] {
        assert!(
            pairs[i].split_once('=').unwrap().1.len() >= 20,
            "pair {i} not encrypted: {}",
            pairs[i]
        );
    }
    let (dec, _) = transform_form_body(enc.as_bytes(), FORM, &field_rules("decrypt_aes", &fields));
    assert_eq!(
        s(&dec),
        "x=1&tags%5B%5D=a&tags%5B%5D=b&employees[0][photo]=p+0&employees[1][photo]=p1&employees[0][name]=n&ssn=12%25zz"
    );
}

#[test]
fn multipart_field_rules_brackets_and_disposition_tricks() {
    let (body, ct) = multipart_body(&[
        ("employees[0][photo]", "p0"),
        ("employees[1][photo]", "p1"),
        ("note", "n"),
    ]);
    let (enc, enc_ct) = transform_multipart_body(
        &body,
        &ct,
        &field_rules("encrypt_aes", &["employees.photo"]),
    );
    let got = multipart_values(&enc, &enc_ct);
    assert!(
        got["employees[0][photo]"] != "p0"
            && got["employees[1][photo]"] != "p1"
            && got["note"] == "n",
        "{got:?}"
    );
    let (dec, dec_ct) = transform_multipart_body(
        &enc,
        &enc_ct,
        &field_rules("decrypt_aes", &["employees[][photo]"]),
    );
    let got = multipart_values(&dec, &dec_ct);
    assert!(
        got["employees[0][photo]"] == "p0" && got["employees[1][photo]"] == "p1",
        "{got:?}"
    );
    for cd in [
        r#"form-data; name="x"; name="ssn""#,
        r#"attachment; name="ssn""#,
    ] {
        let mut w = Writer::with_boundary(b"bb");
        let mut h = PartHeaders::new();
        h.insert(
            b"Content-Disposition".to_vec(),
            vec![cd.as_bytes().to_vec()],
        );
        w.start_part(&h);
        w.write(b"secret");
        let body = w.close();
        let (enc, _) = transform_multipart_body(
            &body,
            b"multipart/form-data; boundary=bb",
            &field_rules("encrypt_aes", &["ssn"]),
        );
        assert!(!s(&enc).contains("secret"), "{cd}");
        let p = compose_multipart_preview(
            b"multipart/form-data; boundary=bb",
            &body,
            &field_rules("mask", &["ssn"]),
        );
        assert!(!s(&p).contains("secret"), "{cd}: {}", s(&p));
    }
}

// A body ending after a delimiter (or inside part headers) without the closing boundary is
// a clean end, so the earlier parts are still rewritten; forwarding the original leaked an
// encrypt_aes value in plaintext.
#[test]
fn multipart_field_rules_body_without_closing_boundary() {
    for tail in ["", "X-A: b\r\n"] {
        let body = format!(
            "--XX\r\nContent-Disposition: form-data; name=\"ssn\"\r\n\r\n123\r\n--XX\r\n{tail}"
        );
        let (enc, enc_ct) = transform_multipart_body(
            body.as_bytes(),
            b"multipart/form-data; boundary=XX",
            &field_rules("encrypt_aes", &["ssn"]),
        );
        assert!(
            enc_ct != b"multipart/form-data; boundary=XX",
            "tail {tail:?}: content type kept"
        );
        let got = multipart_values(&enc, &enc_ct);
        assert!(
            got.len() == 1 && got["ssn"] != "123",
            "tail {tail:?}: {got:?}"
        );
        let (dec, dec_ct) =
            transform_multipart_body(&enc, &enc_ct, &field_rules("decrypt_aes", &["ssn"]));
        assert_eq!(multipart_values(&dec, &dec_ct)["ssn"], "123");
    }
}

#[test]
fn field_rule_source_urlencoded() {
    let rule = RequestFieldRule {
        source: FIELD_SOURCE_FORM_URLENCODED.into(),
        ..Default::default()
    };
    assert!(
        rule_applies_to_source(&rule, "form")
            && !rule_applies_to_source(&rule, "multipart")
            && !rule_applies_to_source(&rule, "json")
    );
}

#[test]
fn field_rule_failures_counted_once_per_request() {
    let rules = field_rules("decrypt_aes", &["ssn"]);
    let mut t = FieldRewriter::new(&rules[0]);
    for _ in 0..1000 {
        t.apply(b"x");
    }
    let line = t.report_failures("form").unwrap();
    assert!(line.contains("1000 value(s)"), "{line}");
}

#[test]
fn mask_json_preview_cases() {
    for (preview, fields, want) in [
        (
            r#"{"user":"x","password":"secret"}"#.to_string(),
            vec!["password"],
            r#"{"user":"x","password":"[MASKED]"}"#.to_string(),
        ),
        (
            r#"{"a":{"password": "s"},"password2":"k"}"#.into(),
            vec!["a.password"],
            r#"{"a":{"password":"[MASKED]"},"password2":"k"}"#.into(),
        ),
        (
            r#"[{"card":{"n":1}},{"card":[1,2]}]"#.into(),
            vec!["card"],
            r#"[{"card":"[MASKED]"},{"card":"[MASKED]"}]"#.into(),
        ),
        (
            r#"{"pass\u0077ord":"s"}"#.into(),
            vec!["password"],
            r#"{"pass\u0077ord":"[MASKED]"}"#.into(),
        ),
        (
            r#"{"Password":"s","user.ssn":"1"}"#.into(),
            vec!["password", "user.ssn"],
            r#"{"Password":"[MASKED]","user.ssn":"[MASKED]"}"#.into(),
        ),
        (
            r#"{"user":"x","password":"secr"#.into(),
            vec!["password"],
            r#"{"user":"x","password":"[MASKED]""#.into(),
        ),
        (
            r#"{"password":"s","note":"trunc"#.into(),
            vec!["password"],
            r#"{"password":"[MASKED]","note":"trunc"#.into(),
        ),
        (
            "\u{feff}{\"password\":\"s\"}".into(),
            vec!["password"],
            "\u{feff}{\"password\":\"[MASKED]\"}".into(),
        ),
        (
            r#"{"a":01,"password":"s"}"#.into(),
            vec!["password"],
            r#"{"a":0[MASKED]"#.into(),
        ),
        (
            r#"{"other":"s"}"#.into(),
            vec!["password"],
            r#"{"other":"s"}"#.into(),
        ),
    ] {
        assert_eq!(
            s(&redact_json_preview(preview.as_bytes(), &fields)),
            want,
            "{preview}"
        );
    }
}

#[test]
fn mask_form_and_multipart_preview() {
    let mask = field_rules("mask", &["password", "cards"]);
    let got = redact_body_preview(b"password=a&x=1&Password=b&cards%5B%5D=4111", "form", &mask);
    assert_eq!(
        s(&got),
        "password=[MASKED]&x=1&Password=[MASKED]&cards%5B%5D=[MASKED]"
    );
    let (body, ct) = multipart_body(&[("password", "a&b=c"), ("x", "1")]);
    assert_eq!(
        s(&compose_multipart_preview(&ct, &body, &mask)),
        "password=[MASKED]&x=1"
    );
}
