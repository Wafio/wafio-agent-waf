//! Tests of the proxy config, its path encoding and timeouts, and the JSON decoding rules.

use super::*;

#[test]
fn parse_proxy_config_defaults() {
    let pc = parse_proxy_config(b"{}").unwrap();
    assert_eq!(
        (
            pc.timeouts.upstream_ms,
            pc.timeouts.read_ms,
            pc.timeouts.write_ms
        ),
        (30000, 60000, 60000)
    );
    assert_eq!(pc.timeouts.connect_ms, 0);
    assert_eq!(pc.max_body_bytes, 67108864);
    assert_eq!(
        (pc.read_buffer_bytes, pc.write_buffer_bytes),
        (16384, 16384)
    );
    assert_eq!(
        (pc.max_conns, pc.conn_wait_ms, pc.idle_conn_ms),
        (512, 5000, 10000)
    );
    assert_eq!(pc.host_header.mode, "preserve");
    assert!(!pc.trust_forwarded, "absent trust_forwarded is false");
}

#[test]
fn parse_proxy_config_absent_is_defaults() {
    let pc = parse_proxy_config(b"").unwrap();
    assert!(!pc.trust_forwarded && pc.max_conns == 512);
}

#[test]
fn parse_proxy_config_trust_forwarded_explicit_false() {
    assert!(
        !parse_proxy_config(br#"{"trust_forwarded":false}"#)
            .unwrap()
            .trust_forwarded
    );
}

#[test]
fn proxy_config_validate() {
    let cases: &[(&str, &str, bool)] = &[
        (
            "valid full",
            r#"{"timeouts":{"connect_ms":2000,"upstream_ms":30000,"read_ms":60000,"write_ms":60000},"max_body_bytes":1048576,"read_buf":16384,"write_buf":16384,"max_conns":512,"conn_wait_ms":5000,"idle_conn_ms":10000,"host_header":{"mode":"custom","value":"api.example.com"},"req_headers":{"add":{"X-Foo":"bar"},"remove":["X-Bar"]},"resp_headers":{"add":{},"remove":[]},"trust_forwarded":false}"#,
            true,
        ),
        (
            "timeout too big",
            r#"{"timeouts":{"upstream_ms":600001}}"#,
            false,
        ),
        ("buf too small", r#"{"read_buf":1023}"#, false),
        ("body too big", r#"{"max_body_bytes":1073741825}"#, false),
        ("max_conns zero", r#"{"max_conns":0}"#, true),
        ("max_conns over", r#"{"max_conns":65536}"#, false),
        (
            "bad host mode",
            r#"{"host_header":{"mode":"weird"}}"#,
            false,
        ),
        (
            "custom no value",
            r#"{"host_header":{"mode":"custom","value":"  "}}"#,
            false,
        ),
        (
            "host value crlf",
            r#"{"host_header":{"mode":"custom","value":"a\r\nb"}}"#,
            false,
        ),
        (
            "bad header name",
            r#"{"req_headers":{"add":{"X Foo":"bar"}}}"#,
            false,
        ),
        (
            "header value crlf",
            r#"{"req_headers":{"add":{"X-Foo":"a\r\nb"}}}"#,
            false,
        ),
        (
            "host in add",
            r#"{"req_headers":{"add":{"Host":"x"}}}"#,
            false,
        ),
        (
            "too many headers",
            r#"{"req_headers":{"remove":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","a1","b1","c1","d1","e1","f1","g1"]}}"#,
            false,
        ),
    ];
    for (name, json, ok) in cases {
        match parse_proxy_config(json.as_bytes()) {
            Err(e) => assert!(!ok, "{name}: parse failed but expected valid: {e}"),
            Ok(pc) => assert_eq!(pc.validate().is_ok(), *ok, "{name}"),
        }
    }
}

#[test]
fn parse_proxy_config_reject_invalid_path_encoding() {
    for (raw, want) in [
        ("", true),
        ("null", true),
        ("{}", true),
        (r#"{"reject_invalid_path_encoding":null}"#, true),
        (r#"{"reject_invalid_path_encoding":true}"#, true),
        (r#"{"reject_invalid_path_encoding":false}"#, false),
        (r#"{"trust_forwarded":false}"#, true),
    ] {
        let pc = parse_proxy_config(raw.as_bytes()).unwrap();
        assert_eq!(pc.reject_invalid_path_encoding, want, "{raw:?}");
        pc.validate().unwrap();
    }
    for raw in [
        r#"{"reject_invalid_path_encoding":"false"}"#,
        r#"{"reject_invalid_path_encoding":0}"#,
    ] {
        assert!(
            parse_proxy_config(raw.as_bytes()).is_err(),
            "{raw}: non-boolean value accepted"
        );
    }
}

#[test]
fn timeout_or_default_ms_table() {
    for (name, v, def, want, unlt) in [
        ("unset falls back to default", 0, 30000, 30000, false),
        ("explicit value wins", 5000, 30000, 5000, false),
        (
            "unlimited resolves to zero",
            TIMEOUT_UNLIMITED,
            30000,
            0,
            true,
        ),
        (
            "other negatives are treated as unset",
            -7,
            30000,
            30000,
            false,
        ),
    ] {
        assert_eq!(timeout_or_default_ms(v, def), want, "{name}");
        assert_eq!(is_unlimited(v), unlt, "{name}");
    }
}

#[test]
fn parse_proxy_config_preserves_unlimited() {
    let pc = parse_proxy_config(br#"{"timeouts":{"upstream_ms":-1,"read_ms":-1,"write_ms":-1}}"#)
        .unwrap();
    assert_eq!(
        (
            pc.timeouts.upstream_ms,
            pc.timeouts.read_ms,
            pc.timeouts.write_ms
        ),
        (-1, -1, -1)
    );
}

#[test]
fn parse_proxy_config_still_defaults_zero() {
    let pc = parse_proxy_config(br#"{"timeouts":{"upstream_ms":0}}"#).unwrap();
    assert_eq!(pc.timeouts.upstream_ms, DEF_PROXY_UPSTREAM_MS);
}

#[test]
fn validate_accepts_unlimited_and_rejects_other_negatives() {
    let base = || parse_proxy_config(b"").unwrap();
    let mut pc = base();
    pc.timeouts.upstream_ms = TIMEOUT_UNLIMITED;
    pc.validate().unwrap();
    pc = base();
    pc.timeouts.upstream_ms = -2;
    let e = pc.validate().unwrap_err();
    assert_eq!(
        e.0,
        "timeouts.upstream_ms must be between 0 and 600000, or -1 for unlimited"
    );
    pc = base();
    pc.timeouts.upstream_ms = 600001;
    assert!(pc.validate().is_err());
}

#[test]
fn decoder_semantics() {
    // Case-insensitive keys, merge on repeated objects, null keeps the value.
    let pc = parse_proxy_config(
        br#"{"Timeouts":{"connect_ms":1},"timeouts":{"READ_MS":2},"max_conns":7,"max_conns":null,"Trust_Forwarded":true}"#,
    )
    .unwrap();
    assert_eq!((pc.timeouts.connect_ms, pc.timeouts.read_ms), (1, 2));
    assert_eq!(pc.max_conns, 7);
    assert!(pc.trust_forwarded);
    // Only the exact key counts for the reject_invalid_path_encoding probe.
    assert!(
        parse_proxy_config(br#"{"Reject_Invalid_Path_Encoding":false}"#)
            .unwrap()
            .reject_invalid_path_encoding
    );
    for bad in [
        r#"{"max_conns":1.5}"#,
        r#"{"max_conns":"5"}"#,
        r#"[]"#,
        r#"{"timeouts":5}"#,
        r#"{"req_headers":{"add":{"X":1}}}"#,
        "{",
    ] {
        assert!(parse_proxy_config(bad.as_bytes()).is_err(), "{bad}");
    }
    let e = parse_proxy_config(br#"{"timeouts":{"connect_ms":"x"}}"#).unwrap_err();
    assert_eq!(
        e.0,
        "proxy_config: json: cannot unmarshal string into Go struct field ProxyConfig.timeouts.connect_ms of type int"
    );
}
