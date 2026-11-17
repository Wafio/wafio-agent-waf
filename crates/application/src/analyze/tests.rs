//! Tests of analyze.rs that need no engine: the early-return paths and
//! the pure helpers (smuggling, header lookup, path rules, content scan).

use super::*;
use crate::ratelimit::MemoryStore as RateStore;

fn request(method: &str, uri: &str, headers: &[(&str, &[&str])]) -> IncomingRequest {
    let mut h = Headers::new();
    for (k, vs) in headers {
        h.insert(
            k.as_bytes().to_vec(),
            vs.iter().map(|v| v.as_bytes().to_vec()).collect(),
        );
    }
    IncomingRequest {
        method: method.into(),
        uri: uri.into(),
        headers: h,
        remote_address: b"203.0.113.4:1234".to_vec(),
        ..Default::default()
    }
}

#[test]
fn smuggling_dual_cl_te_blocks() {
    let r = analyze(
        &request(
            "POST",
            "/api/x",
            &[
                ("Content-Length", &["5"]),
                ("Transfer-Encoding", &["chunked"]),
            ],
        ),
        &AnalyzeConfig::default(),
    );
    assert_eq!(r.action, "block");
    assert_eq!(r.categories, vec!["ProtocolAttack"]);
    assert_eq!(r.match_detail, b"smuggling_cl_te");
    assert_eq!(r.match_source, b"header:fraction");
    assert_eq!(r.status_code, 400);
    assert_eq!(r.analyze_method, "policy");
}

#[test]
fn smuggling_duplicate_cl() {
    assert_eq!(
        smuggling_indicator(&request("POST", "/", &[("Content-Length", &["5", "6"])]).headers),
        "smuggling_duplicate_cl"
    );
    assert_eq!(
        smuggling_indicator(&request("POST", "/", &[("Content-Length", &["5", " 5 "])]).headers),
        ""
    );
    assert_eq!(
        smuggling_indicator(&request("POST", "/", &[("transfer-encoding", &["chunked"])]).headers),
        ""
    );
}

#[test]
fn body_limit_blocks_first() {
    let cfg = AnalyzeConfig {
        request_body_limit: 4,
        ..Default::default()
    };
    let mut rq = request("POST", "/", &[]);
    rq.body = b"12345".to_vec();
    let r = analyze(&rq, &cfg);
    assert_eq!(
        (r.action.as_str(), r.analyze_method.as_str()),
        ("block", "body_limit")
    );
    assert_eq!(r.message, b"Request body exceeds configured limit");
    // BodySize (transport-truncated multipart) wins over the delivered length.
    let mut rq = request("POST", "/", &[]);
    rq.body_size = 10;
    assert_eq!(analyze(&rq, &cfg).categories, vec!["BodyLimit"]);
}

#[test]
fn header_lookup_and_policy_key() {
    let mut rq = request(
        "GET",
        "/",
        &[("X-Token", &["abc"]), ("user-agent", &["UA"])],
    );
    rq.user_agent = b"agent".to_vec();
    rq.host = b"h".to_vec();
    assert_eq!(first_header_value(&rq.headers, b"x-token"), b"abc");
    assert_eq!(first_header_value(&rq.headers, b"User-Agent"), b"UA");
    assert_eq!(first_header_value(&rq.headers, b"missing"), b"");
    let fields = vec![
        "remote_addr".into(),
        " user_agent ".into(),
        "".into(),
        "HEADER: X-Token".into(),
        "bogus".into(),
    ];
    assert_eq!(
        composite_block_key(&rq, &fields),
        b"203.0.113.4:1234\x00agent\x00abc\x00"
    );
    assert_eq!(composite_block_key(&rq, &[]), b"203.0.113.4:1234");
    assert_eq!(
        canonical_header_name(b"content-type").as_ref(),
        b"Content-Type"
    );
    assert_eq!(canonical_header_name(b"bad key").as_ref(), b"bad key");
}

#[test]
fn small_helpers() {
    assert_eq!(strip_port(b"1.2.3.4:80"), b"1.2.3.4");
    assert_eq!(strip_port(b"2001:db8::1"), b"2001:db8::1");
    assert_eq!(raw_query_of_uri(b"/a?b=1#f"), b"b=1");
    assert_eq!(exact_match_value(false, b"x".to_vec()), None);
    assert_eq!(raw_query_of_uri(b"/a#f?b=1"), b"");
    assert_eq!(path_extension(b"/a/b.PHP"), b".PHP");
    assert_eq!(path_extension(b"/a.d/b"), b"");
    let c = parse_cookie_pairs(br#"a=1; b="two words"; =x; c ; a=3"#).unwrap();
    assert_eq!(
        c,
        vec![
            (b"a".to_vec(), b"3".to_vec()),
            (b"b".to_vec(), b"two words".to_vec())
        ]
    );
    assert!(parse_cookie_pairs(b"").is_none());
    assert_eq!(message_for_categories(&[]), "Request blocked by rules.");
    assert_eq!(
        message_for_categories(&["LFI".into(), "RCE".into()]),
        "Request blocked: LFI, RCE."
    );
    assert_eq!(
        block_response_for_semantic_reason("nope").0,
        vec!["Semantic"]
    );
    assert_eq!(
        block_response_for_semantic_reason(REASON_SEMANTIC_SQL).0,
        vec!["SQLi"]
    );
}

#[test]
fn every_semantic_reason_has_a_category() {
    for r in [
        REASON_SEMANTIC_SQL,
        REASON_SEMANTIC_XSS,
        REASON_SEMANTIC_CMD,
        REASON_SEMANTIC_PHP,
        REASON_SEMANTIC_PYTHON,
        REASON_SEMANTIC_LFI,
        REASON_SEMANTIC_SSRF,
        REASON_SEMANTIC_JAVA,
        REASON_SEMANTIC_LDAP,
        REASON_SEMANTIC_PROTO_POLLUTION,
        REASON_SEMANTIC_SSTI,
        REASON_SEMANTIC_XXE,
        REASON_SEMANTIC_DESER,
        REASON_SEMANTIC_NOSQL,
        REASON_SEMANTIC_OPEN_REDIRECT,
        REASON_SEMANTIC_HEADER_INJECTION,
        REASON_SEMANTIC_PROMPT_INJECTION,
        REASON_SEMANTIC_ANOMALY,
        REASON_SEMANTIC_GRAPHQL,
        REASON_SEMANTIC_JWT,
    ] {
        assert!(category_for_semantic_reason(r).is_some(), "{r}");
    }
}

#[test]
fn rate_store_is_object_safe() {
    let s: Arc<dyn RateLimitStore> = Arc::new(RateStore::new());
    assert!(s.allow(b"x", b"y", 1, 1));
}

#[test]
fn path_ip_rules_v4_mapped_cidr_matches_v4_client() {
    // A v4-mapped network is reduced to IPv4 when matching.
    let cfg_for = |mode: &str| {
        let rules = format!(
            r#"{{"path_exceptions":[{{"path":"/zzblk","ip_rules":{{"mode":"{mode}","ips":["::ffff:192.0.2.0/120"]}}}}]}}"#
        );
        let res = crate::deps::engine::load_rules_json(rules.as_bytes()).expect("rules");
        AnalyzeConfig {
            path_exceptions: res.path_exceptions,
            ..Default::default()
        }
    };
    let mut rq = request("GET", "/zzblk", &[]);
    rq.remote_address = b"192.0.2.50:1234".to_vec();
    let r = analyze(&rq, &cfg_for("blocklist"));
    assert_eq!(
        (
            r.action.as_str(),
            r.message.as_slice(),
            r.analyze_method.as_str()
        ),
        ("block", &b"IP blocked by path rule"[..], "policy")
    );
    assert_eq!(r.categories, vec!["PathIPRule"]);
    assert_ne!(
        analyze(&rq, &cfg_for("allowlist")).message,
        b"IP not in path allowlist"
    );
}

fn upload(data: &[u8]) -> IncomingRequest {
    let mut rq = request("POST", "/upload", &[]);
    rq.content_type = b"multipart/form-data; boundary=xYz".to_vec();
    rq.body = [&b"--xYz\r\nContent-Disposition: form-data; name=\"payload\"; filename=\"malware.exe\"\r\nContent-Type: application/octet-stream\r\n\r\n"[..], data, b"\r\n--xYz--\r\n"].concat();
    rq
}

#[test]
fn content_scan_without_database_is_incomplete_not_fail_open() {
    // A missing database is an incomplete scan, so the answer is the `on_incomplete` setting.
    let mut cs = crate::deps::engine::ContentScanConfig {
        enabled: true,
        mode: "block".into(),
        on_incomplete: "block".into(),
        ..Default::default()
    };
    cs.scan_multipart = true;
    let cfg = AnalyzeConfig {
        content_scan: Some(cs),
        ..Default::default()
    };
    let r = analyze(&upload(b"anything"), &cfg);
    assert_eq!(
        (
            r.action.as_str(),
            r.analyze_method.as_str(),
            r.message.as_slice()
        ),
        ("block", "content_scan", &b"Upload hash scan incomplete"[..])
    );
    assert_eq!(r.categories, vec!["ContentScanIncomplete"]);
    assert_eq!(r.match_detail, br#"content_scan:[{"status":"not_scanned","reason":"database_unavailable","bytes_read":0}]"#);
}

// Every app gets the default malware engine: its builtin EICAR signature blocks.
#[test]
fn content_scan_default_engine_blocks_eicar() {
    let eicar: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let cs = crate::deps::engine::ContentScanConfig {
        enabled: true,
        mode: "block".into(),
        scan_multipart: true,
        ..Default::default()
    };
    let cfg = AnalyzeConfig {
        content_scan: Some(cs),
        malware_hash_engine: Some(crate::default_malware_engine()),
        ..Default::default()
    };
    let r = analyze(&upload(eicar), &cfg);
    assert_eq!(
        (r.action.as_str(), r.analyze_method.as_str()),
        ("block", "content_scan")
    );
    assert_eq!(
        r.message,
        b"Known upload hash matched: EICAR.Standard.Antivirus.Test"
    );
    assert!(
        String::from_utf8_lossy(&r.match_detail)
            .contains(r#""signature":"EICAR.Standard.Antivirus.Test""#)
    );
    assert_eq!(analyze(&upload(b"harmless"), &cfg).action, "allow");
}

// TestAnalyze_ContentScanningMaliciousUpload (malicious and log-mode parts)
#[test]
fn content_scan_malicious_upload() {
    use sha2::{Digest, Sha256};
    let eicar: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let e = crate::deps::engine::HashMatcher::new(10, 0.01);
    e.insert_hash(Sha256::digest(eicar).into(), b"EICAR.Standard.Test");
    let cs = crate::deps::engine::ContentScanConfig {
        enabled: true,
        mode: "block".into(),
        max_scan_size_bytes: 10 << 20,
        scan_multipart: true,
        ..Default::default()
    };
    let mut cfg = AnalyzeConfig {
        content_scan: Some(cs),
        malware_hash_engine: Some(Arc::new(e)),
        ..Default::default()
    };
    let r = analyze(&upload(eicar), &cfg);
    assert_eq!(
        (r.action.as_str(), r.analyze_method.as_str(), r.cwe.as_str()),
        ("block", "content_scan", "CWE-434")
    );
    assert_eq!(r.categories, vec!["Malware"]);
    assert_eq!(r.message, b"Known upload hash matched: EICAR.Standard.Test");
    assert_eq!(r.match_source, b"body:payload");
    cfg.content_scan.as_mut().unwrap().mode = "log".into();
    let r = analyze(&upload(eicar), &cfg);
    assert!(
        !(r.action == "block" && r.analyze_method == "content_scan"),
        "{r:?}"
    );
}

// No engine is installed in this test process: the request is allowed, nothing counts as a gap, and the verdict says
// that no engine looked at it.
#[test]
fn without_an_engine_a_request_is_allowed_and_marked() {
    let r = analyze(
        &request("GET", "/item?id=1", &[("User-Agent", &["curl/8"])]),
        &AnalyzeConfig::default(),
    );
    assert_eq!(r.action, "allow", "{r:?}");
    assert_eq!(r.analyze_method, ANALYZE_METHOD_SEMANTIC);
    assert!(r.engine_absent, "{r:?}");
    assert_eq!(r.coverage, "");
    assert!(!r.coverage_raised);
}
