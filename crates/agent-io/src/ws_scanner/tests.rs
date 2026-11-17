//! Engine-independent scanner and binary handshake tests; the scoring tests need the engine crates, so
//! they run here against a fake engine.

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

/// Fake engine: "ATTACK" is a strong detection, "WEAK" a weak one, "LONG" reports truncation, "ENGINE"
/// opens one engine; extraction yields the preset fields.
struct Fake {
    fields: Vec<WsScanField>,
    cov: WsFieldCoverage,
    scanned: RefCell<Vec<Vec<u8>>>,
}

impl Fake {
    fn new(fields: Vec<WsScanField>, cov: WsFieldCoverage) -> Fake {
        Fake {
            fields,
            cov,
            scanned: RefCell::new(Vec::new()),
        }
    }
}

fn field(v: &str, source: &str, summary: bool) -> WsScanField {
    WsScanField {
        value: v.as_bytes().to_vec(),
        source: source.as_bytes().to_vec(),
        summary,
    }
}

impl WsSemantic for Fake {
    fn extract_scan_fields(&self, _payload: &[u8]) -> (Vec<WsScanField>, WsFieldCoverage) {
        (self.fields.clone(), self.cov.clone())
    }
    fn scan_semantics_detailed(&self, value: &[u8]) -> WsDetailed {
        self.scanned.borrow_mut().push(value.to_vec());
        let s = String::from_utf8_lossy(value);
        WsDetailed {
            tier: if s.contains("ATTACK") {
                Tier::Strong
            } else if s.contains("WEAK") {
                Tier::Weak
            } else {
                Tier::Clean
            },
            reason: if s.contains("ATTACK") || s.contains("WEAK") {
                "semantic_sql".into()
            } else {
                String::new()
            },
            engines: i64::from(s.contains("ENGINE") || s.contains("ATTACK")),
            truncated: s.contains("LONG"),
            held_reason: if s.contains("HELD") {
                "SEMANTIC_SQL".into()
            } else {
                String::new()
            },
        }
    }
}

#[test]
fn default_limits() {
    assert_eq!(
        default_scan_budget(),
        WsScanBudget {
            max_text_size: 65536,
            max_binary_size: 1048576,
            max_msgs_per_min: 100
        }
    );
}

#[test]
fn rate_limiter_allows_exactly_max_then_denies() {
    let now = Instant::now();
    let mut l = WsMessageRateLimiter::new(3);
    l.set_clock(move || now);
    for _ in 0..3 {
        assert!(l.allow());
    }
    assert!(!l.allow());
}

#[test]
fn rate_limiter_window_rollover() {
    let base = Instant::now();
    let offset = Arc::new(AtomicU64::new(0));
    let mut l = WsMessageRateLimiter::new(2);
    let o = offset.clone();
    l.set_clock(move || base + Duration::from_secs(o.load(Ordering::SeqCst)));
    assert!(l.allow() && l.allow() && !l.allow());
    offset.store(61, Ordering::SeqCst);
    assert!(l.allow());
}

#[test]
fn scan_empty_payload_is_clean() {
    let f = Fake::new(
        vec![field("ATTACK", "json", false)],
        WsFieldCoverage::default(),
    );
    assert_eq!(scan_frame_payload(&f, b""), WsScanVerdict::default());
}

#[test]
fn scan_takes_max_and_skips_short_leaves() {
    let f = Fake::new(
        vec![
            field("id", "json:lang", false),
            field("x ATTACK", "json:q", false),
        ],
        WsFieldCoverage::default(),
    );
    let r = scan_frame_payload(&f, b"{}");
    assert_eq!(
        (r.tier, r.reason.as_str(), r.incomplete),
        (Tier::Strong, "semantic_sql", "")
    );
    // the short leaf ("id" < MIN_SCANNABLE_LENGTH) is never scanned on its own
    assert_eq!(f.scanned.borrow().len(), 1);
}

#[test]
fn scan_falls_back_to_whole_frame() {
    let skipped = WsFieldCoverage {
        skipped: "binary".into(),
        ..Default::default()
    };
    let f = Fake::new(Vec::new(), skipped);
    assert_eq!(scan_frame_payload(&f, b"ATTACK").tier, Tier::Strong);
    assert_eq!(f.scanned.borrow()[0], b"ATTACK");
    let bt = WsFieldCoverage {
        binary_text: true,
        ..Default::default()
    };
    let f = Fake::new(vec![field("run1", "body", false)], bt);
    scan_frame_payload(&f, b"ab");
    assert_eq!(*f.scanned.borrow(), vec![b"ab".to_vec()]); // short whole-frame fallback still scanned
}

#[test]
fn scan_engine_budget_reports_field_cap() {
    let mut fields: Vec<WsScanField> = (0..BODY_ENGINE_FIELD_LIMIT + 5)
        .map(|i| field(&format!("ENGINE {i}"), "json:k", false))
        .collect();
    fields.push(field("summary ATTACK", "json:keys", true));
    let f = Fake::new(fields, WsFieldCoverage::default());
    let r = scan_frame_payload(&f, b"{}");
    assert_eq!((r.tier, r.incomplete), (Tier::Strong, "field_cap"));
    assert_eq!(f.scanned.borrow().len(), BODY_ENGINE_FIELD_LIMIT + 1);
}

#[test]
fn scan_reports_truncation_unless_capped() {
    let f = Fake::new(
        vec![field("LONG value", "json:k", false)],
        WsFieldCoverage::default(),
    );
    assert_eq!(scan_frame_payload(&f, b"{}").incomplete, "value_truncated");
    let capped = WsFieldCoverage {
        field_capped: true,
        ..Default::default()
    };
    let f = Fake::new(vec![field("LONG value", "json:k", false)], capped);
    assert_eq!(scan_frame_payload(&f, b"{}").incomplete, "field_cap");
}

#[test]
fn scan_runs_one_run_at_a_time() {
    let f = Fake::new(Vec::new(), WsFieldCoverage::default());
    let r = scan_printable_runs(
        &f,
        b"short ATTACK\nthis run has ATTACK in it\nclean run here ok",
    );
    assert_eq!(r.tier, Tier::Strong);
    // "short ATTACK" is exactly 12 bytes: kept; shorter runs are skipped
    assert_eq!(f.scanned.borrow().len(), 3);
    let f = Fake::new(Vec::new(), WsFieldCoverage::default());
    scan_printable_runs(&f, b"ATTACK 1\n");
    assert!(f.scanned.borrow().is_empty());
}

#[test]
fn incomplete_action() {
    let cs = |enabled: bool, mode: &str, on: &str| WsContentScan {
        enabled,
        mode: mode.into(),
        on_incomplete: on.into(),
    };
    assert_eq!(incomplete_frame_action(None), "log");
    for (c, want) in [
        (cs(false, "", "block"), "log"),
        (cs(true, "block", "block"), "block"),
        (cs(true, "log", "block"), "log"),
        (cs(true, "block", "allow"), "allow"),
        (cs(true, "disabled", "block"), "log"),
        (cs(true, "block", ""), "log"),
    ] {
        assert_eq!(incomplete_frame_action(Some(&c)), want, "{c:?}");
    }
}

const MAX_TEXT: usize = 64 << 10;

fn doc(b: &[u8]) -> bool {
    let v = build_scan_input(MESSAGE_KIND_BINARY, b, MAX_TEXT);
    v.text.is_some() && !v.runs
}

fn padded_sqli_frame() -> Vec<u8> {
    let mut b = br#"{"q":"' OR 1=1--"#.to_vec();
    b.extend(std::iter::repeat_n(0xffu8, 11));
    b.extend_from_slice(br#""}"#);
    b
}

fn ratio_dodge_frames() -> Vec<Vec<u8>> {
    let a = b"' OR 1=1-- \xff\xff\xff".to_vec();
    let mut b = b"1' UNION SELECT username, password FROM users-- \xff".to_vec();
    for _ in 0..5 {
        b.extend_from_slice(&[0x01, 0x7f]);
    }
    vec![a, b]
}

#[test]
fn binary_sniff() {
    assert!(doc(br#"{"a":"b"}"#) && doc("héllo wörld".as_bytes()));
    let mut gz = vec![0x1f, 0x8b, 0x08, 0x00];
    for _ in 0..100 {
        gz.extend_from_slice(&[0xff, 0xfe, 0x80, 0x81, 0x00, 0x13]);
    }
    assert!(!doc(&gz));

    let mut fenced = [0xffu8, 0x01].repeat(400);
    fenced.extend_from_slice(b"1' UNION SELECT password FROM users-- ");
    fenced.extend([0x00u8, 0xfe].repeat(400));
    let v = build_scan_input(MESSAGE_KIND_BINARY, &fenced, MAX_TEXT);
    assert!(
        v.runs && String::from_utf8_lossy(v.text.as_ref().unwrap()).contains("UNION SELECT"),
        "{v:?}"
    );

    let mut second = b"' OR 1=1-- union select password from users".to_vec();
    second.extend(std::iter::repeat_n(0xffu8, 200));
    for b in [padded_sqli_frame(), second] {
        let v = build_scan_input(MESSAGE_KIND_BINARY, &b, MAX_TEXT);
        let text = v.text.clone().unwrap();
        assert!(
            !v.runs
                && String::from_utf8_lossy(&text).contains("' OR 1=1--")
                && std::str::from_utf8(&text).is_ok(),
            "{v:?}"
        );
    }
    for b in ratio_dodge_frames() {
        let v = build_scan_input(MESSAGE_KIND_BINARY, &b, MAX_TEXT);
        assert!(v.text.as_ref().is_some_and(|t| t.contains(&b'1')), "{v:?}");
    }
    let expand = b"\xffa".repeat(30 << 10);
    for kind in [MESSAGE_KIND_TEXT, MESSAGE_KIND_BINARY] {
        assert!(
            build_scan_input(kind, &expand, MAX_TEXT).oversize,
            "kind {kind}"
        );
    }
}

#[test]
fn random_binary_is_never_a_text_document() {
    // xorshift: deterministic pseudo-random bytes
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..20 {
        let b: Vec<u8> = (0..64 << 10)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let v = build_scan_input(MESSAGE_KIND_BINARY, &b, MAX_TEXT);
        assert!(v.text.is_none() || v.runs);
        if let Some(t) = &v.text {
            assert!(t.len() <= MAX_TEXT);
            assert!(
                t.split(|&c| c == b'\n')
                    .all(|r| r.len() >= PRINTABLE_RUN_MIN_LENGTH)
            );
        }
    }
}

#[test]
fn text_doc_view_caps_raw_and_decoded() {
    assert_eq!(
        build_scan_input(MESSAGE_KIND_TEXT, b"", MAX_TEXT),
        WsScanInput::default()
    );
    let v = text_document_input(b"abcdef", 4);
    assert!(v.oversize && v.text.as_deref() == Some(&b"abcdef"[..]));
    let v = text_document_input(b"a\xff\xfeb", 6);
    assert_eq!(v.text.as_deref(), Some("a\u{FFFD}b".as_bytes()));
    assert!(!v.oversize);
    assert!(text_document_input(b"\xffa\xffa", 6).oversize); // 4 raw bytes → 8 decoded
    assert_eq!(build_scan_input(9, b"x", MAX_TEXT), WsScanInput::default());
}

#[test]
fn printable_runs_limit_and_min_run() {
    let b = b"\x00abcdefghijkl\x00short\x00ABCDEFGHIJKLMNOP\x01";
    assert_eq!(
        collect_printable_runs(b, 1000),
        b"abcdefghijkl\nABCDEFGHIJKLMNOP".to_vec()
    );
    assert_eq!(collect_printable_runs(b, 5), b"abcde".to_vec());
    assert_eq!(
        collect_printable_runs(b"tail run of text", 100),
        b"tail run of text".to_vec()
    );
}

#[test]
fn decoded_mostly_printable_and_ratio() {
    assert!(looks_mostly_printable(b"\xff\xff0123456789abcdef"));
    assert!(!looks_mostly_printable(b"\xff0123456789abcde")); // 15 printable
    assert!(!looks_mostly_printable(b"0123456789abcdef\x01\x02\x03\x04")); // 16/20 = 80 %
    assert_eq!(printable_fraction(b""), 0.0);
    assert_eq!(printable_fraction("é\x00".as_bytes()), 2.0 / 3.0);
    assert_eq!(printable_fraction("\u{FFFD}".as_bytes()), 1.0);
}

#[test]
fn a_held_detection_is_reported_beside_the_best_and_never_in_it() {
    let f = Fake::new(
        vec![
            field("x HELD", "json:a", false),
            field("x ATTACK", "json:b", false),
        ],
        WsFieldCoverage::default(),
    );
    let r = scan_frame_payload(&f, b"{}");
    assert_eq!((r.tier, r.reason.as_str()), (Tier::Strong, "semantic_sql"));
    assert_eq!(r.held_reason, "SEMANTIC_SQL");

    let only = Fake::new(
        vec![field("x HELD", "json:a", false)],
        WsFieldCoverage::default(),
    );
    let r = scan_frame_payload(&only, b"{}");
    assert_eq!(r.tier, Tier::Clean);
    assert_eq!(r.held_reason, "SEMANTIC_SQL");

    let r = scan_printable_runs(&only, b"printable HELD run\nx");
    assert_eq!(
        (r.tier, r.held_reason.as_str()),
        (Tier::Clean, "SEMANTIC_SQL")
    );
}

#[test]
fn a_strong_detection_outranks_a_weak_one_whatever_the_order() {
    let f = Fake::new(
        vec![
            field("x ATTACK", "json:a", false),
            field("x WEAK", "json:b", false),
        ],
        WsFieldCoverage::default(),
    );
    assert_eq!(scan_frame_payload(&f, b"{}").tier, Tier::Strong);
    let f = Fake::new(
        vec![
            field("x WEAK", "json:a", false),
            field("x ATTACK", "json:b", false),
        ],
        WsFieldCoverage::default(),
    );
    assert_eq!(scan_frame_payload(&f, b"{}").tier, Tier::Strong);
    let weak = Fake::new(
        vec![field("x WEAK", "json:a", false)],
        WsFieldCoverage::default(),
    );
    assert_eq!(scan_frame_payload(&weak, b"{}").tier, Tier::Weak);
}
