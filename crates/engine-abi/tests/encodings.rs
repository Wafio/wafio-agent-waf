//! The encodings round-trip, and decoders meet random and damaged buffers without a panic. The random data comes from a
//! generator with a fixed seed, so a failure repeats.

use std::sync::Arc;

use wafio_engine_abi::config::{self, KEYS, WORDS};
use wafio_engine_abi::wire::*;
use wafio_engine_api::{
    FrameCoverage, FrameField, Held, ScanCoverage, ScanOutcome, SemanticConfig, SemanticScanResult,
    SqlPolicy, SsrfBlocklist, SsrfConfig, Tier,
};

/// xorshift64*: enough for test data.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn flag(&mut self) -> bool {
        self.next() & 1 == 1
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = if self.below(4) == 0 {
            0
        } else {
            self.below(max + 1)
        };
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn text(&mut self, max: usize) -> String {
        let n = self.below(max + 1);
        let mut s = String::new();
        for _ in 0..n {
            s.push(char::from_u32(0x20 + self.below(0x60) as u32).unwrap());
        }
        if self.flag() {
            s.push('é');
        }
        s
    }
}

fn random_coverage(r: &mut Rng) -> ScanCoverage {
    ScanCoverage {
        truncated: r.flag(),
        engine_panic: r.flag(),
        budget: r.flag(),
        field_cap: r.flag(),
        query_cap: r.flag(),
        body_skipped: if r.flag() { r.text(12) } else { String::new() },
        binary_text: r.flag(),
        transport: if r.flag() { r.text(12) } else { String::new() },
        header_count: r.flag(),
        header_len: r.flag(),
        header_skip: r.flag(),
        regex_budget: r.flag(),
        body_scan_gap: r.flag(),
        other_scan_gap: r.flag(),
        engine_absent: r.flag(),
    }
}

fn random_tier(r: &mut Rng) -> Tier {
    [Tier::Clean, Tier::Weak, Tier::Strong][r.below(3)]
}

fn random_outcome(r: &mut Rng) -> ScanOutcome {
    let finding = r.flag();
    ScanOutcome {
        tier: if finding { random_tier(r) } else { Tier::Clean },
        reason: if finding { r.text(24) } else { String::new() },
        detail: if finding { r.bytes(64) } else { Vec::new() },
        source: if finding { r.bytes(24) } else { Vec::new() },
        source_exact: r.flag(),
        value: if finding { r.bytes(300) } else { Vec::new() },
        coverage: random_coverage(r),
        held: r.flag().then(|| Held {
            reason: r.text(24),
            detail: r.bytes(32),
            source: r.bytes(16),
            source_exact: r.flag(),
            value: r.bytes(64),
        }),
    }
}

fn same(a: &ScanOutcome, b: &ScanOutcome) -> bool {
    // ScanOutcome has no PartialEq; its Debug form carries every field.
    format!("{a:?}") == format!("{b:?}")
}

#[test]
fn an_outcome_decodes_to_what_was_encoded() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..5_000 {
        let o = random_outcome(&mut r);
        let mut buf = Vec::new();
        encode_outcome(&o, &mut buf);
        let back = decode_outcome(&buf).expect("a valid encoding decodes");
        assert!(same(&o, &back), "{o:?} != {back:?}");
    }
}

#[test]
fn an_outcome_of_no_finding_is_five_bytes_and_decodes_without_allocating_text() {
    let mut buf = Vec::new();
    encode_outcome(&ScanOutcome::default(), &mut buf);
    assert_eq!(buf, [0, 0, 0, 0, 0]);
    let o = decode_outcome(&buf).unwrap();
    assert_eq!(
        (o.tier, o.reason.capacity(), o.detail.capacity()),
        (Tier::Clean, 0, 0)
    );
}

#[test]
fn random_and_damaged_buffers_never_panic_a_decoder() {
    let mut r = Rng(0xdead_beef_cafe_f00d);
    let calls = |buf: &[u8]| {
        let _ = decode_outcome(buf);
        let _ = decode_frame_fields(buf);
        let _ = decode_scan_value(buf, |_| "");
        let _ = decode_ssrf(buf);
    };
    for _ in 0..20_000 {
        calls(&r.bytes(200));
    }
    for _ in 0..3_000 {
        let o = random_outcome(&mut r);
        let mut buf = Vec::new();
        encode_outcome(&o, &mut buf);
        // every cut
        for n in 0..buf.len().min(80) {
            assert!(
                decode_outcome(&buf[..n]).is_err(),
                "a cut at {n} must not decode"
            );
        }
        // a flipped byte, a flipped length
        for _ in 0..8 {
            let mut d = buf.clone();
            let at = r.below(d.len());
            d[at] ^= 1 << r.below(8);
            calls(&d);
        }
        let mut d = buf.clone();
        d.extend_from_slice(&r.bytes(8));
        calls(&d);
    }
    // A length that claims 4 GiB in a short buffer.
    let mut huge = vec![0b0000_0001, 0, 0, 0, 0];
    huge.extend_from_slice(&1i64.to_le_bytes());
    huge.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(decode_outcome(&huge), Err(DecodeError::Truncated)));
    let mut count = vec![0u8, 0, 0];
    count.extend_from_slice(&u32::MAX.to_le_bytes());
    count.extend_from_slice(&0u32.to_le_bytes());
    assert!(decode_frame_fields(&count).is_err());
}

#[test]
fn frame_fields_round_trip() {
    let mut r = Rng(7);
    for _ in 0..2_000 {
        let cov = FrameCoverage {
            field_capped: r.flag(),
            skipped: if r.flag() { r.text(10) } else { String::new() },
            binary_text: r.flag(),
        };
        let fields: Vec<FrameField> = (0..r.below(6))
            .map(|_| FrameField {
                value: r.bytes(80),
                source: r.bytes(20),
                summary: r.flag(),
            })
            .collect();
        let mut buf = Vec::new();
        encode_frame_fields(&fields, &cov, &mut buf);
        let (f2, c2) = decode_frame_fields(&buf).unwrap();
        assert_eq!((fields, cov), (f2, c2));
    }
}

#[test]
fn a_value_scan_round_trips_and_the_reason_is_mapped_to_a_static_string() {
    let mut r = Rng(11);
    for _ in 0..1_000 {
        let s = SemanticScanResult {
            tier: random_tier(&mut r),
            reason: "SEMANTIC_SQL",
            detail: r.bytes(40),
            truncated: r.flag(),
            engine_panicked: r.flag(),
            budget_exhausted: r.flag(),
            engines: r.next() as i64,
        };
        let mut buf = Vec::new();
        encode_scan_value(&s, &mut buf);
        let back = decode_scan_value(&buf, |t| {
            assert_eq!(t, "SEMANTIC_SQL");
            "SEMANTIC_SQL"
        })
        .unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn an_ssrf_list_round_trips() {
    let mut list = SsrfBlocklist::default();
    list.add_host(b"Metadata.Internal ");
    list.add_host(b"10.0.0.1");
    list.add_suffix(b".corp.example");
    let back = decode_ssrf(&encode_ssrf(&list)).unwrap();
    assert_eq!((&back.hosts, &back.suffixes), (&list.hosts, &list.suffixes));
}

fn random_config(r: &mut Rng) -> SemanticConfig {
    let key = |r: &mut Rng| KEYS[r.below(KEYS.len())].to_string();
    SemanticConfig {
        sql_semantic_policy: r.flag().then(|| SqlPolicy {
            block_threshold: r.below(100) as f64 / 7.0,
            soft_threshold: r.below(100) as f64 / 3.0,
        }),
        disabled_engines: r
            .flag()
            .then(|| (0..r.below(6)).map(|_| (key(r), r.flag())).collect()),
        log_only_engines: r.flag().then(|| (0..r.below(4)).map(|_| key(r)).collect()),
        ssrf_config: r.flag().then(|| Arc::new(SsrfConfig::default())),
        engine_parse_work_budget: r.below(5) as i64 - 1,
        ..Default::default()
    }
}

#[test]
fn a_configuration_row_decodes_to_a_configuration_that_reads_the_same() {
    let mut r = Rng(31);
    for _ in 0..3_000 {
        let c = random_config(&mut r);
        let w = config::encode(&c, 0x1234);
        let d =
            config::decode(&w, b"", c.ssrf_config.clone()).expect("a row of this version decodes");
        // The row is a function of what the engines read, so a second row equals the first.
        assert_eq!(config::encode(&d, 0x1234), w);
        for k in KEYS {
            assert_eq!(c.is_disabled(k), d.is_disabled(k), "{k}");
            assert_eq!(c.is_log_only(k), d.is_log_only(k), "{k}");
        }
        assert_eq!(c.log_only_engines.is_some(), d.log_only_engines.is_some());
        assert_eq!(c.sql_semantic_policy, d.sql_semantic_policy);
        assert_eq!(c.engine_parse_work_budget, d.engine_parse_work_budget);
    }
}

#[test]
fn a_row_with_a_bit_this_version_does_not_know_is_refused() {
    let mut w = config::encode(&SemanticConfig::default(), 0);
    assert!(config::decode(&w, b"", None).is_some());
    w[1] |= 1 << 40;
    assert!(config::decode(&w, b"", None).is_none());
    w[1] = 0;
    w[2] = 1 << 30;
    assert!(config::decode(&w, b"", None).is_none());
    assert_eq!(w.len(), WORDS);
}
