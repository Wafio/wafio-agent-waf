//! Regression tests for review findings: regexp syntax acceptance and program size, glob matching
//! and float parsing in custom rule operators. Expected values are what the control plane's
//! regexp engine, glob matching and float parsing give (from the review's differential).

use wafio_engine_rules::*;

fn build_path_rule(id: &str, pattern: &str) -> CustomGuiRule {
    CustomGuiRule {
        id: id.into(),
        enabled: true,
        action: "block".into(),
        conditions: vec![RuleCondition {
            field: "path".into(),
            operator: "regex".into(),
            value: pattern.into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn eval(pattern: &str, path: &str) -> (String, String) {
    let ctx = RequestRuleContext {
        path: path.as_bytes().to_vec(),
        ..Default::default()
    };
    evaluate_gui_rules(&[build_path_rule("r", pattern)], &ctx)
}

#[test]
fn gui_regex_rules_follow_reference_parser_and_budget() {
    // Nested repetition is rejected: the rule never matches.
    assert_eq!(eval("^/admin+*$", "/admin"), (String::new(), String::new()));
    // `[` inside a class is a literal: 304 instructions, over the 256 budget.
    let big = format!("[[a]{}]", "x".repeat(300));
    assert_eq!(
        eval(&big, &format!("/a{}]", "x".repeat(300))),
        (String::new(), String::new())
    );
    // (?i) literals fold to one rune before prefix factoring: 134 instructions, accepted.
    let fold = format!("(?i)(?:a{}|A{})", "b".repeat(130), "b".repeat(130));
    assert_eq!(
        eval(&fold, &format!("/a{}", "b".repeat(130))),
        ("block".into(), "r".into())
    );
    // \p{^Greek} is accepted.
    assert_eq!(
        eval("^/\\p{^Greek}+$", "/abc"),
        ("block".into(), "r".into())
    );
}

#[test]
fn path_exception_regex_validation_follows_reference() {
    let bad =
        br#"{"path_exceptions":[{"path":"/admin+*","match":"regex","disable_semantic":true}]}"#;
    let e = check_rules_json(bad).unwrap_err().to_string();
    assert!(e.contains("path_exceptions[0].path invalid regex: error parsing regexp: invalid nested repetition operator: `+*`"), "{e}");
    let ok = br#"{"path_exceptions":[{"path":"^/\\p{^Greek}+$","match":"regex","block":{}}]}"#;
    assert!(check_rules_json(ok).is_ok());
    let lr = load_rules_json(ok).unwrap();
    assert!(find_exception_for_raw_target(b"/abc", &lr.path_exceptions).is_some());
}

#[test]
fn rule_regex_errors_match_reference_texts() {
    assert_eq!(
        unusable_pattern_error("(?x)a b"),
        "error parsing regexp: invalid or unsupported Perl syntax: `(?x`"
    );
    assert_eq!(
        unusable_pattern_error("a{2}{3}"),
        "error parsing regexp: invalid nested repetition operator: `{2}{3}`"
    );
    assert_eq!(unusable_pattern_error("\\p{^Greek}"), "");
}

#[test]
fn wildcard_follows_glob_match() {
    for (p, v, want) in [
        ("[]a]", "a", false),
        ("[]a]", "]", false),
        ("[a-]", "-", false),
        ("[-a]", "-", false),
        ("[x-]", "x", false),
        ("[a-c-e]", "-", false),
        ("[\\]]", "]", true),
        ("[é]", "é", true),
        ("[à-ÿ]", "é", true),
        ("caf?", "café", true),
        ("?", "ß", true),
        ("*.php", "index.php", true),
        ("*.php", "a/index.php", false),
        ("a*b*c", "axxbyyc", true),
        ("\\", "", false),
    ] {
        for cs in [true, false] {
            assert_eq!(
                evaluate_operator("wildcard", p.as_bytes(), v.as_bytes(), cs),
                want,
                "{p:?} {v:?} cs={cs}"
            );
        }
    }
    assert_eq!(glob_match(b"[]a]", b""), None);
    assert_eq!(glob_match(b"*", b""), Some(true));
    assert_eq!(glob_match(b"a[", b"x"), None); // the whole chunk is read after a mismatch
}

#[test]
fn num_operators_follow_finite_number_parse() {
    for s in [
        "1_000",
        "+1_000",
        "1_0.5",
        "1e1_0",
        "0x_1p0",
        "0x1p4",
        "0X1P-2",
        "0x1.8p1",
        "inf",
        "-Infinity",
        "1.",
        ".5",
    ] {
        assert!(
            evaluate_operator("num_ge", s.as_bytes(), s.as_bytes(), true),
            "num_ge {s}"
        );
    }
    assert!(evaluate_operator("num_gt", b"0", b"1_000", true));
    assert!(evaluate_operator("num_gt", b"0x1p4 ", b"+1_000", true));
    for s in [
        "_1", "1_", "1__0", "0x1", "+nan", "infx", "1e", "1e400", "0x1p2000", "", ".",
    ] {
        assert_eq!(parse_finite_number(s), None, "{s}");
    }
    assert_eq!(parse_finite_number("0x1.8p1"), Some(3.0));
    assert_eq!(parse_finite_number("0X1P-2"), Some(0.25));
    assert_eq!(parse_finite_number("1_000.5"), Some(1000.5));
    assert!(parse_finite_number("nAn").unwrap().is_nan());
}

/// Replays a recorded differential (regexp size, error and matches, glob matching, float
/// parsing); skipped unless WAFIO_RULES_REVIEW_DIFF names the JSONL file. Match divergences are
/// bytetext's and only counted.
#[test]
fn reference_differential_replay() {
    use wafio_engine_rules::pattern_compile::{compile, program_size};
    let Ok(path) = std::env::var("WAFIO_RULES_REVIEW_DIFF") else {
        return;
    };
    let data = std::fs::read_to_string(path).unwrap();
    let (mut n, mut bad, mut match_bad) = (0, Vec::new(), 0);
    for line in data.lines() {
        let rec: serde_json::Value = serde_json::from_str(line).unwrap();
        n += 1;
        match rec["k"].as_str().unwrap() {
            "re" => {
                let p = rec["p"].as_str().unwrap();
                let got = program_size(p);
                let want = rec["n"].as_i64().unwrap();
                let same = match &got {
                    Ok(k) => *k as i64 == want,
                    Err(e) => want == -1 && e == rec["err"].as_str().unwrap(),
                };
                if !same {
                    bad.push(format!(
                        "re {p:?}: go n={want} err={} rust={got:?}",
                        rec["err"]
                    ));
                }
                if let Some(m) = rec.get("m").and_then(|m| m.as_array()) {
                    let probes = [
                        "", "a", "ab", "abc", "A", "k", "\u{212a}", "é", "σ", "x0", "-", "aa", "Σ",
                        "a b", "\n",
                    ];
                    match compile(p) {
                        Ok(re) => {
                            if probes
                                .iter()
                                .zip(m)
                                .any(|(s, w)| re.is_match(s.as_bytes()) != w.as_bool().unwrap())
                            {
                                match_bad += 1;
                                eprintln!("MATCH {p:?}");
                            }
                        }
                        Err(e) => {
                            match_bad += 1;
                            eprintln!("MATCH {p:?}: rust compile error {e}");
                        }
                    }
                }
            }
            "wc" => {
                let (p, s) = (rec["p"].as_str().unwrap(), rec["s"].as_str().unwrap());
                let want = if rec["err"].as_bool().unwrap() {
                    None
                } else {
                    Some(rec["ok"].as_bool().unwrap())
                };
                let got = glob_match(p.as_bytes(), s.as_bytes());
                if got != want {
                    bad.push(format!("wc {p:?} {s:?}: go {want:?} rust {got:?}"));
                }
            }
            _ => {
                let s = rec["s"].as_str().unwrap();
                let want = rec.get("v").and_then(|v| v.as_str()).map(str::to_string);
                let got = parse_finite_number(s).map(|f| {
                    if f.is_nan() {
                        "NaN".to_string()
                    } else {
                        format!("{:x}", f.to_bits())
                    }
                });
                if got != want {
                    bad.push(format!("pf {s:?}: go {want:?} rust {got:?}"));
                }
            }
        }
    }
    for b in bad.iter().take(40) {
        eprintln!("MISMATCH {b}");
    }
    eprintln!(
        "review differential: {n} cases, {} mismatches, {match_bad} regex match divergences (bytetext)",
        bad.len()
    );
    assert!(bad.is_empty());
}
