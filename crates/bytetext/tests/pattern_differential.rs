//! Differential over generated patterns: accept/reject (+ error text) and all submatch
//! spans over fixed haystacks. Replays a reference file; skips without
//! `WAFIO_REGEXP_ORACLE=<file>`.

use wafio_bytetext::pattern::CompiledRegex;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn fmt_matches(re: &CompiledRegex, hay: &[u8]) -> String {
    let ms = re.find_all_capture_spans(hay, -1);
    if ms.is_empty() {
        return "-".into();
    }
    let parts: Vec<String> = ms
        .iter()
        .map(|m| {
            m.iter()
                .flat_map(|g| match g {
                    Some((a, b)) => [a.to_string(), b.to_string()],
                    None => ["-1".to_string(), "-1".to_string()],
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .collect();
    parts.join(";")
}

#[test]
fn pattern_differential() {
    let Ok(path) = std::env::var("WAFIO_REGEXP_ORACLE") else {
        eprintln!("skipped: set WAFIO_REGEXP_ORACLE=<file>");
        return;
    };
    let data = std::fs::read_to_string(path).unwrap();
    let mut hays: Vec<Vec<u8>> = Vec::new();
    let (mut total, mut bad_accept, mut bad_reject, mut bad_err, mut bad_names, mut bad_match) =
        (0, 0, 0, 0, 0, 0);
    let mut shown = 0;
    let dump: usize = std::env::var("WAFIO_REGEXP_ORACLE_DUMP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    for line in data.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f[0] == "hays" {
            hays = f[1..].iter().map(|h| hex_to_bytes(h)).collect();
            continue;
        }
        total += 1;
        let pat = String::from_utf8(hex_to_bytes(f[1])).unwrap();
        let reference_ok = f[2] == "1";
        let compiled = std::panic::catch_unwind(|| CompiledRegex::compile(&pat));
        let mut problem: Option<String> = None;
        match compiled {
            Err(_) => problem = Some("panic".into()),
            Ok(Err(e)) => {
                if reference_ok {
                    bad_reject += 1;
                    problem = Some(format!("go accepts, rust rejects: {e}"));
                } else if e.as_bytes() != hex_to_bytes(f[3]).as_slice() {
                    bad_err += 1;
                    problem = Some(format!(
                        "error text go={} rust={e}",
                        String::from_utf8_lossy(&hex_to_bytes(f[3]))
                    ));
                }
            }
            Ok(Ok(re)) => {
                if !reference_ok {
                    bad_accept += 1;
                    problem = Some(format!(
                        "go rejects ({}), rust accepts",
                        String::from_utf8_lossy(&hex_to_bytes(f[3]))
                    ));
                } else {
                    let names: Vec<Vec<u8>> = f[5].split(',').map(hex_to_bytes).collect();
                    let rn: Vec<Vec<u8>> = re
                        .group_names()
                        .iter()
                        .map(|n| n.as_bytes().to_vec())
                        .collect();
                    if names != rn || re.group_count().to_string() != f[4] {
                        bad_names += 1;
                        problem = Some("subexp names".into());
                    } else {
                        let want: Vec<&str> = f[6].split('|').collect();
                        for (i, h) in hays.iter().enumerate() {
                            let got = fmt_matches(&re, h);
                            if got != want[i] {
                                bad_match += 1;
                                problem = Some(format!(
                                    "hay {i} {:?}: go={} rust={got}",
                                    String::from_utf8_lossy(h),
                                    want[i]
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }
        if let Some(p) = problem
            && shown < dump
        {
            shown += 1;
            eprintln!("MISMATCH {pat:?}: {p}");
        }
    }
    eprintln!(
        "regexp differential: {total} patterns; go-accept/rust-reject {bad_reject}, go-reject/rust-accept {bad_accept}, error text {bad_err}, names {bad_names}, match {bad_match}"
    );
    assert_eq!(bad_accept + bad_reject + bad_names + bad_match, 0);
}
