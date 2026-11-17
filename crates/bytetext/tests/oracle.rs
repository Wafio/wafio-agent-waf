//! Replays a reference file for the `go.*` and `re.*` kinds. Skipped unless CORE_ORACLE=<file>
//! is set. Composite results: fields joined with "\0"; an error appends "\0ERR:" + its message;
//! booleans are "1"/"0".

use std::collections::BTreeMap;
use wafio_bytetext::base64::{STANDARD, STANDARD_NO_PAD, URL_SAFE};
use wafio_bytetext::pattern::CompiledRegex;
use wafio_bytetext::{hex, html, literal, norm, strings, url};

fn hex_to_bytes(s: &str) -> Vec<u8> {
    hex::decode(s.as_bytes()).expect("oracle hex")
}

fn with_err(mut v: Vec<u8>, err: Option<String>) -> Vec<u8> {
    if let Some(e) = err {
        v.extend_from_slice(b"\0ERR:");
        v.extend_from_slice(e.as_bytes());
    }
    v
}

fn b(x: bool) -> Vec<u8> {
    if x { b"1".to_vec() } else { b"0".to_vec() }
}

fn idx(x: Option<usize>) -> Vec<u8> {
    x.map_or(b"-1".to_vec(), |v| v.to_string().into_bytes())
}

fn reference_kind(kind: &str, a: &[Vec<u8>]) -> Option<Vec<u8>> {
    let s = &a[0];
    Some(match kind {
        "go.lower" => strings::to_lowercase(s),
        "go.upper" => strings::to_uppercase(s),
        "go.trimspace" => strings::trim_whitespace(s).to_vec(),
        "go.fields" => strings::join(&strings::split_whitespace(s), b"\0"),
        "go.trim" => strings::trim_chars(s, b"'\"`").to_vec(),
        "go.trimu" => strings::trim_chars(s, " é\u{a0}".as_bytes()).to_vec(),
        "go.tovalid" => strings::replace_invalid_utf8(s, b"?"),
        "go.indexany" => idx(strings::find_any_of(s, b"\xff<\xc3\xa9")),
        "go.equalfold" => b(strings::eq_ignore_case(s, &a[1])),
        "go.qunescape" => match url::unescape_query_component(s) {
            Ok(v) => v,
            Err(e) => with_err(Vec::new(), Some(e.to_string())),
        },
        "go.punescape" => match url::unescape_path_segment(s) {
            Ok(v) => v,
            Err(e) => with_err(Vec::new(), Some(e.to_string())),
        },
        "go.parsequery" => {
            let (vals, err) = url::parse_query(s);
            let mut out = Vec::new();
            for (k, vs) in &vals {
                out.extend_from_slice(k);
                out.push(1);
                out.extend_from_slice(&strings::join(vs, b"\x02"));
                out.push(3);
            }
            with_err(out, err.map(|e| e.to_string()))
        }
        "go.html" => html::unescape(s),
        "go.unquote" => match literal::unquote(s) {
            Ok(v) => v,
            Err(e) => with_err(Vec::new(), Some(e.to_string())),
        },
        "go.unquoteq" => match literal::unquote(&[b"\"", s.as_slice(), b"\""].concat()) {
            Ok(v) => v,
            Err(e) => with_err(Vec::new(), Some(e.to_string())),
        },
        "go.quote" => literal::quote(s),
        "go.atoi" => match literal::parse_decimal(s) {
            Ok(v) => v.to_string().into_bytes(),
            Err(e) => with_err(e.value.to_string().into_bytes(), Some(e.to_string())),
        },
        "go.parseint0" => match literal::parse_int(s, 0, 64) {
            Ok(v) => v.to_string().into_bytes(),
            Err(e) => with_err(e.value.to_string().into_bytes(), Some(e.to_string())),
        },
        "go.parseint16" => match literal::parse_int(s, 16, 32) {
            Ok(v) => v.to_string().into_bytes(),
            Err(e) => with_err(e.value.to_string().into_bytes(), Some(e.to_string())),
        },
        "go.b64std" | "go.b64raw" | "go.b64url" => {
            let enc = match kind {
                "go.b64std" => &STANDARD,
                "go.b64raw" => &STANDARD_NO_PAD,
                _ => &URL_SAFE,
            };
            let (d, e) = enc.decode_partial(s);
            with_err(d, e.map(|e| e.to_string()))
        }
        "go.hex" => {
            let (d, e) = hex::decode_partial(s);
            with_err(d, e.map(|e| e.to_string()))
        }
        "go.nfkc" => norm::NFKC.normalize(s),
        "go.nfkd" => norm::NFKD.normalize(s),
        "go.nfc" => norm::NFC.normalize(s),
        "go.nfd" => norm::NFD.normalize(s),
        _ => return None,
    })
}

fn fmt_sub(m: &[Vec<Option<(usize, usize)>>]) -> Vec<u8> {
    let mut out = String::new();
    for g in m {
        let parts: Vec<String> = g
            .iter()
            .flat_map(|x| match x {
                Some((a, b)) => [a.to_string(), b.to_string()],
                None => ["-1".to_string(), "-1".to_string()],
            })
            .collect();
        out.push_str(&parts.join(","));
        out.push(';');
    }
    out.into_bytes()
}

#[test]
fn reference_oracle() {
    let Ok(path) = std::env::var("CORE_ORACLE") else {
        eprintln!("CORE_ORACLE not set; skipped");
        return;
    };
    let data = std::fs::read_to_string(&path).expect("read oracle");
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut shown: BTreeMap<String, usize> = BTreeMap::new();
    let mut probes: Vec<Vec<u8>> = Vec::new();
    let mut cache: BTreeMap<Vec<u8>, CompiledRegex> = BTreeMap::new();
    let mut compile_errors = 0;
    let mut cur: Vec<u8> = Vec::new();
    for line in data.lines() {
        let mut it = line.split('\t');
        let kind = it.next().unwrap_or_default().to_string();
        let mut f: Vec<Vec<u8>> = it.map(hex_to_bytes).collect();
        match kind.as_str() {
            "in" => {
                cur = f.pop().expect("input");
                continue;
            }
            "re.probe" => {
                probes.push(f[0].clone());
                continue;
            }
            _ if kind.starts_with("go.") => f.insert(0, cur.clone()),
            _ if kind.starts_with("re.") => {}
            _ => continue,
        }
        let (args, want) = (&f[..f.len() - 1], &f[f.len() - 1]);
        let got: Vec<u8> = if kind.starts_with("go.") {
            match reference_kind(&kind, args) {
                Some(g) => g,
                None => panic!("unhandled oracle kind {kind}"),
            }
        } else {
            let pat = String::from_utf8(args[0].clone()).expect("utf8 pattern");
            let re = match cache.get(args[0].as_slice()) {
                Some(r) => r.clone(),
                None => match CompiledRegex::compile(&pat) {
                    Ok(r) => {
                        cache.insert(args[0].clone(), r.clone());
                        r
                    }
                    Err(e) => {
                        compile_errors += 1;
                        eprintln!("COMPILE {e}");
                        continue;
                    }
                },
            };
            match kind.as_str() {
                "re.match" => probes
                    .iter()
                    .map(|p| if re.is_match(p) { b'1' } else { b'0' })
                    .collect(),
                "re.sub" => {
                    let j: usize = String::from_utf8_lossy(&args[1])
                        .parse()
                        .expect("probe index");
                    let p = &probes[j];
                    let mut g = fmt_sub(&re.find_all_capture_spans(p, -1));
                    // the line carries (indices, replacement) as two fields: compare both
                    if args.len() == 3 {
                        g = [g, b"\0".to_vec(), re.replace_all(p, b"<$1>")].concat();
                        let w = [args[2].clone(), b"\0".to_vec(), want.clone()].concat();
                        let e = counts.entry(kind.clone()).or_default();
                        e.0 += 1;
                        if g != w {
                            e.1 += 1;
                            let n = shown.entry(kind.clone()).or_default();
                            if *n < 20 {
                                *n += 1;
                                eprintln!(
                                    "MISMATCH {kind} /{pat}/ on {:?}\n  go:   {:?}\n  rust: {:?}",
                                    String::from_utf8_lossy(p),
                                    String::from_utf8_lossy(&w),
                                    String::from_utf8_lossy(&g)
                                );
                            }
                        }
                        continue;
                    }
                    g
                }
                _ => panic!("unhandled oracle kind {kind}"),
            }
        };
        let e = counts.entry(kind.clone()).or_default();
        e.0 += 1;
        if &got != want {
            e.1 += 1;
            let n = shown.entry(kind.clone()).or_default();
            if *n < 20 {
                *n += 1;
                if kind == "re.match" {
                    let pat = String::from_utf8_lossy(&args[0]);
                    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
                        if g != w {
                            eprintln!(
                                "MISMATCH re.match /{pat}/ on {:?}: go {} rust {}",
                                String::from_utf8_lossy(&probes[i]),
                                *w as char,
                                *g as char
                            );
                            break;
                        }
                    }
                } else {
                    eprintln!(
                        "MISMATCH {kind} {:?}\n  go:   {:?}\n  rust: {:?}",
                        args.iter()
                            .map(|a| String::from_utf8_lossy(a).into_owned())
                            .collect::<Vec<_>>(),
                        String::from_utf8_lossy(want),
                        String::from_utf8_lossy(&got)
                    );
                }
            }
        }
    }
    let mut bad = compile_errors;
    for (k, (n, m)) in &counts {
        eprintln!("{k}: {n} cases, {m} mismatches");
        bad += m;
    }
    eprintln!("regexp compile errors: {compile_errors}");
    assert_eq!(bad, 0, "oracle mismatches");
}
