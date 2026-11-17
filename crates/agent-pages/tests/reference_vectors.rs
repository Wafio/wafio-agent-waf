//! Compares against reference vectors. Opt-in: WAFIO_GOLDEN_PAGES_VECTORS=<file>.

use serde_json::Value;
use wafio_agent_pages::block_response::render_block_response;
use wafio_agent_pages::challenge::*;
use wafio_agent_pages::challenge_replay::{network_key_for_client, parse_cookie_network_limit};
use wafio_agent_pages::crypto::{B64, Gcm, decode_base64_partial, hex_decode};
use wafio_agent_pages::field_names::FormField;
use wafio_agent_pages::field_paths::*;
use wafio_agent_pages::goodbot::ranges_from_cidrs;
use wafio_agent_pages::iprep::{parse_dotted_quad, parse_netset_partial};

fn b(v: &Value) -> Vec<u8> {
    let (out, ok) = decode_base64_partial(B64::Std, v.as_str().expect("base64 string").as_bytes());
    assert!(ok);
    out
}

fn s(v: &Value) -> &str {
    v.as_str().expect("string")
}

fn fields(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap().to_string())
        .collect()
}

fn rules(action: &str, fs: &[String]) -> Vec<RequestFieldRule> {
    fs.iter()
        .map(|f| RequestFieldRule {
            field: f.clone(),
            source: "any".into(),
            action: action.into(),
            cipher_key_hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                .into(),
            methods: vec![],
        })
        .collect()
}

fn show(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn challenge_settings(i: i64) -> Option<ChallengeSettings> {
    let mut c = ChallengeSettings::default();
    match i {
        0 => return None,
        1 => {
            (
                c.waf_block_format,
                c.policy_block_format,
                c.geo_block_format,
            ) = ("json".into(), "xml".into(), "json".into())
        }
        2 => {
            (
                c.waf_block_format,
                c.policy_block_format,
                c.geo_block_format,
            ) = ("xml".into(), "json".into(), "xml".into())
        }
        _ => {
            c.custom_block_html =
                "<p>{{WAFIO_SCORE}} {{WAFIO_CATEGORIES}} {{WAFIO_METHOD}} {{WAFIO_DETAIL}} {{WAFIO_CWE}} {{WAFIO_MESSAGE}}</p>".into();
            c.custom_policy_block_html = "P {{WAFIO_MESSAGE}}".into();
            c.custom_geo_block_html = "G {{WAFIO_MESSAGE}}".into();
        }
    }
    Some(c)
}

#[test]
fn reference_vectors() {
    let Ok(path) = std::env::var("WAFIO_GOLDEN_PAGES_VECTORS") else {
        eprintln!("WAFIO_GOLDEN_PAGES_VECTORS not set: skipped");
        return;
    };
    let text = std::fs::read_to_string(path).unwrap();
    let mut failures = Vec::new();
    let mut n = 0;
    for line in text.lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        n += 1;
        let kind = s(&v["kind"]);
        let mut check = |name: &str, got: Vec<u8>, want: Vec<u8>| {
            if got != want {
                failures.push(format!(
                    "{kind}/{name}: input {line}\n got  {:?}\n want {:?}",
                    show(&got),
                    show(&want)
                ));
            }
        };
        match kind {
            "gcm" => {
                let key: [u8; 32] = hex_decode(s(&v["key"]).as_bytes())
                    .unwrap()
                    .try_into()
                    .unwrap();
                check(
                    "seal",
                    Gcm::new(&key).seal(Vec::new(), &b(&v["nonce"]), &b(&v["pt"])),
                    b(&v["out"]),
                );
            }
            "instance_secret" => {
                let inst: [u8; 32] = hex_decode(s(&v["secret"]).as_bytes())
                    .unwrap()
                    .try_into()
                    .unwrap();
                set_instance_secret(inst);
            }
            "pow_token" => {
                let now = v["now"].as_i64().unwrap();
                let ok = check_pow_token(
                    s(&v["secret"]),
                    s(&v["scope"]).as_bytes(),
                    &b(&v["token"]),
                    now,
                )
                .map(|(_, d)| d);
                check("valid", format!("{ok:?}").into_bytes(), b"Some(3)".to_vec());
            }
            "pow_token_scope" => {
                let got = check_pow_token(
                    s(&v["secret"]),
                    s(&v["scope"]).as_bytes(),
                    &b(&v["token"]),
                    v["now"].as_i64().unwrap(),
                );
                let want = v["ok"]
                    .as_bool()
                    .unwrap()
                    .then(|| v["diff"].as_i64().unwrap());
                check(
                    "scope",
                    format!("{:?}", got.map(|(_, d)| d)).into_bytes(),
                    format!("{want:?}").into_bytes(),
                );
            }
            "pow_parse" => {
                let got = check_pow_token(
                    s(&v["secret"]),
                    s(&v["scope"]).as_bytes(),
                    &b(&v["in"]),
                    v["now"].as_i64().unwrap(),
                );
                let want = v["ok"].as_bool().unwrap().then(|| {
                    (
                        s(&v["salt"]).as_bytes().to_vec(),
                        v["diff"].as_i64().unwrap(),
                    )
                });
                check(
                    "parse",
                    format!("{got:?}").into_bytes(),
                    format!("{want:?}").into_bytes(),
                );
            }
            "cookie" => {
                let out = b(&v["out"]);
                let exp: i64 = show(&out).split(':').next().unwrap().parse().unwrap();
                let ttl = v["ttl"].as_i64().unwrap();
                let (secret, scope) = (s(&v["secret"]), s(&v["scope"]).as_bytes());
                let id: [u8; 8] = hex_decode(show(&out).split(':').nth(1).unwrap().as_bytes())
                    .unwrap()
                    .try_into()
                    .unwrap();
                check(
                    "gen",
                    issue_challenge_cookie_with_lifetime_from(secret, scope, ttl, id, exp - ttl),
                    out.clone(),
                );
                check(
                    "valid",
                    vec![verify_challenge_cookie(secret, scope, &out, exp) as u8],
                    vec![1],
                );
            }
            "cookie_parse" => {
                let got = decode_challenge_cookie(
                    s(&v["secret"]),
                    s(&v["scope"]).as_bytes(),
                    &b(&v["in"]),
                    v["now"].as_i64().unwrap(),
                );
                let want = v["ok"]
                    .as_bool()
                    .unwrap()
                    .then(|| (s(&v["id"]).as_bytes().to_vec(), v["exp"].as_i64().unwrap()));
                check(
                    "parse",
                    format!("{got:?}").into_bytes(),
                    format!("{want:?}").into_bytes(),
                );
            }
            "network_key" => check("key", network_key_for_client(&b(&v["ip"])), b(&v["out"])),
            "max_networks" => check(
                "limit",
                parse_cookie_network_limit(&show(&b(&v["in"])))
                    .0
                    .to_string()
                    .into_bytes(),
                v["out"].to_string().into_bytes(),
            ),
            "submission" => {
                let (ok, bot, score, reasons) = verify_challenge_submission(
                    s(&v["secret"]),
                    b"",
                    &b(&v["token"]),
                    s(&v["solution"]).as_bytes(),
                    &b(&v["tel"]),
                    s(&v["hless"]).as_bytes(),
                    v["now"].as_i64().unwrap(),
                );
                let got = format!("{ok} {bot} {score} {}", reasons.join(","));
                let want = format!(
                    "{} {} {} {}",
                    v["verified"],
                    v["bot"],
                    v["score"],
                    s(&v["reasons"])
                );
                check("result", got.into_bytes(), want.into_bytes());
            }
            "pow" => {
                let got = check_pow_solution(
                    s(&v["salt"]).as_bytes(),
                    v["sol"].as_i64().unwrap(),
                    v["diff"].as_i64().unwrap(),
                );
                check(
                    "ok",
                    vec![got as u8],
                    vec![v["ok"].as_bool().unwrap() as u8],
                );
            }
            "page_js" => check(
                "page",
                render_js_challenge_page(&b(&v["nonce"]), &b(&v["redirect"])),
                b(&v["out"]),
            ),
            "page_adaptive_js" => check(
                "page",
                render_adaptive_js_page(&b(&v["nonce"]), &b(&v["redirect"])),
                b(&v["out"]),
            ),
            "page_turnstile" => check(
                "page",
                render_turnstile_page(&b(&v["site"]), &b(&v["nonce"]), &b(&v["redirect"])),
                b(&v["out"]),
            ),
            "page_hcaptcha" => check(
                "page",
                render_hcaptcha_page(&b(&v["site"]), &b(&v["nonce"]), &b(&v["redirect"])),
                b(&v["out"]),
            ),
            "page_sim" => check(
                "page",
                render_simulation_page(&b(&v["redirect"])),
                b(&v["out"]),
            ),
            "inject_js" => check(
                "inject",
                render_js_challenge_inline(&b(&v["nonce"]), &b(&v["redirect"])),
                b(&v["out"]),
            ),
            "safe_redirect" => check(
                "redirect",
                sanitize_redirect_target(&b(&v["in"])),
                b(&v["out"]),
            ),
            "inject_custom" => check(
                "inject",
                fill_custom_page(&b(&v["page"]), b"{{WAFIO_INJECT}}", &b(&v["inject"])),
                b(&v["out"]),
            ),
            "page_click" | "page_adaptive_click" | "click_widget" => {
                let seed: [u8; 16] = hex_decode(s(&v["seed"]).as_bytes())
                    .unwrap()
                    .try_into()
                    .unwrap();
                let exp = i64::from_str_radix(s(&v["expiry_hex"]), 16).unwrap();
                let p = issue_click_puzzle_token_from(
                    s(&v["secret"]),
                    s(&v["scope"]).as_bytes(),
                    seed,
                    exp - 300,
                );
                let got = match kind {
                    "page_click" => render_click_page_from(&p, b"/r", b""),
                    "page_adaptive_click" => render_adaptive_click_page_from(
                        &p,
                        b"/r",
                        "Incorrect selection — please try again.".as_bytes(),
                    ),
                    _ => render_click_puzzle_widget_from(&p, b"/w", b"err", b"<x>"),
                };
                check("page", got, b(&v["out"]));
            }
            "click_token" => {
                let token = b(&v["token"]);
                let seed: [u8; 16] = hex_decode(&token[..32]).unwrap().try_into().unwrap();
                let exp = i64::from_str_radix(show(&token).split('|').nth(3).unwrap(), 16).unwrap();
                let p = issue_click_puzzle_token_from(
                    s(&v["secret"]),
                    s(&v["scope"]).as_bytes(),
                    seed,
                    exp - 300,
                );
                check("token", p.token, token);
                check("sig", p.sig, s(&v["sig"]).as_bytes().to_vec());
                check(
                    "label",
                    p.target_label.into_bytes(),
                    s(&v["label"]).as_bytes().to_vec(),
                );
            }
            "click_check" => {
                let (secret, scope, token) =
                    (s(&v["secret"]), s(&v["scope"]).as_bytes(), b(&v["token"]));
                let now = v["now"].as_i64().unwrap();
                let ok = check_click_puzzle_token(
                    secret,
                    scope,
                    &token,
                    s(&v["sig"]).as_bytes(),
                    &b(&v["csv"]),
                    now,
                );
                check(
                    "answer",
                    vec![ok as u8],
                    vec![v["ok"].as_bool().unwrap() as u8],
                );
                let exp = click_puzzle_expiry(secret, scope, &token, now);
                let want = v["exp_ok"]
                    .as_bool()
                    .unwrap()
                    .then(|| v["exp"].as_i64().unwrap());
                check(
                    "expiry",
                    format!("{exp:?}").into_bytes(),
                    format!("{want:?}").into_bytes(),
                );
            }
            "block" => {
                let c = challenge_settings(v["cfg"].as_i64().unwrap());
                let r = render_block_response(
                    42,
                    &[b"SQLi", b"X<SS"],
                    s(&v["method"]).as_bytes(),
                    b"detail \"x\"",
                    b"CWE-89",
                    &b(&v["msg"]),
                    c.as_ref(),
                );
                check(
                    "ct",
                    r.content_type.as_bytes().to_vec(),
                    s(&v["ct"]).as_bytes().to_vec(),
                );
                check("body", r.body, b(&v["out"]));
            }
            "netset" => {
                let (r, err) = parse_netset_partial(&b(&v["in"]), None);
                let got = format!(
                    "{:?} err={}",
                    r.iter().flat_map(|r| [r.start, r.end]).collect::<Vec<_>>(),
                    err.is_some()
                );
                let ranges: Vec<u32> = v["ranges"]
                    .as_array()
                    .map(|a| a.iter().map(|x| x.as_u64().unwrap() as u32).collect())
                    .unwrap_or_default();
                let want = format!("{ranges:?} err={}", v["err"].as_bool().unwrap());
                check("ranges", got.into_bytes(), want.into_bytes());
            }
            "goodbot_ua" => {
                let mut c = ChallengeSettings {
                    good_bot_allowlist: fields(&v["allow"]),
                    ..Default::default()
                };
                finalize_challenge_settings(&mut c);
                check(
                    "good",
                    vec![c.matches_good_bot(&b(&v["ua"])) as u8],
                    vec![v["good"].as_bool().unwrap() as u8],
                );
            }
            "ipv4fast" => {
                let got = parse_dotted_quad(s(&v["in"]).as_bytes());
                let want = v["ok"]
                    .as_bool()
                    .unwrap()
                    .then(|| v["n"].as_u64().unwrap() as u32);
                check(
                    "n",
                    format!("{got:?}").into_bytes(),
                    format!("{want:?}").into_bytes(),
                );
            }
            "goodbot_cidrs" => {
                let got: Vec<u32> = ranges_from_cidrs(&fields(&v["cidrs"]))
                    .iter()
                    .flat_map(|r| [r.start, r.end])
                    .collect();
                let want: Vec<u32> = v["ranges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap() as u32)
                    .collect();
                check(
                    "ranges",
                    format!("{got:?}").into_bytes(),
                    format!("{want:?}").into_bytes(),
                );
            }
            "json_rules" => {
                let fs = fields(&v["fields"]);
                let (enc, body) = (b(&v["enc"]), b(&v["body"]));
                check(
                    "dec",
                    transform_json_body(&enc, b"application/json", &rules("decrypt_aes", &fs)).0,
                    b(&v["dec"]),
                );
                let rr: Vec<ResponseFieldTransformRule> = fs
                    .iter()
                    .map(|f| ResponseFieldTransformRule {
                        field: f.clone(),
                        action: String::new(),
                        cipher_key_hex: rules("x", &fs)[0].cipher_key_hex.clone(),
                    })
                    .collect();
                match decrypt_json_response_fields(&enc, &rr) {
                    Ok(out) => check("resp", out, b(&v["resp"])),
                    Err(_) => check(
                        "resp_err",
                        vec![1],
                        vec![v["resp_err"].as_bool().unwrap() as u8],
                    ),
                }
                // Our encryption decrypts to what the reference round trip gives.
                let (renc, _) =
                    transform_json_body(&body, b"application/json", &rules("encrypt_aes", &fs));
                check(
                    "changed",
                    vec![(renc != body) as u8],
                    vec![v["changed"].as_bool().unwrap() as u8],
                );
                check(
                    "enc_dec",
                    transform_json_body(&renc, b"application/json", &rules("decrypt_aes", &fs)).0,
                    b(&v["dec"]),
                );
            }
            "mask_json" => {
                let fs = fields(&v["fields"]);
                let refs: Vec<&str> = fs.iter().map(String::as_str).collect();
                check(
                    "mask",
                    redact_json_preview(&b(&v["preview"]), &refs),
                    b(&v["out"]),
                );
            }
            "form_rules" => {
                let fs = fields(&v["fields"]);
                let (enc, body) = (b(&v["enc"]), b(&v["body"]));
                let ct = b"application/x-www-form-urlencoded";
                check(
                    "dec",
                    transform_form_body(&enc, ct, &rules("decrypt_aes", &fs)).0,
                    b(&v["dec"]),
                );
                let (renc, _) = transform_form_body(&body, ct, &rules("encrypt_aes", &fs));
                check(
                    "enc_dec",
                    transform_form_body(&renc, ct, &rules("decrypt_aes", &fs)).0,
                    b(&v["dec"]),
                );
                let mf: Vec<FormField> = fs.iter().map(|f| FormField::new(f.as_bytes())).collect();
                check("mask", redact_form_preview(&body, &mf), b(&v["mask"]));
                check(
                    "preview_mask",
                    redact_body_preview(&body, "form", &rules("mask", &fs)),
                    b(&v["preview_mask"]),
                );
            }
            "multipart_rules" => {
                let fs = fields(&v["fields"]);
                let (ct, body, enc, enc_ct) =
                    (b(&v["ct"]), b(&v["body"]), b(&v["enc"]), b(&v["enc_ct"]));
                let (dec, dec_ct) =
                    transform_multipart_body(&enc, &enc_ct, &rules("decrypt_aes", &fs));
                // The boundary is random: compare after swapping ours for the reference's.
                let norm = |body: &[u8], ct: &[u8], want_ct: &[u8]| {
                    let ours = show(ct).rsplit("boundary=").next().unwrap().to_string();
                    let theirs = show(want_ct)
                        .rsplit("boundary=")
                        .next()
                        .unwrap()
                        .to_string();
                    if ours == theirs {
                        body.to_vec()
                    } else {
                        show(body).replace(&ours, &theirs).into_bytes()
                    }
                };
                check("dec", norm(&dec, &dec_ct, &b(&v["dec_ct"])), b(&v["dec"]));
                let (renc, renc_ct) =
                    transform_multipart_body(&body, &ct, &rules("encrypt_aes", &fs));
                check(
                    "changed",
                    vec![(renc != body) as u8],
                    vec![(enc != body) as u8],
                );
                let (rdec, rdec_ct) =
                    transform_multipart_body(&renc, &renc_ct, &rules("decrypt_aes", &fs));
                if renc != body {
                    let unify = |x: &[u8], c: &[u8]| {
                        let bd = show(c).rsplit("boundary=").next().unwrap().to_string();
                        show(x).replace(&bd, "B")
                    };
                    check(
                        "enc_dec",
                        unify(&rdec, &rdec_ct).into_bytes(),
                        unify(&b(&v["dec"]), &b(&v["dec_ct"])).into_bytes(),
                    );
                }
                check(
                    "preview",
                    compose_multipart_preview(&ct, &body, &rules("mask", &fs)),
                    b(&v["preview"]),
                );
            }
            "resp_body" => {
                match decrypt_response_payload(
                    &b(&v["body"]),
                    &rules("x", &["k".into()])[0].cipher_key_hex,
                ) {
                    Ok(out) => check("out", out, b(&v["out"])),
                    Err(_) => check("err", vec![1], vec![v["err"].as_bool().unwrap() as u8]),
                }
            }
            other => panic!("unknown vector kind {other}"),
        }
    }
    assert!(n > 100, "only {n} vectors");
    println!("go_vectors: {} / {n} equal", n - failures.len());
    assert!(
        failures.is_empty(),
        "{} of {n} vectors differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
