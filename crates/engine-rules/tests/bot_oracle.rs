//! Differential test for bot detection (`classify_bot`, UA / JA3 / JA4 / headers) against the
//! oracle file.
//! Skips without `WAFIO_BOT_ORACLE=<file>`. With `WAFIO_BOT_REPO_ROOT=<repo>` the default
//! JA3/JA4 lists the Rust loaders read from `<repo>/security-data` are compared with the lists
//! the oracle loaded.

use serde_json::Value;
use std::collections::BTreeMap;
use wafio_bytetext::base64::STANDARD;
use wafio_engine_rules::bot::{
    BotProtectionConfig, BotRequest, classify_bot, compile_bot_protection,
};
use wafio_engine_rules::bot_defaults::{
    default_ja3_blocklist, default_ja4_allowlist, default_ja4_blocklist,
};

fn b64(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap().as_bytes()).unwrap()
}

fn b64s(v: &Value) -> Vec<String> {
    // Config lists come from rules_json, so they are valid UTF-8 (the oracle's are).
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| String::from_utf8(b64(s)).unwrap())
        .collect()
}

#[allow(clippy::field_reassign_with_default)] // the compiled fields are private: build from default
fn config(c: &Value) -> BotProtectionConfig {
    let mut cfg = BotProtectionConfig::default();
    cfg.enabled = c["enabled"].as_bool().unwrap();
    cfg.mode = c["mode"].as_str().unwrap().to_string();
    cfg.base_score = c["base_score"].as_i64().unwrap();
    cfg.empty_ua_block = c["empty_ua_block"].as_bool().unwrap();
    cfg.ua_blocklist = b64s(&c["ua_blocklist"]);
    cfg.ua_allowlist = b64s(&c["ua_allowlist"]);
    cfg.ja4_blocklist = b64s(&c["ja4_blocklist"]);
    cfg.ja4_allowlist = b64s(&c["ja4_allowlist"]);
    cfg.ja3_blocklist = b64s(&c["ja3_blocklist"]);
    cfg.ja3_allowlist = b64s(&c["ja3_allowlist"]);
    cfg.header_checks = c["header_checks"].as_bool().unwrap();
    cfg.client_hints_check = c["client_hints_check"].as_bool().unwrap();
    cfg.browser_impersonation_check = c["browser_impersonation_check"].as_bool().unwrap();
    cfg.block_ai_crawlers = c["block_ai_crawlers"].as_bool().unwrap();
    compile_bot_protection(&mut cfg);
    cfg
}

#[test]
fn bot_detect_matches_golden() {
    let Ok(path) = std::env::var("WAFIO_BOT_ORACLE") else {
        eprintln!("skipped: set WAFIO_BOT_ORACLE=<file>");
        return;
    };
    let data = std::fs::read_to_string(path).unwrap();
    let mut lines = data.lines();
    let head: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    let cfgs: Vec<BotProtectionConfig> = head["configs"]
        .as_array()
        .unwrap()
        .iter()
        .map(config)
        .collect();

    if let Ok(root) = std::env::var("WAFIO_BOT_REPO_ROOT") {
        // SAFETY: single test in this binary; nothing else reads the environment concurrently.
        unsafe {
            std::env::set_var(
                "WAFIO_JA4_BLACKLIST_FILE",
                format!("{root}/security-data/ja4/ja4.txt"),
            );
            std::env::set_var(
                "WAFIO_JA4_ALLOWLIST_FILE",
                format!("{root}/security-data/ja4/ja4_allowlist.txt"),
            );
            std::env::set_var(
                "WAFIO_JA3_BLACKLIST_FILE",
                format!("{root}/security-data/ja3/ja3.txt"),
            );
        }
        assert_eq!(
            default_ja4_blocklist(&[]),
            b64s(&head["ja4_block"]),
            "default JA4 blocklist"
        );
        assert_eq!(
            default_ja4_allowlist(&[]),
            b64s(&head["ja4_allow"]),
            "default JA4 allowlist"
        );
        assert_eq!(
            default_ja3_blocklist(),
            b64s(&head["ja3_block"]),
            "default JA3 blocklist"
        );
    }

    let (mut total, mut bad) = (0usize, 0usize);
    let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
    for line in lines {
        let c: Value = serde_json::from_str(line).unwrap();
        total += 1;
        let mut headers: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();
        for (k, vs) in c["h"].as_object().unwrap() {
            let key = STANDARD.decode(k.as_bytes()).unwrap();
            headers.insert(key, vs.as_array().unwrap().iter().map(b64).collect());
        }
        let (m, u, ua, ja3, ja4) = (
            b64(&c["m"]),
            b64(&c["u"]),
            b64(&c["ua"]),
            b64(&c["ja3"]),
            b64(&c["ja4"]),
        );
        let req = BotRequest {
            method: &m,
            uri: &u,
            user_agent: &ua,
            ja3: &ja3,
            ja4: &ja4,
            headers: &headers,
        };
        let got = classify_bot(&req, Some(&cfgs[c["c"].as_u64().unwrap() as usize]));
        let want = (
            c["s"].as_i64().unwrap(),
            c["r"].as_str().unwrap().to_string(),
            b64(&c["d"]),
        );
        *by_reason.entry(want.1.clone()).or_default() += 1;
        if (got.score, got.reason.to_string(), got.match_detail.clone()) != want {
            bad += 1;
            if bad <= 20 {
                eprintln!(
                    "MISMATCH cfg {} ua {:?} ja3 {:?} ja4 {:?} hdr {:?}\n  go   = {:?}\n  rust = {:?}",
                    c["c"],
                    String::from_utf8_lossy(&ua),
                    String::from_utf8_lossy(&ja3),
                    String::from_utf8_lossy(&ja4),
                    headers
                        .iter()
                        .map(|(k, v)| (String::from_utf8_lossy(k).into_owned(), v.len()))
                        .collect::<Vec<_>>(),
                    want,
                    (
                        got.score,
                        got.reason,
                        String::from_utf8_lossy(&got.match_detail)
                    )
                );
            }
        }
    }
    eprintln!("bot oracle: {total} cases, {bad} mismatches; reference reasons: {by_reason:?}");
    assert_eq!(bad, 0);
}
