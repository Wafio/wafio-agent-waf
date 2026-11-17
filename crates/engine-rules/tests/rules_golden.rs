//! Replays `build/regression/rules-golden.jsonl`: each record is a rules document or a rule regex with what the agent made
//! of it (config, validation errors, path matching, program sizes). Skips when the file is absent.
//! `WAFIO_WRITE_SNAPSHOT=1` rewrites the file from `WAFIO_RULES_GOLDEN_INPUT` (default the file itself); `scripts/make-snapshot.sh` does.
//! The inputs include documents of earlier versions, so the replay is also the upgrade test of the rules reader.

use base64::Engine as _;
use serde_json::{Map, Value as J, json};
use wafio_engine_rules::*;

fn golden_path() -> std::path::PathBuf {
    match std::env::var("WAFIO_RULES_GOLDEN") {
        Ok(p) => p.into(),
        Err(_) => std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../build/regression/rules-golden.jsonl"),
    }
}

fn s(v: &[u8]) -> J {
    J::String(String::from_utf8_lossy(v).into_owned())
}

fn strs(v: &[String]) -> J {
    json!(v)
}

fn policy(p: Option<&SemanticPolicyJson>) -> J {
    match p {
        None => J::Null,
        Some(p) => {
            json!({"block_threshold": p.block_threshold, "soft_threshold": p.soft_threshold,
            "disabled": p.disabled, "action": p.action})
        }
    }
}

fn tuning(t: &TuningTarget, e: &TuningEffect) -> J {
    let mut m = json!({"target": {"components": t.components, "match": t.match_}, "skip_semantic": e.skip_semantic, "scan_mode": e.scan_mode,
        "action": e.action, "holds_detections_as_log": e.holds_detections_as_log()});
    if let Some(w) = &e.weaken {
        let mut wm = json!({"sensitivity_delta": w.sensitivity_delta, "score_multiplier": w.score_multiplier});
        if let Some(d) = &w.threshold_delta {
            wm["threshold_delta"] = json!({"block": d.block, "log": d.log});
        }
        m["weaken"] = wm;
    }
    m
}

fn pe(e: &PathExceptionConfig) -> J {
    let mut m = json!({
        "disabled": e.disabled, "path": e.path, "match": e.match_, "case_insensitive": e.case_insensitive,
        "inspection_off": e.inspection_off, "disable_semantic": e.disable_semantic, "comment": e.comment,
        "body_size_limit": e.body_size_limit, "response_decrypt_aes": e.response_decrypt_aes,
        "case_insensitive_match": e.matches_case_insensitively(), "restricts_access": e.limits_access(),
        "regex_compiled": e.regex_compiled(), "fold_regex_compiled": e.fold_regex_compiled(),
    });
    if let Some(ov) = &e.semantic_override {
        let mut o = Map::new();
        // The golden file knows the first 16 keys; the detectors after them are this agent's own.
        for (k, p) in ov.policies().into_iter().take(16) {
            o.insert(k.into(), policy(p));
        }
        m["semantic_override"] = J::Object(o);
    }
    if let Some(t) = &e.tuning {
        m["tuning"] = tuning(&t.target, &t.effect);
    }
    if let Some(r) = &e.ip_rules {
        m["ip_rules"] = json!({"mode": r.mode, "ips": r.ips});
    }
    if let Some(l) = &e.login_protection {
        m["login_protection"] = json!({"enabled": l.enabled, "max_attempts": l.max_attempts, "window_sec": l.window_sec, "lockout_sec": l.lockout_sec,
            "by_ip": l.by_ip, "by_user_agent": l.by_user_agent, "identifier_field": l.identifier_field, "methods": l.methods});
    }
    if let Some(b) = &e.block {
        m["block"] = json!({"status": b.status, "message": b.message});
    }
    if let Some(r) = &e.rate_limit {
        m["rate_limit"] = json!({"max_requests": r.max_requests, "window_sec": r.window_sec});
    }
    m["field_rules"] = J::Array(
        e.field_rules
            .iter()
            .map(|f| json!({"field": f.field, "source": f.source, "action": f.action, "aes_key": f.aes_key, "methods": f.methods}))
            .collect(),
    );
    m["response_field_rules"] = J::Array(
        e.response_field_rules
            .iter()
            .map(|f| json!({"field": f.field, "action": f.action, "aes_key": f.aes_key}))
            .collect(),
    );
    m
}

const PATHS: [&str; 31] = [
    "/",
    "/api",
    "/api/x",
    "/API/x",
    "/apix",
    "/admin",
    "/Admin",
    "/admin;jsessionid=1",
    "/public/..;/admin",
    "/public/x",
    "/public/../admin",
    "/public/%2e%2e/admin",
    "/upload",
    "/upload/big",
    "/login",
    "/Login",
    "/LOGIN?x=1",
    "/api/login",
    "/API/Login",
    "/static/..;/login",
    "/Static/x",
    "/a",
    "/a/b",
    "/a%zz",
    "//a//b/",
    "/x/./y/../a",
    "http://evil/admin",
    "/a?b=/admin",
    "/a#frag",
    "/%41dmin",
    "/adm%69n",
];

fn dump(r: &LoadResult) -> J {
    let mut out = json!({
        "request_body_limit": r.request_body_limit,
        "siem": null, "block_policy": null, "ssrf_blocklist": null, "geo": null, "l7_flood": null, "bot_protection": null,
        "semantic_policies": null, "challenge": null, "content_scan": null,
    });
    if let Some(x) = &r.siem {
        out["siem"] = json!({"enabled": x.enabled, "webhook_url": x.webhook_url});
    }
    if let Some(b) = &r.block_policy {
        out["block_policy"] = json!({"enabled": b.enabled, "block_after_n_blocks": b.block_after_n_blocks, "block_duration_sec": b.block_duration_sec,
            "key_field": b.key_field, "key_fields": b.key_fields});
    }
    if let Some(x) = &r.ssrf_blocklist {
        out["ssrf_blocklist"] = json!({"ssrf_blocklist_path": x.ssrf_blocklist_path, "ssrf_blocklist": x.ssrf_blocklist});
    }
    if let Some(g) = &r.geo {
        out["geo"] = json!({"block_countries": g.block_countries, "allow_countries": g.allow_countries, "block_ips": g.block_ips, "allow_ips": g.allow_ips});
    }
    if let Some(f) = &r.l7_flood {
        out["l7_flood"] = json!({"enabled": f.enabled, "max_requests": f.max_requests, "window_sec": f.window_sec, "key_field": f.key_field,
            "key_fields": f.key_fields, "allow_ips": f.allow_ips,
            "exempt": {"10.1.2.3:80": f.exempts_ip("10.1.2.3:80"), "[::1]:1": f.exempts_ip("[::1]:1"), "8.8.8.8": f.exempts_ip("8.8.8.8")}});
    }
    if let Some(b) = &r.bot_protection {
        out["bot_protection"] = json!({"enabled": b.enabled, "mode": b.mode, "base_score": b.base_score, "score_threshold": b.score_threshold, "empty_ua_block": b.empty_ua_block,
            "ua_blocklist": b.ua_blocklist, "ua_allowlist": b.ua_allowlist, "ja4_blocklist": b.ja4_blocklist, "ja4_allowlist": b.ja4_allowlist,
            "ja3_blocklist": b.ja3_blocklist, "ja3_allowlist": b.ja3_allowlist, "header_checks": b.header_checks,
            "client_hints_check": b.client_hints_check, "browser_impersonation_check": b.browser_impersonation_check, "block_ai_crawlers": b.block_ai_crawlers});
    }
    if let Some(sp) = &r.semantic_policies {
        let mut o = Map::new();
        for (k, p) in sp.engine_policies().into_iter().take(16) {
            o.insert(k.into(), policy(p));
        }
        o.insert("inspection_off".into(), json!(sp.inspection_off));
        o.insert("disable_semantic".into(), json!(sp.disable_semantic));
        o.insert("scan_all_headers".into(), json!(sp.scan_all_headers));
        o.insert("on_uninspected".into(), json!(sp.on_uninspected));
        o.insert(
            "record_weak_detections".into(),
            json!(sp.record_weak_detections),
        );
        out["semantic_policies"] = J::Object(o);
    }
    if let Some(c) = &r.challenge {
        out["challenge"] = json!({"enabled": c.enabled, "type": c.type_, "site_key": c.site_key, "secret_key": c.secret_key, "cookie_ttl_sec": c.cookie_ttl_sec,
            "trigger": c.trigger, "simulation": c.simulation, "pow_difficulty": c.pow_difficulty, "template_version": c.template_version,
            "allow_local_ips": c.allow_local_ips, "ip_rep_enabled": c.ip_rep_enabled, "ip_rep_block_level1": c.ip_rep_block_level1,
            "ip_rep_block_level2": c.ip_rep_block_level2, "good_bot_allowlist": c.good_bot_allowlist,
            "custom_js_challenge_html": c.custom_js_challenge_html, "custom_click_puzzle_html": c.custom_click_puzzle_html,
            "custom_ip_rep_block_html": c.custom_ip_rep_block_html, "custom_block_html": c.custom_block_html,
            "custom_policy_block_html": c.custom_policy_block_html, "custom_geo_block_html": c.custom_geo_block_html,
            "waf_block_format": c.waf_block_format, "policy_block_format": c.policy_block_format, "geo_block_format": c.geo_block_format,
            "ip_rep_block_format": c.ip_rep_block_format, "custom_waf_block_json": c.custom_waf_block_json,
            "custom_policy_block_json": c.custom_policy_block_json, "custom_geo_block_json": c.custom_geo_block_json,
            "custom_ip_rep_block_json": c.custom_ip_rep_block_json, "custom_waf_block_xml": c.custom_waf_block_xml,
            "custom_policy_block_xml": c.custom_policy_block_xml, "custom_geo_block_xml": c.custom_geo_block_xml,
            "custom_ip_rep_block_xml": c.custom_ip_rep_block_xml});
    }
    if let Some(c) = &r.content_scan {
        out["content_scan"] = json!({"on_incomplete": c.on_incomplete, "enabled": c.enabled, "mode": c.mode, "max_scan_size_bytes": c.max_scan_size_bytes,
            "scan_multipart": c.scan_multipart, "scan_raw_body": c.scan_raw_body, "custom_blocklist_hashes": c.custom_blocklist_hashes,
            "custom_allowlist_hashes": c.custom_allowlist_hashes, "allow_hashes": c.allow_hashes.len(), "block_hashes": c.block_hashes.len()});
    }
    out["path_exceptions"] = J::Array(r.path_exceptions.iter().map(pe).collect());
    let ign: Vec<String> = r
        .ignored
        .iter()
        .map(|iv| {
            format!(
                "rules_json: {} = {} ignored (must be {}); {}",
                iv.key, iv.value, iv.want, iv.fallback
            )
        })
        .collect();
    out["ignored"] = strs(&ign);
    let mut matches = Map::new();
    for uri in PATHS {
        let rp = readings_for_raw_target(uri.as_bytes());
        let (m, lim) = find_path_rules_for_request(&rp, &r.path_exceptions);
        let idx = |o: Option<usize>| o.map_or(-1, |i| i as i64);
        let fr = find_exception_for_raw_target_with_field_rules(uri.as_bytes(), &r.path_exceptions)
            .map(|p| {
                r.path_exceptions
                    .iter()
                    .position(|x| std::ptr::eq(x, p))
                    .unwrap() as i64
            })
            .unwrap_or(-1);
        matches.insert(
            uri.into(),
            json!({"forwarded": s(&rp.forwarded), "unresolved": s(&rp.unresolved), "no_exemption": rp.no_exemption,
                "exc": idx(m), "rate": lim.rate_limit, "body": idx(lim.body_size), "login": lim.login, "field_rules": fr}),
        );
    }
    out["path_matches"] = J::Object(matches);
    out
}

/// Numbers compared by value (an integral float reads back as an integer).
fn norm(v: &J) -> J {
    match v {
        J::Number(n) => json!(n.as_f64().unwrap()),
        J::Array(a) => J::Array(a.iter().map(norm).collect()),
        J::Object(m) => J::Object(m.iter().map(|(k, v)| (k.clone(), norm(v))).collect()),
        v => v.clone(),
    }
}

/// The first differing JSON path of two values.
fn diff(a: &J, b: &J, path: &str) -> Option<String> {
    match (a, b) {
        (J::Object(x), J::Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.sort();
            keys.dedup();
            keys.into_iter().find_map(|k| {
                diff(
                    x.get(k).unwrap_or(&J::Null),
                    y.get(k).unwrap_or(&J::Null),
                    &format!("{path}.{k}"),
                )
            })
        }
        (J::Array(x), J::Array(y)) if x.len() == y.len() => x
            .iter()
            .zip(y)
            .enumerate()
            .find_map(|(i, (p, q))| diff(p, q, &format!("{path}[{i}]"))),
        _ if a == b => None,
        _ => Some(format!("{path}: recorded={a} now={b}")),
    }
}

/// What the agent makes of the input of a record: the whole record, as it is stored.
fn record_for(rec: &J) -> J {
    match rec["kind"].as_str() {
        Some("rules") => {
            let data = base64::engine::general_purpose::STANDARD
                .decode(rec["input_b64"].as_str().unwrap())
                .unwrap();
            let verr = check_rules(&data).err().map(|e| e.to_string());
            let load = load_rules_json(&data);
            let mut out = json!({
                "kind": "rules", "name": rec["name"], "input_b64": rec["input_b64"],
                "validate_error": verr, "load_error": load.as_ref().err().map(|e| e.to_string()),
            });
            if let Ok(r) = &load {
                out["result"] = dump(r);
            }
            out
        }
        Some("regex") => {
            let p = rec["pattern"].as_str().unwrap();
            json!({
                "kind": "regex", "pattern": p,
                "insts": regex_program_size(p).map_or(-1, |n| n as i64),
                "error": compile_rule_pattern(p).err().map(|e| e.to_string()).unwrap_or_default(),
            })
        }
        _ => rec.clone(),
    }
}

fn read_records(path: &std::path::Path) -> Option<Vec<J>> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(
        text.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect(),
    )
}

#[test]
fn rules_snapshot() {
    let path = golden_path();
    if std::env::var_os("WAFIO_WRITE_SNAPSHOT").is_some() {
        let input = std::env::var_os("WAFIO_RULES_GOLDEN_INPUT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| path.clone());
        let records = read_records(&input).unwrap_or_else(|| panic!("{} absent", input.display()));
        let mut out = String::new();
        for rec in &records {
            out.push_str(&serde_json::to_string(&record_for(rec)).unwrap());
            out.push('\n');
        }
        std::fs::write(&path, out).unwrap();
        eprintln!(
            "rules snapshot: wrote {} records to {}",
            records.len(),
            path.display()
        );
        return;
    }
    let Some(records) = read_records(&path) else {
        eprintln!("rules snapshot {} absent: skipped", path.display());
        return;
    };
    let mut failures = Vec::new();
    for rec in &records {
        if let Some(d) = diff(&norm(rec), &norm(&record_for(rec)), "") {
            let name = rec["name"]
                .as_str()
                .or(rec["pattern"].as_str())
                .unwrap_or("?");
            failures.push(format!("{name}: {d}"));
        }
    }
    for f in &failures {
        eprintln!("MISMATCH {f}");
    }
    eprintln!(
        "rules snapshot: {}/{} records identical",
        records.len() - failures.len(),
        records.len()
    );
    assert!(failures.is_empty(), "{} records differ", failures.len());
}
