//! Snapshot test for bundle application: each scenario of `fixtures/bundle_scenarios.json` goes through the decoder,
//! `Agent::install_bundle` and a real `wafio_proxy::Proxy` (loopback only), and the state after each step must equal
//! `fixtures/bundle_golden.jsonl`. The agent wrote that file; `WAFIO_WRITE_SNAPSHOT=1` (see `scripts/make-snapshot.sh`) rewrites it.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Value, json};
use wafio_agent_pages::goodbot::VerifiedBotChecker;
use wafio_waf_agent::agent::Agent;
use wafio_waf_agent::bundle::decode_bundle;
use wafio_waf_agent::executor::{Stores, startup_executor};
use wafio_waf_agent::ready::{Ready, ReadyActions};
use wafio_waf_agent::tls::dir::KeyDir;

fn exec_dump(e: &wafio_proxy::AppAnalysisSetup) -> Value {
    let c = &e.analyze;
    let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    json!({
        "project_id": c.project_id,
        "records_weak_detections": c.records_weak_detections(),
        "request_body_limit": c.request_body_limit,
        "inspection_off": c.inspection_off,
        "path_exceptions": c.path_exceptions.len(),
        "geo": c.geo.is_some(),
        "block_policy": c.block_policy.as_ref().map(|b| json!({"enabled": b.enabled, "after": b.block_after_n_blocks, "duration": b.block_duration_sec})),
        "l7_flood": c.l7_flood.as_ref().map(|l| json!({"enabled": l.enabled, "max_requests": l.max_requests, "window_sec": l.window_sec})),
        "bot": c.bot_protection.as_ref().map(|b| json!({"enabled": b.enabled, "mode": b.mode, "base_score": b.base_score, "score_threshold": b.score_threshold})),
        "content_scan": c.content_scan.as_ref().map(|s| json!({"enabled": s.enabled, "mode": s.mode, "on_incomplete": s.on_incomplete})),
        "ssrf_hosts": c.ssrf_config.as_ref().and_then(|x| x.blocklist.as_ref()).map(|b| {
            let mut hosts: Vec<String> = b.hosts.iter().map(|h| s(h)).collect();
            hosts.sort();
            json!({"hosts": hosts, "suffixes": b.suffixes.iter().map(|x| s(x)).collect::<Vec<_>>()})
        }),
        "challenge": e.challenge.as_ref().map(|ch| json!({
            "enabled": ch.enabled, "type": ch.type_, "trigger": ch.trigger, "cookie_ttl_sec": ch.cookie_ttl_sec,
            "simulation": ch.simulation, "pow_difficulty": ch.pow_difficulty, "ip_rep_enabled": ch.ip_rep_enabled,
            "ip_rep_block_level1": ch.ip_rep_block_level1, "ip_rep_block_level2": ch.ip_rep_block_level2,
            "good_bots": ch.good_bot_allowlist.len(),
        })),
        "gui_rules": c.custom_gui_rules.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
        "script_rules": c.custom_script_rules.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
        "tuning_rules": c.custom_tuning_rules.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
    })
}

type Prev = BTreeMap<String, usize>;

fn state(a: &Agent, p: &wafio_proxy::Proxy, prev: &mut Prev) -> Value {
    let (generation, agent_id) = a.generation();
    let mut apps = serde_json::Map::new();
    let mut seen = Prev::new();
    for id in a.app_ids() {
        let mut d = exec_dump(&a.app_executor(&id).unwrap());
        let ptr = Arc::as_ptr(&a.stores(Some(&id)).unwrap().block) as usize;
        d["stores_kept"] = json!(prev.get(&id) == Some(&ptr));
        seen.insert(id.clone(), ptr);
        apps.insert(id, d);
    }
    *prev = seen;
    let mut listeners = serde_json::Map::new();
    for addr in p.addresses() {
        let app = p
            .route(&addr)
            .map(|r| r.app_id().to_string())
            .unwrap_or_default();
        listeners.insert(addr, json!(app));
    }
    let mut state = json!({
        "generation": generation,
        "agent_id": agent_id,
        "shared": a.shared_executor().map(|e| exec_dump(&e)),
        "apps": apps,
        "listeners": listeners,
    });
    // Only while some app is served over HTTPS, so the scenarios without one keep their records.
    let tls: Vec<Value> = a
        .tls_apps()
        .into_iter()
        .map(|(app_id, s, served)| {
            json!({
                "app_id": app_id,
                "listen": s.listen,
                "redirect_listen": s.redirect_listen,
                "hosts": s.hosts,
                "source": format!("{:?}", s.source),
                "certificate_id": s.certificate.map(|c| c.id),
                "request_id": s.request_id,
                "served": served,
            })
        })
        .collect();
    if !tls.is_empty() {
        state["tls"] = json!(tls);
    }
    state
}

/// The listen ports the fixture was recorded with (fixed numbers).
const FIXTURE_PORTS: [&str; 5] = ["41871", "41872", "41873", "41874", "41875"];

/// Free loopback ports standing in for [`FIXTURE_PORTS`]: a fixed port failed the test with
/// "failed to bind WAF route listener" whenever another run on the host held it.
fn free_ports() -> Vec<String> {
    loop {
        let held: Vec<_> = (0..FIXTURE_PORTS.len())
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<String> = held
            .iter()
            .map(|l| l.local_addr().unwrap().port().to_string())
            .collect();
        // A substituted number must not contain another fixture port.
        if !ports
            .iter()
            .any(|p| FIXTURE_PORTS.iter().any(|f| p.contains(f)))
        {
            return ports;
        }
    }
}

#[test]
fn bundle_application_matches_the_recorded_snapshot() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let ports = free_ports();
    let mut text = std::fs::read_to_string(dir.join("bundle_scenarios.json")).unwrap();
    for (fixed, free) in FIXTURE_PORTS.iter().zip(&ports) {
        text = text.replace(fixed, free);
    }
    let scenarios: Value = serde_json::from_str(&text).unwrap();
    let golden: Vec<Value> = std::fs::read_to_string(dir.join("bundle_golden.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let rt = wafio_proxy::runtime_builder().build().unwrap();
    let _g = rt.enter();
    let mut got = Vec::new();
    for (n, sc) in scenarios.as_array().unwrap().iter().enumerate() {
        let stores = Stores::new();
        let base = startup_executor(&stores, "", None).unwrap();
        let proxy = Arc::new(wafio_proxy::Proxy::new(wafio_proxy::ProxyOptions::new(
            Arc::new(|_| {}),
        )));
        let mut agent = Agent::new(
            base,
            stores,
            proxy.clone(),
            Arc::new(VerifiedBotChecker::new()),
            Arc::new(Ready::new(ReadyActions::default())),
        );
        // A scenario has a key directory unless it says it has none.
        let keys =
            std::env::temp_dir().join(format!("wafio-golden-keys-{}-{n}", std::process::id()));
        if sc["key_dir"].as_bool().unwrap_or(true) {
            let dir = KeyDir::open(&keys, nix::unistd::geteuid().as_raw()).unwrap();
            agent = agent.with_key_dir(dir);
        }
        let mut prev = Prev::new();
        for (i, step) in sc["steps"].as_array().unwrap().iter().enumerate() {
            let mut rec =
                json!({"scenario": sc["name"], "step": i, "decode_error": null, "error": ""});
            match decode_bundle(step["bundle"].as_str().unwrap().as_bytes()) {
                Err(e) => rec["decode_error"] = json!(e),
                Ok(mut b) => {
                    let g = step["generation"].as_i64().unwrap();
                    if g != 0 {
                        b.generation = g;
                    }
                    if let Err(e) = agent.install_bundle(&b) {
                        rec["error"] = json!(e.to_string());
                    }
                }
            }
            rec["state"] = state(&agent, &proxy, &mut prev);
            got.push(rec);
        }
        rt.block_on(proxy.shutdown(false));
        drop(agent);
        let _ = std::fs::remove_dir_all(&keys);
    }
    // Back to the recorded addresses (the listeners map is the only place a port shows up).
    let mut text = serde_json::to_string(&got).unwrap();
    for (fixed, free) in FIXTURE_PORTS.iter().zip(&ports) {
        text = text.replace(&format!("127.0.0.1:{free}"), &format!("127.0.0.1:{fixed}"));
    }
    let got: Vec<Value> = serde_json::from_str(&text).unwrap();
    if std::env::var_os("WAFIO_WRITE_SNAPSHOT").is_some() {
        let mut out = String::new();
        for rec in &got {
            out.push_str(&serde_json::to_string(rec).unwrap());
            out.push('\n');
        }
        std::fs::write(dir.join("bundle_golden.jsonl"), out).unwrap();
        return;
    }
    assert_eq!(got.len(), golden.len(), "step count");
    let mut diffs = 0;
    for (g, w) in got.iter().zip(&golden) {
        if g != w {
            diffs += 1;
            eprintln!(
                "MISMATCH {} step {}:\n  recorded: {w}\n  now:      {g}",
                w["scenario"], w["step"]
            );
        }
    }
    eprintln!(
        "bundle snapshot: {}/{} steps identical",
        golden.len() - diffs,
        golden.len()
    );
    assert_eq!(diffs, 0);
}
