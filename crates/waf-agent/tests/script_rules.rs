//! Script rules through the proxy, and the replay of recorded results. The replay reads `WAFIO_SCRIPT_GOLDEN`
//! (default `build/regression/script-golden.jsonl`) and returns when the file is missing; with `WAFIO_WRITE_SNAPSHOT=1`
//! it rewrites that file from the cases of `WAFIO_SCRIPT_GOLDEN_INPUT`, with the results of this runner
//! (`scripts/make-snapshot.sh` of wafio-semantic-engine does).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use wafio_agent_pages::goodbot::VerifiedBotChecker;
use wafio_application::ScriptRunner;
use wafio_engine_rules::{
    CustomScriptRule, RequestRuleContext, ScriptBudget, ScriptResult, parse_body_for_rules,
};
use wafio_proxy::{DecisionEvent, Proxy, ProxyOptions};
use wafio_waf_agent::agent::Agent;
use wafio_waf_agent::bundle::decode_bundle;
use wafio_waf_agent::executor::{Stores, startup_executor};
use wafio_waf_agent::ready::{Ready, ReadyActions};
use wafio_waf_agent::script_rules;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An upstream answering every request `200 ok`.
fn upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                if s.read(&mut buf).unwrap_or(0) > 0 {
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                }
            });
        }
    });
    port
}

fn get(port: u16, target: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(
        s,
        "GET {target} HTTP/1.1\r\nHost: app.test\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

async fn fetch(port: u16, target: &'static str) -> String {
    tokio::task::spawn_blocking(move || get(port, target))
        .await
        .unwrap()
}

/// One script rule, as a bundle carries it.
const RULE: &str = r#"
if (path == "/block") then:
    waf_block("by script")
end
if (path == "/log") then:
    waf_log("by script")
end
if (path == "/allow") then:
    waf_allow()
end
"#;

/// A script rule blocks, logs and allows requests that went through the proxy, and the rule was compiled when the
/// bundle was applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_rule_blocks_logs_and_allows_through_the_proxy() {
    let events: Arc<Mutex<Vec<DecisionEvent>>> = Arc::default();
    let sink = events.clone();
    let proxy = Arc::new(Proxy::new(ProxyOptions::new(Arc::new(move |e| {
        sink.lock().unwrap().push(e)
    }))));
    let stores = Stores::new();
    let agent = Agent::new(
        startup_executor(&stores, "", None).unwrap(),
        stores,
        proxy,
        Arc::new(VerifiedBotChecker::new()),
        Arc::new(Ready::new(ReadyActions::default())),
    );
    let (listen, up) = (free_port(), upstream());
    let bundle = serde_json::json!({
        "agent_id": "a", "project_id": "p", "apps": [{
            "app_id": "web", "listen_host": "127.0.0.1", "listen_port": listen,
            "upstream": format!("http://127.0.0.1:{up}"), "mode": "block",
            "custom_script_rules": [{"id": "s1", "enabled": true, "script": RULE}],
        }],
    });
    agent
        .install_bundle(&decode_bundle(bundle.to_string().as_bytes()).unwrap())
        .unwrap();

    let last = |e: &Mutex<Vec<DecisionEvent>>| e.lock().unwrap().last().cloned().unwrap();
    let blocked = fetch(listen, "/block").await;
    assert!(blocked.starts_with("HTTP/1.1 403"), "{blocked}");
    let ev = last(&events);
    assert_eq!(
        (&ev.action[..], &ev.analyze_method[..]),
        (&b"block"[..], &b"custom_rule"[..])
    );
    assert_eq!(ev.status, 403);

    for (path, action) in [("/log", "log"), ("/allow", "allow")] {
        let reply = fetch(listen, path).await;
        assert!(
            reply.starts_with("HTTP/1.1 200") && reply.ends_with("ok"),
            "{reply}"
        );
        let ev = last(&events);
        assert_eq!(ev.action, action.as_bytes(), "{path}");
        assert_eq!(ev.analyze_method, b"custom_rule", "{path}");
    }

    let reply = fetch(listen, "/other").await;
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert_ne!(last(&events).analyze_method, b"custom_rule");
}

// ── the replay ───────────────────────────────────────────────────────────────────────────────

fn text(v: &Value, k: &str) -> Vec<u8> {
    v[k].as_str().unwrap_or("").as_bytes().to_vec()
}

fn pairs(v: &Value, k: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    v[k].as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| {
                    (
                        k.as_bytes().to_vec(),
                        v.as_str().unwrap().as_bytes().to_vec(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn context(v: &Value) -> RequestRuleContext {
    let mut c = RequestRuleContext {
        method: text(v, "method"),
        path: text(v, "path"),
        query: text(v, "query"),
        ip: text(v, "ip"),
        country: text(v, "country"),
        ua: text(v, "ua"),
        headers: pairs(v, "headers"),
        body: text(v, "body"),
        host: text(v, "host"),
        cookies: pairs(v, "cookies"),
        uri: text(v, "uri"),
        path_extension: text(v, "path_ext"),
        body_size: v["body_size"].as_i64().unwrap_or(0),
        body_truncated: v["body_truncated"].as_bool().unwrap_or(false),
        score: v["score"].as_f64().unwrap_or(0.0),
        action: v["action"].as_str().unwrap_or("").to_string(),
        detected: v["detected"]
            .as_array()
            .map(|a| a.iter().map(|d| d.as_str().unwrap().to_string()).collect())
            .unwrap_or_default(),
        ..Default::default()
    };
    if v["parse"].as_bool() == Some(true) {
        c.parsed = Some(parse_body_for_rules(
            &text(v, "parse_ct"),
            &text(v, "parse_body"),
        ));
    }
    for (field, b64) in v["raw_b64"].as_object().into_iter().flatten() {
        let raw = wafio_bytetext::base64::STANDARD
            .decode(b64.as_str().unwrap().as_bytes())
            .unwrap();
        match field.as_str() {
            "body" => c.body = raw,
            "ua" => c.ua = raw,
            "query" => c.query = raw,
            "path" => c.path = raw,
            f => panic!("unknown raw field {f}"),
        }
    }
    c
}

/// The result of a case as the golden file stores it.
fn want_json(r: &ScriptResult) -> Value {
    serde_json::json!({
        "action": r.action, "rule_id": r.rule_id, "incomplete": r.incomplete,
        "incomplete_rule": r.incomplete_rule, "incomplete_reason": r.incomplete_reason,
        "content_incomplete": r.content_incomplete, "coverage": r.coverage,
    })
}

/// Every recorded case (the rules, a request and the result the Go interpreter gave) runs again through the runner
/// of the agent and must give the same result.
#[test]
fn every_script_case_matches_the_recorded_result() {
    let path = std::env::var_os("WAFIO_SCRIPT_GOLDEN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../build/regression/script-golden.jsonl")
        });
    let writing = std::env::var_os("WAFIO_WRITE_SNAPSHOT").is_some();
    let input = std::env::var_os("WAFIO_SCRIPT_GOLDEN_INPUT")
        .filter(|_| writing)
        .map_or_else(|| path.clone(), PathBuf::from);
    let Ok(golden) = std::fs::read_to_string(&input) else {
        eprintln!("{} is missing: skipped", input.display());
        return;
    };
    wafio_waf_agent::multipart_body::install_engine_hooks();
    let (mut total, mut bad, mut written) = (0, Vec::new(), String::new());
    for line in golden.lines() {
        let case: Value = serde_json::from_str(line).unwrap();
        let rules: Vec<CustomScriptRule> = case["rules"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| CustomScriptRule {
                id: r["id"].as_str().unwrap().into(),
                enabled: r["enabled"].as_bool().unwrap(),
                priority: r["priority"].as_i64().unwrap(),
                created_at: r["created_at"].as_i64().unwrap(),
                script: r["script"].as_str().unwrap().into(),
                ..Default::default()
            })
            .collect();
        let budget = ScriptBudget {
            per_script: Duration::from_nanos(case["per_ns"].as_u64().unwrap()),
            total: Duration::from_nanos(case["total_ns"].as_u64().unwrap()),
        };
        let (_, scripts) = script_rules::compile("replay", rules);
        let got = scripts.run_script_rules(&context(&case["ctx"]), budget);
        total += 1;
        if writing {
            let mut out = case.clone();
            out["want"] = want_json(&got);
            written.push_str(&serde_json::to_string(&out).unwrap());
            written.push('\n');
            continue;
        }
        let w = &case["want"];
        let want = ScriptResult {
            action: w["action"].as_str().unwrap().into(),
            rule_id: w["rule_id"].as_str().unwrap().into(),
            incomplete: w["incomplete"].as_bool().unwrap(),
            incomplete_rule: w["incomplete_rule"].as_str().unwrap().into(),
            incomplete_reason: w["incomplete_reason"].as_str().unwrap().into(),
            content_incomplete: w["content_incomplete"].as_bool().unwrap(),
            coverage: w["coverage"].as_str().unwrap().into(),
        };
        if got != want {
            bad.push(format!(
                "{}\n   recorded: {want:?}\n   now:      {got:?}",
                case["name"].as_str().unwrap()
            ));
        }
    }
    if writing {
        std::fs::write(&path, written).unwrap();
        eprintln!("script snapshot: wrote {total} cases");
        return;
    }
    eprintln!("script replay: {}/{total} identical", total - bad.len());
    assert!(total >= 100, "the recorded file holds {total} cases");
    assert!(
        bad.is_empty(),
        "{} cases differ:\n{}",
        bad.len(),
        bad.join("\n")
    );
}
