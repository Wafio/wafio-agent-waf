//! Differential test against recorded reference outputs: the generator in `golden/` writes
//! the outputs for a generated corpus; this test recomputes them. Runs only
//! with `AGENTIO_GOLDEN=<jsonl>` set (see the generator's header).

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::Value as J;

use crate::client_ip::{parse_dotted_quad, strip_port};
use crate::fastcgi_client::{
    FastCgiConnectionPool, FastCgiDeadlines, encode_name_value_pairs, parse_cgi_reply,
    parse_upstream_spec,
};
use crate::metrics::render_float;
use crate::store_limits::parse_store_entry_cap;
use crate::url_parse;
use crate::utf8::repair_utf8;
use crate::websocket_config::check_websocket_rules;
use crate::ws_config::{origins_match, parse_ws_app_policy};
use crate::ws_scanner::{build_scan_input, collect_printable_runs, looks_mostly_printable};

fn hex_to_bytes(s: &J) -> Vec<u8> {
    let s = s.as_str().expect("hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn tohex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn s(v: &J) -> &str {
    v.as_str().unwrap_or("")
}

fn st(b: &[u8]) -> J {
    J::String(String::from_utf8_lossy(b).into_owned())
}

/// Recomputes one golden line; `None` = a function this test does not know.
fn check(fn_: &str, i: &J, o: &J) -> Option<J> {
    Some(match fn_ {
        "frame_view" => {
            let v = build_scan_input(
                i["kind"].as_u64()? as u8,
                &hex_to_bytes(&i["p"]),
                i["max"].as_u64()? as usize,
            );
            serde_json::json!({"text": v.text.map(|t| tohex(&t)), "runs": v.runs, "oversize": v.oversize})
        }
        "printable_runs" => {
            serde_json::json!({"v": tohex(&collect_printable_runs(&hex_to_bytes(&i["p"]), i["limit"].as_u64()? as usize))})
        }
        "decoded_printable" => {
            serde_json::json!({"v": looks_mostly_printable(&hex_to_bytes(&i["p"]))})
        }
        "sanitize" => {
            serde_json::json!({"v": tohex(repair_utf8(&hex_to_bytes(&i["p"])).as_bytes())})
        }
        "ws_config" => match parse_ws_app_policy(s(&i["json"]).as_bytes()) {
            Err(_) => serde_json::json!({"err": true}),
            Ok(c) => serde_json::json!({
                "err": false, "enabled": c.enabled, "oc_enabled": c.origin_check.enabled,
                "origins": if c.origin_check.allowed_origins.is_empty() && o["origins"].is_null() { J::Null } else { serde_json::json!(c.origin_check.allowed_origins) },
                "limits": [c.limits.max_text_bytes, c.limits.max_binary_bytes, c.limits.max_msgs_per_min],
                "scan_bin": c.scan_binary_hashes, "scan_srv": c.scan_server_frames,
            }),
        },
        "ws_validate" => {
            serde_json::json!({"err": check_websocket_rules(s(&i["json"]).as_bytes()).is_err()})
        }
        "origin_equals" => {
            serde_json::json!({"v": origins_match(s(&i["a"]).as_bytes(), s(&i["b"]).as_bytes())})
        }
        "url_parse" => match url_parse::parse(s(&i["raw"]).as_bytes()) {
            Err(_) => serde_json::json!({"err": true}),
            Ok(u) => serde_json::json!({
                "err": false, "scheme": st(&u.scheme), "opaque": st(&u.opaque), "host": st(&u.host), "path": st(&u.path),
                "raw_query": st(&u.raw_query), "fragment": st(&u.fragment), "hostname": st(u.hostname()), "port": st(u.port()),
                "user": u.user.as_ref().map(|(n, p)| serde_json::json!([st(n), p.as_ref().map(|p| st(p))])),
            }),
        },
        "split_host_port" => match url_parse::split_host_and_port(s(&i["hp"]).as_bytes()) {
            Err(_) => serde_json::json!({"err": true, "host": "", "port": ""}),
            Ok((h, p)) => serde_json::json!({"err": false, "host": st(&h), "port": st(&p)}),
        },
        "fcgi_stdout" => {
            let r = parse_cgi_reply(&hex_to_bytes(&i["data"]));
            let headers: BTreeMap<String, Vec<String>> = r
                .headers
                .iter()
                .map(|(k, vs)| {
                    (
                        String::from_utf8_lossy(k).into_owned(),
                        vs.iter()
                            .map(|v| String::from_utf8_lossy(v).into_owned())
                            .collect(),
                    )
                })
                .collect();
            serde_json::json!({"status": r.status, "headers": headers, "body": tohex(&r.body)})
        }
        "encode_params" => {
            let pairs: Vec<(Vec<u8>, Vec<u8>)> = i["pairs"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|p| (s(&p[0]).as_bytes().to_vec(), s(&p[1]).as_bytes().to_vec()))
                        .collect()
                })
                .unwrap_or_default();
            serde_json::json!({"v": tohex(&encode_name_value_pairs(&pairs))})
        }
        "cgi_params" => {
            let mut pool = FastCgiConnectionPool::new("tcp", "x", 1, FastCgiDeadlines::default());
            let p = Arc::get_mut(&mut pool)?;
            p.site_root = s(&i["root"]).as_bytes().to_vec();
            p.index = s(&i["index"]).as_bytes().to_vec();
            let mut lines = Vec::new();
            for h in i["headers"].as_array()? {
                for v in h[1].as_array()? {
                    lines.push((s(&h[0]).as_bytes().to_vec(), s(v).as_bytes().to_vec()));
                }
            }
            let params = pool.build_cgi_variables(
                b"POST",
                s(&i["uri"]).as_bytes(),
                s(&i["host"]).as_bytes(),
                b"203.0.113.9",
                &lines,
                s(&i["ct"]).as_bytes(),
                i["cl"].as_u64()? as usize,
            );
            let got: Vec<(String, String)> = params
                .iter()
                .map(|(k, v)| {
                    (
                        String::from_utf8_lossy(k).into_owned(),
                        String::from_utf8_lossy(v).into_owned(),
                    )
                })
                .collect();
            let want: Vec<(String, String)> = o["params"]
                .as_array()?
                .iter()
                .map(|kv| (s(&kv[0]).to_string(), s(&kv[1]).to_string()))
                .collect();
            // The recorded outputs list the forwarded headers in no fixed order: compare those as a set.
            let split = |v: &[(String, String)]| {
                let n = v
                    .iter()
                    .position(|(k, _)| k.starts_with("HTTP_") && k != "HTTP_HOST")
                    .unwrap_or(v.len());
                let mut tail = v[n..].to_vec();
                tail.sort();
                (v[..n].to_vec(), tail)
            };
            return Some(if split(&got) == split(&want) {
                o.clone()
            } else {
                serde_json::json!({"params": got})
            });
        }
        "fcgi_upstream" => match parse_upstream_spec(
            s(&i["u"]),
            s(&i["root"]),
            s(&i["index"]),
            4,
            FastCgiDeadlines::default(),
        ) {
            Err(_) => serde_json::json!({"err": true}),
            Ok(p) => {
                serde_json::json!({"err": false, "network": p.network(), "addr": p.address(), "root": st(&p.site_root), "index": st(&p.index)})
            }
        },
        "store_max" => serde_json::json!({"v": parse_store_entry_cap(s(&i["s"]).as_bytes())}),
        "ipv4" => {
            let (n, ok) = match parse_dotted_quad(s(&i["s"])) {
                Some(n) => (n, true),
                None => (0, false),
            };
            serde_json::json!({"strip": strip_port(s(&i["s"])), "n": n, "ok": ok})
        }
        "format_float" => {
            serde_json::json!({"v": render_float(f64::from_bits(s(&i["bits"]).parse().ok()?))})
        }
        _ => return None,
    })
}

#[test]
fn reference_golden() {
    let Ok(path) = std::env::var("AGENTIO_GOLDEN") else {
        return;
    };
    let data = std::fs::read_to_string(&path).expect("golden file");
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut fails = Vec::new();
    for line in data.lines() {
        let v: J = serde_json::from_str(line).expect("json line");
        let fn_ = v["fn"].as_str().unwrap_or("").to_string();
        let got = check(&fn_, &v["in"], &v["out"]);
        let c = counts.entry(fn_.clone()).or_default();
        c.0 += 1;
        match got {
            Some(g) if g == v["out"] => c.1 += 1,
            other => {
                if fails.len() < 40 {
                    fails.push(format!(
                        "{fn_} in={} want={} got={:?}",
                        v["in"], v["out"], other
                    ));
                }
            }
        }
    }
    for (k, (n, ok)) in &counts {
        println!("golden {k}: {ok}/{n}");
    }
    assert!(
        fails.is_empty(),
        "{} mismatches, first:\n{}",
        fails.len(),
        fails.join("\n")
    );
}
