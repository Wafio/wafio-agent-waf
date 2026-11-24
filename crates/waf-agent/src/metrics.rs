//! The WAF agent's metrics registration and heartbeat counters
//! (fields 5–8, 11–20). The request-path counters (analyze latency
//! histogram, partial-coverage flags, recovered agent panics) live in `wafio_proxy::metrics`.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use wafio_agent_io::metrics::{Label, Registry, Sample, micros};
use wafio_application::{PARTIAL_COVERAGE_REQUESTS, RECOVERED_ANALYZE_PANICS};
use wafio_control::{ControlLink, HeartbeatCounters};
use wafio_engine_api::engine;
use wafio_proxy::metrics::{
    ANALYZE_LATENCY_HISTOGRAM, COMPRESSED_BROTLI, COMPRESSED_GZIP, COMPRESSION_BYTES_IN,
    COMPRESSION_BYTES_OUT, COMPRESSION_SKIP_REASONS, COMPRESSION_SKIPPED, MAINTENANCE_RESPONSES,
    PANIC_COUNT, STATIC_BYTES, STATIC_RESPONSES, STATIC_STATUSES, coverage_flag_samples,
    latency_percentiles,
};

use crate::tls::metrics::TlsMetrics;

/// The heartbeat counters the agent owns.
pub fn heartbeat_counters() -> HeartbeatCounters {
    let (p50, p95, p99, n) = latency_percentiles();
    let p = |d| if n > 0 { micros(d) } else { 0 };
    HeartbeatCounters {
        analyze_panics_total: RECOVERED_ANALYZE_PANICS.load(Ordering::Relaxed),
        engine_panics_total: engine().counters().recovered_panics,
        partial_coverage_total: PARTIAL_COVERAGE_REQUESTS.load(Ordering::Relaxed),
        parse_budget_exhausted_total: engine().counters().exhausted_parse_budgets,
        script_incomplete_total: crate::script_rules::incomplete_total(),
        script_errors_total: crate::script_rules::errors_total(),
        script_rules_rejected_total: crate::script_rules::rejected_total(),
        script_runs_in_flight: crate::script_rules::runs_in_flight(),
        agent_panics_total: PANIC_COUNT.load(Ordering::Relaxed),
        analyze_latency_p50_us: p(p50),
        analyze_latency_p95_us: p(p95),
        analyze_latency_p99_us: p(p99),
        analyze_latency_samples: n,
        regex_rules_dropped_total: crate::gaps::regex_rules_dropped_total(),
    }
}

fn u(v: u64) -> f64 {
    v as f64
}

/// Threads of this process (`/proc/self/status`).
fn threads() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("Threads:")
                    .map(|v| v.trim().parse::<f64>().unwrap_or(0.0))
            })
        })
        .unwrap_or(0.0)
}

/// `RegisterWAFMetrics`.
pub fn register_agent_metrics(reg: &Registry, link: Arc<ControlLink>, tls: &Arc<TlsMetrics>) {
    tls.register(reg);
    let start = Instant::now();
    reg.gauge(
        "wafio_agent_uptime_seconds",
        "Seconds since the agent process started.",
        move || start.elapsed().as_secs_f64(),
    );
    reg.gauge(
        "wafio_agent_goroutines",
        "Goroutines in the agent process.",
        threads,
    );
    let l = link.clone();
    reg.gauge(
        "wafio_waf_control_plane_connected",
        "1 while the gRPC stream to the control plane is up.",
        move || {
            if l.connected() { 1.0 } else { 0.0 }
        },
    );
    reg.histogram(
        "wafio_waf_analyze_duration_seconds",
        "Time spent in Analyze per request.",
        ANALYZE_LATENCY_HISTOGRAM.clone(),
    );
    reg.counter(
        "wafio_waf_analyze_panics",
        "Panics recovered by Analyze (request allowed without full inspection).",
        || u(RECOVERED_ANALYZE_PANICS.load(Ordering::Relaxed)),
    );
    reg.counter(
        "wafio_waf_engine_panics",
        "Semantic-engine panics recovered in-scan.",
        || u(engine().counters().recovered_panics),
    );
    reg.counter(
        "wafio_waf_agent_panics",
        "Other panics recovered by the agent (WebSocket relay, IP-jail enforcement).",
        || u(PANIC_COUNT.load(Ordering::Relaxed)),
    );
    reg.counter(
        "wafio_waf_maintenance_responses",
        "Requests answered with the maintenance page of an app in maintenance mode.",
        || u(MAINTENANCE_RESPONSES.load(Ordering::Relaxed)),
    );
    // One label value of a sample: `name="value"`.
    let sample = |name: &str, value: &str, n: u64| Sample {
        labels: vec![Label {
            name: name.into(),
            value: value.into(),
        }],
        value: u(n),
    };
    reg.labeled_counter(
        "wafio_waf_compression_responses",
        "Answers sent compressed, by encoding.",
        move || {
            vec![
                sample("encoding", "gzip", COMPRESSED_GZIP.load(Ordering::Relaxed)),
                sample("encoding", "br", COMPRESSED_BROTLI.load(Ordering::Relaxed)),
            ]
        },
    );
    reg.labeled_counter(
        "wafio_waf_compression_bytes",
        "Bytes of the compressed answers before compression (in) and as sent (out).",
        move || {
            vec![
                sample("dir", "in", COMPRESSION_BYTES_IN.load(Ordering::Relaxed)),
                sample("dir", "out", COMPRESSION_BYTES_OUT.load(Ordering::Relaxed)),
            ]
        },
    );
    reg.labeled_counter(
        "wafio_waf_compression_skipped",
        "Answers that could have been compressed and were not: streamed (no length up front), too_large, busy (no free compression slot) or grew (the compressed form was not smaller).",
        move || {
            COMPRESSION_SKIP_REASONS
                .iter()
                .zip(&COMPRESSION_SKIPPED)
                .map(|(reason, n)| sample("reason", reason, n.load(Ordering::Relaxed)))
                .collect()
        },
    );
    reg.labeled_counter(
        "wafio_waf_static_responses",
        "Answers a folder of static files gave, by status: 200 and 206 (the file or a part of it), 304, 308 (a directory asked for without its slash), 416, and 404 and 405 for an app that answers its own misses.",
        move || {
            STATIC_STATUSES
                .iter()
                .zip(&STATIC_RESPONSES)
                .map(|(status, n)| sample("status", &status.to_string(), n.load(Ordering::Relaxed)))
                .collect()
        },
    );
    reg.counter(
        "wafio_waf_static_bytes",
        "Bytes of the bodies of the answers of static folders, as sent.",
        || u(STATIC_BYTES.load(Ordering::Relaxed)),
    );
    reg.labeled_counter(
        "wafio_waf_jail_refused",
        "IP-jail attempts refused because the address is protected (loopback, unspecified, link-local, multicast, own address, control plane, trusted proxy) or invalid, by reason.",
        wafio_agent_io::ip_jail_guard::jail_exemption_samples,
    );
    reg.counter(
        "wafio_waf_partial_coverage_requests",
        "Requests whose semantic scan did not cover the whole request.",
        || u(PARTIAL_COVERAGE_REQUESTS.load(Ordering::Relaxed)),
    );
    reg.labeled_counter(
        "wafio_waf_partial_coverage_flags",
        "Partial-coverage flags by flag (a request can carry several).",
        || {
            coverage_flag_samples()
                .into_iter()
                .map(|(n, v)| Sample {
                    labels: vec![Label {
                        name: "flag".into(),
                        value: n,
                    }],
                    value: u(v),
                })
                .collect()
        },
    );
    reg.counter(
        "wafio_waf_parse_budget_exhausted",
        "Engine scans that skipped relaxed-parse variants because the work budget ran out.",
        || u(engine().counters().exhausted_parse_budgets),
    );
    reg.counter(
        "wafio_waf_script_incomplete",
        "Script-rule evaluations that did not finish (timeout, limit, panic, error, budget).",
        || u(crate::script_rules::incomplete_total()),
    );
    reg.gauge(
        "wafio_waf_apps_with_script_rules",
        "Apps of the bundle in force with an enabled script rule.",
        || u(crate::script_rules::apps_with_script_rules()),
    );
    reg.counter(
        "wafio_waf_script_errors",
        "Script-rule runs that ended in a runtime error.",
        || u(crate::script_rules::errors_total()),
    );
    reg.counter(
        "wafio_waf_script_rules_rejected",
        "Script rules dropped at bundle load because they did not compile.",
        || u(crate::script_rules::rejected_total()),
    );
    reg.gauge(
        "wafio_waf_script_runs_in_flight",
        "Script-rule runs executing now.",
        || crate::script_rules::runs_in_flight() as f64,
    );
    reg.labeled_counter(
        "wafio_waf_ratelimit_evictions",
        "L7 rate-limit buckets removed: expired (cleaner), capacity (store full, least recently used first) or capacity_locked (an active lockout evicted because its shard held nothing else).",
        || {
            use wafio_application::ratelimit as r;
            wafio_agent_io::store_limits::eviction_counter_samples(r::expired_evicted_total(), r::capacity_evicted_total(), r::capacity_locked_evicted_total())
        },
    );
    reg.labeled_counter(
        "wafio_waf_blockstore_evictions",
        "Block-store records removed: expired (cleaner), capacity (store full, least recently used first) or capacity_locked (an active block evicted because its shard held nothing else).",
        || {
            use wafio_application::blocklist as b;
            wafio_agent_io::store_limits::eviction_counter_samples(b::expired_evicted_total(), b::capacity_evicted_total(), b::capacity_locked_evicted_total())
        },
    );
    reg.labeled_counter(
        "wafio_waf_challenge_pinned_evictions",
        "Challenge records evicted while still protected because their table held nothing else: spent_tokens (a solved token can be used again) and revoked_cookies (a revoked cookie works again).",
        || {
            use wafio_agent_pages::challenge_replay as c;
            let store = |v: &str, n: u64| Sample {
                labels: vec![Label {
                    name: "store".into(),
                    value: v.into(),
                }],
                value: u(n),
            };
            vec![
                store("revoked_cookies", c::revoked_cookie_pinned_evictions()),
                store("spent_tokens", c::spent_token_pinned_evictions()),
            ]
        },
    );
    reg.counter(
        "wafio_waf_challenge_verify_limited",
        "Challenge verify POSTs refused with 429 by the per-client-IP limit.",
        || u(wafio_agent_pages::challenge_verify_limit::verify_refused_total()),
    );
    reg.gauge(
        "wafio_waf_body_decode_budget_in_use_bytes",
        "Bytes reserved from the process-wide body decode budget.",
        wafio_bodyinspect_budget_in_use,
    );
    let l = link.clone();
    reg.counter(
        "wafio_waf_telemetry_decisions",
        "Decisions offered to the control-plane telemetry queue.",
        move || u(l.telemetry_stats().decisions),
    );
    let l = link.clone();
    reg.counter(
        "wafio_waf_telemetry_dropped",
        "Decisions dropped because the telemetry queue was full.",
        move || u(l.telemetry_stats().dropped),
    );
    let l = link.clone();
    reg.counter(
        "wafio_waf_telemetry_send_failures",
        "Decisions the gRPC stream refused.",
        move || u(l.telemetry_stats().send_failed),
    );
    reg.gauge(
        "wafio_waf_telemetry_queue_length",
        "Decisions waiting in the telemetry queue.",
        move || link.telemetry_stats().queue_len as f64,
    );
}

/// The decode budget in use, in bytes.
fn wafio_bodyinspect_budget_in_use() -> f64 {
    wafio_bodyinspect::inflight_decode_bytes_used() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_has_no_percentiles_without_samples() {
        let c = heartbeat_counters();
        if c.analyze_latency_samples == 0 {
            assert_eq!(
                (
                    c.analyze_latency_p50_us,
                    c.analyze_latency_p95_us,
                    c.analyze_latency_p99_us
                ),
                (0, 0, 0)
            );
        }
        assert_eq!(c.script_runs_in_flight, 0);
    }

    #[test]
    fn registry_has_the_agent_series() {
        let reg = Registry::new();
        let link = test_link();
        register_agent_metrics(&reg, link, &Arc::new(TlsMetrics::default()));
        let text = String::from_utf8(reg.write()).unwrap();
        for name in [
            "wafio_agent_uptime_seconds",
            "wafio_waf_control_plane_connected",
            "wafio_waf_analyze_duration_seconds",
            "wafio_waf_analyze_panics_total",
            "wafio_waf_partial_coverage_flags",
            "wafio_waf_maintenance_responses_total",
            "wafio_waf_ratelimit_evictions_total",
            r#"wafio_waf_compression_responses_total{encoding="br"}"#,
            r#"wafio_waf_compression_bytes_total{dir="in"}"#,
            r#"wafio_waf_compression_skipped_total{reason="streamed"}"#,
            r#"wafio_waf_static_responses_total{status="200"}"#,
            r#"wafio_waf_static_responses_total{status="416"}"#,
            "wafio_waf_static_bytes_total",
            r#"wafio_waf_challenge_pinned_evictions_total{store="spent_tokens"}"#,
            r#"wafio_waf_challenge_pinned_evictions_total{store="revoked_cookies"}"#,
            "wafio_waf_challenge_verify_limited_total",
            "wafio_waf_body_decode_budget_in_use_bytes",
            "wafio_waf_telemetry_queue_length",
            r#"wafio_waf_acme_orders_total{result="issued"}"#,
            r#"wafio_waf_acme_orders_total{result="failed"}"#,
            r#"wafio_waf_certificate_installs_total{result="ok"}"#,
            "wafio_waf_tls_certificate_expiry_seconds",
        ] {
            assert!(text.contains(name), "{name} missing");
        }
        assert!(!text.contains("wafio_waf_crs_"));
        assert!(!text.contains("wafio_waf_apps_without_rule_engine"));
        assert!(text.ends_with("# EOF\n"));
    }

    fn test_link() -> Arc<ControlLink> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _g = rt.enter();
        let cfg = wafio_control::ControlConfig {
            server_address: "127.0.0.1:1".into(),
            server_name: String::new(),
            cert_pem: Vec::new(),
            key_pem: Vec::new(),
            ca_pem: Vec::new(),
            agent_name: "t".into(),
            hostname: String::new(),
            version: "t".into(),
            host_key: String::new(),
            features: Vec::new(),
            state_dir: String::new(),
            bundle_cache_max_age: std::time::Duration::ZERO,
            security_data_dir: String::new(),
            component_paths: Default::default(),
        };
        let link = ControlLink::new(cfg, crate::run::test_hooks());
        std::mem::forget(rt);
        link
    }
}
