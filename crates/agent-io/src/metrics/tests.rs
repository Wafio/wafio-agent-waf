use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use super::*;

#[test]
fn registry_writes_open_metrics() {
    let reg = Registry::new();
    reg.counter("wafio_test_dropped", "Dropped rows.", || 3.0);
    reg.gauge("wafio_test_pending", "Queue depth.", || 1.5);
    reg.labeled_gauge("wafio_test_streams", "Streams by kind.", || {
        vec![Sample {
            labels: vec![Label {
                name: "kind".into(),
                value: "we\"ird\\\n".into(),
            }],
            value: 2.0,
        }]
    });
    let h = Histogram::new(&[0.001, 0.005], Duration::ZERO, 0);
    h.observe(Duration::from_micros(500));
    h.observe(Duration::from_millis(3));
    h.observe(Duration::from_secs(1));
    reg.histogram("wafio_test_latency_seconds", "Latency.", Arc::new(h));

    let resp = reg.handle("GET");
    assert_eq!(resp.headers[0], ("Content-Type", CONTENT_TYPE.to_string()));
    let body = String::from_utf8(resp.body).unwrap();
    for want in [
        "# TYPE wafio_test_dropped counter\n",
        "wafio_test_dropped_total 3\n",
        "wafio_test_pending 1.5\n",
        "wafio_test_streams{kind=\"we\\\"ird\\\\\\n\"} 2\n",
        "wafio_test_latency_seconds_bucket{le=\"0.001\"} 1\n",
        "wafio_test_latency_seconds_bucket{le=\"0.005\"} 2\n",
        "wafio_test_latency_seconds_bucket{le=\"+Inf\"} 3\n",
        "wafio_test_latency_seconds_count 3\n",
        "wafio_test_latency_seconds_sum 1.0035\n",
    ] {
        assert!(body.contains(want), "missing {want:?} in\n{body}");
    }
    assert!(body.ends_with("# EOF\n"));
    assert!(body.find("wafio_test_dropped") < body.find("wafio_test_streams"));
    assert_eq!(reg.handle("POST").status, 405);
}

#[test]
fn registry_rejects_bad_families() {
    type Case = Box<dyn Fn(&Registry) + std::panic::RefUnwindSafe>;
    let cases: Vec<Case> = vec![
        Box::new(|r| r.counter("x_total", "", || 0.0)),
        Box::new(|r| r.gauge("1bad", "", || 0.0)),
        Box::new(|r| {
            r.gauge("dup", "", || 0.0);
            r.gauge("dup", "", || 0.0);
        }),
    ];
    for fn_ in cases {
        let res = std::panic::catch_unwind(|| fn_(&Registry::new()));
        assert!(res.is_err(), "expected panic");
    }
}

#[test]
fn check_loopback_listen_address_cases() {
    for (addr, ok) in [
        ("127.0.0.1:9100", true),
        ("[::1]:9100", true),
        ("localhost:9100", false),
        ("0.0.0.0:9100", false),
        ("10.0.0.1:9100", false),
        (":9100", false),
        ("127.0.0.1", false),
        ("[::ffff:127.0.0.1]:9100", true),
        ("[fe80::1%lo]:9100", false),
    ] {
        assert_eq!(check_loopback_listen_address(addr).is_ok(), ok, "{addr}");
    }
}

#[tokio::test]
async fn listen_refuses_public_and_serves_loopback() {
    let err = listen("0.0.0.0:0").await.unwrap_err();
    assert!(err.not_loopback);
    let reg = Arc::new(Registry::new());
    reg.gauge("wafio_up", "Up.", || 1.0);
    let ln = listen("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let _srv = serve(ln, reg);
    let get = |path: &'static str| async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).await.unwrap();
        String::from_utf8(out).unwrap()
    };
    let ok = get("/metrics").await;
    assert!(
        ok.starts_with("HTTP/1.1 200") && ok.contains("wafio_up 1\n"),
        "{ok}"
    );
    let other = get("/debug/pprof/").await;
    assert!(other.starts_with("HTTP/1.1 404"), "{other}");
}

#[test]
fn histogram_window_quantiles() {
    let clock = Arc::new(AtomicI64::new(1_000_000 * 1_000_000_000));
    let mut h = Histogram::new(&ANALYZE_LATENCY_BOUNDS, Duration::from_secs(300), 5);
    let c = clock.clone();
    h.set_clock(move || c.load(Ordering::SeqCst));

    assert_eq!(h.quantiles(&[0.5]).1, 0);
    for _ in 0..98 {
        h.observe(Duration::from_micros(300));
    }
    h.observe(Duration::from_millis(20));
    h.observe(Duration::from_millis(20));
    let (q, n) = h.quantiles(&[0.5, 0.95, 0.99]);
    assert_eq!(n, 100);
    assert!(
        q[0] > Duration::from_micros(250) && q[0] <= Duration::from_micros(500),
        "p50={:?}",
        q[0]
    );
    assert!(q[1] <= Duration::from_micros(500), "p95={:?}", q[1]);
    assert!(
        q[2] > Duration::from_millis(10) && q[2] <= Duration::from_millis(25),
        "p99={:?}",
        q[2]
    );

    clock.fetch_add(360 * 1_000_000_000, Ordering::SeqCst);
    assert_eq!(h.quantiles(&[0.99]).1, 0);
    assert_eq!(h.snapshot().1, 100);
    h.observe(Duration::from_secs(2));
    let (q, n) = h.quantiles(&[0.5]);
    assert_eq!((n, q[0]), (1, Duration::from_secs(1)));
}

#[test]
fn micros_conversion() {
    assert_eq!(micros(Duration::from_nanos(1500)), 1);
    assert_eq!(micros(Duration::from_millis(1)), 1000);
    assert_eq!(micros(Duration::ZERO), 0);
}

#[test]
fn render_float_matches_reference() {
    for (v, want) in [
        (0.0, "0"),
        (-0.0, "-0"),
        (3.0, "3"),
        (1.5, "1.5"),
        (1.0035, "1.0035"),
        (0.00025, "0.00025"),
        (0.0001, "0.0001"),
        (0.00001, "1e-05"),
        (123456.0, "123456"),
        (1234567.0, "1.234567e+06"),
        (1e6, "1e+06"),
        (1e21, "1e+21"),
        (100.0, "100"),
        (1e-300, "1e-300"),
        (f64::INFINITY, "+Inf"),
        (f64::NEG_INFINITY, "-Inf"),
        (f64::NAN, "NaN"),
        (-2.5, "-2.5"),
        (18446744073709551615.0, "1.8446744073709552e+19"),
    ] {
        assert_eq!(render_float(v), want, "{v}");
    }
}
