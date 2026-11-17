//! Measurement (not a pass/fail test): detection runs inline on the tokio worker that owns the
//! request, so a big body being inspected blocks that worker. How long does a small
//! request on another connection wait while big bodies are inspected?
//!
//! Run (release-like profile, the numbers are meaningless in debug):
//! `cargo test --profile conformance -p wafio-proxy --test inline_stall -- --ignored --nocapture`
//! and read the `STALL` lines. The server runs on its own runtime built with `runtime_builder()`
//! and a fixed number of workers; the clients and the fake upstream run on a second runtime, so
//! their own scheduling does not pollute the numbers.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use wafio_proxy::{AppSpec, Proxy, ProxyOptions};

const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const BIG: usize = 4 << 20;

fn pct(v: &mut [Duration], p: f64) -> Duration {
    v.sort();
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)]
}

/// A 4 MiB JSON body: `shape` picks what the detection has to chew.
fn big_body(shape: &str) -> Vec<u8> {
    match shape {
        // One huge string value (windowed, head and tail scanned).
        "one-string" => format!(
            r#"{{"card":"4111111111111111","note":"{}"}}"#,
            "lorem ipsum dolor sit amet ".repeat(BIG / 27)
        )
        .into_bytes(),
        // Very many short fields (field cap, engine budget).
        "many-fields" => {
            let mut b = String::from("{");
            let mut i = 0;
            while b.len() < BIG {
                b.push_str(&format!(r#""f{i}":"value {i} text","#));
                i += 1;
            }
            b.push_str(r#""card":"4111111111111111"}"#);
            b.into_bytes()
        }
        _ => unreachable!(),
    }
}

fn post_request(path: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!("POST {path} HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    r.extend_from_slice(body);
    r
}

async fn status_of(addr: std::net::SocketAddr, raw: &[u8]) -> u16 {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(raw).await.unwrap();
    let mut r = tokio::io::BufReader::new(s);
    read_reply(&mut r).await.unwrap().status
}

#[test]
#[ignore = "measurement: run with --profile conformance --ignored --nocapture"]
fn inline_detection_and_small_request_latency() {
    let client = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let up = client.block_on(http_upstream());
    let rules = format!(
        r#"{{"path_exceptions":[{{"path":"/pay","match":"prefix","field_rules":[{{"field":"card","action":"encrypt_aes","aes_key":"{KEY}"}}]}}]}}"#
    );
    for (workers, in_place) in [
        (1usize, false),
        (2, false),
        (4, false),
        (1, true),
        (2, true),
        (4, true),
    ] {
        wafio_proxy::set_block_in_place(in_place);
        let mode = if in_place { "block_in_place" } else { "inline" };
        let server = wafio_proxy::runtime_builder()
            .worker_threads(workers)
            .build()
            .unwrap();
        let port = free_port();
        let proxy = {
            let _g = server.enter();
            let p = Proxy::new(ProxyOptions::new(Arc::new(|_| {})));
            let mut a: AppSpec = app("a1", port, &format!("http://{}", up.addr));
            a.analysis = analysis_setup(&rules);
            p.apply(vec![a]).unwrap();
            p
        };
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        for shape in ["one-string", "many-fields"] {
            let body = big_body(shape);
            let req = post_request("/pay/now", &body);
            // The cost of one big request alone, and of a small one with nobody else around.
            let (alone, small_alone) = client.block_on(async {
                let t = Instant::now();
                assert_eq!(status_of(addr, &req).await, 200);
                let alone = t.elapsed();
                let mut v = Vec::new();
                for _ in 0..200 {
                    let t = Instant::now();
                    assert_eq!(status_of(addr, &get("/s")).await, 200);
                    v.push(t.elapsed());
                }
                (alone, (pct(&mut v.clone(), 0.5), pct(&mut v, 0.99)))
            });
            eprintln!(
                "STALL {mode} workers={workers} shape={shape}: one 4 MiB request alone {alone:?}; small alone p50 {:?} p99 {:?}",
                small_alone.0, small_alone.1
            );
            for big in [1usize, 2, 4] {
                let (mut lat, took) = client.block_on(async {
                    let t = Instant::now();
                    let bigs: Vec<_> = (0..big)
                        .map(|_| {
                            let req = req.clone();
                            tokio::spawn(async move { status_of(addr, &req).await })
                        })
                        .collect();
                    // Small requests, back to back on fresh connections, while the big ones run.
                    let mut lat = Vec::new();
                    while !bigs.iter().all(|h| h.is_finished()) {
                        let s = Instant::now();
                        assert_eq!(status_of(addr, &get("/s")).await, 200);
                        lat.push(s.elapsed());
                    }
                    for h in bigs {
                        assert_eq!(h.await.unwrap(), 200);
                    }
                    (lat, t.elapsed())
                });
                let (p50, p99, max) = (
                    pct(&mut lat, 0.5),
                    pct(&mut lat, 0.99),
                    *lat.iter().max().unwrap(),
                );
                eprintln!(
                    "STALL {mode} workers={workers} shape={shape} big_in_flight={big}: batch {took:?}; {} small requests: p50 {p50:?} p99 {p99:?} max {max:?}",
                    lat.len()
                );
            }
        }
        drop(proxy);
        server.shutdown_background();
    }
    wafio_proxy::set_block_in_place(false);
}
