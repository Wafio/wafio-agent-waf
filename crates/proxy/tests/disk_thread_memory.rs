//! Resident memory after many answers whose bytes are read on a disk thread: a static file read
//! whole, a static file sent in chunks and a copy from the disk tier of the response cache. The
//! agent's allocator, mimalloc 2, gives a block over 64 KiB pages of the thread that made it, and a
//! disk thread that stops allocating never gives them back, so a body made there and freed on a
//! runtime thread stayed resident: about one body per answer. Each case bounds the growth.

#[path = "common/cache_site.rs"]
mod cache_site;
mod common;

use std::net::SocketAddr;

use cache_site::{Dir, reply_to, site, spec};
use common::*;
use wafio_proxy::{CacheSpec, StaticSpec};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const MIB: usize = 1 << 20;
const CONNECTIONS: usize = 8;
/// Answers of the measured round of each case.
const ANSWERS: usize = 1024;

fn resident() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let kib: usize = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap();
    kib << 10
}

/// `answers` requests for `path` over [`CONNECTIONS`] kept-alive connections, each a `200` of `len`
/// bytes with `x_cache` (`None`: no such header).
async fn load(
    addr: SocketAddr,
    path: &'static str,
    len: usize,
    x_cache: Option<&'static str>,
    answers: usize,
) {
    let mut clients = Vec::new();
    for _ in 0..CONNECTIONS {
        clients.push(tokio::spawn(async move {
            let mut c = Client::connect(addr).await.unwrap();
            for _ in 0..answers / CONNECTIONS {
                let r = c.send(&get(path)).await.unwrap();
                assert_eq!(
                    (r.status, r.body.len(), r.header("x-cache")),
                    (200, len, x_cache)
                );
            }
        }));
    }
    for c in clients {
        c.await.unwrap();
    }
}

/// Sends `ANSWERS` answers, after a first round that makes what the connections and the threads
/// keep anyway, and checks that the resident size grew by less than a quarter of `left` per answer:
/// what each one left behind before the fix.
async fn grows_little(
    what: &str,
    addr: SocketAddr,
    path: &'static str,
    len: usize,
    x_cache: Option<&'static str>,
    left: usize,
) {
    load(addr, path, len, x_cache, 64).await;
    settle().await;
    let before = resident();
    load(addr, path, len, x_cache, ANSWERS).await;
    settle().await;
    let grew = resident().saturating_sub(before);
    eprintln!(
        "{what}: {ANSWERS} answers of {} KiB, the resident size grew {} KiB",
        len >> 10,
        grew >> 10
    );
    assert!(grew < ANSWERS * left / 4, "{what}: {} KiB", grew >> 10);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bodies_read_on_a_disk_thread_do_not_stay_resident() {
    let files = Dir::new("disk-thread-memory");
    std::fs::write(files.0.join("whole.bin"), vec![7u8; MIB]).unwrap();
    std::fs::write(files.0.join("chunks.bin"), vec![7u8; 2 * MIB]).unwrap();
    let port = free_port();
    let mut a = app("files", port, "http://127.0.0.1:1");
    a.static_files = Some(StaticSpec::check(files.0.to_str().unwrap(), "not_found", 0).unwrap());
    let (_h, folder) = Harness::serve(vec![a]);

    let up = raw_upstream(|seen| {
        let headers =
            "Content-Type: application/octet-stream\r\nCache-Control: public, max-age=600\r\n";
        (reply_to(seen, "200 OK", headers, &vec![7u8; MIB]), false)
    })
    .await;
    let cache = site(
        up,
        CacheSpec {
            memory_bytes: 0,
            ..spec()
        },
        |_| {},
    )
    .await;
    cache_site::fetch(cache.addr, &get("/copy")).await;

    // The case that left the least goes first, so what the others left cannot hide it.
    let chunk = 256 << 10;
    grows_little(
        "a static file in chunks",
        folder,
        "/chunks.bin",
        2 * MIB,
        None,
        chunk,
    )
    .await;
    grows_little(
        "a disk tier copy",
        cache.addr,
        "/copy",
        MIB,
        Some("HIT"),
        MIB,
    )
    .await;
    grows_little(
        "a static file read whole",
        folder,
        "/whole.bin",
        MIB,
        None,
        MIB,
    )
    .await;
}
