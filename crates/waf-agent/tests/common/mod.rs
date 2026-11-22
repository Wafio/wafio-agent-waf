//! What the test files of this crate share: ports that stay reserved, and the wait for the bundle
//! cache.
#![allow(dead_code)]

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The sockets that keep the ports of [`free_port`] taken until the test process ends.
static RESERVED_PORTS: Mutex<Vec<tokio::net::TcpSocket>> = Mutex::new(Vec::new());

/// A local port that stays reserved for the caller. A port that was bound and released could be
/// handed to another test's bind to port 0 or outgoing connection before the agent bound it. The
/// port stays bound with SO_REUSEADDR and never listens: Linux then gives it to no bind to port 0
/// and no outgoing connection, refuses connections to it, and still lets the agent, which also
/// binds with SO_REUSEADDR, bind and listen on it.
pub fn free_port() -> u16 {
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.set_reuseaddr(true).unwrap();
    sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = sock.local_addr().unwrap().port();
    RESERVED_PORTS.lock().unwrap().push(sock);
    port
}

/// The text of `<state>/last-bundle.json` once it holds `generation` or a later one. The agent acks
/// a bundle before it writes the cache, and an older file would pass a check the newer one fails.
pub async fn cached_bundle(state: &Path, generation: i64) -> String {
    let file = state.join("last-bundle.json");
    let end = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(cached) = wafio_control::load_bundle_cache(state, &|_| Ok(()))
            && cached.generation >= generation
            && let Ok(text) = std::fs::read_to_string(&file)
        {
            return text;
        }
        assert!(
            Instant::now() < end,
            "generation {generation} not in {} within a minute",
            file.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
