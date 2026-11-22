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

/// The text of `<state>/last-bundle.json` once the file is there. The agent acks a bundle before
/// it writes the cache, so a test that reads the cache waits for it; the file appears whole, as
/// the write renames it into place.
pub async fn cached_bundle(state: &Path) -> String {
    let file = state.join("last-bundle.json");
    let end = Instant::now() + Duration::from_secs(60);
    loop {
        match std::fs::read_to_string(&file) {
            Ok(text) => return text,
            Err(e) => assert!(
                Instant::now() < end,
                "{} not written within a minute: {e}",
                file.display()
            ),
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
