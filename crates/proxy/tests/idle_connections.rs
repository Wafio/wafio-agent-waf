//! Heap held by kept-alive connections that each carried one large body. The read buffer of an idle
//! connection must not keep the size its largest body made it grow to.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Duration;

use common::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// The system allocator with a count of the bytes that are live.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is passed to the system allocator unchanged; the counter only adds and subtracts sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Relaxed);
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new_size) };
        if !q.is_null() {
            LIVE.fetch_add(new_size, Relaxed);
            LIVE.fetch_sub(l.size(), Relaxed);
        }
        q
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// An upstream that reads each body and keeps none of it. It answers with a length, or (`streamed`) in
/// chunks with a pause before the last one, which the proxy relays piece by piece.
async fn sink_upstream(streamed: bool) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let mut r = BufReader::new(s);
                while let Ok(Some((_, headers))) = read_head(&mut r).await {
                    let mut left: usize =
                        header(&headers, "content-length").map_or(0, |v| v.parse().unwrap());
                    let mut sink = [0u8; 8192];
                    while left > 0 {
                        match r.read(&mut sink[..left.min(8192)]).await {
                            Ok(n) if n > 0 => left -= n,
                            _ => return,
                        }
                    }
                    let w = r.get_mut();
                    let sent = if streamed {
                        let first =
                            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n";
                        let ok = w.write_all(first).await.is_ok();
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        ok && w.write_all(b"0\r\n\r\n").await.is_ok()
                    } else {
                        let whole = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                        w.write_all(whole).await.is_ok()
                    };
                    if !sent {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// Sends `request` and reads the answer: whole, or chunk by chunk up to the closing one.
async fn exchange(c: &mut Client, request: &[u8], streamed: bool) {
    if !streamed {
        assert_eq!(c.send(request).await.unwrap().status, 200);
        return;
    }
    c.0.get_mut().write_all(request).await.unwrap();
    let (line, _) = read_head(&mut c.0).await.unwrap().unwrap();
    assert_eq!(line.split(' ').nth(1), Some("200"));
    loop {
        let mut size = String::new();
        c.0.read_line(&mut size).await.unwrap();
        let n = usize::from_str_radix(size.trim(), 16).unwrap();
        c.0.read_exact(&mut vec![0; n + 2]).await.unwrap();
        if n == 0 {
            return;
        }
    }
}

const CONNECTIONS: usize = 16;
const BODY: usize = 1 << 20;

/// The bytes that `CONNECTIONS - 1` kept-alive connections hold after each has carried one body of
/// `BODY` bytes, beyond what the first connection had already started.
async fn held_by_idle_connections(streamed: bool) -> usize {
    let up = sink_upstream(streamed).await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![app("idle", port, &format!("http://{up}"))]);
    let request = post("/upload", "application/octet-stream", &vec![b'a'; BODY]);
    // The first connection starts everything the proxy builds once; it stays open too.
    let mut clients = vec![Client::connect(proxy).await.unwrap()];
    exchange(&mut clients[0], &request, streamed).await;
    settle().await;
    let before = LIVE.load(Relaxed);
    for _ in 1..CONNECTIONS {
        let mut c = Client::connect(proxy).await.unwrap();
        exchange(&mut c, &request, streamed).await;
        clients.push(c);
    }
    settle().await;
    let held = LIVE.load(Relaxed).saturating_sub(before);
    drop(clients);
    held
}

#[tokio::test]
async fn idle_connections_do_not_keep_the_buffer_of_a_large_body() {
    let mut held = Vec::new();
    for streamed in [false, true] {
        let bytes = held_by_idle_connections(streamed).await;
        eprintln!(
            "{} idle connections after one {} KiB body each hold {} KiB (streamed answer: {streamed})",
            CONNECTIONS - 1,
            BODY >> 10,
            bytes >> 10
        );
        held.push(bytes);
    }
    // A buffer grown to the body would hold at least BODY bytes per connection.
    for (bytes, streamed) in held.into_iter().zip([false, true]) {
        assert!(
            bytes < (CONNECTIONS - 1) * BODY / 4,
            "the idle connections hold {} KiB (streamed answer: {streamed})",
            bytes >> 10
        );
    }
}
