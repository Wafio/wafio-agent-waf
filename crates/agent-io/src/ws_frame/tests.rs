//! Frame connection tests, plus the connection behaviours the relay relies on.

use std::sync::Arc;

use super::*;

/// An in-memory client/server pair after a real handshake.
async fn connected_pair() -> (Arc<WsConnection>, Arc<WsConnection>) {
    let (nc, ns) = tokio::io::duplex(1 << 20);
    let client =
        tokio::spawn(
            async move { WsConnection::client(Box::new(nc), "pipe.test", "/", &[]).await },
        );
    let server = WsConnection::server(Box::new(ns))
        .await
        .expect("server handshake");
    let (client, sub) = client
        .await
        .unwrap()
        .map_err(|(e, _)| e)
        .expect("client handshake");
    assert_eq!(sub, "");
    (Arc::new(client), Arc::new(server))
}

#[tokio::test]
async fn client_text_to_server() {
    let (client, server) = connected_pair().await;
    client.send_data_message(OP_TEXT, b"hello").await.unwrap();
    assert_eq!(
        server.next_data_message().await.unwrap(),
        (OP_TEXT, b"hello".to_vec())
    );
}

#[tokio::test]
async fn server_binary_to_client_and_large() {
    let (client, server) = connected_pair().await;
    server
        .send_data_message(OP_BINARY, &[1, 2, 3])
        .await
        .unwrap();
    assert_eq!(
        client.next_data_message().await.unwrap(),
        (OP_BINARY, vec![1, 2, 3])
    );
    let big: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    client.send_data_message(OP_BINARY, &big).await.unwrap();
    assert_eq!(server.next_data_message().await.unwrap().1, big);
    server
        .send_data_message(OP_TEXT, &big[..300])
        .await
        .unwrap();
    assert_eq!(
        client.next_data_message().await.unwrap().1,
        big[..300].to_vec()
    );
}

/// Writes raw frames as a client would (masked).
fn client_frame(fin: bool, op: u8, payload: &[u8]) -> Vec<u8> {
    let key = [1u8, 2, 3, 4];
    let mut f = vec![if fin { 0x80 | op } else { op }, 0x80 | payload.len() as u8];
    f.extend_from_slice(&key);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
    f
}

async fn raw_server() -> (tokio::io::DuplexStream, Arc<WsConnection>) {
    let (nc, ns) = tokio::io::duplex(1 << 16);
    (
        nc,
        Arc::new(WsConnection::new(Box::new(ns), true, Vec::new())),
    )
}

#[tokio::test]
async fn fragmented_message_assembled_with_ping_between() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut nc, server) = raw_server().await;
    let mut raw = client_frame(false, OP_TEXT, b"frag");
    raw.extend(client_frame(true, OP_PING, b"p"));
    raw.extend(client_frame(false, OP_CONTINUATION, b"ment"));
    raw.extend(client_frame(true, OP_CONTINUATION, b"ed"));
    nc.write_all(&raw).await.unwrap();
    assert_eq!(
        server.next_data_message().await.unwrap(),
        (OP_TEXT, b"fragmented".to_vec())
    );
    let mut pong = [0u8; 3];
    nc.read_exact(&mut pong).await.unwrap();
    assert_eq!(pong, [0x80 | OP_PONG, 1, b'p']);
}

/// The ping handler ignores a pong that cannot be written within the reply timeout
/// (a data write to a slow peer holds the writer); the read goes on ("hi" after 1 s).
#[tokio::test]
async fn ping_while_writer_busy_keeps_reading() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut nc, server) = raw_server().await;
    let big = vec![7u8; 1 << 20];
    let s = server.clone();
    let b = big.clone();
    let writer = tokio::spawn(async move { s.send_data_message(OP_BINARY, &b).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut raw = client_frame(true, OP_PING, b"p");
    raw.extend(client_frame(true, OP_TEXT, b"hi"));
    nc.write_all(&raw).await.unwrap();
    let start = Instant::now();
    assert_eq!(
        server.next_data_message().await.unwrap(),
        (OP_TEXT, b"hi".to_vec())
    );
    assert!(start.elapsed() >= REPLY_WRITE_TIMEOUT - Duration::from_millis(100));
    // the pong timed out waiting for the writer: not sticky, no frame written
    let mut got = vec![0u8; 10 + big.len()];
    nc.read_exact(&mut got).await.unwrap();
    assert_eq!(
        got[..10],
        [0x80 | OP_BINARY, 127, 0, 0, 0, 0, 0, 0x10, 0, 0]
    );
    assert_eq!(got[10..], big[..]);
    writer.await.unwrap().unwrap();
    server.send_data_message(OP_TEXT, b"ok").await.unwrap();
    let mut ok = [0u8; 4];
    nc.read_exact(&mut ok).await.unwrap();
    assert_eq!(ok, [0x80 | OP_TEXT, 2, b'o', b'k']);
}

/// A pong that took the writer but timed out mid-write is sticky,
/// so no later frame follows a torn one; the read still goes on.
#[tokio::test]
async fn pong_write_timeout_is_sticky_for_writes() {
    use tokio::io::AsyncWriteExt;
    let (mut nc, server) = raw_server().await;
    server
        .send_data_message(OP_BINARY, &vec![0u8; (1 << 16) - 4])
        .await
        .unwrap(); // fills the pipe exactly
    let mut raw = client_frame(true, OP_PING, b"p");
    raw.extend(client_frame(true, OP_TEXT, b"hi"));
    nc.write_all(&raw).await.unwrap();
    assert_eq!(
        server.next_data_message().await.unwrap(),
        (OP_TEXT, b"hi".to_vec())
    );
    assert_eq!(
        server.send_data_message(OP_TEXT, b"x").await.unwrap_err(),
        WsError::Timeout
    );
}

/// A pong write I/O error does not end the read either; it stays the write side's sticky error.
#[tokio::test]
async fn pong_io_error_keeps_reading() {
    struct Broken;
    impl tokio::io::AsyncWrite for Broken {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    let mut raw = client_frame(true, OP_PING, b"p");
    raw.extend(client_frame(true, OP_TEXT, b"hi"));
    let server = WsConnection::new(
        Box::new(tokio::io::join(std::io::Cursor::new(raw), Broken)),
        true,
        Vec::new(),
    );
    assert_eq!(
        server.next_data_message().await.unwrap(),
        (OP_TEXT, b"hi".to_vec())
    );
    assert!(server.send_data_message(OP_TEXT, b"x").await.is_err());
}

#[tokio::test]
async fn close_surfaces_as_typed_error() {
    let (client, server) = connected_pair().await;
    server
        .send_close(WS_CLOSE_POLICY_VIOLATION, "policy violation")
        .await
        .unwrap();
    assert_eq!(
        client.next_data_message().await.unwrap_err(),
        WsError::Close {
            code: 1008,
            text: "policy violation".into()
        }
    );
    // the client answered with a close frame of its own
    assert_eq!(
        server.next_data_message().await.unwrap_err(),
        WsError::Close {
            code: 1008,
            text: String::new()
        }
    );
    // later writes fail: a close was sent
    assert_eq!(
        server.send_data_message(OP_TEXT, b"x").await.unwrap_err(),
        WsError::CloseSent
    );
}

#[tokio::test]
async fn peer_disconnect_is_abnormal_closure() {
    let (nc, server) = raw_server().await;
    drop(nc);
    assert_eq!(
        server.next_data_message().await.unwrap_err(),
        WsError::Close {
            code: 1006,
            text: "unexpected EOF".into()
        }
    );
    // sticky
    assert!(server.next_data_message().await.is_err());
}

#[tokio::test]
async fn write_deadline_enforced() {
    let (client, _server) = connected_pair().await;
    client.set_write_expiry(Some(Instant::now() - Duration::from_secs(1)));
    assert_eq!(
        client.send_data_message(OP_TEXT, b"x").await.unwrap_err(),
        WsError::Timeout
    );
}

#[tokio::test]
async fn read_deadline_wakes_reader() {
    let (_client, server) = connected_pair().await;
    let s = server.clone();
    let t = tokio::spawn(async move { s.next_data_message().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    server.set_read_expiry(Some(Instant::now()));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), t)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err(),
        WsError::Timeout
    );
}

#[tokio::test]
async fn write_close_after_close_is_safe() {
    let (client, _server) = connected_pair().await;
    client.close().await;
    client.close().await;
    assert_eq!(
        client
            .send_close(WS_CLOSE_NORMAL_CLOSURE, "done")
            .await
            .unwrap_err(),
        WsError::Closed
    );
}

#[tokio::test]
async fn read_limit_closes_1009() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut nc, server) = raw_server().await;
    server.set_max_message_bytes(4);
    nc.write_all(&client_frame(true, OP_BINARY, b"too long"))
        .await
        .unwrap();
    assert_eq!(
        server.next_data_message().await.unwrap_err(),
        WsError::ReadLimit
    );
    let mut close = [0u8; 4];
    nc.read_exact(&mut close).await.unwrap();
    assert_eq!(close, [0x80 | OP_CLOSE, 2, 0x03, 0xf1]);
}

#[tokio::test]
async fn protocol_errors_close_1002() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for (raw, msg) in [
        (vec![0x81, 0x01, b'x'], "bad MASK"),
        (
            client_frame(true, OP_CONTINUATION, b"x"),
            "continuation after FIN",
        ),
        (client_frame(true, 3, b""), "bad opcode 3"),
        (client_frame(false, OP_PING, b""), "FIN not set on control"),
        (
            client_frame(true, OP_CLOSE, &[0x03, 0xed]),
            "bad close code 1005",
        ),
        (
            {
                let mut f = client_frame(true, OP_TEXT, b"");
                f[0] |= 0x40;
                f
            },
            "RSV1 set",
        ),
    ] {
        let (mut nc, server) = raw_server().await;
        nc.write_all(&raw).await.unwrap();
        assert_eq!(
            server.next_data_message().await.unwrap_err(),
            WsError::Protocol(msg.into()),
            "{msg}"
        );
        let mut head = [0u8; 4];
        nc.read_exact(&mut head).await.unwrap();
        assert_eq!(
            (head[0], head[2], head[3]),
            (0x80 | OP_CLOSE, 0x03, 0xea),
            "{msg}"
        );
    }
}

#[tokio::test]
async fn server_from_request_validates_and_echoes_subprotocol() {
    use tokio::io::AsyncReadExt;
    let req = |key: &str, version: &str| WsRequestHead {
        method: "GET".into(),
        request_target: "/chat".into(),
        headers: vec![
            ("Connection".into(), "keep-alive, Upgrade".into()),
            ("Upgrade".into(), "WebSocket".into()),
            ("Sec-WebSocket-Version".into(), version.into()),
            ("Sec-WebSocket-Key".into(), key.into()),
        ],
    };
    let (mut nc, ns) = tokio::io::duplex(4096);
    WsConnection::server_from_request(Box::new(ns), &req("dGhlIHNhbXBsZSBub25jZQ==", "13"), "chat")
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let n = nc.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(
        resp.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{resp}"
    );
    assert!(
        resp.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"),
        "{resp}"
    );
    assert!(resp.contains("Sec-WebSocket-Protocol: chat\r\n"), "{resp}");
    for (key, version) in [("short", "13"), ("dGhlIHNhbXBsZSBub25jZQ==", "8")] {
        let (_nc, ns) = tokio::io::duplex(4096);
        assert!(
            WsConnection::server_from_request(Box::new(ns), &req(key, version), "")
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn client_handshake_rejects_bad_accept() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (nc, mut ns) = tokio::io::duplex(4096);
    let t = tokio::spawn(async move { WsConnection::client(Box::new(nc), "h", "/", &[]).await });
    let mut buf = vec![0u8; 1024];
    let _ = ns.read(&mut buf).await.unwrap();
    ns.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: nope\r\nSec-WebSocket-Protocol: v2\r\n\r\n").await.unwrap();
    let (err, sub) = t.await.unwrap().err().unwrap();
    assert_eq!(
        (err, sub.as_str()),
        (WsError::Handshake("websocket: bad handshake".into()), "v2")
    );
}

/// The handshake adds `User-Agent: Go-http-client/1.1` when its headers carry
/// none, writes the first one given and none for an empty value.
#[tokio::test]
async fn client_handshake_default_user_agent() {
    use tokio::io::AsyncReadExt;
    let head = |headers: Vec<(String, String)>| async move {
        let (nc, mut ns) = tokio::io::duplex(4096);
        tokio::spawn(async move { WsConnection::client(Box::new(nc), "h", "/", &headers).await });
        let mut buf = vec![0u8; 2048];
        let n = ns.read(&mut buf).await.unwrap();
        String::from_utf8(buf[..n].to_vec()).unwrap()
    };
    let h = |k: &str, v: &str| (k.to_string(), v.to_string());
    let req = head(vec![]).await;
    assert_eq!(req.matches("User-Agent: ").count(), 1, "{req}");
    assert!(req.contains("User-Agent: Go-http-client/1.1\r\n"), "{req}");
    let req = head(vec![h("User-Agent", "ua/1")]).await;
    assert!(
        req.contains("User-Agent: ua/1\r\n") && !req.contains("Go-http"),
        "{req}"
    );
    let req = head(vec![h("User-Agent", "")]).await;
    assert!(!req.contains("User-Agent"), "{req}");
}

#[test]
fn close_codes_and_format() {
    assert_eq!(
        (WS_CLOSE_POLICY_VIOLATION, WS_CLOSE_MESSAGE_TOO_BIG),
        (1008, 1009)
    );
    assert!(encode_close_payload(1005, "x").is_empty());
    assert_eq!(
        encode_close_payload(1000, "ok"),
        vec![0x03, 0xe8, b'o', b'k']
    );
    assert!(
        is_acceptable_close_code(1000)
            && is_acceptable_close_code(4999)
            && is_acceptable_close_code(1014)
    );
    assert!(
        !is_acceptable_close_code(1004)
            && !is_acceptable_close_code(1006)
            && !is_acceptable_close_code(1015)
            && !is_acceptable_close_code(2999)
    );
}
