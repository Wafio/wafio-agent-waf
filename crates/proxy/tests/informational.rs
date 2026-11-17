//! Upstream informational (1xx) responses: every 1xx but 101 is skipped, up to the interim
//! response limit (100) of them before the final response (the 101st is an error), and a 101 is
//! the final response (no body). The proxy used to skip only `100 Continue`: a `103 Early Hints`
//! was taken for the answer and its body read to the end of the connection.

mod common;

use common::*;

fn final_ok() -> &'static str {
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Up: 1\r\n\r\nok"
}

fn upstream_for(
    interim: usize,
    code: u16,
) -> impl Fn(&Seen) -> (Vec<u8>, bool) + Send + Sync + 'static {
    move |_| {
        let mut out = String::new();
        for _ in 0..interim {
            out.push_str(&format!(
                "HTTP/1.1 {code} Interim\r\nLink: </s.css>; rel=preload\r\n\r\n"
            ));
        }
        out.push_str(final_ok());
        (out.into_bytes(), false)
    }
}

#[tokio::test]
async fn early_hints_and_other_interim_responses_are_skipped() {
    // 103 Early Hints first, then a mix of 100/102/103 in front of the final answer.
    let up = raw_upstream(|seen: &Seen| {
        let pre = match seen.line.split(' ').nth(1).unwrap() {
            "/early" => "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n",
            "/mixed" => "HTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 199 Odd\r\nX-Interim: yes\r\n\r\n",
            _ => "",
        };
        (format!("{pre}{}", final_ok()).into_bytes(), false)
    })
    .await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let mut c = Client::connect(proxy).await.unwrap();
    for path in ["/early", "/mixed", "/plain", "/early"] {
        let r = c.send(&get(path)).await.unwrap();
        assert_eq!((r.status, r.text()), (200, "ok".into()), "{path}");
        // Nothing of the interim responses reaches the client.
        assert!(
            r.header("link").is_none() && r.header("x-interim").is_none(),
            "{path}: {:?}",
            r.headers
        );
        assert_eq!(r.header("x-up"), Some("1"));
    }
    // The upstream connection went back to the pool: the four requests shared it.
    assert_eq!(up.accepts(), 1);
}

#[tokio::test]
async fn interim_responses_are_capped_at_100() {
    // 100 interim responses then the final one are fine, the 101st interim is an error.
    let up100 = raw_upstream(upstream_for(100, 103)).await;
    let up101 = raw_upstream(upstream_for(101, 103)).await;
    let (p1, p2) = (free_port(), free_port());
    let (_h, a) = Harness::serve(vec![
        app("ok", p1, &format!("http://{}", up100.addr)),
        app("many", p2, &format!("http://{}", up101.addr)),
    ]);
    let r = one(a, &get("/")).await;
    assert_eq!((r.status, r.text()), (200, "ok".into()));
    let many = format!("127.0.0.1:{p2}").parse().unwrap();
    let r = one(many, &get("/")).await;
    assert_eq!(r.status, 502, "{r:?}");
    // The error is not retried (not a stale connection): one request reached the upstream.
    assert_eq!(up101.count(), 1);
}

#[tokio::test]
async fn a_101_is_the_final_response_without_a_body() {
    let up = raw_upstream(|_: &Seen| {
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x-test\r\nX-Up: 1\r\n\r\nstray bytes"
                .to_vec(),
            true,
        )
    })
    .await;
    let port = free_port();
    let (_h, proxy) = Harness::serve(vec![app("a1", port, &format!("http://{}", up.addr))]);
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        Client::connect(proxy).await.unwrap().send(&get("/")),
    )
    .await
    .expect("answered")
    .unwrap();
    assert_eq!((r.status, r.body.len()), (101, 0), "{r:?}");
    // The upstream connection was not reused after the 101: the next request dials again.
    assert_eq!(one(proxy, &get("/again")).await.status, 101);
    assert_eq!(up.accepts(), 2);
}
