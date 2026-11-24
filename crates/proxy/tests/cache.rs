//! The response cache through the public API: what is kept and sent again, what never is, what the
//! key holds, what stays on disk and what a damaged or foreign file does. The cases that need an
//! engine to detect something are in `cache_engine.rs`.

#[path = "common/cache_site.rs"]
mod cache_site;
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use cache_site::*;
use common::*;
use wafio_proxy::{CacheHost, CacheRule, CacheSpec, CompressionSpec};

async fn page_site() -> Site {
    site(counting("200 OK", PUBLIC).await, spec(), |_| {}).await
}

// What is kept.

#[tokio::test]
async fn a_page_with_a_lifetime_is_kept_and_sent_again_without_asking_the_application() {
    let s = page_site().await;
    let first = fetch(s.addr, &get("/page")).await;
    assert_eq!((first.status, first.text().as_str()), (200, "answer 1"));
    assert_eq!(x_cache(&first), "MISS");
    assert_eq!(first.header("age"), None);
    let second = fetch(s.addr, &get("/page")).await;
    assert_eq!((second.status, second.text().as_str()), (200, "answer 1"));
    assert_eq!(x_cache(&second), "HIT");
    assert!(
        second
            .header("age")
            .is_some_and(|a| a.parse::<u64>().is_ok())
    );
    assert_eq!(second.header("cache-control"), Some("public, max-age=600"));
    assert_eq!(second.header("content-type"), Some("text/html"));
    assert_eq!(second.header("content-length"), Some("8"));
    assert_eq!(
        second.header("x-up"),
        Some("1"),
        "the application's own headers"
    );
    assert_eq!(s.up.count(), 1);
    // A hit emits the decision event of the request, with the status the visitor got.
    let ev = s.h.last_event();
    assert_eq!((s.up.count(), ev.status), (1, 200));
    assert_eq!(
        (common::s(&ev.action), common::s(&ev.uri)),
        ("allow", "/page")
    );
    assert_eq!(s.h.events().len(), 2, "one event for each request");
}

#[tokio::test]
async fn a_copy_is_not_sent_past_its_lifetime_and_the_new_answer_takes_its_place() {
    let up = counting(
        "200 OK",
        "Content-Type: text/html\r\nCache-Control: public, max-age=1\r\n",
    )
    .await;
    let s = site(up, spec(), |_| {}).await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "HIT");
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let late = fetch(s.addr, &get("/a")).await;
    assert_eq!((x_cache(&late), late.text().as_str()), ("MISS", "answer 2"));
    assert_eq!(s.up.count(), 2);
    // The new answer replaced the old copy.
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "HIT");
    assert_eq!(answer_files(&s.dir.0).len(), 1);
}

#[tokio::test]
async fn the_age_the_application_gave_is_part_of_the_age() {
    let up = counting(
        "200 OK",
        "Content-Type: text/html\r\nCache-Control: max-age=600\r\nAge: 40\r\n",
    )
    .await;
    let s = site(up, spec(), |_| {}).await;
    fetch(s.addr, &get("/a")).await;
    let hit = fetch(s.addr, &get("/a")).await;
    assert_eq!(x_cache(&hit), "HIT");
    let age: u64 = hit.header("age").unwrap().parse().unwrap();
    assert!((40..45).contains(&age), "{age}");
}

#[tokio::test]
async fn files_are_kept_for_the_default_time_and_pages_only_when_the_application_says() {
    let up = raw_upstream(|seen| {
        let (ty, status) = match seen.line.split(' ').nth(1).unwrap() {
            "/logo.png" => ("image/png", "200 OK"),
            "/missing.png" => ("image/png", "404 Not Found"),
            _ => ("text/html", "200 OK"),
        };
        (
            http(status, &format!("Content-Type: {ty}\r\n"), b"x"),
            false,
        )
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    for (path, second) in [
        ("/logo.png", "HIT"),
        ("/page.html", "MISS"),
        ("/missing.png", "MISS"),
    ] {
        assert_eq!(x_cache(&fetch(s.addr, &get(path)).await), "MISS", "{path}");
        assert_eq!(x_cache(&fetch(s.addr, &get(path)).await), second, "{path}");
    }
    assert_eq!(s.up.count(), 5);
}

#[tokio::test]
async fn the_query_is_not_sorted_so_two_orders_are_two_keys() {
    let s = page_site().await;
    for target in ["/p?a=1&b=2", "/p?b=2&a=1", "/p?/a&page=1", "/p?/b&page=1"] {
        assert_eq!(
            x_cache(&fetch(s.addr, &get(target)).await),
            "MISS",
            "{target}"
        );
    }
    for target in ["/p?a=1&b=2", "/p?b=2&a=1", "/p?/a&page=1", "/p?/b&page=1"] {
        assert_eq!(
            x_cache(&fetch(s.addr, &get(target)).await),
            "HIT",
            "{target}"
        );
    }
    assert_eq!(s.up.count(), 4);
}

#[tokio::test]
async fn an_answer_that_varies_is_kept_for_each_value_up_to_four_names() {
    let up = raw_upstream(|seen| {
        let lang = seen.header("accept-language").unwrap_or("none").to_owned();
        (
            http(
                "200 OK",
                "Content-Type: text/html\r\nCache-Control: public, max-age=600\r\nVary: Accept-Language\r\n",
                lang.as_bytes(),
            ),
            false,
        )
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    for lang in ["id", "en", "id", "en", "fr"] {
        let r = fetch(s.addr, &with("/v", &[&format!("Accept-Language: {lang}")])).await;
        assert_eq!(r.text(), lang);
    }
    assert_eq!(s.up.count(), 3, "id, en and fr once each");
    let none = fetch(s.addr, &get("/v")).await;
    assert_eq!((none.text().as_str(), x_cache(&none)), ("none", "MISS"));

    // Four names pass; five are not kept.
    let seen = Arc::new(AtomicUsize::new(0));
    let counted = seen.clone();
    let up = raw_upstream(move |req| {
        counted.fetch_add(1, Ordering::SeqCst);
        let names = if req.line.contains("/four") {
            "A, B, C, D"
        } else {
            "A, B, C, D, E"
        };
        (
            http(
                "200 OK",
                &format!("Content-Type: text/html\r\nCache-Control: public, max-age=600\r\nVary: {names}\r\n"),
                b"x",
            ),
            false,
        )
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    for (path, second) in [("/four", "HIT"), ("/five", "MISS")] {
        assert_eq!(x_cache(&fetch(s.addr, &get(path)).await), "MISS", "{path}");
        assert_eq!(x_cache(&fetch(s.addr, &get(path)).await), second, "{path}");
    }
    assert_eq!(seen.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_path_rule_gives_the_lifetime_and_a_never_keep_rule_sends_the_path_on() {
    let mut cache = spec();
    cache.rules = vec![
        CacheRule {
            prefix: "/blog/".into(),
            bypass: false,
            ttl_s: 300,
            signed_in: false,
        },
        CacheRule {
            prefix: "/admin/".into(),
            bypass: true,
            ttl_s: 0,
            signed_in: false,
        },
    ];
    let s = site(
        counting("200 OK", "Content-Type: text/html\r\n").await,
        cache,
        |_| {},
    )
    .await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/blog/a")).await), "MISS");
    assert_eq!(x_cache(&fetch(s.addr, &get("/blog/a")).await), "HIT");
    for _ in 0..2 {
        assert_eq!(x_cache(&fetch(s.addr, &get("/admin/a")).await), "BYPASS");
        assert_eq!(x_cache(&fetch(s.addr, &get("/other")).await), "MISS");
    }
    assert_eq!(s.up.count(), 5);
}

// What is never kept.

/// Sends `raw` twice to an application that answers `status` and `headers`, and says whether the
/// second answer came from the cache. The application must have been asked both times.
async fn second_is_a_hit(
    status: &'static str,
    headers: &'static str,
    raw: Vec<u8>,
    cache: CacheSpec,
    edit: impl FnOnce(&mut wafio_proxy::AppSpec),
) -> (bool, usize) {
    let s = site(counting(status, headers).await, cache, edit).await;
    let a = fetch(s.addr, &raw).await;
    assert_ne!(x_cache(&a), "HIT");
    let b = fetch(s.addr, &raw).await;
    (x_cache(&b) == "HIT", s.up.count())
}

#[tokio::test]
async fn each_case_that_is_never_stored_stays_unstored() {
    let ok = "Content-Type: text/html\r\nCache-Control: public, max-age=60\r\n";
    let cases: Vec<(&str, &'static str, &'static str, Vec<u8>)> = vec![
        (
            "Set-Cookie",
            "200 OK",
            "Content-Type: text/html\r\nCache-Control: public, max-age=60\r\nSet-Cookie: a=1\r\n",
            get("/x"),
        ),
        (
            "private",
            "200 OK",
            "Content-Type: text/html\r\nCache-Control: private, max-age=60\r\n",
            get("/x"),
        ),
        (
            "no-store",
            "200 OK",
            "Content-Type: text/html\r\nCache-Control: no-store, max-age=60\r\n",
            get("/x"),
        ),
        (
            "no-cache",
            "200 OK",
            "Content-Type: text/html\r\nCache-Control: no-cache, max-age=60\r\n",
            get("/x"),
        ),
        (
            "Vary *",
            "200 OK",
            "Content-Type: text/html\r\nCache-Control: public, max-age=60\r\nVary: *\r\n",
            get("/x"),
        ),
        (
            "Vary Cookie",
            "200 OK",
            "Content-Type: text/html\r\nCache-Control: public, max-age=60\r\nVary: Cookie\r\n",
            get("/x"),
        ),
        (
            "Vary Authorization",
            "200 OK",
            "Content-Type: text/html\r\nCache-Control: public, max-age=60\r\nVary: Authorization\r\n",
            get("/x"),
        ),
        (
            "a redirect",
            "302 Found",
            "Content-Type: text/html\r\nCache-Control: public, max-age=60\r\n",
            get("/x"),
        ),
        (
            "a server error",
            "500 Internal Server Error",
            "Content-Type: text/html\r\nCache-Control: public, max-age=60\r\n",
            get("/x"),
        ),
        (
            "no lifetime",
            "200 OK",
            "Content-Type: text/html\r\n",
            get("/x"),
        ),
        (
            "max-age=0",
            "200 OK",
            "Content-Type: text/html\r\nCache-Control: max-age=0\r\n",
            get("/x"),
        ),
        (
            "an unreadable Cache-Control",
            "200 OK",
            "Content-Type: text/html\r\nCache-Control: max-age=soon\r\n",
            get("/x"),
        ),
        (
            "an unlisted cookie with max-age only",
            "200 OK",
            "Content-Type: text/html\r\nCache-Control: max-age=60\r\n",
            with("/x", &["Cookie: jwt=eyJ.a.b"]),
        ),
        (
            "Authorization",
            "200 OK",
            ok,
            with("/x", &["Authorization: Bearer t"]),
        ),
        (
            "userinfo",
            "200 OK",
            ok,
            b"GET http://u:p@app.test/x HTTP/1.1\r\nHost: app.test\r\n\r\n".to_vec(),
        ),
        (
            "a session cookie",
            "200 OK",
            ok,
            with("/x", &["Cookie: PHPSESSID=abc"]),
        ),
        ("a Range", "200 OK", ok, with("/x", &["Range: bytes=0-3"])),
        ("a POST", "200 OK", ok, post("/x", "text/plain", b"a=1")),
        (
            "a GET with a body",
            "200 OK",
            ok,
            b"GET /x HTTP/1.1\r\nHost: app.test\r\nContent-Length: 4\r\n\r\nabcd".to_vec(),
        ),
        (
            "X-HTTP-Method-Override",
            "200 OK",
            ok,
            with("/x", &["X-HTTP-Method-Override: DELETE"]),
        ),
        (
            "X-HTTP-Method",
            "200 OK",
            ok,
            with("/x", &["X-HTTP-Method: DELETE"]),
        ),
        (
            "X-Method-Override",
            "200 OK",
            ok,
            with("/x", &["X-Method-Override: DELETE"]),
        ),
        (
            "an Upgrade",
            "200 OK",
            ok,
            with("/x", &["Upgrade: h2c", "Connection: Upgrade"]),
        ),
    ];
    for (name, status, headers, raw) in cases {
        let (hit, asked) = second_is_a_hit(status, headers, raw, spec(), |_| {}).await;
        assert!(!hit && asked == 2, "{name}: hit {hit}, asked {asked}");
    }
    // An answer over the largest object, a `..;` path under a rule, and a path that decrypts.
    let small = CacheSpec {
        max_object_bytes: 1024,
        ..spec()
    };
    let big = raw_upstream(|_| (http("200 OK", PUBLIC, &[b'a'; 2000]), false)).await;
    let s = site(big, small, |_| {}).await;
    for _ in 0..2 {
        assert_eq!(x_cache(&fetch(s.addr, &get("/big")).await), "MISS");
    }
    assert_eq!(s.up.count(), 2);

    let rule = CacheRule {
        prefix: "/static/".into(),
        bypass: false,
        ttl_s: 60,
        signed_in: false,
    };
    let ruled = CacheSpec {
        rules: vec![rule],
        ..spec()
    };
    let s = site(
        counting("200 OK", "Content-Type: text/html\r\n").await,
        ruled,
        |_| {},
    )
    .await;
    for path in ["/static/..;/admin/x", "/static/a;b=1"] {
        assert_eq!(
            x_cache(&fetch(s.addr, &get(path)).await),
            "BYPASS",
            "{path}"
        );
        assert_eq!(
            x_cache(&fetch(s.addr, &get(path)).await),
            "BYPASS",
            "{path}"
        );
    }
    assert_eq!(x_cache(&fetch(s.addr, &get("/static/a")).await), "MISS");
    assert_eq!(x_cache(&fetch(s.addr, &get("/static/a")).await), "HIT");
    assert_eq!(s.up.count(), 5);

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let decrypting = format!(
        r#"{{"path_exceptions":[{{"path":"/files","match":"prefix","response_decrypt_aes":"{KEY}"}}]}}"#
    );
    let s = site(counting("200 OK", PUBLIC).await, spec(), |a| {
        a.analysis = analysis_setup(&decrypting)
    })
    .await;
    for _ in 0..2 {
        assert_eq!(x_cache(&fetch(s.addr, &get("/files/a")).await), "BYPASS");
    }
    assert_eq!(x_cache(&fetch(s.addr, &get("/other")).await), "MISS");
    assert_eq!(x_cache(&fetch(s.addr, &get("/other")).await), "HIT");
}

#[tokio::test]
async fn an_answer_without_a_length_is_not_kept() {
    let up = raw_upstream(|_| {
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: public, max-age=600\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n".to_vec(),
            false,
        )
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    // `Connection: close`: the answer has no end of its own but the connection's.
    for _ in 0..2 {
        let r = fetch(s.addr, &with("/stream", &["Connection: close"])).await;
        assert_eq!(x_cache(&r), "MISS");
    }
    assert_eq!(s.up.count(), 2);
    assert!(answer_files(&s.dir.0).is_empty());
}

#[tokio::test]
async fn sessions_never_share_and_a_visitor_who_is_not_signed_in_is_not_given_theirs() {
    let s = page_site().await;
    let a = fetch(s.addr, &with("/me", &["Cookie: sessionid=A"])).await;
    let b = fetch(s.addr, &with("/me", &["Cookie: sessionid=B"])).await;
    assert_eq!(
        (a.text().as_str(), b.text().as_str()),
        ("answer 1", "answer 2")
    );
    assert_eq!((x_cache(&a), x_cache(&b)), ("MISS", "MISS"));
    let anonymous = fetch(s.addr, &get("/me")).await;
    assert_eq!(
        (anonymous.text().as_str(), x_cache(&anonymous)),
        ("answer 3", "MISS")
    );
    assert_eq!(
        answer_files(&s.dir.0).len(),
        1,
        "only the anonymous answer is kept"
    );
}

#[tokio::test]
async fn a_rule_for_the_signed_in_keeps_a_page_for_them_and_nothing_else_is() {
    let mut cache = spec();
    cache.rules = vec![CacheRule {
        prefix: "/docs/".into(),
        bypass: false,
        ttl_s: 60,
        signed_in: true,
    }];
    cache.session_cookies = vec!["MyAuth".into()];
    let s = site(
        counting("200 OK", "Content-Type: text/html\r\n").await,
        cache,
        |_| {},
    )
    .await;
    let signed = ["Cookie: MyAuth=token"];
    assert_eq!(
        x_cache(&fetch(s.addr, &with("/docs/a", &signed)).await),
        "MISS"
    );
    assert_eq!(
        x_cache(&fetch(s.addr, &with("/docs/a", &signed)).await),
        "HIT"
    );
    // The name the app gave counts as a session outside the rule's path too.
    for _ in 0..2 {
        assert_eq!(
            x_cache(&fetch(s.addr, &with("/other", &["Cookie: MyAuth=token"])).await),
            "MISS"
        );
    }
    assert_eq!(s.up.count(), 3);
}

#[tokio::test]
async fn a_fat_get_and_each_override_header_never_poison_the_copy_the_next_visitor_gets() {
    for odd in [
        b"GET /p HTTP/1.1\r\nHost: app.test\r\nContent-Length: 4\r\n\r\nabcd".to_vec(),
        with("/p", &["X-HTTP-Method-Override: POST"]),
        with("/p", &["X-HTTP-Method: POST"]),
        with("/p", &["X-Method-Override: POST"]),
        with("/p", &["X_HTTP_Method_Override: DELETE"]),
        with("/p", &["X_HTTP_Method: DELETE"]),
        with("/p", &["X_Method_Override: DELETE"]),
    ] {
        let s = page_site().await;
        let first = fetch(s.addr, &odd).await;
        assert_eq!(
            (x_cache(&first), first.text().as_str()),
            ("BYPASS", "answer 1")
        );
        let next = fetch(s.addr, &get("/p")).await;
        assert_eq!((x_cache(&next), next.text().as_str()), ("MISS", "answer 2"));
        assert_eq!(x_cache(&fetch(s.addr, &get("/p")).await), "HIT");
    }
}

#[tokio::test]
async fn an_upgrade_get_gets_no_stored_page_and_stores_none() {
    let s = page_site().await;
    fetch(s.addr, &get("/p")).await;
    let up = fetch(
        s.addr,
        &with(
            "/p",
            &[
                "Upgrade: h2c",
                "Connection: Upgrade, HTTP2-Settings",
                "HTTP2-Settings: AAMAAABkAAQAAP__",
            ],
        ),
    )
    .await;
    assert_eq!((x_cache(&up), up.text().as_str()), ("BYPASS", "answer 2"));
    assert_eq!(
        s.up.count(),
        2,
        "it went to the application though a copy was there"
    );
    assert_eq!(x_cache(&fetch(s.addr, &get("/p")).await), "HIT");
}

// The headers a front-end writes.

const UNKEYED: [&str; 14] = [
    "X-Forwarded-Port",
    "X-Forwarded-Scheme",
    "X-Forwarded-Server",
    "X-Forwarded-Prefix",
    "X_Forwarded_Port",
    "X-Original-URL",
    "X-Original-Host",
    "X-Original-Uri",
    "X-Host",
    "X-Rewrite-URL",
    "Forwarded",
    "Front-End-Https",
    "X-Url-Scheme",
    "X-Forwarded-Ssl",
];

#[tokio::test]
async fn an_untrusted_peers_front_end_headers_never_reach_the_application_with_the_cache_on() {
    let s = page_site().await;
    for name in UNKEYED {
        fetch(
            s.addr,
            &with(&format!("/h/{name}"), &[&format!("{name}: evil")]),
        )
        .await;
        let seen = s.up.last();
        assert!(
            !seen
                .headers
                .iter()
                .any(|(k, _)| k.replace('_', "-") == name.to_ascii_lowercase().replace('_', "-")),
            "{name}: {:?}",
            seen.headers
        );
    }
    // The three the agent writes itself are its own, and a line of the client's does not stay.
    fetch(
        s.addr,
        &with(
            "/own",
            &[
                "X-Forwarded-Host: evil.test",
                "X-Forwarded-Host: worse.test",
                "X-Forwarded-Proto: https",
                "X-Forwarded-For: 6.6.6.6",
            ],
        ),
    )
    .await;
    let seen = s.up.last();
    assert_eq!(seen.all("x-forwarded-host"), ["app.test"]);
    assert_eq!(seen.all("x-forwarded-proto"), ["http"]);
    assert_eq!(seen.all("x-forwarded-for"), ["127.0.0.1"]);
    assert_eq!(seen.all("x-real-ip"), ["127.0.0.1"]);
}

/// The values of every line a backend that folds `_` into `-` reads as `name`.
fn folded<'a>(seen: &'a Seen, name: &str) -> Vec<&'a str> {
    seen.headers
        .iter()
        .filter(|(k, _)| k.replace('_', "-").eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

#[tokio::test]
async fn the_underscore_spellings_of_the_headers_the_agent_writes_never_stay_beside_its_own() {
    for trust in [false, true] {
        let s = site(counting("200 OK", PUBLIC).await, spec(), |a| {
            if trust {
                a.proxy_config = br#"{"trust_forwarded":true}"#.to_vec()
            }
        })
        .await;
        fetch(
            s.addr,
            &with(
                "/own",
                &[
                    "X_Forwarded_Host: evil.test",
                    "X_FORWARDED_HOST: worse.test",
                    "X_Forwarded_Proto: https",
                    "X-Forwarded-Proto: https",
                ],
            ),
        )
        .await;
        let seen = s.up.last();
        assert_eq!(folded(&seen, "x-forwarded-host"), ["app.test"], "{trust}");
        // The scheme is the peer's word only from a proxy the route trusts.
        let scheme = if trust { "https" } else { "http" };
        assert_eq!(folded(&seen, "x-forwarded-proto"), [scheme], "{trust}");
    }
}

#[tokio::test]
async fn with_the_cache_off_the_headers_go_on_as_before() {
    let up = counting("200 OK", PUBLIC).await;
    let port = free_port();
    let (_h, addr) = Harness::serve(vec![app_for(&up, port, None)]);
    fetch(
        addr,
        &with("/x", &["X-Forwarded-Port: 8443", "X-Original-URL: /a"]),
    )
    .await;
    let seen = up.last();
    assert_eq!(seen.header("x-forwarded-port"), Some("8443"));
    assert_eq!(seen.header("x-original-url"), Some("/a"));
}

#[tokio::test]
async fn a_trusted_proxys_headers_are_sent_on_and_are_part_of_the_key() {
    let s = site(counting("200 OK", PUBLIC).await, spec(), |a| {
        a.proxy_config = br#"{"trust_forwarded":true}"#.to_vec()
    })
    .await;
    let port_8443 = with("/k", &["X-Forwarded-Port: 8443"]);
    let port_9443 = with("/k", &["X-Forwarded-Port: 9443"]);
    assert_eq!(x_cache(&fetch(s.addr, &port_8443).await), "MISS");
    assert_eq!(s.up.last().header("x-forwarded-port"), Some("8443"));
    assert_eq!(x_cache(&fetch(s.addr, &port_8443).await), "HIT");
    assert_eq!(
        x_cache(&fetch(s.addr, &port_9443).await),
        "MISS",
        "another value, another copy"
    );
    assert_eq!(x_cache(&fetch(s.addr, &get("/k")).await), "MISS");
    // The scheme is the proxy's word, and one key for each.
    let https = with("/s", &["X-Forwarded-Proto: https"]);
    assert_eq!(x_cache(&fetch(s.addr, &https).await), "MISS");
    assert_eq!(s.up.last().header("x-forwarded-proto"), Some("https"));
    assert_eq!(x_cache(&fetch(s.addr, &get("/s")).await), "MISS");
    assert_eq!(x_cache(&fetch(s.addr, &https).await), "HIT");
    // More than 256 bytes of such headers are not cached.
    let fat = with("/f", &[&format!("X-Original-URL: {}", "a".repeat(300))]);
    assert_eq!(x_cache(&fetch(s.addr, &fat).await), "BYPASS");
}

#[tokio::test]
async fn php_gets_the_same_treatment_of_front_end_headers() {
    let (fcgi, fake) = fake_fcgi().await;
    let dir = Dir::new("fcgi");
    let host = CacheHost::open(&dir.0, uid()).unwrap();
    let mut a = fcgi_app(free_port(), format!("fcgi://{fcgi}"), "/srv/www", "");
    a.cache = Some(spec());
    let (_h, addr) = serve_with(&host, a);
    fetch(
        addr,
        &with(
            "/index.php",
            &[
                "X-Forwarded-Port: 8443",
                "X-Forwarded-Host: evil.test",
                "X-Forwarded-Proto: https",
                "X-Original-URL: /admin",
                "Forwarded: host=evil",
            ],
        ),
    )
    .await;
    let params = fake.params.lock().unwrap().last().cloned().unwrap();
    for gone in [
        "HTTP_X_FORWARDED_PORT",
        "HTTP_X_ORIGINAL_URL",
        "HTTP_FORWARDED",
    ] {
        assert!(!params.contains_key(gone), "{gone}: {params:?}");
    }
    assert!(!params.contains_key("HTTP_X_FORWARDED_PROTO"), "{params:?}");
    // The host is the agent's own, as on the HTTP path, not the client's.
    assert_eq!(
        params.get("HTTP_X_FORWARDED_HOST").map(String::as_str),
        Some("app.test")
    );
    assert!(params.contains_key("HTTP_X_REAL_IP"));
}

#[tokio::test]
async fn a_trusted_proxys_forwarded_host_never_reaches_php_so_it_cannot_poison_the_copy() {
    let (fcgi, fake) = fake_fcgi().await;
    let dir = Dir::new("fcgi-trusted");
    let host = CacheHost::open(&dir.0, uid()).unwrap();
    let mut a = fcgi_app(free_port(), format!("fcgi://{fcgi}"), "/srv/www", "");
    a.cache = Some(spec());
    a.proxy_config = br#"{"trust_forwarded":true}"#.to_vec();
    let (_h, addr) = serve_with(&host, a);
    // Two requests that differ only in the header, in each spelling, and one that has none.
    for lines in [
        &[][..],
        &["X-Forwarded-Host: evil.test"][..],
        &[
            "X_Forwarded_Host: evil.test",
            "X-Forwarded-Host: worse.test",
        ][..],
        &["X-FORWARDED-HOST: evil.test"][..],
    ] {
        fetch(addr, &with("/index.php", lines)).await;
        let params = fake.params.lock().unwrap().last().cloned().unwrap();
        assert_eq!(
            params.get("HTTP_X_FORWARDED_HOST").map(String::as_str),
            Some("app.test"),
            "{lines:?}: {params:?}"
        );
    }
    // What the proxy says that is part of the key still goes on.
    fetch(
        addr,
        &with(
            "/index.php",
            &["X-Forwarded-Port: 8443", "X-Forwarded-Proto: https"],
        ),
    )
    .await;
    let params = fake.params.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        params.get("HTTP_X_FORWARDED_PORT").map(String::as_str),
        Some("8443")
    );
    assert_eq!(
        params.get("HTTP_X_FORWARDED_PROTO").map(String::as_str),
        Some("https")
    );
}

// Unsafe methods, conditions, ranges.

#[tokio::test]
async fn a_successful_post_put_patch_or_delete_drops_the_copies_of_the_url() {
    let up = raw_upstream({
        let n = Arc::new(AtomicUsize::new(0));
        move |seen| {
            let i = n.fetch_add(1, Ordering::SeqCst) + 1;
            let status = if seen.line.contains("/fail") && seen.line.starts_with("POST") {
                "500 Internal Server Error"
            } else {
                "200 OK"
            };
            (
                http(status, PUBLIC, format!("answer {i}").as_bytes()),
                false,
            )
        }
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let path = format!("/item/{method}");
        let first = fetch(s.addr, &get(&path)).await;
        assert_eq!(
            x_cache(&fetch(s.addr, &get(&path)).await),
            "HIT",
            "{method}"
        );
        let changed = fetch(s.addr, &request(method, &path, &["Content-Length: 0"])).await;
        assert_eq!((changed.status, x_cache(&changed)), (200, "BYPASS"));
        let after = fetch(s.addr, &get(&path)).await;
        assert_ne!(after.text(), first.text(), "{method}: the copy is gone");
        assert_eq!(x_cache(&after), "MISS", "{method}");
    }
    // A failed change and a change to another URL leave the copy.
    let kept = fetch(s.addr, &get("/fail")).await;
    fetch(s.addr, &post("/fail", "text/plain", b"x")).await;
    assert_eq!(fetch(s.addr, &get("/fail")).await.text(), kept.text());
    fetch(s.addr, &post("/elsewhere", "text/plain", b"x")).await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/fail")).await), "HIT");
}

#[tokio::test]
async fn a_post_drops_every_encoding_of_the_url() {
    let s = site(counting("200 OK", PUBLIC).await, spec(), |_| {}).await;
    for encoding in ["gzip", "br", "identity"] {
        fetch(
            s.addr,
            &with("/e", &[&format!("Accept-Encoding: {encoding}")]),
        )
        .await;
    }
    assert_eq!(answer_files(&s.dir.0).len(), 3);
    fetch(s.addr, &post("/e", "text/plain", b"x")).await;
    for encoding in ["gzip", "br", "identity"] {
        let r = fetch(
            s.addr,
            &with("/e", &[&format!("Accept-Encoding: {encoding}")]),
        )
        .await;
        assert_eq!(x_cache(&r), "MISS", "{encoding}");
    }
    assert_eq!(
        answer_files(&s.dir.0).len(),
        3,
        "the old files are gone, the new ones are in"
    );
}

fn validators() -> &'static str {
    "Content-Type: text/plain\r\nCache-Control: public, max-age=600\r\nETag: \"v1\"\r\nLast-Modified: Mon, 02 Jan 2006 15:04:05 GMT\r\n"
}

#[tokio::test]
async fn a_copy_answers_conditions_one_range_and_head_without_asking_the_application() {
    let up = raw_upstream(|_| (http("200 OK", validators(), b"0123456789"), false)).await;
    let s = site(up, spec(), |_| {}).await;
    // A request with a Range is looked up but never makes a copy.
    let ranged = fetch(s.addr, &with("/r", &["Range: bytes=0-3"])).await;
    assert_eq!((ranged.status, x_cache(&ranged)), (200, "MISS"));
    assert!(answer_files(&s.dir.0).is_empty());
    assert_eq!(x_cache(&fetch(s.addr, &get("/r")).await), "MISS");
    let asked = s.up.count();

    let hit = fetch(s.addr, &get("/r")).await;
    assert_eq!((x_cache(&hit), hit.text().as_str()), ("HIT", "0123456789"));
    let not_modified = fetch(s.addr, &with("/r", &["If-None-Match: \"v1\""])).await;
    assert_eq!((not_modified.status, x_cache(&not_modified)), (304, "HIT"));
    assert_eq!(not_modified.header("etag"), Some("\"v1\""));
    assert!(not_modified.body.is_empty());
    let by_date = fetch(
        s.addr,
        &with("/r", &["If-Modified-Since: Mon, 02 Jan 2006 15:04:05 GMT"]),
    )
    .await;
    assert_eq!(by_date.status, 304);
    let other_tag = fetch(s.addr, &with("/r", &["If-None-Match: \"v2\""])).await;
    assert_eq!(
        (other_tag.status, other_tag.text().as_str()),
        (200, "0123456789")
    );

    let part = fetch(s.addr, &with("/r", &["Range: bytes=2-4"])).await;
    assert_eq!(
        (part.status, part.text().as_str(), x_cache(&part)),
        (206, "234", "HIT")
    );
    assert_eq!(part.header("content-range"), Some("bytes 2-4/10"));
    assert_eq!(
        fetch(s.addr, &with("/r", &["Range: bytes=-3"]))
            .await
            .text(),
        "789"
    );
    assert_eq!(
        fetch(s.addr, &with("/r", &["Range: bytes=20-"]))
            .await
            .status,
        416
    );
    assert_eq!(
        fetch(s.addr, &with("/r", &["Range: bytes=0-1,3-4"]))
            .await
            .status,
        200
    );
    assert_eq!(
        fetch(
            s.addr,
            &with("/r", &["Range: bytes=2-4", "If-Range: \"other\""])
        )
        .await
        .status,
        200
    );
    assert_eq!(
        fetch(
            s.addr,
            &with("/r", &["Range: bytes=2-4", "If-Range: \"v1\""])
        )
        .await
        .status,
        206
    );

    let head = head_of(s.addr, "/r", &[]).await;
    assert_eq!((head.status, x_cache(&head)), (200, "HIT"));
    assert_eq!(head.header("content-length"), Some("10"));
    assert_eq!(head.header("etag"), Some("\"v1\""));
    assert_eq!(
        s.up.count(),
        asked,
        "the application was asked for none of these"
    );
}

#[tokio::test]
async fn a_head_that_finds_no_copy_goes_on_and_makes_none() {
    let s = page_site().await;
    let head = head_of(s.addr, "/h", &[]).await;
    assert_eq!((head.status, x_cache(&head)), (200, "MISS"));
    assert!(answer_files(&s.dir.0).is_empty());
    assert_eq!(x_cache(&fetch(s.addr, &get("/h")).await), "MISS");
    let head = head_of(s.addr, "/h", &[]).await;
    assert_eq!((head.status, x_cache(&head)), (200, "HIT"));
}

// What the answers are sent with.

#[tokio::test]
async fn a_change_to_the_response_header_rules_reaches_a_stored_copy_at_once() {
    let s = site(counting("200 OK", PUBLIC).await, spec(), |a| {
        a.proxy_config = br#"{"resp_headers":{"add":{"X-Rule":"one"},"remove":["X-Up"]}}"#.to_vec();
    })
    .await;
    let first = fetch(s.addr, &get("/p")).await;
    assert_eq!(
        (first.header("x-rule"), first.header("x-up")),
        (Some("one"), None)
    );
    let hit = fetch(s.addr, &get("/p")).await;
    assert_eq!((x_cache(&hit), hit.header("x-rule")), ("HIT", Some("one")));
    let mut a = app_for(&s.up, s.addr.port(), Some(spec()));
    a.proxy_config = br#"{"resp_headers":{"add":{"X-Rule":"two","X-New":"1"}}}"#.to_vec();
    apply(&s.h, a);
    let hit = fetch(s.addr, &get("/p")).await;
    assert_eq!(x_cache(&hit), "HIT");
    assert_eq!(
        (hit.header("x-rule"), hit.header("x-new")),
        (Some("two"), Some("1"))
    );
    assert_eq!(
        hit.header("x-up"),
        Some("1"),
        "the rule that removed it is gone"
    );
    assert_eq!(s.up.count(), 1);
}

#[tokio::test]
async fn the_cache_headers_of_the_application_are_not_trusted_for_x_cache_and_age() {
    let up = counting("200 OK", "Content-Type: text/html\r\nCache-Control: public, max-age=600\r\nX-Cache: HIT\r\nAge: 9999\r\n").await;
    let s = site(up, spec(), |_| {}).await;
    let first = fetch(s.addr, &get("/p")).await;
    assert_eq!(x_cache(&first), "MISS");
    assert_eq!(
        first.headers.iter().filter(|(k, _)| k == "x-cache").count(),
        1
    );
}

#[tokio::test]
async fn compression_runs_before_the_copy_is_made_and_each_encoding_has_its_own() {
    let body: &'static [u8] = Box::leak(vec![b'a'; 4000].into_boxed_slice());
    let up = raw_upstream(move |_| (http("200 OK", PUBLIC, body), false)).await;
    let s = site(up, spec(), |a| {
        a.compression = Some(CompressionSpec { min_bytes: 100 })
    })
    .await;
    let gz = ["Accept-Encoding: gzip"];
    let first = fetch(s.addr, &with("/c", &gz)).await;
    assert_eq!(
        (x_cache(&first), first.header("content-encoding")),
        ("MISS", Some("gzip"))
    );
    let hit = fetch(s.addr, &with("/c", &gz)).await;
    assert_eq!(
        (x_cache(&hit), hit.header("content-encoding")),
        ("HIT", Some("gzip"))
    );
    assert_eq!(hit.body, first.body, "the same compressed bytes");
    assert!(hit.body.len() < 400);
    assert!(
        hit.header("vary")
            .is_some_and(|v| v.contains("Accept-Encoding"))
    );
    let plain = fetch(s.addr, &get("/c")).await;
    assert_eq!(
        (x_cache(&plain), plain.header("content-encoding")),
        ("MISS", None)
    );
    assert_eq!(plain.body.len(), 4000);
    assert_eq!(x_cache(&fetch(s.addr, &get("/c")).await), "HIT");
    assert_eq!(
        x_cache(&fetch(s.addr, &with("/c", &["Accept-Encoding: br"])).await),
        "MISS"
    );
    assert_eq!(s.up.count(), 3);
}

#[tokio::test]
async fn an_answer_the_application_encoded_itself_is_kept_only_for_the_encoding_that_asked() {
    let up = raw_upstream(|seen| {
        let enc = if seen.header("accept-encoding").is_some_and(|a| a.contains("zstd")) {
            "zstd"
        } else {
            "gzip"
        };
        (
            http(
                "200 OK",
                &format!("Content-Type: text/html\r\nCache-Control: public, max-age=600\r\nContent-Encoding: {enc}\r\nVary: Accept-Encoding\r\n"),
                b"packed",
            ),
            false,
        )
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    let gzip = ["Accept-Encoding: gzip"];
    fetch(s.addr, &with("/e", &gzip)).await;
    assert_eq!(x_cache(&fetch(s.addr, &with("/e", &gzip)).await), "HIT");
    // A client that also takes zstd gets zstd from the application, and it is not kept: it would
    // be sent to the client that asked for gzip only.
    let both = ["Accept-Encoding: zstd, gzip"];
    for _ in 0..2 {
        let r = fetch(s.addr, &with("/z", &both)).await;
        assert_eq!(x_cache(&r), "MISS");
    }
    assert_eq!(x_cache(&fetch(s.addr, &with("/z", &gzip)).await), "MISS");
}

#[tokio::test]
async fn files_from_a_folder_are_not_from_the_cache() {
    let dir = Dir::new("folder");
    std::fs::create_dir_all(dir.0.join("public")).unwrap();
    std::fs::write(dir.0.join("public/a.txt"), b"from the folder").unwrap();
    let root = dir.0.join("public").to_str().unwrap().to_owned();
    let s = site(counting("200 OK", PUBLIC).await, spec(), |a| {
        a.static_files = Some(wafio_proxy::StaticSpec::check(&root, "", 0).unwrap());
    })
    .await;
    for _ in 0..2 {
        let r = fetch(s.addr, &get("/a.txt")).await;
        assert_eq!(
            (r.text().as_str(), x_cache(&r)),
            ("from the folder", "BYPASS")
        );
    }
    assert_eq!(s.up.count(), 0);
    assert_eq!(x_cache(&fetch(s.addr, &get("/b")).await), "MISS");
}

#[tokio::test]
async fn an_answer_of_an_app_with_no_cache_has_no_x_cache() {
    let up = counting("200 OK", PUBLIC).await;
    let (_h, addr) = Harness::serve(vec![app_for(&up, free_port(), None)]);
    let r = fetch(addr, &get("/p")).await;
    assert_eq!(r.header("x-cache"), None);
    let r = fetch(addr, &get("/p")).await;
    assert_eq!((r.text().as_str(), r.header("x-cache")), ("answer 2", None));
}

#[tokio::test]
async fn a_failed_application_is_a_502_with_x_cache_and_a_copy_is_not_made_of_it() {
    let port = free_port();
    let dead = "http://127.0.0.1:1";
    let dir = Dir::new("dead");
    let host = CacheHost::open(&dir.0, uid()).unwrap();
    let mut a = app("shop", port, dead);
    a.cache = Some(spec());
    let (_h, addr) = serve_with(&host, a);
    assert!(host.wait_writable(Duration::from_secs(10)));
    let r = fetch(addr, &get("/p")).await;
    assert_eq!((r.status, x_cache(&r)), (502, "MISS"));
}

// The disk.

#[tokio::test]
async fn a_copy_comes_back_after_a_restart_and_a_reload_serves_hits_but_stores_nothing() {
    let dir = Dir::new("restart");
    let up = counting("200 OK", PUBLIC).await;
    let port = free_port();
    {
        let host = CacheHost::open(&dir.0, uid()).unwrap();
        let (_h, addr) = serve_with(&host, app_for(&up, port, Some(spec())));
        assert!(host.wait_writable(Duration::from_secs(10)));
        assert_eq!(x_cache(&fetch(addr, &get("/kept")).await), "MISS");
        host.release();
    }
    // The next process: same directory, hits at once, and it is the writer.
    let host = CacheHost::open(&dir.0, uid()).unwrap();
    let (_h, addr) = serve_with(&host, app_for(&up, free_port(), Some(spec())));
    assert!(host.wait_writable(Duration::from_secs(10)));
    let hit = fetch(addr, &get("/kept")).await;
    assert_eq!((x_cache(&hit), hit.text().as_str()), ("HIT", "answer 1"));
    assert_eq!(x_cache(&fetch(addr, &get("/new")).await), "MISS");
    assert_eq!(x_cache(&fetch(addr, &get("/new")).await), "HIT");
    assert_eq!(up.count(), 2);

    // A reload's successor while this process holds the lock: it serves what it reads, stores nothing.
    let successor = CacheHost::open(&dir.0, uid()).unwrap();
    assert!(!successor.holds_lock());
    let (_h2, addr2) = serve_with(&successor, app_for(&up, free_port(), Some(spec())));
    let before = answer_files(&dir.0);
    assert_eq!(before.len(), 2);
    for _ in 0..50 {
        if successor.is_ready() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(x_cache(&fetch(addr2, &get("/kept")).await), "HIT");
    assert_eq!(x_cache(&fetch(addr2, &get("/not-yet")).await), "MISS");
    assert_eq!(
        x_cache(&fetch(addr2, &get("/not-yet")).await),
        "MISS",
        "nothing was stored"
    );
    assert_eq!(answer_files(&dir.0), before);
    // The writer lets go and the successor takes over: the files the old process stored count.
    host.release();
    let taker = successor.clone();
    assert!(
        tokio::task::spawn_blocking(move || taker.take_over())
            .await
            .unwrap()
    );
    assert_eq!(x_cache(&fetch(addr2, &get("/not-yet")).await), "MISS");
    assert_eq!(x_cache(&fetch(addr2, &get("/not-yet")).await), "HIT");
}

#[tokio::test]
async fn a_write_a_reloads_successor_answers_is_not_undone_when_it_takes_the_lock() {
    let dir = Dir::new("successor-write");
    let up = counting("200 OK", PUBLIC).await;
    let old = CacheHost::open(&dir.0, uid()).unwrap();
    let (_h, addr) = serve_with(&old, app_for(&up, free_port(), Some(spec())));
    assert!(old.wait_writable(Duration::from_secs(10)));
    assert_eq!(x_cache(&fetch(addr, &get("/doc")).await), "MISS");
    assert_eq!(x_cache(&fetch(addr, &get("/doc")).await), "HIT");
    // The successor serves the copy it reads. It answers a POST to the URL: it cannot delete the
    // file, so the copy is gone from its index only.
    let successor = CacheHost::open(&dir.0, uid()).unwrap();
    assert!(!successor.holds_lock());
    let (_h2, addr2) = serve_with(&successor, app_for(&up, free_port(), Some(spec())));
    for _ in 0..500 {
        if successor.is_ready() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(x_cache(&fetch(addr2, &get("/doc")).await), "HIT");
    let changed = fetch(addr2, &post("/doc", "text/plain", b"x")).await;
    assert_eq!(changed.status, 200);
    assert_eq!(x_cache(&fetch(addr2, &get("/doc")).await), "MISS");
    assert_eq!(answer_files(&dir.0).len(), 1, "the file is still there");
    // The old process lets go and the successor takes the lock and reads the directory: the copy
    // the write ended must not come back.
    old.release();
    let taker = successor.clone();
    assert!(
        tokio::task::spawn_blocking(move || taker.take_over())
            .await
            .unwrap()
    );
    assert_eq!(x_cache(&fetch(addr2, &get("/doc")).await), "MISS");
    assert_eq!(x_cache(&fetch(addr2, &get("/doc")).await), "HIT");
    assert_eq!(
        answer_files(&dir.0).len(),
        1,
        "the old file went, the new one is in its place"
    );
}

#[tokio::test]
async fn a_miss_is_answered_without_waiting_for_its_copy_to_be_written() {
    // No disk slot is ever free, so no copy is written, and the write waits 100 ms for a slot
    // before it gives up. The visitor's answer must not wait for that.
    let dir = Dir::new("no-slots");
    let up = counting("200 OK", PUBLIC).await;
    let host = CacheHost::open(&dir.0, uid()).unwrap();
    let (_h, addr) = serve_with_slots(&host, app_for(&up, free_port(), Some(spec())), Some(0));
    assert!(host.wait_writable(Duration::from_secs(10)));
    let mut fastest = Duration::MAX;
    for n in 0..5 {
        let started = Instant::now();
        let r = one(addr, &get(&format!("/m/{n}"))).await;
        fastest = fastest.min(started.elapsed());
        assert_eq!((r.status, x_cache(&r)), (200, "MISS"));
    }
    assert!(
        fastest < Duration::from_millis(90),
        "the fastest of five took {fastest:?}"
    );
    copies_written(addr).await;
    assert!(answer_files(&dir.0).is_empty(), "no slot, no copy");
}

#[tokio::test]
async fn a_large_answer_is_kept_whole_and_sent_again_byte_for_byte() {
    let body: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let sent = body.clone();
    let up = raw_upstream(move |_| (http("200 OK", PUBLIC, &sent), false)).await;
    let s = site(up, spec(), |_| {}).await;
    let first = fetch(s.addr, &get("/big")).await;
    assert_eq!((x_cache(&first), first.body == body), ("MISS", true));
    let again = fetch(s.addr, &get("/big")).await;
    assert_eq!((x_cache(&again), again.body == body), ("HIT", true));
    assert_eq!(s.up.count(), 1);
}

#[tokio::test]
async fn a_crawl_of_unique_urls_stays_within_the_quota_plus_one_object() {
    let up = raw_upstream(|_| (http("200 OK", PUBLIC, &[b'a'; 1500]), false)).await;
    let quota = 20_000u64;
    let s = site(
        up,
        CacheSpec {
            disk_bytes: quota,
            ..spec()
        },
        |_| {},
    )
    .await;
    for n in 0..200 {
        fetch(s.addr, &get(&format!("/crawl/{n}"))).await;
        let (entries, disk, _) = s.host.usage("shop").unwrap();
        assert!(disk <= quota, "{n}: {disk}");
        assert!(entries <= 14, "{n}: {entries}");
    }
    let files = answer_files(&s.dir.0);
    let on_disk: u64 = files
        .iter()
        .map(|f| std::fs::metadata(f).unwrap().len())
        .sum();
    let (entries, disk, _) = s.host.usage("shop").unwrap();
    assert_eq!(
        (files.len(), on_disk),
        (entries, disk),
        "no file outlives its entry"
    );
    assert!(on_disk <= quota + 1700);
    // The newest are kept.
    assert_eq!(x_cache(&fetch(s.addr, &get("/crawl/199")).await), "HIT");
    assert_eq!(x_cache(&fetch(s.addr, &get("/crawl/0")).await), "MISS");
}

#[tokio::test]
async fn a_second_hit_puts_a_small_copy_in_memory_and_the_third_reads_no_disk() {
    let s = page_site().await;
    for path in ["/hot", "/cold"] {
        assert_eq!(x_cache(&fetch(s.addr, &get(path)).await), "MISS");
    }
    assert_eq!(s.host.usage("shop").unwrap().2, 0, "nothing in memory yet");
    assert_eq!(x_cache(&fetch(s.addr, &get("/hot")).await), "HIT");
    assert_eq!(
        s.host.usage("shop").unwrap().2,
        0,
        "a first hit reads the disk"
    );
    assert_eq!(x_cache(&fetch(s.addr, &get("/hot")).await), "HIT");
    assert!(
        s.host.usage("shop").unwrap().2 > 0,
        "the second hit put it in memory"
    );
    // With the files gone, only the copy in memory is still sent.
    for file in answer_files(&s.dir.0) {
        std::fs::remove_file(file).unwrap();
    }
    let hot = fetch(s.addr, &get("/hot")).await;
    assert_eq!((x_cache(&hot), hot.text().as_str()), ("HIT", "answer 1"));
    let cold = fetch(s.addr, &get("/cold")).await;
    assert_eq!((x_cache(&cold), cold.text().as_str()), ("MISS", "answer 3"));
}

#[tokio::test]
async fn memory_zero_keeps_every_copy_on_disk_only() {
    let s = site(
        counting("200 OK", PUBLIC).await,
        CacheSpec {
            memory_bytes: 0,
            ..spec()
        },
        |_| {},
    )
    .await;
    for _ in 0..5 {
        fetch(s.addr, &get("/p")).await;
    }
    assert_eq!(s.host.usage("shop").unwrap().2, 0);
    assert_eq!(s.up.count(), 1);
}

#[tokio::test]
async fn a_damaged_or_swapped_file_is_never_sent_and_is_deleted() {
    let s = page_site().await;
    for path in ["/flip", "/cut", "/swap-a", "/swap-b", "/fine"] {
        fetch(s.addr, &get(path)).await;
    }
    let files = answer_files(&s.dir.0);
    assert_eq!(files.len(), 5);
    // Find which file is which by its key (the path is in it).
    let find = |needle: &str| {
        files
            .iter()
            .find(|f| {
                let bytes = std::fs::read(f).unwrap();
                bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
            })
            .unwrap()
            .clone()
    };
    let (flip, cut, a, b) = (
        find("/flip"),
        find("/cut"),
        find("/swap-a"),
        find("/swap-b"),
    );
    let mut bytes = std::fs::read(&flip).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&flip, bytes).unwrap();
    let bytes = std::fs::read(&cut).unwrap();
    std::fs::write(&cut, &bytes[..bytes.len() - 3]).unwrap();
    // The files of two URLs under each other's names.
    let tmp = a.with_extension("swap");
    std::fs::rename(&a, &tmp).unwrap();
    std::fs::rename(&b, &a).unwrap();
    std::fs::rename(&tmp, &b).unwrap();
    let before = s.up.count();
    for (path, want) in [
        ("/flip", "answer 6"),
        ("/cut", "answer 7"),
        ("/swap-a", "answer 8"),
        ("/swap-b", "answer 9"),
    ] {
        let r = fetch(s.addr, &get(path)).await;
        assert_eq!((r.text().as_str(), x_cache(&r)), (want, "MISS"), "{path}");
    }
    assert_eq!(s.up.count(), before + 4);
    let fine = fetch(s.addr, &get("/fine")).await;
    assert_eq!((x_cache(&fine), fine.text().as_str()), ("HIT", "answer 5"));
    // Each was replaced by a good copy.
    assert_eq!(answer_files(&s.dir.0).len(), 5);
    for path in ["/flip", "/cut", "/swap-a", "/swap-b"] {
        assert_eq!(x_cache(&fetch(s.addr, &get(path)).await), "HIT", "{path}");
    }
}

#[tokio::test]
async fn a_link_or_a_directory_in_place_of_a_file_is_never_followed() {
    let s = page_site().await;
    fetch(s.addr, &get("/p")).await;
    let file = answer_files(&s.dir.0).remove(0);
    let secret = s.dir.0.join("secret");
    std::fs::write(&secret, b"not a cache file").unwrap();
    std::fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink(&secret, &file).unwrap();
    let r = fetch(s.addr, &get("/p")).await;
    assert_eq!((x_cache(&r), r.text().as_str()), ("MISS", "answer 2"));
    assert_eq!(std::fs::read(&secret).unwrap(), b"not a cache file");
}

#[tokio::test]
async fn an_app_that_leaves_the_bundle_loses_its_copies_and_a_cache_switched_off_its_directory() {
    let s = page_site().await;
    fetch(s.addr, &get("/p")).await;
    assert_eq!(answer_files(&s.dir.0).len(), 1);
    // The cache is switched off: nothing is looked up and the directory goes.
    apply(&s.h, app_for(&s.up, s.addr.port(), None));
    for _ in 0..100 {
        if answer_files(&s.dir.0).is_empty() && !s.dir.0.join("shop").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!s.dir.0.join("shop").exists());
    assert_eq!(fetch(s.addr, &get("/p")).await.header("x-cache"), None);
}

#[tokio::test]
async fn a_cache_that_has_no_store_behind_it_is_off() {
    let up = counting("200 OK", PUBLIC).await;
    let port = free_port();
    let mut a = app("shop", port, &format!("http://{}", up.addr));
    a.cache = Some(spec());
    // No directory was given to the proxy: the bundle's cache settings do nothing.
    let (_h, addr) = Harness::serve(vec![a]);
    let r = fetch(addr, &get("/p")).await;
    assert_eq!(r.header("x-cache"), None);
    assert_eq!(fetch(addr, &get("/p")).await.text(), "answer 2");
}
