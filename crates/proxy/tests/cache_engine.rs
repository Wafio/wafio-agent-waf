//! The response cache and the verdict: only an allowed request reads or fills it. These cases need
//! something to detect, so they run with the fake engine.

#[path = "common/cache_site.rs"]
mod cache_site;
mod common;

use std::time::Duration;

use cache_site::*;
use common::*;
use wafio_proxy::CacheHost;

const SQLI: &str = "X-Probe: wafio-test-sql";
const WEAK: &str = "X-Probe: wafio-test-weak";

/// A site whose engine is the fake one.
async fn engine_site(edit: impl FnOnce(&mut wafio_proxy::AppSpec)) -> Site {
    wafio_engine_fake::install();
    site(counting("200 OK", PUBLIC).await, spec(), edit).await
}

#[tokio::test]
async fn an_attack_on_a_cached_path_is_blocked_and_never_a_hit() {
    let s = engine_site(|_| {}).await;
    one(s.addr, &get("/page")).await;
    assert_eq!(x_cache(&one(s.addr, &get("/page")).await), "HIT");
    // The same URL, with an attack in a header: the verdict comes first.
    let attack = one(s.addr, &with("/page", &[SQLI])).await;
    assert_eq!(attack.status, 403);
    assert_eq!(
        attack.header("x-cache"),
        None,
        "a block page is not an answer of the cache"
    );
    assert_eq!(s.up.count(), 1);
    assert_eq!(common::s(&s.h.last_event().action), "block");
    // The copy was not touched.
    assert_eq!(x_cache(&one(s.addr, &get("/page")).await), "HIT");
}

#[tokio::test]
async fn an_attack_never_makes_a_copy() {
    let s = engine_site(|_| {}).await;
    assert_eq!(
        one(s.addr, &with("/page?id=wafio-test-sql", &[]))
            .await
            .status,
        403
    );
    assert!(answer_files(&s.dir.0).is_empty());
    assert_eq!(s.up.count(), 0);
}

#[tokio::test]
async fn log_and_monitor_go_to_the_application_unread_and_unstored() {
    let s = engine_site(|_| {}).await;
    one(s.addr, &get("/page")).await;
    assert_eq!(x_cache(&one(s.addr, &get("/page")).await), "HIT");
    // A weak detection is a `log` verdict: allowed, and the cache is left out of it.
    for _ in 0..2 {
        let r = one(s.addr, &with("/page", &[WEAK])).await;
        assert_eq!((r.status, x_cache(&r)), (200, "BYPASS"));
        assert_eq!(common::s(&s.h.last_event().action), "log");
    }
    assert_eq!(
        s.up.count(),
        3,
        "both went upstream though a copy was there"
    );
    // A fresh path answered to a log verdict is not stored either.
    for _ in 0..2 {
        assert_eq!(
            x_cache(&one(s.addr, &with("/fresh", &[WEAK])).await),
            "BYPASS"
        );
    }
    assert_eq!(
        x_cache(&one(s.addr, &get("/fresh")).await),
        "MISS",
        "no copy was made"
    );

    // Monitor mode: a block becomes a monitor, which also bypasses.
    let up = counting("200 OK", PUBLIC).await;
    let dir = Dir::new("monitor");
    let host = CacheHost::open(&dir.0, uid()).unwrap();
    let mut a = app_for(&up, free_port(), Some(spec()));
    a.mode = "monitor".into();
    let (h, addr) = serve_with(&host, a);
    assert!(host.wait_writable(Duration::from_secs(10)));
    one(addr, &get("/page")).await;
    for _ in 0..2 {
        let r = one(addr, &with("/page", &[SQLI])).await;
        assert_eq!((r.status, x_cache(&r)), (200, "BYPASS"));
        assert_eq!(common::s(&h.last_event().action), "monitor");
    }
    assert_eq!(up.count(), 3);
    assert_eq!(x_cache(&one(addr, &get("/page")).await), "HIT");
}
