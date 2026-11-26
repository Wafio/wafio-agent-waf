//! The response cache once a copy exists or is on its way: one fetch at a time for a key, a copy
//! sent while it is fetched again, asked about when its life is over, sent when the application
//! fails, removed by a purge, and what a full file system does. The cases of what is kept and the
//! key are in `cache.rs`.

#[path = "common/cache_site.rs"]
mod cache_site;
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use cache_site::*;
use common::*;
use wafio_proxy::{CacheHost, CacheRule, CacheSpec, CompressionSpec, PurgeError, PurgeScope};

const SECOND: Duration = Duration::from_millis(2100);
/// Past a life of two seconds, whatever fraction of a second the copy was made at.
const THREE_SECONDS: Duration = Duration::from_millis(3100);

/// An answer the application numbers, with the `Cache-Control` of `control`.
fn numbered(control: &'static str) -> impl Fn(&Seen) -> (Vec<u8>, bool) + Send + Sync + 'static {
    let n = Arc::new(AtomicUsize::new(0));
    move |seen| {
        let i = n.fetch_add(1, Ordering::SeqCst) + 1;
        (
            reply_to(
                seen,
                "200 OK",
                &format!("Content-Type: text/html\r\nCache-Control: {control}\r\n"),
                format!("answer {i}").as_bytes(),
            ),
            false,
        )
    }
}

/// An application that numbers its answers and says `503` while `down` is set.
async fn flaky(control: &'static str, down: Arc<AtomicBool>) -> TestUpstream {
    let ok = numbered(control);
    raw_upstream(move |seen| {
        if down.load(Ordering::SeqCst) {
            return (
                reply_to(
                    seen,
                    "503 Service Unavailable",
                    "Content-Type: text/plain\r\n",
                    b"down",
                ),
                false,
            );
        }
        ok(seen)
    })
    .await
}

/// A site with the settings `spec`, and an application that numbers its answers.
async fn numbering(control: &'static str, spec: CacheSpec) -> Site {
    site(raw_upstream(numbered(control)).await, spec, |_| {}).await
}

fn with_error_window(seconds: u32) -> CacheSpec {
    CacheSpec {
        stale_if_error_s: seconds,
        ..spec()
    }
}

// One fetch at a time for a key.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hundred_parallel_misses_make_one_request_to_the_application() {
    let (up, _) = slow_upstream(Duration::from_millis(300), |seen| {
        reply_to(seen, "200 OK", PUBLIC, b"the page")
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    let replies = burst(s.addr, 100, get("/page")).await;
    assert_eq!(s.up.count(), 1, "one request for the key");
    assert!(replies.iter().all(|r| r.text() == "the page"));
    assert_eq!(labelled(&replies, "MISS"), 1);
    assert_eq!(
        labelled(&replies, "HIT"),
        99,
        "the others waited for its copy"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_that_sets_a_cookie_makes_no_one_wait_and_the_next_burst_skips_the_lock() {
    let delay = Duration::from_millis(300);
    let (up, arrivals) = slow_upstream(delay, |seen| {
        reply_to(
            seen,
            "200 OK",
            "Content-Type: text/html\r\nSet-Cookie: a=b\r\n",
            b"personal",
        )
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    let started = Instant::now();
    let first = burst(s.addr, 100, get("/cookie")).await;
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the waiters woke when the fetch ended, not after five seconds: {:?}",
        started.elapsed()
    );
    assert_eq!(
        s.up.count(),
        100,
        "every one of them was answered by the application"
    );
    assert_eq!(labelled(&first, "MISS"), 100);
    {
        let at = arrivals.lock().unwrap();
        assert!(
            at[1] >= at[0] + delay - Duration::from_millis(50),
            "the others queued behind the first fetch"
        );
    }
    // The key is marked: the next burst takes no lock, so all of it reaches the application
    // before the first answer is due.
    let next = burst(s.addr, 100, get("/cookie")).await;
    assert_eq!(labelled(&next, "MISS"), 100);
    let at = arrivals.lock().unwrap();
    assert_eq!(at.len(), 200);
    let burst_at = &at[100..];
    let spread = burst_at
        .iter()
        .max()
        .unwrap()
        .duration_since(*burst_at.iter().min().unwrap());
    assert!(spread < delay, "the second burst queued: {spread:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_that_cannot_make_a_copy_waits_for_the_fetch_and_a_signed_in_visitor_does_not() {
    let (up, _) = slow_upstream(Duration::from_millis(400), |seen| {
        reply_to(seen, "200 OK", PUBLIC, b"public page")
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    let addr = s.addr;
    let leader = tokio::spawn(async move { one(addr, &get("/page")).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // A visitor who is signed in is the application's: it is asked at once, and nothing of the
    // fetch in progress reaches them.
    let signed_in =
        tokio::spawn(async move { one(addr, &with("/page", &["Cookie: sessionid=abc"])).await });
    // A `HEAD` cannot make a copy but may be answered from one, so it waits for the fetch.
    let head = head_of(addr, "/page", &[]).await;
    assert_eq!((head.status, x_cache(&head)), (200, "HIT"));
    let signed_in = signed_in.await.unwrap();
    assert_eq!(
        (x_cache(&signed_in), signed_in.text().as_str()),
        ("BYPASS", "public page")
    );
    assert_eq!(x_cache(&leader.await.unwrap()), "MISS");
    assert_eq!(
        s.up.count(),
        2,
        "the fetch of the leader and the signed-in visitor's"
    );
}

/// An application that answers `304` to a visitor's `If-None-Match` and `412` to an `If-Match`, as
/// one does that finds the condition not met, and `200` to anything else.
async fn conditional() -> TestUpstream {
    raw_upstream(|seen| {
        if seen.header("if-none-match").is_some() {
            return (
                b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n".to_vec(),
                false,
            );
        }
        if seen.header("if-match").is_some() {
            return (
                b"HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\n\r\n".to_vec(),
                false,
            );
        }
        (
            reply_to(
                seen,
                "200 OK",
                "Content-Type: text/html\r\nETag: \"v1\"\r\nCache-Control: public, max-age=600\r\n",
                b"page",
            ),
            false,
        )
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_condition_of_the_visitor_on_a_page_with_no_copy_does_not_keep_it_out_of_the_cache() {
    let s = site(conditional().await, spec(), |_| {}).await;
    // The first visitor holds the page already and says so in every way a request can.
    let first = fetch(
        s.addr,
        &with(
            "/a",
            &[
                "If-None-Match: *",
                "If-Match: \"other\"",
                "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT",
                "If-Unmodified-Since: Sun, 06 Nov 1994 08:49:37 GMT",
            ],
        ),
    )
    .await;
    assert_eq!(
        (first.status, x_cache(&first), first.body.len()),
        (304, "MISS", 0),
        "the application was asked for the page, and the visitor holds it"
    );
    let asked = s.up.last();
    for name in [
        "if-none-match",
        "if-match",
        "if-modified-since",
        "if-unmodified-since",
    ] {
        assert!(asked.header(name).is_none(), "{name} was sent on");
    }
    // The page was kept: a burst makes no request to the application and every answer is a copy.
    let burst = burst(s.addr, 20, get("/a")).await;
    assert_eq!(labelled(&burst, "HIT"), 20);
    assert_eq!(s.up.count(), 1);
    // A visitor whose tag is not the page's gets the page, and it is kept as well.
    let other = fetch(s.addr, &with("/c", &["If-None-Match: \"old\""])).await;
    assert_eq!(
        (other.status, x_cache(&other), other.text().as_str()),
        (200, "MISS", "page")
    );
    assert_eq!(x_cache(&fetch(s.addr, &get("/c")).await), "HIT");
    // A visitor who may not fill still asks with its own condition, and gets what the application said.
    let signed_in = one(
        s.addr,
        &with("/b", &["Cookie: sessionid=abc", "If-None-Match: \"v1\""]),
    )
    .await;
    assert_eq!(signed_in.status, 304);
    assert_eq!(s.up.last().header("if-none-match"), Some("\"v1\""));
}

#[tokio::test]
async fn an_answer_that_is_not_kept_marks_its_key_but_an_error_of_the_application_does_not() {
    let (up, arrivals) = slow_upstream(Duration::from_millis(250), |seen| {
        let (status, extra) = if seen.line.contains("/boom") {
            ("500 Internal Server Error", "")
        } else {
            ("302 Found", "Location: /elsewhere\r\n")
        };
        reply_to(seen, status, extra, b"")
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    for path in ["/moved", "/boom"] {
        // A first burst: the first request leads and ends unstored; the others queue for it.
        burst(s.addr, 6, get(path)).await;
        let before = arrivals.lock().unwrap().len();
        let next = burst(s.addr, 6, get(path)).await;
        assert_eq!(next.len(), 6);
        let at = arrivals.lock().unwrap();
        let spread = at[before..]
            .iter()
            .max()
            .unwrap()
            .duration_since(*at[before..].iter().min().unwrap());
        if path == "/moved" {
            assert!(
                spread < Duration::from_millis(250),
                "marked, no queue: {spread:?}"
            );
        } else {
            assert!(
                spread >= Duration::from_millis(250),
                "a 500 is not marked, so the burst queued again: {spread:?}"
            );
        }
    }
}

/// A spec with one rule for every path, keeping an answer that says nothing of its life for ten
/// minutes, for visitors who are not signed in.
fn keeping_everything() -> CacheSpec {
    CacheSpec {
        rules: vec![CacheRule {
            prefix: "/".into(),
            bypass: false,
            ttl_s: 600,
            signed_in: false,
        }],
        ..spec()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lead_whose_answer_is_refused_for_its_cookie_hands_the_turn_to_one_waiter() {
    let (up, _) = slow_upstream(Duration::from_millis(300), |seen| {
        reply_to(seen, "200 OK", "Content-Type: text/html\r\n", b"the page")
    })
    .await;
    let s = site(up, keeping_everything(), |_| {}).await;
    let addr = s.addr;
    // The visitor who leads carries an analytics cookie: the page is not marked public, so its
    // answer is not kept, and the key is not marked because the refusal is about the visitor.
    let lead =
        tokio::spawn(async move { one(addr, &with("/p", &["Cookie: _ga=GA1.1.1.1"])).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let waiters = burst(addr, 10, get("/p")).await;
    assert_eq!(x_cache(&lead.await.unwrap()), "MISS");
    assert_eq!(
        s.up.count(),
        2,
        "the lead's request and the one of the waiter that took its place"
    );
    assert_eq!(labelled(&waiters, "MISS"), 1);
    assert_eq!(
        labelled(&waiters, "HIT"),
        9,
        "the others waited for its copy"
    );
    assert!(waiters.iter().all(|r| r.text() == "the page"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_waiter_with_a_cookie_does_not_queue_a_second_time() {
    let (up, arrivals) = slow_upstream(Duration::from_millis(300), |seen| {
        reply_to(seen, "200 OK", "Content-Type: text/html\r\n", b"the page")
    })
    .await;
    let s = site(up, keeping_everything(), |_| {}).await;
    let addr = s.addr;
    let lead =
        tokio::spawn(async move { one(addr, &with("/p", &["Cookie: _ga=GA1.1.1.1"])).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Every waiter has a cookie too: a second lead among them would be refused the same way, so
    // after the first wait they all go to the application together.
    let waiters = burst(addr, 2, with("/p", &["Cookie: _ga=GA1.1.1.2"])).await;
    assert_eq!(x_cache(&lead.await.unwrap()), "MISS");
    assert_eq!(labelled(&waiters, "MISS"), 2);
    assert_eq!(s.up.count(), 3);
    let at = arrivals.lock().unwrap();
    let spread = at[1..]
        .iter()
        .max()
        .unwrap()
        .duration_since(*at[1..].iter().min().unwrap());
    assert!(
        spread < Duration::from_millis(200),
        "one fetch each, not one after the other: {spread:?}"
    );
}

// A copy that is past its life.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_copy_is_sent_at_once_and_one_fetch_in_the_background_makes_it_fresh() {
    // A life of two seconds: the copy that the refresh makes stays fresh for at least one, whatever
    // fraction of a second it was made at, so a busy host does not turn the last look into a miss.
    let s = numbering("public, max-age=2, stale-while-revalidate=60", spec()).await;
    let first = fetch(s.addr, &get("/a")).await;
    assert_eq!(
        (x_cache(&first), first.text().as_str()),
        ("MISS", "answer 1")
    );
    tokio::time::sleep(THREE_SECONDS).await;
    let replies = burst(s.addr, 5, get("/a")).await;
    assert!(
        replies
            .iter()
            .all(|r| r.text() == "answer 1" || r.text() == "answer 2"),
        "no one waited for the application"
    );
    assert!(
        labelled(&replies, "STALE") >= 1,
        "the first was told it is stale"
    );
    let stale = replies.iter().find(|r| x_cache(r) == "STALE").unwrap();
    assert_eq!(stale.text(), "answer 1");
    assert!(
        stale.header("age").unwrap().parse::<u64>().unwrap() >= 2,
        "{stale:?}"
    );
    // Only one refresh went to the application, however many were sent the stale copy.
    assert!(until(|| s.up.count() >= 2).await, "the refresh was made");
    copies_written(s.addr).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(s.up.count(), 2);
    let fresh = fetch(s.addr, &get("/a")).await;
    assert_eq!(
        (x_cache(&fresh), fresh.text().as_str()),
        ("HIT", "answer 2")
    );
    // A STALE answer is a decision event of the request, with the status the visitor got.
    let events = s.h.events();
    assert!(events.iter().all(|e| e.status == 200));
    assert_eq!(events.len(), 1 + 5 + 1);
}

#[tokio::test]
async fn a_copy_past_its_stale_while_revalidate_is_not_sent_but_fetched_first() {
    let s = numbering("public, max-age=1, stale-while-revalidate=1", spec()).await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    tokio::time::sleep(Duration::from_millis(3200)).await;
    let late = fetch(s.addr, &get("/a")).await;
    assert_eq!((x_cache(&late), late.text().as_str()), ("MISS", "answer 2"));
}

#[tokio::test]
async fn a_request_that_cannot_fill_gets_a_stale_copy_and_starts_no_refresh() {
    let s = numbering("public, max-age=1, stale-while-revalidate=60", spec()).await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    tokio::time::sleep(SECOND).await;
    let head = head_of(s.addr, "/a", &[]).await;
    assert_eq!(x_cache(&head), "STALE");
    let ranged = one(s.addr, &with("/a", &["Range: bytes=0-3"])).await;
    assert_eq!((ranged.status, x_cache(&ranged)), (206, "STALE"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(s.up.count(), 1, "no refresh for either");
}

#[tokio::test]
async fn the_refresh_in_the_background_does_not_replay_the_conditions_of_the_visitor() {
    // The copy has no tag and no date, so there is nothing to ask about; the visitor's own
    // condition is not the cache's question.
    let s = numbering("public, max-age=2, stale-while-revalidate=60", spec()).await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    tokio::time::sleep(THREE_SECONDS).await;
    let r = one(s.addr, &with("/a", &["If-None-Match: *"])).await;
    assert_eq!((r.status, x_cache(&r)), (304, "STALE"));
    assert!(until(|| s.up.count() >= 2).await, "the refresh was made");
    assert!(s.up.last().header("if-none-match").is_none());
    // The copy is written after the answer of the refresh is read, which a busy host can delay.
    tokio::time::sleep(Duration::from_millis(300)).await;
    copies_written(s.addr).await;
    let fresh = fetch(s.addr, &get("/a")).await;
    assert_eq!(
        (x_cache(&fresh), fresh.text().as_str()),
        ("HIT", "answer 2")
    );
}

/// An application that numbers its answers with `ETag: "v1"`, says `304` to that tag and counts
/// the questions it was asked.
async fn confirming(first_life: &'static str, confirmed_life: &'static str) -> TestUpstream {
    let n = Arc::new(AtomicUsize::new(0));
    raw_upstream(move |seen| {
        let i = n.fetch_add(1, Ordering::SeqCst) + 1;
        if seen.header("if-none-match") == Some("\"v1\"") {
            return (
                format!(
                    "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nCache-Control: {confirmed_life}\r\n\r\n"
                )
                .into_bytes(),
                false,
            );
        }
        (
            reply_to(
                seen,
                "200 OK",
                &format!(
                    "Content-Type: text/html\r\nETag: \"v1\"\r\nCache-Control: {first_life}\r\n"
                ),
                format!("page {i}").as_bytes(),
            ),
            false,
        )
    })
    .await
}

#[tokio::test]
async fn a_copy_past_its_life_is_asked_about_and_a_304_keeps_it_for_the_new_lifetime() {
    let s = site(
        confirming("public, max-age=1", "public, max-age=600").await,
        spec(),
        |_| {},
    )
    .await;
    let first = fetch(s.addr, &get("/a")).await;
    assert_eq!((x_cache(&first), first.text().as_str()), ("MISS", "page 1"));
    tokio::time::sleep(SECOND).await;
    // The visitor's own condition is the cache's question, not a second one.
    let again = fetch(s.addr, &with("/a", &["If-None-Match: \"other\""])).await;
    assert_eq!((again.status, again.text().as_str()), (200, "page 1"));
    assert_eq!(x_cache(&again), "MISS", "the application was asked");
    let asked = s.up.last();
    assert_eq!(asked.all("if-none-match"), ["\"v1\""]);
    assert!(asked.header("if-modified-since").is_none());
    // The 304 renewed the copy and its headers.
    let hit = fetch(s.addr, &get("/a")).await;
    assert_eq!((x_cache(&hit), hit.text().as_str()), ("HIT", "page 1"));
    assert_eq!(hit.header("cache-control"), Some("public, max-age=600"));
    assert_eq!(s.up.count(), 2);
    assert_eq!(answer_files(&s.dir.0).len(), 1, "the copy was written over");
}

#[tokio::test]
async fn a_visitor_who_holds_the_confirmed_copy_gets_a_304_from_it() {
    let s = site(
        confirming("public, max-age=1", "public, max-age=600").await,
        spec(),
        |_| {},
    )
    .await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    tokio::time::sleep(SECOND).await;
    let r = fetch(s.addr, &with("/a", &["If-None-Match: \"v1\""])).await;
    assert_eq!((r.status, r.body.len()), (304, 0));
    assert_eq!(s.up.count(), 2);
}

#[tokio::test]
async fn an_answer_that_changed_replaces_the_copy_and_a_last_modified_asks_too() {
    let n = Arc::new(AtomicUsize::new(0));
    let up = raw_upstream(move |seen| {
        let i = n.fetch_add(1, Ordering::SeqCst) + 1;
        (
            reply_to(
                seen,
                "200 OK",
                "Content-Type: text/html\r\nCache-Control: public, max-age=2\r\nLast-Modified: Sun, 06 Nov 1994 08:49:37 GMT\r\n",
                format!("version {i}").as_bytes(),
            ),
            false,
        )
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    assert_eq!(fetch(s.addr, &get("/a")).await.text(), "version 1");
    tokio::time::sleep(THREE_SECONDS).await;
    let r = fetch(s.addr, &get("/a")).await;
    assert_eq!((x_cache(&r), r.text().as_str()), ("MISS", "version 2"));
    let asked = s.up.last();
    assert_eq!(
        asked.header("if-modified-since"),
        Some("Sun, 06 Nov 1994 08:49:37 GMT")
    );
    assert!(
        asked.header("if-none-match").is_none(),
        "the copy has no tag"
    );
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "HIT");
}

#[tokio::test]
async fn a_cookie_on_the_304_reaches_the_visitor_and_leaves_no_copy() {
    let up = raw_upstream(|seen| {
        if seen.header("if-none-match") == Some("\"v1\"") {
            return (
                b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nCache-Control: public, max-age=600\r\nSet-Cookie: sid=renewed; Path=/\r\n\r\n".to_vec(),
                false,
            );
        }
        (
            reply_to(
                seen,
                "200 OK",
                "Content-Type: text/html\r\nETag: \"v1\"\r\nCache-Control: public, max-age=1\r\n",
                b"page",
            ),
            false,
        )
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    tokio::time::sleep(SECOND).await;
    let r = fetch(s.addr, &get("/a")).await;
    assert_eq!(
        (r.status, x_cache(&r), r.text().as_str()),
        (200, "MISS", "page")
    );
    assert_eq!(r.header("set-cookie"), Some("sid=renewed; Path=/"));
    assert!(answer_files(&s.dir.0).is_empty(), "no copy of it is kept");
    assert_eq!(s.up.count(), 2);
    // The same for a visitor who holds the page: the 304 it gets carries the cookie too.
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    tokio::time::sleep(SECOND).await;
    let held = fetch(s.addr, &with("/a", &["If-None-Match: \"v1\""])).await;
    assert_eq!(held.status, 304);
    assert_eq!(held.header("set-cookie"), Some("sid=renewed; Path=/"));
    assert!(answer_files(&s.dir.0).is_empty());
}

/// An application that gives a page an `ETag` and no word of its life (a rule gives it one), and
/// says `304` to that tag, with `control` as the `Cache-Control` of both answers when it is not
/// empty.
async fn tagging(control: &'static str) -> TestUpstream {
    raw_upstream(move |seen| {
        let extra = if control.is_empty() {
            String::new()
        } else {
            format!("Cache-Control: {control}\r\n")
        };
        if seen.header("if-none-match") == Some("\"v1\"") {
            return (
                format!("HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n{extra}\r\n").into_bytes(),
                false,
            );
        }
        (
            reply_to(
                seen,
                "200 OK",
                &format!("Content-Type: text/html\r\nETag: \"v1\"\r\n{extra}"),
                b"page",
            ),
            false,
        )
    })
    .await
}

fn two_second_rule() -> CacheSpec {
    CacheSpec {
        rules: vec![CacheRule {
            prefix: "/".into(),
            bypass: false,
            ttl_s: 2,
            signed_in: false,
        }],
        ..spec()
    }
}

#[tokio::test]
async fn a_304_to_a_visitor_with_a_cookie_leaves_the_copy_as_it_is() {
    let s = site(tagging("").await, two_second_rule(), |_| {}).await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    let files = answer_files(&s.dir.0);
    assert_eq!(files.len(), 1);
    tokio::time::sleep(THREE_SECONDS).await;
    // The copy is past its life and a visitor with only an analytics cookie comes. The application
    // confirms the copy, and the cookie keeps the answer from being renewed: the page is not
    // marked public. The copy is not the visitor's, so it is not removed either.
    let r = fetch(s.addr, &with("/a", &["Cookie: _ga=GA1.1.1.1"])).await;
    assert_eq!(
        (r.status, x_cache(&r), r.text().as_str()),
        (200, "MISS", "page")
    );
    assert_eq!(s.up.count(), 2);
    assert_eq!(answer_files(&s.dir.0), files, "the copy is still there");
    // The next visitor with no cookie confirms it and renews it, which a removed copy could not.
    let next = fetch(s.addr, &get("/a")).await;
    assert_eq!(
        (x_cache(&next), next.text().as_str()),
        ("MISS", "page"),
        "the application was asked"
    );
    assert_eq!(s.up.last().all("if-none-match"), ["\"v1\""]);
    assert_eq!(s.up.count(), 3);
    let hit = fetch(s.addr, &get("/a")).await;
    assert_eq!((x_cache(&hit), s.up.count()), ("HIT", 3));
    assert_eq!(answer_files(&s.dir.0), files);
}

#[tokio::test]
async fn a_refresh_in_the_background_for_a_visitor_with_a_cookie_leaves_the_copy_too() {
    let s = site(
        tagging("max-age=1, stale-while-revalidate=60").await,
        spec(),
        |_| {},
    )
    .await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    tokio::time::sleep(SECOND).await;
    // The stale copy is sent at once and the page is asked about in the background.
    let r = one(s.addr, &with("/a", &["Cookie: _ga=GA1.1.1.1"])).await;
    assert_eq!((x_cache(&r), r.text().as_str()), ("STALE", "page"));
    assert!(until(|| s.up.count() == 2).await, "the refresh asked");
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The `304` was refused for the cookie, which leaves the copy as it was: still past its life,
    // so the next visitor is sent it as stale again. A removed copy would be a miss.
    let next = one(s.addr, &get("/a")).await;
    assert_eq!((x_cache(&next), next.text().as_str()), ("STALE", "page"));
    assert_eq!(answer_files(&s.dir.0).len(), 1);
}

#[tokio::test]
async fn only_a_request_that_may_fill_asks_the_application_about_a_copy() {
    let s = site(
        confirming("public, max-age=1", "public, max-age=600").await,
        spec(),
        |_| {},
    )
    .await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    tokio::time::sleep(SECOND).await;
    // A signed-in visitor's request goes on as it is, with no question of the cache's.
    let r = one(s.addr, &with("/a", &["Cookie: sessionid=abc"])).await;
    assert_eq!((r.status, x_cache(&r)), (200, "BYPASS"));
    assert!(s.up.last().header("if-none-match").is_none());
    assert_eq!(r.text(), "page 2", "a full answer, not a copy");
}

// The application cannot answer.

async fn expired_with(control: &'static str, spec: CacheSpec) -> (Site, Arc<AtomicBool>) {
    let down = Arc::new(AtomicBool::new(false));
    let s = site(flaky(control, down.clone()).await, spec, |_| {}).await;
    let first = fetch(s.addr, &get("/a")).await;
    assert_eq!(
        (x_cache(&first), first.text().as_str()),
        ("MISS", "answer 1")
    );
    tokio::time::sleep(SECOND).await;
    (s, down)
}

#[tokio::test]
async fn a_stored_copy_is_sent_when_the_application_is_down_or_answers_a_server_error() {
    let (s, down) = expired_with("public, max-age=1", spec()).await;
    down.store(true, Ordering::SeqCst);
    let r = fetch(s.addr, &get("/a")).await;
    assert_eq!(
        (r.status, x_cache(&r), r.text().as_str()),
        (200, "STALE", "answer 1")
    );
    assert!(r.header("age").unwrap().parse::<u64>().unwrap() >= 2);
    assert_eq!(s.h.last_event().status, 200, "the visitor got the copy");
    // The application itself is gone: a connection that is refused.
    let mut gone = app("shop", s.addr.port(), "http://127.0.0.1:1");
    gone.cache = Some(spec());
    apply(&s.h, gone);
    let r = one(s.addr, &get("/a")).await;
    assert_eq!(
        (r.status, x_cache(&r), r.text().as_str()),
        (200, "STALE", "answer 1")
    );
    assert!(s.up.count() >= 2);
}

#[tokio::test]
async fn a_server_error_that_comes_in_pieces_is_covered_by_a_stored_copy_too() {
    let n = Arc::new(AtomicUsize::new(0));
    let up = raw_upstream(move |seen| {
        if n.fetch_add(1, Ordering::SeqCst) == 0 {
            return (
                reply_to(
                    seen,
                    "200 OK",
                    "Content-Type: text/html\r\nCache-Control: public, max-age=1\r\n",
                    b"good",
                ),
                false,
            );
        }
        // No length: chunked, as the default error page of many frameworks is.
        (
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndown\r\n0\r\n\r\n".to_vec(),
            false,
        )
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    assert_eq!(fetch(s.addr, &get("/a")).await.text(), "good");
    tokio::time::sleep(SECOND).await;
    let r = fetch(s.addr, &get("/a")).await;
    assert_eq!(
        (r.status, x_cache(&r), r.text().as_str()),
        (200, "STALE", "good")
    );
    assert_eq!(s.up.count(), 2, "the application was asked");
    assert_eq!(s.h.last_event().status, 200, "the visitor got the copy");
    // A page with no copy gets the error as the application said it. `Connection: close`: the
    // answer has no end of its own but the connection's.
    let none = fetch(s.addr, &with("/other", &["Connection: close"])).await;
    assert_eq!((none.status, x_cache(&none)), (503, "MISS"));
}

#[tokio::test]
async fn each_server_error_status_is_covered_and_a_client_error_is_not() {
    for (status, covered) in [
        ("500 Internal Server Error", true),
        ("502 Bad Gateway", true),
        ("503 Service Unavailable", true),
        ("504 Gateway Timeout", true),
        ("404 Not Found", false),
        ("501 Not Implemented", false),
    ] {
        let up = {
            let n = Arc::new(AtomicUsize::new(0));
            raw_upstream(move |seen| {
                if n.fetch_add(1, Ordering::SeqCst) == 0 {
                    (
                        reply_to(
                            seen,
                            "200 OK",
                            "Content-Type: text/html\r\nCache-Control: public, max-age=1\r\n",
                            b"good",
                        ),
                        false,
                    )
                } else {
                    (
                        reply_to(seen, status, "Content-Type: text/plain\r\n", b"bad"),
                        false,
                    )
                }
            })
            .await
        };
        let s = site(up, spec(), |_| {}).await;
        assert_eq!(fetch(s.addr, &get("/a")).await.text(), "good");
        tokio::time::sleep(SECOND).await;
        let r = fetch(s.addr, &get("/a")).await;
        let want = if covered {
            ("STALE", "good")
        } else {
            ("MISS", "bad")
        };
        assert_eq!((x_cache(&r), r.text().as_str()), want, "{status}");
    }
}

#[tokio::test]
async fn the_window_is_the_answers_own_else_the_setting_and_past_it_the_error_goes_through() {
    // The setting's window is a second: three seconds past the life is too late.
    let (s, down) = expired_with("public, max-age=1", with_error_window(1)).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    down.store(true, Ordering::SeqCst);
    let r = fetch(s.addr, &get("/a")).await;
    assert_eq!((r.status, r.text().as_str()), (503, "down"));
    // The answer's own window wins over a setting of none.
    let (s, down) =
        expired_with("public, max-age=1, stale-if-error=60", with_error_window(0)).await;
    down.store(true, Ordering::SeqCst);
    let r = fetch(s.addr, &get("/a")).await;
    assert_eq!((r.status, x_cache(&r)), (200, "STALE"));
    // And over a long setting: its own is one second.
    let (s, down) = expired_with(
        "public, max-age=1, stale-if-error=1",
        with_error_window(600),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    down.store(true, Ordering::SeqCst);
    let r = fetch(s.addr, &get("/a")).await;
    assert_eq!(r.status, 503);
}

#[tokio::test]
async fn an_answer_that_must_be_revalidated_is_never_sent_stale() {
    for control in [
        "public, max-age=1, must-revalidate",
        "public, max-age=1, proxy-revalidate",
        "public, s-maxage=1",
    ] {
        let (s, down) = expired_with(control, spec()).await;
        down.store(true, Ordering::SeqCst);
        let r = fetch(s.addr, &get("/a")).await;
        assert_eq!((r.status, r.text().as_str()), (503, "down"), "{control}");
        assert_ne!(x_cache(&r), "STALE", "{control}");
    }
    // Unless the answer names its own window, and then only that one.
    for control in [
        "public, max-age=1, must-revalidate, stale-if-error=60",
        "public, s-maxage=1, stale-if-error=60",
    ] {
        let (s, down) = expired_with(control, spec()).await;
        down.store(true, Ordering::SeqCst);
        let r = fetch(s.addr, &get("/a")).await;
        assert_eq!((r.status, x_cache(&r)), (200, "STALE"), "{control}");
    }
    // Its own stale-while-revalidate does not lift it for an error it did not name: the copy is
    // past that window, and the application is down.
    let (s, down) = expired_with(
        "public, max-age=1, must-revalidate, stale-while-revalidate=1",
        spec(),
    )
    .await;
    down.store(true, Ordering::SeqCst);
    let r = fetch(s.addr, &get("/a")).await;
    assert_eq!((r.status, r.text().as_str()), (503, "down"));
}

#[tokio::test]
async fn a_copy_that_cannot_be_asked_about_or_used_is_not_read_for_nothing() {
    // No validator, no window: past its life the copy is no use, so a request is a plain miss.
    let s = numbering("public, max-age=1", with_error_window(0)).await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    tokio::time::sleep(SECOND).await;
    let r = fetch(s.addr, &get("/a")).await;
    assert_eq!((x_cache(&r), r.text().as_str()), ("MISS", "answer 2"));
}

#[tokio::test]
async fn a_copy_with_no_use_left_is_read_once_and_removed() {
    // The application stops sending answers that may be kept.
    let n = Arc::new(AtomicUsize::new(0));
    let up = raw_upstream(move |seen| {
        let control = if n.fetch_add(1, Ordering::SeqCst) == 0 {
            "public, max-age=1"
        } else {
            "private"
        };
        (
            reply_to(
                seen,
                "200 OK",
                &format!("Content-Type: text/html\r\nCache-Control: {control}\r\n"),
                b"page",
            ),
            false,
        )
    })
    .await;
    let s = site(up, with_error_window(0), |_| {}).await;
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    assert_eq!(s.host.counters("shop").unwrap().objects, 1);
    tokio::time::sleep(SECOND).await;
    let r = fetch(s.addr, &get("/a")).await;
    assert_eq!((x_cache(&r), r.text().as_str()), ("MISS", "page"));
    // The request that found it dead took it out, and the answer was not kept: no file is left
    // for the next request to read and throw away.
    assert_eq!(s.host.counters("shop").unwrap().objects, 0);
    assert!(answer_files(&s.dir.0).is_empty());
}

// A purge.

async fn kept(s: &Site, paths: &[&str]) {
    for path in paths {
        assert_eq!(x_cache(&fetch(s.addr, &get(path)).await), "MISS", "{path}");
    }
}

async fn is_hit(s: &Site, path: &str) -> bool {
    x_cache(&fetch(s.addr, &get(path)).await) == "HIT"
}

#[tokio::test]
async fn a_purge_by_address_removes_every_variant_of_it_in_both_tiers_and_no_other() {
    let s = numbering("public, max-age=600", spec()).await;
    kept(&s, &["/a", "/b", "/a?x=1"]).await;
    let gz = with("/a", &["Accept-Encoding: gzip"]);
    assert_eq!(x_cache(&fetch(s.addr, &gz).await), "MISS");
    // The third visit of /a is read from memory.
    for _ in 0..3 {
        assert!(is_hit(&s, "/a").await);
    }
    let (entries, _, memory) = s.host.usage("shop").unwrap();
    assert_eq!(entries, 4);
    assert!(memory > 0, "a copy is in memory");
    assert_eq!(answer_files(&s.dir.0).len(), 4);

    s.host.purge("shop", PurgeScope::Url("/a")).unwrap();
    let (entries, _, memory) = s.host.usage("shop").unwrap();
    assert_eq!(
        (entries, memory),
        (2, 0),
        "the index is clear when it returns"
    );
    assert_eq!(answer_files(&s.dir.0).len(), 2, "and the files are gone");
    assert_eq!(
        x_cache(&fetch(s.addr, &get("/a")).await),
        "MISS",
        "identity"
    );
    assert_eq!(x_cache(&fetch(s.addr, &gz).await), "MISS", "gzip");
    assert!(is_hit(&s, "/b").await && is_hit(&s, "/a?x=1").await);

    // An absolute address names one host: another host's copy stays.
    s.host
        .purge("shop", PurgeScope::Url("https://other.test/b"))
        .unwrap();
    assert!(is_hit(&s, "/b").await);
    s.host
        .purge("shop", PurgeScope::Url("http://App.test/b"))
        .unwrap();
    assert_eq!(x_cache(&fetch(s.addr, &get("/b")).await), "MISS");
    // A query is part of the address.
    s.host.purge("shop", PurgeScope::Url("/a?x=2")).unwrap();
    assert!(is_hit(&s, "/a?x=1").await);
}

#[tokio::test]
async fn a_purge_names_an_address_as_the_browser_bar_shows_it() {
    let s = numbering("public, max-age=600", spec()).await;
    kept(
        &s,
        &[
            "/wiki/Foo_(bar)",
            "/a-b",
            "/a/b",
            "/wiki/Foo_(baz)",
            "/keep",
        ],
    )
    .await;
    // The stored target has the parentheses escaped, and no dot segment.
    s.host
        .purge("shop", PurgeScope::Url("/wiki/Foo_(bar)"))
        .unwrap();
    assert_eq!(
        x_cache(&fetch(s.addr, &get("/wiki/Foo_(bar)")).await),
        "MISS"
    );
    s.host.purge("shop", PurgeScope::Url("/a%2db")).unwrap();
    assert_eq!(x_cache(&fetch(s.addr, &get("/a-b")).await), "MISS");
    s.host.purge("shop", PurgeScope::Url("/a/./b")).unwrap();
    assert_eq!(x_cache(&fetch(s.addr, &get("/a/b")).await), "MISS");
    s.host
        .purge("shop", PurgeScope::Prefix("/wiki/Foo_(ba"))
        .unwrap();
    assert_eq!(
        x_cache(&fetch(s.addr, &get("/wiki/Foo_(baz)")).await),
        "MISS"
    );
    assert!(is_hit(&s, "/keep").await, "no other copy went");
    assert_eq!(
        s.host.purge("shop", PurgeScope::Url("/a%zz")),
        Err(PurgeError::Invalid)
    );
    assert_eq!(
        s.host.purge("shop", PurgeScope::Prefix("/a b")),
        Err(PurgeError::Invalid)
    );
    assert!(is_hit(&s, "/keep").await, "a refused purge removes nothing");
}

#[tokio::test]
async fn a_purge_by_prefix_names_the_path_and_a_purge_of_the_app_removes_everything() {
    let s = numbering("public, max-age=600", spec()).await;
    kept(&s, &["/p/1", "/p/2?q=1", "/q/1", "/other?next=/p/1"]).await;
    s.host.purge("shop", PurgeScope::Prefix("/p/")).unwrap();
    assert_eq!(x_cache(&fetch(s.addr, &get("/p/1")).await), "MISS");
    assert_eq!(x_cache(&fetch(s.addr, &get("/p/2?q=1")).await), "MISS");
    assert!(is_hit(&s, "/q/1").await);
    assert!(
        is_hit(&s, "/other?next=/p/1").await,
        "the query is not the path"
    );
    s.host
        .purge("shop", PurgeScope::Prefix("http://app.test/q"))
        .unwrap();
    assert_eq!(x_cache(&fetch(s.addr, &get("/q/1")).await), "MISS");
    for _ in 0..3 {
        is_hit(&s, "/p/1").await;
    }
    s.host.purge("shop", PurgeScope::App).unwrap();
    assert_eq!(s.host.usage("shop").unwrap(), (0, 0, 0));
    assert!(answer_files(&s.dir.0).is_empty());
    assert_eq!(x_cache(&fetch(s.addr, &get("/p/1")).await), "MISS");
}

#[tokio::test]
async fn a_purge_names_copies_that_were_on_disk_before_the_process_started() {
    let dir = Dir::new("purge-restart");
    let up = raw_upstream(numbered("public, max-age=600")).await;
    {
        let host = CacheHost::open(&dir.0, uid()).unwrap();
        let (_h, addr) = serve_with(&host, app_for(&up, free_port(), Some(spec())));
        assert!(host.wait_writable(Duration::from_secs(10)));
        for path in ["/kept", "/kept?x=1", "/other"] {
            assert_eq!(x_cache(&fetch(addr, &get(path)).await), "MISS");
        }
        host.release();
    }
    // The next process builds its index from the files: it knows their addresses too.
    let host = CacheHost::open(&dir.0, uid()).unwrap();
    let (_h, addr) = serve_with(&host, app_for(&up, free_port(), Some(spec())));
    assert!(host.wait_writable(Duration::from_secs(10)));
    assert_eq!(host.usage("shop").unwrap().0, 3);
    host.purge("shop", PurgeScope::Url("http://app.test/kept"))
        .unwrap();
    assert_eq!(host.usage("shop").unwrap().0, 2);
    host.purge("shop", PurgeScope::Prefix("/oth")).unwrap();
    assert_eq!(host.usage("shop").unwrap().0, 1);
    assert_eq!(x_cache(&fetch(addr, &get("/kept")).await), "MISS");
    assert_eq!(x_cache(&fetch(addr, &get("/kept?x=1")).await), "HIT");
    assert_eq!(answer_files(&dir.0).len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_that_began_before_a_purge_is_not_stored() {
    let (up, _) = slow_upstream(Duration::from_millis(500), |seen| {
        reply_to(seen, "200 OK", PUBLIC, b"old page")
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    let addr = s.addr;
    let begun = tokio::spawn(async move { one(addr, &get("/slow")).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    s.host.purge("shop", PurgeScope::App).unwrap();
    assert_eq!(x_cache(&begun.await.unwrap()), "MISS");
    copies_written(s.addr).await;
    assert!(
        answer_files(&s.dir.0).is_empty(),
        "the old answer was dropped"
    );
    assert_eq!(x_cache(&fetch(s.addr, &get("/slow")).await), "MISS");
    assert!(
        is_hit(&s, "/slow").await,
        "a fetch that begins after it is kept"
    );
    assert_eq!(s.up.count(), 2);
}

#[tokio::test]
async fn a_purge_that_cannot_be_done_says_why() {
    let s = numbering("public, max-age=600", spec()).await;
    kept(&s, &["/a"]).await;
    assert_eq!(
        s.host.purge("nope", PurgeScope::App),
        Err(PurgeError::CacheOff)
    );
    assert_eq!(
        s.host.purge("shop", PurgeScope::Url("ftp://app.test/a")),
        Err(PurgeError::Invalid)
    );
    assert_eq!(
        s.host.purge("shop", PurgeScope::Prefix("a")),
        Err(PurgeError::Invalid)
    );
    // A reload's successor reads the copies and removes none: the purge is for the process that
    // holds the lock, so it says to try again.
    let successor = CacheHost::open(&s.dir.0, uid()).unwrap();
    successor.commit(&[spec().limits("shop")]);
    assert!(!successor.holds_lock());
    assert_eq!(
        successor.purge("shop", PurgeScope::App),
        Err(PurgeError::Busy)
    );
    assert!(is_hit(&s, "/a").await, "and nothing was removed");
    // Once the holder lets go and the successor takes over, it purges.
    s.host.release();
    assert!(successor.take_over());
    assert_eq!(successor.purge("shop", PurgeScope::App), Ok(()));
    assert!(answer_files(&s.dir.0).is_empty());
}

// A full file system.

#[tokio::test]
async fn a_write_that_fails_for_want_of_room_is_a_skip_and_the_visitor_never_knows() {
    let s = numbering("public, max-age=600", spec()).await;
    s.host.fail_writes_for_want_of_room(true);
    for _ in 0..2 {
        let r = fetch(s.addr, &get("/a")).await;
        assert_eq!((r.status, x_cache(&r)), (200, "MISS"));
    }
    assert!(answer_files(&s.dir.0).is_empty());
    assert_eq!(s.host.counters("shop").unwrap().skipped_disk_full, 2);
    assert_eq!(s.host.counters("shop").unwrap().stored, 0);
    s.host.fail_writes_for_want_of_room(false);
    assert_eq!(x_cache(&fetch(s.addr, &get("/a")).await), "MISS");
    assert!(is_hit(&s, "/a").await, "stores resume");
    assert!(s.host.usage("shop").unwrap().0 == 1);
}

#[tokio::test]
async fn under_five_percent_free_nothing_is_stored_and_the_least_used_copies_go_until_it_is_not() {
    let body: &'static [u8] = Box::leak(vec![b'x'; 1 << 20].into_boxed_slice());
    let up = raw_upstream(move |seen| (reply_to(seen, "200 OK", PUBLIC, body), false)).await;
    let s = site(up, spec(), |_| {}).await;
    let paths: Vec<String> = (0..6).map(|n| format!("/big/{n}")).collect();
    for p in &paths {
        assert_eq!(x_cache(&fetch(s.addr, &get(p)).await), "MISS");
    }
    assert_eq!(s.host.usage("shop").unwrap().0, 6);
    // 1 MiB free of 100 MiB: the floor is 5 MiB, so four more must be made.
    s.host.pretend_free_space(Some((1 << 20, 100 << 20)));
    s.host.check_disk();
    let (entries, disk, _) = s.host.usage("shop").unwrap();
    assert!(
        entries <= 2 && disk <= 2 * ((1 << 20) + 2048),
        "{entries} {disk}"
    );
    assert_eq!(
        answer_files(&s.dir.0).len(),
        entries,
        "the files went with them"
    );
    assert!(s.host.counters("shop").unwrap().evictions >= 4);
    // While it is nearly full no copy is made: a skip, counted.
    let before = s.host.counters("shop").unwrap().skipped_disk_full;
    for _ in 0..2 {
        assert_eq!(x_cache(&fetch(s.addr, &get("/new")).await), "MISS");
    }
    assert_eq!(
        s.host.counters("shop").unwrap().skipped_disk_full,
        before + 2
    );
    // Room again: the next check lets the stores go on.
    s.host.pretend_free_space(Some((50 << 20, 100 << 20)));
    s.host.check_disk();
    assert_eq!(x_cache(&fetch(s.addr, &get("/new")).await), "MISS");
    assert!(is_hit(&s, "/new").await);
}

// What the cache counts.

#[tokio::test]
async fn the_counters_say_what_the_cache_did_and_why_answers_were_not_kept() {
    let up = raw_upstream(|seen| {
        let (headers, body): (&str, &[u8]) = if seen.line.contains("/page") {
            (
                "Content-Type: text/html\r\nCache-Control: public, max-age=600\r\n",
                b"page",
            )
        } else if seen.line.contains("/plain") {
            ("Content-Type: text/html\r\n", b"no lifetime")
        } else if seen.line.contains("/private") {
            (
                "Content-Type: text/html\r\nCache-Control: private, max-age=60\r\n",
                b"mine",
            )
        } else if seen.line.contains("/large") {
            (
                "Content-Type: text/html\r\nCache-Control: public, max-age=600\r\n",
                &[b'x'; 3000],
            )
        } else {
            (
                "Content-Type: text/html\r\nCache-Control: public, max-age=600\r\n",
                b"other",
            )
        };
        (reply_to(seen, "200 OK", headers, body), false)
    })
    .await;
    let s = site(
        up,
        CacheSpec {
            max_object_bytes: 2048,
            ..spec()
        },
        |_| {},
    )
    .await;
    for _ in 0..4 {
        fetch(s.addr, &get("/page")).await;
    }
    fetch(s.addr, &get("/plain")).await;
    fetch(s.addr, &get("/private")).await;
    fetch(s.addr, &get("/large")).await;
    // A signed-in visitor's request is not looked up, and a POST is not checked: both are bypasses.
    fetch(s.addr, &with("/other", &["Cookie: sessionid=abc"])).await;
    let held = s.host.counters("shop").unwrap();
    assert_eq!((held.objects, held.disk_bytes > 0), (1, true));
    one(s.addr, &post("/page", "text/plain", b"x")).await;
    let c = s.host.counters("shop").unwrap();
    assert_eq!(
        (
            c.hits_memory + c.hits_disk,
            c.hits_memory >= 1,
            c.misses,
            c.bypass,
            c.stale
        ),
        (3, true, 4, 2, 0),
        "{c:?}"
    );
    assert_eq!(c.requests, 9);
    assert_eq!((c.skipped_no_lifetime, c.skipped_too_large), (1, 1));
    assert_eq!(
        c.skipped_private, 1,
        "the private answer, not the signed-in visitor"
    );
    assert_eq!(c.stored, 1);
    assert_eq!(
        (c.objects, c.disk_bytes),
        (0, 0),
        "the POST removed the copy"
    );
    assert_eq!(c.corrupt, 0);
}

#[tokio::test]
async fn an_answer_that_comes_in_pieces_is_not_kept_and_is_counted() {
    let up = raw_upstream(|_| {
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: public, max-age=600\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npart\r\n0\r\n\r\n".to_vec(),
            false,
        )
    })
    .await;
    let s = site(up, spec(), |_| {}).await;
    // `Connection: close`: the answer has no end of its own but the connection's.
    for _ in 0..2 {
        let r = fetch(s.addr, &with("/s", &["Connection: close"])).await;
        assert_eq!((r.status, x_cache(&r)), (200, "MISS"));
    }
    assert_eq!(s.host.counters("shop").unwrap().skipped_streamed, 2);
    assert!(answer_files(&s.dir.0).is_empty());
}

// Files of a folder in the memory tier.

#[tokio::test]
async fn a_static_file_is_kept_in_memory_by_the_file_and_the_encoding() {
    let dir = Dir::new("static");
    std::fs::create_dir_all(dir.0.join("public")).unwrap();
    let page = dir.0.join("public/p.html");
    std::fs::write(&page, vec![b'a'; 4000]).unwrap();
    let modified = std::fs::metadata(&page).unwrap().modified().unwrap();
    let root = dir.0.join("public").to_str().unwrap().to_owned();
    let s = site(counting("200 OK", PUBLIC).await, spec(), |a| {
        a.static_files = Some(wafio_proxy::StaticSpec::check(&root, "", 0).unwrap());
        a.compression = Some(CompressionSpec { min_bytes: 100 });
    })
    .await;
    let gz = with("/p.html", &["Accept-Encoding: gzip"]);
    let first = one(s.addr, &gz).await;
    assert_eq!(
        (
            first.status,
            first.header("content-encoding"),
            x_cache(&first)
        ),
        (200, Some("gzip"), "BYPASS")
    );
    let held = s.host.usage("shop").unwrap().2;
    assert!(
        held > 0 && held < 2000,
        "the compressed answer is in memory: {held}"
    );
    // Another file with the same size and time, as stat sees it, is the same key: the memory
    // answers, with the compressed bytes it made before.
    std::fs::write(&page, vec![b'b'; 4000]).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&page)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    let again = one(s.addr, &gz).await;
    assert_eq!(again.body, first.body, "from memory, not from the file");
    // Another encoding is another key, and reads the file as it is now.
    let plain = one(s.addr, &get("/p.html")).await;
    assert_eq!(plain.body, vec![b'b'; 4000]);
    assert!(s.host.usage("shop").unwrap().2 > held);
    // A file that changed (its size, here) is another key.
    std::fs::write(&page, vec![b'c'; 4001]).unwrap();
    let changed = one(s.addr, &get("/p.html")).await;
    assert_eq!(changed.body, vec![b'c'; 4001]);
    assert_eq!(s.up.count(), 0, "the application was never asked");
}

#[tokio::test]
async fn a_static_file_over_64_kib_is_read_once_and_then_served_from_memory() {
    let size = 200usize << 10;
    let dir = Dir::new("static-mid");
    std::fs::create_dir_all(dir.0.join("public")).unwrap();
    let file = dir.0.join("public/m.bin");
    let first: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    std::fs::write(&file, &first).unwrap();
    let modified = std::fs::metadata(&file).unwrap().modified().unwrap();
    let root = dir.0.join("public").to_str().unwrap().to_owned();
    let s = site(counting("200 OK", PUBLIC).await, spec(), |a| {
        a.static_files = Some(wafio_proxy::StaticSpec::check(&root, "", 0).unwrap());
    })
    .await;
    let read = one(s.addr, &get("/m.bin")).await;
    assert_eq!(read.status, 200);
    assert!(read.body == first, "the file as it was read");
    let held = s.host.usage("shop").unwrap().2;
    assert!(held >= size as u64, "the answer is in memory: {held}");
    // Other bytes with the same size and time, as stat sees them, are the same key: the memory
    // answers with what it kept.
    std::fs::write(&file, vec![9u8; size]).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    let again = one(s.addr, &get("/m.bin")).await;
    assert_eq!(again.status, 200);
    assert!(again.body == first, "from memory, not from the file");
    assert_eq!(s.up.count(), 0, "the application was never asked");
}

#[tokio::test]
async fn memory_zero_keeps_no_static_file_in_memory() {
    let dir = Dir::new("static-zero");
    std::fs::create_dir_all(dir.0.join("public")).unwrap();
    std::fs::write(dir.0.join("public/a.txt"), b"a file").unwrap();
    let root = dir.0.join("public").to_str().unwrap().to_owned();
    let s = site(
        counting("200 OK", PUBLIC).await,
        CacheSpec {
            memory_bytes: 0,
            ..spec()
        },
        |a| a.static_files = Some(wafio_proxy::StaticSpec::check(&root, "", 0).unwrap()),
    )
    .await;
    for _ in 0..2 {
        assert_eq!(one(s.addr, &get("/a.txt")).await.text(), "a file");
    }
    assert_eq!(s.host.usage("shop").unwrap().2, 0);
}

#[tokio::test]
async fn an_app_with_no_cache_keeps_nothing_of_its_static_files() {
    let dir = Dir::new("static-off");
    std::fs::create_dir_all(dir.0.join("public")).unwrap();
    std::fs::write(dir.0.join("public/a.txt"), b"a file").unwrap();
    let root = dir.0.join("public").to_str().unwrap().to_owned();
    let up = counting("200 OK", PUBLIC).await;
    let a = {
        let mut a = app("shop", free_port(), &format!("http://{}", up.addr));
        a.static_files = Some(wafio_proxy::StaticSpec::check(&root, "", 0).unwrap());
        a
    };
    let (_h, addr) = Harness::serve(vec![a]);
    for _ in 0..2 {
        let r = one(addr, &get("/a.txt")).await;
        assert_eq!((r.text().as_str(), r.header("x-cache")), ("a file", None));
    }
}
