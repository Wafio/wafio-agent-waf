//! A copy past its life: the question the cache asks the application to see whether it still
//! holds, the headers a `304` brings, and the fetch in the background that makes a stale copy fresh.

use std::time::Duration;

use bytes::Bytes;
use pingora::http::RequestHeader;
use wafio_domain::Headers;

use super::format::{Loaded, StoredHead};
use super::{Ask, Ctx, Old, Pending};
use crate::config::Route;
use crate::response::OutboundResponse;
use crate::upstream::Forwarded;

/// The headers that make a request conditional. The question of the cache replaces the visitor's.
const CONDITIONALS: [&str; 5] = [
    "if-none-match",
    "if-modified-since",
    "if-match",
    "if-unmodified-since",
    "if-range",
];

/// What a `304` never changes of the copy it confirms.
const NOT_REPLACED: [&[u8]; 6] = [
    b"content-type",
    b"content-encoding",
    b"content-length",
    b"content-range",
    b"transfer-encoding",
    b"vary",
];

/// The validators of a stored answer, to ask the application whether it still holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Validator {
    etag: Option<Vec<u8>>,
    last_modified: Option<Vec<u8>>,
}

/// What a request that may fill sends when there is no copy to ask about: no condition at all. The
/// answer is for the cache, so a `304` or `412` to the visitor's own condition would be none.
pub(crate) static NO_CONDITIONS: Validator = Validator {
    etag: None,
    last_modified: None,
};

impl Validator {
    /// `None` for an answer that has neither an `ETag` nor a `Last-Modified`.
    pub fn of(copy: &Loaded) -> Option<Validator> {
        let value = |name: &[u8]| {
            copy.head
                .lines
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        let validator = Validator {
            etag: value(b"ETag"),
            last_modified: value(b"Last-Modified"),
        };
        (validator.etag.is_some() || validator.last_modified.is_some()).then_some(validator)
    }

    /// Makes the upstream request this one's question.
    pub fn apply_http(&self, head: &mut RequestHeader) {
        for name in CONDITIONALS {
            head.remove_header(name);
        }
        // A value http refuses is left out: the request goes as a plain one.
        if let Some(tag) = &self.etag {
            let _ = head.insert_header("If-None-Match", tag.as_slice());
        }
        if let Some(date) = &self.last_modified {
            let _ = head.insert_header("If-Modified-Since", date.as_slice());
        }
    }

    /// The same for the header map a FastCGI request is made from.
    pub fn apply_map(&self, headers: &mut Headers) {
        headers.retain(|name, _| {
            !CONDITIONALS
                .iter()
                .any(|c| name.eq_ignore_ascii_case(c.as_bytes()))
        });
        if let Some(tag) = &self.etag {
            headers.insert(b"If-None-Match".to_vec(), vec![tag.clone()]);
        }
        if let Some(date) = &self.last_modified {
            headers.insert(b"If-Modified-Since".to_vec(), vec![date.clone()]);
        }
    }
}

/// The copy's head with the headers a `304` brought in place of the ones of the same name, and the
/// answer that head and the copy's body make, which carries the `Date` and `Age` of the `304` so
/// that its lifetime is read as that of a new answer. A cookie the `304` sets is in both: no copy
/// is made of an answer that has one, and the visitor still gets it.
pub(super) fn merged(old: &Loaded, answer: &OutboundResponse) -> (StoredHead, OutboundResponse) {
    let mut brought = answer.plain_lines();
    brought.extend(answer.cookie_lines());
    let mut lines = old.head.lines.clone();
    let mut done: Vec<Vec<u8>> = Vec::new();
    for (name, _) in &brought {
        let lower = name.to_ascii_lowercase();
        if NOT_REPLACED.contains(&&lower[..]) || done.contains(&lower) {
            continue;
        }
        lines.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        lines.extend(
            brought
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .cloned(),
        );
        done.push(lower);
    }
    let head = StoredHead {
        status: old.head.status,
        http10: old.head.http10,
        reason: old.head.reason.clone(),
        lines,
    };
    let mut resp = OutboundResponse::from_stored(head.status, &head.reason, &head.lines);
    resp.body = Bytes::copy_from_slice(&old.body);
    for name in [&b"Date"[..], b"Age"] {
        if let Some(value) = answer.peek(name) {
            resp.set(name, value);
        }
    }
    (head, resp)
}

/// The longest a refresh in the background holds the fill lock on a route with no upstream
/// timeout.
const UNLIMITED_LIMIT: Duration = Duration::from_secs(60);

/// How long a refresh in the background may take: the route's upstream timeout, else
/// [`UNLIMITED_LIMIT`].
pub(super) fn limit(route: &Route) -> Duration {
    if route.upstream_unlimited {
        UNLIMITED_LIMIT
    } else {
        route.upstream_timeout
    }
}

/// Fetches the page again behind the visitor who was sent the stale copy. `guard` is the fill
/// lock, so there is one fetch at a time for a key; the copy stays as it was when the application
/// fails, answers in pieces or does not answer within [`limit`], which frees the lock.
pub(super) fn spawn(cx: &Ctx<'_>, ask: &Ask, old: Old, guard: super::FillGuard) {
    let shared = cx.shared.clone();
    let route = cx.route.clone();
    let req = cx.req.clone();
    let peer = cx.peer.clone();
    let remote = cx.remote.to_owned();
    let ask = ask.clone();
    let limit = limit(&route);
    tokio::spawn(async move {
        let cx = Ctx {
            shared: &shared,
            route: &route,
            req: &req,
            peer: &peer,
            remote: &remote,
        };
        // Dropping the future drops the lock it holds.
        let _ = tokio::time::timeout(limit, run(&cx, &ask, old, guard)).await;
    });
}

async fn run(cx: &Ctx<'_>, ask: &Ask, old: Old, guard: super::FillGuard) {
    let sent = crate::pipeline::send_upstream(
        cx.shared,
        cx.route,
        cx.req,
        cx.peer,
        cx.remote,
        &[],
        None,
        old.validator.as_ref(),
        true,
    )
    .await;
    let mut pending = Pending {
        guard: Some(guard),
        old: Some(old),
    };
    match sent {
        Ok(Forwarded::Whole(mut resp)) => {
            if resp.status == 304 && pending.validator().is_some() {
                let _ = super::revalidated(cx, ask, &mut pending, &resp);
                return;
            }
            if let Some(spec) = &cx.route.compression {
                let stats = cx.shared.edge.app(&cx.route.app_id);
                crate::compress::apply(&stats, spec, cx.req, &cx.route.session, &mut resp).await;
            }
            super::fill(
                cx.shared,
                cx.route,
                ask,
                cx.req,
                &resp,
                pending.take_guard(),
            );
        }
        Ok(Forwarded::Stream(_)) => super::note_streamed(cx.route, ask),
        Err((kind, why)) => {
            tracing::debug!(
                "[cache] app={} the copy was not refreshed: {kind}{why}",
                cx.route.app_id
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::format::Times;

    fn copy(lines: &[(&str, &str)]) -> Loaded {
        Loaded {
            times: Times {
                stored_at: 1,
                fresh_until: 2,
                initial_age: 0,
                stale_window: 0,
            },
            head: StoredHead {
                status: 200,
                http10: false,
                reason: b"OK".to_vec(),
                lines: lines
                    .iter()
                    .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
                    .collect(),
            },
            body: b"body".to_vec(),
            size: 0,
        }
    }

    #[test]
    fn the_validators_are_the_etag_and_the_last_modified_of_the_copy() {
        let both = copy(&[
            ("etag", "\"v1\""),
            ("Last-Modified", "Sun, 06 Nov 1994 08:49:37 GMT"),
        ]);
        let v = Validator::of(&both).unwrap();
        assert_eq!(v.etag.as_deref(), Some(&b"\"v1\""[..]));
        assert_eq!(
            v.last_modified.as_deref(),
            Some(&b"Sun, 06 Nov 1994 08:49:37 GMT"[..])
        );
        assert!(Validator::of(&copy(&[("ETag", "W/\"x\"")])).is_some());
        assert!(Validator::of(&copy(&[("Content-Type", "text/html")])).is_none());
    }

    #[test]
    fn the_question_of_the_cache_replaces_every_condition_of_the_visitor() {
        let v = Validator::of(&copy(&[("ETag", "\"v1\"")])).unwrap();
        let mut head = RequestHeader::build("GET", b"/a", None).unwrap();
        for (k, val) in [
            ("If-None-Match", "\"other\""),
            ("If-Modified-Since", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ("If-Match", "\"m\""),
            ("If-Range", "\"r\""),
            ("Accept", "text/html"),
        ] {
            head.append_header(k, val).unwrap();
        }
        v.apply_http(&mut head);
        let got = |name: &str| head.headers.get(name).map(|v| v.as_bytes().to_vec());
        assert_eq!(got("if-none-match"), Some(b"\"v1\"".to_vec()));
        assert_eq!(got("if-modified-since"), None, "the copy has no date");
        assert_eq!((got("if-match"), got("if-range")), (None, None));
        assert_eq!(got("accept"), Some(b"text/html".to_vec()), "the rest stays");
        let mut map = Headers::new();
        map.insert(b"if-none-match".to_vec(), vec![b"\"other\"".to_vec()]);
        map.insert(b"If-Range".to_vec(), vec![b"\"r\"".to_vec()]);
        map.insert(b"Accept".to_vec(), vec![b"x".to_vec()]);
        v.apply_map(&mut map);
        assert_eq!(
            map.get(&b"If-None-Match"[..]),
            Some(&vec![b"\"v1\"".to_vec()])
        );
        assert!(map.keys().all(|k| !k.eq_ignore_ascii_case(b"if-range")));
        assert!(map.contains_key(&b"Accept"[..]));
    }

    #[test]
    fn a_304_replaces_the_headers_it_names_and_leaves_the_rest_of_the_copy() {
        let old = copy(&[
            ("Content-Type", "text/html"),
            ("Cache-Control", "max-age=10"),
            ("ETag", "\"v1\""),
            ("Vary", "Accept-Encoding"),
            ("X-Keep", "1"),
            ("Link", "</a>; rel=x"),
            ("Link", "</b>; rel=y"),
        ]);
        let mut brought = OutboundResponse::new(304);
        brought.add(b"Cache-Control", b"max-age=900");
        brought.add(b"Content-Type", b"text/plain");
        brought.add(b"Vary", b"Cookie");
        brought.add(b"Link", b"</c>; rel=z");
        brought.add(b"Date", b"Sun, 06 Nov 1994 08:49:37 GMT");
        brought.add(b"Age", b"7");
        let (head, resp) = merged(&old, &brought);
        let get = |name: &str| {
            head.lines
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
                .map(|(_, v)| String::from_utf8(v.clone()).unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(get("Cache-Control"), ["max-age=900"]);
        assert_eq!(
            get("Content-Type"),
            ["text/html"],
            "a 304 does not change the type"
        );
        assert_eq!(
            get("Vary"),
            ["Accept-Encoding"],
            "nor what the copy varies by"
        );
        assert_eq!(
            get("Link"),
            ["</c>; rel=z"],
            "every old line of a name goes"
        );
        assert_eq!(get("X-Keep"), ["1"]);
        assert_eq!(get("ETag"), ["\"v1\""]);
        assert!(get("Date").is_empty() && get("Age").is_empty());
        assert_eq!((head.status, &resp.body[..]), (200, &b"body"[..]));
        assert_eq!(
            resp.peek(b"Date"),
            Some(&b"Sun, 06 Nov 1994 08:49:37 GMT"[..])
        );
        assert_eq!(resp.peek(b"Age"), Some(&b"7"[..]));
    }

    #[test]
    fn a_cookie_on_the_304_is_in_the_answer_and_makes_it_one_that_is_not_stored() {
        let old = copy(&[("Cache-Control", "max-age=10"), ("ETag", "\"v1\"")]);
        let mut cookie = OutboundResponse::new(304);
        cookie.add(b"Set-Cookie", b"a=b");
        cookie.add(b"Set-Cookie", b"c=d");
        let (head, resp) = merged(&old, &cookie);
        let sent: Vec<_> = head
            .lines
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(b"Set-Cookie"))
            .map(|(_, v)| v.as_slice())
            .collect();
        assert_eq!(sent, [&b"a=b"[..], b"c=d"]);
        assert_eq!(resp.cookie_lines().count(), 2);
        assert!(resp.stored_lines().is_none(), "nothing is made of it");
    }

    #[test]
    fn no_conditions_removes_those_of_the_visitor_and_adds_none() {
        let mut head = RequestHeader::build("GET", b"/a", None).unwrap();
        for (k, val) in [
            ("If-None-Match", "*"),
            ("If-Modified-Since", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ("If-Match", "\"m\""),
            ("If-Unmodified-Since", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ("Accept", "text/html"),
        ] {
            head.append_header(k, val).unwrap();
        }
        NO_CONDITIONS.apply_http(&mut head);
        let names: Vec<_> = head.headers.keys().map(|k| k.as_str().to_owned()).collect();
        assert_eq!(names, ["accept"]);
        let mut map = Headers::new();
        map.insert(b"if-none-match".to_vec(), vec![b"*".to_vec()]);
        map.insert(b"If-Unmodified-Since".to_vec(), vec![b"x".to_vec()]);
        map.insert(b"Accept".to_vec(), vec![b"x".to_vec()]);
        NO_CONDITIONS.apply_map(&mut map);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&b"Accept"[..]));
    }
}
