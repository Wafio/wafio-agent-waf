//! The answer for a request that found a fresh copy: the copy's own head with an `Age`, answered
//! `304` to a request that already holds it, cut to one range of an identity copy, or sent
//! without its body for `HEAD`.

use std::sync::Arc;

use bytes::Bytes;

use crate::request::InboundRequest;
use crate::response::OutboundResponse;
use crate::static_files::{Asked, asked, parse_http_date};

use super::format::{Loaded, StoredHead};

/// The value of the first line of the stored head named `name`.
fn value<'a>(head: &'a StoredHead, name: &[u8]) -> Option<&'a [u8]> {
    head.lines
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

/// An entity tag with no `W/`, to compare weakly.
fn opaque(tag: &[u8]) -> &[u8] {
    let tag = tag.trim_ascii();
    tag.strip_prefix(b"W/").unwrap_or(tag)
}

/// Whether `If-None-Match` names the copy's tag (weak comparison) or is `*`.
fn none_match(header: &[u8], etag: Option<&[u8]>) -> bool {
    let header = header.trim_ascii();
    header == b"*"
        || etag.is_some_and(|etag| {
            header
                .split(|&c| c == b',')
                .any(|tag| opaque(tag) == opaque(etag))
        })
}

/// Whether the request already holds this copy: `If-None-Match` decides, and without it
/// `If-Modified-Since`, which counts only against a `Last-Modified` the copy has.
fn not_modified(req: &InboundRequest, head: &StoredHead) -> bool {
    let none = req.peek("If-None-Match");
    if !none.is_empty() {
        return none_match(none, value(head, b"ETag"));
    }
    let since = req.peek("If-Modified-Since");
    match (
        parse_http_date(since),
        value(head, b"Last-Modified").and_then(parse_http_date),
    ) {
        (Some(since), Some(modified)) => modified <= since,
        _ => false,
    }
}

/// Whether `If-Range` allows the range: the copy's strong tag, or exactly its `Last-Modified`.
fn if_range_holds(header: &[u8], head: &StoredHead) -> bool {
    let header = header.trim_ascii();
    if header.is_empty() {
        return true;
    }
    if header.starts_with(b"\"") {
        return value(head, b"ETag").is_some_and(|etag| etag.trim_ascii() == header);
    }
    !header.starts_with(b"W/")
        && parse_http_date(header).is_some()
        && value(head, b"Last-Modified").map(<[u8]>::trim_ascii) == Some(header)
}

/// The headers a `304` carries: the ones RFC 9110 says it must, and `Last-Modified`.
const NOT_MODIFIED_HEADERS: [&[u8]; 6] = [
    b"Cache-Control",
    b"Content-Location",
    b"ETag",
    b"Expires",
    b"Last-Modified",
    b"Vary",
];

/// What the copy has aged to at `now`: the age the upstream gave it, then the time it has been
/// here.
pub(crate) fn age(loaded: &Loaded, now: u64) -> u64 {
    u64::from(loaded.times.initial_age)
        .saturating_add(now.saturating_sub(loaded.times.stored_at))
        .min(1 << 31)
}

/// The body of the copy for an answer: moved out when nothing else holds the copy (a big one that
/// was read for this request alone), else copied (one that the memory tier keeps).
fn body_of(loaded: Arc<Loaded>) -> Vec<u8> {
    Arc::try_unwrap(loaded).map_or_else(|shared| shared.body.clone(), |own| own.body)
}

/// The answer to `req` from the copy, without `X-Cache` (the caller says what the cache did).
/// `GET` and `HEAD` only.
pub(crate) fn answer(req: &InboundRequest, loaded: Arc<Loaded>, now: u64) -> OutboundResponse {
    let aged = age(&loaded, now);
    let mut resp = if not_modified(req, &loaded.head) {
        let mut r = OutboundResponse::new(304);
        for name in NOT_MODIFIED_HEADERS {
            if let Some(v) = value(&loaded.head, name) {
                r.add(name, v);
            }
        }
        r
    } else {
        whole_or_part(req, loaded)
    };
    resp.set(b"Age", aged.to_string().as_bytes());
    resp
}

/// `200` as stored, or `206` or `416` for a `Range` of an identity copy that answered `200`.
fn whole_or_part(req: &InboundRequest, loaded: Arc<Loaded>) -> OutboundResponse {
    let head = &loaded.head;
    let range = req.peek("Range");
    let identity = value(head, b"Content-Encoding").is_none_or(|e| {
        e.trim_ascii().is_empty() || e.trim_ascii().eq_ignore_ascii_case(b"identity")
    });
    let asked = if range.is_empty()
        || req.method != b"GET"
        || head.status != 200
        || !identity
        || !if_range_holds(req.peek("If-Range"), head)
    {
        Asked::Ignored
    } else {
        asked(range, loaded.body.len() as u64)
    };
    let size = loaded.body.len() as u64;
    match asked {
        Asked::Ignored => {
            let mut r = OutboundResponse::from_stored(head.status, &head.reason, &head.lines);
            r.body = body_of(loaded).into();
            r
        }
        Asked::Unsatisfiable => {
            let mut r = OutboundResponse::new(416);
            r.set(b"Content-Range", format!("bytes */{size}").as_bytes());
            r
        }
        Asked::Part { start, len } => {
            let lines: Vec<_> = head
                .lines
                .iter()
                .filter(|(n, _)| !n.eq_ignore_ascii_case(b"Content-Range"))
                .cloned()
                .collect();
            let mut r = OutboundResponse::from_stored(206, b"", &lines);
            r.set(
                b"Content-Range",
                format!("bytes {start}-{}/{size}", start + len - 1).as_bytes(),
            );
            let (from, to) = (start as usize, (start + len) as usize);
            r.body = Bytes::copy_from_slice(&loaded.body[from..to]);
            r
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::format::Times;

    /// `answer` for a copy that the test keeps.
    fn answer(req: &InboundRequest, copy: &Loaded, now: u64) -> OutboundResponse {
        super::answer(req, Arc::new(copy.clone()), now)
    }
    use crate::response::http_date;

    const BODY: &[u8] = b"0123456789";
    const MODIFIED: u64 = 1_700_000_000;

    fn copy(status: u16, extra: &[(&str, &str)]) -> Loaded {
        let mut lines = vec![
            (b"Content-Type".to_vec(), b"text/plain".to_vec()),
            (b"ETag".to_vec(), b"\"v1\"".to_vec()),
            (b"Last-Modified".to_vec(), http_date(MODIFIED).into_bytes()),
            (b"Cache-Control".to_vec(), b"public, max-age=600".to_vec()),
            (b"Set-Thing".to_vec(), b"x".to_vec()),
        ];
        lines.extend(
            extra
                .iter()
                .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec())),
        );
        Loaded {
            times: Times {
                stored_at: 1000,
                fresh_until: 1600,
                initial_age: 5,
                stale_window: 0,
            },
            head: StoredHead {
                status,
                http10: false,
                reason: if status == 200 {
                    b"OK".to_vec()
                } else {
                    Vec::new()
                },
                lines,
            },
            body: BODY.to_vec(),
            size: 0,
        }
    }

    fn request(method: &str, head: &str) -> InboundRequest {
        InboundRequest::from_head(
            format!("{method} /a HTTP/1.1\r\nHost: a.test\r\n{head}\r\n").as_bytes(),
        )
    }

    fn wire(r: &OutboundResponse, head: bool) -> String {
        String::from_utf8(r.wire(false, head || r.status == 304, false, 0)).unwrap()
    }

    #[test]
    fn a_copy_is_sent_as_stored_with_the_age_it_has_reached() {
        let r = answer(&request("GET", ""), &copy(200, &[]), 1010);
        assert_eq!((r.status, &r.body[..]), (200, BODY));
        assert_eq!(r.peek(b"Age"), Some(&b"15"[..]), "5 given plus 10 here");
        assert_eq!(r.peek(b"Cache-Control"), Some(&b"public, max-age=600"[..]));
        assert_eq!(r.peek(b"Content-Type"), Some(&b"text/plain"[..]));
        let w = wire(&r, false);
        assert!(w.starts_with("HTTP/1.1 200 OK\r\n"), "{w}");
        assert!(
            w.contains("Content-Length: 10\r\n") && w.ends_with("0123456789"),
            "{w}"
        );
        // A clock that went back does not give a negative age.
        assert_eq!(age(&copy(200, &[]), 10), 5);
    }

    #[test]
    fn head_gets_the_headers_of_get_and_the_length_of_the_body() {
        let r = answer(&request("HEAD", ""), &copy(200, &[]), 1000);
        let w = wire(&r, true);
        assert!(w.contains("Content-Length: 10\r\n"), "{w}");
        assert!(w.ends_with("\r\n\r\n"), "{w}");
    }

    #[test]
    fn a_request_that_holds_the_copy_gets_304_with_the_headers_a_304_carries() {
        for header in [
            "If-None-Match: \"v1\"",
            "If-None-Match: W/\"v1\"",
            "If-None-Match: \"other\", \"v1\"",
            "If-None-Match: *",
        ] {
            let r = answer(
                &request("GET", &format!("{header}\r\n")),
                &copy(200, &[]),
                1000,
            );
            assert_eq!(r.status, 304, "{header}");
            assert!(r.body.is_empty());
            assert_eq!(r.peek(b"ETag"), Some(&b"\"v1\""[..]));
            assert_eq!(r.peek(b"Cache-Control"), Some(&b"public, max-age=600"[..]));
            assert_eq!(r.peek(b"Age"), Some(&b"5"[..]));
            assert_eq!(r.peek(b"Set-Thing"), None, "no other header");
            assert!(!wire(&r, true).contains("Content-Length"));
        }
        let other = answer(
            &request("GET", "If-None-Match: \"v2\"\r\n"),
            &copy(200, &[]),
            1000,
        );
        assert_eq!(other.status, 200);
        // A copy with no tag matches only `*`.
        let mut untagged = copy(200, &[]);
        untagged.head.lines.retain(|(n, _)| n != b"ETag");
        assert_eq!(
            answer(
                &request("GET", "If-None-Match: \"v1\"\r\n"),
                &untagged,
                1000
            )
            .status,
            200
        );
        assert_eq!(
            answer(&request("GET", "If-None-Match: *\r\n"), &untagged, 1000).status,
            304
        );
    }

    #[test]
    fn if_modified_since_counts_without_a_tag_header_and_only_against_a_last_modified() {
        let at = |unix: u64| format!("If-Modified-Since: {}\r\n", http_date(unix));
        let status = |head: &str, copy: &Loaded| answer(&request("GET", head), copy, 1000).status;
        assert_eq!(status(&at(MODIFIED), &copy(200, &[])), 304);
        assert_eq!(status(&at(MODIFIED + 1000), &copy(200, &[])), 304);
        assert_eq!(status(&at(MODIFIED - 1), &copy(200, &[])), 200);
        // `If-None-Match` decides alone: a tag that does not match wins over a date that would.
        let both = format!("If-None-Match: \"v2\"\r\n{}", at(MODIFIED));
        assert_eq!(status(&both, &copy(200, &[])), 200);
        // A date that does not parse, and a copy with no date, are no 304.
        assert_eq!(
            status("If-Modified-Since: yesterday\r\n", &copy(200, &[])),
            200
        );
        let mut undated = copy(200, &[]);
        undated.head.lines.retain(|(n, _)| n != b"Last-Modified");
        assert_eq!(status(&at(MODIFIED), &undated), 200);
    }

    #[test]
    fn one_range_of_an_identity_copy_is_206_with_its_part_only() {
        let get = |range: &str, copy: &Loaded| {
            answer(&request("GET", &format!("Range: {range}\r\n")), copy, 1000)
        };
        let r = get("bytes=2-4", &copy(200, &[]));
        assert_eq!((r.status, &r.body[..]), (206, &b"234"[..]));
        assert_eq!(r.peek(b"Content-Range"), Some(&b"bytes 2-4/10"[..]));
        let w = wire(&r, false);
        assert!(w.starts_with("HTTP/1.1 206 Partial Content\r\n"), "{w}");
        assert!(w.contains("Content-Length: 3\r\n"), "{w}");
        assert_eq!(&get("bytes=7-", &copy(200, &[])).body[..], b"789");
        assert_eq!(&get("bytes=-3", &copy(200, &[])).body[..], b"789");
        assert_eq!(&get("bytes=8-99", &copy(200, &[])).body[..], b"89");
        // Past the end: 416, no body. Several ranges, a unit that is not bytes and a form that
        // does not parse get the whole copy.
        let unsat = get("bytes=10-", &copy(200, &[]));
        assert_eq!(unsat.status, 416);
        assert_eq!(unsat.peek(b"Content-Range"), Some(&b"bytes */10"[..]));
        for ignored in ["bytes=0-1,3-4", "items=0-1", "bytes=x-y", "bytes=4-2"] {
            let r = get(ignored, &copy(200, &[]));
            assert_eq!((r.status, &r.body[..]), (200, BODY), "{ignored}");
        }
        // Not an identity copy, not a 200, not a GET: the range is ignored.
        let gzip = copy(200, &[("Content-Encoding", "gzip")]);
        assert_eq!(get("bytes=2-4", &gzip).status, 200);
        assert_eq!(get("bytes=2-4", &copy(404, &[])).status, 404);
        let head = answer(
            &request("HEAD", "Range: bytes=2-4\r\n"),
            &copy(200, &[]),
            1000,
        );
        assert_eq!(head.status, 200);
    }

    #[test]
    fn if_range_keeps_the_range_only_for_the_strong_tag_or_the_exact_date() {
        let ranged = |if_range: &str| {
            answer(
                &request(
                    "GET",
                    &format!("Range: bytes=2-4\r\nIf-Range: {if_range}\r\n"),
                ),
                &copy(200, &[]),
                1000,
            )
            .status
        };
        assert_eq!(ranged("\"v1\""), 206);
        assert_eq!(ranged(&http_date(MODIFIED)), 206);
        assert_eq!(ranged("\"v2\""), 200);
        assert_eq!(ranged("W/\"v1\""), 200, "a weak tag never");
        assert_eq!(ranged(&http_date(MODIFIED + 1)), 200);
        assert_eq!(ranged("not a validator"), 200);
    }

    #[test]
    fn a_304_wins_over_a_range() {
        let r = answer(
            &request("GET", "Range: bytes=2-4\r\nIf-None-Match: \"v1\"\r\n"),
            &copy(200, &[]),
            1000,
        );
        assert_eq!(r.status, 304);
    }
}
