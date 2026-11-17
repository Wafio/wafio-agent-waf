//! The request as the handlers see it: header names normalised, special headers (Host,
//! Content-Type, User-Agent, Cookie, Connection, Transfer-Encoding) held apart from the other
//! lines, the header map the analysis reads, the URI parts (request target, original path, query
//! string, decoded path, re-quoted forward target) and the lower-cased host. Pingora forwards raw
//! request-targets; every path the pipeline matches or forwards comes from here.

use wafio_domain::Headers;
use wafio_engine_rules::decode_forwarded_path;

use crate::head_parser;

/// One request head as the handlers see it.
#[derive(Clone, Debug, Default)]
pub struct InboundRequest {
    pub method: Vec<u8>,
    /// The request-target as received.
    pub request_target: Vec<u8>,
    /// The path as received (not decoded).
    pub original_path: Vec<u8>,
    /// The query string.
    pub query: Vec<u8>,
    /// The path: decoded, dot segments resolved.
    pub forward_path: Vec<u8>,
    /// `forward_path` re-quoted + `?query` (what upstreams receive).
    pub forward_request_target: Vec<u8>,
    /// The URI host, ASCII lower-cased.
    pub host: Vec<u8>,
    /// The `Host` header as the client wrote it (empty when absent).
    pub host_header_value: Vec<u8>,
    /// The header lines in arrival order (names normalised) that are not special (`Host`,
    /// `Content-Type`, `User-Agent`, `Content-Length`, `Trailer`, a `Connection: close`) or
    /// collected cookies, `Transfer-Encoding: chunked` among them unless an empty body's
    /// swap-delete removed it, then the lines of a chunked body's trailer.
    pub lines: Vec<(Vec<u8>, Vec<u8>)>,
    /// The names of the `Trailer` header (normalised).
    pub trailer: Vec<Vec<u8>>,
    /// The header map the analysis reads, built from every header, special ones included.
    pub headers: Headers,
    pub user_agent: Vec<u8>,
    pub content_type: Vec<u8>,
    /// The connection closes: the last `Connection` line is exactly `close`, or the request is
    /// not HTTP/1.1 and no `Connection` value lists `keep-alive`. It makes `peek("Connection")`
    /// answer `close` whatever the other lines say.
    pub connection_close: bool,
    /// The request line names a protocol other than `HTTP/1.1`.
    pub http10: bool,
    /// The protocol is older than HTTP/1.1: the upstream request says HTTP/1.0 too.
    pub proto_pre11: bool,
    /// The userinfo of an absolute-form target (username, password) when the username is not
    /// empty: the upstream request carries it as `Authorization: Basic`.
    pub userinfo: Option<(Vec<u8>, Vec<u8>)>,
    /// Parsed `Cookie` pairs.
    pub cookies: Vec<(Vec<u8>, Vec<u8>)>,
    /// Length of the raw head (request line + headers + CRLF).
    pub head_len: usize,
}

/// RFC 9110 tchar.
fn is_header_name_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// Canonical-Case unless a byte is not a tchar.
pub fn title_case_header_key(k: &[u8]) -> Vec<u8> {
    if k.is_empty() || !k.iter().all(|&c| is_header_name_byte(c)) {
        return k.to_vec();
    }
    let mut upper = true;
    k.iter()
        .map(|&c| {
            let c = if upper {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            upper = c == b'-';
            c
        })
        .collect()
}

/// Trims spaces (and the surrounding quotes when `skip_quotes`) off a cookie value.
fn decode_cookie_value(mut src: &[u8], skip_quotes: bool) -> Vec<u8> {
    while let [b' ', rest @ ..] = src {
        src = rest;
    }
    while let [rest @ .., b' '] = src {
        src = rest;
    }
    if skip_quotes && src.len() > 1 && src[0] == b'"' && src[src.len() - 1] == b'"' {
        src = &src[1..src.len() - 1];
    }
    src.to_vec()
}

/// Parses a `Cookie` header value into (name, value) pairs appended to `out`.
pub(crate) fn parse_cookie_header(out: &mut Vec<(Vec<u8>, Vec<u8>)>, mut b: &[u8]) {
    while !b.is_empty() {
        let (mut key, mut k, mut is_key) = (Vec::new(), 0, true);
        let mut val = None;
        for (i, &c) in b.iter().enumerate() {
            if c == b'=' && is_key {
                is_key = false;
                key = decode_cookie_value(&b[..i], false);
                k = i + 1;
            } else if c == b';' {
                if is_key {
                    key.clear();
                }
                val = Some(decode_cookie_value(&b[k..i], true));
                let j = if b.get(i + 1) == Some(&b' ') {
                    i + 2
                } else {
                    i + 1
                };
                b = &b[j..];
                break;
            }
        }
        let val = match val {
            Some(v) => v,
            None => {
                if is_key {
                    key.clear();
                }
                let v = decode_cookie_value(&b[k..], true);
                b = &[];
                v
            }
        };
        if (!key.is_empty() || !val.is_empty())
            && !val.iter().any(|c| matches!(c, b'"' | b';' | b'\\'))
        {
            out.push((key, val));
        }
    }
}

/// Joins cookie pairs as a `Cookie` header value (`name=value; ...`).
fn push_cookie_pair(cookies: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut dst = Vec::new();
    for (i, (k, v)) in cookies.iter().enumerate() {
        if !k.is_empty() {
            dst.extend_from_slice(k);
            dst.push(b'=');
        }
        dst.extend_from_slice(v);
        if i + 1 < cookies.len() {
            dst.extend_from_slice(b"; ");
        }
    }
    dst
}

/// Path bytes that stay as they are when the path is re-quoted.
fn path_byte_unescaped(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"$&+,-./:;=@_~".contains(&c)
}

/// Appends `src` as a re-quoted path: bytes outside the kept set become `%XX`, `*` stays.
pub fn push_escaped_path(dst: &mut Vec<u8>, src: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    if src == b"*" {
        dst.push(b'*');
        return;
    }
    for &c in src {
        if path_byte_unescaped(c) {
            dst.push(c);
        } else {
            dst.extend_from_slice(&[b'%', HEX[(c >> 4) as usize], HEX[(c & 15) as usize]]);
        }
    }
}

/// Removes every line named `key` by swapping it with the last one, so each delete reorders the
/// lines that follow it (two lines of one name come out the other way round).
pub(crate) fn remove_all_lines_named(h: &mut Vec<(Vec<u8>, Vec<u8>)>, key: &[u8]) {
    let mut n = h.len();
    let mut i = 0;
    while i < n {
        if h[i].0 == key {
            h.swap(i, n - 1);
            n -= 1;
        } else {
            i += 1;
        }
    }
    h.truncate(n);
}

/// The path and query of the URI the handler sees: `uri` is the request-target with an
/// absolute-form scheme and authority already taken off.
fn split_path_query(uri: &[u8]) -> (&[u8], &[u8]) {
    let q = uri.iter().position(|&c| c == b'?');
    let f = uri.iter().position(|&c| c == b'#');
    match (q, f) {
        (Some(q), Some(f)) if q > f => (&uri[..f], &[]),
        (Some(q), f) => (&uri[..q], &uri[q + 1..f.unwrap_or(uri.len())]),
        (None, Some(f)) => (&uri[..f], &[]),
        (None, None) => (uri, &[]),
    }
}

impl InboundRequest {
    /// Parses a complete raw head (request line + headers); a head that does not parse gives an
    /// empty request. The proxy itself calls [`InboundRequest::from_parsed`] with what it already
    /// parsed.
    pub fn from_head(raw: &[u8]) -> InboundRequest {
        let Ok(head) = head_parser::parse_head(raw) else {
            return InboundRequest::default();
        };
        let Ok(parts) = head_parser::uri_parts(&head.host, &head.request_target) else {
            return InboundRequest::default();
        };
        InboundRequest::from_parsed(&head, parts, &[], true)
    }

    /// The request as the handler sees it: `head` from [`head_parser::parse_head`], the host, the
    /// target without an absolute-form scheme and authority and the userinfo from
    /// [`head_parser::uri_parts`], the trailers a chunked body carried and whether the body came
    /// out empty (that sets the length).
    pub fn from_parsed(
        head: &head_parser::Head,
        parts: head_parser::UriParts,
        trailers: &[(Vec<u8>, Vec<u8>)],
        body_empty: bool,
    ) -> InboundRequest {
        let head_parser::UriParts { host, uri, user } = parts;
        let uri = uri.as_slice();
        let mut req = InboundRequest {
            head_len: head.len,
            method: head.method.clone(),
            request_target: head.request_target.clone(),
            http10: head.http10,
            proto_pre11: head.proto_pre11,
            host_header_value: head.host.clone(),
            trailer: head.trailer.clone(),
            userinfo: user.filter(|(u, _)| !u.is_empty()),
            host,
            ..Default::default()
        };
        let mut h = Vec::new();
        for (key, value) in &head.lines {
            match key.to_ascii_lowercase().as_slice() {
                b"content-type" => req.content_type = value.clone(),
                b"user-agent" => req.user_agent = value.clone(),
                b"host" | b"content-length" => {}
                b"connection" if value == b"close" => {}
                _ => h.push((key.clone(), value.clone())),
            }
        }
        // After the body read: a bodyless request that is not GET/HEAD and an empty chunked body get
        // `Content-Length: 0`, and the latter loses its `Transfer-Encoding` line (swap-deleted).
        let mut content_length = head.content_length_bytes.clone();
        match head.content_length {
            -2 if !(head.method == b"GET" || head.method == b"HEAD") => {
                content_length = Some(b"0".to_vec());
            }
            -1 if body_empty => {
                content_length = Some(b"0".to_vec());
                remove_all_lines_named(&mut h, b"Transfer-Encoding");
            }
            _ => {}
        }
        h.extend(trailers.iter().cloned());
        // The Cookie lines leave the lines for the cookie list, in line order.
        h.retain(|(k, v)| {
            let cookie = k.eq_ignore_ascii_case(b"cookie");
            if cookie {
                parse_cookie_header(&mut req.cookies, v);
            }
            !cookie
        });
        req.lines = h;
        req.connection_close = head.connection_close;
        let (path_original, query) = split_path_query(uri);
        req.original_path = path_original.to_vec();
        req.query = query.to_vec();
        req.forward_path = decode_forwarded_path(&req.request_target).0;
        push_escaped_path(&mut req.forward_request_target, &req.forward_path);
        if !req.query.is_empty() {
            req.forward_request_target.push(b'?');
            req.forward_request_target.extend_from_slice(&req.query);
        }
        // The header map: the Host header as written (not the URI host), Content-Length,
        // Content-Type, User-Agent, Trailer, Cookie, the other lines in order (every non-close
        // Connection line, Transfer-Encoding, the body's trailer lines), then Connection: close
        // when the flag is set.
        let h = &mut req.headers;
        let mut put = |k: &[u8], v: Vec<u8>| h.entry(k.to_vec()).or_default().push(v);
        if !req.host_header_value.is_empty() {
            put(b"Host", req.host_header_value.clone());
        }
        if let Some(cl) = content_length.filter(|c| !c.is_empty()) {
            put(b"Content-Length", cl);
        }
        if !req.content_type.is_empty() {
            put(b"Content-Type", req.content_type.clone());
        }
        if !req.user_agent.is_empty() {
            put(b"User-Agent", req.user_agent.clone());
        }
        if !req.trailer.is_empty() {
            put(b"Trailer", req.trailer.join(&b", "[..]));
        }
        if !req.cookies.is_empty() {
            put(b"Cookie", push_cookie_pair(&req.cookies));
        }
        for (k, v) in &req.lines {
            put(k, v.clone());
        }
        if req.connection_close {
            put(b"Connection", b"close".to_vec());
        }
        req
    }

    /// The special value, else the first line with that name. `Host` is the header as written,
    /// `Connection` is `close` when the close flag is set and otherwise the first line that is
    /// not `close` (a `close` line is kept as the flag, not as a line).
    pub fn peek(&self, name: &str) -> &[u8] {
        match name.to_ascii_lowercase().as_str() {
            "host" => &self.host_header_value,
            "content-type" => &self.content_type,
            "user-agent" => &self.user_agent,
            "connection" if self.connection_close => b"close",
            "connection" => self
                .lines
                .iter()
                .find(|(k, v)| k.eq_ignore_ascii_case(b"connection") && v != b"close")
                .map_or(&[][..], |(_, v)| v.as_slice()),
            _ => self
                .lines
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name.as_bytes()))
                .map_or(&[][..], |(_, v)| v.as_slice()),
        }
    }

    /// The value of the first cookie named `name`.
    pub fn cookie(&self, name: &[u8]) -> &[u8] {
        self.cookies
            .iter()
            .find(|(k, _)| k == name)
            .map_or(&[][..], |(_, v)| v.as_slice())
    }

    pub fn is_get_method(&self) -> bool {
        self.method == b"GET"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_keys_are_normalised() {
        assert_eq!(
            title_case_header_key(b"x-forwarded-FOR"),
            b"X-Forwarded-For"
        );
        assert_eq!(title_case_header_key(b"content-type"), b"Content-Type");
        assert_eq!(title_case_header_key(b"x_y"), b"X_y");
        assert_eq!(title_case_header_key(b"bad key"), b"bad key");
    }

    #[test]
    fn head_parts() {
        let r = InboundRequest::from_head(
            b"GET /a/../b%2Fc%20d/./e?x=1&y=%41#frag HTTP/1.1\r\nHost: App.Test:8080\r\nuser-agent: ua\r\ncookie: a=1; b=\"2\"\r\nCookie: c\r\nx-a: 1\r\nX-A: 2\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert_eq!(r.method, b"GET");
        assert_eq!(r.original_path, b"/a/../b%2Fc%20d/./e");
        assert_eq!(r.query, b"x=1&y=%41");
        assert_eq!(r.forward_path, b"/b/c d/e");
        assert_eq!(r.forward_request_target, b"/b/c%20d/e?x=1&y=%41");
        assert_eq!(r.host, b"app.test:8080");
        assert_eq!(r.headers[&b"Cookie"[..]], vec![b"a=1; b=2; c".to_vec()]);
        assert_eq!(r.headers[&b"X-A"[..]], vec![b"1".to_vec(), b"2".to_vec()]);
        assert_eq!(r.headers[&b"Connection"[..]], vec![b"keep-alive".to_vec()]);
        // A head parsed without its body is an empty body: the chunked line is swap-deleted and the
        // length is 0.
        assert!(!r.headers.contains_key(&b"Transfer-Encoding"[..]));
        assert_eq!(r.headers[&b"Content-Length"[..]], vec![b"0".to_vec()]);
        assert_eq!(r.cookie(b"b"), b"2");
        assert_eq!(r.peek("X-A"), b"1");
    }

    /// The header map holds the `Host` header as written, not the URI host: an absolute-form
    /// target does not validate it, so a payload in it must reach the analysed headers.
    #[test]
    fn host_header_is_the_one_the_client_wrote() {
        let r = InboundRequest::from_head(
            b"GET http://App.Test/p HTTP/1.1\r\nHost: 1' UNION SELECT password FROM users--\r\n\r\n",
        );
        assert_eq!(r.host, b"app.test");
        assert_eq!(
            r.headers[&b"Host"[..]],
            vec![b"1' UNION SELECT password FROM users--".to_vec()]
        );
        assert_eq!(r.peek("host"), b"1' UNION SELECT password FROM users--");
        // Origin form: the URI host is lower-cased, the header keeps its case.
        let r = InboundRequest::from_head(b"GET /p HTTP/1.1\r\nHost: App.Test:8080\r\n\r\n");
        assert_eq!(r.host, b"app.test:8080");
        assert_eq!(r.headers[&b"Host"[..]], vec![b"App.Test:8080".to_vec()]);
        // No Host header at all: no entry, even though the target names a host.
        let r = InboundRequest::from_head(b"GET http://App.Test/p HTTP/1.0\r\n\r\n");
        assert_eq!(r.host, b"app.test");
        assert!(!r.headers.contains_key(&b"Host"[..]));
    }

    /// Every non-close `Connection` line is kept, `peek("Connection")` answers `close` when the
    /// close flag is set and the first kept line otherwise, and the header map lists the lines in
    /// order and then `Connection: close` for the flag.
    #[test]
    fn connection_lines_and_close_flag() {
        let head = |lines: &str, proto: &str| {
            InboundRequest::from_head(
                format!("GET /p {proto}\r\nHost: a\r\n{lines}\r\n").as_bytes(),
            )
        };
        let r = head("Connection: X-A\r\nConnection: X-B\r\n", "HTTP/1.1");
        assert!(!r.connection_close);
        assert_eq!(r.peek("Connection"), b"X-A");
        assert_eq!(
            r.headers[&b"Connection"[..]],
            vec![b"X-A".to_vec(), b"X-B".to_vec()]
        );
        let r = head("Connection: X-A\r\nConnection: close\r\n", "HTTP/1.1");
        assert!(r.connection_close);
        assert_eq!(r.peek("Connection"), b"close");
        assert_eq!(
            r.headers[&b"Connection"[..]],
            vec![b"X-A".to_vec(), b"close".to_vec()]
        );
        // A later non-close line clears the flag; the `close` line is not kept.
        let r = head("Connection: close\r\nConnection: X-B\r\n", "HTTP/1.1");
        assert!(!r.connection_close);
        assert_eq!(r.peek("Connection"), b"X-B");
        assert_eq!(r.headers[&b"Connection"[..]], vec![b"X-B".to_vec()]);
        // A request that is not HTTP/1.1 closes unless a value lists keep-alive: the flag, so
        // `peek` and the header map say `close` whatever the lines name.
        let r = head("Connection: X-A\r\n", "HTTP/1.0");
        assert!(r.connection_close);
        assert_eq!(r.peek("Connection"), b"close");
        assert_eq!(
            r.headers[&b"Connection"[..]],
            vec![b"X-A".to_vec(), b"close".to_vec()]
        );
        let r = head("Connection: keep-alive, X-A\r\n", "HTTP/1.0");
        assert!(!r.connection_close);
        assert_eq!(r.peek("Connection"), b"keep-alive, X-A");
    }

    /// The request after the body read, as the header map shows it.
    fn read(raw: &str, trailers: &[(&str, &str)], body_empty: bool) -> InboundRequest {
        let head = head_parser::parse_head(raw.as_bytes()).unwrap();
        let parts = head_parser::uri_parts(&head.host, &head.request_target).unwrap();
        let trailers: Vec<_> = trailers
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect();
        InboundRequest::from_parsed(&head, parts, &trailers, body_empty)
    }

    fn values(r: &InboundRequest, name: &str) -> Vec<String> {
        r.headers
            .get(name.as_bytes())
            .map(|v| {
                v.iter()
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The header lines after the body read: `Transfer-Encoding: chunked` stays, lower-cased, at
    /// its line's place; an empty chunked body has it swap-deleted (the lines behind it change
    /// places, the cookies are collected after that) and a request without any length that is not
    /// GET/HEAD gets `Content-Length: 0` too; the body's trailer lines come last.
    #[test]
    fn header_lines_after_the_body_read() {
        let post = |tail: &str| format!("POST /p HTTP/1.1\r\nHost: a\r\n{tail}\r\n");
        let r = read(
            &post("Transfer-Encoding: CHUNKED\r\nX-A: 1\r\nX-A: 2\r\nX-A: 3\r\n"),
            &[("X-Tr", "t")],
            false,
        );
        assert_eq!(values(&r, "Transfer-Encoding"), ["chunked"]);
        assert!(values(&r, "Content-Length").is_empty());
        assert_eq!(values(&r, "X-A"), ["1", "2", "3"]);
        assert_eq!(values(&r, "X-Tr"), ["t"]);
        assert_eq!(
            r.lines[0],
            (b"Transfer-Encoding".to_vec(), b"chunked".to_vec())
        );
        // Empty: the swap-delete puts the last line in the Transfer-Encoding line's place: 3, 1, 2.
        let r = read(
            &post("Transfer-Encoding: chunked\r\nX-A: 1\r\nX-A: 2\r\nX-A: 3\r\n"),
            &[("X-Tr", "t")],
            true,
        );
        assert!(values(&r, "Transfer-Encoding").is_empty());
        assert_eq!(values(&r, "Content-Length"), ["0"]);
        assert_eq!(values(&r, "X-A"), ["3", "1", "2"]);
        // Host and the other special headers are not in the lines: the line before Host does not move.
        let r = read(
            "POST /p HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\nX-A: 2\r\nUser-Agent: u\r\nHost: a\r\n\r\n",
            &[],
            true,
        );
        assert_eq!(values(&r, "X-A"), ["2", "1"]);
        // Cookie lines stay in the lines until the cookies are collected, after the swap: c, a, b.
        let r = read(
            &post(
                "Transfer-Encoding: chunked\r\nCookie: a=1\r\nX-A: v\r\nCookie: b=2\r\nCookie: c=3\r\n",
            ),
            &[],
            true,
        );
        assert_eq!(values(&r, "Cookie"), ["c=3; a=1; b=2"]);
        assert_eq!(values(&r, "X-A"), ["v"]);
        // No length: POST gets 0, GET (and HEAD) nothing; a chunked empty GET gets 0.
        assert_eq!(values(&read(&post(""), &[], true), "Content-Length"), ["0"]);
        let get = |tail: &str| format!("GET /p HTTP/1.1\r\nHost: a\r\n{tail}\r\n");
        assert!(values(&read(&get(""), &[], true), "Content-Length").is_empty());
        let r = read(&get("Transfer-Encoding: chunked\r\n"), &[], true);
        assert_eq!(values(&r, "Content-Length"), ["0"]);
        // A declared length is kept as written; `identity` is not a line.
        let r = read(&get("Content-Length: 00\r\n"), &[], true);
        assert_eq!(values(&r, "Content-Length"), ["00"]);
        let r = read(&post("Transfer-Encoding: identity\r\n"), &[], true);
        assert!(values(&r, "Transfer-Encoding").is_empty());
        assert_eq!(values(&r, "Content-Length"), ["0"]);
    }

    /// `Trailer` is held in `trailer`, not as a line: names normalised and joined with `, `, the
    /// last line wins, the header map holds it once.
    #[test]
    fn the_trailer_header_is_not_a_line() {
        let r = read(
            "POST /p HTTP/1.1\r\nHost: a\r\nTrailer: C, ontent-Length\r\nX-A: 1\r\nTrailer: x-a, X-B\r\n\r\n",
            &[],
            true,
        );
        assert_eq!(r.trailer, [b"X-A".to_vec(), b"X-B".to_vec()]);
        assert_eq!(values(&r, "Trailer"), ["X-A, X-B"]);
        assert!(r.lines.iter().all(|(k, _)| k != b"Trailer"));
        let r = read(
            "GET /p HTTP/1.1\r\nHost: a\r\nTrailer: C, ontent-Length\r\n\r\n",
            &[],
            true,
        );
        assert_eq!(values(&r, "Trailer"), ["C, Ontent-Length"]);
    }

    #[test]
    fn absolute_form_and_quoting() {
        let r = InboundRequest::from_head(b"GET http://Other.Host/p?q HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(r.host, b"other.host");
        assert_eq!(r.original_path, b"/p");
        let mut q = Vec::new();
        push_escaped_path(&mut q, b"/a b'(*)!?#\"\xff");
        assert_eq!(q, b"/a%20b%27%28%2A%29%21%3F%23%22%FF");
    }
}
