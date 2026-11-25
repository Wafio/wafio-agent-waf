//! An outbound response (special headers, `add`/`set`/`del` semantics, the server's defaults) and
//! its writing to a Pingora session.

use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::protocols::http::ServerSession;
use wafio_agent_pages::challenge_handler::PageResponse;

use crate::request::title_case_header_key;

/// The `Server` header value when the response has none.
pub const SERVER_HEADER_VALUE: &str = "wafio-route-proxy";
/// The content type used when none is set.
const FALLBACK_CONTENT_TYPE: &[u8] = b"text/plain; charset=utf-8";

#[derive(Clone, Debug, Default)]
pub struct OutboundResponse {
    pub status: u16,
    content_type: Option<Vec<u8>>,
    content_encoding: Option<Vec<u8>>,
    server: Option<Vec<u8>>,
    header_lines: Vec<(Vec<u8>, Vec<u8>)>,
    cookies: Vec<Vec<u8>>,
    /// `Connection: close`.
    pub close: bool,
    /// The status line says `HTTP/1.0` (an upstream that answered HTTP/1.0: the response protocol
    /// is copied).
    pub http10: bool,
    /// The `Content-Length` as parsed from an upstream response, as a number and as written
    /// (`None`: built here, nothing set until it is written). Kept for the statuses and HEAD
    /// answers whose `Content-Length` is never recomputed from the body. The text is a boxed slice
    /// to keep the response below the size clippy accepts for the enums that hold it by value.
    declared_length: Option<(i64, Box<[u8]>)>,
    /// The status message of an upstream answer: written back as the upstream said it, the
    /// standard text only when it said none.
    reason: Option<Vec<u8>>,
    /// The body follows as chunks (a streamed answer to an HTTP/1.1 client), so `wire` writes
    /// `Transfer-Encoding: chunked`.
    pub chunked: bool,
    /// Shared, so the response cache keeps a copy while the answer goes out without copying it.
    pub body: Bytes,
}

/// 1xx, 204 and 304 carry no body: their `Content-Length` is never set from the body.
fn skips_content_length(status: u16) -> bool {
    status != 200 && (status == 204 || status == 304 || (100..200).contains(&status))
}

/// Whether a comma-separated token equals `want` (ASCII case-insensitive).
fn list_contains_token(v: &[u8], want: &[u8]) -> bool {
    v.split(|&c| c == b',')
        .any(|t| t.trim_ascii().eq_ignore_ascii_case(want))
}

impl OutboundResponse {
    pub fn new(status: u16) -> OutboundResponse {
        OutboundResponse {
            status,
            ..Default::default()
        }
    }

    /// A response with a status, content type and body.
    pub fn with(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> OutboundResponse {
        let mut r = OutboundResponse::new(status);
        r.content_type = Some(content_type.as_bytes().to_vec());
        r.body = Bytes::from(body.into());
        r
    }

    /// Keeps the upstream's status message as raw bytes (obs-text and invalid UTF-8 included); an
    /// empty one is not kept.
    pub fn with_reason<R: AsRef<[u8]>>(mut self, reason: Option<R>) -> OutboundResponse {
        self.reason = reason
            .filter(|r| !r.as_ref().is_empty())
            .map(|r| r.as_ref().to_vec());
        self
    }

    /// A plain-text error response.
    pub fn error(status: u16, msg: &str) -> OutboundResponse {
        OutboundResponse::with(status, "text/plain; charset=utf-8", msg)
    }

    /// An upstream response as it is kept for the client: status, protocol, the lines (special
    /// headers through [`OutboundResponse::add`]), the `Content-Length` it declared, and the
    /// connection state (`Connection: close`, a close-delimited body, an HTTP/1.0 answer without
    /// `Connection: keep-alive`).
    pub fn from_upstream<'a>(
        status: u16,
        http10: bool,
        headers: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    ) -> OutboundResponse {
        let mut r = OutboundResponse::new(status);
        r.http10 = http10;
        let (mut len, mut bytes) = (-2i64, Vec::new());
        for (k, v) in headers {
            if k.eq_ignore_ascii_case(b"content-length") {
                if len != -1 && !v.is_empty() && v.iter().all(u8::is_ascii_digit) {
                    len = std::str::from_utf8(v)
                        .ok()
                        .and_then(|d| d.parse().ok())
                        .unwrap_or(i64::MAX);
                    bytes = v.to_vec();
                }
            } else if k.eq_ignore_ascii_case(b"transfer-encoding")
                && !http10
                && v.eq_ignore_ascii_case(b"chunked")
            {
                len = -1;
            }
            r.add(k, v);
        }
        if len < 0 {
            bytes.clear();
        }
        let connection = r
            .header_lines
            .iter()
            .find(|(n, _)| n.as_slice() == b"Connection")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        if len == -2
            && !list_contains_token(&connection, b"upgrade")
            && !skips_content_length(status)
        {
            r.close = true;
        }
        if http10 && !r.close {
            r.close = !list_contains_token(&connection, b"keep-alive");
        }
        r.declared_length = Some((len, bytes.into_boxed_slice()));
        r
    }

    /// The length a body-less answer announces: a `HEAD` answer, or one whose body is sent from a
    /// file after the head.
    pub(crate) fn declare_length(&mut self, len: u64) {
        self.declared_length = Some((
            i64::try_from(len).unwrap_or(i64::MAX),
            len.to_string().into_bytes().into_boxed_slice(),
        ));
    }

    /// Whether the body has no length up front (chunked, or ended by the upstream closing), which
    /// is the only kind that may never end.
    pub fn body_unframed(&self) -> bool {
        !skips_content_length(self.status) && matches!(self.declared_length, Some((n, _)) if n < 0)
    }

    /// Whether the upstream sent the body chunked.
    pub fn upstream_chunked(&self) -> bool {
        matches!(self.declared_length, Some((-1, _)))
    }

    /// An answer as it was stored: status, status message and header lines (the specials among
    /// them go through [`OutboundResponse::add`]). Nothing of the connection is kept, so it is
    /// sent as built here: the length is the body's.
    pub(crate) fn from_stored(
        status: u16,
        reason: &[u8],
        lines: &[(Vec<u8>, Vec<u8>)],
    ) -> OutboundResponse {
        let mut r = OutboundResponse::new(status).with_reason(Some(reason));
        for (name, value) in lines {
            r.add(name, value);
        }
        r
    }

    /// The status message this answer was given by its upstream; empty when it has none.
    pub(crate) fn reason(&self) -> &[u8] {
        self.reason.as_deref().unwrap_or_default()
    }

    /// The header lines to store with the answer: what the upstream said, without what belongs to
    /// the connection (`Connection` and the headers it names, `Keep-Alive`, `Proxy-*`, `TE`,
    /// `Trailer`, `Upgrade`), the length it sent and what is made again for each answer: `Date`,
    /// `Age`, `X-Cache`. `None` when the answer carries a cookie, which is never stored.
    pub(crate) fn stored_lines(&self) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
        self.cookies.is_empty().then(|| self.plain_lines())
    }

    /// [`OutboundResponse::stored_lines`] without the check for a cookie, for an answer that is
    /// made from a copy and is not stored.
    pub(crate) fn plain_lines(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let named: Vec<Vec<u8>> = self
            .values(b"Connection")
            .flat_map(|v| v.split(|&c| c == b','))
            .map(|n| n.trim_ascii().to_ascii_lowercase())
            .collect();
        let own = |name: &[u8]| {
            matches!(
                name.to_ascii_lowercase().as_slice(),
                b"connection"
                    | b"keep-alive"
                    | b"proxy-authenticate"
                    | b"proxy-authorization"
                    | b"te"
                    | b"trailer"
                    | b"transfer-encoding"
                    | b"upgrade"
                    | b"date"
                    | b"age"
                    | b"x-cache"
            ) || named.contains(&name.to_ascii_lowercase())
        };
        let mut lines = Vec::new();
        if let Some(server) = &self.server {
            lines.push((b"Server".to_vec(), server.clone()));
        }
        if let Some(ct) = &self.content_type {
            lines.push((b"Content-Type".to_vec(), ct.clone()));
        }
        if let Some(ce) = &self.content_encoding {
            lines.push((b"Content-Encoding".to_vec(), ce.clone()));
        }
        lines.extend(self.header_lines.iter().filter(|(n, _)| !own(n)).cloned());
        lines
    }

    /// The `Set-Cookie` lines of the answer.
    pub(crate) fn cookie_lines(&self) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> + '_ {
        self.cookies
            .iter()
            .map(|value| (b"Set-Cookie".to_vec(), value.clone()))
    }

    /// A challenge-handler page.
    pub fn from_page(p: PageResponse) -> OutboundResponse {
        let mut r = OutboundResponse::new(p.status);
        r.content_type = p.content_type.map(|c| c.as_bytes().to_vec());
        for (k, v) in p.headers {
            r.set(k.as_bytes(), &v);
        }
        if let Some(c) = p.set_cookie {
            r.cookies.push(c);
        }
        r.body = p.body.into();
        r
    }

    /// The content type (the default when unset).
    pub fn content_type(&self) -> &[u8] {
        self.content_type
            .as_deref()
            .unwrap_or(FALLBACK_CONTENT_TYPE)
    }

    pub fn assign_content_type(&mut self, ct: &[u8]) {
        self.content_type = Some(ct.to_vec());
    }

    /// The value of header `k`, if set.
    pub fn peek(&self, k: &[u8]) -> Option<&[u8]> {
        let k = title_case_header_key(k);
        match k.as_slice() {
            b"Content-Type" => Some(self.content_type()),
            b"Server" => self.server.as_deref(),
            b"Content-Encoding" => self.content_encoding.as_deref(),
            _ => self
                .header_lines
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.as_slice()),
        }
    }

    /// The values of every header line named `k` (not the special headers), in order.
    pub(crate) fn values<'a>(&'a self, k: &[u8]) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        let k = title_case_header_key(k);
        self.header_lines
            .iter()
            .filter(move |(n, _)| *n == k)
            .map(|(_, v)| v.as_slice())
    }

    /// Handles the special response headers; true when handled.
    fn special(&mut self, k: &[u8], v: &[u8], add: bool) -> bool {
        match k {
            b"Content-Type" => self.content_type = Some(v.to_vec()),
            b"Content-Encoding" => self.content_encoding = Some(v.to_vec()),
            b"Server" => self.server = Some(v.to_vec()),
            b"Content-Length" | b"Transfer-Encoding" => {}
            b"Set-Cookie" => {
                if !add {
                    self.cookies.clear();
                }
                self.cookies.push(v.to_vec());
            }
            b"Connection" if v == b"close" => self.close = true,
            b"Connection" => {
                self.close = false;
                return false;
            }
            _ => return false,
        }
        true
    }

    pub fn add(&mut self, k: &[u8], v: &[u8]) {
        let k = title_case_header_key(k);
        if !self.special(&k, v, true) {
            self.header_lines.push((k, v.to_vec()));
        }
    }

    /// Replaces the first line of that name.
    pub fn set(&mut self, k: &[u8], v: &[u8]) {
        let k = title_case_header_key(k);
        if self.special(&k, v, false) {
            return;
        }
        match self.header_lines.iter_mut().find(|(n, _)| *n == k) {
            Some(kv) => kv.1 = v.to_vec(),
            None => self.header_lines.push((k, v.to_vec())),
        }
    }

    pub fn del(&mut self, k: &[u8]) {
        let k = title_case_header_key(k);
        match k.as_slice() {
            b"Content-Type" => self.content_type = None,
            b"Content-Encoding" => self.content_encoding = None,
            b"Server" => self.server = None,
            b"Set-Cookie" => self.cookies.clear(),
            b"Connection" => self.close = false,
            _ => {}
        }
        self.header_lines.retain(|(n, _)| *n != k);
    }

    /// The header block in the server's order, with the server's defaults: `Server`,
    /// `Content-Type` (default `text/plain; charset=utf-8` for a non-empty body),
    /// `Content-Encoding`, `Content-Length`, the rest, `Set-Cookie`. Pingora adds `Date` and
    /// `Connection` (used for the `Connection: close` answers only, see [`write`]).
    pub fn header(&self) -> pingora::Result<ResponseHeader> {
        let mut h = ResponseHeader::build(self.status, Some(self.header_lines.len() + 6))?;
        h.append_header(
            "Server",
            self.server
                .as_deref()
                .unwrap_or(SERVER_HEADER_VALUE.as_bytes()),
        )?;
        if !self.body.is_empty() || self.content_type.is_some() {
            h.append_header("Content-Type", self.content_type())?;
        }
        if let Some(ce) = &self.content_encoding {
            h.append_header("Content-Encoding", ce.as_slice())?;
        }
        h.append_header("Content-Length", self.body.len().to_string())?;
        for (k, v) in &self.header_lines {
            if k.as_slice() == b"Date" {
                continue;
            }
            // shortcut: a name or value http refuses is dropped.
            let _ = h.append_header(String::from_utf8_lossy(k).into_owned(), v.as_slice());
        }
        for c in &self.cookies {
            h.append_header("Set-Cookie", c.as_slice())?;
        }
        Ok(h)
    }
}

impl OutboundResponse {
    /// The response as written to the wire: the header block, then the body.
    /// `req_http10`: the request was not HTTP/1.1, so an answer that keeps the connection gets
    /// `Connection: keep-alive` among the lines. `close`: the connection ends with this answer (the
    /// response's own `Connection: close`, a request that asked for it, an HTTP/1.0 request without
    /// keep-alive, a draining server): `Connection: close` is the last line. `no_body` (HEAD, 1xx,
    /// 204, 304) writes the header block only. Pingora's own writer cannot do this: it adds
    /// `Connection` to every response (`prepare_response_header`) and puts `Date` after the other
    /// lines.
    pub fn wire(&self, req_http10: bool, no_body: bool, close: bool, now_unix: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        let proto = if self.http10 { "HTTP/1.0" } else { "HTTP/1.1" };
        out.extend_from_slice(format!("{proto} {} ", self.status).as_bytes());
        out.extend_from_slice(
            self.reason
                .as_deref()
                .unwrap_or(reason_phrase(self.status).as_bytes()),
        );
        out.extend_from_slice(b"\r\n");
        let mut line = |k: &[u8], v: &[u8]| {
            out.extend_from_slice(k);
            out.extend_from_slice(b": ");
            // A CR or LF in a value becomes a space.
            out.extend(
                v.iter()
                    .map(|&c| if c == b'\r' || c == b'\n' { b' ' } else { c }),
            );
            out.extend_from_slice(b"\r\n");
        };
        // The length is the body's unless the status takes none (then the upstream's value stays, a
        // HEAD answer included) or a HEAD answer has no body to count.
        let (len, len_bytes) =
            if !skips_content_length(self.status) && (!no_body || !self.body.is_empty()) {
                (
                    self.body.len() as i64,
                    self.body.len().to_string().into_bytes().into_boxed_slice(),
                )
            } else {
                self.declared_length.clone().unwrap_or_default()
            };
        line(
            b"Server",
            self.server
                .as_deref()
                .unwrap_or(SERVER_HEADER_VALUE.as_bytes()),
        );
        line(b"Date", http_date(now_unix).as_bytes());
        if (len != 0 || self.content_type.is_some()) && !self.content_type().is_empty() {
            line(b"Content-Type", self.content_type());
        }
        if let Some(ce) = &self.content_encoding {
            line(b"Content-Encoding", ce);
        }
        if !len_bytes.is_empty() {
            line(b"Content-Length", &len_bytes);
        }
        if self.chunked {
            line(b"Transfer-Encoding", b"chunked");
        }
        let mut keep_alive = req_http10 && !close;
        for (k, v) in &self.header_lines {
            if keep_alive && k.as_slice() == b"Connection" {
                // The first Connection line is replaced in place.
                line(k, b"keep-alive");
                keep_alive = false;
            // shortcut: a name that is not an HTTP token is dropped.
            } else if k.as_slice() != b"Date"
                && !k.is_empty()
                && k.iter().all(|&c| c.is_ascii_graphic() && c != b':')
            {
                line(k, v);
            }
        }
        if keep_alive {
            line(b"Connection", b"keep-alive");
        }
        for c in &self.cookies {
            line(b"Set-Cookie", c);
        }
        if close {
            line(b"Connection", b"close");
        }
        out.extend_from_slice(b"\r\n");
        if !no_body {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

/// The standard reason phrase of a status code.
fn reason_phrase(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "Unknown Status Code",
    }
}

/// An HTTP date such as `Mon, 02 Jan 2006 15:04:05 GMT`.
pub(crate) fn http_date(unix: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (days, rem) = (unix / 86_400, unix % 86_400);
    // Civil date from the day count.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[month as usize - 1],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Writes `r` through Pingora's writer and finishes the body: the `Connection: close` answers
/// (it writes `close`). Keep-alive answers go through [`OutboundResponse::wire`].
pub async fn write(s: &mut ServerSession, r: OutboundResponse) -> pingora::Result<()> {
    if r.close {
        s.set_keepalive(None);
    }
    let h = r.header()?;
    s.write_response_header(Box::new(h)).await?;
    if !r.body.is_empty() {
        s.write_response_body(r.body, true).await?;
    }
    s.finish_body().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_answer_comes_back_with_its_message_and_its_lines_and_sheds_what_belongs_to_the_connection()
     {
        let upstream = |headers: &[(&'static str, &'static str)]| {
            let mut r = OutboundResponse::from_upstream(
                404,
                false,
                headers.iter().map(|(k, v)| (k.as_bytes(), v.as_bytes())),
            )
            .with_reason(Some("Gone Missing"));
            r.body = Bytes::from_static(b"nothing here");
            r
        };
        let r = upstream(&[
            ("Content-Type", "text/plain"),
            ("Content-Length", "12"),
            ("Server", "origin"),
            ("Content-Encoding", "gzip"),
            ("Connection", "keep-alive, X-Hop"),
            ("X-Hop", "1"),
            ("Keep-Alive", "timeout=5"),
            ("Proxy-Authenticate", "Basic"),
            ("TE", "trailers"),
            ("Trailer", "X-End"),
            ("Upgrade", "h2c"),
            ("Date", "Mon, 02 Jan 2006 15:04:05 GMT"),
            ("Age", "9"),
            ("X-Cache", "HIT"),
            ("X-Kept", "a"),
            ("X-Kept", "b"),
        ]);
        assert_eq!(r.reason(), b"Gone Missing");
        let lines = r.stored_lines().unwrap();
        let names: Vec<&[u8]> = lines.iter().map(|(n, _)| n.as_slice()).collect();
        assert_eq!(
            names,
            [
                &b"Server"[..],
                b"Content-Type",
                b"Content-Encoding",
                b"X-Kept",
                b"X-Kept"
            ]
        );
        let back = OutboundResponse::from_stored(404, r.reason(), &lines);
        assert_eq!(back.status, 404);
        assert_eq!(back.peek(b"Server"), Some(&b"origin"[..]));
        assert_eq!(back.peek(b"Content-Encoding"), Some(&b"gzip"[..]));
        assert_eq!(
            back.values(b"X-Kept").collect::<Vec<_>>(),
            [&b"a"[..], b"b"]
        );
        assert!(!back.close && back.peek(b"Connection").is_none());
        // Sent with the length of what it holds and the message it had.
        let mut sent = back.clone();
        sent.body = Bytes::from_static(b"x");
        let w = String::from_utf8(sent.wire(false, false, false, 0)).unwrap();
        assert!(
            w.starts_with("HTTP/1.1 404 Gone Missing\r\n") && w.contains("Content-Length: 1\r\n"),
            "{w}"
        );
        // An answer with a cookie is never stored; one with no message gives none back.
        let with_cookie = upstream(&[("Set-Cookie", "a=1")]);
        assert!(with_cookie.stored_lines().is_none());
        assert_eq!(OutboundResponse::new(200).reason(), b"");
    }

    #[test]
    fn http_date_format() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_136_214_245), "Mon, 02 Jan 2006 15:04:05 GMT");
        assert_eq!(http_date(1_709_164_799), "Wed, 28 Feb 2024 23:59:59 GMT");
        assert_eq!(http_date(1_709_164_800), "Thu, 29 Feb 2024 00:00:00 GMT");
        assert_eq!(http_date(4_102_444_800), "Fri, 01 Jan 2100 00:00:00 GMT");
    }

    #[test]
    fn keep_alive_wire_has_no_connection_line() {
        let mut r = OutboundResponse::with(403, "text/html; charset=utf-8", "no");
        r.set(b"x-a", b"1\r\nInjected: yes");
        r.add(b"Set-Cookie", b"c=1");
        let w = String::from_utf8(r.wire(false, false, false, 0)).unwrap();
        assert_eq!(
            w,
            "HTTP/1.1 403 Forbidden\r\nServer: wafio-route-proxy\r\nDate: Thu, 01 Jan 1970 00:00:00 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 2\r\nX-A: 1  Injected: yes\r\nSet-Cookie: c=1\r\n\r\nno"
        );
        // HTTP/1.0 keep-alive: the line sits among the headers, before the cookies.
        let w = String::from_utf8(r.wire(true, true, false, 0)).unwrap();
        assert!(
            w.contains(
                "X-A: 1  Injected: yes\r\nConnection: keep-alive\r\nSet-Cookie: c=1\r\n\r\n"
            ) && w.ends_with("\r\n\r\n")
        );
        // The connection ends: `Connection: close` is the last line.
        let w = String::from_utf8(r.wire(true, false, true, 0)).unwrap();
        assert!(
            w.ends_with("Set-Cookie: c=1\r\nConnection: close\r\n\r\nno"),
            "{w}"
        );
        // HEAD: the header block only, Content-Length as the handler set it.
        let r = OutboundResponse::with(200, "text/plain", "body");
        assert!(
            r.wire(false, true, false, 0)
                .ends_with(b"Content-Length: 4\r\n\r\n")
        );
        assert_eq!(reason_phrase(299), "Unknown Status Code");
    }

    #[test]
    fn upstream_answers_keep_their_protocol_and_content_length_state() {
        let hs = |v: &'static [(&'static str, &'static str)]| {
            v.iter()
                .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
                .collect::<Vec<_>>()
        };
        let wire = |r: &OutboundResponse, head: bool| {
            String::from_utf8(r.wire(false, head || skips_content_length(r.status), r.close, 0))
                .unwrap()
        };
        // 204 without a length: no Content-Length, the default Content-Type.
        let r = OutboundResponse::from_upstream(204, false, hs(&[]));
        assert!(!r.close);
        assert!(
            wire(&r, false).ends_with("Content-Type: text/plain; charset=utf-8\r\n\r\n"),
            "{}",
            wire(&r, false)
        );
        // 304 keeps its other lines after it.
        let r = OutboundResponse::from_upstream(304, false, hs(&[("Etag", "x")]));
        assert!(
            wire(&r, false).ends_with("Content-Type: text/plain; charset=utf-8\r\nEtag: x\r\n\r\n")
        );
        // HEAD: the upstream's Content-Length, no body.
        let r = OutboundResponse::from_upstream(200, false, hs(&[("Content-Length", "12")]));
        assert!(
            wire(&r, true)
                .ends_with("Content-Type: text/plain; charset=utf-8\r\nContent-Length: 12\r\n\r\n")
        );
        // HTTP/1.0 without keep-alive closes and says HTTP/1.0; with keep-alive it stays open.
        let r = OutboundResponse::from_upstream(200, true, hs(&[("Content-Length", "0")]));
        assert!(
            r.close
                && wire(&r, false).starts_with("HTTP/1.0 200 OK\r\n")
                && wire(&r, false).ends_with("Connection: close\r\n\r\n")
        );
        assert!(
            !OutboundResponse::from_upstream(
                200,
                true,
                hs(&[("Content-Length", "0"), ("Connection", "Keep-Alive")])
            )
            .close
        );
        // No length and not chunked: close-delimited, so the connection ends (except 204/304).
        assert!(OutboundResponse::from_upstream(200, false, hs(&[])).close);
        assert!(
            !OutboundResponse::from_upstream(200, false, hs(&[("Transfer-Encoding", "chunked")]))
                .close
        );
        assert!(!OutboundResponse::from_upstream(304, false, hs(&[])).close);
    }

    /// The status message an upstream wrote is kept (for example
    /// `400 Bad Request: malformed Host header`); the standard text is written only when there is
    /// none.
    #[test]
    fn the_upstream_status_message_is_kept() {
        let first = |r: OutboundResponse| {
            let w = r.wire(false, false, false, 0);
            String::from_utf8_lossy(&w[..w.iter().position(|&c| c == b'\r').unwrap()]).into_owned()
        };
        let r = |reason: Option<&str>| {
            first(
                OutboundResponse::from_upstream(400, false, [(&b"Content-Length"[..], &b"0"[..])])
                    .with_reason(reason),
            )
        };
        assert_eq!(
            r(Some("Bad Request: malformed Host header")),
            "HTTP/1.1 400 Bad Request: malformed Host header"
        );
        assert_eq!(r(Some("")), "HTTP/1.1 400 Bad Request");
        assert_eq!(r(None), "HTTP/1.1 400 Bad Request");
        assert_eq!(
            first(
                OutboundResponse::from_upstream(200, false, [(&b"Content-Length"[..], &b"0"[..])])
                    .with_reason(Some("Fine"))
            ),
            "HTTP/1.1 200 Fine"
        );
        // Bytes >= 0x80 are written back as they came (the message is copied untouched).
        let raw =
            OutboundResponse::from_upstream(200, false, [(&b"Content-Length"[..], &b"0"[..])])
                .with_reason(Some(&b"Caf\xc3\xa9 \xff"[..]));
        assert!(
            raw.wire(false, false, false, 0)
                .starts_with(b"HTTP/1.1 200 Caf\xc3\xa9 \xff\r\n")
        );
    }
}
