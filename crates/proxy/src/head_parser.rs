//! The request-head read: the request line, the header block and the URI the handler sees
//! (scheme, host and userinfo split off, the host percent-decoded). The proxy runs it on the
//! bytes it read before Pingora or anything else looks at them; an error is
//! `400 Error when parsing request` + `Connection: close`, and `NeedMore` means read more bytes.
//! Body framing follows from the parsed head (`content_length`: -2 none, -1 chunked, else the
//! declared length) and is read by `body_reader.rs`.
//!
//! shortcut: the IPv6 literal check is structural only (a bracketed host must hold a colon, a
//! non-empty zone, an IPv4 tail that parses as dotted quad); the hextet grammar is not
//! re-checked.

/// Why a head is not ready.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HeadError {
    /// The bytes so far are a prefix of a head: read more.
    NeedMore,
    /// Any other error: answered `400 Error when parsing request`, connection closed.
    Bad,
}

/// One parsed request head.
#[derive(Debug, Default, Clone)]
pub struct Head {
    /// Bytes the head occupies in the buffer (leading empty lines included).
    pub len: usize,
    pub method: Vec<u8>,
    pub request_target: Vec<u8>,
    /// The request line names a protocol other than `HTTP/1.1`.
    pub http10: bool,
    /// The protocol is older than HTTP/1.1 (`HTTP/1.0`, `HTTP/0.9`): what an upstream request
    /// can say about it (the `http` crate has no `HTTP/1.2`, so a newer protocol goes out as
    /// HTTP/1.1).
    pub proto_pre11: bool,
    /// Header lines in arrival order (keys normalised, values folded and trimmed), the special
    /// headers included. `Transfer-Encoding: chunked` stays a line (the canonical value, at its
    /// line's place); `identity` and the `Trailer` lines are not lines (the latter are
    /// [`Head::trailer`]).
    pub lines: Vec<(Vec<u8>, Vec<u8>)>,
    /// The names of the last `Trailer` line (each line resets the list), normalised, in the
    /// order written; kept apart from `lines`.
    pub trailer: Vec<Vec<u8>>,
    /// The `Host` header value, empty when absent.
    pub host: Vec<u8>,
    /// `-2`: no body (neither `Content-Length` nor chunked), `-1`: chunked, else the length.
    pub content_length: i64,
    /// The `Content-Length` value as written; `None` unless the body length is declared.
    pub content_length_bytes: Option<Vec<u8>>,
    /// The connection closes after this request: an exact `Connection: close` (a later other
    /// `Connection` value clears it), or a non-HTTP/1.1 request without `keep-alive`.
    pub connection_close: bool,
    /// `Expect: 100-continue` (the exact value).
    pub expect_continue: bool,
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    memchr::memmem::find(h, n)
}

fn take_line(b: &[u8]) -> Result<(&[u8], &[u8]), HeadError> {
    let nl = memchr::memchr(b'\n', b).ok_or(HeadError::NeedMore)?;
    let n = if nl > 0 && b[nl - 1] == b'\r' {
        nl - 1
    } else {
        nl
    };
    Ok((&b[..n], &b[nl + 1..]))
}

/// RFC 9110 tchar (valid in header names and methods).
pub(crate) fn tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// Valid header value bytes: tab, 0x20..=0x7e and 0x80..=0xff.
fn valid_value_byte(c: u8) -> bool {
    c == b'\t' || (0x20..0x7f).contains(&c) || c >= 0x80
}

fn is_http_version_token(p: &[u8]) -> bool {
    p.len() == 8
        && p.starts_with(b"HTTP/")
        && p[6] == b'.'
        && p[5].is_ascii_digit()
        && p[7].is_ascii_digit()
}

pub(crate) fn is_valid_scheme(s: &[u8]) -> bool {
    match s.split_first() {
        Some((f, rest)) if f.is_ascii_alphabetic() => rest
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.')),
        _ => false,
    }
}

fn contains_ctl(s: &[u8]) -> bool {
    s.iter().any(|&b| b < b' ' || b == 0x7f)
}

/// Whether the request target is acceptable: no control bytes, then `*`, a path, a URI with a
/// valid scheme, or any other form for CONNECT.
fn check_request_target(method: &[u8], uri: &[u8]) -> bool {
    if contains_ctl(uri) {
        return false;
    }
    if uri == b"*" || uri.first() == Some(&b'/') {
        return true;
    }
    if let Some(i) = find(uri, b"://") {
        return is_valid_scheme(&uri[..i]);
    }
    method == b"CONNECT"
}

/// The request line: (bytes consumed, method, request-uri, `http10`, `proto_pre11`).
type FirstLine = (usize, Vec<u8>, Vec<u8>, bool, bool);

fn parse_start_line(buf: &[u8]) -> Result<FirstLine, HeadError> {
    let mut next = buf;
    let line = loop {
        let (l, n) = take_line(next)?;
        next = n;
        if !l.is_empty() {
            break l;
        }
    };
    let n = line
        .iter()
        .position(|&c| c == b' ')
        .filter(|&n| n > 0)
        .ok_or(HeadError::Bad)?;
    let method = &line[..n];
    if !method.iter().all(|&c| tchar(c)) {
        return Err(HeadError::Bad);
    }
    let rest = &line[n + 1..];
    let n = rest.iter().position(|&c| c == b' ').ok_or(HeadError::Bad)?;
    let proto = &rest[n + 1..];
    if !is_http_version_token(proto) || n == 0 || !check_request_target(method, &rest[..n]) {
        return Err(HeadError::Bad);
    }
    Ok((
        buf.len() - next.len(),
        method.to_vec(),
        rest[..n].to_vec(),
        proto != b"HTTP/1.1",
        // `HTTP/d.d`: older than 1.1 when the major digit is 0, or 1 with minor 0.
        proto[5] == b'0' || (proto[5] == b'1' && proto[7] == b'0'),
    ))
}

/// The end of the header block (the first blank line).
fn collect_header_block(buf: &[u8]) -> Result<usize, HeadError> {
    let n = buf
        .iter()
        .position(|&c| c == b'\n')
        .ok_or(HeadError::NeedMore)?;
    if (n == 1 && buf[0] == b'\r') || n == 0 {
        return Ok(n + 1);
    }
    let mut n = n + 1;
    let mut b = buf;
    let mut m = n;
    loop {
        b = &b[m..];
        m = b
            .iter()
            .position(|&c| c == b'\n')
            .ok_or(HeadError::NeedMore)?
            + 1;
        n += m;
        if (m == 2 && b[0] == b'\r') || m == 1 {
            return Ok(n);
        }
    }
}

fn trim(s: &[u8]) -> &[u8] {
    let i = s
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(s.len());
    let n = s
        .iter()
        .rposition(|&c| c != b' ' && c != b'\t')
        .map_or(i, |p| p + 1);
    &s[i..n.max(i)]
}

fn trim_end_spaces(s: &[u8]) -> &[u8] {
    let n = s
        .iter()
        .rposition(|&c| c != b' ' && c != b'\t')
        .map_or(0, |p| p + 1);
    &s[..n]
}

/// Yields (key, value, key has an inner space) for each header line of a block whose end
/// `collect_header_block` found.
struct Scanner<'a> {
    b: &'a [u8],
    r: usize,
    header_block_end: usize,
    initialized: bool,
}

impl<'a> Scanner<'a> {
    fn new(b: &'a [u8], block_end: usize) -> Self {
        Scanner {
            b,
            r: 0,
            header_block_end: block_end,
            initialized: false,
        }
    }

    fn read_header_line(&mut self) -> Option<&'a [u8]> {
        let i = self.b[self.r..].iter().position(|&c| c == b'\n')?;
        let mut line = &self.b[self.r..self.r + i];
        self.r += i + 1;
        if i > 0 && line[i - 1] == b'\r' {
            line = &line[..i - 1];
        }
        Some(line)
    }

    fn skip_leading_space(&mut self) -> bool {
        let mut skipped = false;
        while matches!(self.b.get(self.r), Some(b' ' | b'\t')) {
            self.r += 1;
            skipped = true;
        }
        skipped
    }

    /// `Ok(None)` = the blank line (end of the headers).
    #[allow(clippy::type_complexity)]
    fn next(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>, bool)>, HeadError> {
        if !self.initialized {
            if self.b.starts_with(b"\r\n") {
                self.r = 2;
                return Ok(None);
            }
            if self.header_block_end >= 4
                && self.header_block_end <= self.b.len()
                && &self.b[self.header_block_end - 4..self.header_block_end] == b"\r\n\r\n"
            {
                self.b = &self.b[..self.header_block_end];
            } else {
                let i = find(self.b, b"\r\n\r\n").ok_or(HeadError::NeedMore)?;
                self.b = &self.b[..i + 4];
            }
            if matches!(self.b.first(), Some(b' ' | b'\t')) {
                return Err(HeadError::Bad);
            }
            self.initialized = true;
        }
        // The line, joined with its continuation lines.
        let Some(line) = self.read_header_line() else {
            return Err(HeadError::Bad);
        };
        if line.is_empty() {
            return Ok(None);
        }
        let colon = line.iter().position(|&c| c == b':').ok_or(HeadError::Bad)?;
        let mut kv = trim(line).to_vec();
        while self.skip_leading_space() {
            kv.push(b' ');
            let l = self.read_header_line().unwrap_or_default();
            kv.extend_from_slice(trim(l));
        }
        let (k, v) = (&kv[..colon], &kv[colon + 1..]);
        // A valid key is spaces and tchars; an inner space (one before the last non-space
        // byte) keeps the key un-normalised.
        if k.is_empty() {
            return Err(HeadError::Bad);
        }
        let (mut seen_space, mut inner) = (false, false);
        for &c in k {
            if c == b' ' {
                seen_space = true;
            } else if c < 128 && tchar(c) {
                inner |= seen_space;
            } else {
                return Err(HeadError::Bad);
            }
        }
        let v = &v[v
            .iter()
            .position(|&c| c != b' ' && c != b'\t')
            .unwrap_or(v.len())..];
        Ok(Some((k.to_vec(), v.to_vec(), inner)))
    }

    fn consumed(&self) -> usize {
        self.r
    }
}

fn normalize_key(k: &[u8]) -> Vec<u8> {
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

/// Parses a `Content-Length` value: digits only, no overflow.
pub(crate) fn parse_length_header(b: &[u8]) -> Result<i64, HeadError> {
    if b.is_empty() {
        return Err(HeadError::Bad);
    }
    let mut v: i64 = 0;
    for &c in b {
        let k = c.wrapping_sub(b'0');
        if k > 9 {
            // Parsing stops at the first non-digit; the caller rejects a short parse.
            return Err(HeadError::Bad);
        }
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(i64::from(k)))
            .ok_or(HeadError::Bad)?;
    }
    Ok(v)
}

fn ci_eq(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Header names a request trailer may not carry.
pub(crate) fn is_forbidden_trailer(key: &[u8]) -> bool {
    if key.is_empty() {
        return true;
    }
    let k = key.to_ascii_lowercase();
    let k = k.as_slice();
    matches!(
        k,
        b"authorization"
            | b"connection"
            | b"cookie"
            | b"expect"
            | b"host"
            | b"keep-alive"
            | b"location"
            | b"max-forwards"
            | b"range"
            | b"set-cookie"
            | b"te"
            | b"trailer"
            | b"transfer-encoding"
            | b"www-authenticate"
            | b"content-encoding"
            | b"content-length"
            | b"content-type"
            | b"content-range"
            | b"proxy-connection"
            | b"proxy-authenticate"
            | b"proxy-authorization"
    ) || k.starts_with(b"x-forwarded")
        || k.starts_with(b"x-real-ip")
}

/// Every comma-separated name of a `Trailer` header must be a valid trailer key that is not
/// forbidden; the names come back normalised, in order. `strict` stops at the first refused name
/// (a bad request when a head carries it); otherwise a refused name is skipped (a `Trailer` set
/// by a header rule).
fn trailer_names_with(value: &[u8], strict: bool) -> Result<Vec<Vec<u8>>, HeadError> {
    let (mut rest, mut i, mut out) = (value, -1isize, Vec::new());
    while i + 1 < rest.len() as isize {
        rest = &rest[(i + 1) as usize..];
        let n = rest.iter().position(|&c| c == b',').unwrap_or(rest.len());
        i = n as isize;
        let key = trim(&rest[..n]);
        if key.is_empty() || !key.iter().all(|&c| c < 128 && tchar(c)) || is_forbidden_trailer(key)
        {
            if strict {
                return Err(HeadError::Bad);
            }
            continue;
        }
        out.push(normalize_key(key));
    }
    Ok(out)
}

fn trailer_names(value: &[u8]) -> Result<Vec<Vec<u8>>, HeadError> {
    trailer_names_with(value, true)
}

/// The names of a `Trailer` value set by a header rule: the valid ones.
pub(crate) fn trailer_names_lenient(value: &[u8]) -> Vec<Vec<u8>> {
    trailer_names_with(value, false).unwrap_or_default()
}

/// Trailer lines: (normalised name, value).
pub type Trailers = Vec<(Vec<u8>, Vec<u8>)>;

/// Parses the bytes after a chunked body's last chunk: (bytes consumed, trailers).
pub(crate) fn parse_trailer_names(buf: &[u8]) -> Result<(usize, Trailers), HeadError> {
    let mut sc = Scanner::new(buf, 0);
    let mut out = Vec::new();
    while let Some((raw_key, value, inner)) = sc.next()? {
        let key = trim_end_spaces(&raw_key);
        if key.is_empty() {
            continue;
        }
        if is_forbidden_trailer(key) || !value.iter().all(|&c| valid_value_byte(c)) {
            return Err(HeadError::Bad);
        }
        let key = if inner {
            key.to_vec()
        } else {
            normalize_key(key)
        };
        out.push((key, value));
    }
    Ok((sc.consumed(), out))
}

/// Parses the header block after the request line.
fn parse_header_lines(buf: &[u8], block_end: usize, head: &mut Head) -> Result<usize, HeadError> {
    head.content_length = -2;
    let (mut cl_seen, mut te_seen, mut host_seen) = (false, false, false);
    let mut sc = Scanner::new(buf, block_end);
    let mut conn_first: Option<Vec<u8>> = None;
    while let Some((raw_key, value, inner)) = sc.next()? {
        // A trailing space before the colon is an error for a request.
        if trim_end_spaces(&raw_key).len() != raw_key.len() {
            return Err(HeadError::Bad);
        }
        let key = if inner {
            raw_key
        } else {
            normalize_key(&raw_key)
        };
        if !value.iter().all(|&c| valid_value_byte(c)) {
            return Err(HeadError::Bad);
        }
        let lower = key.to_ascii_lowercase();
        let (mut is_cl, mut is_te, mut cl) = (false, false, 0);
        if lower == b"content-length" {
            is_cl = true;
            if cl_seen {
                return Err(HeadError::Bad);
            }
            cl_seen = true;
            cl = parse_length_header(&value)?;
        } else if lower == b"transfer-encoding" {
            is_te = true;
            if head.http10 || te_seen {
                return Err(HeadError::Bad);
            }
            te_seen = true;
        }
        if lower == b"host" {
            if host_seen {
                return Err(HeadError::Bad);
            }
            host_seen = true;
            head.host = value.clone();
        } else if is_cl {
            if head.content_length != -1 {
                head.content_length = cl;
                head.content_length_bytes = Some(value.clone());
            }
        } else if lower == b"connection" {
            if value == b"close" {
                head.connection_close = true;
            } else {
                head.connection_close = false;
                if conn_first.is_none() {
                    conn_first = Some(value.clone());
                }
            }
        } else if is_te {
            let identity = ci_eq(&value, b"identity");
            let chunked = ci_eq(&value, b"chunked");
            if !identity && !chunked {
                return Err(HeadError::Bad);
            }
            if chunked {
                head.content_length = -1;
                // Kept as a line with the canonical value.
                head.lines
                    .push((b"Transfer-Encoding".to_vec(), b"chunked".to_vec()));
            }
            continue;
        } else if lower == b"trailer" {
            // Held apart from the header lines; a later line replaces the list.
            head.trailer = trailer_names(&value)?;
            continue;
        }
        head.lines.push((key, value));
    }
    if head.content_length < 0 {
        head.content_length_bytes = None;
    }
    if head.http10 && !head.connection_close {
        // A non-HTTP/1.1 request closes unless the first `Connection` value lists keep-alive.
        let keeps = conn_first.as_deref().is_some_and(|v| {
            v.split(|&c| c == b',')
                .any(|p| ci_eq(strip_spaces(p), b"keep-alive"))
        });
        head.connection_close = !keeps;
    }
    Ok(sc.consumed())
}

fn strip_spaces(mut b: &[u8]) -> &[u8] {
    while let [b' ', r @ ..] = b {
        b = r;
    }
    while let [r @ .., b' '] = b {
        b = r;
    }
    b
}

/// Parses and validates the head at the start of `buf`.
pub fn parse_head(buf: &[u8]) -> Result<Head, HeadError> {
    let (m, method, request_uri, http10, proto_pre11) = parse_start_line(buf)?;
    let raw_end = collect_header_block(&buf[m..])?;
    let mut head = Head {
        method,
        request_target: request_uri,
        http10,
        proto_pre11,
        ..Default::default()
    };
    let n = parse_header_lines(&buf[m..], raw_end, &mut head)?;
    head.len = m + n;
    // An HTTP/1.1 request needs a Host.
    if !head.http10 && head.host.is_empty() {
        return Err(HeadError::Bad);
    }
    head.expect_continue = head
        .lines
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(b"expect"))
        .is_some_and(|(_, v)| v == b"100-continue");
    Ok(head)
}

// ---- URI host part -------------------------------------------------------------------------

/// Splits off an absolute-form scheme and authority: (scheme, host, uri).
fn split_host_and_uri<'a>(host: &'a [u8], uri: &'a [u8]) -> (&'a [u8], &'a [u8], &'a [u8]) {
    let Some(n) = find(uri, b"//") else {
        return (b"http", host, uri);
    };
    let mut scheme = &uri[..n];
    if scheme.contains(&b'/') {
        return (b"http", host, uri);
    }
    if scheme.last() == Some(&b':') {
        scheme = &scheme[..scheme.len() - 1];
    }
    let uri = &uri[n + 2..];
    let mut n = uri.iter().position(|&c| c == b'/');
    if let Some(nq) = uri.iter().position(|&c| c == b'?')
        && n.is_none_or(|n| nq < n)
    {
        n = Some(nq);
    }
    if let Some(nh) = uri.iter().position(|&c| c == b'#')
        && n.is_none_or(|n| nh < n)
    {
        n = Some(nh);
    }
    match n {
        None => (scheme, uri, b"/"),
        Some(n) => (scheme, &uri[..n], &uri[n..]),
    }
}

fn is_valid_userinfo(u: &[u8]) -> bool {
    u.iter().all(|&c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
                    | b'@'
            )
    })
}

fn is_valid_port_suffix(p: &[u8]) -> bool {
    match p.split_first() {
        None => true,
        Some((b':', rest)) => rest.iter().all(u8::is_ascii_digit),
        Some(_) => false,
    }
}

fn hexval(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

#[derive(PartialEq, Clone, Copy)]
enum EscapeMode {
    Host,
    Zone,
}

/// Whether byte `c` must be escaped in host and zone modes.
fn needs_escaping(c: u8) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if matches!(
        c,
        b'!' | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'['
            | b']'
            | b'<'
            | b'>'
            | b'"'
    ) {
        return false;
    }
    !matches!(c, b'-' | b'_' | b'.' | b'~')
}

/// Percent-decodes in host / zone mode.
fn unescape(s: &[u8], mode: EscapeMode) -> Result<Vec<u8>, ()> {
    let mut i = 0;
    let mut n = 0;
    while i < s.len() {
        if s[i] == b'%' {
            n += 1;
            if i + 2 >= s.len() {
                return Err(());
            }
            let (Some(h), Some(l)) = (hexval(s[i + 1]), hexval(s[i + 2])) else {
                return Err(());
            };
            let pct25 = &s[i..i + 3] == b"%25";
            if mode == EscapeMode::Host && h < 8 && !pct25 {
                return Err(());
            }
            if mode == EscapeMode::Zone {
                let v = h << 4 | l;
                if !pct25 && v != b' ' && needs_escaping(v) {
                    return Err(());
                }
            }
            i += 3;
        } else {
            if s[i] < 0x80 && needs_escaping(s[i]) {
                return Err(());
            }
            i += 1;
        }
    }
    if n == 0 {
        return Ok(s.to_vec());
    }
    let mut t = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            t.push((hexval(s[i + 1]).unwrap_or(0) << 4) | hexval(s[i + 2]).unwrap_or(0));
            i += 3;
        } else {
            t.push(s[i]);
            i += 1;
        }
    }
    Ok(t)
}

/// Structural checks of an IPv6 literal only (see the module doc).
fn check_ipv6_literal(host: &[u8]) -> Result<(), ()> {
    if host.first() != Some(&b'[') {
        return Ok(());
    }
    let end = host.iter().position(|&c| c == b']').ok_or(())?;
    if end == 1 {
        return Err(());
    }
    let mut addr = &host[1..end];
    if let Some(zi) = addr.iter().position(|&c| c == b'%') {
        if zi == addr.len() - 1 {
            return Err(());
        }
        addr = &addr[..zi];
    }
    if !addr.contains(&b':') {
        return Err(());
    }
    if addr.contains(&b'.') {
        let lc = addr.iter().rposition(|&c| c == b':').ok_or(())?;
        if lc == addr.len() - 1 {
            return Err(());
        }
        let v4 = &addr[lc + 1..];
        let parts: Vec<&[u8]> = v4.split(|&c| c == b'.').collect();
        let ok = parts.len() == 4
            && parts.iter().all(|p| {
                !p.is_empty()
                    && p.len() <= 3
                    && p.iter().all(u8::is_ascii_digit)
                    && (p.len() == 1 || p[0] != b'0')
                    && std::str::from_utf8(p)
                        .ok()
                        .and_then(|s| s.parse::<u16>().ok())
                        <= Some(255)
            });
        if !ok {
            return Err(());
        }
    }
    Ok(())
}

/// The host as the handler sees it (percent-decoded), or an error.
fn unescape_host(host: &[u8]) -> Result<Vec<u8>, ()> {
    if host.first() == Some(&b'[') {
        let i = host.iter().rposition(|&c| c == b']').ok_or(())?;
        if !is_valid_port_suffix(&host[i + 1..]) {
            return Err(());
        }
        if let Some(zone) = find(&host[..i], b"%25") {
            let mut out = unescape(&host[..zone], EscapeMode::Host)?;
            out.extend(unescape(&host[zone..i], EscapeMode::Zone)?);
            out.extend(unescape(&host[i..], EscapeMode::Host)?);
            return Ok(out);
        }
    } else {
        if host.iter().any(|&c| c == b'[' || c == b']') {
            return Err(());
        }
        if let Some(i) = host.iter().rposition(|&c| c == b':')
            && (host[..i].contains(&b':') || !is_valid_port_suffix(&host[i..]))
        {
            return Err(());
        }
    }
    let out = unescape(host, EscapeMode::Host)?;
    check_ipv6_literal(&out)?;
    Ok(out)
}

/// What the URI parse leaves for the handler.
#[derive(Debug, PartialEq, Eq)]
pub struct UriParts {
    /// The lower-cased, percent-decoded host.
    pub host: Vec<u8>,
    /// The request URI once an absolute-form scheme and authority are off.
    pub uri: Vec<u8>,
    /// The userinfo of an absolute-form authority as (username, password), raw; the client
    /// turns a non-empty username into `Authorization: Basic`.
    pub user: Option<(Vec<u8>, Vec<u8>)>,
}

/// Parses the host part and the userinfo of the request target; `Err` is answered 400.
#[allow(clippy::result_unit_err)]
pub fn uri_parts(host_header: &[u8], request_uri: &[u8]) -> Result<UriParts, ()> {
    if contains_ctl(request_uri) {
        return Err(());
    }
    let (mut host, mut uri) = (host_header, request_uri);
    if host.is_empty() || find(uri, b"://").is_some() {
        let (scheme, h, u) = split_host_and_uri(host, uri);
        if !scheme.is_empty() && !is_valid_scheme(scheme) {
            return Err(());
        }
        host = h;
        uri = u;
    }
    let mut user = None;
    if let Some(n) = host.iter().rposition(|&c| c == b'@') {
        let auth = &host[..n];
        if !is_valid_userinfo(auth) {
            return Err(());
        }
        host = &host[n + 1..];
        user = Some(match auth.iter().position(|&c| c == b':') {
            Some(i) => (auth[..i].to_vec(), auth[i + 1..].to_vec()),
            None => (auth.to_vec(), Vec::new()),
        });
    }
    let mut parsed = unescape_host(host)?;
    parsed.make_ascii_lowercase();
    Ok(UriParts {
        host: parsed,
        uri: uri.to_vec(),
        user,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(raw: &str) -> Head {
        parse_head(raw.as_bytes()).unwrap_or_else(|e| panic!("{raw:?}: {e:?}"))
    }
    fn bad(raw: &str) {
        assert_eq!(
            parse_head(raw.as_bytes()).err(),
            Some(HeadError::Bad),
            "{raw:?}"
        );
    }
    fn more(raw: &str) {
        assert_eq!(
            parse_head(raw.as_bytes()).err(),
            Some(HeadError::NeedMore),
            "{raw:?}"
        );
    }

    #[test]
    fn request_line_parsing() {
        let h = ok("GET /a HTTP/1.1\r\nHost: x\r\n\r\nBODY");
        assert_eq!(
            (h.method.as_slice(), h.request_target.as_slice()),
            (&b"GET"[..], &b"/a"[..])
        );
        assert_eq!(h.len, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n".len());
        for l in [
            "GET  / HTTP/1.1",
            "GET / HTTP/1.1 ",
            "GET /a b HTTP/1.1",
            "GET / HTTP/1.1 junk",
            "GET /",
            "GET / HTTP/1.11",
            "GET / HTTP/1",
            "GET / http/1.1",
            "GET / HTTP/1.a",
            "G@T / HTTP/1.1",
            " / HTTP/1.1",
            "GET x HTTP/1.1",
            "GET a:b HTTP/1.1",
            "GET ?x=1 HTTP/1.1",
            "GET /a\x01b HTTP/1.1",
            "GET /a\x7fb HTTP/1.1",
            "GET /a\tb HTTP/1.1",
            "GET 1http://h/ HTTP/1.1",
            "GET ://h/ HTTP/1.1",
            "GET /\r HTTP/1.1",
        ] {
            bad(&format!("{l}\r\nHost: x\r\n\r\n"));
        }
        for l in [
            "GET * HTTP/1.1",
            "GET http://h/ HTTP/1.1",
            "CONNECT h:443 HTTP/1.1",
            "GET /a HTTP/1.2",
            "GET /a HTTP/2.0",
            "M-SEARCH / HTTP/1.1",
            "GET /\u{e9} HTTP/1.1",
        ] {
            ok(&format!("{l}\r\nHost: x\r\n\r\n"));
        }
        // Leading empty lines are skipped, a lone CR line is a request line.
        ok("\r\n\r\n\nGET / HTTP/1.1\r\nHost: x\r\n\r\n");
        bad("\r\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n");
        more("GET / HTTP/1.1\r\nHost: x\r\n");
        more("");
        more("\r\n\r\n");
    }

    #[test]
    fn version_decides_host_and_close() {
        bad("GET / HTTP/1.1\r\n\r\n");
        bad("GET / HTTP/1.1\r\nHost:\r\n\r\n");
        bad("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n");
        assert!(ok("GET / HTTP/1.0\r\n\r\n").connection_close);
        assert!(!ok("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").connection_close);
        assert!(!ok("GET / HTTP/1.0\r\nConnection: Keep-Alive, x\r\n\r\n").connection_close);
        assert!(ok("GET / HTTP/1.2\r\nHost: a\r\n\r\n").connection_close);
        assert!(!ok("GET / HTTP/1.2\r\nHost: a\r\n\r\n").proto_pre11);
        assert!(ok("GET / HTTP/1.0\r\n\r\n").proto_pre11);
        assert!(ok("GET / HTTP/0.9\r\n\r\n").proto_pre11);
        assert!(!ok("GET / HTTP/1.1\r\nHost: a\r\n\r\n").proto_pre11);
        // Only the exact value closes; a later other value reopens.
        assert!(ok("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").connection_close);
        assert!(!ok("GET / HTTP/1.1\r\nHost: a\r\nConnection: Close\r\n\r\n").connection_close);
        assert!(
            !ok("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n")
                .connection_close
        );
        assert!(
            ok("GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n")
                .connection_close
        );
    }

    /// `Transfer-Encoding: chunked` is a line (canonical value, at its place), `identity` is
    /// not; `Trailer` lines go to `trailer`: names normalised, the last line wins, a refused
    /// name is a bad request.
    #[test]
    fn transfer_encoding_and_trailer_lines() {
        let head = |tail: &str| ok(&format!("POST / HTTP/1.1\r\nHost: a\r\n{tail}\r\n"));
        let h = head("X-A: 1\r\ntransfer-encoding: Chunked\r\nX-B: 2\r\n");
        assert_eq!(h.lines[1], (b"X-A".to_vec(), b"1".to_vec()));
        assert_eq!(
            h.lines[2],
            (b"Transfer-Encoding".to_vec(), b"chunked".to_vec())
        );
        assert_eq!(h.lines.len(), 4);
        let h = head("Transfer-Encoding: identity\r\n");
        assert_eq!(h.lines.len(), 1);
        let h = head("Trailer: C, ontent-Length\r\nTrailer: x-a, X-B ,\r\nX-A: 1\r\n");
        assert_eq!(h.trailer, [b"X-A".to_vec(), b"X-B".to_vec()]);
        assert_eq!(h.lines.len(), 2);
        assert!(head("Trailer:\r\n").trailer.is_empty());
        for bad in [
            "Trailer: X-A,,X-B\r\n",
            "Trailer: Host\r\n",
            "Trailer: a b\r\n",
        ] {
            assert!(
                parse_head(format!("POST / HTTP/1.1\r\nHost: a\r\n{bad}\r\n").as_bytes()).is_err()
            );
        }
        assert_eq!(
            trailer_names_lenient(b"X-A, Host, ,x-b"),
            [b"X-A".to_vec(), b"X-B".to_vec()]
        );
    }

    #[test]
    fn header_line_parsing() {
        let h = ok(
            "GET / HTTP/1.1\r\nHost: a\r\nX-Fold: one\r\n two\r\n\t three\r\nx-b:  v \t\r\n\r\n",
        );
        assert_eq!(h.lines[1], (b"X-Fold".to_vec(), b"one two three".to_vec()));
        assert_eq!(h.lines[2], (b"X-B".to_vec(), b"v".to_vec()));
        let h = ok("GET / HTTP/1.1\r\nHost: a\r\nX A: v\r\n\r\n");
        assert_eq!(h.lines[1].0, b"X A");
        let h = ok("GET / HTTP/1.1\r\nHost: a\nX-A: 1\r\n\r\n");
        assert_eq!(h.lines.len(), 2);
        assert!(parse_head(b"GET / HTTP/1.1\r\nHost: a\r\nX-A: a\xffb\tc\r\n\r\n").is_ok());
        for l in [
            "X-No-Colon",
            ": v",
            "X-A : v",
            "X-A\t: v",
            "X(A): v",
            "X-A: a\x00b",
            "X-A: a\rb",
            "X-A: a\x7fb",
            "X-A: a\x01b",
            "X-A: a\nb",
        ] {
            bad(&format!("GET / HTTP/1.1\r\nHost: a\r\n{l}\r\n\r\n"));
        }
        // A leading blank opens the headers: an error; after a header it continues it.
        bad("GET / HTTP/1.1\r\n Host: a\r\n\r\n");
        bad("GET / HTTP/1.1\r\n\tHost: a\r\n\r\n");
        // A bare-LF block is only complete once a CRLF CRLF follows somewhere.
        more("GET / HTTP/1.1\nHost: a\n\n");
        ok("GET / HTTP/1.1\nHost: a\n\r\n\r\n");
    }

    #[test]
    fn body_framing_from_the_head() {
        let post = |h: &str| format!("POST / HTTP/1.1\r\nHost: a\r\n{h}\r\n");
        assert_eq!(ok(&post("Content-Length: 3\r\n")).content_length, 3);
        assert_eq!(
            ok(&post("Content-Length: 003\r\n"))
                .content_length_bytes
                .unwrap(),
            b"003"
        );
        assert_eq!(ok(&post("")).content_length, -2);
        assert_eq!(
            ok(&post("Transfer-Encoding: Chunked\r\n")).content_length,
            -1
        );
        assert_eq!(
            ok(&post("Transfer-Encoding: identity\r\n")).content_length,
            -2
        );
        // Transfer-Encoding wins over Content-Length in either order.
        for h in [
            "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n",
            "Content-Length: 3\r\nTransfer-Encoding: chunked\r\n",
        ] {
            let h = ok(&post(h));
            assert_eq!((h.content_length, h.content_length_bytes), (-1, None));
        }
        for h in [
            "Content-Length: 3\r\nContent-Length: 3\r\n",
            "Content-Length: abc\r\n",
            "Content-Length: -1\r\n",
            "Content-Length: +3\r\n",
            "Content-Length: 0x3\r\n",
            "Content-Length:\r\n",
            "Content-Length: 3, 3\r\n",
            "Content-Length: 3 3\r\n",
            "Content-Length: 99999999999999999999\r\n",
            "Transfer-Encoding: gzip, chunked\r\n",
            "Transfer-Encoding: xchunked\r\n",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: chunked\r\nContent-Length: abc\r\n",
            "Trailer: Content-Length\r\n",
        ] {
            bad(&post(h));
        }
        bad("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert!(ok(&post("Expect: 100-continue\r\n")).expect_continue);
        assert!(!ok(&post("Expect: 100-Continue\r\n")).expect_continue);
    }

    #[test]
    fn uri_host_parsing() {
        let p = |h: &str, u: &str| uri_parts(h.as_bytes(), u.as_bytes());
        let hu = |h: &str, u: &str| p(h, u).map(|x| (x.host, x.uri));
        assert_eq!(
            hu("APP.test:80", "/x").unwrap(),
            (b"app.test:80".to_vec(), b"/x".to_vec())
        );
        assert_eq!(
            hu("a", "http://Other.Host/p?q").unwrap(),
            (b"other.host".to_vec(), b"/p?q".to_vec())
        );
        assert_eq!(p("a", "http://h").unwrap().uri, b"/");
        let x = p("a", "http://u:p%41@h:80/p").unwrap();
        assert_eq!(x.host, b"h:80");
        assert_eq!(x.user, Some((b"u".to_vec(), b"p%41".to_vec())));
        assert_eq!(
            p("a", "http://u@h/p").unwrap().user,
            Some((b"u".to_vec(), Vec::new()))
        );
        assert_eq!(p("a", "/x").unwrap().user, None);
        assert_eq!(
            p("a", "/q?u=http://evil/x").unwrap().uri,
            b"/q?u=http://evil/x"
        );
        assert_eq!(p("[::1]:80", "/").unwrap().host, b"[::1]:80");
        assert_eq!(hu("", "//x/y").unwrap(), (b"x".to_vec(), b"/y".to_vec()));
        for (h, u) in [
            ("a b", "/"),
            ("[::1", "/"),
            ("a:b:c", "/"),
            ("a:80x", "/"),
            ("a%41", "/"),
            ("a", "http://[::1/x"),
            ("a", "http://h:80x/x"),
            ("a", "http://u\"x@h/x"),
            ("a", "ht_tp://h/x"),
            ("a", "?u=http://h"),
            ("[]", "/"),
        ] {
            assert!(p(h, u).is_err(), "{h:?} {u:?}");
        }
    }
}
