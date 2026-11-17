//! The MIME and multipart behaviour field rules depend on, over a complete body: media type
//! parsing, a multipart reader (next part, form name, file name, quoted-printable parts
//! decoded) and a multipart writer (random 60-hex boundary, headers sorted). A 4096-byte
//! read buffer is modelled where it changes results (boundary lines, quoted-printable lines).
//!
//! shortcut: after a quoted-printable decode error the rest of that part is treated as
//! drained; this matches a buffered reader for bodies up to 4 KiB (one buffer fill), larger
//! ones may differ.

use std::collections::BTreeMap;
use wafio_bytetext::strings::{
    cut, to_lowercase, trim_start_by, trim_start_chars, trim_whitespace,
};
use wafio_bytetext::unicode::is_space;

/// Parameters of a media type (keys lowercased).
pub type Params = BTreeMap<Vec<u8>, Vec<u8>>;
/// MIME headers (canonical keys, sorted as `Writer` writes them).
pub type PartHeaders = BTreeMap<Vec<u8>, Vec<Vec<u8>>>;

const READER_BUFFER_BYTES: usize = 4096;
const MAX_PART_HEADER_BYTES: i64 = 10 << 20;
const MAX_PART_HEADER_COUNT: i64 = 10000;

fn is_tspecial_byte(c: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&c)
}

fn is_token_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`{|}~".contains(&c)
}

fn take_token(v: &[u8]) -> (&[u8], &[u8]) {
    match v.iter().position(|&c| !is_token_byte(c)) {
        Some(i) => (&v[..i], &v[i..]),
        None => (v, &v[v.len()..]),
    }
}

fn take_param_value(v: &[u8]) -> (Vec<u8>, &[u8]) {
    if v.is_empty() {
        return (Vec::new(), v);
    }
    if v[0] != b'"' {
        let (t, r) = take_token(v);
        return (t.to_vec(), r);
    }
    let mut buf = Vec::new();
    let mut i = 1;
    while i < v.len() {
        let r = v[i];
        if r == b'"' {
            return (buf, &v[i + 1..]);
        }
        if r == b'\\' && i + 1 < v.len() && is_tspecial_byte(v[i + 1]) {
            buf.push(v[i + 1]);
            i += 2;
            continue;
        }
        if r == b'\r' || r == b'\n' {
            return (Vec::new(), v);
        }
        buf.push(r);
        i += 1;
    }
    (Vec::new(), v)
}

fn trim_left_space(v: &[u8]) -> &[u8] {
    trim_start_by(v, is_space)
}

// (param, value, rest); param empty = no parameter here.
fn take_media_param(v: &[u8]) -> (Vec<u8>, Vec<u8>, &[u8]) {
    let rest = trim_left_space(v);
    let Some(rest) = rest.strip_prefix(b";") else {
        return (Vec::new(), Vec::new(), v);
    };
    let rest = trim_left_space(rest);
    let (param, rest) = take_token(rest);
    let param = param.to_ascii_lowercase();
    if param.is_empty() {
        return (Vec::new(), Vec::new(), v);
    }
    let rest = trim_left_space(rest);
    let Some(rest) = rest.strip_prefix(b"=") else {
        return (Vec::new(), Vec::new(), v);
    };
    let rest = trim_left_space(rest);
    let (value, rest2) = take_param_value(rest);
    if value.is_empty() && rest2.len() == rest.len() {
        return (Vec::new(), Vec::new(), v);
    }
    (param, value, rest2)
}

fn decode_percent_escapes(s: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'%' {
            i += 1;
            continue;
        }
        if i + 2 >= s.len() || !s[i + 1].is_ascii_hexdigit() || !s[i + 2].is_ascii_hexdigit() {
            return None;
        }
        i += 3;
    }
    let mut t = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            let h = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
            t.push(h(s[i + 1]) << 4 | h(s[i + 2]));
            i += 3;
        } else {
            t.push(s[i]);
            i += 1;
        }
    }
    Some(t)
}

fn decode_rfc2231_value(v: &[u8]) -> Option<Vec<u8>> {
    let (charset, v, ok) = cut(v, b"'");
    if !ok {
        return None;
    }
    let (_, ext, ok) = cut(v, b"'");
    if !ok {
        return None;
    }
    let charset = to_lowercase(charset);
    if charset != b"us-ascii" && charset != b"utf-8" {
        return None;
    }
    decode_percent_escapes(ext)
}

fn check_media_type_or_disposition(s: &[u8]) -> Result<(), &'static str> {
    let (typ, rest) = take_token(s);
    if typ.is_empty() {
        return Err("mime: no media type");
    }
    if rest.is_empty() {
        return Ok(());
    }
    let Some(rest) = rest.strip_prefix(b"/") else {
        return Err("mime: expected slash after first token");
    };
    let (sub, rest) = take_token(rest);
    if sub.is_empty() {
        return Err("mime: expected token after slash");
    }
    if !rest.is_empty() {
        return Err("mime: unexpected content after media subtype");
    }
    Ok(())
}

/// (lowercased media type, params). RFC 2231 continuations and encodings decoded.
pub fn split_media_type(v: &[u8]) -> Result<(Vec<u8>, Params), &'static str> {
    let (base, _, _) = cut(v, b";");
    let mediatype = trim_whitespace(&to_lowercase(base)).to_vec();
    check_media_type_or_disposition(&mediatype)?;
    let mut params = Params::new();
    let mut continuation: BTreeMap<Vec<u8>, Params> = BTreeMap::new();
    let mut v = &v[base.len()..];
    while !v.is_empty() {
        v = trim_left_space(v);
        if v.is_empty() {
            break;
        }
        let (key, value, rest) = take_media_param(v);
        if key.is_empty() {
            if trim_whitespace(rest) == b";" {
                break;
            }
            return Err("mime: invalid media parameter");
        }
        let pmap = match key.iter().position(|&c| c == b'*') {
            Some(i) => continuation.entry(key[..i].to_vec()).or_default(),
            None => &mut params,
        };
        if let Some(old) = pmap.get(&key)
            && *old != value
        {
            return Err("mime: duplicate parameter name");
        }
        pmap.insert(key, value);
        v = rest;
    }
    for (key, piece_map) in continuation {
        let single = [key.as_slice(), b"*"].concat();
        if let Some(v) = piece_map.get(&single) {
            if let Some(d) = decode_rfc2231_value(v) {
                params.insert(key, d);
            }
            continue;
        }
        let mut buf = Vec::new();
        let mut valid = false;
        for n in 0.. {
            let simple = [key.as_slice(), format!("*{n}").as_bytes()].concat();
            if let Some(v) = piece_map.get(&simple) {
                valid = true;
                buf.extend_from_slice(v);
                continue;
            }
            let encoded = [simple.as_slice(), b"*"].concat();
            let Some(v) = piece_map.get(&encoded) else {
                break;
            };
            valid = true;
            if n == 0 {
                if let Some(d) = decode_rfc2231_value(v) {
                    buf.extend_from_slice(&d);
                }
            } else {
                buf.extend_from_slice(&decode_percent_escapes(v).unwrap_or_default());
            }
        }
        if valid {
            params.insert(key, buf);
        }
    }
    Ok((mediatype, params))
}

fn is_header_name_byte(c: u8) -> bool {
    is_token_byte(c) && c != b'{' && c != b'}'
}

fn is_header_value_byte(c: u8) -> bool {
    c == b'\t' || (0x20..0x7f).contains(&c) || c >= 0x80
}

/// Canonical MIME header key (validating form).
fn canonical_header_name(a: &[u8]) -> Option<Vec<u8>> {
    if a.is_empty() {
        return None;
    }
    let mut no_canon = false;
    for &c in a {
        if is_header_name_byte(c) {
            continue;
        }
        if c == b' ' {
            no_canon = true;
            continue;
        }
        return None;
    }
    if no_canon {
        return Some(a.to_vec());
    }
    let mut upper = true;
    Some(
        a.iter()
            .map(|&c| {
                let c = if upper {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                };
                upper = c == b'-';
                c
            })
            .collect(),
    )
}

/// One part, read in full: header (QP transfer encoding removed), decoded body and the
/// error a full read of the part would return (None = clean EOF).
#[derive(Clone, Debug)]
pub struct BodyPart {
    pub header: PartHeaders,
    pub body: Vec<u8>,
    pub error: Option<String>,
}

impl BodyPart {
    fn get(&self, key: &[u8]) -> &[u8] {
        self.header
            .get(key)
            .and_then(|v| v.first())
            .map_or(b"", |v| v.as_slice())
    }

    /// All values of the header `key` (key already canonical).
    pub fn header_field_values(&self, key: &[u8]) -> Vec<Vec<u8>> {
        self.header.get(key).cloned().unwrap_or_default()
    }

    fn disposition(&self) -> (Vec<u8>, Params) {
        split_media_type(self.get(b"Content-Disposition")).unwrap_or_default()
    }

    pub fn form_field_name(&self) -> Vec<u8> {
        let (d, p) = self.disposition();
        if d != b"form-data" {
            return Vec::new();
        }
        p.get(b"name".as_slice()).cloned().unwrap_or_default()
    }

    /// The base name of the filename parameter (Unix).
    pub fn client_file_name(&self) -> Vec<u8> {
        let (_, p) = self.disposition();
        let f = p.get(b"filename".as_slice()).cloned().unwrap_or_default();
        if f.is_empty() {
            return f;
        }
        let trimmed = {
            let mut e = f.len();
            while e > 0 && f[e - 1] == b'/' {
                e -= 1;
            }
            &f[..e]
        };
        if trimmed.is_empty() {
            return b"/".to_vec();
        }
        match trimmed.iter().rposition(|&c| c == b'/') {
            Some(i) => trimmed[i + 1..].to_vec(),
            None => trimmed.to_vec(),
        }
    }

    /// The error a read of at most `n` bytes of the part returns.
    pub fn read_error_within(&self, n: usize) -> Option<&str> {
        if self.body.len() >= n {
            None
        } else {
            self.error.as_deref()
        }
    }
}

/// End of input from the line reader (the only error `read_crlf_line` returns at the end).
const EOF: &str = "EOF";

#[derive(PartialEq, Eq)]
enum SliceError {
    Eof,
    BufferFull,
}

/// A multipart reader over a complete body and a boundary.
pub struct Reader<'a> {
    buffer: &'a [u8],
    pos: usize,
    nl: Vec<u8>,
    newline_boundary: Vec<u8>,
    closing_boundary: Vec<u8>,
    opening_boundary: Vec<u8>,
    parts_seen: usize,
}

impl<'a> Reader<'a> {
    pub fn new(body: &'a [u8], boundary: &[u8]) -> Self {
        let b = [b"\r\n--".as_slice(), boundary, b"--"].concat();
        Reader {
            buffer: body,
            pos: 0,
            nl: b[..2].to_vec(),
            newline_boundary: b[..b.len() - 2].to_vec(),
            closing_boundary: b[2..].to_vec(),
            opening_boundary: b[2..b.len() - 2].to_vec(),
            parts_seen: 0,
        }
    }

    // Reads up to the next '\n' with a 4096-byte buffer.
    fn read_until_byte(&mut self) -> (&'a [u8], Option<SliceError>) {
        let buf = self.buffer;
        let rem = &buf[self.pos..];
        match rem.iter().position(|&c| c == b'\n') {
            Some(i) if i < READER_BUFFER_BYTES => {
                self.pos += i + 1;
                (&rem[..=i], None)
            }
            _ if rem.len() >= READER_BUFFER_BYTES => {
                self.pos += READER_BUFFER_BYTES;
                (&rem[..READER_BUFFER_BYTES], Some(SliceError::BufferFull))
            }
            _ => {
                self.pos = self.buffer.len();
                (rem, Some(SliceError::Eof))
            }
        }
    }

    fn is_closing_boundary(&self, line: &[u8]) -> bool {
        let Some(rest) = line.strip_prefix(self.closing_boundary.as_slice()) else {
            return false;
        };
        let rest = trim_start_chars(rest, b" \t");
        rest.is_empty() || rest == self.nl.as_slice()
    }

    fn is_boundary_line(&mut self, line: &[u8]) -> bool {
        let Some(rest) = line.strip_prefix(self.opening_boundary.as_slice()) else {
            return false;
        };
        let rest = trim_start_chars(rest, b" \t");
        if self.parts_seen == 0 && rest == b"\n" {
            self.nl.remove(0);
            self.newline_boundary.remove(0);
        }
        rest == self.nl.as_slice()
    }

    /// Ok(None) at the final boundary.
    pub fn next_decoded_part(&mut self) -> Result<Option<BodyPart>, String> {
        if self.opening_boundary == b"--" {
            return Err("multipart: boundary is empty".into());
        }
        let mut expect_new_part = false;
        loop {
            let (line, err) = self.read_until_byte();
            if err == Some(SliceError::Eof) && self.is_closing_boundary(line) {
                return Ok(None);
            }
            match err {
                Some(SliceError::Eof) => return Err("multipart: NextPart: EOF".into()),
                Some(SliceError::BufferFull) => {
                    return Err("multipart: NextPart: bufio: buffer full".into());
                }
                None => {}
            }
            if self.is_boundary_line(line) {
                self.parts_seen += 1;
                // A bare EOF from the header reader passes through unwrapped:
                // a body ending inside a part's headers is a clean end.
                return match self.begin_part() {
                    Err(e) if e == EOF => Ok(None),
                    r => r.map(Some),
                };
            }
            if self.is_closing_boundary(line) {
                return Ok(None);
            }
            if expect_new_part {
                return Err(format!(
                    "multipart: expecting a new Part; got line {:?}",
                    String::from_utf8_lossy(line)
                ));
            }
            if self.parts_seen == 0 {
                continue;
            }
            if line == self.nl.as_slice() {
                expect_new_part = true;
                continue;
            }
            return Err(format!(
                "multipart: unexpected line in Next(): {:?}",
                String::from_utf8_lossy(line)
            ));
        }
    }

    // A line read through the buffer, accumulated: the line without "\n"/"\r\n".
    fn read_crlf_line(&mut self, lim: i64) -> Result<&'a [u8], String> {
        if self.pos == self.buffer.len() {
            return Err(EOF.into());
        }
        let buf = self.buffer;
        let rem = &buf[self.pos..];
        let line = match rem.iter().position(|&c| c == b'\n') {
            Some(i) => {
                self.pos += i + 1;
                let l = &rem[..i];
                l.strip_suffix(b"\r").unwrap_or(l)
            }
            None => {
                self.pos = self.buffer.len();
                rem
            }
        };
        if lim >= 0 && line.len() as i64 > lim {
            return Err("message too large".into());
        }
        Ok(line)
    }

    fn skip_leading_space(&mut self) -> usize {
        let mut n = 0;
        while self.pos < self.buffer.len()
            && (self.buffer[self.pos] == b' ' || self.buffer[self.pos] == b'\t')
        {
            self.pos += 1;
            n += 1;
        }
        n
    }

    fn read_folded_line(&mut self, lim: i64) -> Result<Vec<u8>, String> {
        let line = self.read_crlf_line(lim)?;
        if line.is_empty() {
            return Ok(Vec::new());
        }
        if !line.contains(&b':') {
            return Err(format!(
                "malformed MIME header: missing colon: {:?}",
                String::from_utf8_lossy(line)
            ));
        }
        let mut buf = trim_ws(line).to_vec();
        let lim = lim - buf.len() as i64;
        while self.skip_leading_space() > 0 {
            buf.push(b' ');
            if buf.len() as i64 >= lim {
                return Err("message too large".into());
            }
            let line = self.read_crlf_line(lim - buf.len() as i64)?;
            buf.extend_from_slice(trim_ws(line));
        }
        Ok(buf)
    }

    fn read_part_headers(&mut self) -> Result<PartHeaders, String> {
        let mut max_memory = MAX_PART_HEADER_BYTES;
        let mut max_headers = MAX_PART_HEADER_COUNT;
        let mut m = PartHeaders::new();
        if matches!(self.buffer.get(self.pos), Some(b' ' | b'\t')) {
            return Err("malformed MIME header initial line".into());
        }
        loop {
            let kv = self.read_folded_line(max_memory)?;
            if kv.is_empty() {
                return Ok(m);
            }
            let (k, v, _) = cut(&kv, b":");
            let bad = || {
                format!(
                    "malformed MIME header line: {:?}",
                    String::from_utf8_lossy(&kv)
                )
            };
            let key = canonical_header_name(k).ok_or_else(bad)?;
            if !v.iter().all(|&c| is_header_value_byte(c)) {
                return Err(bad());
            }
            max_headers -= 1;
            if max_headers < 0 {
                return Err("message too large".into());
            }
            let value = trim_start_chars(v, b" \t").to_vec();
            if !m.contains_key(&key) {
                max_memory -= key.len() as i64 + 200;
            }
            max_memory -= value.len() as i64;
            if max_memory < 0 {
                return Err("message too large".into());
            }
            m.entry(key).or_default().push(value);
        }
    }

    fn begin_part(&mut self) -> Result<BodyPart, String> {
        let mut header = self.read_part_headers()?;
        let (raw, raw_err) = self.read_part_data();
        let qp = header
            .get(b"Content-Transfer-Encoding".as_slice())
            .and_then(|v| v.first())
            .is_some_and(|v| wafio_bytetext::strings::eq_ignore_case(v, b"quoted-printable"));
        if !qp {
            return Ok(BodyPart {
                header,
                body: raw,
                error: raw_err,
            });
        }
        header.remove(b"Content-Transfer-Encoding".as_slice());
        let (body, err) = qp_decode(&raw, raw_err);
        Ok(BodyPart {
            header,
            body,
            error: err,
        })
    }

    // Over the buffered rest of the body: the part's raw bytes and the error
    // ending them (None = boundary reached, EOF).
    fn read_part_data(&mut self) -> (Vec<u8>, Option<String>) {
        let mut data = Vec::new();
        let mut total = 0usize;
        let mut read_err = false;
        loop {
            let peek = &self.buffer[self.pos..];
            let (n, end) = scan_to_boundary(
                peek,
                &self.opening_boundary,
                &self.newline_boundary,
                total,
                read_err,
            );
            if n == 0 && end == ScanEnd::None {
                // Looking one byte past the length hits the end of the body.
                read_err = true;
                continue;
            }
            data.extend_from_slice(&peek[..n]);
            self.pos += n;
            total += n;
            match end {
                ScanEnd::None => {}
                ScanEnd::Boundary => return (data, None),
                ScanEnd::ReadFailed => return (data, Some("unexpected EOF".into())),
            }
        }
    }
}

fn trim_ws(s: &[u8]) -> &[u8] {
    let s = trim_start_chars(s, b" \t");
    let mut e = s.len();
    while e > 0 && (s[e - 1] == b' ' || s[e - 1] == b'\t') {
        e -= 1;
    }
    &s[..e]
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum ScanEnd {
    None,
    Boundary,
    ReadFailed,
}

fn end_from_read_error(read_err: bool) -> ScanEnd {
    if read_err {
        ScanEnd::ReadFailed
    } else {
        ScanEnd::None
    }
}

// -1 not a boundary, 0 need more, +1 boundary.
fn boundary_follows_prefix(buf: &[u8], prefix: &[u8], read_err: bool) -> i32 {
    if buf.len() == prefix.len() {
        return if read_err { 1 } else { 0 };
    }
    let c = buf[prefix.len()];
    if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
        return 1;
    }
    if c == b'-' {
        if buf.len() == prefix.len() + 1 {
            return if read_err { -1 } else { 0 };
        }
        if buf[prefix.len() + 1] == b'-' {
            return 1;
        }
    }
    -1
}

fn scan_to_boundary(
    buf: &[u8],
    dash_boundary: &[u8],
    nl_dash_boundary: &[u8],
    total: usize,
    read_err: bool,
) -> (usize, ScanEnd) {
    if total == 0 {
        if buf.starts_with(dash_boundary) {
            match boundary_follows_prefix(buf, dash_boundary, read_err) {
                -1 => return (dash_boundary.len(), ScanEnd::None),
                0 => return (0, ScanEnd::None),
                _ => return (0, ScanEnd::Boundary),
            }
        }
        if dash_boundary.starts_with(buf) {
            return (0, end_from_read_error(read_err));
        }
    }
    if let Some(i) = wafio_bytetext::strings::find(buf, nl_dash_boundary) {
        match boundary_follows_prefix(&buf[i..], nl_dash_boundary, read_err) {
            -1 => return (i + nl_dash_boundary.len(), ScanEnd::None),
            0 => return (i, ScanEnd::None),
            _ => return (i, ScanEnd::Boundary),
        }
    }
    if nl_dash_boundary.starts_with(buf) {
        return (0, end_from_read_error(read_err));
    }
    if let Some(i) = buf.iter().rposition(|&c| c == nl_dash_boundary[0])
        && nl_dash_boundary.starts_with(&buf[i..])
    {
        return (i, ScanEnd::None);
    }
    (buf.len(), end_from_read_error(read_err))
}

// The quoted-printable source read to the end: decoded bytes and the error.
// The source ends with `src_err` (None = EOF).
fn qp_decode(src: &[u8], src_err: Option<String>) -> (Vec<u8>, Option<String>) {
    #[derive(Clone)]
    enum LineReadError {
        Eof,
        Other(String),
    }
    let mut out = Vec::with_capacity(src.len());
    let mut pos = 0;
    let mut line: Vec<u8> = Vec::new();
    let mut li = 0;
    let mut rerr: Option<LineReadError> = None;
    loop {
        if li == line.len() {
            match &rerr {
                Some(LineReadError::Eof) => return (out, None),
                Some(LineReadError::Other(e)) => return (out, Some(e.clone())),
                None => {}
            }
            // Reads up to '\n' over the part (4096-byte buffer).
            let rem = &src[pos..];
            let (l, e) = match rem.iter().position(|&c| c == b'\n') {
                Some(i) if i < READER_BUFFER_BYTES => (&rem[..=i], None),
                _ if rem.len() >= READER_BUFFER_BYTES => (
                    &rem[..READER_BUFFER_BYTES],
                    Some(LineReadError::Other("bufio: buffer full".into())),
                ),
                _ => (
                    rem,
                    Some(
                        src_err
                            .clone()
                            .map_or(LineReadError::Eof, LineReadError::Other),
                    ),
                ),
            };
            pos += l.len();
            rerr = e;
            let has_lf = l.ends_with(b"\n");
            let has_cr = l.ends_with(b"\r\n");
            let mut end = l.len();
            while end > 0 && matches!(l[end - 1], b'\n' | b'\r' | b' ' | b'\t') {
                end -= 1;
            }
            line = l[..end].to_vec();
            li = 0;
            if line.ends_with(b"=") {
                let right = trim_start_chars(&l[end..], b" \t");
                line.pop();
                let at_eof = matches!(rerr, Some(LineReadError::Eof));
                let well_formed = right.starts_with(b"\n")
                    || right.starts_with(b"\r\n")
                    || (right.is_empty() && !line.is_empty() && at_eof);
                if !well_formed {
                    rerr = Some(LineReadError::Other(format!(
                        "quotedprintable: invalid bytes after =: {:?}",
                        String::from_utf8_lossy(right)
                    )));
                }
            } else if has_lf {
                line.extend_from_slice(if has_cr { b"\r\n" } else { b"\n" });
            }
            continue;
        }
        let mut b = line[li];
        match b {
            b'=' => {
                let rest = &line[li + 1..];
                let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
                let decoded = if rest.len() < 2 {
                    Err("unexpected EOF".to_string())
                } else {
                    match (hex(rest[0]), hex(rest[1])) {
                        (Some(h), Some(l)) => Ok(h << 4 | l),
                        (None, _) => Err(format!(
                            "quotedprintable: invalid hex byte 0x{:02x}",
                            rest[0]
                        )),
                        (_, None) => Err(format!(
                            "quotedprintable: invalid hex byte 0x{:02x}",
                            rest[1]
                        )),
                    }
                };
                match decoded {
                    Ok(v) => {
                        b = v;
                        li += 2;
                    }
                    Err(e) => {
                        if line.len() - li >= 2 && line[li + 1] != b'\r' && line[li + 1] != b'\n' {
                            b = b'=';
                        } else {
                            return (out, Some(e));
                        }
                    }
                }
            }
            b'\t' | b'\r' | b'\n' => {}
            b if b >= 0x80 => {}
            b if !(b' '..=b'~').contains(&b) => {
                return (
                    out,
                    Some(format!(
                        "quotedprintable: invalid unescaped byte 0x{b:02x} in body"
                    )),
                );
            }
            _ => {}
        }
        out.push(b);
        li += 1;
    }
}

/// A multipart writer into a buffer.
pub struct Writer {
    out: Vec<u8>,
    boundary: Vec<u8>,
    has_part: bool,
}

impl Writer {
    /// Random boundary: 30 bytes from the OS CSPRNG, hex.
    pub fn new() -> std::io::Result<Writer> {
        let mut b = [0u8; 30];
        crate::crypto::fill_random_bytes(&mut b)?;
        Ok(Self::with_boundary(&crate::crypto::hex_encode(&b)))
    }

    pub fn with_boundary(boundary: &[u8]) -> Writer {
        Writer {
            out: Vec::new(),
            boundary: boundary.to_vec(),
            has_part: false,
        }
    }

    pub fn boundary(&self) -> &[u8] {
        &self.boundary
    }

    /// Starts a part: boundary line, headers sorted by key ("k: v\r\n" per value), blank line.
    pub fn start_part(&mut self, header: &PartHeaders) {
        self.out
            .extend_from_slice(if self.has_part { b"\r\n--" } else { b"--" });
        self.out.extend_from_slice(&self.boundary);
        self.out.extend_from_slice(b"\r\n");
        for (k, vs) in header {
            for v in vs {
                self.out.extend_from_slice(k);
                self.out.extend_from_slice(b": ");
                self.out.extend_from_slice(v);
                self.out.extend_from_slice(b"\r\n");
            }
        }
        self.out.extend_from_slice(b"\r\n");
        self.has_part = true;
    }

    pub fn write(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
    }

    /// The final boundary; returns the body.
    pub fn close(mut self) -> Vec<u8> {
        self.out.extend_from_slice(b"\r\n--");
        self.out.extend_from_slice(&self.boundary);
        self.out.extend_from_slice(b"--\r\n");
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_type_params() {
        let (t, p) = split_media_type(b"multipart/form-data; boundary=\"a b\"").unwrap();
        assert_eq!(t, b"multipart/form-data");
        assert_eq!(p[b"boundary".as_slice()], b"a b");
        let (_, p) =
            split_media_type(b"form-data; name=\"f\"; filename*=UTF-8''%e2%82%ac.txt").unwrap();
        assert_eq!(p[b"filename".as_slice()], "€.txt".as_bytes());
        assert!(split_media_type(b"form-data; name=a; name=b").is_err());
        assert!(split_media_type(b"text/").is_err());
        let (_, p) = split_media_type(b"form-data; name=a;").unwrap();
        assert_eq!(p[b"name".as_slice()], b"a");
    }

    #[test]
    fn reader_parts_and_qp() {
        let body = b"preamble\r\n--XX\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n--XX\r\ncontent-disposition: form-data; name=\"q\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nx=3Dy=\r\nz\r\n--XX--\r\n";
        let mut r = Reader::new(body, b"XX");
        let a = r.next_decoded_part().unwrap().unwrap();
        assert_eq!(
            (a.form_field_name(), a.body.clone(), a.error.clone()),
            (b"a".to_vec(), b"hello".to_vec(), None)
        );
        let q = r.next_decoded_part().unwrap().unwrap();
        assert_eq!(q.body, b"x=yz");
        assert!(
            !q.header
                .contains_key(b"Content-Transfer-Encoding".as_slice())
        );
        assert!(r.next_decoded_part().unwrap().is_none());
        let mut bad = Reader::new(b"--XX\r\nA: b\r\n\r\nno end", b"XX");
        let p = bad.next_decoded_part().unwrap().unwrap();
        assert_eq!(
            (p.body.as_slice(), p.error.is_some()),
            (b"no end".as_slice(), true)
        );
        assert!(bad.next_decoded_part().is_err());
        assert!(Reader::new(b"--\r\n", b"").next_decoded_part().is_err());
    }

    #[test]
    fn body_ending_inside_part_headers_is_clean_eof() {
        // EOF inside the part headers passes through unwrapped.
        for tail in ["", "X-A: b\r\n", "X-A: b", "X-A: b\r\n  c"] {
            let body = format!(
                "--XX\r\nContent-Disposition: form-data; name=\"ssn\"\r\n\r\n123\r\n--XX\r\n{tail}"
            );
            let mut r = Reader::new(body.as_bytes(), b"XX");
            assert_eq!(r.next_decoded_part().unwrap().unwrap().body, b"123");
            assert!(r.next_decoded_part().unwrap().is_none(), "tail {tail:?}");
        }
        // A header line without a colon is still an error.
        assert!(
            Reader::new(b"--XX\r\nbad\r\n", b"XX")
                .next_decoded_part()
                .is_err()
        );
    }

    #[test]
    fn writer_layout() {
        let mut w = Writer::with_boundary(b"B");
        let mut h = PartHeaders::new();
        h.insert(b"Content-Type".to_vec(), vec![b"text/plain".to_vec()]);
        h.insert(
            b"Content-Disposition".to_vec(),
            vec![b"form-data; name=\"a\"".to_vec()],
        );
        w.start_part(&h);
        w.write(b"1");
        w.start_part(&PartHeaders::new());
        assert_eq!(w.close(), b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: text/plain\r\n\r\n1\r\n--B\r\n\r\n\r\n--B--\r\n");
    }
}
