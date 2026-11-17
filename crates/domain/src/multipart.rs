//! The multipart reading `extract_scan_fields` needs: a buffered reader with a 4096-byte window (the
//! window decides how much one part read returns), media type parsing, MIME header reading, the
//! multipart reader and its parts, and a quoted-printable reader. Only what an in-memory body
//! exercises is implemented; the error values are kinds, not message texts.

use std::collections::BTreeMap;

use crate::text_helpers::{REPLACEMENT_CODE_POINT, decode_code_point, eq_ignore_case, is_space};

/// A read error as far as callers distinguish it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    Eof,
    UnexpectedEof,
    BufferFull,
    Other(&'static str),
}

pub trait ByteSource {
    fn read(&mut self, p: &mut [u8]) -> (usize, Option<ReadError>);
}

/// A reader over an in-memory slice (never n > 0 with an error).
pub struct SliceReader<'a> {
    s: &'a [u8],
    i: usize,
}

impl ByteSource for SliceReader<'_> {
    fn read(&mut self, p: &mut [u8]) -> (usize, Option<ReadError>) {
        if self.i >= self.s.len() {
            return (0, Some(ReadError::Eof));
        }
        let n = p.len().min(self.s.len() - self.i);
        p[..n].copy_from_slice(&self.s[self.i..self.i + n]);
        self.i += n;
        (n, None)
    }
}

const READER_BUFFER_BYTES: usize = 4096;

/// A buffered reader with a 4096-byte window; the source is passed to every call.
pub struct PeekReader {
    buffer: Vec<u8>,
    r: usize,
    w: usize,
    error: Option<ReadError>,
    last_byte: i32,
}

impl PeekReader {
    pub fn new() -> Self {
        PeekReader {
            buffer: vec![0; READER_BUFFER_BYTES],
            r: 0,
            w: 0,
            error: None,
            last_byte: -1,
        }
    }

    fn fill(&mut self, src: &mut dyn ByteSource) {
        if self.r > 0 {
            self.buffer.copy_within(self.r..self.w, 0);
            self.w -= self.r;
            self.r = 0;
        }
        for _ in 0..100 {
            let (n, err) = src.read(&mut self.buffer[self.w..]);
            self.w += n;
            if err.is_some() {
                self.error = err;
                return;
            }
            if n > 0 {
                return;
            }
        }
        self.error = Some(ReadError::Other(
            "multiple Read calls return no data or error",
        ));
    }

    fn take_error(&mut self) -> Option<ReadError> {
        self.error.take()
    }

    pub fn buffered(&self) -> usize {
        self.w - self.r
    }

    /// `Peek(n)`: (start, end) of the peeked bytes in the window.
    fn peek(&mut self, src: &mut dyn ByteSource, n: usize) -> (usize, usize, Option<ReadError>) {
        self.last_byte = -1;
        while self.w - self.r < n && self.w - self.r < self.buffer.len() && self.error.is_none() {
            self.fill(src);
        }
        if n > self.buffer.len() {
            return (self.r, self.w, Some(ReadError::BufferFull));
        }
        let mut n = n;
        let mut err = None;
        let avail = self.w - self.r;
        if avail < n {
            n = avail;
            err = self.take_error().or(Some(ReadError::BufferFull));
        }
        (self.r, self.r + n, err)
    }

    fn read(&mut self, src: &mut dyn ByteSource, p: &mut [u8]) -> (usize, Option<ReadError>) {
        if p.is_empty() {
            if self.buffered() > 0 {
                return (0, None);
            }
            return (0, self.take_error());
        }
        if self.r == self.w {
            if self.error.is_some() {
                return (0, self.take_error());
            }
            if p.len() >= self.buffer.len() {
                let (n, err) = src.read(p);
                self.error = err;
                if n > 0 {
                    self.last_byte = i32::from(p[n - 1]);
                }
                return (n, self.take_error());
            }
            self.r = 0;
            self.w = 0;
            let (n, err) = src.read(&mut self.buffer);
            self.error = err;
            if n == 0 {
                return (0, self.take_error());
            }
            self.w += n;
        }
        let n = p.len().min(self.w - self.r);
        p[..n].copy_from_slice(&self.buffer[self.r..self.r + n]);
        self.r += n;
        self.last_byte = i32::from(self.buffer[self.r - 1]);
        (n, None)
    }

    fn read_byte(&mut self, src: &mut dyn ByteSource) -> Result<u8, ReadError> {
        while self.r == self.w {
            if self.error.is_some() {
                return Err(self.take_error().unwrap_or(ReadError::Eof));
            }
            self.fill(src);
        }
        let c = self.buffer[self.r];
        self.r += 1;
        self.last_byte = i32::from(c);
        Ok(c)
    }

    fn unread_byte(&mut self) {
        if self.last_byte < 0 || (self.r == 0 && self.w > 0) {
            return;
        }
        if self.r > 0 {
            self.r -= 1;
        } else {
            self.w = 1;
        }
        self.buffer[self.r] = self.last_byte as u8;
        self.last_byte = -1;
    }

    /// The line (copied) and error.
    fn read_slice(&mut self, src: &mut dyn ByteSource, delim: u8) -> (Vec<u8>, Option<ReadError>) {
        let mut s = 0;
        let (line, err);
        loop {
            if let Some(i) = self.buffer[self.r + s..self.w]
                .iter()
                .position(|&c| c == delim)
            {
                let i = i + s;
                line = self.buffer[self.r..self.r + i + 1].to_vec();
                self.r += i + 1;
                err = None;
                break;
            }
            if self.error.is_some() {
                line = self.buffer[self.r..self.w].to_vec();
                self.r = self.w;
                err = self.take_error();
                break;
            }
            if self.buffered() >= self.buffer.len() {
                self.r = self.w;
                line = self.buffer.clone();
                err = Some(ReadError::BufferFull);
                break;
            }
            s = self.w - self.r;
            self.fill(src);
        }
        if let Some(&c) = line.last() {
            self.last_byte = i32::from(c);
        }
        (line, err)
    }

    /// (line, is_prefix, error).
    fn read_line(&mut self, src: &mut dyn ByteSource) -> (Vec<u8>, bool, Option<ReadError>) {
        let (mut line, err) = self.read_slice(src, b'\n');
        if err == Some(ReadError::BufferFull) {
            if line.last() == Some(&b'\r') {
                self.r -= 1;
                line.pop();
            }
            return (line, true, None);
        }
        if line.is_empty() {
            return (Vec::new(), false, err);
        }
        if line.last() == Some(&b'\n') {
            let drop = if line.len() > 1 && line[line.len() - 2] == b'\r' {
                2
            } else {
                1
            };
            line.truncate(line.len() - drop);
        }
        (line, false, None)
    }
}

impl Default for PeekReader {
    fn default() -> Self {
        Self::new()
    }
}

// ---- media types ----

/// Media type parameters: lowercased name → value.
pub type MediaParams = BTreeMap<Vec<u8>, Vec<u8>>;

fn is_tspecial_byte(c: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&c)
}

fn is_token_byte(c: u8) -> bool {
    c > 0x20 && c < 0x7f && !is_tspecial_byte(c)
}

fn take_token(v: &[u8]) -> (&[u8], &[u8]) {
    match v.iter().position(|&c| !is_token_byte(c)) {
        Some(i) => (&v[..i], &v[i..]),
        None => (v, &[]),
    }
}

/// The parameter value at the start of `v`, and the rest. An empty value with rest == v means
/// there is no value.
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

fn trim_left_space(mut v: &[u8]) -> &[u8] {
    while !v.is_empty() {
        let (r, n) = decode_code_point(v);
        if (r == REPLACEMENT_CODE_POINT && n == 1) || !is_space(r) {
            break;
        }
        v = &v[n..];
    }
    v
}

fn take_media_param(v: &[u8]) -> (Vec<u8>, Vec<u8>, &[u8]) {
    let none = (Vec::new(), Vec::new(), v);
    let rest = trim_left_space(v);
    let Some(rest) = rest.strip_prefix(b";") else {
        return none;
    };
    let rest = trim_left_space(rest);
    let (param, rest) = take_token(rest);
    let param = param.to_ascii_lowercase();
    if param.is_empty() {
        return none;
    }
    let rest = trim_left_space(rest);
    let Some(rest) = rest.strip_prefix(b"=") else {
        return none;
    };
    let rest = trim_left_space(rest);
    let (value, rest2) = take_param_value(rest);
    if value.is_empty() && rest2.len() == rest.len() {
        return none;
    }
    (param, value, rest2)
}

fn decode_percent_escapes(s: &[u8]) -> Option<Vec<u8>> {
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'%' {
            out.push(s[i]);
            i += 1;
            continue;
        }
        if i + 2 >= s.len() {
            return None;
        }
        out.push(hex(s[i + 1])? << 4 | hex(s[i + 2])?);
        i += 3;
    }
    Some(out)
}

fn decode_rfc2231_value(v: &[u8]) -> Option<Vec<u8>> {
    let i = v.iter().position(|&c| c == b'\'')?;
    let (charset, rest) = (&v[..i], &v[i + 1..]);
    let j = rest.iter().position(|&c| c == b'\'')?;
    let ext = &rest[j + 1..];
    let cs = crate::text_helpers::to_lowercase(charset);
    if cs != b"us-ascii" && cs != b"utf-8" {
        return None;
    }
    decode_percent_escapes(ext)
}

fn check_media_type_or_disposition(s: &[u8]) -> bool {
    let (typ, rest) = take_token(s);
    if typ.is_empty() {
        return false;
    }
    if rest.is_empty() {
        return true;
    }
    let Some(rest) = rest.strip_prefix(b"/") else {
        return false;
    };
    let (sub, rest) = take_token(rest);
    !sub.is_empty() && rest.is_empty()
}

/// Parameters read by `plain_media_param`.
const MAX_PLAIN_PARAMS: usize = 64;

/// The value of the parameter `name` as it is written (`filename=`), whatever an extended form of it
/// (`filename*=`) says: `split_media_type` lets the extended form replace the plain one, and a reader
/// that ignores `*` (PHP reads only `filename`) takes the plain value.
pub fn plain_media_param(v: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let base_len = v.iter().position(|&c| c == b';').unwrap_or(v.len());
    let mut v = &v[base_len..];
    for _ in 0..MAX_PLAIN_PARAMS {
        let (key, value, rest) = take_media_param(v);
        if key.is_empty() {
            return None;
        }
        if key == name {
            return Some(value);
        }
        v = rest;
    }
    None
}

/// Splits a media type header: (lowercased media type, params), or None on error.
pub fn split_media_type(v: &[u8]) -> Option<(Vec<u8>, MediaParams)> {
    let base_len = v.iter().position(|&c| c == b';').unwrap_or(v.len());
    let mediatype =
        crate::text_helpers::trim_whitespace(&crate::text_helpers::to_lowercase(&v[..base_len]))
            .to_vec();
    if !check_media_type_or_disposition(&mediatype) {
        return None;
    }
    let mut params: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut continuation: BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>> = BTreeMap::new();
    let mut v = &v[base_len..];
    while !v.is_empty() {
        v = trim_left_space(v);
        if v.is_empty() {
            break;
        }
        let (key, value, rest) = take_media_param(v);
        if key.is_empty() {
            if crate::text_helpers::trim_whitespace(rest) == b";" {
                break;
            }
            return None;
        }
        let pmap = match key.iter().position(|&c| c == b'*') {
            Some(i) => continuation.entry(key[..i].to_vec()).or_default(),
            None => &mut params,
        };
        if let Some(old) = pmap.get(&key)
            && *old != value
        {
            return None;
        }
        pmap.insert(key, value);
        v = rest;
    }
    for (key, piece_map) in &continuation {
        let mut single = key.clone();
        single.push(b'*');
        if let Some(v) = piece_map.get(&single) {
            if let Some(d) = decode_rfc2231_value(v) {
                params.insert(key.clone(), d);
            }
            continue;
        }
        let mut buf = Vec::new();
        let mut valid = false;
        for n in 0.. {
            let mut simple = key.clone();
            simple.extend_from_slice(format!("*{n}").as_bytes());
            if let Some(v) = piece_map.get(&simple) {
                valid = true;
                buf.extend_from_slice(v);
                continue;
            }
            simple.push(b'*');
            let Some(v) = piece_map.get(&simple) else {
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
            params.insert(key.clone(), buf);
        }
    }
    Some((mediatype, params))
}

// ---- MIME headers ----

fn is_header_name_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn is_header_value_byte(c: u8) -> bool {
    c == b'\t' || (0x20..0x7f).contains(&c) || c >= 0x80
}

/// The canonical MIME header name (internal form): None when invalid.
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

fn trim_lwsp(s: &[u8]) -> &[u8] {
    let st = s
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(s.len());
    let en = s
        .iter()
        .rposition(|&c| c != b' ' && c != b'\t')
        .map_or(st, |i| i + 1);
    &s[st..en.max(st)]
}

const MAX_PART_HEADER_BYTES: i64 = 10 << 20;
const MAX_PART_HEADER_COUNT: i64 = 10000;

/// A part's MIME header: canonical key → values.
pub type PartHeaders = BTreeMap<Vec<u8>, Vec<Vec<u8>>>;

pub fn first_header_value<'h>(h: &'h PartHeaders, key: &[u8]) -> &'h [u8] {
    let k = canonical_header_name(key).unwrap_or_else(|| key.to_vec());
    h.get(&k)
        .and_then(|v| v.first())
        .map_or(&[][..], |v| v.as_slice())
}

fn read_line_bytes(
    br: &mut PeekReader,
    src: &mut dyn ByteSource,
    lim: i64,
) -> Result<Vec<u8>, ReadError> {
    let mut line = Vec::new();
    loop {
        let (l, more, err) = br.read_line(src);
        if let Some(e) = err {
            return Err(e);
        }
        if lim >= 0 && (line.len() + l.len()) as i64 > lim {
            return Err(ReadError::Other("message too large"));
        }
        line.extend_from_slice(&l);
        if !more {
            return Ok(line);
        }
    }
}

fn read_part_headers(
    br: &mut PeekReader,
    src: &mut dyn ByteSource,
) -> Result<PartHeaders, ReadError> {
    let mut m = PartHeaders::new();
    let (s, e, _) = br.peek(src, 1);
    if e > s && (br.buffer[s] == b' ' || br.buffer[s] == b'\t') {
        read_line_bytes(br, src, 80)?;
        return Err(ReadError::Other("malformed MIME header initial line"));
    }
    let mut max_memory = MAX_PART_HEADER_BYTES;
    let mut max_headers = MAX_PART_HEADER_COUNT;
    loop {
        let line = read_line_bytes(br, src, max_memory)?;
        if line.is_empty() {
            return Ok(m);
        }
        if !line.contains(&b':') {
            return Err(ReadError::Other("malformed MIME header: missing colon"));
        }
        let mut kv = trim_lwsp(&line).to_vec();
        let mut cont_err = None;
        loop {
            let mut n = 0;
            loop {
                match br.read_byte(src) {
                    Ok(c) if c == b' ' || c == b'\t' => n += 1,
                    Ok(_) => {
                        br.unread_byte();
                        break;
                    }
                    Err(_) => break,
                }
            }
            if n == 0 {
                break;
            }
            kv.push(b' ');
            match read_line_bytes(br, src, max_memory) {
                Ok(l) => kv.extend_from_slice(trim_lwsp(&l)),
                Err(e) => {
                    cont_err = Some(e);
                    break;
                }
            }
        }
        let _ = cont_err; // a read error ends the continuation loop; kv keeps what was read
        let Some(colon) = kv.iter().position(|&c| c == b':') else {
            return Err(ReadError::Other("malformed MIME header line"));
        };
        let (k, v) = (&kv[..colon], &kv[colon + 1..]);
        let Some(key) = canonical_header_name(k) else {
            return Err(ReadError::Other("malformed MIME header line"));
        };
        if !v.iter().all(|&c| is_header_value_byte(c)) {
            return Err(ReadError::Other("malformed MIME header line"));
        }
        max_headers -= 1;
        if max_headers < 0 {
            return Err(ReadError::Other("message too large"));
        }
        let start = v
            .iter()
            .position(|&c| c != b' ' && c != b'\t')
            .unwrap_or(v.len());
        let value = v[start..].to_vec();
        if !m.contains_key(&key) {
            max_memory -= key.len() as i64 + 200;
        }
        max_memory -= value.len() as i64;
        if max_memory < 0 {
            return Err(ReadError::Other("message too large"));
        }
        m.entry(key).or_default().push(value);
    }
}

// ---- multipart ----

struct PartState {
    n: usize,
    total: i64,
    error: Option<ReadError>,
    read_error: Option<ReadError>,
    qp: Option<QpState>,
}

struct QpState {
    br: PeekReader,
    line: Vec<u8>,
    read_error: Option<ReadError>,
}

/// A multipart reader over an in-memory body.
pub struct MultipartParser<'a> {
    src: SliceReader<'a>,
    br: PeekReader,
    nl: Vec<u8>,
    nl_dash_boundary: Vec<u8>,
    dash_boundary_dash: Vec<u8>,
    dash_boundary: Vec<u8>,
    parts_read: usize,
    part: Option<PartState>,
}

/// One part's header (the reader keeps the body state).
pub struct BodyPart {
    pub header: PartHeaders,
    disposition: Option<(Vec<u8>, MediaParams)>,
}

impl BodyPart {
    fn read_disposition(&mut self) -> &(Vec<u8>, MediaParams) {
        if self.disposition.is_none() {
            let v = first_header_value(&self.header, b"Content-Disposition");
            self.disposition = Some(split_media_type(v).unwrap_or_default());
        }
        self.disposition.as_ref().unwrap()
    }

    pub fn form_field_name(&mut self) -> Vec<u8> {
        let (disp, params) = self.read_disposition();
        if disp != b"form-data" {
            return Vec::new();
        }
        params.get(&b"name"[..]).cloned().unwrap_or_default()
    }

    /// The last path component of the filename parameter.
    pub fn client_file_name(&mut self) -> Vec<u8> {
        let (_, params) = self.read_disposition();
        let f = params.get(&b"filename"[..]).cloned().unwrap_or_default();
        if f.is_empty() {
            return f;
        }
        last_path_component(&f)
    }
}

/// The last component of a `/`-separated path.
fn last_path_component(p: &[u8]) -> Vec<u8> {
    if p.is_empty() {
        return b".".to_vec();
    }
    let mut p = p;
    while p.len() > 1 && p.ends_with(b"/") {
        p = &p[..p.len() - 1];
    }
    if let Some(i) = p.iter().rposition(|&c| c == b'/') {
        p = &p[i + 1..];
    }
    if p.is_empty() {
        return b"/".to_vec();
    }
    p.to_vec()
}

fn boundary_follows_prefix(buf: &[u8], prefix_len: usize, read_err: bool) -> i32 {
    if buf.len() == prefix_len {
        return if read_err { 1 } else { 0 };
    }
    let c = buf[prefix_len];
    if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
        return 1;
    }
    if c == b'-' {
        if buf.len() == prefix_len + 1 {
            return if read_err { -1 } else { 0 };
        }
        if buf[prefix_len + 1] == b'-' {
            return 1;
        }
    }
    -1
}

/// How many bytes of `buf` the part body may take before a boundary: (n, error).
fn scan_to_boundary(
    buf: &[u8],
    dash_boundary: &[u8],
    nl_dash_boundary: &[u8],
    total: i64,
    read_err: &Option<ReadError>,
) -> (usize, Option<ReadError>) {
    if total == 0 {
        if buf.starts_with(dash_boundary) {
            match boundary_follows_prefix(buf, dash_boundary.len(), read_err.is_some()) {
                -1 => return (dash_boundary.len(), None),
                0 => return (0, None),
                _ => return (0, Some(ReadError::Eof)),
            }
        }
        if dash_boundary.starts_with(buf) {
            return (0, read_err.clone());
        }
    }
    if let Some(i) = memchr::memmem::find(buf, nl_dash_boundary) {
        match boundary_follows_prefix(&buf[i..], nl_dash_boundary.len(), read_err.is_some()) {
            -1 => return (i + nl_dash_boundary.len(), None),
            0 => return (i, None),
            _ => return (i, Some(ReadError::Eof)),
        }
    }
    if nl_dash_boundary.starts_with(buf) {
        return (0, read_err.clone());
    }
    if let Some(i) = buf.iter().rposition(|&c| c == nl_dash_boundary[0])
        && nl_dash_boundary.starts_with(&buf[i..])
    {
        return (i, None);
    }
    (buf.len(), read_err.clone())
}

impl<'a> MultipartParser<'a> {
    pub fn new(body: &'a [u8], boundary: &[u8]) -> Self {
        let mut b = b"\r\n--".to_vec();
        b.extend_from_slice(boundary);
        b.extend_from_slice(b"--");
        MultipartParser {
            src: SliceReader { s: body, i: 0 },
            br: PeekReader::new(),
            nl: b[..2].to_vec(),
            nl_dash_boundary: b[..b.len() - 2].to_vec(),
            dash_boundary_dash: b[2..].to_vec(),
            dash_boundary: b[2..b.len() - 2].to_vec(),
            parts_read: 0,
            part: None,
        }
    }

    /// The raw part reader.
    fn raw_read(
        br: &mut PeekReader,
        src: &mut SliceReader<'a>,
        st: &mut PartState,
        db: &[u8],
        ndb: &[u8],
        d: &mut [u8],
    ) -> (usize, Option<ReadError>) {
        while st.n == 0 && st.error.is_none() {
            let buffered = br.buffered();
            let (s, e, _) = br.peek(src, buffered);
            let (n, err) = scan_to_boundary(&br.buffer[s..e], db, ndb, st.total, &st.read_error);
            st.n = n;
            st.error = err;
            if st.n == 0 && st.error.is_none() {
                let (_, _, e2) = br.peek(src, e - s + 1);
                st.read_error = match e2 {
                    Some(ReadError::Eof) => Some(ReadError::UnexpectedEof),
                    other => other,
                };
            }
        }
        if st.n == 0 {
            return (0, st.error.clone());
        }
        let n = d.len().min(st.n);
        let (n, _) = br.read(src, &mut d[..n]);
        st.total += n as i64;
        st.n -= n;
        if st.n == 0 {
            return (n, st.error.clone());
        }
        (n, None)
    }

    /// Reads from the current part.
    pub fn part_read(&mut self, d: &mut [u8]) -> (usize, Option<ReadError>) {
        let MultipartParser {
            src,
            br,
            part,
            dash_boundary,
            nl_dash_boundary,
            ..
        } = self;
        let Some(st) = part.as_mut() else {
            return (0, Some(ReadError::Eof));
        };
        let Some(mut qp) = st.qp.take() else {
            return Self::raw_read(br, src, st, dash_boundary, nl_dash_boundary, d);
        };
        struct Raw<'r, 'a> {
            br: &'r mut PeekReader,
            src: &'r mut SliceReader<'a>,
            st: &'r mut PartState,
            db: &'r [u8],
            ndb: &'r [u8],
        }
        impl<'a> ByteSource for Raw<'_, 'a> {
            fn read(&mut self, p: &mut [u8]) -> (usize, Option<ReadError>) {
                MultipartParser::raw_read(self.br, self.src, self.st, self.db, self.ndb, p)
            }
        }
        let mut raw = Raw {
            br,
            src,
            st,
            db: dash_boundary,
            ndb: nl_dash_boundary,
        };
        let res = qp_read(&mut qp, &mut raw, d);
        raw.st.qp = Some(qp);
        res
    }

    /// Drains the part (8 KiB reads).
    pub fn part_close(&mut self) {
        if self.part.is_none() {
            return;
        }
        let mut buf = vec![0u8; 8192];
        loop {
            let (_, err) = self.part_read(&mut buf);
            if err.is_some() {
                return;
            }
        }
    }

    fn is_closing_boundary(&self, line: &[u8]) -> bool {
        let Some(rest) = line.strip_prefix(self.dash_boundary_dash.as_slice()) else {
            return false;
        };
        let st = rest
            .iter()
            .position(|&c| c != b' ' && c != b'\t')
            .unwrap_or(rest.len());
        let rest = &rest[st..];
        rest.is_empty() || rest == self.nl.as_slice()
    }

    fn is_boundary_line(&mut self, line: &[u8]) -> bool {
        let Some(rest) = line.strip_prefix(self.dash_boundary.as_slice()) else {
            return false;
        };
        let st = rest
            .iter()
            .position(|&c| c != b' ' && c != b'\t')
            .unwrap_or(rest.len());
        let rest = &rest[st..];
        if self.parts_read == 0 && rest == b"\n" {
            self.nl.remove(0);
            self.nl_dash_boundary.remove(0);
        }
        rest == self.nl.as_slice()
    }

    /// The next part: Err(Eof) at the final boundary, Err(other) on a malformed body. A quoted-printable
    /// part is decoded and loses its `Content-Transfer-Encoding` header.
    pub fn next_decoded_part(&mut self) -> Result<BodyPart, ReadError> {
        self.advance_to_part(false)
    }

    /// Like `next_decoded_part`, but the part body and its `Content-Transfer-Encoding` header stay as sent
    /// (no quoted-printable decoding).
    pub fn next_undecoded_part(&mut self) -> Result<BodyPart, ReadError> {
        self.advance_to_part(true)
    }

    fn advance_to_part(&mut self, raw_part: bool) -> Result<BodyPart, ReadError> {
        self.part_close();
        self.part = None;
        if self.dash_boundary == b"--" {
            return Err(ReadError::Other("multipart: boundary is empty"));
        }
        let mut expect_new_part = false;
        loop {
            let (line, err) = self.br.read_slice(&mut self.src, b'\n');
            if err == Some(ReadError::Eof) && self.is_closing_boundary(&line) {
                return Err(ReadError::Eof);
            }
            if let Some(e) = err {
                return Err(match e {
                    ReadError::Eof => ReadError::Other("multipart: NextPart: EOF"),
                    other => other,
                });
            }
            if self.is_boundary_line(&line) {
                self.parts_read += 1;
                let mut header = read_part_headers(&mut self.br, &mut self.src)?;
                let mut st = PartState {
                    n: 0,
                    total: 0,
                    error: None,
                    read_error: None,
                    qp: None,
                };
                let cte = first_header_value(&header, b"Content-Transfer-Encoding");
                if !raw_part && eq_ignore_case(cte, b"quoted-printable") {
                    header.remove(&b"Content-Transfer-Encoding"[..]);
                    st.qp = Some(QpState {
                        br: PeekReader::new(),
                        line: Vec::new(),
                        read_error: None,
                    });
                }
                self.part = Some(st);
                return Ok(BodyPart {
                    header,
                    disposition: None,
                });
            }
            if self.is_closing_boundary(&line) {
                return Err(ReadError::Eof);
            }
            if expect_new_part {
                return Err(ReadError::Other("multipart: expecting a new Part"));
            }
            if self.parts_read == 0 {
                continue;
            }
            if line == self.nl {
                expect_new_part = true;
                continue;
            }
            return Err(ReadError::Other("multipart: unexpected line in Next()"));
        }
    }
}

fn qp_read(q: &mut QpState, src: &mut dyn ByteSource, p: &mut [u8]) -> (usize, Option<ReadError>) {
    let mut n = 0;
    let mut p = p;
    while !p.is_empty() {
        if q.line.is_empty() {
            if q.read_error.is_some() {
                return (n, q.read_error.clone());
            }
            let (whole, rerr) = q.br.read_slice(src, b'\n');
            q.read_error = rerr;
            let has_lf = whole.ends_with(b"\n");
            let has_cr = whole.ends_with(b"\r\n");
            let end = whole
                .iter()
                .rposition(|c| !matches!(c, b'\n' | b'\r' | b' ' | b'\t'))
                .map_or(0, |i| i + 1);
            let mut line = whole[..end].to_vec();
            if line.ends_with(b"=") {
                let tail = &whole[end..];
                let st = tail
                    .iter()
                    .position(|&c| c != b' ' && c != b'\t')
                    .unwrap_or(tail.len());
                let right = &tail[st..];
                line.pop();
                let well_formed = right.starts_with(b"\n")
                    || right.starts_with(b"\r\n")
                    || (right.is_empty()
                        && !line.is_empty()
                        && q.read_error == Some(ReadError::Eof));
                if !well_formed {
                    q.read_error = Some(ReadError::Other("quotedprintable: invalid bytes after ="));
                }
            } else if has_lf {
                line.extend_from_slice(if has_cr { b"\r\n" } else { b"\n" });
            }
            q.line = line;
            continue;
        }
        let mut b = q.line[0];
        if b == b'=' {
            let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
            match (
                q.line.get(1).and_then(|&c| hex(c)),
                q.line.get(2).and_then(|&c| hex(c)),
            ) {
                (Some(h), Some(l)) if q.line.len() >= 3 => {
                    b = h << 4 | l;
                    q.line.drain(..2);
                }
                _ => {
                    if q.line.len() >= 2 && q.line[1] != b'\r' && q.line[1] != b'\n' {
                        b = b'=';
                    } else {
                        let err = if q.line.len() < 3 {
                            ReadError::UnexpectedEof
                        } else {
                            ReadError::Other("quotedprintable: invalid hex byte")
                        };
                        return (n, Some(err));
                    }
                }
            }
        } else if !(b == b'\t'
            || b == b'\r'
            || b == b'\n'
            || b >= 0x80
            || (b' '..=b'~').contains(&b))
        {
            return (
                n,
                Some(ReadError::Other("quotedprintable: invalid unescaped byte")),
            );
        }
        p[0] = b;
        p = &mut p[1..];
        q.line.remove(0);
        n += 1;
    }
    (n, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_media_type_cases() {
        let (t, p) = split_media_type(b"multipart/form-data; boundary=\"a b\"").unwrap();
        assert_eq!(t, b"multipart/form-data");
        assert_eq!(p[&b"boundary"[..]], b"a b");
        let (_, p) =
            split_media_type(b"form-data; name=x; filename*=UTF-8''%e2%82%ac.txt").unwrap();
        assert_eq!(p[&b"filename"[..]], "€.txt".as_bytes());
        assert!(split_media_type(b"form-data; name=a; name=b").is_none());
        assert!(split_media_type(b"").is_none());
        assert!(split_media_type(b"a/b/c").is_none());
        let (_, p) = split_media_type(b"form-data; name=a;").unwrap();
        assert_eq!(p[&b"name"[..]], b"a");
    }

    #[test]
    fn multipart_parser_reads_parts() {
        let body = b"preamble\r\n--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"../x/y.php\"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nq=3Dp=\r\nz\r\n--b--\r\n";
        let mut r = MultipartParser::new(body, b"b");
        let mut p = r.next_decoded_part().unwrap();
        assert_eq!(p.form_field_name(), b"a");
        let mut buf = [0u8; 64];
        let (n, err) = r.part_read(&mut buf);
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(err, Some(ReadError::Eof));
        let mut p = r.next_decoded_part().unwrap();
        assert_eq!(p.client_file_name(), b"y.php");
        let mut out = Vec::new();
        loop {
            let (n, err) = r.part_read(&mut buf);
            out.extend_from_slice(&buf[..n]);
            if err.is_some() {
                break;
            }
        }
        assert_eq!(out, b"q=pz");
        assert!(matches!(r.next_decoded_part(), Err(ReadError::Eof)));
    }

    // The undecoded reader keeps the quoted-printable header and the encoded bytes.
    #[test]
    fn next_undecoded_part_keeps_transfer_encoding() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.bin\"\r\nContent-Transfer-Encoding: Quoted-Printable\r\n\r\nq=3Dp=\r\nz\r\n--b--\r\n";
        let mut r = MultipartParser::new(body, b"b");
        let p = r.next_undecoded_part().unwrap();
        assert_eq!(
            first_header_value(&p.header, b"Content-Transfer-Encoding"),
            b"Quoted-Printable"
        );
        let mut buf = [0u8; 64];
        let (n, err) = r.part_read(&mut buf);
        assert_eq!(
            (&buf[..n], err),
            (&b"q=3Dp=\r\nz"[..], Some(ReadError::Eof))
        );
        assert!(matches!(r.next_undecoded_part(), Err(ReadError::Eof)));
        // the same body through next_decoded_part is decoded and the header is gone
        let mut r = MultipartParser::new(body, b"b");
        let p = r.next_decoded_part().unwrap();
        assert_eq!(
            first_header_value(&p.header, b"Content-Transfer-Encoding"),
            b""
        );
    }
}
