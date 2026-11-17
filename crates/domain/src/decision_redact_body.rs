//! Body redaction of stored decisions: form, JSON (any depth, cut prefixes) and
//! multipart text parts; every other byte kept, never panics.

use crate::decision_redact::{
    DECISION_REDACTED_MARKER, Evidence, Kind, MatchEvidence, is_redaction_marker,
    is_sensitive_field_name, redact_query_pairs, resembles_attack_payload,
};
use crate::text_helpers::{
    CodePoint, REPLACEMENT_CODE_POINT, eq_ignore_case, is_valid_utf8, push_code_point,
    to_lowercase, trim_whitespace, unescape_query_component,
};

/// URL-decodes a key carrying '%'; keys that do not decode are kept.
fn decode_percent_json_key(key: &[u8]) -> Vec<u8> {
    if key.contains(&b'%')
        && let Ok(d) = unescape_query_component(key)
    {
        return d;
    }
    key.to_vec()
}

const MARKER: &[u8] = DECISION_REDACTED_MARKER.as_bytes();

#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    None,
    Form,
    Json,
    Multipart,
}

/// Redacts a stored body copy taken as the whole request body.
pub fn redact_stored_body(body: &[u8], content_type: &[u8], m: &MatchEvidence) -> Vec<u8> {
    redact_stored_body_copy(body, content_type, m, true)
}

/// The agent keeps the first 512 runes as body_preview.
pub const BODY_PREVIEW_LIMIT: usize = 512;
/// The agent keeps the first 4096 bytes as request_body.
pub const REQUEST_BODY_CAPTURE_LIMIT: usize = 4096;

/// Reports whether a stored copy of at most `limit` bytes (or runes) is the
/// whole body of `body_size` bytes.
pub fn is_body_copy_complete(copy: &[u8], body_size: i64, limit: i64) -> bool {
    body_size > 0 && body_size <= limit && copy.len() as i64 == body_size && is_valid_utf8(copy)
}

/// Redacts a stored copy that holds the whole body only when `complete`.
pub fn redact_stored_body_copy(
    body: &[u8],
    content_type: &[u8],
    m: &MatchEvidence,
    complete: bool,
) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    let (kind, boundary) = classify_decision_body(body, content_type);
    let mut e = m.parse();
    e.cut = !complete;
    match kind {
        BodyKind::Form => redact_query_pairs(body, &e, Kind::Body, false),
        BodyKind::Json => redact_json_text(body, &e),
        BodyKind::Multipart => redact_multipart_text(body, &boundary, &e),
        BodyKind::None => body.to_vec(),
    }
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    memchr::memmem::find(h, n).is_some()
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    memchr::memmem::find(h, n)
}

fn classify_decision_body(body: &[u8], content_type: &[u8]) -> (BodyKind, Vec<u8>) {
    let ct = to_lowercase(trim_whitespace(content_type));
    let (mt, params) = match ct.iter().position(|&c| c == b';') {
        Some(i) => (&ct[..i], &ct[i + 1..]),
        None => (&ct[..], &b""[..]),
    };
    let mt = trim_whitespace(mt);
    if mt == b"json" || contains(mt, b"json") {
        return (BodyKind::Json, Vec::new());
    }
    if mt == b"form" || mt == b"application/x-www-form-urlencoded" {
        return (BodyKind::Form, Vec::new());
    }
    if mt == b"multipart" || mt.starts_with(b"multipart/") {
        if body.starts_with(b"--") {
            return (
                BodyKind::Multipart,
                boundary_of_content_type(content_type, params, body),
            );
        }
        return (BodyKind::Form, Vec::new());
    }
    if mt == b"xml"
        || mt == b"html"
        || mt == b"soap"
        || contains(mt, b"xml")
        || contains(mt, b"html")
    {
        return (BodyKind::None, Vec::new());
    }
    let t = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
    let st = t
        .iter()
        .position(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(t.len());
    let t = &t[st..];
    if t.is_empty() {
        return (BodyKind::None, Vec::new());
    }
    if t[0] == b'{' || t[0] == b'[' {
        return (BodyKind::Json, Vec::new());
    }
    if t[0] == b'<' {
        return (BodyKind::None, Vec::new());
    }
    if t.starts_with(b"--") && contains(&to_lowercase(t), b"content-disposition") {
        return (BodyKind::Multipart, boundary_of_content_type(b"", b"", t));
    }
    if t.iter().position(|&c| c == b'=').is_some_and(|i| i > 0) {
        return (BodyKind::Form, Vec::new());
    }
    (BodyKind::None, Vec::new())
}

/// The boundary from the Content-Type parameters, else the body's first line.
fn boundary_of_content_type(content_type: &[u8], lower_params: &[u8], body: &[u8]) -> Vec<u8> {
    if let Some(i) = find(lower_params, b"boundary=") {
        let orig_params = content_type
            .iter()
            .position(|&c| c == b';')
            .map_or(&b""[..], |j| &content_type[j + 1..]);
        if orig_params.len() == lower_params.len() {
            let mut b = &orig_params[i + b"boundary=".len()..];
            if let Some(j) = b.iter().position(|&c| c == b';') {
                b = &b[..j];
            }
            let b = trim_whitespace(b);
            let st = b.iter().position(|&c| c != b'"').unwrap_or(b.len());
            let en = b.iter().rposition(|&c| c != b'"').map_or(st, |k| k + 1);
            let b = &b[st..en.max(st)];
            if !b.is_empty() {
                return b.to_vec();
            }
        }
    }
    let line = match body.iter().position(|&c| c == b'\r' || c == b'\n') {
        Some(i) => &body[..i],
        None => body,
    };
    trim_whitespace(line.strip_prefix(b"--").unwrap_or(line)).to_vec()
}

/// Copies s lazily: nothing is allocated until the first replacement.
struct BodyRewriter<'a> {
    s: &'a [u8],
    b: Vec<u8>,
    copied: usize,
    changed: bool,
}

impl<'a> BodyRewriter<'a> {
    fn new(s: &'a [u8]) -> Self {
        BodyRewriter {
            s,
            b: Vec::new(),
            copied: 0,
            changed: false,
        }
    }

    fn replace(&mut self, start: usize, end: usize, with: &[u8]) {
        if start < self.copied || end < start || end > self.s.len() {
            return;
        }
        if &self.s[start..end] == with {
            return;
        }
        if !self.changed {
            self.b.reserve(self.s.len() + 16);
            self.changed = true;
        }
        self.b.extend_from_slice(&self.s[self.copied..start]);
        self.b.extend_from_slice(with);
        self.copied = end;
    }

    fn result(mut self) -> Vec<u8> {
        if !self.changed {
            return self.s.to_vec();
        }
        self.b.extend_from_slice(&self.s[self.copied..]);
        self.b
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Mode {
    Keep,
    Redact,
    Named,
    PerItem,
}

#[derive(Clone, Copy)]
struct Frame {
    object: bool,
    mode: Mode,
}

const MAX_REDACT_JSON_DEPTH: usize = 64;

fn redact_json_text(s: &[u8], e: &Evidence) -> Vec<u8> {
    let mut e = e.clone();
    if e.kind == Kind::Body && e.counts_targets() && (e.cut || redact_json_walk(s, &e, true).1 > 1)
    {
        e.multi = true;
    }
    redact_json_walk(s, &e, false).0
}

fn quoted(v: &[u8]) -> Vec<u8> {
    [b"\"", v, b"\""].concat()
}

fn redact_json_walk(s: &[u8], e: &Evidence, count: bool) -> (Vec<u8>, usize) {
    let mut w = BodyRewriter::new(s);
    let mut stack = [Frame {
        object: false,
        mode: Mode::Keep,
    }; MAX_REDACT_JSON_DEPTH];
    let (mut depth, mut over) = (0usize, 0usize);
    let mut expect_key = false;
    let mut pending = Mode::Keep;
    let mut count_next = false;
    let mut n = 0usize;
    let in_object = |depth: usize, over: usize, stack: &[Frame]| {
        over == 0 && depth > 0 && stack[depth - 1].object
    };
    let value_mode = |depth: usize, over: usize, stack: &[Frame], pending: Mode| {
        if over > 0 {
            Mode::Redact
        } else if depth == 0 {
            Mode::Keep
        } else if stack[depth - 1].object {
            pending
        } else {
            stack[depth - 1].mode
        }
    };
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' | b':' => i += 1,
            b',' => {
                if in_object(depth, over, &stack) {
                    expect_key = true;
                }
                i += 1;
            }
            b'{' | b'[' => {
                if count_next {
                    n += 1;
                    count_next = false;
                }
                let mut mode = value_mode(depth, over, &stack, pending);
                if mode == Mode::Named {
                    mode = if e.cred || e.value_known {
                        Mode::Redact
                    } else {
                        Mode::Keep
                    };
                }
                if over > 0 || depth == stack.len() {
                    over += 1;
                } else {
                    stack[depth] = Frame {
                        object: c == b'{',
                        mode,
                    };
                    depth += 1;
                }
                expect_key = c == b'{';
                pending = Mode::Keep;
                i += 1;
            }
            b'}' | b']' => {
                if over > 0 {
                    over -= 1;
                } else {
                    depth = depth.saturating_sub(1);
                }
                expect_key = false;
                count_next = false;
                i += 1;
            }
            b'"' => {
                let (end, closed) = end_of_json_string(s, i);
                let inner = &s[i + 1..end - usize::from(closed)];
                if over > 0 {
                    if !is_key_position(s, end) && !is_redaction_marker(inner) && !count {
                        w.replace(i, end, &quoted(MARKER));
                    }
                    i = end;
                    continue;
                }
                if in_object(depth, over, &stack) && expect_key {
                    pending = key_mode_for_json_key(inner, stack[depth - 1].mode, e);
                    count_next = count && pending >= Mode::Named;
                    expect_key = false;
                    i = end;
                    continue;
                }
                if count_next {
                    if !is_redaction_marker(inner) {
                        n += 1;
                    }
                    count_next = false;
                }
                if !count {
                    match value_mode(depth, over, &stack, pending) {
                        Mode::Redact => {
                            if !is_redaction_marker(inner) {
                                w.replace(i, end, &quoted(MARKER));
                            }
                        }
                        Mode::PerItem => {
                            if !resembles_attack_payload(inner) && !is_redaction_marker(inner) {
                                w.replace(i, end, &quoted(MARKER));
                            }
                        }
                        Mode::Named => {
                            let nv = e.named_value(inner);
                            if nv != inner {
                                w.replace(i, end, &quoted(&nv));
                            }
                        }
                        Mode::Keep => {}
                    }
                }
                i = end;
            }
            _ => {
                let mut j = i;
                while j < s.len() && !is_json_delimiter(s[j]) {
                    j += 1;
                }
                if j == i {
                    j += 1;
                }
                let lit = &s[i..j];
                if (in_object(depth, over, &stack) && expect_key)
                    || (over > 0 && is_key_position(s, j))
                {
                    i = j;
                    continue;
                }
                if count_next {
                    n += 1;
                    count_next = false;
                }
                if lit != b"true" && lit != b"false" && lit != b"null" && !count {
                    match value_mode(depth, over, &stack, pending) {
                        Mode::Redact | Mode::PerItem => w.replace(i, j, &quoted(MARKER)),
                        Mode::Named => {
                            let nv = e.named_value(lit);
                            if nv != lit {
                                w.replace(i, j, &quoted(&nv));
                            }
                        }
                        Mode::Keep => {}
                    }
                }
                i = j;
            }
        }
    }
    (w.result(), n)
}

fn key_mode_for_json_key(raw_key: &[u8], inherited: Mode, e: &Evidence) -> Mode {
    let (unescaped, decoded) = collect_json_key_names(raw_key);
    let secret = is_sensitive_field_name(&decoded)
        || (unescaped != decoded && is_sensitive_field_name(&unescaped));
    if !secret {
        return inherited;
    }
    if e.kind == Kind::Body && eq_ignore_case(&decoded, &e.target) {
        return if e.multi { Mode::PerItem } else { Mode::Named };
    }
    Mode::Redact
}

fn is_key_position(s: &[u8], mut i: usize) -> bool {
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i < s.len() && s[i] == b':'
}

fn is_json_delimiter(c: u8) -> bool {
    matches!(
        c,
        b' ' | b'\t' | b'\r' | b'\n' | b',' | b':' | b'{' | b'}' | b'[' | b']' | b'"'
    )
}

/// The index just past the string starting at s[i] and whether it closed.
fn end_of_json_string(s: &[u8], i: usize) -> (usize, bool) {
    let mut j = i + 1;
    while j < s.len() {
        match s[j] {
            b'\\' => j += 1,
            b'"' => return (j + 1, true),
            _ => {}
        }
        j += 1;
    }
    (s.len(), false)
}

fn collect_json_key_names(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let unescaped = unescape_json_string(raw).unwrap_or_else(|| raw.to_vec());
    let decoded = decode_percent_json_key(&unescaped);
    (unescaped, decoded)
}

/// Decodes the escapes of a raw JSON string body as encoding/json does (lone
/// surrogate → U+FFFD); None for a malformed escape.
pub(crate) fn unescape_json_string(raw: &[u8]) -> Option<Vec<u8>> {
    if !raw.contains(&b'\\') {
        return Some(raw.to_vec());
    }
    let mut b = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if c != b'\\' {
            b.push(c);
            i += 1;
            continue;
        }
        i += 1;
        if i >= raw.len() {
            return None;
        }
        match raw[i] {
            b'"' | b'\\' | b'/' => b.push(raw[i]),
            b'b' => b.push(0x08),
            b'f' => b.push(0x0C),
            b'n' => b.push(b'\n'),
            b'r' => b.push(b'\r'),
            b't' => b.push(b'\t'),
            b'u' => {
                let mut r = parse_json_hex4(raw, i + 1)?;
                i += 4;
                if (0xD800..0xE000).contains(&r) {
                    let mut r2 = None;
                    if i + 2 < raw.len() && raw[i + 1] == b'\\' && raw[i + 2] == b'u' {
                        r2 = parse_json_hex4(raw, i + 3);
                    }
                    match r2 {
                        Some(r2)
                            if (0xD800..0xDC00).contains(&r) && (0xDC00..0xE000).contains(&r2) =>
                        {
                            r = (((r - 0xD800) << 10) | (r2 - 0xDC00)) + 0x10000;
                            i += 6;
                        }
                        _ => r = REPLACEMENT_CODE_POINT,
                    }
                }
                push_code_point(&mut b, r);
            }
            _ => return None,
        }
        i += 1;
    }
    Some(b)
}

fn parse_json_hex4(raw: &[u8], i: usize) -> Option<CodePoint> {
    if i + 4 > raw.len() {
        return None;
    }
    let mut r: CodePoint = 0;
    for &c in &raw[i..i + 4] {
        let d = (c as char).to_digit(16)?;
        r = (r << 4) | d as CodePoint;
    }
    Some(r)
}

struct MpPart {
    name: Vec<u8>,
    start: usize,
    end: usize,
}

/// Replaces the content of secret-named text parts of a raw multipart body.
fn redact_multipart_text(s: &[u8], boundary: &[u8], e: &Evidence) -> Vec<u8> {
    if boundary.is_empty() {
        return s.to_vec();
    }
    let delim = [b"--", boundary].concat();
    let mut parts: Vec<MpPart> = Vec::new();
    let mut pos = find(s, &delim);
    while let Some(p) = pos {
        let hdr_start = p + delim.len();
        if s[hdr_start..].starts_with(b"--") {
            break;
        }
        let next = find(&s[hdr_start..], &delim);
        let part_end = next.map_or(s.len(), |n| hdr_start + n);
        let seg = &s[hdr_start..part_end];
        let (hdr_end, sep_len) = match find(seg, b"\r\n\r\n") {
            Some(h) => (Some(h), 4),
            None => (find(seg, b"\n\n"), 2),
        };
        if let Some(hdr_end) = hdr_end {
            let (name, is_file) = disposition_of_part(&seg[..hdr_end]);
            let cs = hdr_start + hdr_end + sep_len;
            let mut ce = part_end;
            if next.is_some() {
                if ce >= cs + 2 && &s[ce - 2..ce] == b"\r\n" {
                    ce -= 2;
                } else if ce > cs && s[ce - 1] == b'\n' {
                    ce -= 1;
                }
            }
            if !is_file && !name.is_empty() {
                parts.push(MpPart {
                    name,
                    start: cs,
                    end: ce,
                });
            }
        }
        if next.is_none() {
            break;
        }
        pos = Some(part_end);
    }
    let mut e = e.clone();
    if e.kind == Kind::Body && e.counts_targets() {
        let n = parts
            .iter()
            .filter(|p| p.name == e.target && !is_redaction_marker(&s[p.start..p.end]))
            .count();
        e.multi = n > 1 || e.cut;
    }
    let mut w = BodyRewriter::new(s);
    for p in &parts {
        if !is_sensitive_field_name(&p.name) {
            continue;
        }
        let val = &s[p.start..p.end];
        if val.is_empty() || is_redaction_marker(val) {
            continue;
        }
        let mut nv = MARKER.to_vec();
        if e.kind == Kind::Body && p.name == e.target {
            if e.exact && e.multi {
                if resembles_attack_payload(val) {
                    continue;
                }
            } else {
                nv = e.named_value(val);
            }
        }
        w.replace(p.start, p.end, &nv);
    }
    w.result()
}

/// The field name of a part's headers and whether it is a file part.
fn disposition_of_part(headers: &[u8]) -> (Vec<u8>, bool) {
    let mut name = Vec::new();
    let mut is_file = false;
    for line in headers.split(|&c| c == b'\n') {
        let line = trim_whitespace(line);
        let Some(i) = line.iter().position(|&c| c == b':') else {
            continue;
        };
        let (k, v) = (&line[..i], &line[i + 1..]);
        if !eq_ignore_case(trim_whitespace(k), b"content-disposition") {
            continue;
        }
        for p in v.split(|&c| c == b';') {
            let p = trim_whitespace(p);
            let Some(j) = p.iter().position(|&c| c == b'=') else {
                continue;
            };
            let (pk, pv) = (&p[..j], &p[j + 1..]);
            let pv = trim_whitespace(pv);
            let st = pv.iter().position(|&c| c != b'"').unwrap_or(pv.len());
            let en = pv.iter().rposition(|&c| c != b'"').map_or(st, |k| k + 1);
            let pv = &pv[st..en.max(st)];
            match to_lowercase(trim_whitespace(pk)).as_slice() {
                b"name" => name = pv.to_vec(),
                b"filename" | b"filename*" => is_file = true,
                _ => {}
            }
        }
    }
    (name, is_file)
}
