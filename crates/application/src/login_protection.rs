//! Per-path login protection. Every attempt at a protected path counts, keyed by the identifier the
//! upstream may read (one value: that account; none: the client IP; several or a request not read
//! completely: the client IP plus a path-wide bucket).

use sha2::{Digest, Sha256};
use wafio_bytetext::norm::NFKD;
use wafio_bytetext::strings::{eq_ignore_case, to_lowercase, to_uppercase, trim_whitespace};
use wafio_bytetext::unicode::{
    CC, CF, ME, MN, Z, in_any_table, is_space, to_lowercase as code_point_lower,
    to_uppercase as code_point_upper,
};
use wafio_bytetext::utf8::{decode_code_point, push_code_point};
use wafio_domain::{
    ANALYZE_METHOD_POLICY, AnalysisResult, BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET, IncomingRequest,
};

use crate::analyze::{AnalyzeConfig, first_header_value, geo_client_ip, raw_query_of_uri};
use crate::deps::engine::{
    FormKeyMatcher, PathExceptionConfig, allows_method, login_scope_key, unescape_form_leniently,
};
use crate::geo::{parse_ip, to_ipv4};
use wafio_domain::multipart::{MultipartParser, ReadError, split_media_type};

const LOGIN_BODY_MAX_BYTES: usize = 128 << 10;
const LOGIN_MAX_OCCURRENCES: usize = 64;
const LOGIN_MULTIPART_MAX_PARTS: usize = 64;
const LOGIN_VALUE_MAX_BYTES: usize = 4 << 10;
const LOGIN_JSON_MAX_DEPTH: usize = 64;
const LOGIN_KEY_MAX_BYTES: usize = 128;

/// Path-wide threshold for ambiguous or unread attempts.
fn path_wide_attempt_threshold(max_attempts: i64) -> i64 {
    (10 * max_attempts).max(50)
}

/// Every governing protection counts the attempt; the first one over its limit gives the block verdict.
pub(crate) fn evaluate_login_protection(
    req: &IncomingRequest,
    excs: &[&PathExceptionConfig],
    cfg: &AnalyzeConfig,
) -> Option<AnalysisResult> {
    let store = cfg.rate_limit_store.as_ref()?;
    if excs.is_empty() {
        return None;
    }
    let mut reads: Vec<(String, LoginIdentifiers)> = Vec::new();
    let mut verdict = None;
    for exc in excs {
        if let Some(res) = enforce_login_protection(req, exc, cfg, store.as_ref(), &mut reads)
            && verdict.is_none()
        {
            verdict = Some(res);
        }
    }
    verdict
}

fn enforce_login_protection(
    req: &IncomingRequest,
    exc: &PathExceptionConfig,
    cfg: &AnalyzeConfig,
    store: &dyn crate::ratelimit::RateLimitStore,
    reads: &mut Vec<(String, LoginIdentifiers)>,
) -> Option<AnalysisResult> {
    let lp = exc
        .login_protection
        .as_ref()
        .expect("login exception without login_protection");
    if !allows_method(&lp.methods, &req.method) {
        return None;
    }
    let scope = login_scope_key(&cfg.project_id, &exc.path);

    // Without an identifier field the client IP is the default bucket.
    let mut by_ip = lp.by_ip || (!lp.by_user_agent && lp.identifier_field.is_empty());
    let mut path_wide = false;
    let mut account: Vec<u8> = Vec::new();
    if !lp.identifier_field.is_empty() {
        let ids = match reads.iter().find(|(f, _)| *f == lp.identifier_field) {
            Some((_, ids)) => ids.clone(),
            None => {
                let ids = read_identifier_values(req, &lp.identifier_field);
                reads.push((lp.identifier_field.clone(), ids.clone()));
                ids
            }
        };
        if ids.keys.is_empty() && !ids.incomplete && is_bodiless_safe_method(req) {
            return None; // not an attempt: the login page, a CORS preflight
        } else if ids.keys.len() > 1 {
            (by_ip, path_wide) = (true, true);
        } else if ids.incomplete {
            (by_ip, path_wide) = (true, true);
            if ids.keys.len() == 1 {
                account = ids.keys[0].clone();
            }
        } else if ids.load_skipped {
            by_ip = true;
            if ids.keys.len() == 1 {
                account = ids.keys[0].clone();
            }
        } else if ids.keys.is_empty() {
            by_ip = true;
        } else {
            account = ids.keys[0].clone();
        }
    }

    // Every bucket is incremented (no short-circuit).
    let bucket = |suffix: &str| [scope.as_bytes(), b"\x00", suffix.as_bytes()].concat();
    let mut tripped: Vec<&str> = Vec::new();
    if !account.is_empty()
        && !store.allow_login(
            &bucket("f"),
            &account,
            lp.max_attempts,
            lp.window_sec,
            lp.lockout_sec,
        )
    {
        tripped.push("identifier");
    }
    if by_ip
        && !store.allow_login(
            &bucket("ip"),
            &client_network_key(req),
            lp.max_attempts,
            lp.window_sec,
            lp.lockout_sec,
        )
    {
        tripped.push("ip");
    }
    if path_wide
        && !store.allow_login(
            &bucket("u"),
            b"",
            path_wide_attempt_threshold(lp.max_attempts),
            lp.window_sec,
            lp.lockout_sec,
        )
    {
        tripped.push("unread_identifier");
    }
    if lp.by_user_agent {
        let ua: &[u8] = if req.user_agent.is_empty() {
            first_header_value(&req.headers, b"User-Agent")
        } else {
            &req.user_agent
        };
        if !ua.is_empty()
            && !store.allow_login(
                &bucket("ua"),
                ua,
                lp.max_attempts,
                lp.window_sec,
                lp.lockout_sec,
            )
        {
            tripped.push("user_agent");
        }
    }
    if tripped.is_empty() {
        return None;
    }
    Some(AnalysisResult {
        action: "block".into(),
        message: b"Login attempt limit exceeded".to_vec(),
        categories: vec!["LoginProtection".into()],
        analyze_method: ANALYZE_METHOD_POLICY.into(),
        match_source: [b"path:".as_slice(), exc.path.as_bytes()].concat(),
        match_detail: format!("login_protection:{}", tripped.join(",")).into_bytes(),
        ..Default::default()
    })
}

/// The IPv4 address, or the /64 of an IPv6 client.
fn client_network_key(req: &IncomingRequest) -> Vec<u8> {
    let s = geo_client_ip(req);
    let Some(ip) = parse_ip(&s) else { return s };
    if let Some(v4) = to_ipv4(&ip) {
        return v4.to_string().into_bytes();
    }
    let std::net::IpAddr::V6(v6) = ip else {
        unreachable!("to4 covers IPv4")
    };
    let mut o = v6.octets();
    o[8..].fill(0);
    format!("{}/64", std::net::Ipv6Addr::from(o)).into_bytes()
}

/// GET, HEAD or OPTIONS without a body.
fn is_bodiless_safe_method(req: &IncomingRequest) -> bool {
    if !matches!(
        to_uppercase(&req.method).as_slice(),
        b"GET" | b"HEAD" | b"OPTIONS"
    ) {
        return false;
    }
    req.body.is_empty()
        && req.content_scan_body.as_ref().is_none_or(Vec::is_empty)
        && req.body_size == 0
        && req.body_scan_skipped.is_empty()
}

#[derive(Clone, Debug, Default)]
struct LoginIdentifiers {
    keys: Vec<Vec<u8>>,
    raws: Vec<Vec<u8>>,
    occurrences: usize,
    incomplete: bool,
    load_skipped: bool,
}

impl LoginIdentifiers {
    fn add(&mut self, v: &[u8]) {
        if self.done() {
            return;
        }
        self.occurrences += 1;
        if self.occurrences > LOGIN_MAX_OCCURRENCES {
            self.incomplete = true;
            return;
        }
        if self.raws.iter().any(|r| r == v) {
            return;
        }
        self.raws.push(v.to_vec());
        let Some(k) = normalized_bucket_key(v) else {
            return;
        };
        if !self.keys.contains(&k) {
            self.keys.push(k);
        }
    }

    /// Reading on can no longer change how the attempt counts.
    fn done(&self) -> bool {
        self.keys.len() > 1 || self.occurrences > LOGIN_MAX_OCCURRENCES
    }
}

/// The identifier's values from the query, the body (form, JSON, multipart whatever the Content-Type says)
/// and a same-named header.
fn read_identifier_values(req: &IncomingRequest, field_name: &str) -> LoginIdentifiers {
    let field = field_name.as_bytes();
    let mut c = LoginIdentifiers::default();
    let m = FormKeyMatcher::new(field_name);
    let q = raw_query_of_uri(&req.uri);
    if !q.is_empty() {
        gather_form_identifiers(q, &m, &mut c);
    }
    let mut body: &[u8] = &req.body;
    if req.body_scan_skipped == BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET {
        c.load_skipped = true;
    } else if !req.body_scan_skipped.is_empty()
        || (body.is_empty()
            && req
                .content_scan_body
                .as_ref()
                .is_some_and(|b| !b.is_empty()))
        || body.len() > LOGIN_BODY_MAX_BYTES
    {
        c.incomplete = true;
    }
    if req.body_scan_skipped.is_empty()
        && !body.is_empty()
        && body.len() <= LOGIN_BODY_MAX_BYTES
        && !c.done()
    {
        body = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(body);
        if to_lowercase(trim_whitespace(&req.content_type)).starts_with(b"multipart/") {
            gather_multipart_identifiers(&req.content_type, body, &m, &mut c);
        } else {
            let b = trim_left_ws(body);
            if b.first() == Some(&b'{') {
                gather_json_identifiers(b, field, &mut c);
            }
            gather_form_identifiers(body, &m, &mut c);
        }
    }
    let v = first_header_value(&req.headers, field);
    if !v.is_empty() {
        c.add(v);
    }
    c
}

fn trim_left_ws(b: &[u8]) -> &[u8] {
    let i = b
        .iter()
        .position(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(b.len());
    &b[i..]
}

fn cut(s: &[u8], sep: u8) -> (&[u8], &[u8]) {
    match s.iter().position(|&c| c == sep) {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, b""),
    }
}

// ── urlencoded ───────────────────────────────────────────────────────────────

/// Lenient urlencoded read; a pair holding ';' is also read as ';'-separated pairs.
fn gather_form_identifiers(mut s: &[u8], m: &FormKeyMatcher, c: &mut LoginIdentifiers) {
    while !s.is_empty() && !c.done() {
        let pair;
        (pair, s) = cut(s, b'&');
        if pair.len() < m.min_len() {
            continue;
        }
        gather_form_pair(pair, m, c);
        if !pair.contains(&b';') {
            continue;
        }
        let mut rest = pair;
        while !rest.is_empty() && !c.done() {
            let sub;
            (sub, rest) = cut(rest, b';');
            let sub = &sub[sub.iter().position(|&b| b != b' ').unwrap_or(sub.len())..];
            gather_form_pair(sub, m, c);
        }
    }
}

fn gather_form_pair(pair: &[u8], m: &FormKeyMatcher, c: &mut LoginIdentifiers) {
    if pair.is_empty() {
        return;
    }
    let (k, v) = cut(pair, b'=');
    if m.matches(k, true) {
        c.add(&unescape_form_leniently(v));
    }
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

// ── JSON ─────────────────────────────────────────────────────────────────────

/// Malformed or too deep JSON / identifier read complete.
#[derive(Debug, PartialEq)]
enum JsonStop {
    Malformed,
    Done,
}

/// A key named like the whole field at the first level and the dotted path; keys compared
/// case-insensitively after escapes; every value of a duplicated key counts.
fn gather_json_identifiers(body: &[u8], field: &[u8], c: &mut LoginIdentifiers) {
    let mut paths: Vec<Vec<Vec<u8>>> = vec![vec![field.to_vec()]];
    let segs: Vec<Vec<u8>> = field.split(|&b| b == b'.').map(<[u8]>::to_vec).collect();
    if segs.len() > 1 {
        paths.push(segs);
    }
    let mut s = JsonIdentScanner {
        b: body,
        i: 0,
        paths: &paths,
        c,
    };
    let all = (1u8 << paths.len()) - 1;
    match s.value(0, all, 0) {
        Err(JsonStop::Done) => {}
        Err(JsonStop::Malformed) => s.c.incomplete = true,
        Ok(()) => {
            s.ws();
            if s.i != s.b.len() {
                s.c.incomplete = true;
            }
        }
    }
}

struct JsonIdentScanner<'a, 'c> {
    b: &'a [u8],
    i: usize,
    paths: &'a [Vec<Vec<u8>>],
    c: &'c mut LoginIdentifiers,
}

impl JsonIdentScanner<'_, '_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }

    fn peek(&self) -> u8 {
        self.b.get(self.i).copied().unwrap_or(0)
    }

    fn value(&mut self, depth: usize, active: u8, leaf: u8) -> Result<(), JsonStop> {
        self.ws();
        if leaf != 0 {
            let start = self.i;
            self.value(depth, 0, 0)?;
            let b = self.b;
            capture(&b[start..self.i], self.c);
            if self.c.done() {
                return Err(JsonStop::Done);
            }
            return Ok(());
        }
        match self.peek() {
            b'{' => self.object(depth, active),
            b'[' => self.array(depth),
            b'"' => self.str().map(|_| ()),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            _ => self.number(),
        }
    }

    fn object(&mut self, depth: usize, active: u8) -> Result<(), JsonStop> {
        if depth >= LOGIN_JSON_MAX_DEPTH {
            return Err(JsonStop::Malformed);
        }
        self.i += 1;
        self.ws();
        if self.peek() == b'}' {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.ws();
            if self.peek() != b'"' {
                return Err(JsonStop::Malformed);
            }
            let start = self.i;
            let escaped = self.str()?;
            let (mut child_active, mut child_leaf) = (0, 0);
            if active != 0 {
                (child_active, child_leaf) = self.descend(start, escaped, depth, active);
            }
            self.ws();
            if self.peek() != b':' {
                return Err(JsonStop::Malformed);
            }
            self.i += 1;
            self.value(depth + 1, child_active, child_leaf)?;
            self.ws();
            match self.peek() {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(JsonStop::Malformed),
            }
        }
    }

    /// Matches the quoted key at depth against the active paths.
    fn descend(&self, start: usize, escaped: bool, depth: usize, active: u8) -> (u8, u8) {
        let quoted = &self.b[start..self.i];
        let decoded;
        let key: &[u8] = if escaped {
            match wafio_domain::json_text::unquote_json_string(quoted) {
                Some(k) => {
                    decoded = k;
                    &decoded
                }
                None => return (0, 0),
            }
        } else {
            &quoted[1..quoted.len() - 1]
        };
        let (mut child_active, mut child_leaf) = (0u8, 0u8);
        for (p, path) in self.paths.iter().enumerate() {
            let bit = 1u8 << p;
            if active & bit == 0 || depth >= path.len() || !eq_ignore_case(key, &path[depth]) {
                continue;
            }
            if depth + 1 == path.len() {
                child_leaf |= bit;
            } else {
                child_active |= bit;
            }
        }
        (child_active, child_leaf)
    }

    fn array(&mut self, depth: usize) -> Result<(), JsonStop> {
        if depth >= LOGIN_JSON_MAX_DEPTH {
            return Err(JsonStop::Malformed);
        }
        self.i += 1;
        self.ws();
        if self.peek() == b']' {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.value(depth + 1, 0, 0)?;
            self.ws();
            match self.peek() {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(JsonStop::Malformed),
            }
        }
    }

    /// Scans a string from its opening quote; reports whether it holds escapes.
    fn str(&mut self) -> Result<bool, JsonStop> {
        self.i += 1;
        let mut escaped = false;
        while self.i < self.b.len() {
            let c = self.b[self.i];
            if c == b'"' {
                self.i += 1;
                return Ok(escaped);
            } else if c == b'\\' {
                escaped = true;
                match self.b.get(self.i + 1) {
                    None => return Err(JsonStop::Malformed),
                    Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => self.i += 2,
                    Some(b'u') => {
                        if self.i + 5 >= self.b.len()
                            || !self.b[self.i + 2..self.i + 6].iter().all(|&h| is_hex(h))
                        {
                            return Err(JsonStop::Malformed);
                        }
                        self.i += 6;
                    }
                    Some(_) => return Err(JsonStop::Malformed),
                }
            } else if c < 0x20 {
                return Err(JsonStop::Malformed);
            } else {
                self.i += 1;
            }
        }
        Err(JsonStop::Malformed)
    }

    fn literal(&mut self, lit: &[u8]) -> Result<(), JsonStop> {
        if !self.b[self.i..].starts_with(lit) {
            return Err(JsonStop::Malformed);
        }
        self.i += lit.len();
        Ok(())
    }

    fn number(&mut self) -> Result<(), JsonStop> {
        let start = self.i;
        let mut digits = false;
        while self.i < self.b.len() {
            let c = self.b[self.i];
            if c.is_ascii_digit() {
                digits = true;
            } else if !matches!(c, b'-' | b'+' | b'.' | b'e' | b'E') {
                break;
            }
            self.i += 1;
        }
        if !digits || self.i == start {
            return Err(JsonStop::Malformed);
        }
        Ok(())
    }
}

/// A string as is, a number in one canonical form, a boolean as its literal, a one-element array as its
/// element; null and [] carry nothing; an object or longer array makes the attempt incomplete.
fn capture(raw: &[u8], c: &mut LoginIdentifiers) {
    match raw[0] {
        b'"' => {
            if !raw.contains(&b'\\') {
                c.add(&raw[1..raw.len() - 1]);
            } else if let Some(v) = wafio_domain::json_text::unquote_json_string(raw) {
                c.add(&v);
            }
        }
        b'n' => {}
        b't' | b'f' => c.add(raw),
        b'{' => c.incomplete = true,
        b'[' => {
            let paths: Vec<Vec<Vec<u8>>> = Vec::new();
            let mut sub = JsonIdentScanner {
                b: raw,
                i: 1,
                paths: &paths,
                c,
            };
            sub.ws();
            if sub.peek() == b']' {
                return;
            }
            let start = sub.i;
            if sub.value(1, 0, 0).is_err() {
                sub.c.incomplete = true;
                return;
            }
            let end = sub.i;
            sub.ws();
            let elem = &raw[start..end];
            if sub.i != raw.len() - 1 || elem[0] == b'[' || elem[0] == b'{' {
                sub.c.incomplete = true;
                return;
            }
            capture(elem, sub.c);
        }
        _ => match parse_json_number(raw) {
            Some(f) => c.add(format!("{f}").as_bytes()),
            None => c.add(raw),
        },
    }
}

/// Parses a JSON number token (digits, sign, '.', exponent) as an f64: None on a syntax error or overflow.
// shortcut: Rust's float grammar for this alphabet; revisit if
// the scanner ever hands it other bytes.
fn parse_json_number(raw: &[u8]) -> Option<f64> {
    let f: f64 = std::str::from_utf8(raw).ok()?.parse().ok()?;
    f.is_finite().then_some(f)
}

// ── multipart ────────────────────────────────────────────────────────────────

/// The non-file parts named like the identifier; malformed or more than LOGIN_MULTIPART_MAX_PARTS parts =
/// incomplete.
fn gather_multipart_identifiers(
    content_type: &[u8],
    body: &[u8],
    m: &FormKeyMatcher,
    c: &mut LoginIdentifiers,
) {
    let boundary = match split_media_type(content_type) {
        Some((_, params)) => params.get(&b"boundary"[..]).cloned().unwrap_or_default(),
        None => Vec::new(),
    };
    if boundary.is_empty() {
        c.incomplete = true;
        return;
    }
    let mut mr = MultipartParser::new(body, &boundary);
    let mut n = 0;
    while !c.done() {
        if n == LOGIN_MULTIPART_MAX_PARTS {
            c.incomplete = true;
            return;
        }
        n += 1;
        let mut part = match mr.next_decoded_part() {
            Ok(p) => p,
            Err(ReadError::Eof) => return,
            Err(_) => {
                c.incomplete = true;
                return;
            }
        };
        let name = part.form_field_name();
        if !name.is_empty() && part.client_file_name().is_empty() && m.matches(&name, false) {
            // Reads the part up to LOGIN_VALUE_MAX_BYTES, errors ignored.
            let mut v = vec![0u8; LOGIN_VALUE_MAX_BYTES];
            let mut got = 0;
            while got < v.len() {
                let (k, err) = mr.part_read(&mut v[got..]);
                got += k;
                if err.is_some() || k == 0 {
                    break;
                }
            }
            v.truncate(got);
            c.add(&v);
        }
        mr.part_close();
    }
}

// ── bucket key ───────────────────────────────────────────────────────────────

/// NFKD, combining marks, format/control characters and white space dropped, case folded; a long key as its
/// SHA-256.
fn normalized_bucket_key(v: &[u8]) -> Option<Vec<u8>> {
    let d = NFKD.normalize(v);
    let mut b = Vec::with_capacity(d.len());
    let mut i = 0;
    while i < d.len() {
        let (r, w) = decode_code_point(&d[i..]);
        i += w;
        if in_any_table(r, &[MN, ME, CF, CC, Z]) || is_space(r) {
            continue;
        }
        append_fold(&mut b, r);
    }
    if b.is_empty() {
        return None;
    }
    if b.len() > LOGIN_KEY_MAX_BYTES {
        let sum = Sha256::digest(&b);
        let hex: String = sum.iter().map(|x| format!("{x:02x}")).collect();
        return Some(format!("sha256:{hex}").into_bytes());
    }
    Some(b)
}

/// Unicode full case folding of one rune.
// shortcut: simple folding through upper→lower plus the common full-folding
// expansions; generate the complete case folding table if the conformance tests show a gap.
fn append_fold(out: &mut Vec<u8>, r: i32) {
    let full: Option<&[i32]> = match r {
        0x00DF | 0x1E9E => Some(&[0x73, 0x73]),
        0x0130 => Some(&[0x69, 0x307]),
        0x0149 => Some(&[0x2BC, 0x6E]),
        0xFB00 => Some(&[0x66, 0x66]),
        0xFB01 => Some(&[0x66, 0x69]),
        0xFB02 => Some(&[0x66, 0x6C]),
        0xFB03 => Some(&[0x66, 0x66, 0x69]),
        0xFB04 => Some(&[0x66, 0x66, 0x6C]),
        0xFB05 | 0xFB06 => Some(&[0x73, 0x74]),
        _ => None,
    };
    if let Some(rs) = full {
        rs.iter().for_each(|&x| push_code_point(out, x));
        return;
    }
    // Cherokee folds to upper case.
    if (0xAB70..=0xABBF).contains(&r) || (0x13F8..=0x13FD).contains(&r) {
        push_code_point(out, code_point_upper(r));
        return;
    }
    push_code_point(out, code_point_lower(code_point_upper(r)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_key() {
        assert_eq!(normalized_bucket_key(b"Admin"), Some(b"admin".to_vec()));
        assert_eq!(
            normalized_bucket_key("ａｄｍｉｎ".as_bytes()),
            Some(b"admin".to_vec())
        );
        assert_eq!(
            normalized_bucket_key("Ádmin \u{200b}".as_bytes()),
            Some(b"admin".to_vec())
        );
        assert_eq!(
            normalized_bucket_key("STRAßE".as_bytes()),
            Some(b"strasse".to_vec())
        );
        assert_eq!(normalized_bucket_key(b"  \t"), None);
        let long = vec![b'a'; 200];
        assert!(
            normalized_bucket_key(&long)
                .unwrap()
                .starts_with(b"sha256:")
        );
    }

    #[test]
    fn json_capture() {
        let mut c = LoginIdentifiers::default();
        gather_json_identifiers(
            br#"{"user":{"Email":"a@x"},"USER.email":"b@x"}"#,
            b"user.email",
            &mut c,
        );
        assert_eq!(c.keys, vec![b"a@x".to_vec(), b"b@x".to_vec()]);
        assert!(!c.incomplete);

        let mut c = LoginIdentifiers::default();
        gather_json_identifiers(br#"{"id": 1.234e3, "x": [1, {"a": null}]}"#, b"id", &mut c);
        assert_eq!(c.keys, vec![b"1234".to_vec()]);
        assert!(!c.incomplete);

        let mut c = LoginIdentifiers::default();
        gather_json_identifiers(br#"{"u": ["admin"]}"#, b"u", &mut c);
        assert_eq!(c.keys, vec![b"admin".to_vec()]);

        let mut c = LoginIdentifiers::default();
        gather_json_identifiers(br#"{"u": {"a": 1}}"#, b"u", &mut c);
        assert!(c.incomplete);

        let mut c = LoginIdentifiers::default();
        gather_json_identifiers(br#"{"u": "a" "#, b"u", &mut c);
        assert!(c.incomplete);

        let mut c = LoginIdentifiers::default();
        gather_json_identifiers(br#"{"u": "esc"} trailing"#, b"u", &mut c);
        assert_eq!(c.keys, vec![b"esc".to_vec()]);
        assert!(c.incomplete);
    }

    #[test]
    fn multipart_identifier() {
        let m = FormKeyMatcher::new("user");
        let body = b"--XX\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n--XX\r\nContent-Disposition: form-data; name=\"user\"; filename=\"a.txt\"\r\n\r\nfile\r\n--XX--\r\n";
        let mut c = LoginIdentifiers::default();
        gather_multipart_identifiers(b"multipart/form-data; boundary=XX", body, &m, &mut c);
        assert_eq!(c.keys, vec![b"alice".to_vec()]);
        assert!(!c.incomplete);
        let mut c = LoginIdentifiers::default();
        gather_multipart_identifiers(b"multipart/form-data", body, &m, &mut c);
        assert!(c.incomplete);
    }

    #[test]
    fn client_key() {
        let req = |a: &str| IncomingRequest {
            remote_address: a.as_bytes().to_vec(),
            ..Default::default()
        };
        assert_eq!(client_network_key(&req("192.0.2.1:5")), b"192.0.2.1");
        assert_eq!(
            client_network_key(&req("[2001:db8:1:2:3:4:5:6]:5")),
            b"2001:db8:1:2::/64"
        );
        assert_eq!(client_network_key(&req("::ffff:192.0.2.1")), b"192.0.2.1");
        assert_eq!(client_network_key(&req("junk")), b"junk");
    }

    #[test]
    fn identifiers_dedupe_and_cap() {
        let mut c = LoginIdentifiers::default();
        c.add(b"Admin");
        c.add(b"admin");
        assert_eq!(c.keys.len(), 1);
        c.add(b"other");
        assert!(c.done());
        let mut c = LoginIdentifiers::default();
        for _ in 0..=LOGIN_MAX_OCCURRENCES {
            c.add(b"same");
        }
        assert!(c.incomplete);
    }
}
