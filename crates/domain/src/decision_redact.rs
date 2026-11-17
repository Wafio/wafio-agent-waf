//! Decision secret redaction of request headers, query strings and URIs. Idempotent: redacting an already
//! redacted decision with the same evidence changes nothing. Body redaction is in `decision_redact_body`.

use std::collections::BTreeMap;

use crate::decision_redact_body::unescape_json_string;
use crate::request::AnalysisResult;
use crate::text_helpers::{
    eq_ignore_case, to_lowercase, trim_whitespace, unescape_query_component,
};
use wafio_bytetext::url::unescape_path_segment;

/// Replaces a credential value; the name is kept.
pub const DECISION_REDACTED_MARKER: &str = "[redacted]";
const MARKER: &[u8] = DECISION_REDACTED_MARKER.as_bytes();
/// Starts the reduced form of a credential flagged by a credential check.
const REDACTED_LEN_PREFIX: &[u8] = b"[redacted:len=";
/// What a mask field rule writes into the body preview.
const FIELD_MASKED_MARKER: &[u8] = b"[MASKED]";
/// Caps the JWT header segment kept from an Authorization value.
const MAX_KEPT_AUTH_HEADER_SEGMENT: usize = 1024;

const SECRET_EXACT_NAMES: &[&[u8]] = &[
    b"key", b"x-key", b"sig", b"x-sig", b"auth", b"x-auth", b"pass", b"x-pass", b"ticket", b"code",
];

const SECRET_WORDS: &[&[u8]] = &[
    b"pwd", b"pw", b"sid", b"otp", b"totp", b"pin", b"cvv", b"cvv2", b"cvc", b"ssn",
];

const SECRET_SUBSTRINGS: &[&[u8]] = &[
    b"token",
    b"secret",
    b"password",
    b"passwd",
    b"passphrase",
    b"apikey",
    b"accesskey",
    b"privatekey",
    b"clientkey",
    b"licensekey",
    b"masterkey",
    b"signingkey",
    b"encryptionkey",
    b"subscriptionkey",
    b"functionskey",
    b"authkey",
    b"signature",
    b"hmac",
    b"credential",
    b"session",
    b"sessid",
    b"csrf",
    b"xsrf",
    b"authorization",
    b"jwt",
    b"bearer",
    b"passcode",
    b"authcode",
    b"samlresponse",
    b"samlrequest",
    b"cardnumber",
    b"creditcard",
    b"ccnum",
];

/// Reports whether a header, query parameter, cookie, form field or JSON key
/// name is one whose value is treated as a credential in a stored decision.
pub fn is_sensitive_field_name(name: &[u8]) -> bool {
    let name = trim_whitespace(name);
    if name.is_empty() {
        return false;
    }
    let mut norm = Vec::with_capacity(name.len());
    let mut compact = Vec::with_capacity(name.len());
    for &c in name {
        let c = match c {
            b'A'..=b'Z' => c + 32,
            b'_' | b'.' | b' ' | b'[' | b']' => b'-',
            c => c,
        };
        norm.push(c);
        if c != b'-' {
            compact.push(c);
        }
    }
    let st = norm.iter().position(|&c| c != b'-').unwrap_or(norm.len());
    let en = norm.iter().rposition(|&c| c != b'-').map_or(st, |i| i + 1);
    let norm = &norm[st..en.max(st)];
    if SECRET_EXACT_NAMES.contains(&norm) {
        return true;
    }
    if norm
        .split(|&c| c == b'-')
        .any(|w| !w.is_empty() && SECRET_WORDS.contains(&w))
    {
        return true;
    }
    (0..compact.len()).any(|i| {
        SECRET_SUBSTRINGS
            .iter()
            .any(|s| compact[i..].starts_with(s))
    })
}

/// The request input a decision names as its evidence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MatchEvidence {
    pub source: Vec<u8>,
    /// An engine named that input itself (typed marker, never inferred).
    pub exact: bool,
    /// The verdict of a check whose flagged value can be a real credential.
    pub credential: bool,
    /// The decoded value of the flagged part (WAF agent only).
    pub flagged: Option<Vec<u8>>,
}

impl AnalysisResult {
    /// The MatchEvidence of an analysis result, its flagged value included.
    pub fn evidence(&self) -> MatchEvidence {
        let mut m = decision_evidence(
            &self.match_source,
            self.match_source_exact,
            &self.categories,
        );
        if self.match_source_exact {
            m.flagged = self.match_value.clone();
        }
        m
    }
}

/// The evidence of a guessed (or unknown) match source.
pub fn inferred_match_evidence(source: &[u8]) -> MatchEvidence {
    MatchEvidence {
        source: source.to_vec(),
        ..Default::default()
    }
}

/// The evidence of a decision.
pub fn decision_evidence<S: AsRef<str>>(
    source: &[u8],
    exact: bool,
    categories: &[S],
) -> MatchEvidence {
    MatchEvidence {
        source: source.to_vec(),
        exact,
        credential: has_credential_category(categories),
        flagged: None,
    }
}

const CREDENTIAL_CATEGORIES: [&str; 2] = ["JWT", "Anomaly"];

/// Reports whether a decision with these categories comes from a
/// credential-type check.
pub fn has_credential_category<S: AsRef<str>>(categories: &[S]) -> bool {
    categories.iter().any(|c| {
        CREDENTIAL_CATEGORIES
            .iter()
            .any(|cc| eq_ignore_case(trim_whitespace(c.as_ref().as_bytes()), cc.as_bytes()))
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Kind {
    #[default]
    None,
    Header,
    Query,
    /// The parameter NAME was the payload.
    QueryName,
    Cookie,
    /// A form/multipart field or a JSON key of the body.
    Body,
}

/// A parsed MatchEvidence.
#[derive(Clone, Debug, Default)]
pub(crate) struct Evidence {
    pub(crate) kind: Kind,
    pub(crate) target: Vec<u8>,
    pub(crate) multi: bool,
    pub(crate) exact: bool,
    pub(crate) cred: bool,
    pub(crate) flagged: Vec<u8>,
    pub(crate) value_known: bool,
    pub(crate) cut: bool,
}

impl MatchEvidence {
    pub(crate) fn parse(&self) -> Evidence {
        let (kind, target, multi) = parse_match_source_targets(&self.source);
        let mut e = Evidence {
            kind,
            target,
            multi,
            exact: self.exact,
            cred: self.credential,
            ..Default::default()
        };
        if self.exact
            && let Some(f) = &self.flagged
        {
            e.flagged = f.clone();
            e.value_known = true;
        }
        e
    }
}

impl Evidence {
    /// Whether the target's values must be counted to know which was flagged.
    pub(crate) fn counts_targets(&self) -> bool {
        self.exact && !self.multi && !self.value_known && is_sensitive_field_name(&self.target)
    }

    /// What a secret-named value the evidence names is stored as.
    pub(crate) fn named_value(&self, v: &[u8]) -> Vec<u8> {
        if is_redaction_marker(v) {
            return v.to_vec();
        }
        if !self.exact || (self.value_known && !self.is_flagged(v)) {
            return MARKER.to_vec();
        }
        if self.cred {
            return shorten_credential_value(v);
        }
        v.to_vec()
    }

    /// Whether a stored value is the flagged value: as is, trimmed, or
    /// decoded as the engine decoded it.
    fn is_flagged(&self, v: &[u8]) -> bool {
        if !self.value_known {
            return false;
        }
        let f = self.flagged.as_slice();
        if v == f || trim_whitespace(v) == trim_whitespace(f) {
            return true;
        }
        let mut d = v.to_vec();
        if d.contains(&b'\\')
            && let Some(u) = unescape_json_string(&d)
        {
            if u == f {
                return true;
            }
            d = u;
        }
        for _ in 0..2 {
            if !d.contains(&b'%') && !d.contains(&b'+') {
                break;
            }
            match unescape_query_component(&d) {
                Ok(u) if u != d => {
                    if u == f {
                        return true;
                    }
                    d = u;
                }
                _ => break,
            }
        }
        false
    }
}

fn cut_prefix<'a>(s: &'a [u8], p: &[u8]) -> Option<&'a [u8]> {
    s.strip_prefix(p)
}

/// Parses a match source.
pub(crate) fn parse_match_source_targets(ms: &[u8]) -> (Kind, Vec<u8>, bool) {
    let none = (Kind::None, Vec::new(), false);
    let ms = trim_whitespace(ms);
    let Some(i) = ms.iter().position(|&c| c == b':') else {
        return none;
    };
    if i == 0 || i == ms.len() - 1 {
        return none;
    }
    let (prefix, rest) = (to_lowercase(&ms[..i]), &ms[i + 1..]);
    match prefix.as_slice() {
        b"header" | b"request_headers" => (Kind::Header, rest.to_vec(), false),
        b"cookie" | b"request_cookies" => (Kind::Cookie, rest.to_vec(), false),
        b"args_get" | b"args" => (Kind::Query, rest.to_vec(), false),
        b"query" => {
            if let Some(n) = cut_prefix(rest, b"hpp:").filter(|n| !n.is_empty()) {
                return (Kind::Query, n.to_vec(), true);
            }
            if let Some(n) = cut_prefix(rest, b"name:").filter(|n| !n.is_empty()) {
                return (Kind::QueryName, n.to_vec(), false);
            }
            (Kind::Query, rest.to_vec(), false)
        }
        b"body" => {
            if let Some(n) = cut_prefix(rest, b"hpp:").filter(|n| !n.is_empty()) {
                return (Kind::Body, n.to_vec(), true);
            }
            if rest.starts_with(b"name:") {
                return none;
            }
            for suf in [&b":filename"[..], b":filecontent"] {
                if let Some(n) = rest.strip_suffix(suf).filter(|n| !n.is_empty()) {
                    return (Kind::Body, n.to_vec(), false);
                }
            }
            (Kind::Body, rest.to_vec(), false)
        }
        b"body.json" => (Kind::Body, rest.to_vec(), false),
        _ => none,
    }
}

/// Reports a value this module wrote.
pub(crate) fn is_redaction_marker(v: &[u8]) -> bool {
    if v == MARKER || v == FIELD_MASKED_MARKER {
        return true;
    }
    if let Some(digits) = v.strip_prefix(REDACTED_LEN_PREFIX)
        && let Some(digits) = digits.strip_suffix(b"]")
        && !digits.is_empty()
        && digits.iter().all(u8::is_ascii_digit)
    {
        return true;
    }
    if let Some(seg) = v.strip_suffix(b".[redacted]") {
        return is_jwt_header_part(seg);
    }
    false
}

fn is_jwt_header_part(seg: &[u8]) -> bool {
    seg.len() >= 3
        && seg.len() <= MAX_KEPT_AUTH_HEADER_SEGMENT
        && seg.starts_with(b"eyJ")
        && seg
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn split_once(s: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    s.iter()
        .position(|&c| c == sep)
        .map(|i| (&s[..i], &s[i + 1..]))
}

fn shorten_credential_value(v: &[u8]) -> Vec<u8> {
    let t = trim_whitespace(v);
    if is_redaction_marker(t) {
        return t.to_vec();
    }
    if let Some((seg, _)) = split_once(t, b'.')
        && is_jwt_header_part(seg)
    {
        return [seg, b".", MARKER].concat();
    }
    [REDACTED_LEN_PREFIX, v.len().to_string().as_bytes(), b"]"].concat()
}

const URL_VALUED_HEADERS: [&str; 5] = [
    "Referer",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-URI",
    "X-Original-URI",
];

fn is_url_header(k: &[u8]) -> bool {
    URL_VALUED_HEADERS
        .iter()
        .any(|n| eq_ignore_case(k, n.as_bytes()))
}

fn header_named(k: &[u8], name: &[u8]) -> bool {
    eq_ignore_case(trim_whitespace(k), name)
}

/// A decision's flattened request headers.
pub type DecisionHeaders = BTreeMap<Vec<u8>, Vec<u8>>;

/// Redacts a decision's flattened request headers; None when nothing is left.
pub fn redact_stored_headers(mut h: DecisionHeaders, m: &MatchEvidence) -> Option<DecisionHeaders> {
    if h.is_empty() {
        return None;
    }
    let e = m.parse();
    let named = |k: &[u8]| {
        e.kind == Kind::Header && eq_ignore_case(trim_whitespace(&e.target), trim_whitespace(k))
    };
    let keys: Vec<Vec<u8>> = h.keys().cloned().collect();
    for k in keys {
        let v = h[&k].clone();
        if header_named(&k, b"authorization") || header_named(&k, b"proxy-authorization") {
            if named(&k) {
                h.insert(k, shorten_authorization(&v));
            } else {
                h.remove(&k);
            }
        } else if header_named(&k, b"set-cookie") {
            h.remove(&k);
        } else if header_named(&k, b"cookie") {
            let kept = if e.kind == Kind::Cookie {
                cookie_by_name(&v, &e)
            } else if named(&k) {
                redact_cookie_values(&v, e.exact)
            } else {
                Vec::new()
            };
            if kept.is_empty() {
                h.remove(&k);
            } else {
                h.insert(k, kept);
            }
        } else if named(&k) && is_url_header(trim_whitespace(&k)) {
            let nv = redact_request_uri(&v, &Evidence::default(), e.exact);
            h.insert(k, nv);
        } else if named(&k) && is_sensitive_field_name(&k) {
            let nv = if e.exact && v.contains(&b',') {
                keep_payload_like_elements(&v)
            } else {
                e.named_value(&v)
            };
            h.insert(k, nv);
        } else if named(&k) {
            // the attack evidence keeps its value
        } else if is_sensitive_field_name(&k) {
            h.insert(k, MARKER.to_vec());
        } else if is_url_header(trim_whitespace(&k)) {
            let nv = redact_request_uri(&v, &Evidence::default(), false);
            h.insert(k, nv);
        }
    }
    if h.is_empty() { None } else { Some(h) }
}

fn cookie_by_name(v: &[u8], e: &Evidence) -> Vec<u8> {
    let pairs = split_named_cookie_pairs(v, &e.target);
    if pairs.is_empty() {
        return Vec::new();
    }
    if !is_sensitive_field_name(&e.target) {
        return pairs.join(&b"; "[..]);
    }
    if pairs.len() > 1 || !e.exact {
        return redact_cookie_values(&pairs.join(&b"; "[..]), e.exact);
    }
    match split_once(pairs[0], b'=') {
        None => redact_cookie_values(pairs[0], e.exact),
        Some((n, val)) => [n, b"=", &e.named_value(val)].concat(),
    }
}

fn shorten_authorization(v: &[u8]) -> Vec<u8> {
    let v = trim_whitespace(v);
    let Some((scheme, cred)) = split_once(v, b' ') else {
        return MARKER.to_vec();
    };
    if scheme.is_empty() {
        return MARKER.to_vec();
    }
    if eq_ignore_case(scheme, b"bearer") {
        let cred = trim_whitespace(cred);
        if let Some((seg, _)) = split_once(cred, b'.')
            && is_jwt_header_part(seg)
        {
            return [scheme, b" ", seg, b".", MARKER].concat();
        }
    }
    [scheme, b" ", MARKER].concat()
}

fn keep_payload_like_elements(v: &[u8]) -> Vec<u8> {
    if !v.contains(&b',') {
        return if resembles_attack_payload(v) {
            v.to_vec()
        } else {
            MARKER.to_vec()
        };
    }
    let mut kept = false;
    let parts: Vec<Vec<u8>> = v
        .split(|&c| c == b',')
        .map(|p| {
            let p = trim_whitespace(p);
            if resembles_attack_payload(p) {
                kept = true;
                p.to_vec()
            } else {
                MARKER.to_vec()
            }
        })
        .collect();
    if !kept {
        return MARKER.to_vec();
    }
    parts.join(&b", "[..])
}

fn split_cookie_pairs(v: &[u8]) -> Vec<&[u8]> {
    v.split(|&c| c == b';')
        .map(trim_whitespace)
        .filter(|p| !p.is_empty())
        .collect()
}

fn split_named_cookie_pairs<'a>(v: &'a [u8], name: &[u8]) -> Vec<&'a [u8]> {
    let name = trim_whitespace(name);
    if name.is_empty() {
        return Vec::new();
    }
    split_cookie_pairs(v)
        .into_iter()
        .filter(|p| {
            let n = split_once(p, b'=').map_or(*p, |(n, _)| n);
            trim_whitespace(n) == name
        })
        .collect()
}

/// Keeps every cookie by name and its value only when it looks like an
/// injection payload (an exactly named Cookie header).
pub fn keep_suspicious_cookie_values(v: &[u8]) -> Vec<u8> {
    redact_cookie_values(v, true)
}

/// As keep_suspicious_cookie_values for a guessed Cookie header: secret-named
/// cookie values are redacted even when they look like a payload.
pub fn redact_guessed_cookie(v: &[u8]) -> Vec<u8> {
    redact_cookie_values(v, false)
}

fn redact_cookie_values(v: &[u8], secret_payload_kept: bool) -> Vec<u8> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for p in split_cookie_pairs(v) {
        let Some((n, val)) = split_once(p, b'=') else {
            if resembles_attack_payload(p) {
                out.push(p.to_vec());
            }
            continue;
        };
        let keep =
            resembles_attack_payload(val) && (secret_payload_kept || !is_sensitive_field_name(n));
        if keep || is_redaction_marker(val) {
            out.push(p.to_vec());
        } else {
            out.push([n, b"=", MARKER].concat());
        }
    }
    out.join(&b"; "[..])
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    memchr::memmem::find(h, n).is_some()
}

fn header_value_looks_suspicious(v: &[u8]) -> bool {
    if v.is_empty() {
        return false;
    }
    let lower = to_lowercase(v);
    let l = |n: &[u8]| contains(&lower, n);
    if l(b"<")
        || l(b"%3c")
        || l(b"%3e")
        || l(b"script")
        || l(b"javascript:")
        || l(b"onerror=")
        || l(b"onload=")
        || l(b"onclick=")
        || l(b"alert(")
        || l(b"confirm(")
    {
        return true;
    }
    if l(b"union ")
        || l(b"select ")
        || l(b"insert ")
        || l(b"delete ")
        || l(b"drop ")
        || l(b"sleep(")
        || l(b"benchmark(")
        || l(b"--")
        || l(b"/*")
        || l(b"*/")
    {
        return true;
    }
    if (contains(v, b"'") || contains(v, b"\""))
        && (l(b" or ") || l(b" and ") || l(b"=") || l(b";"))
    {
        return true;
    }
    contains(v, b"%25") || contains(v, b"&#")
}

/// Reports whether a header, parameter or cookie value carries injection
/// syntax (token-shaped values never do unless they hold "../").
pub fn resembles_attack_payload(v: &[u8]) -> bool {
    let v = trim_whitespace(v);
    if v.is_empty() || is_redaction_marker(v) {
        return false;
    }
    if has_token_shape(v) {
        return contains(v, b"../");
    }
    if v.contains(&b'%')
        && let Ok(dec) = unescape_path_segment(v)
        && has_token_shape(&dec)
    {
        return contains(&dec, b"../");
    }
    let decoded = unescape_query_component(v).unwrap_or_else(|_| v.to_vec());
    header_value_looks_suspicious(v)
        || header_value_looks_suspicious(&decoded)
        || has_strong_attack_shape(&decoded)
}

const STRONG_ATTACK_MARKERS: [&[u8]; 8] = [
    b"${", b"{{", b"$(", b"`", b"../", b"..\\", b"\x00", b"jndi:",
];

fn has_strong_attack_shape(v: &[u8]) -> bool {
    STRONG_ATTACK_MARKERS.iter().any(|m| contains(v, m))
}

fn has_token_shape(v: &[u8]) -> bool {
    let v = if v.len() >= 2 && v[0] == b'"' && v[v.len() - 1] == b'"' {
        &v[1..v.len() - 1]
    } else {
        v
    };
    !v.is_empty()
        && v.iter()
            .all(|&c| c.is_ascii_alphanumeric() || b"+/=_-.~:".contains(&c))
}

/// The match source of a verdict whose engine did not name the input: the
/// first non-secret query parameter whose value looks like a payload, else
/// "query".
pub fn infer_query_match_source(raw_query: &[u8]) -> Vec<u8> {
    for pair in raw_query.split(|&c| c == b'&' || c == b';') {
        let Some((name, val)) = split_once(pair, b'=') else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let name = unescape_query_component(name).unwrap_or_else(|_| name.to_vec());
        if name.is_empty() || is_sensitive_field_name(&name) || !resembles_attack_payload(val) {
            continue;
        }
        return [b"query:", name.as_slice()].concat();
    }
    b"query".to_vec()
}

/// Replaces the values of secret-named parameters of a raw query string.
pub fn redact_stored_query(q: &[u8], m: &MatchEvidence) -> Vec<u8> {
    redact_query_pairs(q, &m.parse(), Kind::Query, false)
}

/// Redacts secret-named values of q ('&' or ';' separated pairs; a form body
/// uses pair_kind Body).
pub(crate) fn redact_query_pairs(
    q: &[u8],
    e: &Evidence,
    pair_kind: Kind,
    keep_payload: bool,
) -> Vec<u8> {
    if q.is_empty() || !q.contains(&b'=') {
        return q.to_vec();
    }
    let mut e = e.clone();
    if e.kind == pair_kind && e.counts_targets() && (e.cut || count_query_pairs(q, &e.target) > 1) {
        e.multi = true;
    }
    let mut out = Vec::new();
    let mut copied = 0;
    let mut changed = false;
    let mut start = 0;
    while start <= q.len() {
        let end = q[start..]
            .iter()
            .position(|&c| c == b'&' || c == b';')
            .map_or(q.len(), |i| i + start);
        let pair = &q[start..end];
        let (name, val, ok) = match split_once(pair, b'=') {
            Some((n, v)) => (n, v, true),
            None => (pair, &b""[..], false),
        };
        if let Some(nv) = value_of_query_pair(name, val, ok, &e, pair_kind, keep_payload) {
            changed = true;
            out.extend_from_slice(&q[copied..start]);
            out.extend_from_slice(name);
            out.push(b'=');
            out.extend_from_slice(&nv);
            copied = end;
        }
        start = end + 1;
    }
    if !changed {
        return q.to_vec();
    }
    out.extend_from_slice(&q[copied..]);
    out
}

fn count_query_pairs(q: &[u8], target: &[u8]) -> usize {
    q.split(|&c| c == b'&' || c == b';')
        .filter(|p| !p.is_empty())
        .filter(|pair| {
            let (name, val) = split_once(pair, b'=').unwrap_or((pair, b""));
            if is_redaction_marker(val) {
                return false;
            }
            unescape_query_component(name).unwrap_or_else(|_| name.to_vec()) == target
        })
        .count()
}

/// One pair: None keeps it, Some(nv) stores nv as its value.
fn value_of_query_pair(
    name: &[u8],
    val: &[u8],
    has_value: bool,
    e: &Evidence,
    pair_kind: Kind,
    keep_payload: bool,
) -> Option<Vec<u8>> {
    if !has_value || val.is_empty() || is_redaction_marker(val) {
        return None;
    }
    let dn = unescape_query_component(name).unwrap_or_else(|_| name.to_vec());
    if !is_sensitive_field_name(&dn) {
        return None;
    }
    let is_target = e.kind == pair_kind && dn == e.target;
    if keep_payload || (is_target && e.exact && e.multi) {
        if resembles_attack_payload(val) {
            return None;
        }
    } else if is_target {
        let nv = e.named_value(val);
        return if nv == val { None } else { Some(nv) };
    }
    Some(MARKER.to_vec())
}

fn redact_path_parameters(p: &[u8]) -> Vec<u8> {
    if !p.contains(&b';') {
        return p.to_vec();
    }
    let mut b = Vec::with_capacity(p.len());
    let mut changed = false;
    let mut rest = p;
    loop {
        let Some(i) = rest.iter().position(|&c| c == b';') else {
            b.extend_from_slice(rest);
            break;
        };
        b.extend_from_slice(&rest[..=i]);
        rest = &rest[i + 1..];
        let end = rest
            .iter()
            .position(|&c| c == b'/' || c == b';')
            .unwrap_or(rest.len());
        let seg = &rest[..end];
        let (name, val, ok) = match split_once(seg, b'=') {
            Some((n, v)) => (n, v, true),
            None => (seg, &b""[..], false),
        };
        let dn = unescape_path_segment(name).unwrap_or_else(|_| name.to_vec());
        if ok
            && !val.is_empty()
            && !is_redaction_marker(val)
            && is_sensitive_field_name(&dn)
            && !resembles_attack_payload(val)
        {
            changed = true;
            b.extend_from_slice(name);
            b.push(b'=');
            b.extend_from_slice(MARKER);
        } else {
            b.extend_from_slice(seg);
        }
        rest = &rest[end..];
    }
    if !changed {
        return p.to_vec();
    }
    b
}

/// Applies redact_stored_query to the query part of a URI or URL and
/// redacts secret-named path parameters of its path.
pub fn redact_stored_uri(uri: &[u8], m: &MatchEvidence) -> Vec<u8> {
    redact_request_uri(uri, &m.parse(), false)
}

fn redact_request_uri(uri: &[u8], e: &Evidence, keep_payload: bool) -> Vec<u8> {
    let (path, q, has_query) = match split_once(uri, b'?') {
        Some((p, q)) => (p, q, true),
        None => (uri, &b""[..], false),
    };
    let np = redact_path_parameters(path);
    let nq = if has_query {
        redact_query_pairs(q, e, Kind::Query, keep_payload)
    } else {
        q.to_vec()
    };
    if np == path && nq == q {
        return uri.to_vec();
    }
    if !has_query {
        return np;
    }
    [np.as_slice(), b"?", nq.as_slice()].concat()
}

#[cfg(test)]
mod tests;
