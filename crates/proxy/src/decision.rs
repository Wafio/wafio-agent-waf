//! Decision events and the helpers that fill them. The sink receives every event unredacted:
//! credential redaction and the gRPC queue are the sink's (control crate).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use wafio_bytetext::strings;
use wafio_domain::Headers;

/// One WAF decision. Field names and types follow `wafio_control::DecisionEvent` so the
/// binary moves them over one to one; `mode` is a JSON-only field (never on the wire).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DecisionEvent {
    pub app_id: Vec<u8>,
    pub host: Vec<u8>,
    pub method: Vec<u8>,
    pub uri: Vec<u8>,
    pub remote_addr: Vec<u8>,
    pub user_agent: Vec<u8>,
    pub content_type: Vec<u8>,
    /// "block" | "allow" | "log" | "monitor" | "challenge" | "upstream_error".
    pub action: Vec<u8>,
    pub score: i64,
    pub categories: Vec<Vec<u8>>,
    pub cwe: Vec<u8>,
    pub match_detail: Vec<u8>,
    pub analyze_method: Vec<u8>,
    pub body_size: i64,
    pub latency_us: i64,
    pub body_preview: Vec<u8>,
    pub mode: Vec<u8>,
    /// Unix seconds of the event time.
    pub event_time_unix: i64,
    pub match_source: Vec<u8>,
    pub match_source_exact: bool,
    /// The flagged value; for redaction only, never sent.
    pub match_value: Option<Vec<u8>>,
    pub request_headers: HashMap<Vec<u8>, Vec<u8>>,
    pub request_body: Vec<u8>,
    pub query_params: Vec<u8>,
    pub payload_type: Vec<u8>,
    pub coverage: Vec<u8>,
    /// The HTTP status the client received (0 = not recorded: a WebSocket handshake event emitted
    /// before the upstream is dialled).
    pub status: i64,
}

/// The coverage string of a decision event: the verdict's gap flags, then `engine_disabled:<key>` for every detector the
/// operator switched off and `engine_log_only:<key>` for every one whose blocking detection was held back as LOG. The
/// marks are not gaps: they are not counted as partial coverage and not part of `coverage`. `engine_absent` follows them
/// when the agent has no semantic engine.
pub fn event_coverage(verdict: &wafio_domain::AnalysisResult) -> String {
    let mut out = verdict.coverage.clone();
    let marks = [
        ("engine_disabled:", &verdict.engines_off),
        ("engine_log_only:", &verdict.engines_log_only),
    ];
    for (prefix, keys) in marks {
        for key in keys {
            if !out.is_empty() {
                out.push(',');
            }
            out.push_str(prefix);
            out.push_str(key);
        }
    }
    if verdict.engine_absent {
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str("engine_absent");
    }
    out
}

/// Where decisions go: must not block.
pub type DecisionSink = Arc<dyn Fn(DecisionEvent) + Send + Sync>;

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Longest body preview, in runes.
pub const BODY_PREVIEW_LIMIT: usize = 512;
/// Longest request body capture, in bytes.
pub const REQUEST_BODY_CAPTURE_LIMIT: usize = 4096;

/// The request fields a decision event carries.
#[derive(Clone, Debug, Default)]
pub struct AnalysisRequest {
    pub method: Vec<u8>,
    pub uri: Vec<u8>,
    pub host: Vec<u8>,
    pub remote_address: Vec<u8>,
    pub user_agent: Vec<u8>,
    pub headers: Headers,
    pub body_size: i64,
    /// The audit preview copy of the body (decoded, possibly masked); None = no preview.
    pub body_preview_source: Option<Vec<u8>>,
    pub coverage: String,
}

/// The verdict fields a decision records.
#[derive(Clone, Debug, Default)]
pub struct Verdict {
    pub action: String,
    pub score: i64,
    pub categories: Vec<String>,
    pub cwe: String,
    pub match_detail: Vec<u8>,
    pub analyze_method: String,
    pub match_source: Vec<u8>,
    pub match_exact: bool,
    pub match_value: Option<Vec<u8>>,
}

pub(crate) fn emit_decision_event(
    sink: &DecisionSink,
    app_id: &str,
    mode: &str,
    req: &AnalysisRequest,
    v: &Verdict,
    latency: Duration,
    status: u16,
) {
    let ct = first_header_value(&req.headers, b"Content-Type");
    let request_body = capture_request_body(req);
    sink(DecisionEvent {
        app_id: app_id.as_bytes().to_vec(),
        host: req.host.clone(),
        method: req.method.clone(),
        uri: req.uri.clone(),
        remote_addr: req.remote_address.clone(),
        user_agent: req.user_agent.clone(),
        content_type: canonical_content_type(ct),
        action: v.action.as_bytes().to_vec(),
        score: v.score,
        categories: v.categories.iter().map(|c| c.as_bytes().to_vec()).collect(),
        cwe: v.cwe.as_bytes().to_vec(),
        match_detail: v.match_detail.clone(),
        analyze_method: v.analyze_method.as_bytes().to_vec(),
        body_size: req.body_size,
        latency_us: latency.as_micros() as i64,
        body_preview: truncate_body_preview(req),
        mode: mode.as_bytes().to_vec(),
        event_time_unix: now_unix(),
        match_source: v.match_source.clone(),
        match_source_exact: v.match_exact,
        match_value: v.match_value.clone(),
        request_headers: collect_loggable_headers(&req.headers),
        payload_type: classify_payload(ct, &request_body),
        request_body,
        query_params: capture_query_string(&req.uri),
        coverage: req.coverage.as_bytes().to_vec(),
        status: i64::from(status),
    });
}

pub(crate) fn emit_upstream_error_event(
    sink: &DecisionSink,
    app_id: &str,
    mode: &str,
    req: &AnalysisRequest,
    latency: Duration,
) {
    sink(DecisionEvent {
        app_id: app_id.as_bytes().to_vec(),
        host: req.host.clone(),
        method: req.method.clone(),
        uri: req.uri.clone(),
        remote_addr: req.remote_address.clone(),
        action: b"upstream_error".to_vec(),
        latency_us: latency.as_micros() as i64,
        mode: mode.as_bytes().to_vec(),
        event_time_unix: now_unix(),
        status: 502,
        ..Default::default()
    });
}

/// The first value of the first key equal to `name` ignoring case (Unicode lowercasing; header
/// names are ASCII once the head is parsed).
pub fn first_header_value<'a>(headers: &'a Headers, name: &[u8]) -> &'a [u8] {
    let needle = strings::to_lowercase(name);
    headers
        .iter()
        .find(|(k, v)| strings::to_lowercase(k) == needle && !v.is_empty())
        .map_or(&[][..], |(_, v)| v[0].as_slice())
}

/// The first 512 runes of the preview copy.
fn truncate_body_preview(req: &AnalysisRequest) -> Vec<u8> {
    let Some(body) = req.body_preview_source.as_deref().filter(|b| !b.is_empty()) else {
        return Vec::new();
    };
    // Invalid bytes become U+FFFD only when the body is cut.
    let (mut out, mut i, mut runes) = (Vec::new(), 0, 0);
    while i < body.len() {
        if runes == BODY_PREVIEW_LIMIT {
            return out;
        }
        let (r, size) = wafio_bytetext::utf8::decode_code_point(&body[i..]);
        wafio_bytetext::utf8::push_code_point(&mut out, r);
        i += size;
        runes += 1;
    }
    body.to_vec()
}

/// One string per name (", " joined; "; " for Cookie).
fn collect_loggable_headers(headers: &Headers) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut out = HashMap::new();
    for (k, vals) in headers {
        if vals.is_empty() {
            continue;
        }
        let sep: &[u8] = if strings::eq_ignore_case(k, b"cookie") {
            b"; "
        } else {
            b", "
        };
        out.insert(k.clone(), vals.join(sep));
    }
    out
}

/// The first 4 KiB of the preview copy.
fn capture_request_body(req: &AnalysisRequest) -> Vec<u8> {
    let raw = req.body_preview_source.as_deref().unwrap_or_default();
    raw[..raw.len().min(REQUEST_BODY_CAPTURE_LIMIT)].to_vec()
}

/// The query string of `uri` (empty when there is none).
fn capture_query_string(uri: &[u8]) -> Vec<u8> {
    match uri.iter().position(|&c| c == b'?') {
        Some(i) if i != uri.len() - 1 => uri[i + 1..].to_vec(),
        _ => Vec::new(),
    }
}

fn mime_of(ct: &[u8]) -> Vec<u8> {
    let ct = match ct.iter().position(|&c| c == b';') {
        Some(i) => &ct[..i],
        None => ct,
    };
    strings::trim_whitespace(&strings::to_lowercase(ct)).to_vec()
}

/// The label of a known content type (`json`, `form`, ...); any other media type is kept, cut to
/// 64 bytes.
pub fn canonical_content_type(ct: &[u8]) -> Vec<u8> {
    if ct.is_empty() {
        return Vec::new();
    }
    let ct = mime_of(ct);
    let label: &[u8] = match ct.as_slice() {
        b"application/json" => b"json",
        b"application/x-www-form-urlencoded" => b"form",
        b"multipart/form-data" => b"multipart",
        b"text/xml" | b"application/xml" | b"application/soap+xml" => b"xml",
        b"text/plain" => b"text",
        b"application/octet-stream" => b"binary",
        b"application/grpc" | b"application/grpc+proto" => b"grpc",
        b"application/graphql" | b"application/graphql+json" => b"graphql",
        b"" => b"",
        _ => return ct[..ct.len().min(64)].to_vec(),
    };
    label.to_vec()
}

pub fn classify_payload(ct: &[u8], body: &[u8]) -> Vec<u8> {
    if !ct.is_empty() {
        let mime = mime_of(ct);
        let label: Option<&[u8]> = match mime.as_slice() {
            b"application/json"
            | b"application/json-patch+json"
            | b"application/merge-patch+json"
            | b"application/vnd.api+json" => Some(b"json"),
            b"application/x-www-form-urlencoded" => Some(b"form-urlencoded"),
            b"multipart/form-data" => Some(b"multipart-form"),
            b"text/xml" | b"application/xml" => Some(b"xml"),
            b"application/soap+xml" => Some(b"soap"),
            b"text/html" | b"application/xhtml+xml" => Some(b"html"),
            b"application/graphql" | b"application/graphql+json" => Some(b"graphql"),
            b"application/grpc" | b"application/grpc+proto" => Some(b"grpc"),
            b"application/protobuf"
            | b"application/x-protobuf"
            | b"application/vnd.google.protobuf" => Some(b"protobuf"),
            b"text/csv" | b"application/csv" => Some(b"csv"),
            b"application/x-yaml" | b"text/yaml" | b"application/yaml" => Some(b"yaml"),
            b"text/plain" | b"application/octet-stream" => None,
            m if m.starts_with(b"text/") => Some(b"text"),
            b"" => None,
            m => return m[..m.len().min(48)].to_vec(),
        };
        if let Some(l) = label {
            return l.to_vec();
        }
    }
    let b = strings::trim_whitespace(body);
    if b.is_empty() {
        return b"empty".to_vec();
    }
    if b[0] == b'{' || b[0] == b'[' {
        return b"json".to_vec();
    }
    if b[0] == b'<' {
        let lower = strings::to_lowercase(b);
        let has = |p: &[u8]| lower.starts_with(p);
        if has(b"<soap:")
            || has(b"<soap-env:")
            || has(b"<?xml") && memchr::memmem::find(&lower, b"soap").is_some()
        {
            return b"soap".to_vec();
        }
        if has(b"<?xml") || has(b"<root") {
            return b"xml".to_vec();
        }
        if has(b"<!doctype") || has(b"<html") {
            return b"html".to_vec();
        }
        return b"xml".to_vec();
    }
    let lower = strings::to_lowercase(b);
    if [&b"query "[..], b"mutation ", b"fragment ", b"subscription "]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        return b"graphql".to_vec();
    }
    if b.starts_with(b"---") {
        return b"yaml".to_vec();
    }
    if is_form_encoded(b) {
        return b"form-urlencoded".to_vec();
    }
    if looks_like_csv(b) {
        return b"csv".to_vec();
    }
    if looks_binary(b) {
        return b"binary".to_vec();
    }
    b"text".to_vec()
}

fn is_form_encoded(s: &[u8]) -> bool {
    if !s.contains(&b'=') {
        return false;
    }
    if s.contains(&b'\n') && !s.contains(&b'&') {
        return false;
    }
    let pairs: Vec<&[u8]> = s.split(|&c| c == b'&').collect();
    let valid = pairs.iter().filter(|p| p.contains(&b'=')).count();
    valid >= 1 && valid as f64 / pairs.len() as f64 >= 0.5
}

fn looks_like_csv(s: &[u8]) -> bool {
    let lines: Vec<&[u8]> = s.splitn(4, |&c| c == b'\n').collect();
    if lines.len() < 2 {
        return false;
    }
    let commas = |l: &[u8]| l.iter().filter(|&&c| c == b',').count();
    let first = commas(lines[0]);
    first >= 1 && lines[1..].iter().any(|l| commas(l) == first)
}

fn looks_binary(s: &[u8]) -> bool {
    let check = &s[..s.len().min(512)];
    let non_print = check
        .iter()
        .filter(|&&c| c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f)
        .count();
    !check.is_empty() && non_print as f64 / check.len() as f64 > 0.1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_event_coverage_lists_the_marks_after_the_gap_flags() {
        let mut v = wafio_domain::AnalysisResult::default();
        assert_eq!(event_coverage(&v), "");
        v.engines_off = vec!["xss".into(), "jwt".into()];
        assert_eq!(
            event_coverage(&v),
            "engine_disabled:xss,engine_disabled:jwt"
        );
        v.coverage = "body_decompress_error,field_cap".into();
        assert_eq!(
            event_coverage(&v),
            "body_decompress_error,field_cap,engine_disabled:xss,engine_disabled:jwt"
        );
        // The verdict's own coverage never holds a mark.
        assert!(!v.coverage.contains("engine_disabled"));
        v.engines_log_only = vec!["sql".into()];
        assert_eq!(
            event_coverage(&v),
            "body_decompress_error,field_cap,engine_disabled:xss,engine_disabled:jwt,engine_log_only:sql"
        );
        // An agent without an engine says so last.
        v.engine_absent = true;
        assert_eq!(
            event_coverage(&v),
            "body_decompress_error,field_cap,engine_disabled:xss,engine_disabled:jwt,engine_log_only:sql,engine_absent"
        );
        v.coverage.clear();
        v.engines_off.clear();
        v.engines_log_only.clear();
        assert_eq!(event_coverage(&v), "engine_absent");
    }

    #[test]
    fn content_type_labels() {
        assert_eq!(
            canonical_content_type(b"Application/JSON; charset=utf-8"),
            b"json"
        );
        assert_eq!(
            canonical_content_type(b"multipart/form-data; boundary=x"),
            b"multipart"
        );
        assert_eq!(canonical_content_type(b"image/png"), b"image/png");
        assert_eq!(canonical_content_type(b""), b"");
    }

    #[test]
    fn payload_types() {
        assert_eq!(classify_payload(b"application/json", b""), b"json");
        assert_eq!(
            classify_payload(b"text/plain", b"a=1&b=2"),
            b"form-urlencoded"
        );
        assert_eq!(classify_payload(b"", b"  {\"a\":1}"), b"json");
        assert_eq!(
            classify_payload(b"", b"<?xml version='1.0'?><soap:x/>"),
            b"soap"
        );
        assert_eq!(classify_payload(b"", b"query { a }"), b"graphql");
        assert_eq!(classify_payload(b"", b"a,b\n1,2"), b"csv");
        assert_eq!(classify_payload(b"", b"\x00\x01\x02abc"), b"binary");
        assert_eq!(classify_payload(b"", b""), b"empty");
        assert_eq!(classify_payload(b"text/html", b""), b"html");
        assert_eq!(classify_payload(b"text/x-foo", b""), b"text");
    }

    #[test]
    fn query_params_and_preview() {
        assert_eq!(capture_query_string(b"/a?x=1"), b"x=1");
        assert!(capture_query_string(b"/a?").is_empty());
        let req = AnalysisRequest {
            body_preview_source: Some("é".repeat(600).into_bytes()),
            ..Default::default()
        };
        assert_eq!(truncate_body_preview(&req), "é".repeat(512).into_bytes());
    }
}
