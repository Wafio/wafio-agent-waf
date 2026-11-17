//! Builds the copy of an HTTP request body the WAF inspects: Content-Encoding decoding under
//! per-request and process-wide memory limits and Content-Type sniffing of declared-binary
//! bodies. The bytes a backend receives are never modified.

#![forbid(unsafe_code)]

use std::borrow::Cow;

use wafio_domain::request::{ANALYZE_METHOD_SEMANTIC, AnalysisResult, Headers, IncomingRequest};
use wafio_domain::text_helpers::{
    REPLACEMENT_CODE_POINT, decode_code_point, eq_ignore_case, to_lowercase, trim_whitespace,
};

mod budget;
mod decode;

pub use budget::{
    DEFAULT_INFLIGHT_DECODE_BYTES, INFLIGHT_DECODE_BYTES_ENV, inflight_decode_bytes_limit,
    inflight_decode_bytes_used, set_inflight_decode_bytes, skipped_decode_count,
};
pub use decode::{
    CODING_LAYER_LIMIT, DECODED_BODY_LIMIT_BYTES, EXPANSION_RATIO_LIMIT, RATIO_CHECK_MIN_OUTPUT,
    SKIP_REASON_DECOMPRESS_BUDGET, SKIP_REASON_DECOMPRESS_ERROR, SKIP_REASON_DECOMPRESS_LIMIT,
    SKIP_REASON_ENCODING_PREFIX, declared_codings, decode, decoded_size_cap, gunzip_to_vec,
    sanitize_coding_label,
};

/// Bytes examined by the text sniffer; the head decides.
pub const SNIFF_WINDOW_BYTES: usize = 64 << 10;
/// Same threshold as the semantic whole-body fallback.
const SNIFF_MIN_PRINTABLE_RATIO: f64 = 0.85;
/// Declared-type label length in the mismatch note.
const LABEL_MAX_LEN: usize = 64;

/// Genuine binary upload: the text engines never see it.
pub const BODY_KIND_BINARY: &str = "binary";
/// Raw multipart: the WAF parses parts per field.
pub const BODY_KIND_MULTIPART: &str = "multipart";
/// Everything else: scanned as a text body.
pub const BODY_KIND_TEXT: &str = "text";

/// Tunes `inspect` for one entry path. The default is valid.
#[derive(Default)]
pub struct Options<'f> {
    /// Caps decoded output; <= 0 means DECODED_BODY_LIMIT_BYTES.
    pub output_limit: i64,
    /// Applied to a decoded copy before sniffing (the agent's decrypt field
    /// rules). Only ever receives the decoded copy.
    pub transform: Option<&'f dyn Fn(Vec<u8>) -> Vec<u8>>,
}

/// The WAF's view of one request body.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct InspectResult<'a> {
    /// One of BODY_KIND_*.
    pub kind: &'static str,
    /// Bytes the WAF inspects; None for BODY_KIND_BINARY.
    pub scan: Option<Cow<'a, [u8]>>,
    /// The inspected bytes are a decoded copy, not the input.
    pub decoded: bool,
    /// "json" / "form" when a declared-binary body sniffed as text.
    pub sniffed: &'static str,
    /// `IncomingRequest.body_scan_skipped`.
    pub skipped: String,
    /// Match-detail notes for body-driven verdicts.
    pub notes: Vec<String>,
}

/// Decides what the WAF inspects for a request body. `body`
/// is what the backend receives and is never modified.
pub fn inspect<'a>(
    body: &'a [u8],
    content_type: &[u8],
    headers: &Headers,
    opt: &Options<'_>,
) -> InspectResult<'a> {
    let mut res = InspectResult::default();
    let ct = to_lowercase(content_type);

    let mut inspect: Cow<'a, [u8]> = Cow::Borrowed(body);
    let codings = declared_codings(headers);
    if !codings.is_empty() {
        let limit = if opt.output_limit <= 0 {
            DECODED_BODY_LIMIT_BYTES
        } else {
            opt.output_limit
        };
        let (decoded, skipped) = decode(body, &codings, limit);
        res.skipped = skipped;
        if let Some(decoded) = decoded {
            let mut decoded = decoded.into_owned();
            if let Some(t) = opt.transform {
                decoded = t(decoded);
            }
            inspect = Cow::Owned(decoded);
            res.decoded = true;
            res.notes.push(format!(
                "body_decoded:{}",
                sanitize_coding_label(&codings.join(&b'+'))
            ));
        }
    }

    let declared_binary = declares_binary_content(&ct);
    if declared_binary {
        res.sniffed = detect_text_payload(&inspect);
        if res.sniffed.is_empty() && res.decoded {
            // Known binary decoded content: an incomplete decode costs no text coverage.
            res.skipped.clear();
        }
    }
    if declared_binary && res.sniffed.is_empty() {
        res.kind = BODY_KIND_BINARY;
    } else if ct.starts_with(b"multipart/") {
        res.kind = BODY_KIND_MULTIPART;
        res.scan = Some(inspect);
    } else {
        res.kind = BODY_KIND_TEXT;
        res.scan = Some(inspect);
        if !res.sniffed.is_empty() {
            res.notes.push(format!(
                "body_ct_mismatch:{}->{}",
                content_type_label(&ct),
                res.sniffed
            ));
        }
    }
    if !res.skipped.is_empty() {
        res.notes
            .push(format!("body_scan_incomplete:{}", res.skipped));
    }
    res
}

/// Applies `inspect` to a request whose body is the body as the client sent
/// it and stores the scan view on the request. Returns the inspect notes.
pub fn prepare_body_for_engines(req: &mut IncomingRequest) -> Vec<String> {
    if req.content_type.is_empty() {
        req.content_type = first_header_value(&req.headers, b"Content-Type").to_vec();
    }
    if req.body.is_empty() {
        return Vec::new();
    }
    let body = std::mem::take(&mut req.body);
    let res = inspect(&body, &req.content_type, &req.headers, &Options::default());
    if !res.skipped.is_empty() {
        req.body_scan_skipped = res.skipped.clone();
    }
    let notes = res.notes;
    if res.decoded || res.scan.is_none() {
        let new_body = res.scan.map(Cow::into_owned).unwrap_or_default();
        if req.body_size == 0 {
            req.body_size = body.len() as i64;
        }
        if req.content_scan_body.is_none() {
            req.content_scan_body = Some(body);
        }
        req.body = new_body;
    } else {
        req.body = body;
    }
    notes
}

/// Reports whether inspect notes belong on a verdict's match detail:
/// block/log verdicts from the engines that read body content.
pub fn should_attach_notes(action: &str, analyze_method: &str) -> bool {
    if action != "block" && action != "log" {
        return false;
    }
    analyze_method == ANALYZE_METHOD_SEMANTIC
}

/// Appends note to a match detail using the "; " separator.
pub fn join_note(detail: &[u8], note: &[u8]) -> Vec<u8> {
    if note.is_empty() {
        return detail.to_vec();
    }
    if detail.is_empty() {
        return note.to_vec();
    }
    [detail, b"; ", note].concat()
}

/// Appends inspect notes to a verdict the way the inline proxy records it.
pub fn attach_notes(result: &mut AnalysisResult, notes: &[String]) {
    if !notes.is_empty() && should_attach_notes(&result.action, &result.analyze_method) {
        result.match_detail = join_note(&result.match_detail, notes.join("; ").as_bytes());
    }
}

/// Reports whether the (lowercased) Content-Type is one not handed to the
/// text engines as-is. multipart/* is not in this set.
pub fn declares_binary_content(ct: &[u8]) -> bool {
    [
        "image/",
        "video/",
        "audio/",
        "font/",
        "application/octet-stream",
        "application/zip",
        "application/pdf",
        "application/x-tar",
        "application/x-gzip",
    ]
    .iter()
    .any(|p| ct.starts_with(p.as_bytes()))
}

/// Reports whether a body declared as binary is really a text payload a
/// lenient backend would parse: "json", "form", or "" (binary).
pub fn detect_text_payload(b: &[u8]) -> &'static str {
    let head = &b[..b.len().min(SNIFF_WINDOW_BYTES)];
    let trimmed = head.strip_prefix(b"\xef\xbb\xbf").unwrap_or(head);
    let start = trimmed
        .iter()
        .position(|c| !matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(trimmed.len());
    let trimmed = &trimmed[start..];
    if trimmed.is_empty() || printable_fraction(head) < SNIFF_MIN_PRINTABLE_RATIO {
        return "";
    }
    if trimmed[0] == b'{' || trimmed[0] == b'[' {
        return "json";
    }
    if contains_form_pair(trimmed) {
        return "form";
    }
    ""
}

/// Reports whether b holds at least one urlencoded key=value pair whose key
/// is a token (pairs split on '&' and ';').
fn contains_form_pair(mut b: &[u8]) -> bool {
    while !b.is_empty() {
        let seg;
        match b.iter().position(|&c| c == b'&' || c == b';') {
            Some(i) => {
                seg = &b[..i];
                b = &b[i + 1..];
            }
            None => {
                seg = b;
                b = &[];
            }
        }
        let Some(eq) = seg.iter().position(|&c| c == b'=') else {
            continue;
        };
        let key = trim_whitespace(&seg[..eq]);
        if key.is_empty() {
            continue;
        }
        if key.iter().all(|&c| c > b' ' && c != 0x7f) {
            return true;
        }
    }
    false
}

/// Share of bytes that are printable ASCII, tab/CR/LF, or part of a valid
/// multi-byte UTF-8 sequence.
pub fn printable_fraction(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    let mut n = 0usize;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c < 0x80 {
            if c == b'\t' || c == b'\n' || c == b'\r' || (0x20..=0x7e).contains(&c) {
                n += 1;
            }
            i += 1;
            continue;
        }
        let (r, size) = decode_code_point(&b[i..]);
        if r != REPLACEMENT_CODE_POINT || size > 1 {
            n += size;
        }
        i += size;
    }
    n as f64 / b.len() as f64
}

/// Names a declared-binary Content-Type in the mismatch note: "binary" for
/// application/octet-stream, else the media type limited to [a-z0-9.+_/-].
fn content_type_label(ct: &[u8]) -> String {
    let ct = match ct.iter().position(|&c| c == b';') {
        Some(i) => &ct[..i],
        None => ct,
    };
    let ct = trim_whitespace(ct);
    if ct == b"application/octet-stream" {
        return "binary".into();
    }
    let mut b = String::new();
    for &c in ct {
        if b.len() >= LABEL_MAX_LEN {
            break;
        }
        if c.is_ascii_lowercase() || c.is_ascii_digit() || b".+_/-".contains(&c) {
            b.push(char::from(c));
        }
    }
    if b.is_empty() {
        return "unknown".into();
    }
    b
}

/// The first value of the named header, matched case-insensitively.
fn first_header_value<'h>(headers: &'h Headers, name: &[u8]) -> &'h [u8] {
    for (k, vals) in headers {
        if eq_ignore_case(k, name)
            && let Some(v) = vals.first()
        {
            return v;
        }
    }
    b""
}

#[cfg(test)]
mod tests;
