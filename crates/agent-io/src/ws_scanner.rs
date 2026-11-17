//! Per-connection WebSocket limits, the frame scan view, the text and printable-run scanners, the
//! incomplete-frame action and the per-connection message rate limiter.
//! The semantic engine is reached through [`WsSemantic`].

use std::sync::Mutex;
use std::time::{Duration, Instant};

use wafio_bytetext::strings::replace_invalid_utf8;
use wafio_bytetext::utf8::{REPLACEMENT_CODE_POINT, decode_code_point, is_valid as is_valid_utf8};
use wafio_engine_api::{Tier, outranks};

/// WebSocket opcodes of a data message (text / binary).
pub const MESSAGE_KIND_TEXT: u8 = 1;
pub const MESSAGE_KIND_BINARY: u8 = 2;

pub const BODY_ENGINE_FIELD_LIMIT: usize = 256;
pub const MIN_SCANNABLE_LENGTH: usize = 4;

/// Per-connection WebSocket limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WsScanBudget {
    pub max_text_size: usize,
    pub max_binary_size: usize,
    pub max_msgs_per_min: i64,
}

pub fn default_scan_budget() -> WsScanBudget {
    WsScanBudget {
        max_text_size: 64 << 10,
        max_binary_size: 1 << 20,
        max_msgs_per_min: 100,
    }
}

/// What the relay needs to pick an action.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsScanVerdict {
    pub tier: Tier,
    pub reason: String,
    /// The scan limit the frame hit ("field_cap" | "value_truncated"), "" when
    /// the whole frame was scanned.
    pub incomplete: &'static str,
    /// The strongest detection of an engine that only logs and would have blocked: not in `tier`. Empty when
    /// no engine held one back.
    pub held_reason: String,
}

/// One value the field extractor emitted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsScanField {
    pub value: Vec<u8>,
    pub source: Vec<u8>,
    pub summary: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsFieldCoverage {
    pub field_capped: bool,
    pub skipped: String,
    pub binary_text: bool,
}

/// The detailed semantic scan result fields the scanner reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsDetailed {
    pub tier: Tier,
    pub reason: String,
    /// Engines opened for the value.
    pub engines: i64,
    pub truncated: bool,
    /// The detection of an engine that only logs and would have blocked: not in `tier`.
    pub held_reason: String,
}

/// The engine calls the scanner makes, bound to one semantic config (the
/// project's precomputed `SemanticConfig`, or the default one when there is none).
pub trait WsSemantic {
    /// Extracts the scan fields (with coverage) of a frame payload.
    fn extract_scan_fields(&self, payload: &[u8]) -> (Vec<WsScanField>, WsFieldCoverage);
    fn scan_semantics_detailed(&self, value: &[u8]) -> WsDetailed;
}

/// Keeps the stronger of the detection `r` found and the best so far, and the stronger held one.
fn merge_best(best: &mut WsScanVerdict, r: WsDetailed) {
    if outranks((r.tier, &r.reason), (best.tier, &best.reason)) {
        (best.tier, best.reason) = (r.tier, r.reason);
    }
    if !r.held_reason.is_empty()
        && (best.held_reason.is_empty()
            || outranks(
                (Tier::Strong, &r.held_reason),
                (Tier::Strong, &best.held_reason),
            ))
    {
        best.held_reason = r.held_reason;
    }
}

/// Scans a frame payload: a JSON frame is decomposed into fields
/// scanned one by one, anything else (or text the extractor refuses) whole.
/// Returns the strongest hit and its reason.
pub fn scan_frame_payload(sem: &impl WsSemantic, payload: &[u8]) -> WsScanVerdict {
    if payload.is_empty() {
        return WsScanVerdict::default();
    }
    let mut best = WsScanVerdict::default();
    let mut truncated = false;
    let (mut fields, mut cov) = sem.extract_scan_fields(payload);
    if (fields.is_empty() && !cov.skipped.is_empty()) || cov.binary_text {
        // The frame holds no field the extraction can read: scan the whole text frame instead.
        fields = vec![WsScanField {
            value: payload.to_vec(),
            source: b"body".to_vec(),
            summary: false,
        }];
    }
    let mut engine_fields = 0;
    for field in &fields {
        // Engine budget as for HTTP bodies; summaries stay scanned.
        if !field.summary && engine_fields >= BODY_ENGINE_FIELD_LIMIT {
            cov.field_capped = true;
            continue;
        }
        if field.source != b"body" && field.value.len() < MIN_SCANNABLE_LENGTH {
            continue;
        }
        let r = sem.scan_semantics_detailed(&field.value);
        if r.engines > 0 && !field.summary {
            engine_fields += 1;
        }
        truncated = truncated || r.truncated;
        merge_best(&mut best, r);
    }
    if cov.field_capped {
        best.incomplete = "field_cap";
    } else if truncated {
        best.incomplete = "value_truncated";
    }
    best
}

/// Scans the '\n'-separated printable runs
/// of a non-text binary frame, one run at a time. Coverage gaps not reported.
pub fn scan_printable_runs(sem: &impl WsSemantic, runs: &[u8]) -> WsScanVerdict {
    let mut best = WsScanVerdict::default();
    for run in runs.split(|&c| c == b'\n') {
        if run.len() < PRINTABLE_RUN_MIN_LENGTH {
            continue;
        }
        merge_best(&mut best, sem.scan_semantics_detailed(run));
    }
    best
}

/// Least printable content a binary frame with invalid UTF-8 must carry to be
/// read as a whole text document.
pub const DECODED_TEXT_MIN_LENGTH: usize = 16;

/// Shortest printable run `collect_printable_runs` keeps.
pub const PRINTABLE_RUN_MIN_LENGTH: usize = 12;

/// A binary frame up to this size is always scanned whole (decoded).
pub const SMALL_BINARY_FRAME_LIMIT: usize = 256;

/// What the relay scans for one data frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsScanInput {
    /// The scan input; `None` = nothing to scan.
    pub text: Option<Vec<u8>>,
    /// `text` is the printable runs of a non-text binary frame (best effort).
    pub runs: bool,
    /// A text document over the text size cap (raw or decoded).
    pub oversize: bool,
}

/// How a data frame of `kind` is scanned.
pub fn build_scan_input(kind: u8, payload: &[u8], max_text: usize) -> WsScanInput {
    if payload.is_empty() {
        return WsScanInput::default();
    }
    match kind {
        MESSAGE_KIND_TEXT => return text_document_input(payload, max_text),
        MESSAGE_KIND_BINARY => {
            if payload.len() <= SMALL_BINARY_FRAME_LIMIT
                || is_valid_utf8(payload)
                || printable_fraction(payload) >= 0.85
                || wafio_domain::json_text::is_valid_json(payload)
                || looks_mostly_printable(payload)
            {
                return text_document_input(payload, max_text);
            }
            let runs = collect_printable_runs(payload, max_text);
            if !runs.is_empty() {
                return WsScanInput {
                    text: Some(runs),
                    runs: true,
                    oversize: false,
                };
            }
        }
        _ => {}
    }
    WsScanInput::default()
}

/// Decodes a text document (each run of invalid bytes →
/// one U+FFFD) and applies the size cap to its raw and decoded length.
pub fn text_document_input(payload: &[u8], max_text: usize) -> WsScanInput {
    if payload.len() > max_text {
        return WsScanInput {
            text: Some(payload.to_vec()),
            runs: false,
            oversize: true,
        };
    }
    if is_valid_utf8(payload) {
        return WsScanInput {
            text: Some(payload.to_vec()),
            runs: false,
            oversize: false,
        };
    }
    let decoded = replace_invalid_utf8(payload, "\u{FFFD}".as_bytes());
    let oversize = decoded.len() > max_text;
    WsScanInput {
        text: Some(decoded),
        runs: false,
        oversize,
    }
}

/// Whether the bytes outside invalid UTF-8 sequences
/// are ≥ 85 % printable, with ≥ [`DECODED_TEXT_MIN_LENGTH`] of them.
pub fn looks_mostly_printable(payload: &[u8]) -> bool {
    let (mut valid, mut printable) = (0usize, 0usize);
    let mut i = 0;
    while i < payload.len() {
        let (r, size) = decode_code_point(&payload[i..]);
        i += size;
        if r == REPLACEMENT_CODE_POINT && size == 1 {
            continue;
        }
        valid += 1;
        if r >= 0x80
            || r == '\t' as i32
            || r == '\n' as i32
            || r == '\r' as i32
            || (0x20..0x7f).contains(&r)
        {
            printable += 1;
        }
    }
    printable >= DECODED_TEXT_MIN_LENGTH && printable * 100 >= valid * 85
}

/// Collects printable ASCII runs (space..~ and tab) of at least
/// [`PRINTABLE_RUN_MIN_LENGTH`] bytes, joined by '\n', stopping at `limit` bytes.
pub fn collect_printable_runs(b: &[u8], limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let flush = |out: &mut Vec<u8>, start: &mut Option<usize>, end: usize| -> bool {
        if let Some(s) = *start
            && end - s >= PRINTABLE_RUN_MIN_LENGTH
        {
            if !out.is_empty() {
                out.push(b'\n');
            }
            out.extend_from_slice(&b[s..end]);
        }
        *start = None;
        out.len() >= limit
    };
    for (i, &c) in b.iter().enumerate() {
        if c == b'\t' || (0x20..0x7f).contains(&c) {
            if start.is_none() {
                start = Some(i);
            }
            continue;
        }
        if flush(&mut out, &mut start, i) {
            break;
        }
    }
    if out.len() < limit {
        flush(&mut out, &mut start, b.len());
    }
    out.truncate(limit);
    out
}

/// Share of bytes that are printable
/// ASCII, tab/CR/LF, or part of a valid multi-byte UTF-8 sequence.
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

/// The `content_scan` fields [`incomplete_frame_action`] reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsContentScan {
    pub enabled: bool,
    pub mode: String,
    pub on_incomplete: String,
}

/// What a frame the scanner could not cover in full
/// becomes: `content_scan.on_incomplete` when content scanning is on
/// and sets it, else "log"; content-scan mode "log" never blocks.
pub fn incomplete_frame_action(cs: Option<&WsContentScan>) -> String {
    let mut action = "log".to_string();
    if let Some(cs) = cs
        && cs.enabled
        && cs.mode != "disabled"
        && !cs.on_incomplete.is_empty()
    {
        action = cs.on_incomplete.clone();
        if cs.mode == "log" && action == "block" {
            action = "log".into();
        }
    }
    action
}

/// Fixed-window per-connection limiter counting data
/// messages per minute.
pub struct WsMessageRateLimiter {
    max: i64,
    window: Duration,
    state: Mutex<(i64, Option<Instant>)>,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl WsMessageRateLimiter {
    /// A limiter allowing `max_per_min` data messages per 1-minute window.
    pub fn new(max_per_min: i64) -> WsMessageRateLimiter {
        WsMessageRateLimiter {
            max: max_per_min,
            window: Duration::from_secs(60),
            state: Mutex::new((0, None)),
            now: Box::new(Instant::now),
        }
    }

    /// Replaces the clock; tests only.
    pub fn set_clock(&mut self, now: impl Fn() -> Instant + Send + Sync + 'static) {
        self.now = Box::new(now);
    }

    /// Whether one more data message fits in the current window.
    pub fn allow(&self) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = (self.now)();
        let roll = match st.1 {
            None => true,
            Some(start) => now.saturating_duration_since(start) >= self.window,
        };
        if roll {
            *st = (0, Some(now));
        }
        if st.0 >= self.max {
            return false;
        }
        st.0 += 1;
        true
    }
}

#[cfg(test)]
mod tests;
