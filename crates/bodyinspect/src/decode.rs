//! Content-Encoding decoding for WAF inspection. Everything here builds a COPY; the input is
//! never modified. gzip (multistream) and zlib framing are checked here; the deflate data
//! itself goes through `miniz_oxide`, brotli through the `brotli` crate's stream decoder.

use std::borrow::Cow;

use brotli::enc::StandardAlloc;
use brotli::{BrotliDecompressStream, BrotliResult, BrotliState};
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress};
use wafio_domain::request::{BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET, Headers};

use crate::budget::shared_budget;

/// Absolute decoded-size cap (8 MiB).
pub const DECODED_BODY_LIMIT_BYTES: i64 = 8 << 20;
/// The ratio guard applies only above 256 KiB of output.
pub const RATIO_CHECK_MIN_OUTPUT: i64 = 256 << 10;
/// Max decoded:wire ratio above the floor.
pub const EXPANSION_RATIO_LIMIT: i64 = 100;
/// Stacked codings decoded at most.
pub const CODING_LAYER_LIMIT: usize = 3;
/// Coding name length kept in flags / match detail.
const CODING_LABEL_MAX_LEN: usize = 32;

/// An inflate state plus the gzip/zlib wrappers.
const INFLATE_STATE_RESERVE: i64 = 128 << 10;
/// A brotli reader apart from its ring buffer.
const BROTLI_STATE_RESERVE: i64 = 3 << 20;
/// WBITS values with the 4-bit header form, the only form rewritten in place.
const BROTLI_MIN_WINDOW_BITS: u32 = 18;
const BROTLI_MAX_WINDOW_BITS: u32 = 24;
/// The brotli spec's gap between window size and largest backward distance.
const BROTLI_WINDOW_MARGIN: i64 = 16;

/// `body_scan_skipped` values produced here.
pub const SKIP_REASON_ENCODING_PREFIX: &str = "content_encoding:";
pub const SKIP_REASON_DECOMPRESS_LIMIT: &str = "decompress_limit";
pub const SKIP_REASON_DECOMPRESS_ERROR: &str = "decompress_error";
pub const SKIP_REASON_DECOMPRESS_BUDGET: &str = BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET;

/// The content-codings applied to a request body in applied order, lowercased, "identity"
/// and empty tokens dropped. Header names match case-insensitively; collection stops one
/// past CODING_LAYER_LIMIT.
pub fn declared_codings(headers: &Headers) -> Vec<Vec<u8>> {
    use wafio_domain::text_helpers::{eq_ignore_case, to_lowercase, trim_whitespace};
    let mut out = Vec::new();
    // Headers iterate in sorted key order.
    for (k, vals) in headers {
        if !eq_ignore_case(k, b"Content-Encoding") {
            continue;
        }
        for v in vals {
            for tok in v.split(|&c| c == b',') {
                let tok = to_lowercase(trim_whitespace(tok));
                if tok.is_empty() || tok == b"identity" {
                    continue;
                }
                out.push(tok);
                if out.len() > CODING_LAYER_LIMIT {
                    return out;
                }
            }
        }
    }
    out
}

/// The decoded-size cap for one request: min(route max body, 8 MiB);
/// route_max <= 0 means no route cap.
pub fn decoded_size_cap(route_max: i64) -> i64 {
    if route_max > 0 && route_max < DECODED_BODY_LIMIT_BYTES {
        return route_max;
    }
    DECODED_BODY_LIMIT_BYTES
}

/// Decodes a COPY of body for inspection. `codings` are in applied order;
/// decoding runs in reverse. Returns the bytes to inspect and a
/// `body_scan_skipped` value; None means "inspect the raw bytes".
pub fn decode<'a, S: AsRef<[u8]>>(
    body: &'a [u8],
    codings: &[S],
    limit: i64,
) -> (Option<Cow<'a, [u8]>>, String) {
    for c in codings {
        if !is_supported_coding(c.as_ref()) {
            return (
                None,
                format!(
                    "{SKIP_REASON_ENCODING_PREFIX}{}",
                    sanitize_coding_label(c.as_ref())
                ),
            );
        }
    }
    if codings.len() > CODING_LAYER_LIMIT {
        return (None, SKIP_REASON_DECOMPRESS_LIMIT.into());
    }
    if codings.is_empty() {
        return (Some(Cow::Borrowed(body)), String::new());
    }
    let mut layer_budget = RATIO_CHECK_MIN_OUTPUT
        .max(body.len() as i64 * EXPANSION_RATIO_LIMIT)
        .min(limit);
    let b = shared_budget();
    let mut reserve = worst_case_reservation(codings, layer_budget);
    let capacity = b.capacity.load(std::sync::atomic::Ordering::SeqCst);
    if capacity > 0 && reserve > capacity {
        layer_budget = fit_layer_budget(codings, layer_budget, capacity);
        if layer_budget <= 0 {
            return (None, SKIP_REASON_DECOMPRESS_LIMIT.into());
        }
        reserve = worst_case_reservation(codings, layer_budget);
    }
    if !b.try_acquire(reserve) {
        b.skips.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        return (None, SKIP_REASON_DECOMPRESS_BUDGET.into());
    }
    struct Release(i64);
    impl Drop for Release {
        fn drop(&mut self) {
            shared_budget().release(self.0);
        }
    }
    let _release = Release(reserve);

    let mut cur: Cow<'a, [u8]> = Cow::Borrowed(body);
    for i in (0..codings.len()).rev() {
        match decode_one_layer(&cur, codings[i].as_ref(), layer_budget) {
            Ok(out) => cur = Cow::Owned(out),
            Err(LayerError::Limit(out)) => {
                if i > 0 || out.is_empty() {
                    return (None, SKIP_REASON_DECOMPRESS_LIMIT.into());
                }
                return (Some(Cow::Owned(out)), SKIP_REASON_DECOMPRESS_LIMIT.into());
            }
            Err(LayerError::Corrupt) => return (None, SKIP_REASON_DECOMPRESS_ERROR.into()),
        }
    }
    (Some(cur), String::new())
}

/// Worst-case memory of one decode with the given per-layer output budget.
pub(crate) fn worst_case_reservation<S: AsRef<[u8]>>(codings: &[S], layer_budget: i64) -> i64 {
    let out = layer_budget + 1;
    let mut reserve = 2 * out;
    if codings.len() > 1 {
        reserve += out;
    }
    let mut state = INFLATE_STATE_RESERVE;
    for c in codings {
        if c.as_ref() == b"br" {
            let (_, ring) = brotli_window_bits_for(layer_budget);
            state = state.max(BROTLI_STATE_RESERVE + ring);
        }
    }
    reserve + state
}

/// The largest per-layer budget, at most layer_budget, whose reservation fits
/// capacity; <= 0 when none does.
pub(crate) fn fit_layer_budget<S: AsRef<[u8]>>(
    codings: &[S],
    layer_budget: i64,
    capacity: i64,
) -> i64 {
    let per_byte = if codings.len() > 1 { 3 } else { 2 };
    let state = worst_case_reservation(codings, layer_budget) - per_byte * (layer_budget + 1);
    layer_budget.min((capacity - state) / per_byte - 1)
}

/// The brotli window (WBITS) a stream is decoded with when its output is
/// capped at budget bytes, and the peak memory of a ring buffer of it.
pub(crate) fn brotli_window_bits_for(budget: i64) -> (u32, i64) {
    let mut wbits = BROTLI_MIN_WINDOW_BITS;
    while wbits < BROTLI_MAX_WINDOW_BITS && (1i64 << wbits) - BROTLI_WINDOW_MARGIN < budget + 1 {
        wbits += 1;
    }
    let ring = 1i64 << wbits;
    (wbits, ring + ring / 2 + (4 << 10))
}

/// The rewritten first header byte when the declared
/// window is larger than brotli_window_bits_for(budget), else None.
pub(crate) fn rewrite_brotli_window_header(data: &[u8], budget: i64) -> Option<u8> {
    if data.is_empty() || data[0] & 1 == 0 {
        return None; // WBITS 16
    }
    let n = u32::from(data[0] >> 1) & 7;
    if n == 0 {
        return None; // 7-bit form or large-window
    }
    let (cap_bits, _) = brotli_window_bits_for(budget);
    if 17 + n <= cap_bits {
        return None;
    }
    Some(data[0] & !0x0E | ((cap_bits - 17) as u8) << 1)
}

fn is_supported_coding(c: &[u8]) -> bool {
    matches!(c, b"gzip" | b"x-gzip" | b"deflate" | b"br")
}

enum LayerError {
    /// Output reached budget+1: the first budget bytes.
    Limit(Vec<u8>),
    Corrupt,
}

/// Decodes a whole gzip file for data the agent fetches itself: the same strict member rules as
/// a request body, but neither the process-wide budget nor the ratio guard, and no output beyond
/// `max_output` bytes.
pub fn gunzip_to_vec(data: &[u8], max_output: usize) -> Result<Vec<u8>, &'static str> {
    let mut sink = Sink::new(data.len().saturating_mul(2), max_output.saturating_add(1));
    let res = gunzip(data, &mut sink);
    if sink.is_full() {
        return Err("output over the size limit");
    }
    res.map_err(|_| "corrupt gzip stream")?;
    Ok(sink.into_vec())
}

/// Why one coding reader stopped before a clean end.
enum Stop {
    /// Output reached the read limit (budget + 1).
    Limit,
    Corrupt,
}

/// Room for the decoded bytes of one layer: `buf[..len]` is output, the rest is zeroed space
/// that grows by doubling up to `limit`.
struct Sink {
    buf: Vec<u8>,
    len: usize,
    limit: usize,
}

impl Sink {
    /// `initial` is the first guess of the output size; it is zeroed up front, so it stays low
    /// for streams that do not compress.
    fn new(initial: usize, limit: usize) -> Self {
        let cap = initial.clamp(512, limit.max(512)).min(limit.max(1));
        Sink {
            buf: vec![0; cap],
            len: 0,
            limit,
        }
    }

    fn is_full(&self) -> bool {
        self.len >= self.limit
    }

    /// Doubles the room, up to the limit; false when it is already there.
    fn grow(&mut self) -> bool {
        if self.buf.len() >= self.limit {
            return false;
        }
        let cap = self.buf.len().saturating_mul(2).max(512).min(self.limit);
        self.buf.resize(cap, 0);
        true
    }

    fn into_vec(mut self) -> Vec<u8> {
        self.buf.truncate(self.len);
        self.buf
    }
}

/// Decodes one layer, reading at most budget bytes of output (the read limit is budget + 1).
/// Input left over after the compressed stream is an error.
fn decode_one_layer(data: &[u8], coding: &[u8], budget: i64) -> Result<Vec<u8>, LayerError> {
    let limit = usize::try_from(budget + 1).unwrap_or(0);
    if limit == 0 {
        return Err(LayerError::Limit(Vec::new()));
    }
    // The brotli decoder runs slower when its output room starts small.
    let per_wire_byte = if coding == b"br" { 4 } else { 2 };
    let mut sink = Sink::new(data.len().saturating_mul(per_wire_byte), limit);
    let res = match coding {
        b"gzip" | b"x-gzip" => gunzip(data, &mut sink),
        b"deflate" => inflate_deflate(data, &mut sink),
        b"br" => unbrotli(data, &mut sink, budget),
        _ => Err(Stop::Corrupt),
    };
    let over = sink.is_full();
    let mut out = sink.into_vec();
    if over {
        out.truncate(limit - 1);
        return Err(LayerError::Limit(out));
    }
    match res {
        Ok(()) => Ok(out),
        Err(_) => Err(LayerError::Corrupt),
    }
}

const GZIP_FHCRC: u8 = 1 << 1;
const GZIP_FEXTRA: u8 = 1 << 2;
const GZIP_FNAME: u8 = 1 << 3;
const GZIP_FCOMMENT: u8 = 1 << 4;
/// A file name or comment whose NUL sits beyond this many bytes (NUL included) is corrupt.
const GZIP_TEXT_FIELD_MAX: usize = 512;

/// Checks the gzip header at data[pos..]; returns the position after it.
fn gzip_header(data: &[u8], pos: usize) -> Result<usize, Stop> {
    let h = &data[pos..];
    if h.len() < 10 || h[..3] != [0x1f, 0x8b, 8] {
        return Err(Stop::Corrupt);
    }
    let flags = h[3];
    let mut at = 10;
    if flags & GZIP_FEXTRA != 0 {
        let xlen = h.get(at..at + 2).ok_or(Stop::Corrupt)?;
        at += 2 + usize::from(u16::from_le_bytes([xlen[0], xlen[1]]));
        if at > h.len() {
            return Err(Stop::Corrupt);
        }
    }
    for flag in [GZIP_FNAME, GZIP_FCOMMENT] {
        if flags & flag != 0 {
            let text = h.get(at..).ok_or(Stop::Corrupt)?;
            let nul = text.iter().take(GZIP_TEXT_FIELD_MAX).position(|&c| c == 0);
            at += nul.ok_or(Stop::Corrupt)? + 1;
        }
    }
    if flags & GZIP_FHCRC != 0 {
        let want = h.get(at..at + 2).ok_or(Stop::Corrupt)?;
        if u16::from_le_bytes([want[0], want[1]]) != crc32fast::hash(&h[..at]) as u16 {
            return Err(Stop::Corrupt);
        }
        at += 2;
    }
    Ok(pos + at)
}

/// Every gzip member is decoded (multistream) and its CRC-32 and size checked; trailing bytes
/// that are not another member fail.
fn gunzip(data: &[u8], sink: &mut Sink) -> Result<(), Stop> {
    let mut pos = 0;
    loop {
        pos = gzip_header(data, pos)?;
        let start = sink.len;
        pos += inflate(&data[pos..], sink)?;
        let trailer = data.get(pos..pos + 8).ok_or(Stop::Corrupt)?;
        let member = &sink.buf[start..sink.len];
        let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        let size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
        if crc != crc32fast::hash(member) || size != member.len() as u32 {
            return Err(Stop::Corrupt);
        }
        pos += 8;
        if pos == data.len() {
            return Ok(());
        }
    }
}

/// Inflates the raw RFC 1951 stream at the start of `data` into the sink, which stays full
/// when the limit is reached. Returns the input bytes the stream used. A match never reaches
/// back into the output of an earlier gzip member: the decoder sees only this stream's bytes.
fn inflate(data: &[u8], sink: &mut Sink) -> Result<usize, Stop> {
    let start = sink.len;
    let mut state = Box::<DecompressorOxide>::default();
    let mut used = 0;
    loop {
        let out_pos = sink.len - start;
        let (status, read, wrote) = decompress(
            &mut state,
            &data[used..],
            &mut sink.buf[start..],
            out_pos,
            TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        );
        used += read;
        sink.len += wrote;
        if sink.is_full() {
            return Err(Stop::Limit);
        }
        match status {
            TINFLStatus::Done => return Ok(used),
            TINFLStatus::HasMoreOutput if sink.grow() => {}
            _ => return Err(Stop::Corrupt),
        }
    }
}

/// RFC 9110 "deflate": zlib-wrapped (RFC 1950) when the first bytes are a
/// valid zlib header (see `zlib_header`), else raw RFC 1951.
fn inflate_deflate(data: &[u8], sink: &mut Sink) -> Result<(), Stop> {
    let Some(start) = zlib_header(data) else {
        let used = inflate(data, sink)?;
        return if used == data.len() {
            Ok(())
        } else {
            Err(Stop::Corrupt)
        };
    };
    let end = start + inflate(&data[start..], sink)?;
    let sum = data.get(end..end + 4).ok_or(Stop::Corrupt)?;
    let sum = u32::from_be_bytes([sum[0], sum[1], sum[2], sum[3]]);
    // A checksum mismatch and trailing data after the stream are both corrupt.
    if sum != adler2::adler32_slice(&sink.buf[..sink.len]) || end + 4 != data.len() {
        return Err(Stop::Corrupt);
    }
    Ok(())
}

/// Checks a zlib header: the deflate data offset, or None when it is not
/// valid (and the caller falls back to raw deflate).
fn zlib_header(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    let h = u16::from_be_bytes([data[0], data[1]]);
    if data[0] & 0x0f != 8 || data[0] >> 4 > 7 || !h.is_multiple_of(31) {
        return None;
    }
    if data[1] & 0x20 != 0 {
        // FDICT: no dictionary is passed, whose Adler-32 is 1.
        if data.len() < 6 || u32::from_be_bytes([data[2], data[3], data[4], data[5]]) != 1 {
            return None;
        }
        return Some(6);
    }
    Some(2)
}

/// Input piece size handed to the brotli decoder.
const BROTLI_INPUT_CHUNK_SIZE: usize = 32 * 1024;

/// Brotli with the declared window capped (see `rewrite_brotli_window_header`). The stream
/// must end exactly at the end of the input. When the input runs out first, the output the
/// decoder still holds counts as decoded before the stream is called truncated.
fn unbrotli(data: &[u8], sink: &mut Sink, budget: i64) -> Result<(), Stop> {
    let patched = rewrite_brotli_window_header(data, budget).map(|b| [b]);
    let mut pieces: Vec<&[u8]> = Vec::new();
    let rest = match &patched {
        Some(b) => {
            pieces.push(b);
            &data[1..]
        }
        None => data,
    };
    pieces.extend(rest.chunks(BROTLI_INPUT_CHUNK_SIZE));
    // Strict: the crate's default decoder accepts large-window streams; they are rejected here.
    let mut state = BrotliState::new_strict(
        StandardAlloc::default(),
        StandardAlloc::default(),
        StandardAlloc::default(),
    );
    let mut total_out = 0;
    for (i, piece) in pieces.iter().enumerate() {
        let (mut avail_in, mut read) = (piece.len(), 0);
        loop {
            if sink.len == sink.buf.len() {
                sink.grow();
            }
            let before = sink.len;
            let mut avail_out = sink.buf.len() - sink.len;
            let res = BrotliDecompressStream(
                &mut avail_in,
                &mut read,
                piece,
                &mut avail_out,
                &mut sink.len,
                &mut sink.buf,
                &mut total_out,
                &mut state,
            );
            if sink.is_full() {
                return Err(Stop::Limit);
            }
            match res {
                BrotliResult::ResultSuccess => {
                    let last = i + 1 == pieces.len();
                    return if read == piece.len() && last {
                        Ok(())
                    } else {
                        Err(Stop::Corrupt)
                    };
                }
                BrotliResult::ResultFailure => return Err(Stop::Corrupt),
                BrotliResult::NeedsMoreOutput => {}
                BrotliResult::NeedsMoreInput if read < piece.len() => return Err(Stop::Corrupt),
                BrotliResult::NeedsMoreInput if sink.len > before => {}
                BrotliResult::NeedsMoreInput => break,
            }
        }
    }
    Err(Stop::Corrupt)
}

/// Bounds an attacker-chosen coding name before it is stored in a flag or
/// match detail: [a-z0-9.+_-] only, at most 32 bytes, "invalid" when empty.
pub fn sanitize_coding_label(c: &[u8]) -> String {
    let mut b = String::new();
    for &ch in c {
        if b.len() >= CODING_LABEL_MAX_LEN {
            break;
        }
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, b'.' | b'+' | b'_' | b'-')
        {
            b.push(char::from(ch));
        }
    }
    if b.is_empty() {
        return "invalid".into();
    }
    b
}
