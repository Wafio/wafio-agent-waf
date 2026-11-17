//! The byte encodings of the results a library hands back, and of the SSRF list the agent hands over. All integers
//! are little-endian. A byte string is a `u32` length and then that many bytes; a text is a byte string of UTF-8.
//! The decoders read only what the buffer holds: a short, long or malformed buffer is an error, never a panic or an
//! allocation larger than the buffer.
//!
//! Scan outcome (`wafio_engine_scan_request`):
//!
//! ```text
//! u8   tag        bit 0 a finding follows, bit 1 a held finding follows, bit 2 the source is exact,
//!                 bit 3 the coverage texts follow
//! u32  coverage   bit 0 truncated, 1 engine_panic, 2 budget, 3 field_cap, 4 query_cap, 5 binary_text,
//!                 6 header_count, 7 header_len, 8 header_skip, 9 regex_budget, 10 body_scan_gap,
//!                 11 other_scan_gap, 12 engine_absent
//! finding (bit 0):    u8 tier (1 weak, 2 strong), text reason, bytes detail, bytes source, bytes value
//! coverage texts (bit 3): text body_skipped, text transport
//! held (bit 1):       text reason, bytes detail, bytes source, u8 source_exact, bytes value (a strong finding)
//! ```
//!
//! A request with no finding and no coverage text is the five bytes of the tag and the coverage bits.
//!
//! Frame fields (`wafio_engine_frame_fields`): `u8 flags` (bit 0 field_capped, bit 1 binary_text), text `skipped`,
//! `u32 n`, then `n` times `u8 summary`, bytes `value`, bytes `source`.
//!
//! Scan value (`wafio_engine_scan_value`): `u8 flags` (bit 0 truncated, bit 1 engine_panicked, bit 2
//! budget_exhausted), `u8 tier` (0 clean, 1 weak, 2 strong), `i64 engines`, text `reason`, bytes `detail`.
//!
//! Match source (`wafio_engine_guess_match_source`): the bytes of the source, no framing.
//!
//! SSRF list (`wafio_engine_ssrf_new`): `u32 n`, `n` byte strings of hosts, `u32 m`, `m` byte strings of suffixes.

use std::fmt;

use wafio_engine_api::{
    FrameCoverage, FrameField, Held, ScanCoverage, ScanOutcome, SemanticScanResult, SsrfBlocklist,
    Tier,
};

/// Why a buffer is not a valid encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer ends before the value does.
    Truncated,
    /// A flag, a count or a text is not allowed.
    Invalid(&'static str),
    /// Bytes are left after the value.
    Trailing,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => f.write_str("the result is cut short"),
            DecodeError::Invalid(what) => write!(f, "the result is not valid: {what}"),
            DecodeError::Trailing => f.write_str("the result has bytes after its end"),
        }
    }
}

impl std::error::Error for DecodeError {}

pub fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// A length-prefixed byte string. A value of 4 GiB or more is cut at `u32::MAX` bytes.
pub fn put_bytes(out: &mut Vec<u8>, v: &[u8]) {
    let n = v.len().min(u32::MAX as usize);
    put_u32(out, n as u32);
    out.extend_from_slice(&v[..n]);
}

/// A cursor over a buffer.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    pub fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    pub fn owned_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        self.bytes().map(<[u8]>::to_vec)
    }

    pub fn text(&mut self) -> Result<String, DecodeError> {
        String::from_utf8(self.owned_bytes()?)
            .map_err(|_| DecodeError::Invalid("text is not UTF-8"))
    }

    /// A count of items that each take at least `min_item` bytes: it cannot exceed what is left.
    pub fn count(&mut self, min_item: usize) -> Result<usize, DecodeError> {
        let n = self.u32()? as usize;
        if n > self.buf.len() / min_item.max(1) {
            return Err(DecodeError::Invalid("count larger than the buffer"));
        }
        Ok(n)
    }

    pub fn finish(self) -> Result<(), DecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Trailing)
        }
    }
}

/// The number of coverage bits.
const COVERAGE_BIT_COUNT: u32 = 13;

fn coverage_bits(c: &ScanCoverage) -> u32 {
    [
        c.truncated,
        c.engine_panic,
        c.budget,
        c.field_cap,
        c.query_cap,
        c.binary_text,
        c.header_count,
        c.header_len,
        c.header_skip,
        c.regex_budget,
        c.body_scan_gap,
        c.other_scan_gap,
        c.engine_absent,
    ]
    .into_iter()
    .enumerate()
    .fold(0, |bits, (i, on)| bits | (u32::from(on) << i))
}

fn set_coverage_bits(c: &mut ScanCoverage, bits: u32) {
    let on = |i: u32| bits & (1 << i) != 0;
    c.truncated = on(0);
    c.engine_panic = on(1);
    c.budget = on(2);
    c.field_cap = on(3);
    c.query_cap = on(4);
    c.binary_text = on(5);
    c.header_count = on(6);
    c.header_len = on(7);
    c.header_skip = on(8);
    c.regex_budget = on(9);
    c.body_scan_gap = on(10);
    c.other_scan_gap = on(11);
    c.engine_absent = on(12);
}

const TAG_FINDING: u8 = 1;
const TAG_HELD: u8 = 1 << 1;
const TAG_EXACT: u8 = 1 << 2;
const TAG_COVERAGE_TEXT: u8 = 1 << 3;

fn tier_byte(t: Tier) -> u8 {
    match t {
        Tier::Clean => 0,
        Tier::Weak => 1,
        Tier::Strong => 2,
    }
}

fn tier_of(b: u8) -> Result<Tier, DecodeError> {
    match b {
        0 => Ok(Tier::Clean),
        1 => Ok(Tier::Weak),
        2 => Ok(Tier::Strong),
        _ => Err(DecodeError::Invalid("unknown tier")),
    }
}

fn has_finding(o: &ScanOutcome) -> bool {
    o.tier != Tier::Clean
        || !o.reason.is_empty()
        || !o.detail.is_empty()
        || !o.source.is_empty()
        || !o.value.is_empty()
}

/// Appends the encoding of an outcome.
pub fn encode_outcome(o: &ScanOutcome, out: &mut Vec<u8>) {
    let c = &o.coverage;
    let text = !c.body_skipped.is_empty() || !c.transport.is_empty();
    let finding = has_finding(o);
    let mut tag = 0;
    if finding {
        tag |= TAG_FINDING;
    }
    if o.held.is_some() {
        tag |= TAG_HELD;
    }
    if o.source_exact {
        tag |= TAG_EXACT;
    }
    if text {
        tag |= TAG_COVERAGE_TEXT;
    }
    put_u8(out, tag);
    put_u32(out, coverage_bits(c));
    if finding {
        put_u8(out, tier_byte(o.tier));
        put_bytes(out, o.reason.as_bytes());
        put_bytes(out, &o.detail);
        put_bytes(out, &o.source);
        put_bytes(out, &o.value);
    }
    if text {
        put_bytes(out, c.body_skipped.as_bytes());
        put_bytes(out, c.transport.as_bytes());
    }
    if let Some(h) = &o.held {
        put_bytes(out, h.reason.as_bytes());
        put_bytes(out, &h.detail);
        put_bytes(out, &h.source);
        put_u8(out, u8::from(h.source_exact));
        put_bytes(out, &h.value);
    }
}

/// Reads an outcome. A buffer of no finding allocates nothing.
pub fn decode_outcome(buf: &[u8]) -> Result<ScanOutcome, DecodeError> {
    let mut r = Reader::new(buf);
    let tag = r.u8()?;
    if tag & !(TAG_FINDING | TAG_HELD | TAG_EXACT | TAG_COVERAGE_TEXT) != 0 {
        return Err(DecodeError::Invalid("unknown tag bit"));
    }
    let bits = r.u32()?;
    if bits >> COVERAGE_BIT_COUNT != 0 {
        return Err(DecodeError::Invalid("unknown coverage bit"));
    }
    let mut o = ScanOutcome {
        source_exact: tag & TAG_EXACT != 0,
        ..Default::default()
    };
    set_coverage_bits(&mut o.coverage, bits);
    if tag & TAG_FINDING != 0 {
        o.tier = tier_of(r.u8()?)?;
        o.reason = r.text()?;
        o.detail = r.owned_bytes()?;
        o.source = r.owned_bytes()?;
        o.value = r.owned_bytes()?;
    }
    if tag & TAG_COVERAGE_TEXT != 0 {
        o.coverage.body_skipped = r.text()?;
        o.coverage.transport = r.text()?;
    }
    if tag & TAG_HELD != 0 {
        o.held = Some(Held {
            reason: r.text()?,
            detail: r.owned_bytes()?,
            source: r.owned_bytes()?,
            source_exact: match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(DecodeError::Invalid("source_exact is not 0 or 1")),
            },
            value: r.owned_bytes()?,
        });
    }
    r.finish()?;
    Ok(o)
}

/// Appends the encoding of the fields of a WebSocket frame.
pub fn encode_frame_fields(fields: &[FrameField], cov: &FrameCoverage, out: &mut Vec<u8>) {
    put_u8(
        out,
        u8::from(cov.field_capped) | (u8::from(cov.binary_text) << 1),
    );
    put_bytes(out, cov.skipped.as_bytes());
    put_u32(out, fields.len().min(u32::MAX as usize) as u32);
    for f in fields {
        put_u8(out, u8::from(f.summary));
        put_bytes(out, &f.value);
        put_bytes(out, &f.source);
    }
}

pub fn decode_frame_fields(buf: &[u8]) -> Result<(Vec<FrameField>, FrameCoverage), DecodeError> {
    let mut r = Reader::new(buf);
    let flags = r.u8()?;
    if flags > 3 {
        return Err(DecodeError::Invalid("unknown frame flag"));
    }
    let cov = FrameCoverage {
        field_capped: flags & 1 != 0,
        binary_text: flags & 2 != 0,
        skipped: r.text()?,
    };
    let n = r.count(9)?;
    let mut fields = Vec::with_capacity(n);
    for _ in 0..n {
        let summary = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(DecodeError::Invalid("summary is not 0 or 1")),
        };
        fields.push(FrameField {
            summary,
            value: r.owned_bytes()?,
            source: r.owned_bytes()?,
        });
    }
    r.finish()?;
    Ok((fields, cov))
}

/// Appends the encoding of a value scan. The reason is carried as text.
pub fn encode_scan_value(r: &SemanticScanResult, out: &mut Vec<u8>) {
    put_u8(
        out,
        u8::from(r.truncated)
            | (u8::from(r.engine_panicked) << 1)
            | (u8::from(r.budget_exhausted) << 2),
    );
    put_u8(out, tier_byte(r.tier));
    put_i64(out, r.engines);
    put_bytes(out, r.reason.as_bytes());
    put_bytes(out, &r.detail);
}

/// Reads a value scan. `reason` maps the text to the static string of the result.
pub fn decode_scan_value(
    buf: &[u8],
    reason: impl FnOnce(&str) -> &'static str,
) -> Result<SemanticScanResult, DecodeError> {
    let mut r = Reader::new(buf);
    let flags = r.u8()?;
    if flags > 7 {
        return Err(DecodeError::Invalid("unknown scan flag"));
    }
    let tier = tier_of(r.u8()?)?;
    let engines = r.i64()?;
    let text = r.text()?;
    let detail = r.owned_bytes()?;
    r.finish()?;
    Ok(SemanticScanResult {
        tier,
        reason: reason(&text),
        detail,
        truncated: flags & 1 != 0,
        engine_panicked: flags & 2 != 0,
        budget_exhausted: flags & 4 != 0,
        engines,
    })
}

/// The encoding of an SSRF list.
pub fn encode_ssrf(b: &SsrfBlocklist) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, b.hosts.len().min(u32::MAX as usize) as u32);
    for h in &b.hosts {
        put_bytes(&mut out, h);
    }
    put_u32(&mut out, b.suffixes.len().min(u32::MAX as usize) as u32);
    for s in &b.suffixes {
        put_bytes(&mut out, s);
    }
    out
}

pub fn decode_ssrf(buf: &[u8]) -> Result<SsrfBlocklist, DecodeError> {
    let mut r = Reader::new(buf);
    let mut list = SsrfBlocklist::default();
    for _ in 0..r.count(4)? {
        list.hosts.insert(r.owned_bytes()?);
    }
    for _ in 0..r.count(4)? {
        list.suffixes.push(r.owned_bytes()?);
    }
    r.finish()?;
    Ok(list)
}
