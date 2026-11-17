//! RE2-style regular expressions on top of `regex::bytes`.
//!
//! Two differences between RE2 and the regex crate are closed here:
//! - Syntax: a pattern is parsed by [`crate::pattern_syntax`]: it accepts and rejects the RE2
//!   (Perl) syntax with fixed error text, and the regex crate then compiles an explicit pattern
//!   written from the syntax tree (ASCII Perl classes, `\b`, folded literals as classes, every
//!   class as ranges, flags resolved), so no construct depends on how the regex crate reads the
//!   pattern text.
//! - Invalid UTF-8: each invalid byte reads as U+FFFD (width 1). A haystack that is not valid
//!   UTF-8 is matched as the string with each invalid byte replaced by U+FFFD and every
//!   reported offset is mapped back to the original bytes, so `.`/`[^x]` match an invalid byte
//!   and submatches are slices of the original input.
//!
//! Offsets are byte offsets into the haystack, `None` stands for no match or an unmatched group.

use crate::utf8;
use regex::bytes::{CaptureLocations, Regex, RegexBuilder};
use std::borrow::Cow;
use std::cell::{Cell, RefCell};

/// A compiled regular expression.
#[derive(Clone, Debug)]
pub struct CompiledRegex {
    expr: String,
    re: Regex,
    names: Vec<String>,
    /// The pattern holds `\B`, which the regex crate also satisfies between the bytes of a
    /// multi-byte character (both sides non-word); `\B` is only tested between runes.
    has_no_word_boundary: bool,
}

/// One match: the (start, end) of every group, `None` for a group that did not take part.
pub type CaptureSpans = Vec<Option<(usize, usize)>>;

impl CompiledRegex {
    /// The error is the parse error text, or a regex-crate failure (program too big).
    pub fn compile(expr: &str) -> Result<CompiledRegex, String> {
        let (rust, names) = crate::pattern_syntax::to_rust_pattern(expr)?;
        let re = RegexBuilder::new(&rust)
            .size_limit(1 << 27)
            .dfa_size_limit(1 << 24)
            .build()
            .map_err(|e| format!("regexp: {expr:?} (as {rust:?}): {e}"))?;
        // `emit` writes this text for `\B` only (a literal backslash is a `\x{5C}` class).
        let has_no_word_boundary = rust.contains(r"(?-u:\B)");
        Ok(CompiledRegex {
            expr: expr.to_string(),
            re,
            names,
            has_no_word_boundary,
        })
    }

    pub fn compile_or_panic(expr: &str) -> CompiledRegex {
        match CompiledRegex::compile(expr) {
            Ok(r) => r,
            Err(e) => panic!("{e}"),
        }
    }

    /// The source pattern.
    pub fn as_str(&self) -> &str {
        &self.expr
    }

    /// The underlying regex crate pattern (translated).
    pub fn inner(&self) -> &Regex {
        &self.re
    }

    pub fn group_count(&self) -> usize {
        self.names.len() - 1
    }

    /// Group names ("" for an unnamed group; index 0 is the whole match).
    pub fn group_names(&self) -> &[String] {
        &self.names
    }

    pub fn is_match(&self, s: &[u8]) -> bool {
        self.is_match_text(&Text::new(s))
    }

    /// As [`Self::is_match`], on a text converted once (see [`Text`]).
    pub fn is_match_text(&self, t: &Text<'_>) -> bool {
        let h = t.hay.bytes();
        if self.has_no_word_boundary {
            return self.exec_span(h, 0).is_some();
        }
        self.re.is_match(h)
    }

    pub fn find_span(&self, s: &[u8]) -> Option<(usize, usize)> {
        self.find_span_text(&Text::new(s))
    }

    /// As [`Self::find_span`], on a text converted once (see [`Text`]).
    pub fn find_span_text(&self, t: &Text<'_>) -> Option<(usize, usize)> {
        // The first match is always accepted.
        let (a, b) = self.exec_span(t.hay.bytes(), 0)?;
        Some(t.hay.map_span(a, b))
    }

    /// The matched text (None = no match).
    pub fn find<'a>(&self, s: &'a [u8]) -> Option<&'a [u8]> {
        self.find_span(s).map(|(a, b)| &s[a..b])
    }

    pub fn find_capture_spans(&self, s: &[u8]) -> Option<CaptureSpans> {
        self.find_all_capture_spans_limited(s, 1, true)
            .into_iter()
            .next()
    }

    /// A group that did not take part is "".
    pub fn find_captures<'a>(&self, s: &'a [u8]) -> Option<Vec<&'a [u8]>> {
        self.find_capture_spans(s).map(|m| slices(s, &m))
    }

    /// At most `n` matches (n < 0: all).
    pub fn find_all_spans(&self, s: &[u8], n: isize) -> Vec<(usize, usize)> {
        self.find_all_capture_spans_limited(s, n, false)
            .into_iter()
            .filter_map(|m| m[0])
            .collect()
    }

    pub fn find_all<'a>(&self, s: &'a [u8], n: isize) -> Vec<&'a [u8]> {
        self.find_all_spans(s, n)
            .into_iter()
            .map(|(a, b)| &s[a..b])
            .collect()
    }

    pub fn find_all_capture_spans(&self, s: &[u8], n: isize) -> Vec<CaptureSpans> {
        self.find_all_capture_spans_limited(s, n, true)
    }

    pub fn find_all_captures<'a>(&self, s: &'a [u8], n: isize) -> Vec<Vec<&'a [u8]>> {
        self.find_all_capture_spans_limited(s, n, true)
            .iter()
            .map(|m| slices(s, m))
            .collect()
    }

    /// Successive matches: an empty match right after a previous match is skipped, and the
    /// search advances one rune past an empty match.
    fn find_all_capture_spans_limited(
        &self,
        s: &[u8],
        n: isize,
        groups: bool,
    ) -> Vec<CaptureSpans> {
        let hay = Hay::new(s);
        let h = hay.bytes();
        let mut locs = if groups {
            Some(self.re.capture_locations())
        } else {
            None
        };
        let n = if n < 0 { usize::MAX } else { n as usize };
        let mut out = Vec::new();
        let end = h.len();
        let mut pos = 0usize;
        let mut prev_match_end: Option<usize> = None;
        while out.len() < n && pos <= end {
            let m = match locs.as_mut() {
                Some(locs) => self.exec(h, pos, locs),
                None => self.exec_span(h, pos).map(|sp| vec![Some(sp)]),
            };
            let Some(m) = m else {
                break;
            };
            let (ms, me) = m[0].expect("group 0");
            let mut accept = true;
            if me == pos {
                if Some(ms) == prev_match_end {
                    accept = false;
                }
                let w = if pos < end {
                    utf8::decode_code_point(&h[pos..]).1
                } else {
                    0
                };
                pos = if w > 0 { pos + w } else { end + 1 };
            } else {
                pos = me;
            }
            prev_match_end = Some(me);
            if accept {
                out.push(hay.map_capture_spans(m));
            }
        }
        out
    }

    /// The next match at or after `pos` with every group (offsets in the haystack).
    fn exec(&self, h: &[u8], mut pos: usize, locs: &mut CaptureLocations) -> Option<CaptureSpans> {
        loop {
            let m = self.exec_raw(h, pos, locs)?;
            let (ms, me) = m[0].expect("group 0");
            // `\B` alone can match (empty) inside a character; only such a match is dropped, and the
            // search resumes at the next character boundary (nothing else can start in between).
            if !self.inside_char(h, ms, me) {
                return Some(m);
            }
            pos = next_boundary(h, ms);
        }
    }

    /// `exec` without groups: the span of the next match at or after `pos`.
    fn exec_span(&self, h: &[u8], mut pos: usize) -> Option<(usize, usize)> {
        loop {
            let m = self.re.find_at(h, pos)?;
            let (ms, me) = (m.start(), m.end());
            if !self.inside_char(h, ms, me) {
                return Some((ms, me));
            }
            pos = next_boundary(h, ms);
        }
    }

    fn inside_char(&self, h: &[u8], ms: usize, me: usize) -> bool {
        self.has_no_word_boundary && ms == me && ms < h.len() && h[ms] & 0xC0 == 0x80
    }

    fn exec_raw(&self, h: &[u8], pos: usize, locs: &mut CaptureLocations) -> Option<CaptureSpans> {
        self.re.captures_read_at(locs, h, pos)?;
        // The regex crate drops groups that cannot match (`(a){0}`) when they are the last
        // ones; they are reported as unmatched.
        Some(
            (0..self.names.len())
                .map(|i| if i < locs.len() { locs.get(i) } else { None })
                .collect(),
        )
    }

    /// The replace-all driver. `find` gives the next match (haystack offsets) at or after a
    /// position and may keep its groups in `state`; `repl` appends the replacement for the match
    /// (original offsets) to the output. The text is borrowed back when nothing matched.
    fn replace_all_core<'a, S>(
        &self,
        t: &Text<'a>,
        state: &mut S,
        mut find: impl FnMut(&CompiledRegex, &[u8], usize, &mut S) -> Option<(usize, usize)>,
        mut repl: impl FnMut(&mut S, &mut Vec<u8>, (usize, usize)),
    ) -> Cow<'a, [u8]> {
        let src = t.source;
        let h = t.hay.bytes();
        let mut buf: Option<Vec<u8>> = None;
        let mut last_match_end = 0usize; // original offsets
        let mut search_pos = 0usize; // haystack offsets
        let end = h.len();
        while search_pos <= end {
            let Some((hs, he)) = find(self, h, search_pos, state) else {
                break;
            };
            let (s0, s1) = t.hay.map_span(hs, he);
            let buf = buf.get_or_insert_with(|| Vec::with_capacity(src.len()));
            buf.extend_from_slice(&src[last_match_end..s0]);
            if s1 > last_match_end || s0 == 0 {
                repl(state, buf, (s0, s1));
            }
            last_match_end = s1;
            let width = if search_pos < end {
                utf8::decode_code_point(&h[search_pos..]).1
            } else {
                0
            };
            if search_pos + width > he {
                search_pos += width;
            } else if search_pos + 1 > he {
                search_pos += 1;
            } else {
                search_pos = he;
            }
        }
        match buf {
            None => Cow::Borrowed(src),
            Some(mut b) => {
                b.extend_from_slice(&src[last_match_end..]);
                Cow::Owned(b)
            }
        }
    }

    fn replace_all_spans<'a>(
        &self,
        t: &Text<'a>,
        mut repl: impl FnMut(&mut Vec<u8>, usize, usize),
    ) -> Cow<'a, [u8]> {
        self.replace_all_core(
            t,
            &mut (),
            |re, h, pos, _| re.exec_span(h, pos),
            |_, dst, (a, b)| repl(dst, a, b),
        )
    }

    /// `$1`, `${1}`, `$name`, `${name}` and `$$` are expanded in `repl`.
    pub fn replace_all(&self, src: &[u8], repl: &[u8]) -> Vec<u8> {
        self.replace_all_cow(src, repl).into_owned()
    }

    /// As [`Self::replace_all`], borrowing `src` back when nothing matched.
    pub fn replace_all_cow<'a>(&self, src: &'a [u8], repl: &[u8]) -> Cow<'a, [u8]> {
        self.replace_all_text(&Text::new(src), repl)
    }

    /// As [`Self::replace_all`], on a text converted once (see [`Text`]).
    pub fn replace_all_text<'a>(&self, t: &Text<'a>, repl: &[u8]) -> Cow<'a, [u8]> {
        if !repl.contains(&b'$') {
            return self.replace_all_spans(t, |dst, _, _| dst.extend_from_slice(repl));
        }
        let mut locs = self.re.capture_locations();
        let mut found: CaptureSpans = Vec::new();
        self.replace_all_core(
            t,
            &mut found,
            |re, h, pos, found| {
                *found = re.exec(h, pos, &mut locs)?;
                found[0]
            },
            |found, dst, _| {
                let m = t.hay.map_capture_spans(std::mem::take(found));
                self.expand(dst, repl, t.source, &m);
            },
        )
    }

    pub fn replace_all_literal(&self, src: &[u8], repl: &[u8]) -> Vec<u8> {
        self.replace_all_literal_cow(src, repl).into_owned()
    }

    /// As [`Self::replace_all_literal`], borrowing `src` back when nothing matched.
    pub fn replace_all_literal_cow<'a>(&self, src: &'a [u8], repl: &[u8]) -> Cow<'a, [u8]> {
        self.replace_all_literal_text(&Text::new(src), repl)
    }

    /// As [`Self::replace_all_literal`], on a text converted once (see [`Text`]).
    pub fn replace_all_literal_text<'a>(&self, t: &Text<'a>, repl: &[u8]) -> Cow<'a, [u8]> {
        self.replace_all_spans(t, |dst, _, _| dst.extend_from_slice(repl))
    }

    pub fn replace_all_with(&self, src: &[u8], f: impl FnMut(&[u8]) -> Vec<u8>) -> Vec<u8> {
        self.replace_all_with_cow(src, f).into_owned()
    }

    /// As [`Self::replace_all_with`], borrowing `src` back when nothing matched.
    pub fn replace_all_with_cow<'a>(
        &self,
        src: &'a [u8],
        f: impl FnMut(&[u8]) -> Vec<u8>,
    ) -> Cow<'a, [u8]> {
        self.replace_all_with_text(&Text::new(src), f)
    }

    /// As [`Self::replace_all_with`], on a text converted once (see [`Text`]).
    pub fn replace_all_with_text<'a>(
        &self,
        t: &Text<'a>,
        mut f: impl FnMut(&[u8]) -> Vec<u8>,
    ) -> Cow<'a, [u8]> {
        self.replace_all_spans(t, |dst, a, b| dst.extend_from_slice(&f(&t.source[a..b])))
    }

    /// Appends `template` to `dst`, expanding `$` references from `m`.
    pub fn expand(&self, dst: &mut Vec<u8>, template: &[u8], src: &[u8], m: &CaptureSpans) {
        let mut t = template;
        while let Some(i) = t.iter().position(|&c| c == b'$') {
            dst.extend_from_slice(&t[..i]);
            t = &t[i + 1..];
            if !t.is_empty() && t[0] == b'$' {
                dst.push(b'$');
                t = &t[1..];
                continue;
            }
            let Some((name, num, rest)) = extract(t) else {
                dst.push(b'$');
                continue;
            };
            t = rest;
            if let Some(num) = num {
                if let Some(Some((a, b))) = m.get(num) {
                    dst.extend_from_slice(&src[*a..*b]);
                }
            } else {
                for (i, n) in self.names.iter().enumerate() {
                    if n.as_bytes() == name {
                        if let Some(Some((a, b))) = m.get(i) {
                            dst.extend_from_slice(&src[*a..*b]);
                        }
                        break;
                    }
                }
            }
        }
        dst.extend_from_slice(t);
    }

    pub fn split<'a>(&self, s: &'a [u8], n: isize) -> Vec<&'a [u8]> {
        if n == 0 {
            return Vec::new();
        }
        if !self.expr.is_empty() && s.is_empty() {
            return vec![s];
        }
        let matches = self.find_all_spans(s, n);
        let mut out = Vec::new();
        let (mut beg, mut end) = (0, 0);
        for (a, b) in matches {
            if n > 0 && out.len() as isize == n - 1 {
                break;
            }
            end = a;
            if b != 0 {
                out.push(&s[beg..end]);
            }
            beg = b;
        }
        if end != s.len() {
            out.push(&s[beg..]);
        }
        out
    }
}

/// For [`CompiledRegex::expand`]: (name, number when the name is a number, rest).
fn extract(s: &[u8]) -> Option<(&[u8], Option<usize>, &[u8])> {
    if s.is_empty() {
        return None;
    }
    let (brace, s) = if s[0] == b'{' {
        (true, &s[1..])
    } else {
        (false, s)
    };
    let mut i = 0;
    while i < s.len() {
        let (r, size) = utf8::decode_code_point(&s[i..]);
        if !crate::unicode::is_letter(r) && !crate::unicode::is_digit(r) && r != b'_' as i32 {
            break;
        }
        i += size;
    }
    if i == 0 {
        return None;
    }
    let name = &s[..i];
    if brace {
        if i >= s.len() || s[i] != b'}' {
            return None;
        }
        i += 1;
    }
    let mut num: Option<usize> = Some(0);
    for &c in name {
        match num {
            Some(v) if c.is_ascii_digit() && v < 100_000_000 => {
                num = Some(v * 10 + (c - b'0') as usize)
            }
            _ => {
                num = None;
                break;
            }
        }
    }
    if name[0] == b'0' && name.len() > 1 {
        num = None;
    }
    Some((name, num, &s[i..]))
}

fn slices<'a>(s: &'a [u8], m: &CaptureSpans) -> Vec<&'a [u8]> {
    m.iter()
        .map(|g| g.map_or(&s[..0], |(a, b)| &s[a..b]))
        .collect()
}

/// The haystack the matcher sees: the input itself when it is valid UTF-8 (borrowed, validated
/// once per call), else a copy with every invalid byte replaced by U+FFFD plus the positions of
/// the replacements, which is all that is needed to map offsets back to the original bytes.
enum Hay<'a> {
    Valid(&'a [u8]),
    Mapped {
        h: Vec<u8>,
        /// Offset in `h` of the k-th U+FFFD (each stands for one invalid input byte and is
        /// 2 bytes longer than it), ascending.
        fffd: Vec<usize>,
    },
}

/// Inputs shorter than this are validated every time (cheaper than a compare).
const VALID_MEMO_MIN: usize = 512;
/// Longest input whose validity is remembered (a semantic window is at most 64 KiB).
const VALID_MEMO_MAX: usize = 64 * 1024;

/// The valid, non-ASCII inputs this thread's regex calls saw last (four, the least recently used
/// replaced). The engines run dozens of regexes over one large value and alternate between a few
/// (the window, its lower-cased copy, a decoded one); for text with multi-byte characters a compare
/// against the remembered bytes (`memcmp`, 10 to 30 times cheaper than validating) stands in for
/// `str::from_utf8` on every repeat. ASCII text is never stored: checking it is as cheap as the
/// compare. The key is the content, never the address, so the answer cannot go stale; the memory is
/// bounded (4 x [`VALID_MEMO_MAX`] per thread, sized to the text, not to the largest one seen).
/// Callers that run many regexes over one value should convert it once with [`Text`], which needs
/// no memo.
struct ValidMemo {
    slots: [Vec<u8>; VALID_MEMO_SLOTS],
    /// Last use of each slot (a tick of `VALID_CLOCK`); 0 = never used.
    used: [u64; VALID_MEMO_SLOTS],
}

const VALID_MEMO_SLOTS: usize = 4;
/// Calls of [`validate_utf8`] after which an unused slot is released.
const VALID_MEMO_RELEASE_AFTER: u64 = 4096;

thread_local! {
    static VALID_MEMO: RefCell<ValidMemo> = const {
        RefCell::new(ValidMemo { slots: [const { Vec::new() }; VALID_MEMO_SLOTS], used: [0; VALID_MEMO_SLOTS] })
    };
    /// Calls of [`validate_utf8`] on this thread (starts at 1, so 0 stays "never used").
    static VALID_CLOCK: Cell<u64> = const { Cell::new(0) };
}

/// `std::str::from_utf8(s)` without the text, remembered for large non-ASCII valid `s` (see
/// [`ValidMemo`]). The clock advances on every call, whichever way it is answered, so a
/// thread that stops seeing large multi-byte values (only short or ASCII ones) still gives the
/// remembered texts back.
fn validate_utf8(s: &[u8]) -> Result<(), std::str::Utf8Error> {
    let now = VALID_CLOCK.with(|c| {
        let n = c.get() + 1;
        c.set(n);
        n
    });
    // A slot nothing has hit for a long run of calls gives its memory back.
    if now.is_multiple_of(1024) {
        VALID_MEMO.with(|cell| {
            let mut m = cell.borrow_mut();
            for i in 0..VALID_MEMO_SLOTS {
                if m.used[i] != 0 && now - m.used[i] > VALID_MEMO_RELEASE_AFTER {
                    m.slots[i] = Vec::new();
                    m.used[i] = 0;
                }
            }
        });
    }
    if s.len() < VALID_MEMO_MIN {
        return std::str::from_utf8(s).map(drop);
    }
    if s.is_ascii() {
        return Ok(());
    }
    if s.len() > VALID_MEMO_MAX {
        return std::str::from_utf8(s).map(drop);
    }
    VALID_MEMO.with(|cell| {
        let mut m = cell.borrow_mut();
        if let Some(i) = m.slots.iter().position(|slot| slot == s) {
            m.used[i] = now;
            return Ok(());
        }
        std::str::from_utf8(s)?;
        let v = (0..VALID_MEMO_SLOTS)
            .min_by_key(|&i| m.used[i])
            .expect("slots");
        m.used[v] = now;
        let slot = &mut m.slots[v];
        slot.clear();
        if slot.capacity() > 2 * s.len() + 4096 {
            slot.shrink_to(s.len());
        }
        slot.extend_from_slice(s);
        Ok(())
    })
}

impl<'a> Hay<'a> {
    fn new(s: &'a [u8]) -> Hay<'a> {
        let mut err = match validate_utf8(s) {
            Ok(()) => return Hay::Valid(s),
            Err(e) => e,
        };
        let mut h = Vec::with_capacity(s.len() + 16);
        let mut fffd = Vec::new();
        let mut rest = s;
        loop {
            let good = err.valid_up_to();
            h.extend_from_slice(&rest[..good]);
            // Each byte of an invalid or truncated sequence reads as its own U+FFFD
            let bad = err.error_len().unwrap_or(rest.len() - good);
            for _ in 0..bad {
                fffd.push(h.len());
                h.extend_from_slice("\u{FFFD}".as_bytes());
            }
            rest = &rest[good + bad..];
            match std::str::from_utf8(rest) {
                Ok(_) => {
                    h.extend_from_slice(rest);
                    break;
                }
                Err(e) => err = e,
            }
        }
        Hay::Mapped { h, fffd }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Hay::Valid(h) => h,
            Hay::Mapped { h, .. } => h,
        }
    }

    /// The input offsets of the haystack span `a..b`.
    fn map_span(&self, a: usize, b: usize) -> (usize, usize) {
        match self {
            Hay::Valid(_) => (a, b),
            Hay::Mapped { fffd, .. } => (orig_offset(fffd, a), orig_offset(fffd, b)),
        }
    }

    fn map_capture_spans(&self, m: CaptureSpans) -> CaptureSpans {
        match self {
            Hay::Valid(_) => m,
            Hay::Mapped { fffd, .. } => m
                .into_iter()
                .map(|g| g.map(|(a, b)| (orig_offset(fffd, a), orig_offset(fffd, b))))
                .collect(),
        }
    }
}

/// A haystack as the matcher reads it (invalid bytes read as U+FFFD, offsets mapped back to
/// the input), converted once. Every `CompiledRegex` method taking `&[u8]` converts (validates) its
/// input per call; an engine that runs dozens of regexes over one value builds a `Text` first
/// and calls the `*_text` methods, which validate nothing and copy nothing.
pub struct Text<'a> {
    source: &'a [u8],
    hay: Hay<'a>,
}

impl<'a> Text<'a> {
    pub fn new(src: &'a [u8]) -> Text<'a> {
        Text {
            source: src,
            hay: Hay::new(src),
        }
    }

    /// The original bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.source
    }
}

/// First character boundary after `ms` (a continuation byte starts no character).
fn next_boundary(h: &[u8], ms: usize) -> usize {
    let mut pos = ms + 1;
    while pos < h.len() && h[pos] & 0xC0 == 0x80 {
        pos += 1;
    }
    pos
}

/// Input offset of haystack offset `x`: a position inside a U+FFFD maps to its invalid byte.
fn orig_offset(fffd: &[usize], x: usize) -> usize {
    // replacements that end at or before x
    let k = fffd.partition_point(|&p| p + 3 <= x);
    if k < fffd.len() && fffd[k] < x {
        fffd[k] - 2 * k
    } else {
        x - 2 * k
    }
}

pub fn escape_regex_meta(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for &c in s {
        if br"\.+*?()|[]{}^$".contains(&c) {
            out.push(b'\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(re: &str, s: &[u8]) -> bool {
        CompiledRegex::compile_or_panic(re).is_match(s)
    }

    #[test]
    fn perl_classes_are_ascii() {
        assert!(!m(r"^\s$", b"\x0b")); // \s excludes \v
        assert!(!m(r"^\s$", "\u{a0}".as_bytes()));
        assert!(!m(r"^\d$", "٣".as_bytes()));
        assert!(!m(r"^\w$", "é".as_bytes()));
        assert!(m(r"^\W$", "é".as_bytes()));
        assert!(m(r"a\b", "aé".as_bytes()));
        assert!(m(r"(?i)^\w$", "\u{212a}".as_bytes())); // \w folds under (?i)
        assert!(m(r"^[\s\d]+$", b" 1\t2"));
        assert!(!m(r"^[\s]$", b"\x0b"));
        assert!(m(r"^[^\s]$", b"\x0b"));
    }

    /// The chunked `Hay::new` equals the per-byte reading (the old byte loop) on every short
    /// byte string over an alphabet of lead, continuation, surrogate, overlong and ASCII bytes.
    #[test]
    fn hay_matches_per_byte_reading() {
        fn reference(s: &[u8]) -> (Vec<u8>, Vec<usize>) {
            let (mut h, mut map, mut i) = (Vec::new(), Vec::new(), 0);
            while i < s.len() {
                let (r, w) = utf8::decode_code_point(&s[i..]);
                if r == utf8::REPLACEMENT_CODE_POINT && w == 1 {
                    h.extend_from_slice("\u{FFFD}".as_bytes());
                    map.extend_from_slice(&[i, i, i]);
                } else {
                    h.extend_from_slice(&s[i..i + w]);
                    map.extend(i..i + w);
                }
                i += w;
            }
            map.push(s.len());
            (h, map)
        }
        const ALPHA: [u8; 11] = [
            b'a', 0xC3, 0xA9, 0xE2, 0x82, 0xAC, 0xF0, 0x90, 0x80, 0xED, 0xFF,
        ];
        let mut buf = Vec::new();
        fn walk(depth: usize, buf: &mut Vec<u8>) {
            let (rh, rmap) = reference(buf);
            match Hay::new(buf) {
                Hay::Valid(h) => {
                    assert_eq!(h, &buf[..]);
                    assert_eq!(rh, buf.as_slice(), "{buf:?}");
                }
                Hay::Mapped { h, fffd } => {
                    assert_eq!(h, rh, "{buf:?}");
                    for (x, &o) in rmap.iter().enumerate() {
                        assert_eq!(orig_offset(&fffd, x), o, "{buf:?} at {x}");
                    }
                }
            }
            if depth == 0 {
                return;
            }
            for &b in &ALPHA {
                buf.push(b);
                walk(depth - 1, buf);
                buf.pop();
            }
        }
        walk(5, &mut buf);
    }

    /// `\B` is tested between runes only (stepping rune by rune); the regex crate also satisfies
    /// it between the bytes of a character and of the U+FFFD that stands for an invalid byte.
    #[test]
    fn no_word_boundary_is_between_code_points_only() {
        let re = CompiledRegex::compile_or_panic(r"\B");
        for (hay, want) in [
            (&b"a\xc3\xa9"[..], vec![(3, 3)]),
            ("SSßẞ".as_bytes(), vec![(1, 1), (4, 4), (7, 7)]),
            (b"a\xffb", vec![]),
            (b"\xff\xff", vec![(0, 0), (1, 1), (2, 2)]),
            ("日本a語".as_bytes(), vec![(0, 0), (3, 3), (10, 10)]),
            (b"\xc3\xa9\xffa \xe6\x97\xa5b", vec![(0, 0), (2, 2), (5, 5)]),
        ] {
            assert_eq!(re.find_all_spans(hay, -1), want, "{hay:?}");
            assert_eq!(re.is_match(hay), !want.is_empty(), "{hay:?}");
        }
        assert_eq!(re.replace_all("aé".as_bytes(), b"-"), "aé-".as_bytes());
        // Inside a larger pattern, and with a group.
        assert_eq!(
            CompiledRegex::compile_or_panic(r"\Bb").find_all_spans(b"ab \xc3\xa9b", -1),
            vec![(1, 2)]
        );
        assert_eq!(
            CompiledRegex::compile_or_panic(r"(\B)|x").find_all_capture_spans("é".as_bytes(), -1),
            vec![
                vec![Some((0, 0)), Some((0, 0))],
                vec![Some((2, 2)), Some((2, 2))]
            ]
        );
    }

    #[test]
    fn literals_follow_reference_syntax() {
        assert!(m(r"\<a\>", b"<a>"));
        assert!(m(r"[a&&b]", b"&"));
        assert!(m(r"[+--]", b","));
        assert!(m(r"[[]", b"["));
        assert!(m(r"a{", b"a{"));
        assert!(m(r"a{,3}", b"a{,3}"));
        assert!(m(r"^a{2}$", b"aa"));
        assert!(m(r"\0", b"\0"));
        assert!(m(r"\101", b"A"));
        assert!(m(r"\Q.*\E", b".*"));
        assert!(!m(r"\Q.*\E", b"ab"));
        assert!(m(r"[]a]", b"]"));
        assert!(m(r"[a-]", b"-"));
        assert!(m(r"\/\=", b"/="));
        assert!(m(r"[[:alpha:]]", b"x"));
        assert!(m(r"(?P<n>x)(?<m>y)", b"xy"));
        assert!(CompiledRegex::compile(r"\1").is_err());
    }

    #[test]
    fn invalid_utf8_reads_as_fffd() {
        assert!(m(r"^a.b$", b"a\xffb"));
        assert!(m(r"^a[^x]b$", b"a\xffb"));
        assert!(!m(r"^a..b$", b"a\xffb"));
        assert!(m(r"^a..b$", b"a\xe2\x82b")); // two invalid bytes, two runes
        assert!(m("^a\u{FFFD}b$", b"a\xffb"));
        assert!(m(r"(?i)^\s*(GET|POST)\s+.*\s+HTTP/", b"GET /\xff HTTP/1.1"));
        let re = CompiledRegex::compile_or_panic(r"b(.)c");
        let s = b"a\xffb\xfec";
        assert_eq!(
            re.find_capture_spans(s),
            Some(vec![Some((2, 5)), Some((3, 4))])
        );
        assert_eq!(re.find_captures(s).unwrap()[1], b"\xfe");
        assert_eq!(re.replace_all(s, b"<$1>"), b"a\xff<\xfe>");
    }

    #[test]
    fn reference_syntax_gaps_closed() {
        // A repeat right after a flag-only group repeats the previous atom, with the greedy bit
        // of the flags in force after the group.
        assert_eq!(
            CompiledRegex::compile_or_panic("a(?i)*").find_span(b"aaA"),
            Some((0, 2))
        );
        assert_eq!(
            CompiledRegex::compile_or_panic("a(?U)*").find_span(b"aaa"),
            Some((0, 0))
        );
        assert_eq!(
            CompiledRegex::compile_or_panic("a(?U)*?").find_span(b"aaa"),
            Some((0, 3))
        );
        // `{01}` is not a repeat: the braces are literals.
        assert!(m(r"^x{01}$", b"x{01}"));
        assert!(!m(r"^x{01}$", b"x"));
        assert!(m(r"^x{1}$", b"x"));
        assert!(m(r"^x{,2}$", b"x{,2}"));
        // Surrogates exist as a category but never as input runes.
        assert!(!m(r"\p{Cs}", "a\u{FFFD}".as_bytes()));
        assert!(m(r"^\P{Cs}+$", "a\u{FFFD}\u{10FFFF}".as_bytes()));
        assert!(m(r"^[^\p{Surrogate}]$", b"a"));
        assert!(!m(r"[\p{Cs}]", b"a"));
        // Repeat counts are capped at 1000; the rest are rejected at compile time.
        assert!(CompiledRegex::compile("x{1000}").is_ok());
        assert!(CompiledRegex::compile("x{1001}").is_err());
        assert!(CompiledRegex::compile("x{2,1}").is_err());
        assert!(CompiledRegex::compile("(x{500}){3}").is_err());
        assert!(CompiledRegex::compile("x**").is_err());
        assert!(CompiledRegex::compile("(?:)*").is_ok());
        assert!(CompiledRegex::compile("*").is_err());
        assert_eq!(
            CompiledRegex::compile("x{1001}").err().as_deref(),
            Some("error parsing regexp: invalid repeat count: `{1001}`")
        );
        // A group that can never match still counts: later groups keep their numbers.
        let re = CompiledRegex::compile_or_panic("(a){0}(b)");
        assert_eq!(
            re.find_capture_spans(b"b"),
            Some(vec![Some((0, 1)), None, Some((0, 1))])
        );
        assert_eq!(
            CompiledRegex::compile_or_panic("x(a){0}").find_capture_spans(b"x"),
            Some(vec![Some((0, 1)), None])
        );
    }

    /// The `*_text` and `*_cow` entry points equal the plain ones, and a replace that matched
    /// nothing borrows its input back.
    #[test]
    fn text_and_cow_entry_points_match_plain_ones() {
        let hays: [&[u8]; 6] = [
            b"",
            b"plain ascii a@b c@d",
            "caf\u{e9} a@b \u{212a}".as_bytes(),
            b"a@b\xffc@d\xfe",
            b"no match here",
            b"\xc3",
        ];
        for pat in [r"(\w+)@(\w+)", r"\w*", r"\B", r"x", r"(?i)k", ""] {
            let re = CompiledRegex::compile_or_panic(pat);
            for h in hays {
                let t = Text::new(h);
                assert_eq!(t.as_bytes(), h);
                assert_eq!(re.is_match_text(&t), re.is_match(h), "{pat} {h:?}");
                assert_eq!(re.find_span_text(&t), re.find_span(h), "{pat} {h:?}");
                for repl in [&b"<$1|$2>"[..], b"-", b"$$"] {
                    let got = re.replace_all_text(&t, repl);
                    assert_eq!(
                        got.as_ref(),
                        re.replace_all(h, repl),
                        "{pat} {h:?} {repl:?}"
                    );
                }
                let got = re.replace_all_literal_text(&t, b"#");
                assert_eq!(got.as_ref(), re.replace_all_literal(h, b"#"));
                let got = re.replace_all_with_text(&t, |m| m.to_ascii_uppercase());
                assert_eq!(
                    got.as_ref(),
                    re.replace_all_with(h, |m| m.to_ascii_uppercase())
                );
            }
        }
        let re = CompiledRegex::compile_or_panic("zzz");
        assert!(matches!(re.replace_all_cow(b"abc", b"-"), Cow::Borrowed(_)));
        assert!(matches!(
            re.replace_all_literal_cow(b"abc", b"-"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            re.replace_all_with_cow(b"abc", |m| m.to_vec()),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            CompiledRegex::compile_or_panic("b").replace_all_cow(b"abc", b"-"),
            Cow::Owned(_)
        ));
    }

    /// The validation memo answers for multi-byte text without changing a result, also when the
    /// text changes by one byte or turns invalid.
    #[test]
    fn valid_memo_is_content_keyed() {
        let mut base: Vec<u8> = "h\u{e9}llo w\u{f6}rld ".repeat(80).into_bytes();
        assert!(base.len() > VALID_MEMO_MIN);
        let re = CompiledRegex::compile_or_panic(r"w.rld");
        for _ in 0..3 {
            assert!(re.is_match(&base));
        }
        let n = base.len();
        base[n - 1] = 0xff; // same length, now invalid at the end
        assert!(re.is_match(&base));
        assert!(matches!(Hay::new(&base), Hay::Mapped { .. }));
        base[5] = 0xc3; // lone lead byte inside the text
        assert!(matches!(Hay::new(&base), Hay::Mapped { .. }));
        // more distinct texts than slots, used in turn: every answer stays right
        let texts: Vec<Vec<u8>> = (0..VALID_MEMO_SLOTS + 3)
            .map(|i| format!("\u{e9}{i}").repeat(300).into_bytes())
            .collect();
        for round in 0..3 {
            for (i, t) in texts.iter().enumerate() {
                let mut t = t.clone();
                if round == 1 && i % 2 == 0 {
                    let n = t.len();
                    t[n - 2] = 0xff; // invalid, same length as a remembered text
                }
                assert_eq!(
                    matches!(Hay::new(&t), Hay::Valid(_)),
                    std::str::from_utf8(&t).is_ok()
                );
            }
        }
        let big = "\u{e9}".repeat(VALID_MEMO_MAX); // over the memo bound: validated every time
        for _ in 0..2 {
            assert!(matches!(Hay::new(big.as_bytes()), Hay::Valid(_)));
        }
    }

    /// A remembered text nothing asks for any more is released after a long run of other calls.
    #[test]
    fn valid_memo_releases_idle_slots() {
        let cold = "\u{e9}a".repeat(400).into_bytes();
        let hot = [
            "\u{f6}b".repeat(400).into_bytes(),
            "\u{fc}c".repeat(450).into_bytes(),
        ];
        assert!(matches!(Hay::new(&cold), Hay::Valid(_)));
        let held = |t: &[u8]| VALID_MEMO.with(|c| c.borrow().slots.iter().any(|s| s == t));
        assert!(held(&cold));
        for i in 0..VALID_MEMO_RELEASE_AFTER as usize + 2048 {
            assert!(matches!(Hay::new(&hot[i % 2]), Hay::Valid(_)));
        }
        assert!(!held(&cold));
        assert!(held(&hot[0]) && held(&hot[1]));
        // and it is simply validated (and remembered) again when it comes back
        assert!(matches!(Hay::new(&cold), Hay::Valid(_)));
        // the clock also runs on calls that never reach the memo (short and ASCII text)
        assert!(held(&cold));
        for i in 0..VALID_MEMO_RELEASE_AFTER as usize + 2048 {
            let t: &[u8] = if i % 2 == 0 { b"short" } else { &[b'a'; 600] };
            assert!(matches!(Hay::new(t), Hay::Valid(_)));
        }
        assert!(!held(&cold) && !held(&hot[0]));
    }

    #[test]
    fn find_all_and_replace_like_reference() {
        let re = CompiledRegex::compile_or_panic("a*");
        assert_eq!(
            re.find_all_spans(b"baaab", -1),
            vec![(0, 0), (1, 4), (5, 5)]
        );
        assert_eq!(re.replace_all(b"baaab", b"-"), b"-b-b-");
        let re = CompiledRegex::compile_or_panic("x*");
        assert_eq!(re.replace_all("éa".as_bytes(), b"-"), "-é-a-".as_bytes());
        let re = CompiledRegex::compile_or_panic(r"(\w+)@(\w+)");
        assert_eq!(
            re.replace_all(b"a@b c@d", b"$2.$1 ${1}x $3 $$ $"),
            b"b.a ax  $ $ d.c cx  $ $"
        );
        assert_eq!(re.replace_all(b"a@b", b"$1x"), b""); // $1x is the group named "1x"
        let re = CompiledRegex::compile_or_panic(r"(?P<user>\w+)@");
        assert_eq!(re.replace_all(b"bob@x", b"[$user]"), b"[bob]x");
        assert_eq!(re.replace_all_literal(b"bob@x", b"$user"), b"$userx");
        let re = CompiledRegex::compile_or_panic(",");
        assert_eq!(re.split(b"a,b,,c", -1), vec![&b"a"[..], b"b", b"", b"c"]);
        assert_eq!(re.split(b"a,b,c", 2), vec![&b"a"[..], b"b,c"]);
        let re = CompiledRegex::compile_or_panic("");
        assert_eq!(re.split(b"abc", -1), vec![&b"a"[..], b"b", b"c"]);
        let re = CompiledRegex::compile_or_panic(r"[a-z]+");
        assert_eq!(re.find_all(b"ab 12 cd ef", 2), vec![&b"ab"[..], b"cd"]);
        assert_eq!(
            re.replace_all_with(b"ab 1 cd", |m| m.to_ascii_uppercase()),
            b"AB 1 CD"
        );
    }
}
