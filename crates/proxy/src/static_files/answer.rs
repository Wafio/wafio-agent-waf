//! What a request gets for a file that was found: the validators, the conditional headers and the
//! range. Pure functions of the file's size and modification time and of the request's headers.

/// What the answer is made from: the size and the modification time (whole seconds) of the
/// file as `fstat` said when it was opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Meta {
    pub size: u64,
    pub mtime: u64,
}

impl Meta {
    /// `"<mtime in hex>-<size in hex>"`, quoted. Strong: the same two numbers are the same file
    /// as far as a folder of files can tell.
    pub fn etag(&self) -> String {
        format!("\"{:x}-{:x}\"", self.mtime, self.size)
    }
}

/// The request headers that decide the answer. An empty value is an absent header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Conditions {
    pub if_none_match: Vec<u8>,
    pub if_modified_since: Vec<u8>,
    pub range: Vec<u8>,
    pub if_range: Vec<u8>,
}

/// What to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Plan {
    /// `304`, no body.
    NotModified,
    /// `416`: the range is outside the file.
    Unsatisfiable,
    /// `200`, the whole file.
    Whole,
    /// `206`, `len` bytes from `start`.
    Part { start: u64, len: u64 },
}

/// A date that is one of the two the validators use. Only the form HTTP servers write (`Sun, 06
/// Nov 1994 08:49:37 GMT`) is read: any other form is no date, and a header that holds one is
/// left out of the decision.
pub(crate) fn parse_http_date(value: &[u8]) -> Option<u64> {
    const MONTHS: [&[u8]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];
    let v = value.trim_ascii();
    if v.len() != 29
        || !v[..3].iter().all(u8::is_ascii_alphabetic)
        || &v[3..5] != b", "
        || (v[7], v[11], v[16], v[19], v[22]) != (b' ', b' ', b' ', b':', b':')
        || &v[25..] != b" GMT"
    {
        return None;
    }
    let number = |at: usize, n: usize| -> Option<u64> {
        let digits = &v[at..at + n];
        digits.iter().all(u8::is_ascii_digit).then(|| {
            digits
                .iter()
                .fold(0, |acc, d| acc * 10 + u64::from(d - b'0'))
        })
    };
    let (day, year) = (number(5, 2)?, number(12, 4)?);
    let month = u64::try_from(MONTHS.iter().position(|m| *m == &v[8..11])?).ok()? + 1;
    let (hour, minute, second) = (number(17, 2)?, number(20, 2)?, number(23, 2)?);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let month_days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if year < 1970 || !(1..=month_days).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Days from the civil date (the inverse of the formatter in `response`).
    let y = i64::try_from(year).ok()? - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy =
        (153 * ((i64::try_from(month).ok()? + 9) % 12) + 2) / 5 + i64::try_from(day).ok()? - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = u64::try_from(era * 146_097 + doe - 719_468).ok()?;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Whether an `If-None-Match` value names this file: `*`, or a list of entity tags one of which
/// is the file's, compared weakly (a `W/` in front does not matter).
fn none_match(value: &[u8], etag: &str) -> bool {
    let value = value.trim_ascii();
    value == b"*"
        || value.split(|&c| c == b',').any(|tag| {
            let tag = tag.trim_ascii();
            tag.strip_prefix(b"W/").unwrap_or(tag) == etag.as_bytes()
        })
}

/// Whether `If-Range` says the file is still the one the client has a part of: its strong tag, or
/// exactly its modification date. A weak tag never does.
fn still_the_same(value: &[u8], meta: &Meta) -> bool {
    let value = value.trim_ascii();
    if value.starts_with(b"\"") {
        value == meta.etag().as_bytes()
    } else {
        !value.starts_with(b"W/") && parse_http_date(value) == Some(meta.mtime)
    }
}

/// What a `Range` header asks of a file of `size` bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Asked {
    /// Not a range this server answers: no `bytes` unit, several ranges, a form that does not
    /// parse, or an end before its start. The whole file is sent.
    Ignored,
    Unsatisfiable,
    Part {
        start: u64,
        len: u64,
    },
}

/// `text` cut at the first `byte`, without it.
fn split_at_byte(text: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let at = text.iter().position(|&c| c == byte)?;
    Some((&text[..at], &text[at + 1..]))
}

fn digits(text: &[u8]) -> Option<u64> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}

pub(crate) fn asked(value: &[u8], size: u64) -> Asked {
    let Some((unit, ranges)) = split_at_byte(value.trim_ascii(), b'=') else {
        return Asked::Ignored;
    };
    if !unit.eq_ignore_ascii_case(b"bytes") || ranges.contains(&b',') {
        return Asked::Ignored;
    }
    let Some((first, last)) = split_at_byte(ranges, b'-') else {
        return Asked::Ignored;
    };
    match (first, last) {
        // The last N bytes.
        ([], n) => match digits(n) {
            None => Asked::Ignored,
            Some(0) => Asked::Unsatisfiable,
            Some(_) if size == 0 => Asked::Unsatisfiable,
            Some(n) => {
                let len = n.min(size);
                Asked::Part {
                    start: size - len,
                    len,
                }
            }
        },
        // From a byte to the end.
        (from, []) => match digits(from) {
            None => Asked::Ignored,
            Some(from) if from >= size => Asked::Unsatisfiable,
            Some(from) => Asked::Part {
                start: from,
                len: size - from,
            },
        },
        (from, to) => match (digits(from), digits(to)) {
            (Some(from), Some(to)) if to >= from => {
                if from >= size {
                    Asked::Unsatisfiable
                } else {
                    Asked::Part {
                        start: from,
                        len: to.min(size - 1) - from + 1,
                    }
                }
            }
            _ => Asked::Ignored,
        },
    }
}

/// The answer for a file and a request. `If-None-Match` decides, and without it `If-Modified-Since`;
/// then a `Range` is read, unless `If-Range` says the file changed.
pub(super) fn plan(meta: &Meta, c: &Conditions) -> Plan {
    let unchanged = if c.if_none_match.is_empty() {
        parse_http_date(&c.if_modified_since).is_some_and(|since| meta.mtime <= since)
    } else {
        none_match(&c.if_none_match, &meta.etag())
    };
    if unchanged {
        return Plan::NotModified;
    }
    if c.range.is_empty() || (!c.if_range.is_empty() && !still_the_same(&c.if_range, meta)) {
        return Plan::Whole;
    }
    match asked(&c.range, meta.size) {
        Asked::Ignored => Plan::Whole,
        Asked::Unsatisfiable => Plan::Unsatisfiable,
        Asked::Part { start, len } => Plan::Part { start, len },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::http_date;

    const M: Meta = Meta {
        size: 1000,
        mtime: 1_700_000_000,
    };

    fn conditions(range: &str) -> Conditions {
        Conditions {
            range: range.into(),
            ..Conditions::default()
        }
    }

    fn part(start: u64, len: u64) -> Plan {
        Plan::Part { start, len }
    }

    #[test]
    fn the_validator_is_the_time_and_the_size_in_hex() {
        assert_eq!(M.etag(), "\"6553f100-3e8\"");
        let other = Meta { size: 1001, ..M };
        assert_ne!(M.etag(), other.etag());
    }

    #[test]
    fn a_date_is_read_back_to_the_second_it_was_written_from() {
        for unix in [
            0,
            1,
            784_111_777,
            1_136_214_245,
            1_709_164_799,
            1_709_164_800,
            4_102_444_800,
        ] {
            assert_eq!(
                parse_http_date(http_date(unix).as_bytes()),
                Some(unix),
                "{unix}"
            );
        }
        assert_eq!(
            parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(
            parse_http_date(b"  Sun, 06 Nov 1994 08:49:37 GMT "),
            Some(784_111_777)
        );
    }

    #[test]
    fn a_value_that_is_not_the_one_date_form_is_no_date() {
        for bad in [
            "",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 06 Nov 1994 08:49:37",
            "Sun, 6 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nox 1994 08:49:37 GMT",
            "Sun, 31 Nov 1994 08:49:37 GMT",
            "Sun, 29 Feb 1995 08:49:37 GMT",
            "Sun, 00 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:49:37 GMT",
            "Sun, 06 Nov 1994 08:60:37 GMT",
            "Sun, 06 Nov 1994 08:49:60 GMT",
            "Sun, 06 Nov 1969 08:49:37 GMT",
            "Sun, 06 Nov 19x4 08:49:37 GMT",
            "Sun,06 Nov 1994 08:49:37 GMT ",
            "1994-11-06T08:49:37Z",
        ] {
            assert_eq!(parse_http_date(bad.as_bytes()), None, "{bad:?}");
        }
        assert!(parse_http_date(b"Thu, 29 Feb 2024 00:00:00 GMT").is_some());
    }

    #[test]
    fn if_none_match_is_compared_weakly_and_wins_over_if_modified_since() {
        let tag = M.etag();
        for (value, hit) in [
            (tag.clone(), true),
            (format!("W/{tag}"), true),
            (format!("\"a\", {tag}"), true),
            (format!("\"a\",W/{tag} , \"b\""), true),
            ("*".into(), true),
            ("  *  ".into(), true),
            ("\"other\"".into(), false),
            (format!("{}x", &tag[..tag.len() - 1]) + "\"", false),
            ("\"a\", \"b\"".into(), false),
            (tag.trim_matches('"').to_owned(), false),
        ] {
            let c = Conditions {
                if_none_match: value.clone().into(),
                ..Conditions::default()
            };
            let want = if hit { Plan::NotModified } else { Plan::Whole };
            assert_eq!(plan(&M, &c), want, "{value}");
        }
        // With a tag that does not match, a date that would match does not count.
        let c = Conditions {
            if_none_match: b"\"nope\"".to_vec(),
            if_modified_since: http_date(M.mtime + 10).into(),
            ..Conditions::default()
        };
        assert_eq!(plan(&M, &c), Plan::Whole);
    }

    #[test]
    fn if_modified_since_is_not_modified_at_or_after_the_modification_time() {
        let since = |unix: u64| Conditions {
            if_modified_since: http_date(unix).into(),
            ..Conditions::default()
        };
        assert_eq!(plan(&M, &since(M.mtime)), Plan::NotModified);
        assert_eq!(plan(&M, &since(M.mtime + 1)), Plan::NotModified);
        assert_eq!(plan(&M, &since(M.mtime - 1)), Plan::Whole);
        let garbage = Conditions {
            if_modified_since: b"yesterday".to_vec(),
            ..Conditions::default()
        };
        assert_eq!(plan(&M, &garbage), Plan::Whole);
    }

    #[test]
    fn a_range_is_one_span_clamped_to_the_file() {
        for (range, want) in [
            ("bytes=0-0", part(0, 1)),
            ("bytes=0-499", part(0, 500)),
            ("bytes=500-999", part(500, 500)),
            ("bytes=500-", part(500, 500)),
            ("bytes=999-", part(999, 1)),
            ("bytes=0-", part(0, 1000)),
            ("bytes=-1", part(999, 1)),
            ("bytes=-500", part(500, 500)),
            ("bytes=-1000", part(0, 1000)),
            ("bytes=-99999", part(0, 1000)),
            ("bytes=990-5000", part(990, 10)),
            ("bytes=0-99999999999", part(0, 1000)),
            ("BYTES=0-9", part(0, 10)),
            ("  bytes=0-9  ", part(0, 10)),
        ] {
            assert_eq!(plan(&M, &conditions(range)), want, "{range}");
        }
    }

    #[test]
    fn a_range_outside_the_file_is_unsatisfiable() {
        for range in [
            "bytes=1000-",
            "bytes=1000-1001",
            "bytes=5000-6000",
            "bytes=-0",
            "bytes=99999999999-",
        ] {
            assert_eq!(plan(&M, &conditions(range)), Plan::Unsatisfiable, "{range}");
        }
        // Nothing of an empty file is in range.
        let empty = Meta { size: 0, ..M };
        for range in ["bytes=0-", "bytes=0-0", "bytes=-1", "bytes=-0"] {
            assert_eq!(
                plan(&empty, &conditions(range)),
                Plan::Unsatisfiable,
                "{range}"
            );
        }
        assert_eq!(plan(&empty, &Conditions::default()), Plan::Whole);
    }

    #[test]
    fn several_ranges_and_forms_that_do_not_parse_send_the_whole_file() {
        for range in [
            "bytes=0-9,20-29",
            "bytes=0-9, 20-",
            "bytes=-5,-6",
            "items=0-9",
            "bytes",
            "bytes=",
            "bytes=-",
            "bytes=a-b",
            "bytes=1-b",
            "bytes=a-1",
            "bytes=10-5",
            "bytes=0-9x",
            "bytes= 0-9",
            "bytes=0 -9",
            "bytes=+1-5",
            "bytes=--5",
            "bytes=1--5",
            "bytes=99999999999999999999-",
            "bytes=0-99999999999999999999",
            "0-9",
            "=0-9",
        ] {
            assert_eq!(plan(&M, &conditions(range)), Plan::Whole, "{range}");
        }
    }

    #[test]
    fn if_range_keeps_the_range_only_for_the_same_file() {
        let range = |if_range: &str| Conditions {
            range: b"bytes=0-9".to_vec(),
            if_range: if_range.into(),
            ..Conditions::default()
        };
        let tag = M.etag();
        assert_eq!(plan(&M, &range(&tag)), part(0, 10));
        assert_eq!(plan(&M, &range(&http_date(M.mtime))), part(0, 10));
        for stale in [
            "\"another\"".to_owned(),
            format!("W/{tag}"),
            http_date(M.mtime + 1),
            http_date(M.mtime - 1),
            "garbage".to_owned(),
            "6553f100-3e8".to_owned(),
        ] {
            assert_eq!(plan(&M, &range(&stale)), Plan::Whole, "{stale}");
        }
        // Without a Range an If-Range means nothing.
        let c = Conditions {
            if_range: tag.into(),
            ..Conditions::default()
        };
        assert_eq!(plan(&M, &c), Plan::Whole);
    }

    #[test]
    fn a_condition_that_holds_ends_the_request_before_the_range_is_read() {
        let c = Conditions {
            if_none_match: M.etag().into(),
            range: b"bytes=5000-".to_vec(),
            ..Conditions::default()
        };
        assert_eq!(plan(&M, &c), Plan::NotModified);
    }
}
