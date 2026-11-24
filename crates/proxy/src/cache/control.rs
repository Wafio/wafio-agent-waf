//! What an answer says about keeping it: `Cache-Control`, `Expires` and `Vary`. Every reader here
//! is bounded and answers "do not keep it" for what it cannot read, never "keep it".

use crate::static_files::parse_http_date;

/// The largest lifetime the agent keeps an answer for: 365 days.
pub(crate) const MAX_LIFETIME_S: u64 = 31_536_000;
/// What a delta-seconds value above this counts as (2^31, as RFC 9111 asks of a reader that cannot
/// hold more).
const DELTA_CAP: u64 = 1 << 31;
/// The most of one `Cache-Control` line that is read, and the most directives of all the lines:
/// a header that goes past either is read as one that cannot be trusted.
const LINE_MAX: usize = 4096;
const DIRECTIVES_MAX: usize = 64;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CacheControl {
    pub no_store: bool,
    pub private: bool,
    pub no_cache: bool,
    pub public: bool,
    pub must_revalidate: bool,
    pub proxy_revalidate: bool,
    pub max_age: Option<u64>,
    pub s_maxage: Option<u64>,
    pub stale_while_revalidate: Option<u64>,
    pub stale_if_error: Option<u64>,
    /// A line that is too long, more directives than are read, or a number directive that does not
    /// parse or says two things.
    pub invalid: bool,
}

/// The directives of one line, cut at the commas that are outside a quoted string.
fn split_directives(line: &[u8]) -> Vec<&[u8]> {
    let (mut out, mut start, mut quoted, mut escaped) = (Vec::new(), 0, false, false);
    for (i, &c) in line.iter().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                quoted = false;
            }
        } else if c == b'"' {
            quoted = true;
        } else if c == b',' {
            out.push(&line[start..i]);
            start = i + 1;
        }
    }
    out.push(&line[start..]);
    out
}

fn unquote(value: &[u8]) -> &[u8] {
    match value {
        [b'"', inner @ .., b'"'] => inner,
        _ => value,
    }
}

/// A delta-seconds value: digits only, a value too big for the cap taken as the cap.
fn delta(value: &[u8]) -> Option<u64> {
    let value = unquote(value.trim_ascii());
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut n = 0u64;
    for d in value {
        n = (n * 10 + u64::from(d - b'0')).min(DELTA_CAP);
    }
    Some(n)
}

impl CacheControl {
    /// Reads every `Cache-Control` line of an answer.
    pub fn parse<'a>(lines: impl IntoIterator<Item = &'a [u8]>) -> CacheControl {
        let mut cc = CacheControl::default();
        let mut seen = 0;
        for line in lines {
            if line.len() > LINE_MAX {
                cc.invalid = true;
                continue;
            }
            for token in split_directives(line) {
                let token = token.trim_ascii();
                if token.is_empty() {
                    continue;
                }
                seen += 1;
                if seen > DIRECTIVES_MAX {
                    cc.invalid = true;
                    return cc;
                }
                let (name, value) = match token.iter().position(|&c| c == b'=') {
                    Some(at) => (&token[..at], Some(&token[at + 1..])),
                    None => (token, None),
                };
                cc.directive(&name.trim_ascii().to_ascii_lowercase(), value);
            }
        }
        cc
    }

    fn directive(&mut self, name: &[u8], value: Option<&[u8]>) {
        let number = |slot: &mut Option<u64>, invalid: &mut bool| match value.and_then(delta) {
            // The same directive twice with two values: nothing says which one holds.
            Some(n) if slot.is_none_or(|old| old == n) => *slot = Some(n),
            _ => *invalid = true,
        };
        match name {
            b"no-store" => self.no_store = true,
            b"private" => self.private = true,
            b"no-cache" => self.no_cache = true,
            b"public" => self.public = true,
            b"must-revalidate" => self.must_revalidate = true,
            b"proxy-revalidate" => self.proxy_revalidate = true,
            b"max-age" => number(&mut self.max_age, &mut self.invalid),
            b"s-maxage" => number(&mut self.s_maxage, &mut self.invalid),
            b"stale-while-revalidate" => {
                number(&mut self.stale_while_revalidate, &mut self.invalid)
            }
            b"stale-if-error" => number(&mut self.stale_if_error, &mut self.invalid),
            _ => {}
        }
    }

    /// Whether the answer says it is not for a shared cache.
    pub fn forbids_storing(&self) -> bool {
        self.no_store || self.private || self.no_cache
    }

    /// The lifetime the answer gives itself, for a shared cache: `s-maxage`, else `max-age`, else
    /// `Expires` minus `Date` (the time of the answer when `Date` is missing or does not parse;
    /// an `Expires` that does not parse is already past). `None` when it says nothing.
    pub fn lifetime(&self, expires: Option<&[u8]>, date: Option<&[u8]>, now: u64) -> Option<u64> {
        if let Some(n) = self.s_maxage.or(self.max_age) {
            return Some(n);
        }
        let expires = expires?;
        let Some(end) = parse_http_date(expires) else {
            return Some(0);
        };
        let from = date.and_then(parse_http_date).unwrap_or(now);
        Some(end.saturating_sub(from))
    }

    /// The seconds past the end of its lifetime that the answer allows itself to be sent stale:
    /// the larger of what it says for `stale-while-revalidate` and `stale-if-error`.
    pub fn stale_window(&self) -> u64 {
        self.stale_while_revalidate
            .unwrap_or(0)
            .max(self.stale_if_error.unwrap_or(0))
    }
}

/// The names an answer varies by: lower case, sorted, once each. `Err` for an answer that is not
/// kept: `*`, `Cookie`, `Authorization` (a copy cannot be told apart by them), more than four
/// names, or a name over 256 bytes.
#[allow(clippy::result_unit_err)]
pub(crate) fn vary_names<'a>(
    lines: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<Vec<u8>>, ()> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    for line in lines {
        for name in line.split(|&c| c == b',') {
            let name = name.trim_ascii().to_ascii_lowercase();
            if name.is_empty() {
                continue;
            }
            if name.len() > 256 || matches!(&name[..], b"*" | b"cookie" | b"authorization") {
                return Err(());
            }
            if !names.contains(&name) {
                names.push(name);
                if names.len() > 4 {
                    return Err(());
                }
            }
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(lines: &[&str]) -> CacheControl {
        CacheControl::parse(lines.iter().map(|l| l.as_bytes()))
    }

    #[test]
    fn the_directives_are_read_in_any_case_and_with_any_spacing() {
        let cc = parse(&["Public , MAX-AGE = 60,s-maxage=\"30\"", "must-revalidate"]);
        assert!(cc.public && cc.must_revalidate && !cc.invalid);
        assert_eq!((cc.max_age, cc.s_maxage), (Some(60), Some(30)));
        let cc = parse(&["stale-while-revalidate=5, stale-if-error=90, proxy-revalidate"]);
        assert_eq!(cc.stale_window(), 90);
        assert!(cc.proxy_revalidate);
        assert_eq!(parse(&[]), CacheControl::default());
    }

    #[test]
    fn what_forbids_storing_is_found_with_or_without_a_field_list() {
        for line in [
            "no-store",
            "private",
            "no-cache",
            "private=\"Set-Cookie, X-A\"",
            "no-cache=\"Set-Cookie\", max-age=60",
            "max-age=60, NO-STORE",
        ] {
            assert!(parse(&[line]).forbids_storing(), "{line}");
        }
        assert!(!parse(&["public, max-age=60"]).forbids_storing());
        // A comma inside a quoted list does not end the directive.
        let cc = parse(&["private=\"a, public\", max-age=5"]);
        assert!(cc.private && !cc.public);
    }

    #[test]
    fn a_number_that_does_not_parse_or_says_two_things_is_invalid() {
        for line in [
            "max-age=-1",
            "max-age=abc",
            "max-age=",
            "max-age",
            "max-age=1.5",
            "max-age=60, max-age=61",
            "s-maxage=1, s-maxage=2",
            "max-age=60 90",
        ] {
            assert!(parse(&[line]).invalid, "{line}");
        }
        assert!(!parse(&["max-age=60, max-age=60"]).invalid);
        assert_eq!(
            parse(&["max-age=99999999999999999999"]).max_age,
            Some(1 << 31)
        );
    }

    #[test]
    fn a_header_too_long_or_with_too_many_directives_cannot_be_trusted() {
        assert!(parse(&[&format!("max-age=60, {}", "a".repeat(5000))]).invalid);
        let many = vec!["a"; 70].join(",");
        assert!(parse(&[&many]).invalid);
        let sixty_four = vec!["a"; 64].join(",");
        assert!(!parse(&[&sixty_four]).invalid);
        // The directive that matters is not lost behind padding.
        let padded = format!("{} no-store", " ".repeat(4090));
        assert!(parse(&[&padded]).forbids_storing() || parse(&[&padded]).invalid);
    }

    #[test]
    fn the_lifetime_is_s_maxage_then_max_age_then_expires_minus_date() {
        let now = 1_700_000_000;
        let life = |cc: &str, expires: Option<&str>, date: Option<&str>| {
            parse(&[cc]).lifetime(expires.map(str::as_bytes), date.map(str::as_bytes), now)
        };
        assert_eq!(life("s-maxage=10, max-age=99", None, None), Some(10));
        assert_eq!(
            life("max-age=99", Some("Sun, 06 Nov 1994 08:49:37 GMT"), None),
            Some(99)
        );
        assert_eq!(life("", None, None), None);
        assert_eq!(life("public", None, None), None);
        let (expires, date) = (
            "Sun, 06 Nov 1994 08:59:37 GMT",
            Some("Sun, 06 Nov 1994 08:49:37 GMT"),
        );
        assert_eq!(life("", Some(expires), date), Some(600));
        // Expires before Date, and one that does not parse, are already past.
        assert_eq!(
            life("", Some("Sun, 06 Nov 1994 08:39:37 GMT"), date),
            Some(0)
        );
        assert_eq!(life("", Some("tomorrow"), date), Some(0));
        assert_eq!(life("", Some("0"), None), Some(0));
        // No Date: counted from now.
        let in_an_hour = crate::response::http_date(now + 3600);
        assert_eq!(life("", Some(&in_an_hour), None), Some(3600));
    }

    #[test]
    fn vary_names_are_sorted_once_each_and_the_unkeepable_ones_are_refused() {
        let names = |lines: &[&str]| vary_names(lines.iter().map(|l| l.as_bytes()));
        assert_eq!(
            names(&["Accept-Language, accept-encoding", "ACCEPT-LANGUAGE"]),
            Ok(vec![
                b"accept-encoding".to_vec(),
                b"accept-language".to_vec()
            ])
        );
        assert_eq!(names(&[]), Ok(Vec::new()));
        assert_eq!(names(&[" , "]), Ok(Vec::new()));
        for refused in ["*", "Cookie", "accept, AUTHORIZATION", "a, *"] {
            assert!(names(&[refused]).is_err(), "{refused}");
        }
        assert!(names(&["a, b, c, d"]).is_ok(), "four names pass");
        assert!(names(&["a, b, c, d, e"]).is_err(), "five are not kept");
        assert!(names(&["a, b, c", "d, a, e"]).is_err());
        assert!(names(&[&"a".repeat(256)]).is_ok());
        assert!(names(&[&"a".repeat(257)]).is_err());
    }
}
