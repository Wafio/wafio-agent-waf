//! Timestamps as the cache envelope and the security-data report use them: RFC 3339 formatting
//! (seconds, or nanoseconds without trailing zeros), RFC 3339 parsing, the zero time, and a text
//! for whole-second durations (log lines).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// An instant as Unix seconds plus nanoseconds (0..1e9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub unix: i64,
    pub nanos: u32,
}

/// The zero time: 0001-01-01T00:00:00Z.
const ZERO_UNIX: i64 = -62_135_596_800;

impl Timestamp {
    pub const ZERO: Timestamp = Timestamp {
        unix: ZERO_UNIX,
        nanos: 0,
    };

    pub fn from_system(t: SystemTime) -> Self {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => Timestamp {
                unix: d.as_secs() as i64,
                nanos: d.subsec_nanos(),
            },
            Err(e) => {
                let d = e.duration();
                let (mut s, mut n) = (-(d.as_secs() as i64), d.subsec_nanos());
                if n > 0 {
                    s -= 1;
                    n = 1_000_000_000 - n;
                }
                Timestamp { unix: s, nanos: n }
            }
        }
    }

    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    /// Nanoseconds from `self` to `now` (negative when `self` is later).
    pub fn nanos_until(&self, now: SystemTime) -> i128 {
        let n = Timestamp::from_system(now);
        (n.unix as i128 - self.unix as i128) * 1_000_000_000 + n.nanos as i128 - self.nanos as i128
    }

    fn civil(&self) -> (i64, u32, u32, u32, u32, u32) {
        let days = self.unix.div_euclid(86_400);
        let secs = self.unix.rem_euclid(86_400) as u32;
        let (y, m, d) = civil_from_days(days);
        (y, m, d, secs / 3600, secs / 60 % 60, secs % 60)
    }

    /// RFC 3339 in UTC, whole seconds.
    pub fn format_rfc3339(&self) -> String {
        let (y, mo, d, h, mi, s) = self.civil();
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    }

    /// RFC 3339 in UTC with nanoseconds, trailing zeros trimmed; the form written into JSON.
    pub fn format_rfc3339_nano(&self) -> String {
        let mut out = self.format_rfc3339();
        out.pop();
        if self.nanos != 0 {
            let frac = format!("{:09}", self.nanos);
            out.push('.');
            out.push_str(frac.trim_end_matches('0'));
        }
        out.push('Z');
        out
    }

    /// Parses `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`, fraction with `.` or `,`, at most nine digits
    /// kept.
    pub fn parse_rfc3339(s: &str) -> Result<Self, String> {
        let bad = || format!("parsing time {s:?} as RFC3339: invalid");
        let b = s.as_bytes();
        let num = |from: usize, to: usize| -> Result<u32, String> {
            let part = b.get(from..to).ok_or_else(bad)?;
            if !part.iter().all(u8::is_ascii_digit) {
                return Err(bad());
            }
            Ok(part
                .iter()
                .fold(0u32, |acc, c| acc * 10 + u32::from(c - b'0')))
        };
        if b.len() < 20
            || b[4] != b'-'
            || b[7] != b'-'
            || b[10] != b'T'
            || b[13] != b':'
            || b[16] != b':'
        {
            return Err(bad());
        }
        let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
        let (hour, min, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
        let mut i = 19;
        let mut nanos = 0u32;
        if (b[i] == b'.' || b[i] == b',') && b.get(i + 1).is_some_and(u8::is_ascii_digit) {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            let digits = &b[i + 1..j];
            for k in 0..9 {
                nanos = nanos * 10 + digits.get(k).map_or(0, |c| u32::from(c - b'0'));
            }
            i = j;
        }
        let offset: i64 = match b.get(i) {
            Some(b'Z') if i + 1 == b.len() => 0,
            Some(&sign @ (b'+' | b'-')) if b.len() == i + 6 && b[i + 3] == b':' => {
                let (oh, om) = (num(i + 1, i + 3)?, num(i + 4, i + 6)?);
                if oh >= 24 || om >= 60 {
                    return Err(bad());
                }
                let o = i64::from(oh * 3600 + om * 60);
                if sign == b'-' { -o } else { o }
            }
            _ => return Err(bad()),
        };
        if !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(i64::from(year), month)
            || hour >= 24
            || min >= 60
            || sec >= 60
        {
            return Err(format!("parsing time {s:?}: value out of range"));
        }
        let days = days_from_civil(i64::from(year), month, day);
        let unix = days * 86_400 + i64::from(hour * 3600 + min * 60 + sec) - offset;
        Ok(Timestamp { unix, nanos })
    }
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Civil calendar algorithms (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Rounds `d` nanoseconds to a multiple of `m` (halfway rounds away from zero).
pub(crate) fn round_nanos(d: i128, m: i128) -> i128 {
    let r = d % m;
    if d < 0 {
        let r = -r;
        if r + r < m { d + r } else { d - m + r }
    } else if r + r < m {
        d - r
    } else {
        d + m - r
    }
}

/// Text of a whole number of seconds ("1h2m3s", "0s").
pub(crate) fn whole_seconds_text(nanos: i128) -> String {
    let s = nanos / 1_000_000_000;
    if s == 0 {
        return "0s".into();
    }
    let (sign, s) = if s < 0 { ("-", -s) } else { ("", s) };
    let (h, m, sec) = (s / 3600, s / 60 % 60, s % 60);
    if h > 0 {
        format!("{sign}{h}h{m}m{sec}s")
    } else if m > 0 {
        format!("{sign}{m}m{sec}s")
    } else {
        format!("{sign}{sec}s")
    }
}

/// Nanoseconds of `d`, saturating at the largest i64 value.
pub(crate) fn duration_nanos(d: Duration) -> i128 {
    d.as_nanos().min(i64::MAX as u128) as i128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_time_and_epoch() {
        assert_eq!(days_from_civil(1, 1, 1) * 86_400, ZERO_UNIX);
        assert_eq!(
            Timestamp::ZERO.format_rfc3339_nano(),
            "0001-01-01T00:00:00Z"
        );
        assert_eq!(
            Timestamp { unix: 0, nanos: 0 }.format_rfc3339(),
            "1970-01-01T00:00:00Z"
        );
        assert!(
            Timestamp::parse_rfc3339("0001-01-01T00:00:00Z")
                .unwrap()
                .is_zero()
        );
        assert!(
            Timestamp::parse_rfc3339("0001-01-01T07:00:00+07:00")
                .unwrap()
                .is_zero()
        );
    }

    #[test]
    fn format_matches_rfc3339nano() {
        let t = Timestamp::parse_rfc3339("2026-11-12T10:00:00.123456789Z").unwrap();
        assert_eq!(t.format_rfc3339_nano(), "2026-11-12T10:00:00.123456789Z");
        let t = Timestamp::parse_rfc3339("2026-11-12T10:00:00.120Z").unwrap();
        assert_eq!(t.format_rfc3339_nano(), "2026-11-12T10:00:00.12Z");
        let t = Timestamp::parse_rfc3339("2024-02-29T23:59:59-01:30").unwrap();
        assert_eq!(t.format_rfc3339_nano(), "2024-03-01T01:29:59Z");
        let t = Timestamp::parse_rfc3339("2026-09-28T00:00:00,5Z").unwrap();
        assert_eq!(t.nanos, 500_000_000);
        let t = Timestamp::parse_rfc3339("2026-09-28T00:00:00.1234567891Z").unwrap();
        assert_eq!(t.nanos, 123_456_789);
    }

    #[test]
    fn parse_rejects_malformed_timestamps() {
        for s in [
            "",
            "2026-09-28",
            "2026-09-28 00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-09-28T24:00:00Z",
            "2026-09-28T00:00:60Z",
            "2026-09-28T00:00:00",
            "2026-09-28T00:00:00+0700",
            "2026-09-28T00:00:00.Z",
            "2026-09-28T00:00:00Zx",
        ] {
            assert!(Timestamp::parse_rfc3339(s).is_err(), "{s}");
        }
    }

    #[test]
    fn durations_print_as_hours_minutes_seconds() {
        let s = 1_000_000_000i128;
        assert_eq!(whole_seconds_text(0), "0s");
        assert_eq!(whole_seconds_text(45 * s), "45s");
        assert_eq!(whole_seconds_text(60 * s), "1m0s");
        assert_eq!(whole_seconds_text(3723 * s), "1h2m3s");
        assert_eq!(whole_seconds_text(7 * 24 * 3600 * s), "168h0m0s");
        assert_eq!(whole_seconds_text(-5 * s), "-5s");
        assert_eq!(round_nanos(90 * s, 60 * s), 120 * s);
        assert_eq!(round_nanos(89 * s, 60 * s), 60 * s);
        assert_eq!(round_nanos(-90 * s, 60 * s), -120 * s);
    }
}
