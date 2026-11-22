//! How long an app waits before it orders again: the backoff the agent sets after a failed order,
//! and the wait the authority sets when it says it limits the rate.

/// The problem type of an authority that says it has issued too much for now.
pub const RATE_LIMITED: &str = "urn:ietf:params:acme:error:rateLimited";

/// The shortest wait after a rate limit, whatever the authority says or leaves out.
pub const CA_WAIT_FLOOR: i64 = 3600;
/// The longest wait an authority can set. Its limits are counted over a week at most, and one that
/// asks for more must not be able to park an app for good.
pub const CA_WAIT_CAP: i64 = 7 * 24 * 3600;

/// The wait after `failures` failed orders in a row: 10 minutes, 1 hour, 4 hours, 12 hours, then a
/// day. Two failed validations an attempt stay under the 5 an hour the authority allows for a name.
pub fn backoff(failures: u32) -> i64 {
    match failures {
        0 | 1 => 10 * 60,
        2 => 3600,
        3 => 4 * 3600,
        4 => 12 * 3600,
        _ => 24 * 3600,
    }
}

/// The time, in seconds since the epoch, before which no order may start because the authority
/// asked for it, or 0 when it asked for nothing: only a rate limit does. The wait is the later of
/// an hour and what `Retry-After` asks for, and at most `CA_WAIT_CAP`; a header that is missing,
/// malformed or in the past asks for no more than the hour.
pub fn ca_wait_until(problem: Option<&str>, retry_after: Option<&str>, now: i64) -> i64 {
    if problem != Some(RATE_LIMITED) {
        return 0;
    }
    let asked = retry_after.and_then(|text| delay(text, now)).unwrap_or(0);
    now.saturating_add(asked.clamp(CA_WAIT_FLOOR, CA_WAIT_CAP))
}

/// The seconds from `now` that a `Retry-After` value asks for: a number of seconds or an HTTP date.
/// A date that has passed asks for none. `None` for anything else.
fn delay(text: &str, now: i64) -> Option<i64> {
    let text = text.trim();
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        // More digits than a number holds is a very long wait, which the cap cuts.
        return Some(text.parse().unwrap_or(i64::MAX));
    }
    Some(http_date(text)?.saturating_sub(now).max(0))
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// A number of exactly `digits` digits.
fn number(text: &str, digits: usize) -> Option<i64> {
    if text.len() != digits || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The seconds since the epoch of a date in the form `Sun, 06 Nov 1994 08:49:37 GMT`, the only form
/// RFC 9110 lets a sender use. The two obsolete forms are not read.
fn http_date(text: &str) -> Option<i64> {
    let (weekday, rest) = text.split_once(", ")?;
    if weekday.len() != 3 || !weekday.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let mut parts = rest.split(' ');
    let day = number(parts.next()?, 2)?;
    let name = parts.next()?;
    let month = i64::try_from(MONTHS.iter().position(|m| *m == name)?).ok()? + 1;
    let year = number(parts.next()?, 4)?;
    let mut clock = parts.next()?.split(':');
    let (hour, minute, second) = (
        number(clock.next()?, 2)?,
        number(clock.next()?, 2)?,
        number(clock.next()?, 2)?,
    );
    if clock.next().is_some() || parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second)
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn wait(problem: &str, retry_after: Option<&str>) -> i64 {
        ca_wait_until(Some(problem), retry_after, NOW) - NOW
    }

    #[test]
    fn the_backoff_climbs_from_ten_minutes_to_a_day_and_stays_there() {
        let steps: Vec<i64> = (1..=7).map(backoff).collect();
        assert_eq!(
            steps,
            [600, 3600, 4 * 3600, 12 * 3600, 86_400, 86_400, 86_400]
        );
        assert_eq!(backoff(0), 600, "no failure is read as the first");
        assert_eq!(backoff(u32::MAX), 86_400);
    }

    #[test]
    fn a_date_is_read_as_seconds_since_the_epoch() {
        // The example of the standard.
        assert_eq!(
            http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        // A leap day, and the first day after it.
        assert_eq!(
            http_date("Thu, 29 Feb 2024 00:00:00 GMT"),
            Some(1_709_164_800)
        );
        assert_eq!(
            http_date("Fri, 01 Mar 2024 00:00:00 GMT"),
            Some(1_709_251_200)
        );
        assert_eq!(
            http_date("Fri, 31 Dec 9999 23:59:59 GMT"),
            Some(253_402_300_799)
        );
        for bad in [
            "",
            "Sun, 06 Nov 1994 08:49:37",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun 06 Nov 1994 08:49:37 GMT",
            "Sun, 6 Nov 1994 08:49:37 GMT",
            "Sun, 32 Nov 1994 08:49:37 GMT",
            "Sun, 00 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nowhere 1994 08:49:37 GMT",
            "Sun, 06 Nov 94 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:49:37 GMT",
            "Sun, 06 Nov 1994 08:60:37 GMT",
            "Sun, 06 Nov 1994 08:49 GMT",
            "Sun, 06 Nov 1994 08:49:37 GMT extra",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun, 06 Nov -994 08:49:37 GMT",
        ] {
            assert_eq!(http_date(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_rate_limit_waits_an_hour_or_what_retry_after_asks_for() {
        // Seconds.
        assert_eq!(wait(RATE_LIMITED, Some("7200")), 7200);
        assert_eq!(wait(RATE_LIMITED, Some(" 7200 ")), 7200);
        assert_eq!(wait(RATE_LIMITED, Some("3600")), 3600);
        // Less than an hour is an hour.
        assert_eq!(wait(RATE_LIMITED, Some("60")), 3600);
        assert_eq!(wait(RATE_LIMITED, Some("0")), 3600);
        // An HTTP date: three hours from now, formatted by hand.
        let three_hours = NOW + 3 * 3600;
        let date = format_date(three_hours);
        assert_eq!(http_date(&date), Some(three_hours), "{date}");
        assert_eq!(wait(RATE_LIMITED, Some(&date)), 3 * 3600);
        // A date half an hour ahead is less than an hour too.
        assert_eq!(wait(RATE_LIMITED, Some(&format_date(NOW + 1800))), 3600);
    }

    #[test]
    fn a_retry_after_that_is_missing_in_the_past_or_malformed_asks_for_no_more_than_the_hour() {
        assert_eq!(wait(RATE_LIMITED, None), 3600);
        assert_eq!(wait(RATE_LIMITED, Some("")), 3600);
        assert_eq!(wait(RATE_LIMITED, Some(&format_date(NOW - 86_400))), 3600);
        assert_eq!(
            wait(RATE_LIMITED, Some("Thu, 01 Jan 1970 00:00:00 GMT")),
            3600
        );
        for bad in [
            "soon",
            "-5",
            "+7200",
            "12.5",
            "7200 seconds",
            "0x10",
            "Sun, 32 Nov 1994 08:49:37 GMT",
        ] {
            assert_eq!(wait(RATE_LIMITED, Some(bad)), 3600, "{bad:?}");
        }
    }

    #[test]
    fn a_huge_retry_after_is_cut_to_the_cap_so_an_authority_cannot_park_an_app() {
        let week = 7 * 24 * 3600;
        assert_eq!(wait(RATE_LIMITED, Some("604800")), week);
        assert_eq!(wait(RATE_LIMITED, Some("604801")), week);
        for huge in [
            "999999999999",
            "9223372036854775807",
            "9223372036854775808",
            "99999999999999999999999999999999",
            &"9".repeat(10_000),
        ] {
            assert_eq!(wait(RATE_LIMITED, Some(huge)), week, "{huge:.40}");
        }
        // A date in the year 9999.
        assert_eq!(
            wait(RATE_LIMITED, Some("Fri, 31 Dec 9999 23:59:59 GMT")),
            week
        );
    }

    #[test]
    fn whatever_the_header_says_the_wait_is_between_an_hour_and_a_week_and_nothing_panics() {
        // Strings made of the pieces of both forms, in every order a generator reaches.
        let pieces = [
            "0",
            "7",
            "99",
            "604800",
            "9223372036854775808",
            "-",
            "+",
            " ",
            ", ",
            ":",
            ".",
            "GMT",
            "Sun",
            "Nov",
            "06",
            "1994",
            "9999",
            "08:49:37",
            "\u{e9}",
            "\0",
        ];
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..20_000 {
            let mut text = String::new();
            for _ in 0..(seed % 9) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                text.push_str(pieces[usize::try_from(seed % pieces.len() as u64).unwrap()]);
            }
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let wait = ca_wait_until(Some(RATE_LIMITED), Some(&text), NOW) - NOW;
            assert!(
                (CA_WAIT_FLOOR..=CA_WAIT_CAP).contains(&wait),
                "{text:?}: {wait}"
            );
        }
    }

    #[test]
    fn only_a_rate_limit_sets_a_wait() {
        for problem in [
            None,
            Some("urn:ietf:params:acme:error:connection"),
            Some("urn:ietf:params:acme:error:serverInternal"),
            Some("rateLimited"),
        ] {
            assert_eq!(ca_wait_until(problem, Some("7200"), NOW), 0, "{problem:?}");
        }
        assert_eq!(
            ca_wait_until(Some(RATE_LIMITED), Some("7200"), NOW),
            NOW + 7200
        );
    }

    /// An HTTP date for `unix`, written without the code under test.
    fn format_date(unix: i64) -> String {
        let (days, secs) = (unix.div_euclid(86_400), unix.rem_euclid(86_400));
        // 1970-01-01 was a Thursday.
        let weekday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"]
            [usize::try_from(days.rem_euclid(7)).unwrap()];
        // The civil date of a day number (Hinnant's algorithm, the other way round).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        format!(
            "{weekday}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
            MONTHS[usize::try_from(month - 1).unwrap()],
            secs / 3600,
            secs % 3600 / 60,
            secs % 60
        )
    }
}
