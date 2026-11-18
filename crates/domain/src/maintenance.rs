//! The per-app maintenance settings (the `maintenance` object of a bundle app, present only while
//! maintenance mode is on). The decoding is lenient, in the style of `proxyconfig`: keys match exactly or
//! case-insensitively, unknown keys are ignored, and a bad entry is dropped with one log line. An app is
//! never failed over it.

use crate::ip_address::{parse_ip_address, parse_ip_prefix};
use crate::json_text::{self, Value, key_matches};
use crate::text_helpers::{quote, trim_whitespace};

/// What the agent needs to answer for an app in maintenance mode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MaintenanceSettings {
    /// Plain text; empty means the default message.
    pub message: String,
    /// The expected end in Unix seconds (UTC), when the object carried a valid one.
    pub end_unix: Option<i64>,
    /// The expected end as `YYYY-MM-DDTHH:MM:SSZ`; empty when `end_unix` is `None`.
    pub end_text: String,
    /// The visitor page; empty means the stock page.
    pub custom_html: String,
    /// Client IPs or CIDR ranges that get the site.
    pub allow_ips: Vec<String>,
    /// Paths that get the site, each matched against the path the upstream receives.
    pub allow_paths: Vec<Vec<u8>>,
}

impl MaintenanceSettings {
    /// Whether `path` (decoded, dot segments resolved) is let through: it equals an entry, lies
    /// below an entry (`/a` covers `/a/b`), or starts with an entry that ends in `/`. Case-sensitive.
    pub fn allows_path(&self, path: &[u8]) -> bool {
        path_matches(&self.allow_paths, path)
    }
}

/// Whether `path` equals one of `entries`, lies below one, or starts with one that ends in `/`.
pub fn path_matches(entries: &[Vec<u8>], path: &[u8]) -> bool {
    entries.iter().any(|entry| {
        path == entry.as_slice()
            || path
                .strip_prefix(entry.as_slice())
                .is_some_and(|rest| entry.last() == Some(&b'/') || rest.first() == Some(&b'/'))
    })
}

/// Reads the `maintenance` object of a bundle app. `None` for an empty value, `null`, an object
/// whose `enabled` is not `true`, and a value that is not a JSON object.
pub fn parse_maintenance(raw: &[u8]) -> Option<MaintenanceSettings> {
    let trimmed = trim_whitespace(raw);
    if trimmed.is_empty() || trimmed == b"null" {
        return None;
    }
    let Ok(Value::Object(members)) = json_text::parse(raw) else {
        tracing::warn!("[maintenance] ignored: the value is not a JSON object");
        return None;
    };
    let mut m = MaintenanceSettings::default();
    let mut enabled = false;
    for (k, v) in &members {
        if key_matches(k, "enabled") {
            enabled = matches!(v, Value::Bool(true));
        } else if key_matches(k, "message") {
            string_field(v, "message", &mut m.message);
        } else if key_matches(k, "custom_html") {
            string_field(v, "custom_html", &mut m.custom_html);
        } else if key_matches(k, "end_time") {
            let mut text = String::new();
            string_field(v, "end_time", &mut text);
            (m.end_unix, m.end_text) = match parse_end_time(&text) {
                Some(unix) => (Some(unix), text),
                None => {
                    if !text.is_empty() {
                        tracing::warn!(
                            "[maintenance] end_time {} dropped: not YYYY-MM-DDTHH:MM:SSZ",
                            quote(text.as_bytes())
                        );
                    }
                    (None, String::new())
                }
            };
        } else if key_matches(k, "allow_ips") {
            m.allow_ips = string_list(v, "allow_ips", |s| {
                let valid = if s.contains('/') {
                    parse_ip_prefix(s.as_bytes()).is_ok()
                } else {
                    parse_ip_address(s.as_bytes()).is_ok_and(|a| a.zone().is_empty())
                };
                valid.then(|| s.to_string())
            });
        } else if key_matches(k, "allow_paths") {
            m.allow_paths = string_list(v, "allow_paths", |s| {
                s.starts_with('/').then(|| s.as_bytes().to_vec())
            });
        }
    }
    enabled.then_some(m)
}

fn string_field(v: &Value, name: &str, dst: &mut String) {
    match v {
        Value::Null => {}
        Value::String(s) => *dst = String::from_utf8_lossy(s).into_owned(),
        other => tracing::warn!(
            "[maintenance] {name} ignored: expected a string, got {}",
            other.type_name()
        ),
    }
}

/// The entries of a string array that `keep` accepts, trimmed, in order. Anything else is dropped with
/// one log line each (an empty entry silently: it holds nothing).
fn string_list<T>(v: &Value, name: &str, keep: impl Fn(&str) -> Option<T>) -> Vec<T> {
    let items = match v {
        Value::Array(items) => items,
        Value::Null => return Vec::new(),
        other => {
            tracing::warn!(
                "[maintenance] {name} ignored: expected an array, got {}",
                other.type_name()
            );
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::String(s) = item else {
            tracing::warn!("[maintenance] {name} entry dropped: not a string");
            continue;
        };
        let s = String::from_utf8_lossy(s);
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        match keep(s) {
            Some(entry) => out.push(entry),
            None => tracing::warn!("[maintenance] {name} entry {} dropped", quote(s.as_bytes())),
        }
    }
    out
}

/// `YYYY-MM-DDTHH:MM:SSZ` and nothing else, as Unix seconds.
fn parse_end_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20
        || [
            (4, b'-'),
            (7, b'-'),
            (10, b'T'),
            (13, b':'),
            (16, b':'),
            (19, b'Z'),
        ]
        .iter()
        .any(|&(i, c)| b[i] != c)
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let digits = &b[from..to];
        digits
            .iter()
            .all(u8::is_ascii_digit)
            .then(|| digits.iter().fold(0, |n, &d| n * 10 + i64::from(d - b'0')))
    };
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=month_days).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days from 1970-01-01 to a proleptic Gregorian date (`month` 1..=12, `day` valid for it).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let year_of_era = y - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Collects the text of every tracing event.
    struct Collect(Arc<Mutex<Vec<String>>>);

    impl tracing::Subscriber for Collect {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Text(String);
            impl tracing::field::Visit for Text {
                fn record_debug(&mut self, _: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                    self.0.push_str(&format!("{v:?} "));
                }
            }
            let mut t = Text(String::new());
            event.record(&mut t);
            self.0.lock().unwrap().push(t.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Every test that reads a maintenance object goes through here. tracing caches whether a log
    /// site is enabled, and a site that one thread registers while another sets its collector can
    /// end up cached as disabled, so the readers of this module run one at a time.
    static READER: Mutex<()> = Mutex::new(());

    fn parse(raw: &[u8]) -> Option<MaintenanceSettings> {
        let _one_at_a_time = READER.lock().unwrap_or_else(|e| e.into_inner());
        parse_maintenance(raw)
    }

    /// The log lines `parse_maintenance` writes for `raw`.
    fn warnings(raw: &str) -> Vec<String> {
        let _one_at_a_time = READER.lock().unwrap_or_else(|e| e.into_inner());
        let lines = Arc::new(Mutex::new(Vec::new()));
        tracing::subscriber::with_default(Collect(lines.clone()), || {
            parse_maintenance(raw.as_bytes());
        });
        lines.lock().unwrap().clone()
    }

    #[test]
    fn each_dropped_entry_writes_exactly_one_warning() {
        let w = warnings(
            r#"{"enabled":true,"allow_ips":["nope","10.0.0.0/33",7,"fe80::1%eth0","","1.2.3.4"]}"#,
        );
        assert_eq!(w.len(), 4, "{w:?}");
        assert!(w.iter().all(|l| l.contains("allow_ips")), "{w:?}");
        for (line, entry) in w
            .iter()
            .zip(["nope", "10.0.0.0/33", "not a string", "fe80::1%eth0"])
        {
            assert!(line.contains(entry), "{line} should name {entry}");
        }

        let w = warnings(r#"{"enabled":true,"allow_paths":["c",null,"/a"]}"#);
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w.iter().all(|l| l.contains("allow_paths")), "{w:?}");
        assert!(
            w[0].contains("\"c\"") && w[1].contains("not a string"),
            "{w:?}"
        );
    }

    #[test]
    fn a_bad_field_value_writes_exactly_one_warning() {
        for (raw, field) in [
            (r#"{"enabled":true,"end_time":"tomorrow"}"#, "end_time"),
            (r#"{"enabled":true,"message":5}"#, "message"),
            (r#"{"enabled":true,"custom_html":[]}"#, "custom_html"),
            (r#"{"enabled":true,"allow_ips":"1.2.3.4"}"#, "allow_ips"),
            (r#"{"enabled":true,"allow_paths":{"a":1}}"#, "allow_paths"),
            (r#"[1]"#, "not a JSON object"),
            (r#""on""#, "not a JSON object"),
        ] {
            let w = warnings(raw);
            assert_eq!(w.len(), 1, "{raw}: {w:?}");
            assert!(w[0].contains(field), "{raw}: {w:?}");
        }
    }

    #[test]
    fn what_is_fine_or_empty_writes_no_warning() {
        for raw in [
            r#"{"enabled":true,"end_time":"","message":"","allow_ips":["","  "],"allow_paths":[""]}"#,
            r#"{"enabled":true,"end_time":null,"allow_ips":null,"allow_paths":null,"message":null}"#,
            r#"{"enabled":true,"end_time":"2026-11-18T22:00:00Z","allow_ips":["1.2.3.4","::1","10.0.0.0/8"],"allow_paths":["/a"]}"#,
            "",
            "null",
        ] {
            let w = warnings(raw);
            assert!(w.is_empty(), "{raw}: {w:?}");
        }
    }

    fn parsed(raw: &str) -> MaintenanceSettings {
        parse(raw.as_bytes()).expect("maintenance on")
    }

    #[test]
    fn off_or_empty_gives_none() {
        for raw in [
            "",
            "  ",
            "null",
            "{}",
            r#"{"enabled":false,"message":"x"}"#,
            r#"{"enabled":"true"}"#,
            r#"{"enabled":1}"#,
            "[]",
            "not json",
            r#""text""#,
        ] {
            assert_eq!(parse(raw.as_bytes()), None, "{raw}");
        }
    }

    #[test]
    fn a_full_object() {
        let m = parsed(
            r#"{"enabled":true,"message":"Back at nine.","end_time":"2026-11-18T22:00:00Z",
                "custom_html":"<p>{{WAFIO_MESSAGE}}</p>","allow_ips":["203.0.113.7","10.0.0.0/8","2001:db8::/32"],
                "allow_paths":["/healthz","/api/payments/webhook"],"started_at":"2026-11-18T20:00:00Z"}"#,
        );
        assert_eq!(m.message, "Back at nine.");
        assert_eq!(m.end_unix, Some(1_795_039_200));
        assert_eq!(m.end_text, "2026-11-18T22:00:00Z");
        assert_eq!(m.custom_html, "<p>{{WAFIO_MESSAGE}}</p>");
        assert_eq!(m.allow_ips, ["203.0.113.7", "10.0.0.0/8", "2001:db8::/32"]);
        assert_eq!(
            m.allow_paths,
            [b"/healthz".to_vec(), b"/api/payments/webhook".to_vec()]
        );
    }

    #[test]
    fn the_object_the_control_plane_stores_for_a_bare_switch() {
        let m = parsed(
            r#"{"enabled":true,"message":"","end_time":"","custom_html":"","allow_ips":[],"allow_paths":[],"started_at":"2026-11-18T20:00:00Z"}"#,
        );
        assert_eq!(m, MaintenanceSettings::default());
    }

    #[test]
    fn keys_match_without_case_and_unknown_keys_are_ignored() {
        let m = parsed(r#"{"ENABLED":true,"Message":"hi","future":{"a":[1]}}"#);
        assert_eq!(m.message, "hi");
        let m = parsed(r#"{"enabled":false,"enabled":true,"message":"a","message":"b"}"#);
        assert_eq!(m.message, "b", "the last occurrence wins");
        assert_eq!(parse(br#"{"enabled":true,"enabled":false}"#), None);
    }

    #[test]
    fn a_bad_end_time_is_dropped_and_the_rest_kept() {
        for bad in [
            "tomorrow",
            "2026-11-18 22:00:00Z",
            "2026-11-18T22:00:00+00:00",
            "2026-11-18T22:00:00.5Z",
            "2026-11-18T22:00Z",
            "2026-02-29T10:00:00Z",
            "2026-13-01T10:00:00Z",
            "2026-11-31T10:00:00Z",
            "2026-11-18T24:00:00Z",
            "2026-11-18T22:60:00Z",
            "2026-11-18T22:00:60Z",
            "2026-11-18t22:00:00z",
            "+026-11-18T22:00:00Z",
        ] {
            let m = parsed(&format!(
                r#"{{"enabled":true,"message":"m","end_time":"{bad}"}}"#
            ));
            assert_eq!((m.end_unix, m.end_text.as_str()), (None, ""), "{bad}");
            assert_eq!(m.message, "m");
        }
        let m = parsed(r#"{"enabled":true,"end_time":"2028-02-29T00:00:00Z"}"#);
        assert_eq!(m.end_unix, Some(1_835_395_200), "a leap day");
        let m = parsed(r#"{"enabled":true,"end_time":"1970-01-01T00:00:00Z"}"#);
        assert_eq!(m.end_unix, Some(0));
    }

    #[test]
    fn bad_entries_are_dropped_and_good_ones_kept_in_order() {
        let m = parsed(
            r#"{"enabled":true,
                "allow_ips":["  203.0.113.7  ","nope","10.0.0.0/33","",7,"fe80::1%eth0","::1","192.0.2.0/24"],
                "allow_paths":["/a"," /b ","c","","/",null,"/d/"]}"#,
        );
        assert_eq!(m.allow_ips, ["203.0.113.7", "::1", "192.0.2.0/24"]);
        assert_eq!(
            m.allow_paths,
            [
                b"/a".to_vec(),
                b"/b".to_vec(),
                b"/".to_vec(),
                b"/d/".to_vec()
            ]
        );
    }

    #[test]
    fn a_value_of_the_wrong_type_leaves_the_field_at_its_default() {
        let m = parsed(
            r#"{"enabled":true,"message":5,"custom_html":[],"end_time":7,"allow_ips":"1.2.3.4","allow_paths":{"a":1}}"#,
        );
        assert_eq!(m, MaintenanceSettings::default());
        let m = parsed(r#"{"enabled":true,"message":null,"allow_ips":null,"end_time":null}"#);
        assert_eq!(m, MaintenanceSettings::default());
    }

    #[test]
    fn path_matching() {
        let m = MaintenanceSettings {
            allow_paths: vec![
                b"/healthz".to_vec(),
                b"/static/".to_vec(),
                b"/api/payments/webhook".to_vec(),
            ],
            ..Default::default()
        };
        for yes in [
            "/healthz",
            "/healthz/",
            "/healthz/x",
            "/healthz/x/y",
            "/static/",
            "/static/app.js",
            "/api/payments/webhook",
            "/api/payments/webhook/stripe",
        ] {
            assert!(m.allows_path(yes.as_bytes()), "{yes}");
        }
        for no in [
            "/",
            "/healthzx",
            "/health",
            "/Healthz",
            "/healthz.json",
            "/static",
            "/staticx/a",
            "/admin",
            "/api/payments",
            "/x/healthz",
            "",
        ] {
            assert!(!m.allows_path(no.as_bytes()), "{no}");
        }
        assert!(!MaintenanceSettings::default().allows_path(b"/healthz"));
        let root = MaintenanceSettings {
            allow_paths: vec![b"/".to_vec()],
            ..Default::default()
        };
        assert!(
            root.allows_path(b"/anything"),
            "an entry of / lets every path through"
        );
    }

    #[test]
    fn days_from_civil_matches_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2026, 11, 18), 20_775);
        assert_eq!(parse_end_time("2038-01-19T03:14:08Z"), Some(2_147_483_648));
    }
}
