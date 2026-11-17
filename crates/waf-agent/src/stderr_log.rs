//! A `tracing` subscriber that writes "YYYY/MM/DD HH:MM:SS message" per line on stderr,
//! without levels: every event at INFO and above is printed, fields after the message as
//! `key=value`.
//!
//! Timestamps are UTC (no tz database in the workspace).
//! Under systemd the journal adds its own timestamp.

use std::fmt::Write as _;
use std::io::Write as _;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

pub struct StderrLog;

struct Fields(String, String);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.1, " {}={value:?}", field.name());
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        } else {
            let _ = write!(self.1, " {}={value}", field.name());
        }
    }
}

/// Civil date of days since 1970-01-01.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// The "YYYY/MM/DD HH:MM:SS" timestamp prefix for a Unix time.
pub fn timestamp(unix: i64) -> String {
    let (y, m, d) = civil(unix.div_euclid(86_400));
    let s = unix.rem_euclid(86_400);
    format!(
        "{y:04}/{m:02}/{d:02} {:02}:{:02}:{:02}",
        s / 3600,
        s / 60 % 60,
        s % 60
    )
}

impl Subscriber for StderrLog {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        *m.level() <= Level::INFO
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, e: &Event<'_>) {
        let mut f = Fields(String::new(), String::new());
        e.record(&mut f);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let line = format!("{} {}{}\n", timestamp(now), f.0, f.1);
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

/// Installs [`StderrLog`] as the process-wide subscriber (once).
pub fn init() {
    let _ = tracing::subscriber::set_global_default(StderrLog);
}

#[cfg(test)]
mod tests {
    #[test]
    fn stderr_log_timestamp() {
        assert_eq!(super::timestamp(0), "1970/01/01 00:00:00");
        assert_eq!(super::timestamp(1_789_000_000), "2026/09/10 00:26:40");
        assert_eq!(super::timestamp(951_782_400), "2000/02/29 00:00:00");
    }
}
