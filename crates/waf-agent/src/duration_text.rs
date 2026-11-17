//! Duration text parsing for the duration flags (`WAFIO_BUNDLE_CACHE_MAX_AGE`).
//! Durations are i64 nanoseconds.

const NS: u64 = 1;
const US: u64 = 1_000;
const MS: u64 = 1_000_000;
const S: u64 = 1_000_000_000;

fn unit(u: &str) -> Option<u64> {
    Some(match u {
        "ns" => NS,
        "us" | "\u{b5}s" | "\u{3bc}s" => US,
        "ms" => MS,
        "s" => S,
        "m" => 60 * S,
        "h" => 3600 * S,
        _ => return None,
    })
}

/// ASCII ≥ ' ' verbatim (`"` and `\` escaped), every other byte `\xNN`.
fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        if (c as u32) < 0x20 || (c as u32) >= 0x80 {
            let mut b = [0u8; 4];
            for byte in c.encode_utf8(&mut b).bytes() {
                out.push_str(&format!("\\x{byte:02x}"));
            }
        } else {
            if c == '"' || c == '\\' {
                out.push('\\');
            }
            out.push(c);
        }
    }
    out.push('"');
    out
}

const LIMIT: u64 = 1 << 63;

fn read_digits(s: &[u8]) -> Result<(u64, &[u8]), ()> {
    let mut x: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        if x > LIMIT / 10 {
            return Err(());
        }
        x = x * 10 + u64::from(s[i] - b'0');
        if x > LIMIT {
            return Err(());
        }
        i += 1;
    }
    Ok((x, &s[i..]))
}

fn read_fraction_digits(s: &[u8]) -> (u64, f64, &[u8]) {
    let (mut x, mut scale, mut overflow) = (0u64, 1f64, false);
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        if !overflow {
            if x > (LIMIT - 1) / 10 {
                overflow = true;
            } else {
                let y = x * 10 + u64::from(s[i] - b'0');
                if y > LIMIT {
                    overflow = true;
                } else {
                    x = y;
                    scale *= 10.0;
                }
            }
        }
        i += 1;
    }
    (x, scale, &s[i..])
}

/// Parses a duration text (decimal numbers with unit suffixes) into i64 nanoseconds.
pub fn parse_duration(orig: &str) -> Result<i64, String> {
    let invalid = || format!("time: invalid duration {}", quote(orig));
    let mut s = orig.as_bytes();
    let mut neg = false;
    if let Some(&c) = s.first()
        && (c == b'-' || c == b'+')
    {
        neg = c == b'-';
        s = &s[1..];
    }
    if s == b"0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(invalid());
    }
    let mut d: u64 = 0;
    while !s.is_empty() {
        if !(s[0] == b'.' || s[0].is_ascii_digit()) {
            return Err(invalid());
        }
        let pl = s.len();
        let (mut v, rest) = read_digits(s).map_err(|_| invalid())?;
        s = rest;
        let pre = pl != s.len();
        let (mut f, mut scale, mut post) = (0u64, 1f64, false);
        if s.first() == Some(&b'.') {
            s = &s[1..];
            let pl = s.len();
            let (ff, sc, rest) = read_fraction_digits(s);
            (f, scale, s) = (ff, sc, rest);
            post = pl != s.len();
        }
        if !pre && !post {
            return Err(invalid());
        }
        let i = s
            .iter()
            .position(|&c| c == b'.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        if i == 0 {
            return Err(format!("time: missing unit in duration {}", quote(orig)));
        }
        // The unit is a run of bytes; the input is UTF-8, and digits/'.' never split a char.
        let u = std::str::from_utf8(&s[..i]).unwrap_or("");
        s = &s[i..];
        let Some(un) = unit(u) else {
            return Err(format!(
                "time: unknown unit {} in duration {}",
                quote(u),
                quote(orig)
            ));
        };
        if v > LIMIT / un {
            return Err(invalid());
        }
        v *= un;
        if f > 0 {
            v += (f as f64 * (un as f64 / scale)) as u64;
            if v > LIMIT {
                return Err(invalid());
            }
        }
        d += v;
        if d > LIMIT {
            return Err(invalid());
        }
    }
    if neg {
        return Ok((d as i64).wrapping_neg());
    }
    if d > LIMIT - 1 {
        return Err(invalid());
    }
    Ok(d as i64)
}

#[cfg(test)]
mod tests {
    use super::parse_duration;

    #[test]
    fn duration_text_table() {
        let ok: &[(&str, i64)] = &[
            ("0", 0),
            ("5s", 5_000_000_000),
            ("30s", 30_000_000_000),
            ("1478s", 1_478_000_000_000),
            ("-5s", -5_000_000_000),
            ("+5s", 5_000_000_000),
            ("-0", 0),
            ("+0", 0),
            ("5.0s", 5_000_000_000),
            ("5.6s", 5_600_000_000),
            ("5.s", 5_000_000_000),
            (".5s", 500_000_000),
            ("1.0s", 1_000_000_000),
            ("1.00s", 1_000_000_000),
            ("1.004s", 1_004_000_000),
            ("1.0040s", 1_004_000_000),
            ("100.00100s", 100_001_000_000),
            ("10ns", 10),
            ("11us", 11_000),
            ("12\u{b5}s", 12_000),
            ("12\u{3bc}s", 12_000),
            ("13ms", 13_000_000),
            ("14s", 14_000_000_000),
            ("15m", 900_000_000_000),
            ("16h", 57_600_000_000_000),
            ("3h30m", 12_600_000_000_000),
            ("10.5s4m", 250_500_000_000),
            ("-2m3.4s", -123_400_000_000),
            ("1h2m3s4ms5us6ns", 3_723_004_005_006),
            ("39h9m14.425s", 140_954_425_000_000),
            ("52763797000ns", 52_763_797_000),
            ("0.3333333333333333333h", 1_200_000_000_000),
            ("9007199254740993ns", 9_007_199_254_740_993),
            ("9223372036854775807ns", i64::MAX),
            ("9223372036854775.807us", i64::MAX),
            ("9223372036s854ms775us807ns", i64::MAX),
            ("-9223372036854775808ns", i64::MIN),
            ("-9223372036854775.808us", i64::MIN),
            ("0.100000000000000000000h", 360_000_000_000),
            ("0.830103483285477580700h", 2_988_372_539_827),
            ("168h0m0s", 7 * 24 * 3_600_000_000_000),
        ];
        for (s, want) in ok {
            assert_eq!(parse_duration(s), Ok(*want), "{s}");
        }
        for (s, want) in [
            ("", "time: invalid duration \"\""),
            ("3", "time: missing unit in duration \"3\""),
            ("-", "time: invalid duration \"-\""),
            ("s", "time: invalid duration \"s\""),
            (".", "time: invalid duration \".\""),
            ("-.", "time: invalid duration \"-.\""),
            (".s", "time: invalid duration \".s\""),
            ("+.s", "time: invalid duration \"+.s\""),
            ("1d", "time: unknown unit \"d\" in duration \"1d\""),
            ("\u{0}", "time: invalid duration \"\\x00\""),
            (
                "9223372036854775808ns",
                "time: invalid duration \"9223372036854775808ns\"",
            ),
            (
                "9223372036854775.808us",
                "time: invalid duration \"9223372036854775.808us\"",
            ),
            (
                "9223372036854ms775us808ns",
                "time: invalid duration \"9223372036854ms775us808ns\"",
            ),
        ] {
            assert_eq!(parse_duration(s), Err(want.to_string()), "{s:?}");
        }
    }
}
