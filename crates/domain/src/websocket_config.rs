//! Validation of the agent-only `websocket` section of an app's rules_json. Includes a private
//! URL parser for the parts the origin check reads.

use crate::ip_address::parse_ip_address;
use crate::json_text::{self, Value, key_matches, type_mismatch_text};
use crate::text_helpers::{quote, to_lowercase, trim_whitespace};

/// A websocket section error (user-facing message).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketConfigError(pub String);

impl std::fmt::Display for WebSocketConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WebSocketConfigError {}

fn fail<T>(s: impl Into<String>) -> Result<T, WebSocketConfigError> {
    Err(WebSocketConfigError(s.into()))
}

/// The last member with exactly this key.
fn map_get<'v>(m: &'v [(Vec<u8>, Value)], key: &str) -> Option<&'v Value> {
    m.iter()
        .rev()
        .find(|(k, _)| k.as_slice() == key.as_bytes())
        .map(|(_, v)| v)
}

#[derive(Default)]
struct OriginCheck {
    enabled: bool,
    allowed_origins: Vec<Vec<u8>>,
}

#[derive(Default)]
struct Limits {
    max_text_bytes: i64,
    max_binary_bytes: i64,
    max_msgs_per_min: i64,
}

#[derive(Default)]
struct WebSocketRules {
    origin_check: Option<OriginCheck>,
    limits: Option<Limits>,
}

/// Decodes the config members: the first type error, or the decoded pointers.
fn decode_rules(members: &[(Vec<u8>, Value)]) -> Result<WebSocketRules, String> {
    let mut cfg = WebSocketRules::default();
    let mut first: Option<String> = None;
    let mut type_err = |v: &Value, field: &str, ty: &str| {
        if first.is_none() {
            first = Some(type_mismatch_text(field, &v.kind_text(), ty));
        }
    };
    let int =
        |v: &Value, dst: &mut i64, field: &str, te: &mut dyn FnMut(&Value, &str, &str)| match v {
            Value::Null => {}
            Value::Number(n) => match std::str::from_utf8(n)
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
            {
                Some(x) => *dst = x,
                None => te(v, field, "int"),
            },
            _ => te(v, field, "int"),
        };
    for (k, v) in members {
        if key_matches(k, "enabled")
            || key_matches(k, "scan_binary_hashes")
            || key_matches(k, "scan_server_frames")
        {
            if !matches!(v, Value::Null | Value::Bool(_)) {
                let name = if key_matches(k, "enabled") {
                    "enabled"
                } else if key_matches(k, "scan_binary_hashes") {
                    "scan_binary_hashes"
                } else {
                    "scan_server_frames"
                };
                type_err(v, name, "bool");
            }
        } else if key_matches(k, "origin_check") {
            match v {
                Value::Null => cfg.origin_check = None,
                Value::Object(m) => {
                    let oc = cfg.origin_check.get_or_insert_with(OriginCheck::default);
                    for (ok, ov) in m {
                        if key_matches(ok, "enabled") {
                            match ov {
                                Value::Null => {}
                                Value::Bool(b) => oc.enabled = *b,
                                _ => type_err(ov, "origin_check.enabled", "bool"),
                            }
                        } else if key_matches(ok, "allowed_origins") {
                            match ov {
                                Value::Null => oc.allowed_origins.clear(),
                                Value::Array(items) => {
                                    let mut out = Vec::with_capacity(items.len());
                                    for (i, it) in items.iter().enumerate() {
                                        match it {
                                            Value::String(s) => out.push(s.clone()),
                                            Value::Null => out.push(
                                                oc.allowed_origins
                                                    .get(i)
                                                    .cloned()
                                                    .unwrap_or_default(),
                                            ),
                                            _ => {
                                                type_err(
                                                    it,
                                                    "origin_check.allowed_origins",
                                                    "string",
                                                );
                                                out.push(Vec::new());
                                            }
                                        }
                                    }
                                    oc.allowed_origins = out;
                                }
                                _ => type_err(ov, "origin_check.allowed_origins", "[]string"),
                            }
                        }
                    }
                }
                _ => type_err(v, "origin_check", "struct"),
            }
        } else if key_matches(k, "limits") {
            match v {
                Value::Null => cfg.limits = None,
                Value::Object(m) => {
                    let lim = cfg.limits.get_or_insert_with(Limits::default);
                    for (lk, lv) in m {
                        if key_matches(lk, "max_text_bytes") {
                            int(
                                lv,
                                &mut lim.max_text_bytes,
                                "limits.max_text_bytes",
                                &mut type_err,
                            );
                        } else if key_matches(lk, "max_binary_bytes") {
                            int(
                                lv,
                                &mut lim.max_binary_bytes,
                                "limits.max_binary_bytes",
                                &mut type_err,
                            );
                        } else if key_matches(lk, "max_messages_per_min") {
                            int(
                                lv,
                                &mut lim.max_msgs_per_min,
                                "limits.max_messages_per_min",
                                &mut type_err,
                            );
                        }
                    }
                }
                _ => type_err(v, "limits", "struct"),
            }
        }
    }
    match first {
        Some(e) => Err(e),
        None => Ok(cfg),
    }
}

fn reject_nulls(
    prefix: &str,
    fields: Option<&[(Vec<u8>, Value)]>,
    keys: &[&str],
) -> Result<(), WebSocketConfigError> {
    let Some(fields) = fields else { return Ok(()) };
    for key in keys {
        if let Some(Value::Null) = map_get(fields, key) {
            return fail(format!("{prefix}.{key} must not be null"));
        }
    }
    Ok(())
}

fn object_of(v: Option<&Value>) -> Option<&[(Vec<u8>, Value)]> {
    match v {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    }
}

/// Checks the agent-only websocket section before a control plane stores or distributes per-app rules_json.
pub fn check_websocket_rules(data: &[u8]) -> Result<(), WebSocketConfigError> {
    if trim_whitespace(data).is_empty() {
        return Ok(());
    }
    let root = match json_text::parse(data) {
        Ok(v) => v,
        Err(e) => return fail(format!("websocket: invalid rules_json: {e}")),
    };
    let rules = match &root {
        Value::Null => return Ok(()),
        Value::Object(m) => m,
        other => {
            return fail(format!(
                "websocket: invalid rules_json: {}",
                type_mismatch_text("", other.type_name(), "object")
            ));
        }
    };
    let Some(raw) = map_get(rules, "websocket") else {
        return Ok(());
    };
    let Value::Object(fields) = raw else {
        return fail("websocket must be an object");
    };
    let cfg = match decode_rules(fields) {
        Ok(c) => c,
        Err(e) => return fail(format!("websocket: {e}")),
    };
    reject_nulls(
        "websocket",
        Some(fields),
        &[
            "enabled",
            "scan_binary_hashes",
            "scan_server_frames",
            "origin_check",
            "limits",
        ],
    )?;
    if let Some(oc) = &cfg.origin_check {
        reject_nulls(
            "websocket.origin_check",
            object_of(map_get(fields, "origin_check")),
            &["enabled", "allowed_origins"],
        )?;
        if oc.enabled && oc.allowed_origins.is_empty() {
            return fail(
                "websocket.origin_check.allowed_origins is required when origin check is enabled",
            );
        }
        for origin in &oc.allowed_origins {
            if !valid_origin(origin) {
                return fail(format!(
                    "websocket.origin_check.allowed_origins contains invalid origin {}",
                    quote(origin)
                ));
            }
        }
    }
    if let Some(lim) = &cfg.limits {
        reject_nulls(
            "websocket.limits",
            object_of(map_get(fields, "limits")),
            &["max_text_bytes", "max_binary_bytes", "max_messages_per_min"],
        )?;
        // shortcut: with several negative limits the control plane names a random one;
        // this names the first in field order.
        for (name, value) in [
            ("max_text_bytes", lim.max_text_bytes),
            ("max_binary_bytes", lim.max_binary_bytes),
            ("max_messages_per_min", lim.max_msgs_per_min),
        ] {
            if value < 0 {
                return fail(format!("websocket.limits.{name} must be >= 0"));
            }
        }
    }
    Ok(())
}

fn valid_origin(origin: &[u8]) -> bool {
    let Ok(u) = parse_url(origin) else {
        return false;
    };
    if (u.scheme != b"http" && u.scheme != b"https")
        || hostname(&u.host).is_empty()
        || u.user
        || !u.path.is_empty()
        || !u.raw_query.is_empty()
        || !u.fragment.is_empty()
        || trim_whitespace(origin) != origin
    {
        return false;
    }
    if u.host.ends_with(b":") {
        return false;
    }
    let port = port(&u.host);
    if !port.is_empty() {
        match wafio_bytetext::literal::parse_decimal(port) {
            Ok(n) if (1..=65535).contains(&n) => {}
            _ => return false,
        }
    }
    true
}

/// The URL fields the origin check reads.
#[derive(Debug, Default)]
struct ParsedUrl {
    scheme: Vec<u8>,
    user: bool,
    host: Vec<u8>,
    path: Vec<u8>,
    raw_query: Vec<u8>,
    fragment: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq)]
enum EscapeMode {
    Path,
    Host,
    Zone,
    UserPassword,
    Fragment,
}

/// Whether `c` must be percent-escaped in a host or zone.
fn should_escape_host(c: u8) -> bool {
    !(c.is_ascii_alphanumeric() || b"!$&'()*+,;=:[]<>\"-_.~".contains(&c))
}

/// Percent-unescapes `s` (no `+` handling outside query components).
fn unescape(s: &[u8], mode: EscapeMode) -> Result<Vec<u8>, ()> {
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                if i + 2 >= s.len() || hex(s[i + 1]).is_none() || hex(s[i + 2]).is_none() {
                    return Err(());
                }
                let h = hex(s[i + 1]).unwrap_or(0);
                if mode == EscapeMode::Host && h < 8 && &s[i..i + 3] != b"%25" {
                    return Err(());
                }
                if mode == EscapeMode::Zone {
                    let v = h << 4 | hex(s[i + 2]).unwrap_or(0);
                    if &s[i..i + 3] != b"%25" && v != b' ' && should_escape_host(v) {
                        return Err(());
                    }
                }
                i += 3;
            }
            c => {
                if (mode == EscapeMode::Host || mode == EscapeMode::Zone)
                    && c < 0x80
                    && should_escape_host(c)
                {
                    return Err(());
                }
                i += 1;
            }
        }
    }
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            out.push(hex(s[i + 1]).unwrap_or(0) << 4 | hex(s[i + 2]).unwrap_or(0));
            i += 3;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn split_scheme(raw: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    for (i, &c) in raw.iter().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok((b"", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err(());
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok((b"", raw)),
        }
    }
    Ok((b"", raw))
}

fn is_valid_port_suffix(port: &[u8]) -> bool {
    port.is_empty() || (port[0] == b':' && port[1..].iter().all(u8::is_ascii_digit))
}

fn is_valid_userinfo(s: &[u8]) -> bool {
    // Any non-ASCII rune is invalid, so checking bytes gives the same answer as checking runes.
    s.iter()
        .all(|&c| c.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(&c))
}

fn unescape_host(scheme: &[u8], host: &[u8]) -> Result<Vec<u8>, ()> {
    let open = host.iter().rposition(|&c| c == b'[');
    if let Some(open) = open {
        if open > 0 {
            return Err(());
        }
        let close = host.iter().rposition(|&c| c == b']').ok_or(())?;
        let colon_port = &host[close + 1..];
        if !is_valid_port_suffix(colon_port) {
            return Err(());
        }
        let colon_port = unescape(colon_port, EscapeMode::Host)?;
        let hostname = host.get(1..close).ok_or(())?;
        let unescaped = match memchr::memmem::find(hostname, b"%25") {
            Some(z) => [
                unescape(&hostname[..z], EscapeMode::Host)?,
                unescape(&hostname[z..], EscapeMode::Zone)?,
            ]
            .concat(),
            None => unescape(hostname, EscapeMode::Host)?,
        };
        let addr = parse_ip_address(&unescaped).map_err(|_| ())?;
        if addr.is_ipv4() {
            return Err(());
        }
        return Ok([&b"["[..], &unescaped, b"]", &colon_port].concat());
    }
    if let Some(mut i) = host.iter().position(|&c| c == b':') {
        let last = host.iter().rposition(|&c| c == b':').unwrap_or(i);
        // For http and https the port suffix starts at the first colon, for other schemes at the last.
        if last != i && scheme != b"http" && scheme != b"https" {
            i = last;
        }
        if !is_valid_port_suffix(&host[i..]) {
            return Err(());
        }
    }
    unescape(host, EscapeMode::Host)
}

/// Parses a URL (only the fields the origin check reads; errors only as Err).
fn parse_url(raw: &[u8]) -> Result<ParsedUrl, ()> {
    let (u, frag) = match raw.iter().position(|&c| c == b'#') {
        Some(i) => (&raw[..i], &raw[i + 1..]),
        None => (raw, &b""[..]),
    };
    let mut url = ParsedUrl::default();
    if u.iter().any(|&b| b < b' ' || b == 0x7f) {
        return Err(());
    }
    if u == b"*" {
        url.path = b"*".to_vec();
    } else {
        let (scheme, rest) = split_scheme(u)?;
        url.scheme = to_lowercase(scheme);
        let mut rest = rest;
        if rest.ends_with(b"?") && rest.iter().filter(|&&c| c == b'?').count() == 1 {
            rest = &rest[..rest.len() - 1];
        } else if let Some(i) = rest.iter().position(|&c| c == b'?') {
            url.raw_query = rest[i + 1..].to_vec();
            rest = &rest[..i];
        }
        let mut opaque = false;
        if !rest.starts_with(b"/") {
            if !url.scheme.is_empty() {
                opaque = true;
            } else {
                let seg = rest.split(|&c| c == b'/').next().unwrap_or(b"");
                if seg.contains(&b':') {
                    return Err(());
                }
            }
        }
        if !opaque {
            if (!url.scheme.is_empty() || !rest.starts_with(b"///")) && rest.starts_with(b"//") {
                let mut authority = &rest[2..];
                rest = b"";
                if let Some(i) = authority.iter().position(|&c| c == b'/') {
                    rest = &authority[i..];
                    authority = &authority[..i];
                }
                let at = authority.iter().rposition(|&c| c == b'@');
                url.host =
                    unescape_host(&url.scheme, at.map_or(authority, |i| &authority[i + 1..]))?;
                if let Some(i) = at {
                    let userinfo = &authority[..i];
                    if !is_valid_userinfo(userinfo) {
                        return Err(());
                    }
                    match userinfo.iter().position(|&c| c == b':') {
                        None => {
                            unescape(userinfo, EscapeMode::UserPassword)?;
                        }
                        Some(j) => {
                            unescape(&userinfo[..j], EscapeMode::UserPassword)?;
                            unescape(&userinfo[j + 1..], EscapeMode::UserPassword)?;
                        }
                    }
                    url.user = true;
                }
            }
            url.path = unescape(rest, EscapeMode::Path)?;
        }
    }
    if !frag.is_empty() {
        url.fragment = unescape(frag, EscapeMode::Fragment)?;
    }
    Ok(url)
}

/// Splits `host:port` (used for the hostname and the port number of a URL).
fn split_host_and_port(host_port: &[u8]) -> (&[u8], &[u8]) {
    let mut host = host_port;
    let mut port: &[u8] = b"";
    if let Some(colon) = host.iter().rposition(|&c| c == b':')
        && is_valid_port_suffix(&host[colon..])
    {
        port = &host[colon + 1..];
        host = &host[..colon];
    }
    if host.starts_with(b"[") && host.ends_with(b"]") && host.len() >= 2 {
        host = &host[1..host.len() - 1];
    }
    (host, port)
}

fn hostname(h: &[u8]) -> &[u8] {
    split_host_and_port(h).0
}

fn port(h: &[u8]) -> &[u8] {
    split_host_and_port(h).1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64decode(s: &str) -> Vec<u8> {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let (mut acc, mut bits) = (0u32, 0);
        for c in s.bytes() {
            let Some(v) = T.iter().position(|&t| t == c) else {
                continue;
            };
            acc = acc << 6 | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    }

    /// Replays a recorded dump (`GODUMP_WS`).
    #[test]
    fn websocket_differential() {
        let Ok(path) = std::env::var("GODUMP_WS") else {
            return;
        };
        let data = std::fs::read_to_string(path).unwrap();
        let (mut n, mut bad) = (0, 0);
        for line in data.lines() {
            let rec: [String; 2] = serde_json::from_str(line).unwrap();
            let doc = b64decode(&rec[0]);
            let got = if check_websocket_rules(&doc).is_ok() {
                "ok"
            } else {
                "err"
            };
            n += 1;
            if got != rec[1] {
                bad += 1;
                if bad <= 10 {
                    eprintln!(
                        "MISMATCH {:?}: got {got}, want {}",
                        String::from_utf8_lossy(&doc),
                        rec[1]
                    );
                }
            }
        }
        assert_eq!(
            bad, 0,
            "{bad} of {n} websocket cases differ from the recorded reference"
        );
        eprintln!("websocket reference: {n} cases identical");
    }

    #[test]
    fn validate_websocket_rules_json_recorded_cases() {
        for input in [
            &br#"{"websocket":null}"#[..],
            br#"{"websocket":7}"#,
            br#"{"websocket":{"limits":{"max_text_bytes":-1}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":[]}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test/path"]}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test:bad"]}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test:70000"]}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":null,"allowed_origins":["https://ok.test"]}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":false,"allowed_origins":null}}}"#,
            br#"{"websocket":{"limits":{"max_text_bytes":null}}}"#,
        ] {
            assert!(check_websocket_rules(input).is_err(), "{}: want validation error", String::from_utf8_lossy(input));
        }
        for input in [
            &b"{}"[..],
            br#"{"websocket":{"enabled":false}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://ok.test:443"]},"limits":{"max_text_bytes":65536}}}"#,
        ] {
            assert!(check_websocket_rules(input).is_ok(), "{}", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn validate_websocket_rules_json_table() {
        for ok in [
            &b""[..],
            b"{}",
            br#"{"websocket":{"enabled":true,"origin_check":{"enabled":true,"allowed_origins":["https://app.example.com"]}}}"#,
            br#"{"websocket":{"limits":{"max_text_bytes":0,"max_binary_bytes":0,"max_messages_per_min":0}}}"#,
        ] {
            assert!(check_websocket_rules(ok).is_ok(), "{}", String::from_utf8_lossy(ok));
        }
        for bad in [
            &br#"{"websocket":[]}"#[..],
            br#"{"websocket":{"enabled":"yes"}}"#,
            br#"{"websocket":{"enabled":null}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["*"]}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://app.example.com/path"]}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://app.example.com:"]}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://app.example.com:0"]}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":[" https://app.example.com"]}}}"#,
            br#"{"websocket":{"origin_check":{"enabled":true,"allowed_origins":["https://user@app.example.com"]}}}"#,
            br#"{"websocket":{"limits":{"max_text_bytes":-1}}}"#,
            br#"{"websocket":{"limits":null}}"#,
            br#"{"websocket":{"limits":{"max_text_bytes":1.5}}}"#,
            b"{",
            b"[]",
        ] {
            assert!(check_websocket_rules(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn origin_parse_rules() {
        for (o, ok) in [
            ("https://a.example", true),
            ("http://a.example:8080", true),
            ("https://[::1]:443", true),
            ("https://[1.2.3.4]", false),
            ("https://a.example:65536", false),
            ("https://a.example?", true), // empty query
            ("https://a.example#", true), // empty fragment dropped
            ("https://a.example#x", false),
            ("https://a.example?x", false),
            ("ftp://a.example", false),
            ("https:a.example", false),
            ("https://a b", false),
            ("https://a%41", false),
            ("https://a.example:1:2", false),
            ("HTTPS://A.EXAMPLE", true),
            ("https://@a.example", false),
            ("https://", false),
        ] {
            assert_eq!(valid_origin(o.as_bytes()), ok, "{o}");
        }
        let e = check_websocket_rules(br#"{"websocket":{"limits":{"max_text_bytes":-1}}}"#)
            .unwrap_err();
        assert_eq!(e.0, "websocket.limits.max_text_bytes must be >= 0");
        let e =
            check_websocket_rules(br#"{"websocket":{"origin_check":{"allowed_origins":["*"]}}}"#)
                .unwrap_err();
        assert_eq!(
            e.0,
            r#"websocket.origin_check.allowed_origins contains invalid origin "*""#
        );
    }
}
