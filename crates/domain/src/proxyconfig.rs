//! The per-app reverse-proxy configuration (`apps.proxy_config`). Decoding: keys match the json
//! names exactly or case-insensitively, a repeated key decodes again into the same field
//! (objects merge), `null` leaves a field unchanged, and a type mismatch is an error.

use std::collections::BTreeMap;

use crate::clientip::{build_trusted_prefixes, check_trusted_proxies};
use crate::ip_address::IpPrefix;
use crate::json_text::{self, Value, key_matches};
use crate::text_helpers::{eq_ignore_case, quote, trim_whitespace};

/// A proxy_config parse or validation error (user-facing message).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyError(pub String);

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProxyError {}

/// The canonical per-app reverse-proxy configuration. All numeric defaults
/// equal the agent's previous hardcoded behaviour; an ABSENT
/// trust_forwarded means false.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProxyConfig {
    pub timeouts: ProxyTimeouts,
    pub max_body_bytes: i64,
    pub read_buffer_bytes: i64,
    pub write_buffer_bytes: i64,
    pub max_conns: i64,
    pub conn_wait_ms: i64,
    pub idle_conn_ms: i64,
    pub host_header: ProxyHostHeader,
    pub request_headers: ProxyHeaderRules,
    pub response_headers: ProxyHeaderRules,
    pub trust_forwarded: bool,
    /// Peers (IP or CIDR, at most MAX_TRUSTED_PROXIES) allowed to name the
    /// client; empty = loopback + RFC 1918 + RFC 4193.
    pub trusted_proxies: Vec<String>,
    /// `trusted_proxies` compiled by parse_proxy_config (invalid entries
    /// dropped). None when built without it.
    pub(crate) trusted: Option<Vec<IpPrefix>>,
    /// Answer 400 for a path with a '%' not followed by two hex digits;
    /// absent or null means true.
    pub reject_invalid_path_encoding: bool,
}

/// Per-app deadlines in milliseconds: 0 unset (default), -1 unlimited, > 0 ms.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyTimeouts {
    pub connect_ms: i64,
    pub upstream_ms: i64,
    pub read_ms: i64,
    pub write_ms: i64,
}

/// The sentinel meaning "impose no deadline".
pub const TIMEOUT_UNLIMITED: i64 = -1;

/// Turns a stored value into the milliseconds to apply; 0 for unlimited.
pub fn timeout_or_default_ms(v: i64, def: i64) -> i64 {
    if v == TIMEOUT_UNLIMITED {
        0
    } else if v <= 0 {
        def
    } else {
        v
    }
}

/// Reports whether a stored timeout value disables the deadline.
pub fn is_unlimited(v: i64) -> bool {
    v == TIMEOUT_UNLIMITED
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyHostHeader {
    pub mode: String,
    pub value: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyHeaderRules {
    /// None when there is no map (parse_proxy_config always fills it).
    pub add: Option<BTreeMap<String, String>>,
    pub remove: Vec<String>,
}

const DEF_PROXY_UPSTREAM_MS: i64 = 30000;
const DEF_PROXY_READ_MS: i64 = 60000;
const DEF_PROXY_WRITE_MS: i64 = 60000;
const DEF_PROXY_MAX_BODY: i64 = 64 * 1024 * 1024;
const DEFAULT_PROXY_BUFFER_BYTES: i64 = 16384;
const DEF_PROXY_MAX_CONNS: i64 = 512;
const DEF_PROXY_CONN_WAIT_MS: i64 = 5000;
const DEF_PROXY_IDLE_CONN_MS: i64 = 10000;
const MAX_PROXY_HEADERS: usize = 32;
const MAX_PROXY_HEADER_BYTE: usize = 8192;

/// JSON decode state: the first type error is kept, decoding continues.
#[derive(Default)]
struct ConfigDecoder {
    error: Option<String>,
}

impl ConfigDecoder {
    fn type_error(&mut self, v: &Value, path: &str, ty: &str) {
        if self.error.is_none() {
            let what = match v {
                Value::Number(n) => format!("number {}", String::from_utf8_lossy(n)),
                other => other.type_name().to_string(),
            };
            self.error = Some(format!(
                "json: cannot unmarshal {what} into Go struct field ProxyConfig.{path} of type {ty}"
            ));
        }
    }

    fn int(&mut self, v: &Value, dst: &mut i64, path: &str) {
        match v {
            Value::Null => {}
            Value::Number(n) => match std::str::from_utf8(n)
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
            {
                Some(x) => *dst = x,
                None => self.type_error(v, path, "int"),
            },
            _ => self.type_error(v, path, "int"),
        }
    }

    fn boolean(&mut self, v: &Value, dst: &mut bool, path: &str) {
        match v {
            Value::Null => {}
            Value::Bool(b) => *dst = *b,
            _ => self.type_error(v, path, "bool"),
        }
    }

    fn string(&mut self, v: &Value, dst: &mut String, path: &str) {
        match v {
            Value::Null => {}
            Value::String(s) => *dst = String::from_utf8_lossy(s).into_owned(),
            _ => self.type_error(v, path, "string"),
        }
    }

    fn strings(&mut self, v: &Value, dst: &mut Vec<String>, path: &str) {
        match v {
            Value::Null => dst.clear(),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for (i, it) in items.iter().enumerate() {
                    // shortcut: on null at an index a previous duplicate key filled, the
                    // control plane keeps the old element; this stores "".
                    let mut s = dst.get(i).cloned().unwrap_or_default();
                    self.string(it, &mut s, path);
                    out.push(s);
                }
                *dst = out;
            }
            _ => self.type_error(v, path, "[]string"),
        }
    }

    fn object<'v>(&mut self, v: &'v Value, path: &str, ty: &str) -> Option<&'v [(Vec<u8>, Value)]> {
        match v {
            Value::Object(m) => Some(m),
            Value::Null => None,
            _ => {
                self.type_error(v, path, ty);
                None
            }
        }
    }

    fn timeouts(&mut self, v: &Value, t: &mut ProxyTimeouts) {
        let Some(m) = self.object(v, "timeouts", "domain.ProxyTimeouts") else {
            return;
        };
        for (k, val) in m {
            if key_matches(k, "connect_ms") {
                self.int(val, &mut t.connect_ms, "timeouts.connect_ms");
            } else if key_matches(k, "upstream_ms") {
                self.int(val, &mut t.upstream_ms, "timeouts.upstream_ms");
            } else if key_matches(k, "read_ms") {
                self.int(val, &mut t.read_ms, "timeouts.read_ms");
            } else if key_matches(k, "write_ms") {
                self.int(val, &mut t.write_ms, "timeouts.write_ms");
            }
        }
    }

    fn host_header(&mut self, v: &Value, h: &mut ProxyHostHeader) {
        let Some(m) = self.object(v, "host_header", "domain.ProxyHostHeader") else {
            return;
        };
        for (k, val) in m {
            if key_matches(k, "mode") {
                self.string(val, &mut h.mode, "host_header.mode");
            } else if key_matches(k, "value") {
                self.string(val, &mut h.value, "host_header.value");
            }
        }
    }

    fn header_rules(&mut self, v: &Value, r: &mut ProxyHeaderRules, name: &str) {
        let Some(m) = self.object(v, name, "domain.ProxyHeaderRules") else {
            return;
        };
        for (k, val) in m {
            if key_matches(k, "add") {
                let path = format!("{name}.add");
                match val {
                    Value::Null => r.add = None,
                    Value::Object(items) => {
                        let add = r.add.get_or_insert_with(BTreeMap::new);
                        for (hk, hv) in items {
                            let mut s = String::new();
                            self.string(hv, &mut s, &path);
                            add.insert(String::from_utf8_lossy(hk).into_owned(), s);
                        }
                    }
                    other => self.type_error(other, &path, "map[string]string"),
                }
            } else if key_matches(k, "remove") {
                self.strings(val, &mut r.remove, &format!("{name}.remove"));
            }
        }
    }
}

/// Decodes raw jsonb into a ProxyConfig, filling defaults. Empty input
/// yields the all-default config; reject_invalid_path_encoding defaults to
/// true when absent, trust_forwarded to false.
pub fn parse_proxy_config(raw: &[u8]) -> Result<ProxyConfig, ProxyError> {
    let mut pc = ProxyConfig::default();
    let trimmed = trim_whitespace(raw);
    if trimmed.is_empty() || trimmed == b"null" {
        fill_proxy_defaults(&mut pc);
        pc.reject_invalid_path_encoding = true;
        return Ok(pc);
    }
    let Ok(root) = json_text::parse(raw) else {
        return Err(ProxyError("proxy_config: invalid JSON".into()));
    };
    let Value::Object(members) = &root else {
        return Err(ProxyError(format!(
            "proxy_config: json: cannot unmarshal {} into Go value of type map[string]json.RawMessage",
            root.type_name()
        )));
    };
    let mut d = ConfigDecoder::default();
    for (k, v) in members {
        if key_matches(k, "timeouts") {
            d.timeouts(v, &mut pc.timeouts);
        } else if key_matches(k, "max_body_bytes") {
            d.int(v, &mut pc.max_body_bytes, "max_body_bytes");
        } else if key_matches(k, "read_buf") {
            d.int(v, &mut pc.read_buffer_bytes, "read_buf");
        } else if key_matches(k, "write_buf") {
            d.int(v, &mut pc.write_buffer_bytes, "write_buf");
        } else if key_matches(k, "max_conns") {
            d.int(v, &mut pc.max_conns, "max_conns");
        } else if key_matches(k, "conn_wait_ms") {
            d.int(v, &mut pc.conn_wait_ms, "conn_wait_ms");
        } else if key_matches(k, "idle_conn_ms") {
            d.int(v, &mut pc.idle_conn_ms, "idle_conn_ms");
        } else if key_matches(k, "host_header") {
            d.host_header(v, &mut pc.host_header);
        } else if key_matches(k, "req_headers") {
            d.header_rules(v, &mut pc.request_headers, "req_headers");
        } else if key_matches(k, "resp_headers") {
            d.header_rules(v, &mut pc.response_headers, "resp_headers");
        } else if key_matches(k, "trust_forwarded") {
            d.boolean(v, &mut pc.trust_forwarded, "trust_forwarded");
        } else if key_matches(k, "trusted_proxies") {
            d.strings(v, &mut pc.trusted_proxies, "trusted_proxies");
        } else if key_matches(k, "reject_invalid_path_encoding") {
            d.boolean(
                v,
                &mut pc.reject_invalid_path_encoding,
                "reject_invalid_path_encoding",
            );
        }
    }
    if let Some(e) = d.error {
        return Err(ProxyError(format!("proxy_config: {e}")));
    }
    fill_proxy_defaults(&mut pc);
    // Absent or null keeps the hardened default: only an explicit false opts
    // out. The probe takes the exact key, last occurrence wins.
    let probe = members
        .iter()
        .rev()
        .find(|(k, _)| k.as_slice() == b"reject_invalid_path_encoding");
    if matches!(probe, None | Some((_, Value::Null))) {
        pc.reject_invalid_path_encoding = true;
    }
    pc.trusted = Some(build_trusted_prefixes(&pc.trusted_proxies));
    Ok(pc)
}

fn fill_proxy_defaults(pc: &mut ProxyConfig) {
    if pc.timeouts.upstream_ms == 0 {
        pc.timeouts.upstream_ms = DEF_PROXY_UPSTREAM_MS;
    }
    if pc.timeouts.read_ms == 0 {
        pc.timeouts.read_ms = DEF_PROXY_READ_MS;
    }
    if pc.timeouts.write_ms == 0 {
        pc.timeouts.write_ms = DEF_PROXY_WRITE_MS;
    }
    if pc.max_body_bytes <= 0 {
        pc.max_body_bytes = DEF_PROXY_MAX_BODY;
    }
    if pc.read_buffer_bytes <= 0 {
        pc.read_buffer_bytes = DEFAULT_PROXY_BUFFER_BYTES;
    }
    if pc.write_buffer_bytes <= 0 {
        pc.write_buffer_bytes = DEFAULT_PROXY_BUFFER_BYTES;
    }
    if pc.max_conns <= 0 {
        pc.max_conns = DEF_PROXY_MAX_CONNS;
    }
    if pc.conn_wait_ms <= 0 {
        pc.conn_wait_ms = DEF_PROXY_CONN_WAIT_MS;
    }
    if pc.idle_conn_ms <= 0 {
        pc.idle_conn_ms = DEF_PROXY_IDLE_CONN_MS;
    }
    if trim_whitespace(pc.host_header.mode.as_bytes()).is_empty() {
        pc.host_header.mode = "preserve".into();
    }
    pc.request_headers.add.get_or_insert_with(BTreeMap::new);
    pc.response_headers.add.get_or_insert_with(BTreeMap::new);
}

fn has_crlf(s: &str) -> bool {
    s.bytes().any(|c| c == b'\r' || c == b'\n')
}

fn valid_header_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

impl ProxyConfig {
    /// Checks ranges and header safety. Call after parse_proxy_config.
    pub fn validate(&self) -> Result<(), ProxyError> {
        let in_range = |name: &str, v: i64, lo: i64, hi: i64| -> Result<(), ProxyError> {
            if v < lo || v > hi {
                if lo == TIMEOUT_UNLIMITED {
                    return Err(ProxyError(format!(
                        "{name} must be between 0 and {hi}, or -1 for unlimited"
                    )));
                }
                return Err(ProxyError(format!("{name} must be between {lo} and {hi}")));
            }
            Ok(())
        };
        for (name, v, lo, hi) in [
            (
                "timeouts.connect_ms",
                self.timeouts.connect_ms,
                TIMEOUT_UNLIMITED,
                600000,
            ),
            (
                "timeouts.upstream_ms",
                self.timeouts.upstream_ms,
                TIMEOUT_UNLIMITED,
                600000,
            ),
            (
                "timeouts.read_ms",
                self.timeouts.read_ms,
                TIMEOUT_UNLIMITED,
                600000,
            ),
            (
                "timeouts.write_ms",
                self.timeouts.write_ms,
                TIMEOUT_UNLIMITED,
                600000,
            ),
            ("read_buf", self.read_buffer_bytes, 1024, 1048576),
            ("write_buf", self.write_buffer_bytes, 1024, 1048576),
            ("max_body_bytes", self.max_body_bytes, 1024, 1073741824),
            ("max_conns", self.max_conns, 1, 65535),
            ("conn_wait_ms", self.conn_wait_ms, 0, 600000),
            ("idle_conn_ms", self.idle_conn_ms, 0, 600000),
        ] {
            in_range(name, v, lo, hi)?;
        }
        match self.host_header.mode.as_str() {
            "preserve" | "upstream" => {}
            "custom" => {
                if trim_whitespace(self.host_header.value.as_bytes()).is_empty() {
                    return Err(ProxyError(
                        "host_header.value is required when mode is custom".into(),
                    ));
                }
                if has_crlf(&self.host_header.value) {
                    return Err(ProxyError(
                        "host_header.value must not contain CR/LF".into(),
                    ));
                }
            }
            _ => {
                return Err(ProxyError(
                    "host_header.mode must be preserve, upstream, or custom".into(),
                ));
            }
        }
        for (label, rules) in [
            ("req_headers", &self.request_headers),
            ("resp_headers", &self.response_headers),
        ] {
            let empty = BTreeMap::new();
            let add = rules.add.as_ref().unwrap_or(&empty);
            if add.len() + rules.remove.len() > MAX_PROXY_HEADERS {
                return Err(ProxyError(format!(
                    "{label}: too many entries (max {MAX_PROXY_HEADERS})"
                )));
            }
            let mut total = 0;
            for (k, v) in add {
                if !valid_header_name(k) {
                    return Err(ProxyError(format!(
                        "{label}: invalid header name {}",
                        quote(k.as_bytes())
                    )));
                }
                if has_crlf(v) {
                    return Err(ProxyError(format!(
                        "{label}: header {} value must not contain CR/LF",
                        quote(k.as_bytes())
                    )));
                }
                if eq_ignore_case(k.as_bytes(), b"Host") {
                    return Err(ProxyError(format!(
                        "{label}: set Host via host_header, not headers"
                    )));
                }
                total += k.len() + v.len();
            }
            for k in &rules.remove {
                if !valid_header_name(k) {
                    return Err(ProxyError(format!(
                        "{label}: invalid header name {}",
                        quote(k.as_bytes())
                    )));
                }
                total += k.len();
            }
            if total > MAX_PROXY_HEADER_BYTE {
                return Err(ProxyError(format!(
                    "{label}: header rules too large (max {MAX_PROXY_HEADER_BYTE} bytes)"
                )));
            }
        }
        check_trusted_proxies(&self.trusted_proxies)
    }
}

#[cfg(test)]
mod tests;
