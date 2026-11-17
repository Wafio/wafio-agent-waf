//! The SIEM verdict event: its JSON and what a final verdict reports (with the body and header
//! snippets). The delivery queue and the webhook are the binary's ([`SiemEventSender`]).

use wafio_bytetext::pattern::CompiledRegex;
use wafio_bytetext::strings::{eq_ignore_case, replace_all, trim_whitespace};
use wafio_bytetext::url::unescape_query_component;
use wafio_domain::json_text::append_quoted_string;
use wafio_domain::{
    AnalysisResult, Headers, IncomingRequest, MatchEvidence, redact_guessed_cookie,
    redact_stored_body_copy, redact_stored_uri,
};
use wafio_engine_api::engine;

/// One final verdict (BLOCK, LOG or challenge) for the webhook.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SiemEvent {
    pub action: String,
    pub score: i64,
    pub rule_ids: Vec<i64>,
    pub categories: Vec<String>,
    pub analyze_method: String,
    /// Event time (UTC): Unix seconds and nanoseconds.
    pub timestamp: (i64, u32),
    pub method: Vec<u8>,
    pub uri: Vec<u8>,
    pub host: Vec<u8>,
    pub remote_addr: Vec<u8>,
    pub user_agent: Vec<u8>,
    pub request_id: Vec<u8>,
    pub match_detail: Vec<u8>,
    pub match_source: Vec<u8>,
    pub cwe: String,
    pub mitre_techniques: Vec<String>,
    pub body_injection_fields: Vec<u8>,
    pub header_injection_fields: Vec<u8>,
}

/// `send` queues the event; `Ok` means accepted in memory, not delivered. It must not block
/// (the WAF path never waits on the webhook).
pub trait SiemEventSender: Send + Sync {
    fn send(&self, evt: &SiemEvent) -> Result<(), String>;
}

impl SiemEvent {
    /// The event as JSON: fixed field order, empty optional fields omitted.
    pub fn to_json(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(512);
        o.extend_from_slice(b"{\"action\":");
        append_quoted_string(&mut o, self.action.as_bytes());
        o.extend_from_slice(format!(",\"score\":{}", self.score).as_bytes());
        if !self.rule_ids.is_empty() {
            o.extend_from_slice(b",\"rule_ids\":[");
            o.extend_from_slice(
                self.rule_ids
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
                    .as_bytes(),
            );
            o.push(b']');
        }
        strings(&mut o, "categories", &self.categories);
        field(
            &mut o,
            "analyze_method",
            self.analyze_method.as_bytes(),
            true,
        );
        o.extend_from_slice(
            format!(
                ",\"timestamp\":\"{}\"",
                format_utc_timestamp(self.timestamp.0, self.timestamp.1)
            )
            .as_bytes(),
        );
        field(&mut o, "method", &self.method, true);
        field(&mut o, "uri", &self.uri, true);
        field(&mut o, "host", &self.host, true);
        field(&mut o, "remote_addr", &self.remote_addr, true);
        field(&mut o, "user_agent", &self.user_agent, true);
        field(&mut o, "request_id", &self.request_id, true);
        field(&mut o, "match_detail", &self.match_detail, true);
        field(&mut o, "match_source", &self.match_source, false);
        field(&mut o, "cwe", self.cwe.as_bytes(), true);
        strings(&mut o, "mitre_techniques", &self.mitre_techniques);
        field(
            &mut o,
            "body_injection_fields",
            &self.body_injection_fields,
            false,
        );
        field(
            &mut o,
            "header_injection_fields",
            &self.header_injection_fields,
            false,
        );
        o.push(b'}');
        o
    }
}

fn field(o: &mut Vec<u8>, key: &str, v: &[u8], omit_empty: bool) {
    if omit_empty && v.is_empty() {
        return;
    }
    o.extend_from_slice(format!(",\"{key}\":").as_bytes());
    append_quoted_string(o, v);
}

fn strings(o: &mut Vec<u8>, key: &str, v: &[String]) {
    if v.is_empty() {
        return;
    }
    o.extend_from_slice(format!(",\"{key}\":[").as_bytes());
    for (i, s) in v.iter().enumerate() {
        if i > 0 {
            o.push(b',');
        }
        append_quoted_string(o, s.as_bytes());
    }
    o.push(b']');
}

/// RFC 3339 in UTC with the fraction's trailing zeros trimmed.
fn format_utc_timestamp(secs: i64, nanos: u32) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from the day count.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let mut s = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    );
    if nanos > 0 {
        s.push_str(format!(".{nanos:09}").trim_end_matches('0'));
    }
    s.push('Z');
    s
}

/// Allow (and fail-open errors, which are allows) are not reported.
fn reports_action(action: &str) -> bool {
    matches!(action, "block" | "log" | "challenge")
}

/// Verdicts decided before content inspection, on the body's size or by a custom rule carry
/// no body or header snippets.
fn skips_content_fields(method: &str) -> bool {
    matches!(
        method,
        wafio_domain::ANALYZE_METHOD_BODY_LIMIT
            | wafio_domain::ANALYZE_METHOD_POLICY
            | wafio_domain::ANALYZE_METHOD_GEO
            | wafio_domain::ANALYZE_METHOD_BOT
            | wafio_domain::ANALYZE_METHOD_CUSTOM_RULE
    )
}

/// Reports one final verdict (once per request) to `sender`; a failed send is the sender's own
/// accounting.
pub fn send_verdict(sender: &dyn SiemEventSender, req: &IncomingRequest, out: &AnalysisResult) {
    if !reports_action(&out.action) {
        return;
    }
    let match_detail = if out.match_detail.is_empty() {
        out.categories.join(", ").into_bytes()
    } else {
        out.match_detail.clone()
    };
    let analyze_method = if out.analyze_method.is_empty() {
        "semantic".to_string()
    } else {
        out.analyze_method.clone()
    };
    let (mut body_fields, mut header_fields) = (Vec::new(), Vec::new());
    if !skips_content_fields(&out.analyze_method) {
        body_fields = injection_fields_for_body_log(&req.body);
        header_fields = injection_fields_for_header_log(&req.headers);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let _ = sender.send(&SiemEvent {
        action: out.action.clone(),
        score: out.score,
        rule_ids: out.rule_ids.clone(),
        categories: out.categories.clone(),
        analyze_method,
        timestamp: (now.as_secs() as i64, now.subsec_nanos()),
        method: req.method.clone(),
        uri: redact_stored_uri(&req.uri, &out.evidence()),
        host: req.host.clone(),
        remote_addr: req.remote_address.clone(),
        user_agent: req.user_agent.clone(),
        request_id: req.request_id.clone(),
        match_detail,
        match_source: out.match_source.clone(),
        cwe: out.cwe.clone(),
        mitre_techniques: out.mitre_techniques.clone(),
        body_injection_fields: body_fields,
        header_injection_fields: header_fields,
    });
}

const BODY_INJECTION_FIELDS_MAX_LEN: usize = 512;
const HEADER_INJECTION_FIELDS_MAX_LEN: usize = 512;

/// A safe, truncated body snippet for the SIEM: the stored decision's body redaction with no
/// evidence exempt, newlines replaced, then the older credential pattern; empty for an empty body.
pub fn injection_fields_for_body_log(body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    let cut = body.len() > BODY_INJECTION_FIELDS_MAX_LEN;
    let body = if cut {
        &body[..BODY_INJECTION_FIELDS_MAX_LEN]
    } else {
        body
    };
    let mut s = redact_stored_body_copy(body, b"", &MatchEvidence::default(), !cut);
    s = replace_all(&s, b"\r\n", b" ");
    s = replace_all(&s, b"\n", b" ");
    s = replace_all(&s, b"\r", b" ");
    let mut s = redact_sensitive_fields(&s);
    if cut {
        s.extend_from_slice(b"...");
    }
    s
}

static SENSITIVE_FIELD_RE: std::sync::LazyLock<CompiledRegex> = std::sync::LazyLock::new(|| {
    CompiledRegex::compile_or_panic(
        r#"(?i)((?:^|[&?;{,\s])"?(?:[a-z0-9_.\-\[\]]*?(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|auth|credential|session|cookie|otp|totp|pin|cvv|cvc|card[_-]?number|ccnum|ssn))"?\s*[:=]\s*)("(?:[^"\\]|\\.)*"?|[^&;,}\s]*)"#,
    )
});

fn redact_sensitive_fields(s: &[u8]) -> Vec<u8> {
    SENSITIVE_FIELD_RE.replace_all_with(s, |m| {
        let Some(sub) = SENSITIVE_FIELD_RE.find_captures(m) else {
            return m.to_vec();
        };
        if sub.len() < 3 || sub[2].is_empty() {
            return m.to_vec();
        }
        let mut out = sub[1].to_vec();
        out.extend_from_slice(if sub[2][0] == b'"' {
            &b"\"[redacted]\""[..]
        } else {
            b"[redacted]"
        });
        out
    })
}

/// The suspicious values of Referer, User-Agent, Cookie, Origin and X-Forwarded-For (cookies and
/// the referring URL redacted), each as `Name: value`, joined by `; `, cut at 512 bytes.
pub fn injection_fields_for_header_log(headers: &Headers) -> Vec<u8> {
    if headers.is_empty() {
        return Vec::new();
    }
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for name in [
        "Referer",
        "User-Agent",
        "Cookie",
        "Origin",
        "X-Forwarded-For",
    ] {
        let values: &[Vec<u8>] = headers
            .iter()
            .find(|(k, vals)| eq_ignore_case(k, name.as_bytes()) && !vals.is_empty())
            .map_or(&[], |(_, v)| v.as_slice());
        for v in values {
            if v.is_empty() {
                continue;
            }
            let decoded = unescape_query_component(v).unwrap_or_else(|_| v.clone());
            let engine = engine();
            if !(engine.header_value_looks_suspicious(v)
                || engine.header_value_looks_suspicious(&decoded))
            {
                continue;
            }
            let mut display = if decoded.is_empty() {
                v.clone()
            } else {
                decoded
            };
            match name {
                // Session cookies beside the payload stay out of the event.
                "Cookie" => display = redact_guessed_cookie(v),
                // So do ?access_token= and ;jsessionid= of the referring URL.
                "Referer" => {
                    display = redact_stored_uri(v, &MatchEvidence::default());
                    if let Ok(dec) = unescape_query_component(&display) {
                        display = dec;
                    }
                }
                _ => {}
            }
            let mut p = trim_whitespace(name.as_bytes()).to_vec();
            p.extend_from_slice(b": ");
            p.extend(sanitize_log_value(&display));
            parts.push(p);
        }
    }
    if parts.is_empty() {
        return Vec::new();
    }
    let mut s = parts.join(&b"; "[..]);
    if s.len() > HEADER_INJECTION_FIELDS_MAX_LEN {
        s.truncate(HEADER_INJECTION_FIELDS_MAX_LEN);
        s.extend_from_slice(b"...");
    }
    s
}

fn sanitize_log_value(s: &[u8]) -> Vec<u8> {
    replace_all(
        &replace_all(&replace_all(s, b"\r\n", b" "), b"\n", b" "),
        b"\r",
        b" ",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_json_field_order_and_omitted_empty_fields() {
        let e = SiemEvent {
            action: "block".into(),
            score: 180,
            categories: vec!["SQLi".into()],
            timestamp: (1_700_000_000, 123_000_000),
            method: b"GET".to_vec(),
            uri: b"/a?<x>".to_vec(),
            match_source: b"query:q".to_vec(),
            ..Default::default()
        };
        assert_eq!(
            String::from_utf8(e.to_json()).unwrap(),
            r#"{"action":"block","score":180,"categories":["SQLi"],"timestamp":"2023-11-14T22:13:20.123Z","method":"GET","uri":"/a?\u003cx\u003e","match_source":"query:q","body_injection_fields":"","header_injection_fields":""}"#
        );
        let e = SiemEvent {
            action: "log".into(),
            rule_ids: vec![942100, 7],
            mitre_techniques: vec!["T1190".into()],
            cwe: "CWE-89".into(),
            timestamp: (0, 0),
            ..Default::default()
        };
        assert_eq!(
            String::from_utf8(e.to_json()).unwrap(),
            r#"{"action":"log","score":0,"rule_ids":[942100,7],"timestamp":"1970-01-01T00:00:00Z","match_source":"","cwe":"CWE-89","mitre_techniques":["T1190"],"body_injection_fields":"","header_injection_fields":""}"#
        );
    }

    #[test]
    fn only_block_log_and_challenge_are_reported() {
        struct Collect(std::sync::Mutex<Vec<SiemEvent>>);
        impl SiemEventSender for Collect {
            fn send(&self, e: &SiemEvent) -> Result<(), String> {
                self.0.lock().unwrap().push(e.clone());
                Ok(())
            }
        }
        let c = Collect(Default::default());
        let req = IncomingRequest {
            method: b"POST".to_vec(),
            uri: b"/p".to_vec(),
            body: b"a=1".to_vec(),
            ..Default::default()
        };
        for action in ["allow", "block", "log", "challenge", "error"] {
            send_verdict(
                &c,
                &req,
                &AnalysisResult {
                    action: action.into(),
                    categories: vec!["XSS".into(), "SQLi".into()],
                    ..Default::default()
                },
            );
        }
        let got = c.0.lock().unwrap();
        assert_eq!(
            got.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(),
            ["block", "log", "challenge"]
        );
        // No match detail: the categories; no method: "semantic".
        assert_eq!(
            (
                got[0].match_detail.as_slice(),
                got[0].analyze_method.as_str()
            ),
            (&b"XSS, SQLi"[..], "semantic")
        );
        assert_eq!(got[0].body_injection_fields, b"a=1");
        drop(got);
        // A custom rule's verdict carries no body or header snippets.
        send_verdict(
            &c,
            &req,
            &AnalysisResult {
                action: "log".into(),
                analyze_method: "custom_rule".into(),
                ..Default::default()
            },
        );
        assert!(
            c.0.lock()
                .unwrap()
                .last()
                .unwrap()
                .body_injection_fields
                .is_empty()
        );
    }
}
