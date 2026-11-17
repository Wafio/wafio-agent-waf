//! The per-app `websocket` block of an app's rules_json (agent-side only). Key absent → interception
//! ON with default limits and no origin check.

use wafio_domain::json_text::{Value, type_mismatch_text};
use wafio_domain::text_helpers::{eq_ignore_case, trim_whitespace};

use crate::url_parse;
use crate::websocket_config::{
    Decoder, check_websocket_rules, decode_limits, decode_origin_check, map_get, parse_raw_map,
};

/// CSWSH defense: a handshake whose Origin is not in the allowlist is refused
/// with 403 before the hijack. Exact match, no wildcards.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsOriginPolicy {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
}

/// Per-field overrides of the relay defaults; 0 keeps the default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WsConfiguredLimits {
    pub max_text_bytes: i64,
    pub max_binary_bytes: i64,
    pub max_msgs_per_min: i64,
}

/// The parsed `websocket` block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsAppPolicy {
    pub enabled: bool,
    pub origin_check: WsOriginPolicy,
    pub limits: WsConfiguredLimits,
    pub scan_binary_hashes: bool,
    /// Scan upstream→client frames with the client-direction scanner (default false).
    pub scan_server_frames: bool,
}

/// Whether the rules JSON is absent, `{}`, `null` or `[]`.
pub fn is_empty_rules_json(rules_json: &[u8]) -> bool {
    if rules_json.is_empty() {
        return true;
    }
    let t = trim_whitespace(rules_json);
    t == b"{}" || t == b"null" || t == b"[]"
}

/// Parses the block. A present but malformed block is an error so a typo
/// cannot silently disable protections.
pub fn parse_ws_app_policy(rules_json: &[u8]) -> Result<WsAppPolicy, String> {
    let mut cfg = WsAppPolicy {
        enabled: true,
        ..Default::default()
    };
    if is_empty_rules_json(rules_json) {
        return Ok(cfg);
    }
    check_websocket_rules(rules_json)?;
    let top = parse_raw_map(rules_json)
        .map_err(|e| format!("websocket: rules_json is not valid JSON: {e}"))?;
    let Some(raw) = map_get(&top, "websocket") else {
        return Ok(cfg);
    };

    let mut d = Decoder::default();
    let (mut enabled, mut origin_check, mut limits) = (None, None, None);
    match raw {
        Value::Null => {}
        Value::Object(members) => {
            for (i, v) in d.fields(
                members,
                &[
                    "enabled",
                    "origin_check",
                    "limits",
                    "scan_binary_hashes",
                    "scan_server_frames",
                ],
            ) {
                match i {
                    0 => d.opt_bool_into(v, &mut enabled, "enabled"),
                    1 => decode_origin_check(&mut d, v, &mut origin_check),
                    2 => decode_limits(&mut d, v, &mut limits),
                    3 => d.bool_into(v, &mut cfg.scan_binary_hashes, "scan_binary_hashes"),
                    _ => d.bool_into(v, &mut cfg.scan_server_frames, "scan_server_frames"),
                }
            }
        }
        other => {
            return Err(format!(
                "websocket: {}",
                type_mismatch_text("", other.type_name(), "object")
            ));
        }
    }
    if let Some(e) = d.first_error {
        return Err(format!("websocket: {e}"));
    }
    if let Some(e) = enabled {
        cfg.enabled = e;
    }
    if let Some(oc) = origin_check {
        if oc
            .allowed_origins
            .iter()
            .any(|o| trim_whitespace(o.as_bytes()).is_empty())
        {
            return Err("websocket.origin_check: allowed_origins contains an empty entry".into());
        }
        cfg.origin_check = WsOriginPolicy {
            enabled: oc.enabled,
            allowed_origins: oc.allowed_origins,
        };
    }
    if let Some(l) = limits {
        if l.max_text_bytes < 0 {
            return Err("websocket.limits: max_text_bytes must be >= 0".into());
        }
        if l.max_binary_bytes < 0 {
            return Err("websocket.limits: max_binary_bytes must be >= 0".into());
        }
        if l.max_msgs_per_min < 0 {
            return Err("websocket.limits: max_messages_per_min must be >= 0".into());
        }
        cfg.limits = WsConfiguredLimits {
            max_text_bytes: l.max_text_bytes,
            max_binary_bytes: l.max_binary_bytes,
            max_msgs_per_min: l.max_msgs_per_min,
        };
    }
    Ok(cfg)
}

impl WsOriginPolicy {
    /// Whether `origin` is allowed: a missing origin never matches (fails closed).
    pub fn permits_origin(&self, origin: &[u8]) -> bool {
        !origin.is_empty()
            && self
                .allowed_origins
                .iter()
                .any(|a| origins_match(origin, a.as_bytes()))
    }
}

/// Exact equality, or case-insensitive scheme and host
/// when both parse as absolute URLs.
pub fn origins_match(a: &[u8], b: &[u8]) -> bool {
    if a == b {
        return true;
    }
    let (Ok(ua), Ok(ub)) = (
        url_parse::parse(trim_whitespace(a)),
        url_parse::parse(trim_whitespace(b)),
    ) else {
        return false;
    };
    if !ua.has_scheme() || !ub.has_scheme() || ua.host.is_empty() || ub.host.is_empty() {
        return false;
    }
    if !ua.path.is_empty()
        || !ua.raw_query.is_empty()
        || !ua.fragment.is_empty()
        || ua.user.is_some()
    {
        return false;
    }
    eq_ignore_case(&ua.scheme, &ub.scheme) && eq_ignore_case(&ua.host, &ub.host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_key_defaults_on() {
        for input in [&b""[..], b"{}", br#"{"thresholds":{"block":150,"log":80}}"#] {
            let cfg = parse_ws_app_policy(input).unwrap();
            assert_eq!(
                cfg,
                WsAppPolicy {
                    enabled: true,
                    ..Default::default()
                }
            );
        }
    }

    #[test]
    fn full_block() {
        let cfg = parse_ws_app_policy(
            br#"{
            "websocket": {
                "enabled": false,
                "origin_check": {"enabled": true, "allowed_origins": ["https://a.test", "https://b.test:8443"]},
                "limits": {"max_text_bytes": 1024, "max_binary_bytes": 4096, "max_messages_per_min": 5},
                "scan_binary_hashes": true,
                "scan_server_frames": true
            }
        }"#,
        )
        .unwrap();
        assert!(!cfg.enabled);
        assert_eq!(
            cfg.origin_check,
            WsOriginPolicy {
                enabled: true,
                allowed_origins: vec!["https://a.test".into(), "https://b.test:8443".into()]
            }
        );
        assert_eq!(
            cfg.limits,
            WsConfiguredLimits {
                max_text_bytes: 1024,
                max_binary_bytes: 4096,
                max_msgs_per_min: 5
            }
        );
        assert!(cfg.scan_binary_hashes && cfg.scan_server_frames);
    }

    #[test]
    fn scan_server_frames() {
        for (input, want) in [
            (r#"{"thresholds":{"block":150,"log":80}}"#, false),
            (r#"{"websocket":{}}"#, false),
            (r#"{"websocket":{"scan_server_frames":false}}"#, false),
            (r#"{"websocket":{"scan_server_frames":true}}"#, true),
            (
                r#"{"websocket":{"enabled":true,"scan_server_frames":true}}"#,
                true,
            ),
            (r#"{"websocket":{"SCAN_SERVER_FRAMES":true}}"#, true),
        ] {
            assert_eq!(
                parse_ws_app_policy(input.as_bytes())
                    .unwrap()
                    .scan_server_frames,
                want,
                "{input}"
            );
        }
    }

    #[test]
    fn malformed() {
        for input in [
            r#"{"websocket": 7}"#,
            r#"{"websocket": "chat"}"#,
            r#"{"websocket": []}"#,
            r#"{"websocket": {}} {"websocket": {}}"#,
            r#"{"websocket": {"limits": {"max_text_bytes": -1}}}"#,
            r#"{"websocket": {"limits": {"max_binary_bytes": -5}}}"#,
            r#"{"websocket": {"limits": {"max_messages_per_min": -2}}}"#,
            r#"{"websocket": {"origin_check": {"enabled": true, "allowed_origins": [""]}}}"#,
            r#"{"websocket": {"origin_check": {"enabled": true, "allowed_origins": ["https://ok.test", "  "]}}}"#,
            "  ",
        ] {
            assert!(parse_ws_app_policy(input.as_bytes()).is_err(), "{input}");
        }
    }

    #[test]
    fn unknown_subkeys_tolerated() {
        let cfg = parse_ws_app_policy(br#"{"websocket": {"future_knob": "x", "limits": {"max_text_bytes": 512, "future": 1}}}"#).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.limits.max_text_bytes, 512);
    }

    #[test]
    fn enabled_omitted_means_on_and_zero_limits_kept() {
        let cfg =
            parse_ws_app_policy(br#"{"websocket": {"limits": {"max_text_bytes": 256}}}"#).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.limits.max_text_bytes, 256);
        let cfg = parse_ws_app_policy(br#"{"websocket": {"limits": {"max_text_bytes": 0, "max_binary_bytes": 0, "max_messages_per_min": 0}}}"#).unwrap();
        assert_eq!(cfg.limits, WsConfiguredLimits::default());
    }

    #[test]
    fn origin_check_allowed() {
        let oc = WsOriginPolicy {
            enabled: true,
            allowed_origins: vec![
                "https://app.example.com".into(),
                "http://localhost:5173".into(),
            ],
        };
        for o in [
            "https://app.example.com",
            "HTTPS://APP.EXAMPLE.COM",
            "http://localhost:5173",
        ] {
            assert!(oc.permits_origin(o.as_bytes()), "{o}");
        }
        for o in [
            "https://evil.com",
            "https://app.example.com.evil.com",
            "https://evil.com/app.example.com",
            "http://app.example.com",
            "https://app.example.com:8443",
            "",
        ] {
            assert!(!oc.permits_origin(o.as_bytes()), "{o}");
        }
    }

    #[test]
    fn origin_check_unparseable_and_garbage() {
        let oc = WsOriginPolicy {
            enabled: true,
            allowed_origins: vec!["%zz://not a url".into()],
        };
        assert!(oc.permits_origin(b"%zz://not a url"));
        assert!(!oc.permits_origin(b"https://x.test"));
        let oc = WsOriginPolicy {
            enabled: true,
            allowed_origins: vec!["https://app.example.com".into()],
        };
        assert!(!oc.permits_origin(b"javascript:alert(1)"));
        assert!(!oc.permits_origin("A".repeat(4096).as_bytes()));
        assert!(!oc.permits_origin(b"https://app.example.com/other"));
    }
}
