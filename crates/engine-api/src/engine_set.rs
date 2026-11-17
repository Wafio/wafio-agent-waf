//! The detector switch key that belongs to a finding reason.

use crate::reason::*;

/// The disabled-engines key of a switchable engine's reason, else the lower-cased reason
/// without its "SEMANTIC_"/"semantic_" prefix.
pub fn disabled_key_from_reason(reason: &str) -> String {
    let k = match reason {
        REASON_SEMANTIC_SQL => "sql",
        REASON_SEMANTIC_XSS => "xss",
        REASON_SEMANTIC_CMD => "cmd",
        REASON_SEMANTIC_PHP => "php",
        REASON_SEMANTIC_PYTHON => "python",
        REASON_SEMANTIC_LFI => "lfi",
        REASON_SEMANTIC_SSRF => "ssrf",
        REASON_SEMANTIC_JAVA => "java",
        REASON_SEMANTIC_NOSQL => "nosql",
        REASON_SEMANTIC_SSTI => "ssti",
        REASON_SEMANTIC_XXE => "xxe",
        REASON_SEMANTIC_DESER => "deser",
        REASON_SEMANTIC_LDAP => "ldap",
        REASON_SEMANTIC_PROTO_POLLUTION => "proto_pollution",
        REASON_SEMANTIC_HEADER_INJECTION => "header_injection",
        _ => {
            let r = reason.strip_prefix("SEMANTIC_").unwrap_or(reason);
            let r = r.strip_prefix("semantic_").unwrap_or(r);
            return String::from_utf8(wafio_bytetext::strings::to_lowercase(r.as_bytes()))
                .expect("utf8 in, utf8 out");
        }
    };
    k.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_map_to_detector_keys() {
        assert_eq!(
            disabled_key_from_reason(REASON_SEMANTIC_HEADER_INJECTION),
            "header_injection"
        );
        assert_eq!(
            disabled_key_from_reason(REASON_SEMANTIC_OPEN_REDIRECT),
            "open_redirect"
        );
        assert_eq!(disabled_key_from_reason(REASON_SEMANTIC_GRAPHQL), "graphql");
        assert_eq!(disabled_key_from_reason(REASON_SEMANTIC_NOSQL), "nosql");
    }
}
