//! The names the agent and the engines share: the reason of each semantic finding and the SIEM form of a
//! reason with its detail.

use wafio_bytetext::strings;

pub const REASON_SEMANTIC_SQL: &str = "SEMANTIC_SQL";
pub const REASON_SEMANTIC_XSS: &str = "SEMANTIC_XSS";
pub const REASON_SEMANTIC_CMD: &str = "SEMANTIC_CMD";
pub const REASON_SEMANTIC_PHP: &str = "SEMANTIC_PHP";
pub const REASON_SEMANTIC_PYTHON: &str = "SEMANTIC_PYTHON";
pub const REASON_SEMANTIC_LFI: &str = "SEMANTIC_LFI";
pub const REASON_SEMANTIC_SSRF: &str = "SEMANTIC_SSRF";
pub const REASON_SEMANTIC_JAVA: &str = "SEMANTIC_JAVA";
pub const REASON_SEMANTIC_LDAP: &str = "SEMANTIC_LDAP";
pub const REASON_SEMANTIC_PROTO_POLLUTION: &str = "SEMANTIC_PROTO_POLLUTION";
pub const REASON_SEMANTIC_SSTI: &str = "SEMANTIC_SSTI";
pub const REASON_SEMANTIC_XXE: &str = "SEMANTIC_XXE";
pub const REASON_SEMANTIC_DESER: &str = "SEMANTIC_DESER";
pub const REASON_SEMANTIC_NOSQL: &str = "SEMANTIC_NOSQL";
pub const REASON_SEMANTIC_OPEN_REDIRECT: &str = "SEMANTIC_OPEN_REDIRECT";
pub const REASON_SEMANTIC_HEADER_INJECTION: &str = "SEMANTIC_HEADER_INJECTION";
pub const REASON_SEMANTIC_PROMPT_INJECTION: &str = "SEMANTIC_PROMPT_INJECTION";
pub const REASON_SEMANTIC_ANOMALY: &str = "SEMANTIC_ANOMALY";
pub const REASON_SEMANTIC_GRAPHQL: &str = "semantic_graphql";
pub const REASON_SEMANTIC_JWT: &str = "SEMANTIC_JWT";

pub const ALL_SEMANTIC_REASONS: [&str; 20] = [
    REASON_SEMANTIC_SQL,
    REASON_SEMANTIC_XSS,
    REASON_SEMANTIC_CMD,
    REASON_SEMANTIC_PHP,
    REASON_SEMANTIC_PYTHON,
    REASON_SEMANTIC_LFI,
    REASON_SEMANTIC_SSRF,
    REASON_SEMANTIC_JAVA,
    REASON_SEMANTIC_LDAP,
    REASON_SEMANTIC_PROTO_POLLUTION,
    REASON_SEMANTIC_SSTI,
    REASON_SEMANTIC_XXE,
    REASON_SEMANTIC_DESER,
    REASON_SEMANTIC_NOSQL,
    REASON_SEMANTIC_OPEN_REDIRECT,
    REASON_SEMANTIC_HEADER_INJECTION,
    REASON_SEMANTIC_PROMPT_INJECTION,
    REASON_SEMANTIC_ANOMALY,
    REASON_SEMANTIC_GRAPHQL,
    REASON_SEMANTIC_JWT,
];

/// The reason and match detail as the SIEM event shows them.
pub fn siem_reason_and_detail(reason: &str, detail: &[u8]) -> (String, Vec<u8>) {
    let pre = |name: &str, strip: Option<&[u8]>| -> (String, Vec<u8>) {
        if detail.is_empty() {
            return (reason.to_string(), reason.as_bytes().to_vec());
        }
        let d = match strip {
            Some(p) => strings::trim_prefix(detail, p),
            None => detail,
        };
        (reason.to_string(), [name.as_bytes(), b":", d].concat())
    };
    match reason {
        REASON_SEMANTIC_SQL => pre("sql", Some(b"sql_")),
        REASON_SEMANTIC_XSS => pre("xss", None),
        REASON_SEMANTIC_CMD => pre("cmd", Some(b"cmd_")),
        REASON_SEMANTIC_PHP => pre("php", Some(b"php_")),
        REASON_SEMANTIC_PYTHON => pre("python", Some(b"python_")),
        REASON_SEMANTIC_LFI => pre("lfi", Some(b"lfi_")),
        REASON_SEMANTIC_SSRF => pre("ssrf", Some(b"ssrf_")),
        REASON_SEMANTIC_JAVA => pre("java", Some(b"java_")),
        REASON_SEMANTIC_SSTI => pre("ssti", None),
        REASON_SEMANTIC_XXE => pre("xxe", None),
        REASON_SEMANTIC_DESER => pre("deser", None),
        REASON_SEMANTIC_NOSQL => {
            if detail.is_empty() {
                (reason.to_string(), reason.as_bytes().to_vec())
            } else if detail.starts_with(b"nosql") {
                (reason.to_string(), detail.to_vec())
            } else {
                (reason.to_string(), [b"nosql:", detail].concat())
            }
        }
        _ => {
            if !detail.is_empty() {
                (reason.to_string(), detail.to_vec())
            } else {
                (reason.to_string(), reason.as_bytes().to_vec())
            }
        }
    }
}
