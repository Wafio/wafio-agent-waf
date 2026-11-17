//! CWE and MITRE ATT&CK ids per detection, for the audit trail and SIEM.

use crate::reason::*;

/// The CWE id and MITRE ATT&CK techniques of one detection. An empty `cwe` / technique list means none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttackClassification {
    pub cwe: &'static str,
    pub mitre_techniques: &'static [&'static str],
}

const fn tax(cwe: &'static str, mitre_techniques: &'static [&'static str]) -> AttackClassification {
    AttackClassification {
        cwe,
        mitre_techniques,
    }
}

/// The classification of a normalized reason and its match detail.
pub fn classify_semantic_reason(
    normalized_reason: &str,
    match_detail: &[u8],
) -> AttackClassification {
    match normalized_reason {
        REASON_SEMANTIC_SQL => tax("CWE-89", &["T1190"]),
        REASON_SEMANTIC_XSS => tax("CWE-79", &["T1059.007"]),
        REASON_SEMANTIC_CMD => tax("CWE-78", &["T1059"]),
        REASON_SEMANTIC_PHP => tax("CWE-94", &["T1059"]),
        REASON_SEMANTIC_PYTHON => tax("CWE-94", &["T1059"]),
        REASON_SEMANTIC_LFI => tax("CWE-22", &["T1083"]),
        REASON_SEMANTIC_SSRF => tax("CWE-918", &["T1071"]),
        REASON_SEMANTIC_JAVA => tax("CWE-917", &["T1190", "T1059"]),
        REASON_SEMANTIC_LDAP => tax("CWE-90", &["T1190"]),
        REASON_SEMANTIC_PROTO_POLLUTION => tax("CWE-1321", &["T1059.007"]),
        REASON_SEMANTIC_SSTI => tax("CWE-1336", &["T1221", "T1059"]),
        REASON_SEMANTIC_XXE => tax("CWE-611", &["T1190"]),
        REASON_SEMANTIC_DESER => tax("CWE-502", &["T1190", "T1059"]),
        REASON_SEMANTIC_NOSQL => tax("CWE-943", &["T1190"]),
        REASON_SEMANTIC_OPEN_REDIRECT => tax("CWE-601", &["T1566.002"]),
        REASON_SEMANTIC_HEADER_INJECTION => tax("CWE-113", &["T1190"]),
        // MITRE ATLAS AML.T0051 (LLM prompt injection); no classic ATT&CK technique.
        REASON_SEMANTIC_PROMPT_INJECTION => tax("CWE-1427", &["T1190"]),
        REASON_SEMANTIC_GRAPHQL => tax("CWE-200", &["T1592"]),
        REASON_SEMANTIC_JWT => {
            if wafio_bytetext::strings::contains(match_detail, b"kid_traversal") {
                tax("CWE-22", &["T1550.001", "T1190"])
            } else {
                tax("CWE-347", &["T1550.001", "T1190"])
            }
        }
        REASON_SEMANTIC_ANOMALY => tax("", &["T1190"]),
        _ => AttackClassification::default(),
    }
}

/// Deprecated alias of [`classify_semantic_reason`].
pub fn classify_legacy_scan_reason(
    normalized_reason: &str,
    match_detail: &[u8],
) -> AttackClassification {
    classify_semantic_reason(normalized_reason, match_detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_semantic_reason_has_classification() {
        assert!(!ALL_SEMANTIC_REASONS.is_empty());
        for reason in ALL_SEMANTIC_REASONS {
            if reason == REASON_SEMANTIC_ANOMALY {
                continue;
            }
            let t = classify_semantic_reason(reason, b"");
            assert!(!t.cwe.is_empty(), "reason {reason} has no CWE mapping");
            assert!(
                !t.mitre_techniques.is_empty(),
                "reason {reason} has no MITRE technique"
            );
        }
    }

    #[test]
    fn legacy_scan_classification_alias_matches() {
        for reason in ALL_SEMANTIC_REASONS {
            assert_eq!(
                classify_semantic_reason(reason, b"").cwe,
                classify_legacy_scan_reason(reason, b"").cwe
            );
        }
    }
}
