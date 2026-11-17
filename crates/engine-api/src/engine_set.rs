//! The `EngineSet` type and the switch keys of the detectors that have an engine of their own.

use crate::reason::*;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

/// The engines with an engine of their own (the first fifteen keys of semantic_policies); `jwt`, `graphql`,
/// `open_redirect`, `prompt_injection` and `anomaly` are not in it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EngineSet(pub u32);

pub const ENGINE_SQL: EngineSet = EngineSet(1 << 0);
pub const ENGINE_XSS: EngineSet = EngineSet(1 << 1);
pub const ENGINE_CMD: EngineSet = EngineSet(1 << 2);
pub const ENGINE_PHP: EngineSet = EngineSet(1 << 3);
pub const ENGINE_PYTHON: EngineSet = EngineSet(1 << 4);
pub const ENGINE_LFI: EngineSet = EngineSet(1 << 5);
pub const ENGINE_SSRF: EngineSet = EngineSet(1 << 6);
pub const ENGINE_JAVA: EngineSet = EngineSet(1 << 7);
pub const ENGINE_NOSQL: EngineSet = EngineSet(1 << 8);
pub const ENGINE_SSTI: EngineSet = EngineSet(1 << 9);
pub const ENGINE_XXE: EngineSet = EngineSet(1 << 10);
pub const ENGINE_DESER: EngineSet = EngineSet(1 << 11);
pub const ENGINE_LDAP: EngineSet = EngineSet(1 << 12);
pub const ENGINE_PROTO_POLLUTION: EngineSet = EngineSet(1 << 13);
pub const ENGINE_HEADER_INJECTION: EngineSet = EngineSet(1 << 14);

/// Bit i → its DisabledEngines key.
pub const ENGINE_SET_KEYS: [&str; 15] = [
    "sql",
    "xss",
    "cmd",
    "php",
    "python",
    "lfi",
    "ssrf",
    "java",
    "nosql",
    "ssti",
    "xxe",
    "deser",
    "ldap",
    "proto_pollution",
    "header_injection",
];

impl BitOr for EngineSet {
    type Output = EngineSet;
    fn bitor(self, o: EngineSet) -> EngineSet {
        EngineSet(self.0 | o.0)
    }
}
impl BitOrAssign for EngineSet {
    fn bitor_assign(&mut self, o: EngineSet) {
        self.0 |= o.0;
    }
}
impl BitAnd for EngineSet {
    type Output = EngineSet;
    fn bitand(self, o: EngineSet) -> EngineSet {
        EngineSet(self.0 & o.0)
    }
}
impl BitAndAssign for EngineSet {
    fn bitand_assign(&mut self, o: EngineSet) {
        self.0 &= o.0;
    }
}
impl Not for EngineSet {
    type Output = EngineSet;
    fn not(self) -> EngineSet {
        EngineSet(!self.0)
    }
}

impl EngineSet {
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether every engine of e is in s (false for an empty e).
    pub fn has(self, e: EngineSet) -> bool {
        e.0 != 0 && self.0 & e.0 == e.0
    }

    /// The engine keys in s in bit order (empty when s is empty).
    pub fn keys(self) -> Vec<&'static str> {
        ENGINE_SET_KEYS
            .iter()
            .enumerate()
            .filter(|(i, _)| self.0 & (1 << i) != 0)
            .map(|(_, k)| *k)
            .collect()
    }
}

/// The engine bit of a disabled-engines key; empty for an unknown key.
pub fn engine_set_from_disabled_key(key: &str) -> EngineSet {
    match ENGINE_SET_KEYS.iter().position(|k| *k == key) {
        Some(i) => EngineSet(1 << i),
        None => EngineSet(0),
    }
}

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
    fn engine_set_basics() {
        let s = ENGINE_SQL | ENGINE_LDAP;
        assert!(s.has(ENGINE_SQL) && !s.has(ENGINE_XSS) && !s.has(EngineSet(0)));
        assert_eq!(s.keys(), vec!["sql", "ldap"]);
        assert_eq!(
            engine_set_from_disabled_key("proto_pollution"),
            ENGINE_PROTO_POLLUTION
        );
        assert_eq!(engine_set_from_disabled_key("jwt"), EngineSet(0));
        assert_eq!(
            engine_set_from_disabled_key("header_injection"),
            ENGINE_HEADER_INJECTION
        );
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
