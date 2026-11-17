//! The semantic scan configuration the agent builds from a rules document and hands to the engine.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::policy::*;
use crate::ssrf_config::SsrfConfig;
use crate::tier::Tier;

/// The evidence thresholds of the detectors that have them, the switches, and the SSRF list for the semantic scan.
/// Optional fields are `Option<T>`; integer fields are i64.
#[derive(Clone, Debug, Default)]
pub struct SemanticConfig {
    pub sql_semantic_policy: Option<SqlPolicy>,
    pub xss_semantic_policy: Option<XssPolicy>,
    pub cmd_semantic_policy: Option<CmdPolicy>,
    pub php_semantic_policy: Option<PhpPolicy>,
    pub python_semantic_policy: Option<PythonPolicy>,
    pub lfi_semantic_policy: Option<LfiPolicy>,
    pub ssrf_semantic_policy: Option<SsrfPolicy>,
    pub java_semantic_policy: Option<JavaPolicy>,
    pub ssrf_config: Option<Arc<SsrfConfig>>,
    pub nosql_semantic_policy: Option<NosqlPolicy>,
    pub ssti_semantic_policy: Option<SstiPolicy>,
    pub xxe_semantic_policy: Option<XxePolicy>,
    pub deser_semantic_policy: Option<DeserPolicy>,
    /// Engines to skip; key = engine key (sql/xss/cmd/...).
    pub disabled_engines: Option<HashMap<String, bool>>,
    /// Engines whose strong detections become LOG (`action: "log"`); None when no engine is.
    pub log_only_engines: Option<HashSet<String>>,
    /// Relaxed-parse work budget per engine per scan window; <= 0 = per-engine default.
    pub engine_parse_work_budget: i64,
    /// Lower-cased form/JSON field name of a scanned body value ("" otherwise).
    pub field_name: Vec<u8>,
}

impl SemanticConfig {
    pub fn is_disabled(&self, key: &str) -> bool {
        self.disabled_engines
            .as_ref()
            .is_some_and(|m| m.get(key).copied().unwrap_or(false))
    }

    pub fn is_log_only(&self, key: &str) -> bool {
        self.log_only_engines
            .as_ref()
            .is_some_and(|s| s.contains(key))
    }

    /// This config with every log-only engine switched off: what would block if they only log.
    pub fn without_log_only(&self) -> SemanticConfig {
        let mut c = self.clone();
        if let Some(keys) = c.log_only_engines.take() {
            let off = c.disabled_engines.get_or_insert_with(HashMap::new);
            off.extend(keys.into_iter().map(|k| (k, true)));
        }
        c
    }
}

/// What one value scan found; a clean tier and an empty reason mean nothing was found.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SemanticScanResult {
    pub tier: Tier,
    pub reason: &'static str,
    pub detail: Vec<u8>,
    pub truncated: bool,
    pub engine_panicked: bool,
    pub budget_exhausted: bool,
    /// engine closures run (gates opened), head + tail window
    pub engines: i64,
}

impl SemanticScanResult {
    /// Whether no coverage flag is set.
    pub fn complete(&self) -> bool {
        !self.truncated && !self.engine_panicked && !self.budget_exhausted
    }

    /// Whether this finding is the one to report instead of `other`: a stronger tier, or the same tier with a
    /// higher [`decision_score`](crate::decision_score) for its reason.
    pub fn outranks(&self, other: &SemanticScanResult) -> bool {
        crate::tier::outranks((self.tier, self.reason), (other.tier, other.reason))
    }
}
