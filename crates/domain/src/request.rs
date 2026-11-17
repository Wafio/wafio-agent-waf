//! Request and decision types of the analyze path.

use std::collections::BTreeMap;
use std::time::SystemTime;

/// Request headers: name → values in arrival order. The map is sorted by name,
/// so its iteration order is stable.
pub type Headers = BTreeMap<Vec<u8>, Vec<Vec<u8>>>;

/// `IncomingRequest.body_scan_skipped` for a body left undecoded because the
/// process-wide decode memory budget had no room (load-induced, never blocks).
pub const BODY_SCAN_SKIPPED_DECOMPRESS_BUDGET: &str = "decompress_budget";

/// The canonical request representation for analysis. Strings are raw bytes
/// (they may hold arbitrary bytes).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IncomingRequest {
    pub method: Vec<u8>,
    /// Raw request-target as received (path + query), scanned as-is.
    pub uri: Vec<u8>,
    /// Decoded, normalized path the proxy forwards upstream; empty when the
    /// caller has no live proxy request (the analyzer derives it from `uri`).
    pub forwarded_path: Vec<u8>,
    pub headers: Headers,
    pub remote_address: Vec<u8>,
    /// `remote_address` came from X-Forwarded-For / X-Real-IP of a trusted proxy;
    /// the L7 → XDP jail skips such clients.
    pub client_forwarded: bool,
    pub host: Vec<u8>,
    /// Body sent to the WAF (may be truncated for multipart).
    pub body: Vec<u8>,
    /// Complete upload body, separate from semantic input; None falls back to `body`.
    pub content_scan_body: Option<Vec<u8>>,
    /// Original body size in bytes, for the limit check.
    pub body_size: i64,
    /// Raw request Content-Type header value.
    pub content_type: Vec<u8>,
    /// Non-empty when the transport could not hand the analyzer the complete
    /// scannable body: `content_encoding:<enc>`, `decompress_limit`,
    /// `decompress_error`, `decompress_budget`.
    pub body_scan_skipped: String,
    pub user_agent: Vec<u8>,
    pub request_id: Vec<u8>,
    /// Modern TLS client fingerprint.
    pub ja4: Vec<u8>,
    /// Legacy TLS client fingerprint (MD5 hash).
    pub ja3: Vec<u8>,
}

/// How the decision was produced.
pub const ANALYZE_METHOD_SEMANTIC: &str = "semantic";
/// Deprecated alias for ANALYZE_METHOD_SEMANTIC.
pub const ANALYZE_METHOD_FAST_SCAN: &str = "semantic";
pub const ANALYZE_METHOD_POLICY: &str = "policy";
pub const ANALYZE_METHOD_GEO: &str = "geo";
pub const ANALYZE_METHOD_BOT: &str = "bot";
pub const ANALYZE_METHOD_BODY_LIMIT: &str = "body_limit";
pub const ANALYZE_METHOD_ERROR: &str = "error";
pub const ANALYZE_METHOD_CUSTOM_RULE: &str = "custom_rule";
pub const ANALYZE_METHOD_CONTENT_SCAN: &str = "content_scan";

/// The response of the analyze use case (allow / log / block).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AnalysisResult {
    /// "allow", "log", "block", "challenge".
    pub action: String,
    /// What the decision event carries as its score: the fixed number of the detection's category and tier
    /// (`decision_score` of the engine boundary), or the bot score of a bot decision. No verdict reads it.
    pub score: i64,
    /// Rule IDs that contributed. The semantic engines set none; the field stays for the
    /// decisions of earlier agents.
    pub rule_ids: Vec<i64>,
    pub categories: Vec<String>,
    /// If set and in the future: the client should block this key until then.
    pub block_until: Option<SystemTime>,
    pub message: Vec<u8>,
    pub analyze_method: String,
    pub match_detail: Vec<u8>,
    /// E.g. "body", "query:q", "header:Referer", "path".
    pub match_source: Vec<u8>,
    /// An engine named the match source input itself.
    pub match_source_exact: bool,
    /// Decoded value of the flagged part (None: unknown). In process only.
    pub match_value: Option<Vec<u8>>,
    /// HTTP status override for block responses (0 = default 403).
    pub status_code: i64,
    pub cwe: String,
    pub mitre_techniques: Vec<String>,
    /// Comma-separated coverage flags ("" = complete).
    pub coverage: String,
    /// Detector keys the operator switched off for this request (project, path or tuning rule). Not a coverage gap and
    /// not in `coverage`: the decision event lists them as `engine_disabled:<key>` next to the gap flags.
    pub engines_off: Vec<String>,
    /// Detector keys whose blocking detection was held back as LOG on this request (`action: "log"`). The decision
    /// event lists them as `engine_log_only:<key>` after the `engine_disabled` marks.
    pub engines_log_only: Vec<String>,
    /// No semantic engine is installed in this agent, so nothing inspected the request for attacks. The decision
    /// event lists it as `engine_absent` next to the other marks.
    pub engine_absent: bool,
    /// The action was raised only because part of the request was not
    /// inspected; never feeds per-client penalties (IP jail).
    pub coverage_raised: bool,
    /// With action "challenge": the pipeline verdict once the client holds a
    /// valid challenge cookie or cannot be challenged ("" reads as "allow").
    pub challenge_fallback: String,
}
