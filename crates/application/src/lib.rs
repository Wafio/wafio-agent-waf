//! The WAF agent's analyze pipeline and the in-memory L7 stores (`blocklist`, `ratelimit`).

#![forbid(unsafe_code)]

pub mod analyze;
pub mod blocklist;
pub mod content_scan;
pub mod coverage;
pub mod deps;
pub mod geo;
pub mod gui_rules;
mod login_protection;
pub mod ratelimit;
pub mod script_rules;
mod semantic_config;
mod uninspected;

pub use analyze::{
    AnalyzeConfig, RECOVERED_ANALYZE_PANICS, analyze, cache_base_semantic_config,
    check_block_store, composite_block_key, decode_or_keep_url_escapes, first_header_value,
};
pub use blocklist::BlockStore;
pub use content_scan::default_malware_engine;
pub use coverage::PARTIAL_COVERAGE_REQUESTS;
pub use geo::{DisabledGeoLookup, GeoLookup};
pub use ratelimit::RateLimitStore;
pub use script_rules::ScriptRunner;
