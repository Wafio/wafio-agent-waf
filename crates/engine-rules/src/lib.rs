//! The rules side of the engine: rules JSON with the WAF agent's semantics, path exceptions, custom GUI
//! and tuning rules, rule regexes, body parse for custom rules, the types of script rules.

#![forbid(unsafe_code)]

pub mod bot;
pub mod bot_defaults;
pub mod config;
pub mod content_scan;
pub mod custom_rules;
pub mod custom_rules_v2;
pub mod custom_rules_validate;
pub mod field_names;
pub mod forwarded_path;
pub mod ip_network;
pub mod json_decode;
pub mod login_protection;
pub mod parsed_body;
pub mod path_rules;
pub mod pattern_compile;
pub mod rule_regex;
pub mod script_sandbox;
pub mod tuning;

pub use config::*;
pub use content_scan::*;
pub use custom_rules::*;
pub use custom_rules_v2::*;
pub use custom_rules_validate::*;
pub use field_names::*;
pub use forwarded_path::*;
pub use login_protection::*;
pub use parsed_body::*;
pub use path_rules::*;
pub use rule_regex::*;
pub use script_sandbox::*;
pub use tuning::*;
