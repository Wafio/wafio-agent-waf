//! The domain types and rules the WAF agent's analyze path and proxy use. Strings that carry
//! request data are `Vec<u8>` / `&[u8]`; JSON-decoded configuration is
//! `String` (a JSON decoder always yields valid UTF-8).

#![forbid(unsafe_code)]

pub mod app;
pub mod clientip;
pub mod decision_redact;
pub mod decision_redact_body;
pub mod ip_address;
pub mod json_text;
pub mod multipart;
pub mod proxyconfig;
pub mod request;
pub mod text_helpers;
pub mod waf_custom_rule;
pub mod websocket_config;

pub use app::App;
pub use clientip::*;
pub use decision_redact::*;
pub use decision_redact_body::*;
pub use proxyconfig::*;
pub use request::*;
pub use waf_custom_rule::*;
pub use websocket_config::*;
