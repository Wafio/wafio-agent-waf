//! Framework-independent WAF agent I/O logic: WebSocket frames, scan views and config, the FastCGI
//! client and pool, client IP trust, the IP jail and its guard, store limits, UTF-8 sanitizing for
//! proto fields and the OpenMetrics writer. No Pingora or hyper types here.

#![forbid(unsafe_code)]

pub mod client_ip;
pub mod fastcgi_client;
pub mod ip_jail;
pub mod ip_jail_guard;
pub mod metrics;
mod sha1;
pub mod store_limits;
pub mod url_parse;
pub mod utf8;
pub mod websocket_config;
pub mod ws_config;
pub mod ws_frame;
pub mod ws_scanner;

/// The version the build stamped through `WAFIO_AGENT_VERSION`; `dev` when it did not.
pub const AGENT_VERSION: &str = match option_env!("WAFIO_AGENT_VERSION") {
    Some(v) => v,
    None => "dev",
};

/// The `User-Agent` of the requests the agent makes on its own.
pub fn user_agent() -> String {
    format!("wafio-waf-agent/{AGENT_VERSION}")
}
