//! Flag handling: every flag with its name and default, the `WAFIO_*` env fallback
//! (CLI > env > error), required flags, path checks.

use std::path::Path;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use crate::duration_text;

/// The default bundle cache max age (7 days), in nanoseconds.
pub const DEFAULT_BUNDLE_CACHE_MAX_AGE_NS: i64 = 7 * 24 * 3600 * 1_000_000_000;
pub const DEFAULT_HOST_AGENT_TOKEN_PATH: &str = "/run/wafio/host-agent.token";
pub const LOCAL_API_TOKEN_FILE_ENV: &str = "WAFIO_LOCAL_API_TOKEN_FILE";

const LONG_ABOUT: &str = "wafio-waf-agent connects to the WAFio control plane over mTLS gRPC
and applies the routing/upstream configuration pushed from the dashboard.
The agent never runs in \"static\" mode — listen ports and upstream targets
are exclusively managed from the UI.";

#[derive(Parser, Debug)]
#[command(name = "wafio-waf-agent", about = "Server-driven per-host WAF agent", long_about = LONG_ABOUT)]
pub struct Cli {
    /// Print the version and the engine this agent would run with (a start loads the same library), then exit.
    #[arg(long = "features", hide = true)]
    pub print_features: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
    #[command(flatten)]
    pub agent: AgentArgs,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Download security data required by the WAF agent
    #[command(name = "fetch-data")]
    FetchData(crate::fetch_data::FetchDataFlags),
}

/// Go `agentFlags`. Field names follow the Go struct.
#[derive(Args, Debug, Clone, Default, PartialEq)]
pub struct AgentArgs {
    /// WAFio gRPC control-plane address (host:port) [REQUIRED]
    #[arg(
        allow_hyphen_values = true,
        long = "grpc-server",
        default_value = "",
        hide_default_value = true
    )]
    pub grpc_server: String,
    /// server name for SNI / cert verification (defaults to host of --grpc-server)
    #[arg(
        allow_hyphen_values = true,
        long = "grpc-server-name",
        default_value = "",
        hide_default_value = true
    )]
    pub grpc_server_name: String,
    /// path to PEM-encoded mTLS client certificate [REQUIRED]
    #[arg(
        allow_hyphen_values = true,
        long = "client-cert",
        default_value = "",
        hide_default_value = true
    )]
    pub client_cert: String,
    /// path to PEM-encoded mTLS client private key [REQUIRED]
    #[arg(
        allow_hyphen_values = true,
        long = "client-key",
        default_value = "",
        hide_default_value = true
    )]
    pub client_key: String,
    /// path to PEM-encoded WAFio agent CA bundle [REQUIRED]
    #[arg(
        allow_hyphen_values = true,
        long = "ca-cert",
        default_value = "",
        hide_default_value = true
    )]
    pub ca_cert: String,

    /// friendly agent identifier registered in the dashboard [REQUIRED]
    #[arg(
        allow_hyphen_values = true,
        long = "agent-name",
        default_value = "",
        hide_default_value = true
    )]
    pub agent_name: String,
    /// optional Host Key (wafh_*) when this agent runs on a registered host
    #[arg(
        allow_hyphen_values = true,
        long = "host-key",
        default_value = "",
        hide_default_value = true
    )]
    pub host_key: String,

    /// directory of the security data (geoip, user agents, malware hashes; env WAFIO_SECURITY_DATA_DIR; default /etc/wafio/security-data)
    #[arg(
        allow_hyphen_values = true,
        long = "security-data-dir",
        default_value = "",
        hide_default_value = true
    )]
    pub security_data_dir: String,
    /// deprecated name of the data directory setting of earlier versions (env WAFIO_CRS_DEFAULT_DIR); use --security-data-dir
    #[arg(
        allow_hyphen_values = true,
        long = "crs-default-dir",
        default_value = "",
        hide_default_value = true,
        hide = true
    )]
    pub legacy_data_dir: String,

    /// GeoLite2-Country.mmdb path (env WAFIO_GEO_COUNTRY_DB_PATH) [REQUIRED]
    #[arg(
        allow_hyphen_values = true,
        long = "geo-country-db",
        default_value = "",
        hide_default_value = true
    )]
    pub geo_country_db: String,
    /// GeoLite2-City.mmdb path (env WAFIO_GEO_CITY_DB_PATH) [REQUIRED]
    #[arg(
        allow_hyphen_values = true,
        long = "geo-city-db",
        default_value = "",
        hide_default_value = true
    )]
    pub geo_city_db: String,
    /// GeoLite2-ASN.mmdb path (env WAFIO_GEO_ASN_DB_PATH) [REQUIRED]
    #[arg(
        allow_hyphen_values = true,
        long = "geo-asn-db",
        default_value = "",
        hide_default_value = true
    )]
    pub geo_asn_db: String,

    /// bad user-agent list file (env WAFIO_UA_BAD_BOT_FILE) [REQUIRED]
    #[arg(
        allow_hyphen_values = true,
        long = "bot-ua-file",
        default_value = "",
        hide_default_value = true
    )]
    pub bot_ua_file: String,
    /// JA4 fingerprint blocklist file (env WAFIO_JA4_BLACKLIST_FILE; optional)
    #[arg(
        allow_hyphen_values = true,
        long = "bot-ja4-file",
        default_value = "",
        hide_default_value = true
    )]
    pub bot_ja4_file: String,
    /// JA3 fingerprint blacklist file (env WAFIO_JA3_BLACKLIST_FILE; optional, legacy)
    #[arg(
        allow_hyphen_values = true,
        long = "bot-ja3-file",
        default_value = "",
        hide_default_value = true
    )]
    pub bot_ja3_file: String,

    /// PID file path for zero-downtime binary upgrades via SIGUSR2 (e.g. /run/wafio/wafio-waf-agent.pid; optional)
    #[arg(
        allow_hyphen_values = true,
        long = "pid-file",
        default_value = "",
        hide_default_value = true
    )]
    pub pid_file: String,

    /// path to local firehol_level1.netset (optional; if unset the agent downloads from GitHub)
    #[arg(
        allow_hyphen_values = true,
        long = "iprep-level1-file",
        default_value = "",
        hide_default_value = true
    )]
    pub iprep_level1_file: String,
    /// path to local firehol_level2.netset (optional; if unset the agent downloads from GitHub)
    #[arg(
        allow_hyphen_values = true,
        long = "iprep-level2-file",
        default_value = "",
        hide_default_value = true
    )]
    pub iprep_level2_file: String,

    /// WAF blocks within the window before an IP is jailed in the host-agent XDP blocklist (0 = disabled)
    #[arg(allow_hyphen_values = true, long = "jail-threshold", default_value = "5", value_parser = parse_int_flag)]
    pub jail_threshold: i64,
    /// jail sliding window in seconds
    #[arg(allow_hyphen_values = true, long = "jail-window-sec", default_value = "60", value_parser = parse_int_flag)]
    pub jail_window_sec: i64,
    /// how long a jailed IP stays in the XDP blocklist
    #[arg(allow_hyphen_values = true, long = "jail-duration-sec", default_value = "3600", value_parser = parse_int_flag)]
    pub jail_duration_sec: i64,
    /// host-agent local blocklist endpoint receiving jail pushes (POST {entries:[{ip,ttl_ms}]})
    #[arg(
        allow_hyphen_values = true,
        long = "jail-url",
        default_value = "http://127.0.0.1:18089/api/ebpf/blocklist"
    )]
    pub jail_url: String,
    /// host-agent local API token file sent as Bearer on jail pushes (default /run/wafio/host-agent.token; env WAFIO_LOCAL_API_TOKEN_FILE; the WAF agent user needs read access, see host agent --local-api-token-group)
    #[arg(
        allow_hyphen_values = true,
        long = "jail-token-file",
        default_value = "",
        hide_default_value = true
    )]
    pub jail_token_file: String,

    /// directory for last-bundle.json (env WAFIO_STATE_DIR; default $STATE_DIRECTORY set by systemd StateDirectory=; empty = no bundle cache)
    #[arg(
        allow_hyphen_values = true,
        long = "state-dir",
        default_value = "",
        hide_default_value = true
    )]
    pub state_dir: String,
    /// the semantic engine library to load (env WAFIO_ENGINE_LIB; default /usr/lib/wafio/libwafio_semantic_engine.so). Only an agent without the engine linked in loads one
    #[arg(
        allow_hyphen_values = true,
        long = "engine-lib",
        default_value = "",
        hide_default_value = true
    )]
    pub engine_lib: String,
    /// age after which a cached bundle is reported stale in the heartbeat (still applied; env WAFIO_BUNDLE_CACHE_MAX_AGE)
    #[arg(allow_hyphen_values = true, long = "bundle-cache-max-age", default_value = "168h0m0s", value_parser = parse_duration_flag)]
    pub bundle_cache_max_age: i64,
}

/// An integer flag value (64-bit; a base prefix selects the base).
pub fn parse_int_flag(s: &str) -> Result<i64, String> {
    wafio_bytetext::literal::parse_int(s.as_bytes(), 0, 64).map_err(|e| e.to_string())
}

/// A duration flag value, in nanoseconds.
pub fn parse_duration_flag(s: &str) -> Result<i64, String> {
    duration_text::parse_duration(s)
}

/// The process environment as the env fallback reads it (injectable for tests).
pub trait Env {
    fn get(&self, key: &str) -> String;
    /// The file exists and is not empty.
    fn non_empty_file(&self, path: &str) -> bool {
        std::fs::metadata(path)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
    }
}

/// The real environment: unset and non-UTF-8 values read as "".
pub struct OsEnv;

impl Env for OsEnv {
    fn get(&self, key: &str) -> String {
        std::env::var(key).unwrap_or_default()
    }
}

/// Default JA4 file locations the env fallback tries in order.
const JA4_CANDIDATES: [&str; 3] = [
    "security-data/ja4/ja4.txt",
    "/etc/wafio/security-data/ja4/ja4.txt",
    "/usr/local/share/wafio/ja4/ja4.txt",
];

impl AgentArgs {
    /// Fills unset flags from the environment. Returns the log lines it produces while doing so.
    pub fn fill_from_env(&mut self, env: &dyn Env) -> Vec<String> {
        let mut logs = Vec::new();
        let fill = |v: &mut String, key: &str| {
            if v.is_empty() {
                *v = env.get(key);
            }
        };
        fill(&mut self.agent_name, "WAFIO_AGENT_NAME");
        fill(&mut self.host_key, "WAFIO_HOST_KEY");
        fill(&mut self.grpc_server, "WAFIO_GRPC_SERVER");
        fill(&mut self.grpc_server_name, "WAFIO_GRPC_SERVER_NAME");
        fill(&mut self.client_cert, "WAFIO_GRPC_CLIENT_CERT");
        fill(&mut self.client_key, "WAFIO_GRPC_CLIENT_KEY");
        fill(&mut self.ca_cert, "WAFIO_GRPC_CA_CERT");
        fill(&mut self.security_data_dir, "WAFIO_SECURITY_DATA_DIR");
        fill(&mut self.legacy_data_dir, "WAFIO_CRS_DEFAULT_DIR");
        fill(&mut self.geo_country_db, "WAFIO_GEO_COUNTRY_DB_PATH");
        fill(&mut self.geo_city_db, "WAFIO_GEO_CITY_DB_PATH");
        fill(&mut self.geo_asn_db, "WAFIO_GEO_ASN_DB_PATH");
        fill(&mut self.engine_lib, crate::engine_lib::ENV_LIBRARY);
        fill(&mut self.bot_ua_file, "WAFIO_UA_BAD_BOT_FILE");
        fill(&mut self.bot_ja4_file, "WAFIO_JA4_BLACKLIST_FILE");
        if self.bot_ja4_file.is_empty()
            && let Some(c) = JA4_CANDIDATES.iter().find(|c| env.non_empty_file(c))
        {
            self.bot_ja4_file = (*c).to_string();
        }
        fill(&mut self.bot_ja3_file, "WAFIO_JA3_BLACKLIST_FILE");
        fill(&mut self.iprep_level1_file, "WAFIO_IPREP_LEVEL1_FILE");
        fill(&mut self.iprep_level2_file, "WAFIO_IPREP_LEVEL2_FILE");
        if !env.get("WAFIO_TLS_SITES_FILE").is_empty() {
            logs.push(
                "[wafio-waf-agent] WARNING: WAFIO_TLS_SITES_FILE is no longer read: the HTTPS settings of an app come from the dashboard"
                    .to_string(),
            );
        }
        self.state_dir = choose_state_dir(
            &self.state_dir,
            &env.get("WAFIO_STATE_DIR"),
            &env.get("STATE_DIRECTORY"),
        );
        let v = env.get("WAFIO_BUNDLE_CACHE_MAX_AGE");
        // The env only applies while the flag still holds its default value.
        if !v.is_empty() && self.bundle_cache_max_age == DEFAULT_BUNDLE_CACHE_MAX_AGE_NS {
            match duration_text::parse_duration(&v) {
                Ok(d) if d > 0 => self.bundle_cache_max_age = d,
                _ => logs.push(format!(
                    "[wafio-waf-agent] ignoring invalid WAFIO_BUNDLE_CACHE_MAX_AGE={}",
                    wafio_domain::text_helpers::quote(v.as_bytes())
                )),
            }
        }
        logs
    }

    /// Every missing required flag in one error.
    pub fn check_required(&self) -> Result<(), String> {
        let required = [
            ("--grpc-server", &self.grpc_server),
            ("--client-cert", &self.client_cert),
            ("--client-key", &self.client_key),
            ("--ca-cert", &self.ca_cert),
            ("--agent-name", &self.agent_name),
            ("--geo-country-db", &self.geo_country_db),
            ("--geo-city-db", &self.geo_city_db),
            ("--geo-asn-db", &self.geo_asn_db),
            ("--bot-ua-file", &self.bot_ua_file),
        ];
        let blank = |v: &str| wafio_bytetext::strings::trim_whitespace(v.as_bytes()).is_empty();
        let mut missing: Vec<&str> = required
            .iter()
            .filter(|(_, v)| blank(v))
            .map(|(n, _)| *n)
            .collect();
        if blank(&self.bot_ja4_file) && blank(&self.bot_ja3_file) {
            missing.push("--bot-ja4-file");
        }
        if !missing.is_empty() {
            return Err(format!("missing required flag(s): {}", missing.join(", ")));
        }
        Ok(())
    }

    /// Every file exists and is not empty.
    pub fn check_paths(&self) -> Result<(), String> {
        let mut files = vec![
            ("--client-cert", &self.client_cert),
            ("--client-key", &self.client_key),
            ("--ca-cert", &self.ca_cert),
            ("--geo-country-db", &self.geo_country_db),
            ("--geo-city-db", &self.geo_city_db),
            ("--geo-asn-db", &self.geo_asn_db),
            ("--bot-ua-file", &self.bot_ua_file),
        ];
        if !self.bot_ja4_file.is_empty() {
            files.push(("--bot-ja4-file", &self.bot_ja4_file));
        }
        if !self.bot_ja3_file.is_empty() {
            files.push(("--bot-ja3-file", &self.bot_ja3_file));
        }
        for (flag, path) in files {
            let q = wafio_domain::text_helpers::quote(path.as_bytes());
            match std::fs::metadata(path) {
                Err(e) => {
                    return Err(format!(
                        "{flag}: cannot stat {q}: {}",
                        stat_error_text(path, &e)
                    ));
                }
                Ok(m) if m.len() == 0 => return Err(format!("{flag}: {q} is empty")),
                Ok(_) => {}
            }
        }
        Ok(())
    }

    /// The security-data directory: `--security-data-dir` (or its env), else the one the deprecated
    /// `--crs-default-dir` (or its env) implies; empty when neither is set.
    pub fn resolved_security_data_dir(&self) -> String {
        if !self.security_data_dir.is_empty() {
            return self.security_data_dir.clone();
        }
        if self.legacy_data_dir.is_empty() {
            return String::new();
        }
        crate::security_data::security_data_dir_from_legacy_setting(&self.legacy_data_dir)
    }

    /// The one start warning when the directory comes from the deprecated setting; None otherwise.
    pub fn legacy_data_dir_warning(&self) -> Option<String> {
        if !self.security_data_dir.is_empty() || self.legacy_data_dir.is_empty() {
            return None;
        }
        let dir = self.resolved_security_data_dir();
        Some(format!(
            "[wafio-waf-agent] WARNING: --crs-default-dir and WAFIO_CRS_DEFAULT_DIR are deprecated: using {dir} as the security-data directory; set --security-data-dir or WAFIO_SECURITY_DATA_DIR to {dir}"
        ))
    }

    /// The values the engine crates read from the environment (bot lists,
    /// GeoIP) and the upgraded child inherits. Call before any thread starts.
    pub fn engine_env(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![("WAFIO_AGENT_NAME", self.agent_name.clone())];
        if !self.host_key.is_empty() {
            out.push(("WAFIO_HOST_KEY", self.host_key.clone()));
        }
        out.push(("WAFIO_GRPC_SERVER", self.grpc_server.clone()));
        let dir = self.resolved_security_data_dir();
        if !dir.is_empty() {
            out.push(("WAFIO_SECURITY_DATA_DIR", dir));
        }
        out.push(("WAFIO_GEO_COUNTRY_DB_PATH", self.geo_country_db.clone()));
        out.push(("WAFIO_GEO_CITY_DB_PATH", self.geo_city_db.clone()));
        out.push(("WAFIO_GEO_ASN_DB_PATH", self.geo_asn_db.clone()));
        out.push(("WAFIO_UA_BAD_BOT_FILE", self.bot_ua_file.clone()));
        if !self.bot_ja4_file.is_empty() {
            out.push(("WAFIO_JA4_BLACKLIST_FILE", self.bot_ja4_file.clone()));
        }
        if !self.bot_ja3_file.is_empty() {
            out.push(("WAFIO_JA3_BLACKLIST_FILE", self.bot_ja3_file.clone()));
        }
        out
    }

    /// `--grpc-server-name`, else everything before the last ':' of `--grpc-server`.
    pub fn server_name(&self) -> String {
        if !self.grpc_server_name.is_empty() {
            return self.grpc_server_name.clone();
        }
        wafio_control::default_server_name(&self.grpc_server)
    }

    /// `--bundle-cache-max-age` as the bundle cache reads it (≤ 0 → 7 days).
    pub fn bundle_cache_max_age(&self) -> Duration {
        if self.bundle_cache_max_age <= 0 {
            return Duration::from_nanos(DEFAULT_BUNDLE_CACHE_MAX_AGE_NS as u64);
        }
        Duration::from_nanos(self.bundle_cache_max_age as u64)
    }

    /// The jail token file: the flag, else `WAFIO_LOCAL_API_TOKEN_FILE`; the jail enforcer
    /// falls back to the default path when both are empty.
    pub fn jail_token_file(&self, env: &dyn Env) -> String {
        if self.jail_token_file.is_empty() {
            env.get(LOCAL_API_TOKEN_FILE_ENV)
        } else {
            self.jail_token_file.clone()
        }
    }

    /// The component paths the agent reports.
    pub fn component_paths(&self) -> std::collections::BTreeMap<String, String> {
        [
            ("geoip-country", &self.geo_country_db),
            ("geoip-city", &self.geo_city_db),
            ("geoip-asn", &self.geo_asn_db),
            ("ua", &self.bot_ua_file),
            ("ja4", &self.bot_ja4_file),
            ("ja3", &self.bot_ja3_file),
            ("firehol-level1", &self.iprep_level1_file),
            ("firehol-level2", &self.iprep_level2_file),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }
}

/// The state directory: `--state-dir`, then `WAFIO_STATE_DIR`, then systemd's
/// `STATE_DIRECTORY` (first entry when the unit lists several).
pub fn choose_state_dir(flag_val: &str, env_val: &str, systemd_val: &str) -> String {
    let t = |s: &str| {
        String::from_utf8_lossy(wafio_bytetext::strings::trim_whitespace(s.as_bytes())).into_owned()
    };
    let v = t(flag_val);
    if !v.is_empty() {
        return v;
    }
    let v = t(env_val);
    if !v.is_empty() {
        return v;
    }
    let first = systemd_val.split(':').next().unwrap_or("");
    t(first)
}

/// The error text for a failed stat: "stat <path>: <errno text>".
fn stat_error_text(path: &str, e: &std::io::Error) -> String {
    path_error_text("stat", path, e)
}

/// A path error text: "<op> <path>: <errno text>" ("open" when opening a file).
pub(crate) fn path_error_text(op: &str, path: &str, e: &std::io::Error) -> String {
    let text = match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        _ => {
            let s = e.to_string();
            // Rust appends " (os error N)"; only the errno text is wanted.
            match s.find(" (os error") {
                Some(i) => s[..i].to_lowercase(),
                None => s,
            }
        }
    };
    format!("{op} {}: {text}", Path::new(path).display())
}

#[cfg(test)]
mod tests;
