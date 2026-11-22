//! wafio-waf-agent: flags, startup, control link and bundle application.

// One audited `unsafe` site in this crate carries `#[allow(unsafe_code)]`; anything new needs the same, with its reason.
#![deny(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod agent;
pub mod bundle;
pub mod challenge_key;
pub mod duration_text;
pub mod engine_lib;
pub mod executor;
pub mod fetch_data;
pub mod flags;
pub mod gaps;
pub mod hostinfo;
pub mod httpclient;
pub mod metrics;
pub mod multipart_body;
pub mod ready;
pub mod redact;
pub mod reload;
pub mod run;
pub mod script_rules;
pub mod security_data;
pub mod setup;
mod setup_ja4;
mod setup_malware;
pub mod siem;
pub mod stderr_log;
pub mod tls;

use std::process::ExitCode;

use clap::Parser;

/// `main`: parse, dispatch, print `wafio-waf-agent: <error>` and exit 1 on failure.
pub fn main_entry() -> ExitCode {
    let cli = match flags::Cli::try_parse() {
        Ok(c) => c,
        Err(e) if !e.use_stderr() => {
            let _ = e.print();
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("wafio-waf-agent: {}", e.to_string().trim_end());
            return ExitCode::FAILURE;
        }
    };
    if cli.print_features {
        // The step of a start with the same plan (the library that was named, else the default path), so that this probe
        // shows the engine the service would run with. A library error that stops a start stops the probe too.
        stderr_log::init();
        let asked = match cli.agent.engine_lib.as_str() {
            "" => std::env::var(engine_lib::ENV_LIBRARY).unwrap_or_default(),
            flag => flag.to_string(),
        };
        if let Err(e) = engine_lib::load_for_report(&asked) {
            eprintln!("wafio-waf-agent: {e}");
            return ExitCode::FAILURE;
        }
        println!("version: {}", hostinfo::AGENT_VERSION);
        println!("engine: {}", wafio_engine_api::engine().info().name);
        return ExitCode::SUCCESS;
    }
    let res = match cli.command {
        Some(flags::Command::FetchData(f)) => fetch_data::run(&f),
        None => start(cli.agent),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wafio-waf-agent: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Startup up to exporting the engine environment, single-threaded; then the Tokio runtime.
fn start(mut f: flags::AgentArgs) -> Result<(), String> {
    stderr_log::init();
    // Keeps the keys of the served certificates out of core dumps and away from ptrace.
    #[cfg(target_os = "linux")]
    if let Err(e) = nix::sys::prctl::set_dumpable(false) {
        tracing::info!("[tls] WARNING: cannot keep key material out of core dumps: {e}");
    }
    for l in f.fill_from_env(&flags::OsEnv) {
        tracing::info!("{l}");
    }
    f.check_required()?;
    f.check_paths()?;
    f.resolved_acme_directory()?;
    let metrics_addr =
        std::env::var(wafio_agent_io::metrics::LISTEN_ADDRESS_ENV).unwrap_or_default();
    if !metrics_addr.is_empty() {
        wafio_agent_io::metrics::check_loopback_listen_address(&metrics_addr)
            .map_err(|e| format!("{}: {e}", wafio_agent_io::metrics::LISTEN_ADDRESS_ENV))?;
    }
    if let Some(w) = f.legacy_data_dir_warning() {
        tracing::info!("{w}");
    }
    let keys = match tls::dir::KeyDir::open_default() {
        Ok(dir) => Some(dir),
        Err(e) => {
            tracing::info!(
                "[tls] WARNING: this agent does not serve apps over HTTPS: key directory {e}"
            );
            None
        }
    };
    engine_lib::load_at_start(&f.engine_lib)?;
    for (k, v) in f.engine_env() {
        // SAFETY: no other thread exists yet (the runtime is built below); the engine crates
        // read these (bot lists, GeoIP) and an upgraded child inherits them.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(k, v);
        }
    }
    let rt = wafio_proxy::runtime_builder()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(run::run_waf_agent(f, metrics_addr, keys))
}
