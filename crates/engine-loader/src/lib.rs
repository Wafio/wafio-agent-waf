//! Loads a semantic engine from a shared library and presents it to the agent as an [`Engine`].
//!
//! This is the only crate of the agent that crosses the C interface of `wafio-engine-abi`, and so the only one that
//! holds `unsafe` for it. Every `unsafe` block says in one line why it holds. Everything the agent sees stays safe
//! Rust: [`install`] checks the file ([`files`]), loads it, checks the interface version, and installs a
//! [`LoadedEngine`] as the engine of the process.
//!
//! A library is never half loaded: any failure before the end of [`load`] leaves the process with the engine it had.
//! The library stays loaded until the process ends.

// A static musl agent cannot load a library (see `load`); the code stays in the build so that it is checked there too.
#![cfg_attr(target_env = "musl", allow(dead_code))]
#![deny(clippy::undocumented_unsafe_blocks)]

mod config_cache;
mod engine;
mod error;
pub mod files;

pub use engine::LoadedEngine;
pub use error::LoadError;
pub use files::Trust;

use std::path::{Path, PathBuf};

use wafio_engine_abi::INTERFACE_VERSION;

/// Where the installer puts the library.
pub const DEFAULT_LIBRARY_PATH: &str = "/usr/lib/wafio/libwafio_semantic_engine.so";

/// Whether this build can load a library at all. A static musl agent cannot.
pub const CAN_LOAD: bool = cfg!(not(target_env = "musl"));

/// What a loaded library says about itself.
#[derive(Clone, Debug)]
pub struct LibraryInfo {
    pub path: PathBuf,
    pub name: &'static str,
    pub version: &'static str,
    pub api_revision: &'static str,
    pub interface_version: u32,
}

/// Checks and loads the library at `path`, and returns the engine it holds. The engine lives for the rest of the process.
#[cfg(not(target_env = "musl"))]
pub fn load(path: &Path, trust: Trust) -> Result<(&'static LoadedEngine, LibraryInfo), LoadError> {
    engine::load(path, trust)
}

#[cfg(target_env = "musl")]
pub fn load(
    _path: &Path,
    _trust: Trust,
) -> Result<(&'static LoadedEngine, LibraryInfo), LoadError> {
    Err(LoadError::Unsupported(
        "a static musl agent cannot load a shared library; use the glibc build or the official agent with the engine linked in",
    ))
}

/// Loads the library and installs it as the engine of the process. When an engine is installed already the library
/// stays unused, and a warning says so.
pub fn install(path: &Path, trust: Trust) -> Result<LibraryInfo, LoadError> {
    let (engine, info) = load(path, trust)?;
    if !wafio_engine_api::install(engine) {
        tracing::warn!(
            "an engine was installed before {}: the library is not used",
            path.display()
        );
    }
    Ok(info)
}

/// The version of the interface this agent speaks.
pub const fn interface_version() -> u32 {
    INTERFACE_VERSION
}
