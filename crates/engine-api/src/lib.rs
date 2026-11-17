//! The boundary between the agent and the semantic detection engines.
//!
//! This crate holds what both sides must agree on: the scan configuration, the names of the findings, the
//! coverage marks and the [`Engine`] trait. The agent calls [`engine()`] and nothing else; it is the
//! no-detection engine until a binary [`install`]s another one. The engines themselves live elsewhere.

#![forbid(unsafe_code)]

pub mod config;
pub mod coverage;
pub mod engine;
pub mod engine_set;
pub mod policy;
pub mod reason;
pub mod ssrf_config;
pub mod taxonomy;
pub mod tier;

pub use config::*;
pub use coverage::ScanCoverage;
pub use engine::{
    BotSeeds, Engine, EngineCounters, EngineInfo, FrameCoverage, FrameField, Held, NoEngine,
    ParamBaseline, ScanOutcome, ScanRequest, engine, install,
};
pub use engine_set::*;
pub use policy::*;
pub use reason::*;
pub use ssrf_config::*;
pub use taxonomy::*;
pub use tier::*;
