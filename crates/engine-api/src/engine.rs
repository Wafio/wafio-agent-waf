//! The [`Engine`] trait, the engine that detects nothing, and the one place that holds the installed engine.

use std::sync::{Arc, OnceLock};

use wafio_domain::IncomingRequest;

use crate::config::{SemanticConfig, SemanticScanResult};
use crate::coverage::ScanCoverage;
use crate::tier::Tier;

/// What an engine says about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineInfo {
    /// False for [`NoEngine`].
    pub installed: bool,
    /// A stable name: `none` or the name of the installed engine.
    pub name: &'static str,
}

/// Counters the engine keeps for the heartbeat and the metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EngineCounters {
    /// Panics recovered inside a scan.
    pub recovered_panics: u64,
    /// Scans that skipped relaxed-parse variants because the work budget ran out.
    pub exhausted_parse_budgets: u64,
}

/// The JA4 fingerprints an engine ships. The operator's files and the rules document come on top; without
/// any of them the bot check uses these.
#[derive(Clone, Copy, Debug, Default)]
pub struct BotSeeds {
    pub ja4_block: &'static [&'static str],
    pub ja4_allow: &'static [&'static str],
}

/// A per-project baseline of the query parameter names a project has used. An agent keeps one per application.
pub trait ParamBaseline: Send + Sync {
    /// Records `param` for the project and reports whether it is new after the baseline has warmed up.
    fn observe(&self, project_id: &[u8], param: &[u8]) -> bool;

    /// The baseline as `Any`, for an engine that must recognise a baseline of its own among the ones the agent
    /// hands back (a baseline that lives behind a library boundary). Most baselines leave it at `None`.
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }
}

/// The baseline of an agent without an engine: nothing is ever new.
struct NoBaseline;

impl ParamBaseline for NoBaseline {
    fn observe(&self, _project_id: &[u8], _param: &[u8]) -> bool {
        false
    }
}

/// One value of a WebSocket frame that an engine decided to scan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameField {
    pub value: Vec<u8>,
    /// Where in the frame the value sat (`body.json:name`, `body`).
    pub source: Vec<u8>,
    /// A summary of the whole document: outside the per-message field budget.
    pub summary: bool,
}

/// How completely a frame was turned into fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameCoverage {
    /// An extraction limit dropped content.
    pub field_capped: bool,
    /// Non-empty when a frame was present but not read (`binary`).
    pub skipped: String,
    /// The payload met binary framing and the text runs were taken.
    pub binary_text: bool,
}

/// One request handed to [`Engine::scan_request`].
pub struct ScanRequest<'a> {
    pub request: &'a IncomingRequest,
    /// The scan configuration with the project policy, the path override and the tuning skips applied.
    pub config: &'a SemanticConfig,
    /// The URL-decoded request target.
    pub normalized_input: &'a [u8],
    /// The path as the route sees it, after the proxy's rewrite.
    pub forwarded_path: &'a [u8],
    pub project_id: &'a [u8],
    /// Every non-structural header is scanned, not only the legacy set.
    pub scan_all_headers: bool,
    /// Regex conditions of the custom rules ran out of budget, so the verdict is incomplete anyway.
    pub regex_incomplete: bool,
    /// False when a tuning rule skips the engines: nothing is scanned, the baselines still learn.
    pub run_scan: bool,
    /// The baseline of query parameter names to keep, if any.
    pub track_params: Option<&'a dyn ParamBaseline>,
}

/// A strong finding that a log-only engine held back from the verdict.
#[derive(Clone, Debug, Default)]
pub struct Held {
    pub reason: String,
    pub detail: Vec<u8>,
    pub source: Vec<u8>,
    pub source_exact: bool,
    pub value: Vec<u8>,
}

/// What an engine found in one request: the strongest finding, where it sat, and what the scan did not cover.
#[derive(Clone, Debug, Default)]
pub struct ScanOutcome {
    pub tier: Tier,
    pub reason: String,
    pub detail: Vec<u8>,
    /// Where the finding sat (`query:id`, `header:Referer`, `body.json:name`, `path`), and whether that is exact.
    pub source: Vec<u8>,
    pub source_exact: bool,
    /// The decoded value of the part that held it.
    pub value: Vec<u8>,
    pub coverage: ScanCoverage,
    /// The detection of a log-only engine that would have blocked; `tier` and the rest then hold what the
    /// other engines found.
    pub held: Option<Held>,
}

/// The semantic detection the agent asks for. An engine is stateless towards the agent: the same request and
/// configuration give the same answer, apart from the baselines it keeps.
pub trait Engine: Send + Sync {
    fn info(&self) -> EngineInfo;

    /// The semantic stage of one request: the address, the headers, the query and the body.
    fn scan_request(&self, scan: &ScanRequest<'_>) -> ScanOutcome;

    /// The values of a WebSocket frame's payload that are worth a scan, with what the extraction left out.
    fn frame_fields(&self, payload: &[u8]) -> (Vec<FrameField>, FrameCoverage);

    /// One value, for the frames of a WebSocket.
    fn scan_value(&self, value: &[u8], config: &SemanticConfig) -> SemanticScanResult;

    /// Whether a GraphQL body holds more operations than `max_batch` (0 = the default limit).
    fn graphql_batch_over_limit(&self, body: &[u8], max_batch: i64) -> bool;

    /// Where in the request a non-blocking decision most likely points (`header:Referer`, `body`,
    /// `query:name`, `path`, or empty).
    fn guess_match_source(&self, request: &IncomingRequest) -> Vec<u8>;

    /// Whether a header value holds text that looks like an attack, for the snippets of a decision event.
    fn header_value_looks_suspicious(&self, value: &[u8]) -> bool;

    /// Gives the calling thread the stack budget the engines may recurse into.
    fn prepare_thread(&self, stack_budget_bytes: usize);

    fn counters(&self) -> EngineCounters;

    fn bot_seeds(&self) -> BotSeeds;

    /// A new, empty baseline of query parameter names.
    fn new_param_baseline(&self) -> Arc<dyn ParamBaseline>;
}

/// The engine of a build without detection: every scan finds nothing and says so in its coverage.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoEngine;

impl Engine for NoEngine {
    fn info(&self) -> EngineInfo {
        EngineInfo {
            installed: false,
            name: "none",
        }
    }

    fn scan_request(&self, _scan: &ScanRequest<'_>) -> ScanOutcome {
        ScanOutcome {
            coverage: ScanCoverage {
                engine_absent: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn frame_fields(&self, _payload: &[u8]) -> (Vec<FrameField>, FrameCoverage) {
        (Vec::new(), FrameCoverage::default())
    }

    fn scan_value(&self, _value: &[u8], _config: &SemanticConfig) -> SemanticScanResult {
        SemanticScanResult::default()
    }

    fn graphql_batch_over_limit(&self, _body: &[u8], _max_batch: i64) -> bool {
        false
    }

    fn guess_match_source(&self, _request: &IncomingRequest) -> Vec<u8> {
        Vec::new()
    }

    fn header_value_looks_suspicious(&self, _value: &[u8]) -> bool {
        false
    }

    fn prepare_thread(&self, _stack_budget_bytes: usize) {}

    fn counters(&self) -> EngineCounters {
        EngineCounters::default()
    }

    fn bot_seeds(&self) -> BotSeeds {
        BotSeeds::default()
    }

    fn new_param_baseline(&self) -> Arc<dyn ParamBaseline> {
        Arc::new(NoBaseline)
    }
}

static INSTALLED: OnceLock<&'static dyn Engine> = OnceLock::new();

/// Installs the engine of this process. Only the first call counts; it returns whether this one did. Call it
/// before the agent starts, because the answer of [`engine`] is read on every request.
pub fn install(engine: &'static dyn Engine) -> bool {
    INSTALLED.set(engine).is_ok()
}

/// The installed engine, or [`NoEngine`].
pub fn engine() -> &'static dyn Engine {
    INSTALLED.get().copied().unwrap_or(&NoEngine)
}
