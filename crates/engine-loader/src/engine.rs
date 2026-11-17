//! The library behind the [`Engine`] trait: loading, the calls, and what happens when one fails.
//!
//! A call that fails (a panic caught in the library, a result the agent cannot read) never reaches the rest of the agent
//! as anything but what an engine fault already is. A scan of a request unwinds to the `catch_unwind` of `analyze`, which
//! allows the request unanalysed and counts it; the other calls return what an engine that found nothing returns. Each
//! failure is counted, and logged when its count is a power of two.

use std::cell::RefCell;
use std::collections::HashSet;
use std::path::Path;
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use libloading::os::unix::{Library, RTLD_LOCAL, RTLD_NOW};
use wafio_domain::IncomingRequest;
use wafio_engine_abi::config::{self, Words};
use wafio_engine_abi::wire::{self, DecodeError};
use wafio_engine_abi::*;
use wafio_engine_api::{
    ALL_SEMANTIC_REASONS, BotSeeds as ApiBotSeeds, Engine, EngineCounters, EngineInfo,
    FrameCoverage, FrameField, NoEngine, ParamBaseline, ScanOutcome, ScanRequest, SemanticConfig,
    SemanticScanResult, SsrfConfig,
};

use crate::LibraryInfo;
use crate::config_cache::{self, Entry, Shared, SsrfHandle};
use crate::error::LoadError;
use crate::files::{self, Trust};

/// The bytes of the result buffer each thread offers the library: a result of no finding, and most findings, fit.
const SCRATCH_BYTES: usize = 4096;
const INIT_ERROR_BYTES: usize = 512;
/// How many reason texts outside the known list the loader keeps (each is leaked once).
const OTHER_REASONS: usize = 64;

#[derive(Clone, Copy)]
struct Symbols {
    ssrf_new: SsrfNewFn,
    ssrf_free: FreeHandleFn,
    config_new: ConfigNewFn,
    config_free: FreeHandleFn,
    baseline_new: BaselineNewFn,
    baseline_observe: BaselineObserveFn,
    baseline_free: FreeHandleFn,
    scan_request: ScanRequestFn,
    frame_fields: FrameFieldsFn,
    scan_value: ScanValueFn,
    graphql_batch: GraphqlBatchFn,
    guess_match_source: GuessMatchSourceFn,
    header_suspicious: HeaderSuspiciousFn,
    prepare_thread: PrepareThreadFn,
    counters: CountersFn,
    buffer_free: BufferFreeFn,
}

#[derive(Clone, Copy)]
enum Call {
    ScanRequest,
    FrameFields,
    ScanValue,
    Graphql,
    GuessMatchSource,
    HeaderSuspicious,
    Baseline,
    Counters,
}

const CALLS: usize = 8;

impl Call {
    fn name(self) -> &'static str {
        match self {
            Call::ScanRequest => "scan_request",
            Call::FrameFields => "frame_fields",
            Call::ScanValue => "scan_value",
            Call::Graphql => "graphql_batch_over_limit",
            Call::GuessMatchSource => "guess_match_source",
            Call::HeaderSuspicious => "header_value_looks_suspicious",
            Call::Baseline => "baseline",
            Call::Counters => "counters",
        }
    }
}

/// A library that was loaded and checked, as an engine. It lives until the process ends.
pub struct LoadedEngine {
    sym: Symbols,
    info: EngineInfo,
    seeds: ApiBotSeeds,
    shared: Shared,
    faults: AtomicU64,
    by_call: [AtomicU64; CALLS],
    _library: Library,
}

thread_local! {
    static OUT: RefCell<Box<[u8; SCRATCH_BYTES]>> = RefCell::new(Box::new([0; SCRATCH_BYTES]));
    static HEADERS: RefCell<Vec<Header>> = const { RefCell::new(Vec::new()) };
}

/// The buffer of a result, freed through the library when the library allocated it.
struct OutGuard {
    buf: OutBuf,
    free: BufferFreeFn,
}

impl Drop for OutGuard {
    fn drop(&mut self) {
        if self.buf.owned != 0 {
            // SAFETY: `owned` says the library allocated `buf`, and it is freed once, here, by the library that made it.
            unsafe { (self.free)(&mut self.buf) }
        }
    }
}

fn describe(status: i32) -> String {
    match status {
        status::PANIC => "a panic was caught inside the library".into(),
        status::BAD_ARGUMENT => "the library did not accept its arguments".into(),
        status::FAILED => "the library reported a failure".into(),
        other => format!("the library returned status {other}"),
    }
}

fn fill_request(req: &IncomingRequest, headers: &mut Vec<Header>) -> Request {
    headers.clear();
    for (name, values) in &req.headers {
        for value in values {
            headers.push(Header {
                name: Slice::of(name),
                value: Slice::of(value),
            });
        }
    }
    Request {
        method: Slice::of(&req.method),
        uri: Slice::of(&req.uri),
        content_type: Slice::of(&req.content_type),
        body: Slice::of(&req.body),
        body_scan_skipped: Slice::of(req.body_scan_skipped.as_bytes()),
        headers: headers.as_ptr(),
        header_count: headers.len(),
    }
}

/// The reason texts as `&'static str`: the known ones, then a few others kept once.
fn static_reason(text: &str) -> &'static str {
    if text.is_empty() {
        return "";
    }
    if let Some(known) = ALL_SEMANTIC_REASONS.iter().find(|r| **r == text) {
        return known;
    }
    static OTHER: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let mut set = OTHER
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(have) = set.get(text) {
        return have;
    }
    if set.len() >= OTHER_REASONS {
        return "SEMANTIC_UNKNOWN";
    }
    let leaked: &'static str = text.to_string().leak();
    set.insert(leaked);
    leaked
}

impl LoadedEngine {
    fn note(&self, call: Call, what: &str) {
        self.faults.fetch_add(1, Ordering::Relaxed);
        let n = self.by_call[call as usize].fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_power_of_two() {
            tracing::error!(
                "engine library: {} failed ({what}); {n} time(s) so far",
                call.name()
            );
        }
    }

    /// A failed scan of a request: counted, then raised as the panic that `analyze` already recovers from.
    fn fail_request(&self, what: &str) -> ! {
        self.faults.fetch_add(1, Ordering::Relaxed);
        self.by_call[Call::ScanRequest as usize].fetch_add(1, Ordering::Relaxed);
        std::panic::resume_unwind(Box::new(format!(
            "engine library: scan_request failed ({what})"
        )))
    }

    /// Runs a call that fills a result buffer and hands `decode` the bytes it wrote.
    fn call_out<T>(
        &self,
        call: impl FnOnce(*mut OutBuf) -> i32,
        decode: impl FnOnce(&[u8]) -> Result<T, DecodeError>,
    ) -> Result<T, String> {
        OUT.with(|cell| {
            let mut scratch = cell.borrow_mut();
            let mut out = OutBuf::over(&mut scratch[..]);
            let (ptr, cap) = (out.ptr, out.cap);
            let status = call(&mut out);
            let guard = OutGuard {
                buf: out,
                free: self.sym.buffer_free,
            };
            if status != status::OK {
                return Err(describe(status));
            }
            let b = &guard.buf;
            if b.owned == 0 && (b.ptr != ptr || b.cap != cap) {
                return Err("the library replaced the buffer without owning it".into());
            }
            if b.len > b.cap || (b.ptr.is_null() && b.len > 0) {
                return Err("the library reported more bytes than its buffer holds".into());
            }
            let bytes = if b.len == 0 {
                &[][..]
            } else {
                // SAFETY: `ptr` is the buffer this thread offered or one the library owns until the guard frees it, and
                // `len <= cap` was checked above; nothing writes to it while `bytes` lives.
                unsafe { slice::from_raw_parts(b.ptr, b.len) }
            };
            decode(bytes).map_err(|e| e.to_string())
        })
    }

    fn ssrf_handle(&self, list: &Arc<SsrfConfig>) -> Result<Arc<SsrfHandle>, String> {
        let key = Arc::as_ptr(list) as usize;
        if let Some(have) = self.shared.ssrf(key) {
            return Ok(have);
        }
        // An empty blob stands for a list with no extra hosts at all; a list always encodes to eight bytes or more.
        let blob = list
            .blocklist
            .as_deref()
            .map(wire::encode_ssrf)
            .unwrap_or_default();
        let mut handle = 0u64;
        // SAFETY: `blob` is live for the call and `handle` is a place for one u64.
        let status = unsafe { (self.sym.ssrf_new)(blob.as_ptr(), blob.len(), &mut handle) };
        if status != status::OK || handle == 0 {
            return Err(format!("ssrf_new: {}", describe(status)));
        }
        Ok(self.shared.insert_ssrf(
            key,
            Arc::new(SsrfHandle {
                handle,
                free: self.sym.ssrf_free,
                _keep: list.clone(),
            }),
        ))
    }

    fn create_entry(&self, c: &SemanticConfig, row: &Words) -> Result<Entry, String> {
        let ssrf = c
            .ssrf_config
            .as_ref()
            .map(|l| self.ssrf_handle(l))
            .transpose()?;
        let mut out = ConfigOut::default();
        // SAFETY: `row` holds `row.len()` words and `c.field_name` its length in bytes, both live for the call; `out` is
        // a place for one `ConfigOut`.
        let status = unsafe {
            (self.sym.config_new)(
                row.as_ptr(),
                row.len(),
                c.field_name.as_ptr(),
                c.field_name.len(),
                ssrf.as_ref().map_or(0, |s| s.handle),
                &mut out,
            )
        };
        if status != status::OK || out.handle == 0 {
            return Err(format!("config_new: {}", describe(status)));
        }
        Ok(Entry::new(out.handle, self.sym.config_free, ssrf))
    }

    fn shared_entry(&self, row: &Words, c: &SemanticConfig) -> Result<Arc<Entry>, String> {
        if let Some(have) = self.shared.get(row) {
            return Ok(have);
        }
        let made = Arc::new(self.create_entry(c, row)?);
        Ok(self.shared.insert(*row, made))
    }

    /// Runs `f` with the handle of the library's copy of `c`, handing the configuration over first when the library has
    /// not got it.
    fn with_config<R>(&self, c: &SemanticConfig, f: impl FnOnce(&Entry) -> R) -> Result<R, String> {
        let list = c
            .ssrf_config
            .as_ref()
            .map_or(0, |l| Arc::as_ptr(l) as usize as u64);
        let row = config::encode(c, list);
        if !c.field_name.is_empty() {
            // Not part of the row, never repeated in practice: handed over for this call only.
            return Ok(f(&self.create_entry(c, &row)?));
        }
        config_cache::with_local(
            std::ptr::from_ref(self) as usize,
            &row,
            || self.shared_entry(&row, c),
            f,
        )
    }

    fn flag_call(&self, call: Call, run: impl FnOnce(*mut u8) -> i32) -> bool {
        let mut flag = 0u8;
        let status = run(&mut flag);
        if status != status::OK {
            self.note(call, &describe(status));
            return false;
        }
        flag != 0
    }
}

impl Engine for LoadedEngine {
    fn info(&self) -> EngineInfo {
        self.info
    }

    fn scan_request(&self, scan: &ScanRequest<'_>) -> ScanOutcome {
        let baseline = scan
            .track_params
            .and_then(|p| p.as_any())
            .and_then(|a| a.downcast_ref::<LoaderBaseline>())
            .map_or(0, |b| b.handle);
        let mut flags = 0;
        for (on, bit) in [
            (scan.scan_all_headers, SCAN_ALL_HEADERS),
            (scan.regex_incomplete, SCAN_REGEX_INCOMPLETE),
            (scan.run_scan, SCAN_RUN),
        ] {
            if on {
                flags |= bit;
            }
        }
        let result = self.with_config(scan.config, |cfg| {
            HEADERS.with(|cell| {
                let mut headers = cell.borrow_mut();
                let request = fill_request(scan.request, &mut headers);
                let args = ScanArgs {
                    config: cfg.handle,
                    baseline,
                    request,
                    normalized_input: Slice::of(scan.normalized_input),
                    forwarded_path: Slice::of(scan.forwarded_path),
                    project_id: Slice::of(scan.project_id),
                    flags,
                    reserved: 0,
                };
                let out = self.call_out(
                    // SAFETY: `args` and everything it points to (the request, the headers, the slices) outlive the call,
                    // which keeps none of them; `o` is the buffer `call_out` made.
                    |o| unsafe { (self.sym.scan_request)(&args, o) },
                    wire::decode_outcome,
                );
                headers.clear();
                out
            })
        });
        match result {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(why)) | Err(why) => self.fail_request(&why),
        }
    }

    fn frame_fields(&self, payload: &[u8]) -> (Vec<FrameField>, FrameCoverage) {
        self.call_out(
            // SAFETY: `payload` outlives the call, which keeps nothing.
            |o| unsafe { (self.sym.frame_fields)(payload.as_ptr(), payload.len(), o) },
            wire::decode_frame_fields,
        )
        .unwrap_or_else(|why| {
            self.note(Call::FrameFields, &why);
            (
                Vec::new(),
                FrameCoverage {
                    skipped: "engine_fault".into(),
                    ..Default::default()
                },
            )
        })
    }

    fn scan_value(&self, value: &[u8], config: &SemanticConfig) -> SemanticScanResult {
        let result = self.with_config(config, |cfg| {
            self.call_out(
                // SAFETY: `value` outlives the call, which keeps nothing; `cfg.handle` is held by `cfg`.
                |o| unsafe { (self.sym.scan_value)(cfg.handle, value.as_ptr(), value.len(), o) },
                |bytes| wire::decode_scan_value(bytes, static_reason),
            )
        });
        match result {
            Ok(Ok(r)) => r,
            Ok(Err(why)) | Err(why) => {
                self.note(Call::ScanValue, &why);
                SemanticScanResult {
                    engine_panicked: true,
                    ..Default::default()
                }
            }
        }
    }

    fn graphql_batch_over_limit(&self, body: &[u8], max_batch: i64) -> bool {
        self.flag_call(Call::Graphql, |flag| {
            // SAFETY: `body` outlives the call and `flag` is a place for one byte.
            unsafe { (self.sym.graphql_batch)(body.as_ptr(), body.len(), max_batch, flag) }
        })
    }

    fn guess_match_source(&self, request: &IncomingRequest) -> Vec<u8> {
        HEADERS
            .with(|cell| {
                let mut headers = cell.borrow_mut();
                let req = fill_request(request, &mut headers);
                let out = self.call_out(
                    // SAFETY: `req` and the headers it points to outlive the call, which keeps none of them.
                    |o| unsafe { (self.sym.guess_match_source)(&req, o) },
                    |bytes| Ok(bytes.to_vec()),
                );
                headers.clear();
                out
            })
            .unwrap_or_else(|why| {
                self.note(Call::GuessMatchSource, &why);
                Vec::new()
            })
    }

    fn header_value_looks_suspicious(&self, value: &[u8]) -> bool {
        self.flag_call(Call::HeaderSuspicious, |flag| {
            // SAFETY: `value` outlives the call and `flag` is a place for one byte.
            unsafe { (self.sym.header_suspicious)(value.as_ptr(), value.len(), flag) }
        })
    }

    fn prepare_thread(&self, stack_budget_bytes: usize) {
        // SAFETY: the call takes a number and touches only the calling thread's state in the library.
        let status = unsafe { (self.sym.prepare_thread)(stack_budget_bytes as u64) };
        if status != status::OK {
            tracing::error!(
                "engine library: prepare_thread failed: {}",
                describe(status)
            );
        }
    }

    fn counters(&self) -> EngineCounters {
        let mut c = Counters::default();
        // SAFETY: `c` is a place for one `Counters`.
        let status = unsafe { (self.sym.counters)(&mut c) };
        if status != status::OK {
            self.note(Call::Counters, &describe(status));
        }
        EngineCounters {
            recovered_panics: c.recovered_panics + self.faults.load(Ordering::Relaxed),
            exhausted_parse_budgets: c.exhausted_parse_budgets,
        }
    }

    fn bot_seeds(&self) -> ApiBotSeeds {
        self.seeds
    }

    fn new_param_baseline(&self) -> Arc<dyn ParamBaseline> {
        let mut handle = 0u64;
        // SAFETY: `handle` is a place for one u64.
        let status = unsafe { (self.sym.baseline_new)(&mut handle) };
        if status != status::OK || handle == 0 {
            self.note(Call::Baseline, &describe(status));
            return NoEngine.new_param_baseline();
        }
        Arc::new(LoaderBaseline {
            handle,
            observe: self.sym.baseline_observe,
            free: self.sym.baseline_free,
        })
    }
}

/// A baseline of query parameter names that lives in the library.
struct LoaderBaseline {
    handle: u64,
    observe: BaselineObserveFn,
    free: FreeHandleFn,
}

impl ParamBaseline for LoaderBaseline {
    fn observe(&self, project_id: &[u8], param: &[u8]) -> bool {
        let mut is_new = 0u8;
        // SAFETY: both byte strings outlive the call, which keeps neither; `is_new` is a place for one byte; `handle` is
        // freed only when this struct drops.
        let status = unsafe {
            (self.observe)(
                self.handle,
                project_id.as_ptr(),
                project_id.len(),
                param.as_ptr(),
                param.len(),
                &mut is_new,
            )
        };
        status == status::OK && is_new != 0
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

impl Drop for LoaderBaseline {
    fn drop(&mut self) {
        // SAFETY: `handle` came from `wafio_engine_baseline_new` of this library and is freed once, here.
        unsafe { (self.free)(self.handle) }
    }
}

/// The library's way into the log of the agent.
unsafe extern "C" fn host_log(level: u32, msg: *const u8, len: usize) {
    // A panic must not unwind into the library.
    let _ = std::panic::catch_unwind(|| {
        let bytes = if msg.is_null() || len == 0 {
            &[][..]
        } else {
            // SAFETY: the library passes a message that is valid for `len` bytes during this call.
            unsafe { slice::from_raw_parts(msg, len) }
        };
        let text = String::from_utf8_lossy(bytes);
        match level {
            level::ERROR => tracing::error!("{text}"),
            level::WARN => tracing::warn!("{text}"),
            level::INFO => tracing::info!("{text}"),
            _ => tracing::debug!("{text}"),
        }
    });
}

/// A static string of the library, copied and leaked once.
fn leak_text(s: Slice, what: &str) -> Result<&'static str, LoadError> {
    if s.len == 0 {
        return Ok("");
    }
    if s.ptr.is_null() {
        return Err(LoadError::BadIdentity(format!("{what} is null")));
    }
    // SAFETY: the library promises static strings that stay valid until the process ends; the length is the library's own.
    let bytes = unsafe { slice::from_raw_parts(s.ptr, s.len) };
    let text = std::str::from_utf8(bytes)
        .map_err(|_| LoadError::BadIdentity(format!("{what} is not UTF-8")))?;
    Ok(text.to_string().leak())
}

fn seeds_of(raw: &BotSeeds) -> Result<ApiBotSeeds, LoadError> {
    let list =
        |ptr: *const Slice, len: usize, what: &str| -> Result<&'static [&'static str], LoadError> {
            if len == 0 {
                return Ok(&[]);
            }
            if ptr.is_null() {
                return Err(LoadError::BadIdentity(format!("{what} is null")));
            }
            // SAFETY: the library promises an array of `len` slices in static memory.
            let items = unsafe { slice::from_raw_parts(ptr, len) };
            let texts: Vec<&'static str> = items
                .iter()
                .map(|s| leak_text(*s, what))
                .collect::<Result<_, _>>()?;
            Ok(Vec::leak(texts))
        };
    Ok(ApiBotSeeds {
        ja4_block: list(raw.ja4_block, raw.ja4_block_len, "the JA4 block list")?,
        ja4_allow: list(raw.ja4_allow, raw.ja4_allow_len, "the JA4 allow list")?,
    })
}

pub(crate) fn load(
    path: &Path,
    trust: Trust,
) -> Result<(&'static LoadedEngine, LibraryInfo), LoadError> {
    let verified = files::verify(path, trust)?;
    let shown = verified.path.clone();
    // SAFETY: the file passed the owner, mode and checksum checks and is opened through the descriptor that was checked.
    // Loading runs the constructors of the library: that is the code execution the checks are for.
    let library = unsafe {
        Library::open(
            Some(verified.load_path()),
            RTLD_NOW | RTLD_LOCAL | libc::RTLD_NODELETE,
        )
    }
    .map_err(|e| LoadError::Open {
        path: shown.clone(),
        reason: e.to_string(),
    })?;
    // The descriptor stays open for the life of the process. The dynamic loader takes two loads of one name for one library,
    // and the name here is /proc/self/fd/N: a closed descriptor would hand its number, and so a second library, the first
    // library's handle.
    let _kept_open = std::os::fd::IntoRawFd::into_raw_fd(verified.file);

    // The first call. Nothing else is looked up before the version is known.
    // SAFETY: `VersionFn` is the signature of this symbol in the interface; the copy of the pointer is used while the
    // library, which is never unloaded, is mapped.
    let version: VersionFn = unsafe {
        *library
            .get::<VersionFn>(symbols::VERSION)
            .map_err(|_| LoadError::MissingSymbol("wafio_engine_interface_version"))?
    };
    // SAFETY: the call takes no arguments.
    let found = unsafe { version() };
    if found != INTERFACE_VERSION {
        return Err(LoadError::VersionMismatch {
            path: shown,
            found,
            wanted: INTERFACE_VERSION,
        });
    }

    macro_rules! symbol {
        ($ty:ty, $name:expr) => {
            // SAFETY: the type is the signature this symbol has in the interface of this version.
            unsafe {
                *library.get::<$ty>($name).map_err(|_| {
                    LoadError::MissingSymbol(
                        std::str::from_utf8(&$name[..$name.len() - 1]).unwrap_or("?"),
                    )
                })?
            }
        };
    }
    let identity: IdentityFn = symbol!(IdentityFn, symbols::IDENTITY);
    let init: InitFn = symbol!(InitFn, symbols::INIT);
    let bot_seeds: BotSeedsFn = symbol!(BotSeedsFn, symbols::BOT_SEEDS);
    let sym = Symbols {
        ssrf_new: symbol!(SsrfNewFn, symbols::SSRF_NEW),
        ssrf_free: symbol!(FreeHandleFn, symbols::SSRF_FREE),
        config_new: symbol!(ConfigNewFn, symbols::CONFIG_NEW),
        config_free: symbol!(FreeHandleFn, symbols::CONFIG_FREE),
        baseline_new: symbol!(BaselineNewFn, symbols::BASELINE_NEW),
        baseline_observe: symbol!(BaselineObserveFn, symbols::BASELINE_OBSERVE),
        baseline_free: symbol!(FreeHandleFn, symbols::BASELINE_FREE),
        scan_request: symbol!(ScanRequestFn, symbols::SCAN_REQUEST),
        frame_fields: symbol!(FrameFieldsFn, symbols::FRAME_FIELDS),
        scan_value: symbol!(ScanValueFn, symbols::SCAN_VALUE),
        graphql_batch: symbol!(GraphqlBatchFn, symbols::GRAPHQL_BATCH),
        guess_match_source: symbol!(GuessMatchSourceFn, symbols::GUESS_MATCH_SOURCE),
        header_suspicious: symbol!(HeaderSuspiciousFn, symbols::HEADER_SUSPICIOUS),
        prepare_thread: symbol!(PrepareThreadFn, symbols::PREPARE_THREAD),
        counters: symbol!(CountersFn, symbols::COUNTERS),
        buffer_free: symbol!(BufferFreeFn, symbols::BUFFER_FREE),
    };

    let mut id = Identity {
        name: Slice::EMPTY,
        version: Slice::EMPTY,
        api_revision: Slice::EMPTY,
    };
    // SAFETY: `id` is a place for one `Identity`.
    let status = unsafe { identity(&mut id) };
    if status != status::OK {
        return Err(LoadError::BadIdentity(describe(status)));
    }
    let name = leak_text(id.name, "the engine name")?;
    if name.is_empty() {
        return Err(LoadError::BadIdentity("the engine name is empty".into()));
    }
    let engine_version = leak_text(id.version, "the version")?;
    let api_revision = leak_text(id.api_revision, "the engine-api revision")?;

    let host = HostApi {
        log: Some(host_log),
    };
    let mut err = [0u8; INIT_ERROR_BYTES];
    let mut err_len = 0usize;
    // SAFETY: `host` is live for the call and read during it only; `err` has `err.len()` bytes and `err_len` is a place
    // for one usize.
    let status = unsafe { init(&host, err.as_mut_ptr(), err.len(), &mut err_len) };
    if status != status::OK {
        let text = String::from_utf8_lossy(&err[..err_len.min(err.len())]).into_owned();
        return Err(LoadError::InitFailed(if text.is_empty() {
            describe(status)
        } else {
            text
        }));
    }

    let mut raw_seeds = BotSeeds {
        ja4_block: std::ptr::null(),
        ja4_block_len: 0,
        ja4_allow: std::ptr::null(),
        ja4_allow_len: 0,
    };
    // SAFETY: `raw_seeds` is a place for one `BotSeeds`.
    let status = unsafe { bot_seeds(&mut raw_seeds) };
    if status != status::OK {
        return Err(LoadError::BadIdentity(format!(
            "bot seeds: {}",
            describe(status)
        )));
    }
    let seeds = seeds_of(&raw_seeds)?;

    let engine: &'static LoadedEngine = Box::leak(Box::new(LoadedEngine {
        sym,
        info: EngineInfo {
            installed: true,
            name,
        },
        seeds,
        shared: Shared::default(),
        faults: AtomicU64::new(0),
        by_call: Default::default(),
        _library: library,
    }));
    Ok((
        engine,
        LibraryInfo {
            path: shown,
            name,
            version: engine_version,
            api_revision,
            interface_version: found,
        },
    ))
}
