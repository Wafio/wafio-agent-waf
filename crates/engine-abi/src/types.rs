//! The `#[repr(C)]` structs, the function signatures and the symbol names of the interface. `include/wafio_engine.h`
//! says the same in C; the sizes asserted at the end of this file are asserted there too.
//!
//! The interface is defined for 64-bit little-endian targets (x86_64 and aarch64 Linux). Pointers and lengths are
//! 8 bytes wide.

use std::ptr;

const _: () = assert!(
    size_of::<usize>() == 8,
    "the interface is defined for 64-bit targets"
);
const _: () = assert!(
    cfg!(target_endian = "little"),
    "the encodings are little-endian"
);

/// A borrowed run of bytes. `ptr` may be null when `len` is 0. The memory belongs to whoever passed the slice and
/// is read only for the duration of the call.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Slice {
    pub ptr: *const u8,
    pub len: usize,
}

impl Slice {
    pub const EMPTY: Slice = Slice {
        ptr: ptr::null(),
        len: 0,
    };

    pub fn of(bytes: &[u8]) -> Slice {
        Slice {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }
}

/// One header value of a request. A name with several values appears once per value, in arrival order.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub name: Slice,
    pub value: Slice,
}

/// The parts of a request an engine reads. The headers are `header_count` entries of [`Header`], sorted by the bytes
/// of the name, with the values of one name next to each other.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Request {
    pub method: Slice,
    /// The raw request target, path and query.
    pub uri: Slice,
    pub content_type: Slice,
    pub body: Slice,
    /// UTF-8; empty when the transport handed over the whole body.
    pub body_scan_skipped: Slice,
    pub headers: *const Header,
    pub header_count: usize,
}

/// [`ScanArgs::flags`]: every non-structural header is scanned.
pub const SCAN_ALL_HEADERS: u32 = 1;
/// [`ScanArgs::flags`]: the regex conditions of the custom rules ran out of budget.
pub const SCAN_REGEX_INCOMPLETE: u32 = 1 << 1;
/// [`ScanArgs::flags`]: scan the request; clear when a tuning rule skips the engines (the baselines still learn).
pub const SCAN_RUN: u32 = 1 << 2;
/// Every flag bit a library of this interface version knows.
pub const SCAN_FLAGS_MASK: u32 = 0x7;

/// The argument of `wafio_engine_scan_request`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ScanArgs {
    /// A handle from `wafio_engine_config_new`.
    pub config: u64,
    /// A handle from `wafio_engine_baseline_new`, or 0 for none.
    pub baseline: u64,
    pub request: Request,
    /// The URL-decoded request target.
    pub normalized_input: Slice,
    /// The path as the route sees it.
    pub forwarded_path: Slice,
    pub project_id: Slice,
    pub flags: u32,
    pub reserved: u32,
}

/// A buffer the library writes a result into. The caller sets `ptr` and `cap` to memory it owns (or both to 0),
/// and `len` and `owned` to 0. When the result fits, the library writes it there and sets `len`. When it does not,
/// the library allocates, points `ptr` at its own memory, sets `cap`, `len` and `owned` to non-zero, and the caller
/// must hand the struct to `wafio_engine_buffer_free` after reading the bytes. The library never keeps the pointer.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OutBuf {
    pub ptr: *mut u8,
    pub cap: usize,
    pub len: usize,
    pub owned: u32,
    pub reserved: u32,
}

impl OutBuf {
    /// A buffer over `scratch`, empty.
    pub fn over(scratch: &mut [u8]) -> OutBuf {
        OutBuf {
            ptr: scratch.as_mut_ptr(),
            cap: scratch.len(),
            len: 0,
            owned: 0,
            reserved: 0,
        }
    }
}

/// What a library says about itself. The strings are static in the library and valid until the process ends.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    /// The engine name, `wafio-semantic-engine` for the official one.
    pub name: Slice,
    /// The build version of the library.
    pub version: Slice,
    /// The revision of the `wafio-engine-api` crate the library was built against.
    pub api_revision: Slice,
}

/// Counters the library keeps for the heartbeat and the metrics.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub recovered_panics: u64,
    pub exhausted_parse_budgets: u64,
}

/// The JA4 fingerprints a library ships: two arrays of [`Slice`] in static memory of the library.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BotSeeds {
    pub ja4_block: *const Slice,
    pub ja4_block_len: usize,
    pub ja4_allow: *const Slice,
    pub ja4_allow_len: usize,
}

/// The result of `wafio_engine_config_new`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfigOut {
    pub handle: u64,
}

/// What the library may call back: one function, to write a log line into the log of the agent.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostApi {
    pub log: Option<unsafe extern "C" fn(level: u32, msg: *const u8, len: usize)>,
}

/// [`HostApi::log`] levels.
pub mod level {
    pub const ERROR: u32 = 1;
    pub const WARN: u32 = 2;
    pub const INFO: u32 = 3;
    pub const DEBUG: u32 = 4;
}

pub type VersionFn = unsafe extern "C" fn() -> u32;
pub type IdentityFn = unsafe extern "C" fn(out: *mut Identity) -> i32;
pub type InitFn = unsafe extern "C" fn(
    host: *const HostApi,
    err: *mut u8,
    err_cap: usize,
    err_len: *mut usize,
) -> i32;
pub type SsrfNewFn = unsafe extern "C" fn(blob: *const u8, len: usize, out: *mut u64) -> i32;
pub type FreeHandleFn = unsafe extern "C" fn(handle: u64);
pub type ConfigNewFn = unsafe extern "C" fn(
    words: *const u64,
    n_words: usize,
    field_name: *const u8,
    field_name_len: usize,
    ssrf: u64,
    out: *mut ConfigOut,
) -> i32;
pub type BaselineNewFn = unsafe extern "C" fn(out: *mut u64) -> i32;
pub type BaselineObserveFn = unsafe extern "C" fn(
    handle: u64,
    project: *const u8,
    project_len: usize,
    param: *const u8,
    param_len: usize,
    is_new: *mut u8,
) -> i32;
pub type ScanRequestFn = unsafe extern "C" fn(args: *const ScanArgs, out: *mut OutBuf) -> i32;
pub type FrameFieldsFn =
    unsafe extern "C" fn(payload: *const u8, len: usize, out: *mut OutBuf) -> i32;
pub type ScanValueFn =
    unsafe extern "C" fn(config: u64, value: *const u8, len: usize, out: *mut OutBuf) -> i32;
pub type GraphqlBatchFn =
    unsafe extern "C" fn(body: *const u8, len: usize, max_batch: i64, over: *mut u8) -> i32;
pub type GuessMatchSourceFn =
    unsafe extern "C" fn(request: *const Request, out: *mut OutBuf) -> i32;
pub type HeaderSuspiciousFn =
    unsafe extern "C" fn(value: *const u8, len: usize, suspicious: *mut u8) -> i32;
pub type PrepareThreadFn = unsafe extern "C" fn(stack_budget_bytes: u64) -> i32;
pub type CountersFn = unsafe extern "C" fn(out: *mut Counters) -> i32;
pub type BotSeedsFn = unsafe extern "C" fn(out: *mut BotSeeds) -> i32;
pub type BufferFreeFn = unsafe extern "C" fn(buf: *mut OutBuf);

/// The symbol names, NUL-terminated for `dlsym`.
pub mod symbols {
    pub const VERSION: &[u8] = b"wafio_engine_interface_version\0";
    pub const IDENTITY: &[u8] = b"wafio_engine_identity\0";
    pub const INIT: &[u8] = b"wafio_engine_init\0";
    pub const SSRF_NEW: &[u8] = b"wafio_engine_ssrf_new\0";
    pub const SSRF_FREE: &[u8] = b"wafio_engine_ssrf_free\0";
    pub const CONFIG_NEW: &[u8] = b"wafio_engine_config_new\0";
    pub const CONFIG_FREE: &[u8] = b"wafio_engine_config_free\0";
    pub const BASELINE_NEW: &[u8] = b"wafio_engine_baseline_new\0";
    pub const BASELINE_OBSERVE: &[u8] = b"wafio_engine_baseline_observe\0";
    pub const BASELINE_FREE: &[u8] = b"wafio_engine_baseline_free\0";
    pub const SCAN_REQUEST: &[u8] = b"wafio_engine_scan_request\0";
    pub const FRAME_FIELDS: &[u8] = b"wafio_engine_frame_fields\0";
    pub const SCAN_VALUE: &[u8] = b"wafio_engine_scan_value\0";
    pub const GRAPHQL_BATCH: &[u8] = b"wafio_engine_graphql_batch_over_limit\0";
    pub const GUESS_MATCH_SOURCE: &[u8] = b"wafio_engine_guess_match_source\0";
    pub const HEADER_SUSPICIOUS: &[u8] = b"wafio_engine_header_value_looks_suspicious\0";
    pub const PREPARE_THREAD: &[u8] = b"wafio_engine_prepare_thread\0";
    pub const COUNTERS: &[u8] = b"wafio_engine_counters\0";
    pub const BOT_SEEDS: &[u8] = b"wafio_engine_bot_seeds\0";
    pub const BUFFER_FREE: &[u8] = b"wafio_engine_buffer_free\0";

    /// Every exported symbol. `nm -D --defined-only` of a library prints exactly these.
    pub const ALL: [&[u8]; 20] = [
        VERSION,
        IDENTITY,
        INIT,
        SSRF_NEW,
        SSRF_FREE,
        CONFIG_NEW,
        CONFIG_FREE,
        BASELINE_NEW,
        BASELINE_OBSERVE,
        BASELINE_FREE,
        SCAN_REQUEST,
        FRAME_FIELDS,
        SCAN_VALUE,
        GRAPHQL_BATCH,
        GUESS_MATCH_SOURCE,
        HEADER_SUSPICIOUS,
        PREPARE_THREAD,
        COUNTERS,
        BOT_SEEDS,
        BUFFER_FREE,
    ];
}

const _: () = {
    assert!(size_of::<Slice>() == 16);
    assert!(size_of::<Header>() == 32);
    assert!(size_of::<Request>() == 96);
    assert!(size_of::<ScanArgs>() == 168);
    assert!(size_of::<OutBuf>() == 32);
    assert!(size_of::<Identity>() == 48);
    assert!(size_of::<Counters>() == 16);
    assert!(size_of::<BotSeeds>() == 32);
    assert!(size_of::<ConfigOut>() == 8);
    assert!(size_of::<HostApi>() == 8);
};
