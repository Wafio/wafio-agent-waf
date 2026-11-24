//! Request pipeline of the Rust WAF agent: the per-app inline proxy.
//!
//! Pingora 0.9 is a toolkit here, not a framework: own accept loops per app
//! (`listeners::RouteManager`), the request read of every connection (`route::RouteApp` on the
//! raw stream: `head_parser` parses the head, `body_reader` frames and reads the body;
//! Pingora's HTTP/1 server session is not used), the whole body read and analysed before any
//! upstream contact, Pingora's `Connector` for HTTP upstreams, agent-io's FastCGI pool and
//! WebSocket frames, own SIGUSR2 handover (`upgrade`).
//!
//! Entry points for the binary: [`Proxy::new`], [`Proxy::apply`] (a bundle's apps, atomically),
//! [`Proxy::certificates`] (what the TLS listeners serve), [`Proxy::shutdown`],
//! [`Proxy::handover_fds`], [`runtime_builder`], the decision sink in [`ProxyOptions`] and the
//! counters in [`metrics`].

// One audited `unsafe` site in this crate carries `#[allow(unsafe_code)]`; anything new needs the same, with its reason.
#![deny(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod body_reader;
mod cache;
pub mod cert_store;
pub mod client_hello;
mod compress;
pub mod config;
pub mod decision;
mod edge_stats;
pub mod fastcgi;
pub mod head_parser;
pub(crate) mod https;
pub mod listeners;
pub(crate) mod maintenance;
pub mod metrics;
pub mod pipeline;
pub mod proxy;
mod redirect;
pub mod request;
pub mod response;
pub mod route;
pub mod siem;
mod signed_in;
pub mod sniff;
mod static_files;
#[doc(hidden)]
pub mod testing;
pub mod upgrade;
pub mod upstream;
pub mod websocket;

pub use cache::{
    CacheHost, CacheLimits, CacheRefusal, CacheRefusalCode, CacheRule, CacheSpec, HostFacts,
    valid_app_id,
};
pub use config::{AppAnalysisSetup, AppSpec, CompressionSpec, MAX_MIN_COMPRESS_BYTES, TlsSite};
pub use decision::{DecisionEvent, DecisionSink};
pub use edge_stats::CompressionCounters;
pub use proxy::{Proxy, ProxyOptions};
pub use siem::{SiemEvent, SiemEventSender};
pub use static_files::{MAX_BROWSER_CACHE_S, RefusalCode, StaticRefusal, StaticSpec};

use std::cell::Cell;

/// Stack size of every thread that runs detection (bodyinspect + Analyze). Engine parsers recurse
/// up to their depth caps (XSS: 1,000 nested JS levels) and a Rust stack does not grow.
pub const DETECTION_STACK_SIZE: usize = 16 << 20;

/// What the SQL parser's recursion may use of a detection thread's stack (the rest is the caller's
/// frames): with it every nesting the engine-sql measurements cover (4,096+ levels) parses
/// without exhausting the stack. The budget is thread-local and defaults to 1 MiB, so every
/// detection thread declares it.
pub const SQL_STACK_BUDGET: usize = 12 << 20;

/// What the next detection thread declares (tests lower it to show what the engine does without
/// the budget; threads already running keep theirs).
static SQL_BUDGET: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(SQL_STACK_BUDGET);

#[doc(hidden)]
pub fn set_sql_stack_budget(bytes: usize) {
    SQL_BUDGET.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

thread_local! {
    static BIG_STACK: Cell<bool> = const { Cell::new(false) };
}

/// Worker threads the runtime was built with (0 = not built by [`runtime_builder`]).
static WORKERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Logical CPUs the process may run on (`sched_getaffinity`): the `Cpus_allowed_list` of
/// `/proc/self/status`, else `available_parallelism`.
fn affinity_cpus() -> usize {
    let listed = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            let l = s
                .lines()
                .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))?;
            let mut n = 0usize;
            for part in l.trim().split(',') {
                let (lo, hi) = part.split_once('-').unwrap_or((part, part));
                n += hi
                    .trim()
                    .parse::<usize>()
                    .ok()?
                    .checked_sub(lo.trim().parse().ok()?)?
                    + 1;
            }
            Some(n)
        })
        .filter(|&n| n > 0);
    listed.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from))
}

/// The CPU throughput limit of the process's cgroup in CPUs (quota / period), if one is set.
/// Only the leaf cgroup is read; the mount point is taken to be `/sys/fs/cgroup`.
fn cgroup_cpu_limit() -> Option<f64> {
    let cg = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let read = |p: String| std::fs::read_to_string(p).ok();
    for line in cg.lines() {
        let mut it = line.splitn(3, ':');
        let (id, ctrl, path) = (it.next()?, it.next()?, it.next()?);
        if id == "0" && ctrl.is_empty() {
            // cgroup v2: `cpu.max` = "<quota|max> <period>".
            for base in [format!("/sys/fs/cgroup{path}"), "/sys/fs/cgroup".into()] {
                if let Some(s) = read(format!("{base}/cpu.max")) {
                    return cpu_max_limit(&s);
                }
            }
            return None;
        }
        if ctrl.split(',').any(|c| c == "cpu") {
            // cgroup v1: `cpu.cfs_quota_us` (-1 = none) and `cpu.cfs_period_us`.
            for base in [
                format!("/sys/fs/cgroup/cpu{path}"),
                format!("/sys/fs/cgroup/cpu,cpuacct{path}"),
                "/sys/fs/cgroup/cpu".into(),
                "/sys/fs/cgroup/cpu,cpuacct".into(),
            ] {
                if let (Some(q), Some(p)) = (
                    read(format!("{base}/cpu.cfs_quota_us")),
                    read(format!("{base}/cpu.cfs_period_us")),
                ) {
                    let (q, p) = (q.trim().parse::<i64>().ok()?, p.trim().parse::<i64>().ok()?);
                    return (q >= 0 && p > 0).then(|| q as f64 / p as f64);
                }
            }
            return None;
        }
    }
    None
}

/// A cgroup v2 `cpu.max` as a CPU count.
fn cpu_max_limit(s: &str) -> Option<f64> {
    let mut f = s.split_whitespace();
    let (quota, period) = (f.next()?, f.next()?);
    let (quota, period) = (quota.parse::<u64>().ok()?, period.parse::<u64>().ok()?);
    (period > 0).then(|| quota as f64 / period as f64)
}

/// The default worker count: the CPUs the process may use, lowered to the cgroup throughput
/// limit rounded up (a limit under 2 counts as 2) when that is lower.
fn default_parallelism(ncpu: usize, limit: Option<f64>) -> usize {
    match limit {
        Some(l) => ncpu.min((l.ceil() as usize).max(2)),
        None => ncpu,
    }
    .max(1)
}

/// Tokio worker threads when `TOKIO_WORKER_THREADS` is unset (tokio's own default rounds a
/// 1.5-CPU quota down to one worker, this rounds up to two).
pub fn default_worker_threads() -> usize {
    default_parallelism(affinity_cpus(), cgroup_cpu_limit())
}

/// The tokio runtime builder the agent must use: multi-thread, every worker and blocking thread
/// with a [`DETECTION_STACK_SIZE`] stack and marked, sized by [`default_worker_threads`] unless
/// `TOKIO_WORKER_THREADS` says otherwise. Detection runs on the worker that owns the request;
/// a big request under `block_in_place` (see [`run_detection_async`]). The SQL parser's stack
/// budget is set on each thread.
pub fn runtime_builder() -> tokio::runtime::Builder {
    let workers = std::env::var("TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(default_worker_threads);
    WORKERS.store(workers, std::sync::atomic::Ordering::Relaxed);
    let mut b = tokio::runtime::Builder::new_multi_thread();
    b.enable_all()
        .worker_threads(workers)
        .thread_stack_size(DETECTION_STACK_SIZE)
        .on_thread_start(|| {
            BIG_STACK.with(|c| c.set(true));
            wafio_engine_api::engine()
                .prepare_thread(SQL_BUDGET.load(std::sync::atomic::Ordering::Relaxed));
        });
    b
}

/// A request whose body is at least this long is inspected under `tokio::task::block_in_place`
/// (`usize::MAX` = never, 0 = always). Detection of a smaller one costs 0.3-3 ms, below the price
/// of handing the worker over (an extra thread with its own allocator heap: the 2026-11-12 load
/// run, which handed over every request, went from 100 to 165-190 MiB RSS and 7 to 17 threads); a
/// big one costs 35-380 ms and would stall every connection its worker serves.
static BLOCK_IN_PLACE_FROM: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(32 << 10);

/// Measurement switch (`tests/inline_stall.rs`): `true` hands over every detection, `false` runs
/// every one inline (the baseline); the default is the size gate above.
#[doc(hidden)]
pub fn set_block_in_place(on: bool) {
    BLOCK_IN_PLACE_FROM.store(
        if on { 0 } else { usize::MAX },
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Detections that run under `block_in_place` at once: `max(2, workers)`, so the replacement
/// threads and the per-request memory stay bounded; the rest wait here, holding no thread.
fn detection_slots() -> &'static tokio::sync::Semaphore {
    static SLOTS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| tokio::sync::Semaphore::new(worker_count().max(2)))
}

/// The worker threads of the runtime, or the CPUs when it was not built by [`runtime_builder`].
fn worker_count() -> usize {
    match WORKERS.load(std::sync::atomic::Ordering::Relaxed) {
        0 => std::thread::available_parallelism().map_or(1, usize::from),
        n => n,
    }
}

/// [`run_detection`] for a request of `weight` bytes (its body): a big one first waits for one of
/// the [`detection_slots`] and then runs under `block_in_place`, so the worker's other connections
/// move to another thread meanwhile; a small one runs inline.
pub async fn run_detection_async<R: Send>(weight: usize, f: impl FnOnce() -> R + Send) -> R {
    let on_worker = BIG_STACK.with(Cell::get)
        && tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if on_worker && weight >= BLOCK_IN_PLACE_FROM.load(std::sync::atomic::Ordering::Relaxed) {
        let _slot = detection_slots().acquire().await;
        return tokio::task::block_in_place(f);
    }
    run_detection(f)
}

/// Runs `f` on a thread with a [`DETECTION_STACK_SIZE`] stack: inline on a thread from
/// [`runtime_builder`], else (tests, other runtimes) on a scoped thread of that size.
pub fn run_detection<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    if BIG_STACK.with(Cell::get) {
        return f();
    }
    std::thread::scope(|s| {
        let work = move || {
            wafio_engine_api::engine()
                .prepare_thread(SQL_BUDGET.load(std::sync::atomic::Ordering::Relaxed));
            f()
        };
        let h = std::thread::Builder::new()
            .stack_size(DETECTION_STACK_SIZE)
            .spawn_scoped(s, work)
            .expect("spawn detection thread");
        match h.join() {
            Ok(r) => r,
            Err(p) => std::panic::resume_unwind(p),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_parallelism_follows_cgroup_rules() {
        // No limit: the CPUs. A limit rounds up and never goes under 2; it only lowers.
        assert_eq!(default_parallelism(8, None), 8);
        assert_eq!(default_parallelism(8, Some(1.5)), 2);
        assert_eq!(default_parallelism(8, Some(0.5)), 2);
        assert_eq!(default_parallelism(8, Some(2.0)), 2);
        assert_eq!(default_parallelism(8, Some(2.1)), 3);
        assert_eq!(default_parallelism(4, Some(16.0)), 4);
        assert_eq!(default_parallelism(1, Some(1.5)), 1);
    }

    #[test]
    fn cpu_max_is_quota_over_period() {
        assert_eq!(cpu_max_limit("max 100000\n"), None);
        assert_eq!(cpu_max_limit("150000 100000\n"), Some(1.5));
        assert_eq!(cpu_max_limit("garbage"), None);
    }
}
