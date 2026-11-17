//! The agent without a detection engine: everything but semantic detection. The official binary is built by the
//! engine repository, which installs its engine before it calls the same entry point.

#![forbid(unsafe_code)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> std::process::ExitCode {
    wafio_waf_agent::main_entry()
}
