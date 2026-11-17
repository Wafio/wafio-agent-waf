//! The C interface between the agent and a semantic engine that lives in a shared library.
//!
//! Rust has no stable ABI, so nothing with Rust layout crosses the boundary: only `extern "C"` functions, `#[repr(C)]`
//! structs of pointers, lengths and integers, and byte buffers in the encodings of [`wire`] and [`config`]. This crate
//! holds both halves of that contract that need no `unsafe`: the struct layouts and the symbol names ([`types`]), and
//! the encoders and decoders. The agent loads a library with `wafio-engine-loader`; the library exports the functions
//! of `include/wafio_engine.h`.
//!
//! The interface has one version, [`INTERFACE_VERSION`]. A library whose version differs is not loaded.

#![forbid(unsafe_code)]

pub mod config;
pub mod types;
pub mod wire;

pub use types::*;

/// The version of this interface. Any change to a struct layout, a symbol, an encoding or the meaning of a field
/// raises it; the agent loads a library of exactly this version and no other.
pub const INTERFACE_VERSION: u32 = 2;

/// Status codes returned by the functions of the library.
pub mod status {
    /// The call did what it was asked to.
    pub const OK: i32 = 0;
    /// A panic was caught inside the library. The call has no result; the library stays usable.
    pub const PANIC: i32 = 1;
    /// An argument was null where it must not be, or a struct or encoding was not understood.
    pub const BAD_ARGUMENT: i32 = 2;
    /// The library could not do what it was asked to and says nothing more.
    pub const FAILED: i32 = 3;
}
