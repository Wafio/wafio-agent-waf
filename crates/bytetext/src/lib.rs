//! Text functions over byte strings (`&[u8]`) that give a defined result for every input,
//! invalid UTF-8 included.

#![forbid(unsafe_code)]
// Nested ifs keep their order of checks.
#![allow(clippy::collapsible_if)]

pub mod base64;
pub mod digest;
pub mod hex;
pub mod html;
mod html_entities;
pub mod literal;
pub mod net;
pub mod norm;
pub mod path;
pub mod pattern;
pub mod pattern_syntax;
pub mod sort;
pub mod strings;
pub mod transforms;
pub mod unicode;
#[allow(clippy::all)]
mod unicode_tables;
pub mod url;
mod url_parse;
pub mod utf16;
pub mod utf8;

/// A code point (int32).
pub type CodePoint = i32;
