//! The regexp syntax parser lives in `wafio_bytetext::pattern_syntax` (the parser every
//! `CompiledRegex::compile` runs); this module keeps the names the rules code uses.

use wafio_bytetext::pattern::CompiledRegex;
pub use wafio_bytetext::pattern_syntax::program_size;

/// The parse error text, or the compiled regexp.
pub fn compile(pattern: &str) -> Result<CompiledRegex, String> {
    CompiledRegex::compile(pattern)
}
