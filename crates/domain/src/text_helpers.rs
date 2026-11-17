//! Text helpers used across this crate (and by `wafio-bodyinspect`), delegating to `wafio-bytetext`. Kept
//! as one module so callers have a single import path.

pub use wafio_bytetext::CodePoint;
pub use wafio_bytetext::strings::{eq_ignore_case, to_lowercase, trim_whitespace};
pub use wafio_bytetext::unicode::is_space;
pub use wafio_bytetext::url::unescape_query_component;
pub use wafio_bytetext::utf8::{
    REPLACEMENT_CODE_POINT, decode_code_point, decode_last_code_point, is_valid as is_valid_utf8,
    push_code_point,
};

/// `trim_whitespace` on a `&str` (cuts only at rune boundaries of valid UTF-8).
pub fn trim_whitespace_str(s: &str) -> &str {
    std::str::from_utf8(trim_whitespace(s.as_bytes())).unwrap_or(s)
}

/// The quoted, escaped form of `s` as a `String` (its output is valid UTF-8).
pub fn quote(s: &[u8]) -> String {
    String::from_utf8_lossy(&wafio_bytetext::literal::quote(s)).into_owned()
}
