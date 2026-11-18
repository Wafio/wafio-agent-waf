//! Framework-independent agent logic: challenge configuration, pages and verification, block
//! pages, good-bot ranges, FireHOL reputation and field rules. Inputs are plain values
//! (bytes, Unix seconds); outputs are response parts or rewritten bodies.

#![forbid(unsafe_code)]

pub mod block_response;
pub mod challenge;
pub mod challenge_handler;
pub mod challenge_replay;
pub mod challenge_verify_limit;
pub mod crypto;
pub mod field_names;
pub mod field_paths;
pub mod goodbot;
pub mod iprep;
pub mod json_tree;
pub mod maintenance;
pub mod multipart;
pub mod seeded_rng;
#[rustfmt::skip]
pub mod templates;
