# AGENTS.md

Instructions for coding assistants that work on wafio-agent-waf. The rules for every contribution are in
`CONTRIBUTING.md`; this file is the short form.

## What this is

The open part of the Wafio WAF agent, in Rust: a reverse proxy that enforces rules and reports to the control
plane. It builds without a detection engine. The workspace needs a checkout of uddin-lang-rs next to it
(`../uddin-lang-rs`). Linux only.

## Commands

    cargo build --release -p wafio-waf-agent   # the agent, as wafio-waf-agent-open
    scripts/ci-local.sh                        # the gate: must pass before a pull request
    cargo test --locked --workspace --features wafio-waf-agent/test-tls,wafio-waf-agent/test-cache-delay   # the tests

The gate runs the secret scan, the notices and advisory checks, `cargo fmt --check`, `cargo clippy` with
`-D warnings`, the tests, and with docker the certificate orders against Pebble (`WAFIO_SKIP_ACME=1` skips that step). Fix what it
reports; do not disable a check.

## Rules

- No detection logic here. Code that decides whether a request is an attack belongs to the engine behind
  `crates/engine-api`. README, "The engine boundary", says where the line is.
- Code that reads bytes from the network is Rust, with no C library behind it.
- A change comes with a test. Tests must pass without the private engine (`crates/engine-fake`).
- A new dependency must be maintained and have a licence GPL-3.0 allows; add its notice
  (`scripts/notices/notices.json`).

## Do not edit

- `proto/`: a copy of the protocol file of wafio-cp-backend. Change it there, then run `scripts/sync-proto.sh`.
- `LICENSE`, `CLA.md`, `scripts/advisories.allow`.
- Snapshot fixtures, except with the command the README names for them.

## Writing

Comments, commit messages and documents are plain English. One topic per pull request.

## Security

Do not put a vulnerability in an issue, a pull request or a commit message. `SECURITY.md` says how to report it.

## The person, not the assistant

The person who opens the pull request has read the change, understands it and answers for it, and agrees to
`CLA.md`. A security
report must be reproduced before it is sent. `CONTRIBUTING.md`, "Work done with a coding assistant", says the same.
