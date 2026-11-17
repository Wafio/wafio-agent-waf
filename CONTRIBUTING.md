# Contributing to wafio-agent-waf

Thank you for looking at the code. This file says what a change needs before it can be merged.

## Before you start

- For anything larger than a small fix, open an issue first and say what you want to change. It saves you work if the change does not fit.
- A security problem does not go into an issue: see `SECURITY.md`.

## Build and test

The requirements are in the README. The agent builds and runs on Linux, and it needs a checkout of uddin-lang-rs next to this one. The full gate:

```sh
scripts/ci-local.sh
```

## Rules of this repository

- No detection logic in this repository. The agent calls the engine through the interface in `crates/engine-api`; the README section "The engine boundary" says where the line is. A change that decides whether a request is an attack does not belong here.
- The tests run with the engine that detects nothing or with `crates/engine-fake`, so a change must not need the private engine to be tested.
- Code that reads bytes from the network is written in Rust, without a C library behind it.
- A new dependency must be maintained and have a licence that GPL-3.0 allows; the gate checks the advisories and the notices.
- Code translated or adapted from another project needs an entry in `scripts/notices/notices.json` with its licence text in `scripts/notices/texts/`.
- `proto/` is a copy of the protocol file of wafio-cp-backend. Change it there, then run `scripts/sync-proto.sh`.

## Pull requests

- One topic per pull request, with tests for what it changes.
- Say what the change does and how you checked it.
- Commit messages and comments are plain English.
- Do not commit secrets, local configuration, certificates or keys.
- Do not add instruction files for coding assistants, or planning notes, to the repository. The gate refuses them.

## Licence of your contribution

The project is under the GNU General Public License, version 3 only (`LICENSE`). Before a contribution can be merged you must agree to the Wafio Contributor Licence Agreement in `CLA.md`. You keep your copyright; the agreement gives Wafio the right to publish your contribution in this project and in the products built from it. Section 5 of `CLA.md` says how to agree.

If part of a change comes from another project, say so in the pull request: the project, the copyright holder and the licence. Such code needs an entry in the third-party notices.
