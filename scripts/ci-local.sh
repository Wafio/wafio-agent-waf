#!/usr/bin/env bash
# Every gate of this repo, cheapest first. Run it on a Linux host that has cargo.
#
# The repo holds the agent without a detection engine, so its tests run with the engine that detects nothing or with the
# small fake of crates/engine-fake. What detection finds is tested in the engine repository, which has its own gate.
#
# WAFIO_CARGO_PROFILE (default conformance): the cargo profile of clippy and the tests. It is the release
#   profile without LTO, so the crates build in minutes instead of tens of minutes.
set -euo pipefail
cd "$(dirname "$0")/.."

profile=${WAFIO_CARGO_PROFILE:-conformance}

echo '== agent material'
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  scripts/check-ai.sh
else
  echo 'skipped: no .git here (run scripts/check-ai.sh in the checkout)'
fi

echo '== secrets'
command -v gitleaks >/dev/null || { echo 'gitleaks not installed (pinned to 8.30.1)' >&2; exit 1; }
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  gitleaks git --redact --exit-code 1 --config .gitleaks.toml .
else
  # A copy without .git: scan the tree. build/ can be a link, which gitleaks dir does not follow.
  gitleaks dir --redact --exit-code 1 --config .gitleaks.toml .
fi

echo '== proto'
scripts/sync-proto.sh --check

echo '== notices'
python3 scripts/test_gen_notices.py
python3 scripts/gen-notices.py -o /dev/null --spdx /dev/null

echo '== advisories'
# Asks OSV about the locked crates; offline it warns and passes (scripts/advisories.py).
python3 scripts/test_advisories.py
python3 scripts/advisories.py Cargo.lock

echo '== test certificates'
scripts/gen-test-certs.sh

echo '== fmt'
cargo fmt --all --check

echo '== clippy'
cargo clippy --locked --workspace --all-targets --profile "$profile" -- -D warnings

echo '== test'
cargo test --locked --workspace --profile "$profile"
