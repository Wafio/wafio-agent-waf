#!/usr/bin/env bash
# The `acme` step of scripts/ci-local.sh: the tests of crates/waf-agent/tests/tls_bundle.rs named pebble_*, which have the real
# agent order certificates from Pebble (scripts/pebble.sh). Run it after the test step, whose build it reuses.
#
#   WAFIO_SKIP_ACME=1     prints "acme: skipped" and runs nothing.
#   WAFIO_TARGET=private  docker missing or unusable fails the step; on any other host the step is skipped and says why.
#   WAFIO_CARGO_PROFILE   as for ci-local.sh (default conformance).
#
# Two Pebbles run in turn: the pebble_reuse_ cases need one that reuses authorizations, the others run on a plain one. Each gets
# 10 minutes and the cases take about 4 together. A Pebble this step started is taken down however the step ends.
set -euo pipefail
here=${0%/*}
[ "$here" != "$0" ] || here=.
cd "$here/.."

if [ "${WAFIO_SKIP_ACME:-}" = 1 ]; then
  echo 'acme: skipped'
  exit 0
fi
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  if [ "${WAFIO_TARGET:-}" = private ]; then
    echo 'acme: docker is missing or cannot be used, and the private gate needs it (WAFIO_SKIP_ACME=1 skips this step)' >&2
    exit 1
  fi
  echo 'acme: skipped (docker is missing or cannot be used)'
  exit 0
fi

profile=${WAFIO_CARGO_PROFILE:-conformance}
runs=()
out=
cleanup() {
  local run
  for run in ${runs[@]+"${runs[@]}"}; do
    scripts/pebble.sh down "$run" || true
  done
  [ -z "$out" ] || rm -f "$out"
}
trap cleanup EXIT
# A signal ends the step through the trap above.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# run_cases FILTER SKIP [PEBBLE_SETTING=value ...]: starts a Pebble with the settings, runs the tests whose names contain FILTER
# and not SKIP (when given) against it, and takes it down.
run_cases() {
  local filter=$1 skip=$2 started
  shift 2
  started=$(env "$@" scripts/pebble.sh up)
  eval "$started"
  runs+=("$WAFIO_PEBBLE_RUN")
  echo "acme: $filter against Pebble at $WAFIO_PEBBLE_DIRECTORY ($*)"
  out=$(mktemp)
  # --test-threads=1: Pebble connects to the two ports of its run, which each case uses in turn.
  timeout 600 cargo test --locked --workspace --profile "$profile" --features wafio-waf-agent/test-tls --test tls_bundle \
    "$filter" -- --test-threads=1 ${skip:+--skip "$skip"} 2>&1 | tee "$out"
  # A filter that matches no case would pass and test nothing.
  if grep -q '^running 0 tests' "$out"; then
    echo "acme: no test matches $filter" >&2
    exit 1
  fi
  rm -f "$out"
  out=
  scripts/pebble.sh down "$WAFIO_PEBBLE_RUN"
  unset 'runs[${#runs[@]}-1]'
}

run_cases pebble_ pebble_reuse_
run_cases pebble_reuse_ '' PEBBLE_AUTHZREUSE=100
echo 'acme: every case passed'
