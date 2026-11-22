#!/usr/bin/env bash
# The `acme` step of scripts/ci-local.sh: the tests of crates/waf-agent/tests/tls_bundle.rs named pebble_*, which have the real
# agent order certificates from Pebble (scripts/pebble.sh). Run it after the test step, whose build it reuses.
#
# The private gate is the one with WAFIO_TARGET=private. The step says which gate it saw.
#
#   private gate          docker missing or unusable fails the step, and WAFIO_SKIP_ACME=1 is refused, so that a green private
#                         gate always has the Pebble cases behind it.
#   any other gate        docker missing or unusable skips the step and says why; WAFIO_SKIP_ACME=1 prints "acme: skipped".
#   WAFIO_CARGO_PROFILE   as for ci-local.sh (default conformance).
#
# Two Pebbles run in turn: the pebble_reuse_ cases need one that reuses authorizations, the others run on a plain one. The cases
# take about 4 minutes together, and the runs are held to the limits below. A Pebble this step started is taken down however
# the step ends, a kill by a signal included; after a kill nothing can catch, the next `scripts/pebble.sh up` takes it down.
set -euo pipefail
here=${0%/*}
[ "$here" != "$0" ] || here=.
cd "$here/.."

target=shared
case ${WAFIO_TARGET:-} in private) target=private ;; esac
echo "acme: $target gate (WAFIO_TARGET=${WAFIO_TARGET-unset})"

if [ "${WAFIO_SKIP_ACME:-}" = 1 ]; then
  if [ "$target" = private ]; then
    echo 'acme: the private gate runs this step: WAFIO_SKIP_ACME=1 is not allowed there' >&2
    exit 1
  fi
  echo 'acme: skipped'
  exit 0
fi
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  if [ "$target" = private ]; then
    echo 'acme: docker is missing or cannot be used, and the private gate needs it' >&2
    exit 1
  fi
  echo 'acme: skipped (docker is missing or cannot be used)'
  exit 0
fi

profile=${WAFIO_CARGO_PROFILE:-conformance}
cargo_test=(cargo test --locked --workspace --profile "$profile" --features wafio-waf-agent/test-tls --test tls_bundle)

# What is up and not yet taken down: the output of `pebble.sh up` of the Pebble that runs, and the pid of the cargo run against
# it. Each is set as soon as the command that makes it returns, and a signal waits for that, so the clean-up always sees it.
started=
cases=
cleanup() {
  # A second signal must not cut the clean-up short.
  trap '' HUP INT TERM
  if [ -n "$cases" ]; then
    # timeout passes the signal on to cargo and to everything cargo started, which are in its process group.
    kill "$cases" 2>/dev/null || true
    wait "$cases" 2>/dev/null || true
  fi
  [ -z "$started" ] || (eval "$started" && scripts/pebble.sh down "$WAFIO_PEBBLE_RUN") || true
}
trap cleanup EXIT
# A signal ends the step through the trap above. `wait` returns at once when one comes in, which a command that runs in the
# foreground would not do: bash holds the trap back until that command is over.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# run_cases LIMIT FILTER SKIP [PEBBLE_SETTING=value ...]: starts a Pebble with the settings, runs the tests whose names contain
# FILTER and not SKIP (when given) against it for at most LIMIT seconds, and takes it down.
run_cases() {
  local limit=$1 filter=$2 skip=$3 names status=0
  shift 3
  # A filter that matches no case would pass and test nothing, so the names are asked for first, before a Pebble is started.
  names=$("${cargo_test[@]}" "$filter" -- --list ${skip:+--skip "$skip"})
  case $names in
    *': test'*) ;;
    *)
      echo "acme: no test matches $filter" >&2
      exit 1
      ;;
  esac
  started=$(env WAFIO_PEBBLE_OWNER=$$ "$@" scripts/pebble.sh up)
  eval "$started"
  echo "acme: $filter against Pebble at $WAFIO_PEBBLE_DIRECTORY ($*)"
  # --test-threads=1: Pebble connects to the two ports of its run, which each case uses in turn.
  timeout -k 10 "$limit" "${cargo_test[@]}" "$filter" -- --test-threads=1 ${skip:+--skip "$skip"} &
  cases=$!
  wait "$cases" || status=$?
  cases=
  if [ "$status" != 0 ]; then
    echo "acme: the $filter cases failed (status $status; 124 means they did not end in $limit seconds)" >&2
    exit 1
  fi
  scripts/pebble.sh down "$WAFIO_PEBBLE_RUN"
  started=
}

run_cases 400 pebble_ pebble_reuse_
run_cases 60 pebble_reuse_ '' PEBBLE_AUTHZREUSE=100
echo "acme: every case passed ($SECONDS seconds)"
