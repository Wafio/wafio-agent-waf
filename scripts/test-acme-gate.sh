#!/usr/bin/env bash
# Checks the step `acme` (scripts/acme-gate.sh) on a host where docker is missing or cannot be used, which it is made to look
# like through PATH: the private gate fails, WAFIO_SKIP_ACME=1 skips, and any other host skips and says why.
set -euo pipefail
here=${0%/*}
[ "$here" != "$0" ] || here=.
cd "$here/.."

bash=$(command -v bash)
env=$(command -v env)
bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT

status=0
output=
# gate NAME=value...: the step with an empty PATH and only these variables set.
gate() {
  status=0
  output=$("$env" -i PATH="$bin" "$@" "$bash" scripts/acme-gate.sh 2>&1) || status=$?
}
fail() {
  echo "test-acme-gate: $1 (status $status): $output" >&2
  exit 1
}

for kind in missing unusable; do
  rm -f "$bin/docker"
  # A docker that is installed and refuses every command, as one the user may not talk to does.
  [ "$kind" = missing ] || printf '#!/bin/sh\nexit 1\n' >"$bin/docker"
  [ "$kind" = missing ] || chmod +x "$bin/docker"

  gate WAFIO_TARGET=private
  [ "$status" != 0 ] || fail "$kind docker passed the private gate"
  case $output in *'docker'*) ;; *) fail "$kind docker: the failure does not name docker" ;; esac

  gate WAFIO_TARGET=private WAFIO_SKIP_ACME=1
  { [ "$status" = 0 ] && [ "$output" = 'acme: skipped' ]; } || fail "$kind docker: WAFIO_SKIP_ACME=1 under the private gate"

  gate WAFIO_SKIP_ACME=1
  { [ "$status" = 0 ] && [ "$output" = 'acme: skipped' ]; } || fail "$kind docker: WAFIO_SKIP_ACME=1"

  gate
  { [ "$status" = 0 ] && [ "${output#acme: skipped (}" != "$output" ]; } || fail "$kind docker: another host does not skip"
done
echo 'test-acme-gate: ok'
