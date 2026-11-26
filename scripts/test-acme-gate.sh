#!/usr/bin/env bash
# Checks the step `acme` (scripts/acme-gate.sh) and the clean-up of scripts/pebble.sh without a Pebble:
#   - on a host where docker is missing or cannot be used, which is made to look like through PATH: the private gate
#     (WAFIO_TARGET=private) fails and refuses WAFIO_SKIP_ACME=1, any other gate skips and says why, whatever its cargo directory;
#   - with a stub docker, cargo and pebble.sh: a Pebble is taken down once when the cases pass or fail, and when the step is
#     stopped by TERM while the Pebble starts or while the cases run, which also ends the cases;
#   - pebble.sh up takes down the run of an owner that is gone and leaves the others.
# Needs Linux (timeout, flock, python3), as the gate does.
set -euo pipefail
here=${0%/*}
[ "$here" != "$0" ] || here=.
cd "$here/.."

bash=$(command -v bash)
env=$(command -v env)
tree=$(mktemp -d)
trap 'rm -rf "$tree"' EXIT
bin=$tree/bin
mkdir "$bin"

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
last_line() { printf '%s\n' "${output##*$'\n'}"; }

for kind in missing unusable; do
  rm -f "$bin/docker"
  # A docker that is installed and refuses every command, as one the user may not talk to does.
  [ "$kind" = missing ] || printf '#!/bin/sh\nexit 1\n' >"$bin/docker"
  [ "$kind" = missing ] || chmod +x "$bin/docker"

  # The private gate, as WAFIO_TARGET says.
  for private in WAFIO_TARGET=private; do
    gate "$private"
    [ "$status" != 0 ] || fail "$kind docker passed the private gate ($private)"
    case $output in *'docker'*) ;; *) fail "$kind docker: the failure does not name docker ($private)" ;; esac
    case $output in *'acme: private gate'*) ;; *) fail "$kind docker: the step does not say it is private ($private)" ;; esac

    gate "$private" WAFIO_SKIP_ACME=1
    [ "$status" != 0 ] || fail "$kind docker: WAFIO_SKIP_ACME=1 passed the private gate ($private)"
    case $output in *'acme: skipped'*) fail "$kind docker: the private gate skipped ($private)" ;; esac
    case $output in *'WAFIO_SKIP_ACME=1 is not allowed'*) ;; *) fail "$kind docker: no reason for the refusal ($private)" ;; esac
  done

  # Only WAFIO_TARGET marks the private gate, whatever the cargo directory.
  for shared in 'CARGO_TARGET_DIR=/home/u/wr/target WAFIO_TARGET=shared' CARGO_TARGET_DIR=/home/u/wr/target-ws CARGO_TARGET_DIR=target-ws; do
    # shellcheck disable=SC2086 # the words are separate variables on purpose
    gate $shared
    { [ "$status" = 0 ] && [ "${output#*'acme: shared gate'}" != "$output" ]; } || fail "$kind docker: the shared target ($shared)"
    { [ "$status" = 0 ] && [ "$(last_line)" = 'acme: skipped (docker is missing or cannot be used)' ]; } || fail "$kind docker: another host does not skip ($shared)"
  done

  gate WAFIO_SKIP_ACME=1
  { [ "$status" = 0 ] && [ "$(last_line)" = 'acme: skipped' ]; } || fail "$kind docker: WAFIO_SKIP_ACME=1"
done
rm -f "$bin/docker"

# A stub docker, cargo and pebble.sh, and the step copied beside the stub pebble.sh, which it finds through its own path.
stubs=$tree/stubs
steps=$tree/steps
state=$tree/state
mkdir -p "$stubs" "$steps/scripts"
cp scripts/acme-gate.sh "$steps/scripts/acme-gate.sh"
printf '#!/bin/sh\nexit 0\n' >"$stubs/docker"
cat >"$stubs/cargo" <<'SH'
#!/bin/sh
# --list names the cases; the other call is the cases, which end as STUB_CASES says or run for a minute.
case " $* " in
  *' --list '*)
    [ "$STUB_LIST" = none ] || echo 'pebble_one: test'
    exit 0
    ;;
esac
case $STUB_CASES in
  pass) exit 0 ;;
  fail) exit 1 ;;
esac
sleep 60 &
echo $! >"$STUB_DIR/cases.pid"
wait
SH
cat >"$steps/scripts/pebble.sh" <<'SH'
#!/bin/sh
case $1 in
  up)
    echo "up owner=$WAFIO_PEBBLE_OWNER" >>"$STUB_DIR/log"
    : >"$STUB_DIR/up-began"
    sleep "$STUB_UP_SLEEP"
    echo "export WAFIO_PEBBLE_RUN=$STUB_DIR/run.1"
    echo "export WAFIO_PEBBLE_DIRECTORY=https://localhost:1/dir"
    ;;
  down) echo "down $2" >>"$STUB_DIR/log" ;;
esac
SH
chmod +x "$stubs/docker" "$stubs/cargo" "$steps/scripts/pebble.sh"

# stub_run CASES LIST UP_SLEEP: runs the step with the stubs to its end, and what it printed is in $output.
stub_run() {
  rm -rf "$state"
  mkdir "$state"
  status=0
  output=$("$env" -i PATH="$stubs:/usr/bin:/bin" STUB_DIR="$state" STUB_CASES="$1" STUB_LIST="$2" STUB_UP_SLEEP="$3" \
    "$bash" "$steps/scripts/acme-gate.sh" 2>&1) || status=$?
}
downs() { grep -c '^down ' "$state/log" || true; }

stub_run pass some 0
{ [ "$status" = 0 ] && [ "$(downs)" = 2 ]; } || fail "cases that pass: both Pebbles go down once"
case $output in *'acme: every case passed'*) ;; *) fail "cases that pass: no word of it" ;; esac
grep -q '^up owner=[0-9][0-9]*$' "$state/log" || fail "the step does not name itself as the owner of its Pebble"

stub_run fail some 0
{ [ "$status" != 0 ] && [ "$(downs)" = 1 ]; } || fail "cases that fail: the Pebble goes down once"
case $output in *'cases failed (status 1'*) ;; *) fail "cases that fail: no word of it" ;; esac

stub_run pass none 0
{ [ "$status" != 0 ] && [ ! -e "$state/up-began" ]; } || fail "no case matches: a Pebble was started"
case $output in *'no test matches pebble_'*) ;; *) fail "no case matches: no word of it" ;; esac

# stopped CASES UP_SLEEP FILE: starts the step, sends TERM when FILE exists in the state directory, gives it 20 seconds to end.
stopped() {
  local pid i
  rm -rf "$state"
  mkdir "$state"
  "$env" -i PATH="$stubs:/usr/bin:/bin" STUB_DIR="$state" STUB_CASES="$1" STUB_LIST=some STUB_UP_SLEEP="$2" \
    "$bash" "$steps/scripts/acme-gate.sh" >"$state/out" 2>&1 &
  pid=$!
  for i in $(seq 1 100); do
    [ -e "$state/$3" ] && break
    sleep 0.1
  done
  [ -e "$state/$3" ] || { kill -9 "$pid" 2>/dev/null || true; output=$(cat "$state/out"); fail "the step did not get as far as $3"; }
  kill -TERM "$pid"
  for i in $(seq 1 200); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
    output=$(cat "$state/out")
    fail "the step was still running 20 seconds after TERM"
  fi
  status=0
  wait "$pid" || status=$?
  output=$(cat "$state/out")
}

# TERM while the cases run: the cases end and the Pebble goes down.
stopped run 0 cases.pid
[ "$status" = 143 ] || fail "TERM during the cases"
[ "$(downs)" = 1 ] && grep -q "^down $state/run.1$" "$state/log" || fail "TERM during the cases: the Pebble was not taken down once"
# The process the cases left running is gone, once its parent has taken it over.
for i in $(seq 1 20); do
  kill -0 "$(cat "$state/cases.pid")" 2>/dev/null || break
  sleep 0.1
done
! kill -0 "$(cat "$state/cases.pid")" 2>/dev/null || fail "TERM during the cases: the cases still run"

# TERM while the Pebble starts: it is up by the time the step looks at the signal, and goes down.
stopped run 2 up-began
[ "$status" = 143 ] || fail "TERM during the start of the Pebble"
[ "$(downs)" = 1 ] && grep -q "^down $state/run.1$" "$state/log" || fail "TERM during the start of the Pebble: it was not taken down once"
[ ! -e "$state/cases.pid" ] || fail "TERM during the start of the Pebble: the cases were started"

# The next `pebble.sh up` takes down a run whose owner is gone, and leaves the live ones and the ones with no owner. docker
# refuses to create the container, so `up` goes no further than that after it has swept.
runs=$tree/runs
mkdir -p "$runs"
printf '#!/bin/sh\necho "$@" >>"%s/docker.log"\nexit 1\n' "$tree" >"$bin/docker"
chmod +x "$bin/docker"
sleep 0 &
gone=$!
wait "$gone"
mkdir "$runs/run.gone" "$runs/run.live" "$runs/run.none" "$runs/run.odd"
echo "$gone" >"$runs/run.gone/owner"
echo "$$" >"$runs/run.live/owner"
echo 'not a pid' >"$runs/run.odd/owner"
status=0
output=$("$env" -i PATH="$bin:/usr/bin:/bin" WAFIO_PEBBLE_STATE="$runs" "$bash" scripts/pebble.sh up 2>&1) || status=$?
[ "$status" != 0 ] || fail "pebble.sh up went on with a docker that refuses"
[ ! -e "$runs/run.gone" ] || fail "pebble.sh up left the run of an owner that is gone"
{ [ -d "$runs/run.live" ] && [ -d "$runs/run.none" ] && [ -d "$runs/run.odd" ]; } || fail "pebble.sh up took down a run that is not abandoned"
grep -q '^rm -f wafio-pebble-run.gone wafio-challtestsrv-run.gone$' "$tree/docker.log" || fail "the containers of the abandoned run were not removed"
! grep -q 'run\.\(live\|none\|odd\)' "$tree/docker.log" || fail "the containers of a run that is not abandoned were removed"

echo 'test-acme-gate: ok'
