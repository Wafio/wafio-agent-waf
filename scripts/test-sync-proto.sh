#!/usr/bin/env bash
# Checks scripts/sync-proto.sh on a copy of its layout and a throwaway wafio-cp-backend checkout: a sync records the sha256 of the
# proto and of each fixture, --check passes after it, and fails for an edited proto, an edited fixture copy, a fixture that differs
# from or is missing in the checkout, and a proto that differs from its tag; without a checkout only the recorded sha256 values
# are compared.
set -euo pipefail
here=${0%/*}
[ "$here" != "$0" ] || here=.
cd "$here/.."

tree=$(mktemp -d)
trap 'rm -rf "$tree"' EXIT
agent=$tree/agent
cp_dir=$tree/cp
mkdir -p "$agent/scripts" "$agent/proto/agent/v1" "$agent/crates/proxy/tests/data"
cp scripts/sync-proto.sh "$agent/scripts/"
mkdir -p "$cp_dir/shared/proto/agent/v1" "$cp_dir/test/frontend-fixtures"
echo 'syntax = "proto3";' >"$cp_dir/shared/proto/agent/v1/agent_control.proto"
echo '{".bashrc":1}' >"$cp_dir/test/frontend-fixtures/trace-keep-names.json"
echo '{"strip_path_prefix":[]}' >"$cp_dir/test/frontend-fixtures/delivery-checks.json"
git -C "$cp_dir" init -q
git -C "$cp_dir" add -A
git -C "$cp_dir" -c user.name=t -c user.email=t@example.com commit -q -m fixtures
git -C "$cp_dir" tag shared/v9.9.9

sync() { WAFIO_CP_BACKEND=$cp_dir "$agent/scripts/sync-proto.sh" "$@" 2>&1; }
fail() {
  echo "test-sync-proto: $1" >&2
  exit 1
}
passes() { sync --check >/dev/null || fail "$1: --check failed"; }
refuses() { # refuses <message part> <what happened>
  local out
  if out=$(sync --check); then fail "$2: --check passed"; fi
  case $out in *"$1"*) ;; *) fail "$2: no '$1' in: $out" ;; esac
}

sync shared/v9.9.9 >/dev/null
passes 'after a sync'
grep -q '^tag: shared/v9.9.9$' "$agent/proto/SOURCE" || fail 'the tag is not recorded'
for f in trace-keep-names.json delivery-checks.json; do
  grep -q "^fixture: $f [0-9a-f]\{64\}\$" "$agent/proto/SOURCE" || fail "the sha256 of $f is not recorded"
done

fixture=$agent/crates/proxy/tests/data/trace-keep-names.json
saved=$(cat "$fixture")
echo ' ' >>"$fixture"
refuses 'differs from the sha256 in proto/SOURCE' 'an edited fixture copy'
echo "$saved" >"$fixture"
passes 'a restored fixture copy'

second=$agent/crates/proxy/tests/data/delivery-checks.json
echo ' ' >>"$second"
refuses 'delivery-checks.json differs from the sha256 in proto/SOURCE' 'an edited second fixture copy'
echo '{"strip_path_prefix":[]}' >"$second"
passes 'a restored second fixture copy'

echo '// edited' >>"$agent/proto/agent/v1/agent_control.proto"
refuses 'differs from the sha256 in proto/SOURCE' 'an edited proto'
sync shared/v9.9.9 >/dev/null

echo '{".bashrc":2}' >"$cp_dir/test/frontend-fixtures/trace-keep-names.json"
refuses 'trace-keep-names.json differs from' 'a fixture that changed in the checkout'
echo '{".bashrc":1}' >"$cp_dir/test/frontend-fixtures/trace-keep-names.json"
passes 'a checkout fixture put back'

echo '{"strip_path_prefix":[1]}' >"$cp_dir/test/frontend-fixtures/delivery-checks.json"
refuses 'delivery-checks.json differs from' 'a second fixture that changed in the checkout'
echo '{"strip_path_prefix":[]}' >"$cp_dir/test/frontend-fixtures/delivery-checks.json"
passes 'a second checkout fixture put back'

# A fixture the checkout lacks: a copy of a file that is not merged there yet, or one that was renamed.
mv "$cp_dir/test/frontend-fixtures/delivery-checks.json" "$cp_dir/delivery-checks.json.away"
refuses 'delivery-checks.json' 'a fixture missing from the checkout'
mv "$cp_dir/delivery-checks.json.away" "$cp_dir/test/frontend-fixtures/delivery-checks.json"
passes 'a fixture back in the checkout'

# A copy that matches its recorded sha256 but is not the file at its tag (someone edited both).
echo '// edited' >>"$agent/proto/agent/v1/agent_control.proto"
sha=$(sha256sum "$agent/proto/agent/v1/agent_control.proto" | cut -d' ' -f1)
sed -i.bak "s/^sha256: .*/sha256: $sha/" "$agent/proto/SOURCE"
refuses 'differs from shared/v9.9.9' 'a proto that is not the file at its tag'

# A worktree of the checkout has a .git file, not a directory, and is a checkout all the same.
git -C "$cp_dir" worktree add -q "$tree/wt" -b other
echo '{".bashrc":3}' >"$tree/wt/test/frontend-fixtures/trace-keep-names.json"
if out=$(WAFIO_CP_BACKEND=$tree/wt "$agent/scripts/sync-proto.sh" --check 2>&1); then fail 'a worktree was not compared: --check passed'; fi
case $out in *'trace-keep-names.json differs from'*) ;; *) fail "a worktree was not compared: $out" ;; esac

rm -rf "$cp_dir/.git"
out=$(sync --check) || fail 'a missing checkout failed the check'
case $out in *'only proto/SOURCE was checked'*) ;; *) fail "a missing checkout was not said: $out" ;; esac
echo 'test-sync-proto: ok'
