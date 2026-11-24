#!/usr/bin/env bash
# The agent protocol proto is owned by wafio-cp-backend (shared/proto) and vendored here, so the
# Rust build needs no second checkout. proto/SOURCE records where the copy came from.
#
#   scripts/sync-proto.sh <tag>    copy the file as of <tag> and the fixtures from the wafio-cp-backend checkout and rewrite proto/SOURCE
#   scripts/sync-proto.sh --check  proto/SOURCE matches the file and the fixtures; when the checkout exists, they match it too
#
# The fixtures are the files of test/frontend-fixtures that the agent tests read, copied as the checkout has them (they are not
# tied to a tag). proto/SOURCE holds the sha256 of each, so a gate on a host without the checkout still sees an edited copy.
# WAFIO_CP_BACKEND: path of the wafio-cp-backend checkout (default ../wafio-cp-backend).
set -euo pipefail
cd "$(dirname "$0")/.."

rel=shared/proto/agent/v1/agent_control.proto
dst=proto/agent/v1/agent_control.proto
cp_dir=${WAFIO_CP_BACKEND:-../wafio-cp-backend}
fixture_src=test/frontend-fixtures
fixture_dst=crates/proxy/tests/data
fixtures=(trace-keep-names.json)

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
src_value() { sed -n "s/^$1: //p" proto/SOURCE; }
# The sha256 proto/SOURCE records for fixture $1 (empty when it records none).
fixture_sha() { sed -n "s/^fixture: $1 //p" proto/SOURCE; }

case "${1:-}" in
  --check)
    [ "$(src_value sha256)" = "$(sha "$dst")" ] || { echo "sync-proto: $dst differs from the sha256 in proto/SOURCE" >&2; exit 1; }
    for f in "${fixtures[@]}"; do
      [ "$(fixture_sha "$f")" = "$(sha "$fixture_dst/$f")" ] || { echo "sync-proto: $fixture_dst/$f differs from the sha256 in proto/SOURCE" >&2; exit 1; }
    done
    if [ -d "$cp_dir/.git" ]; then
      for f in "${fixtures[@]}"; do
        cmp "$cp_dir/$fixture_src/$f" "$fixture_dst/$f" || { echo "sync-proto: $fixture_dst/$f differs from $cp_dir/$fixture_src/$f" >&2; exit 1; }
      done
      tag=$(src_value tag)
      if git -C "$cp_dir" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
        git -C "$cp_dir" show "$tag:$rel" | cmp - "$dst" || { echo "sync-proto: $dst differs from $tag" >&2; exit 1; }
      else
        echo "sync-proto: tag $tag not in $cp_dir, comparing with its working tree" >&2
        cmp "$cp_dir/$rel" "$dst" || { echo "sync-proto: $dst differs from $cp_dir/$rel" >&2; exit 1; }
      fi
    else
      echo "sync-proto: no checkout at $cp_dir, only proto/SOURCE was checked" >&2
    fi
    echo 'sync-proto: ok'
    ;;
  '' | -*)
    echo 'usage: scripts/sync-proto.sh <tag> | --check' >&2
    exit 2
    ;;
  *)
    tag=$1
    git -C "$cp_dir" show "$tag:$rel" >"$dst"
    printf '# Vendored copy; scripts/sync-proto.sh <tag> rewrites this file.\nrepo: Wafio/wafio-cp-backend\npath: %s\ntag: %s\nsha256: %s\n' "$rel" "$tag" "$(sha "$dst")" >proto/SOURCE
    for f in "${fixtures[@]}"; do
      cp "$cp_dir/$fixture_src/$f" "$fixture_dst/$f"
      printf 'fixture: %s %s\n' "$f" "$(sha "$fixture_dst/$f")" >>proto/SOURCE
    done
    echo "sync-proto: $dst now as of $tag"
    ;;
esac
