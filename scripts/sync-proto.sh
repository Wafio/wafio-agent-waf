#!/usr/bin/env bash
# The agent protocol proto is owned by wafio-cp-backend (shared/proto) and vendored here, so the
# Rust build needs no second checkout. proto/SOURCE records where the copy came from.
#
#   scripts/sync-proto.sh <tag>    copy the file as of <tag> from the wafio-cp-backend checkout and rewrite proto/SOURCE
#   scripts/sync-proto.sh --check  proto/SOURCE matches the file; when the checkout exists, the file matches it too
#
# WAFIO_CP_BACKEND: path of the wafio-cp-backend checkout (default ../wafio-cp-backend).
set -euo pipefail
cd "$(dirname "$0")/.."

rel=shared/proto/agent/v1/agent_control.proto
dst=proto/agent/v1/agent_control.proto
cp_dir=${WAFIO_CP_BACKEND:-../wafio-cp-backend}

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
src_value() { sed -n "s/^$1: //p" proto/SOURCE; }

case "${1:-}" in
  --check)
    [ "$(src_value sha256)" = "$(sha "$dst")" ] || { echo "sync-proto: $dst differs from the sha256 in proto/SOURCE" >&2; exit 1; }
    if [ -d "$cp_dir/.git" ]; then
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
    echo "sync-proto: $dst now as of $tag"
    ;;
esac
