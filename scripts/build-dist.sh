#!/usr/bin/env bash
# Build the distributable pieces of the Rust WAF agent for linux/amd64 into target/dist/ of this checkout:
#
#   wafio-waf-agent-open-linux-amd64-baseline   release profile, stripped, any x86-64 CPU. This checkout builds the
#                                          agent without a detection engine, so the name says so and release.sh
#                                          refuses it. The official agent, with the engine, is built by the engine
#                                          repository (below) as wafio-waf-agent-linux-amd64-baseline, the file the
#                                          release bundle takes (wafio-release scripts/release.sh --waf-agent)
#   wafio-waf-agent-open-linux-amd64-v3    the same with -C target-cpu=x86-64-v3 (AVX2, BMI2, FMA:
#                                          Haswell / Zen and newer; it dies with SIGILL on older CPUs). Only
#                                          built when asked for; it is not part of a release
#   NOTICES.txt                            the notices of the crates the agent links, of the code adapted from other
#                                          projects and of the runtime data (scripts/gen-notices.py)
#   SHA256SUMS                             of the binaries this run built (not of older ones left in the directory)
#   VERSION                                the version this run stamped (wafio-release scripts/release.sh compares it
#                                          exactly with the release version)
#
# Without a flag it runs where cargo is, i.e. on the build host, and the binary needs the glibc of that host
# (fine for a development build, refused by wafio-release scripts/release.sh above its WAFIO_MAX_GLIBC).
# With --container it re-runs this same script inside a pinned old-glibc image (docker needed, no cargo): that is how
# a release input is built:
#
#   WAFIO_VERSION=v2.0.0 scripts/build-dist.sh --container
#   WAFIO_VERSION=v2.0.0 scripts/build-dist.sh --container baseline v3
#   WAFIO_VERSION=v2.0.0 scripts/build-dist.sh    # host glibc, dev only
#
# --musl builds a static binary with no glibc and no loader, in an Alpine based image with a native musl gcc. It is
# an option, not the release build. The file is <binary>-linux-amd64-<piece>-musl in target/dist-musl, so it
# never replaces a glibc build in target/dist.
#
# Environment:
#   WAFIO_VERSION    stamped into the agent (Hello `agent_version`, host info). Default dev, which
#                    wafio-release scripts/release.sh refuses.
#   WAFIO_DIST_DIR   output directory, default target/dist of this checkout (target/dist-musl with --musl). It is
#                    never under build/: on a shared build host build/ can be a link several checkouts
#                    use, so another checkout's build could replace the binary and the notices before a
#                    release copies them.
#   CARGO_FLAGS      default --locked: a stale Cargo.lock fails here instead of drifting; set it empty to let
#                    cargo refresh the lock.
#   CARGO_TARGET_DIR default target; each variant gets its own subdirectory because RUSTFLAGS differ. A container
#                    build keeps its objects in <CARGO_TARGET_DIR>/container (container-musl), apart from a host
#                    build: C objects compiled against another libc must never be linked into it.
#
# With --container or --musl:
#   WAFIO_CACHE_DIR  cargo home and rustup home, mounted into the container (default ~/.cache/wafio-dist). The
#                    pinned toolchain and the crates are downloaded into it once and reused.
#   WAFIO_DOCKER_ARGS extra words for docker run, for example '--cpuset-cpus 10,11,12 --cpus 3 --memory 8g'.
#   WAFIO_UDDIN_DIR  the checkout of uddin-lang-rs, mounted at /uddin-lang-rs (default: ../uddin-lang-rs next to this repository).
#   CARGO_BUILD_JOBS passed through; the build runs under nice.
#   WAFIO_PASS_ENV   names (space separated) of environment variables to hand to the container, for a build that reads a
#                    value at compile time. Only the names are given to docker; the values are copied from this
#                    environment and never appear on a command line.
#
# Paths in the files. cargo does not strip: this script strips the files that ship, so that the unstripped library can be
# kept (WAFIO_DEBUG_DIR). What a shipped file still says about the build host is the paths in its panic locations and
# file!() strings, and --remap-path-prefix turns them into short tokens: the checkout of the workspace into w, this one
# (its crates directory too) into o, the cargo target directory (generated sources) into b, the cargo home (registry sources)
# into c, the Rust toolchain into t, uddin-lang-rs into u.
# When the workspace is not this checkout, each of its crates/*/src/**/*.rs files becomes p001, p002, ... in sorted order, so
# that no source file name of that workspace is in the binary. The debug info keeps the real paths (--remap-path-scope=macro).
# Not reachable with a flag: the standard library is precompiled, and its panic locations (/rustc/<commit>/library/...,
# /rust/deps/...) stay in every binary.
#
#   WAFIO_DEBUG_DIR  where the unstripped copy of the engine library is kept (default ~/wr/debug on the build host; with
#                    --container the directory is mounted at /debug). It must not be the output directory or inside it:
#                    the copy is for the people who read crashes, never for a bundle. It holds
#                      <build id>.debug   the library as linked, with line tables and symbols
#                      <build id>.paths   the token and the real path of every remapped source file
#                    The build id is the one of the shipped file (readelf -n). To resolve a crash address of a shipped
#                    library, the offset in the file, and a panic location pNNN:line:column:
#                      addr2line -f -C -i -e ~/wr/debug/<build id>.debug <address>
#                      grep '^pNNN' ~/wr/debug/<build id>.paths
#
# The official agent: the engine repository (wafio-semantic-engine) has its own scripts/build-dist.sh, which runs this
# script over its workspace. It sets
#   WAFIO_WORKSPACE_DIR  the checkout whose Cargo workspace is built (default: this one). A container build mounts it at
#                        /src and this checkout at /wafio-agent-waf, next to each other as on the host.
#   WAFIO_BIN_PACKAGE    the package that holds the binary (default wafio-waf-agent)
#   WAFIO_BIN_NAME       the binary and the name of the files in the output (default wafio-waf-agent-open)
#   WAFIO_NOTICES_SCRIPT the script that writes NOTICES.txt (default scripts/gen-notices.py of this checkout)
#   WAFIO_LIB_PACKAGE    a package that builds the engine library (a cdylib), built with each piece next to the binary; with
#   WAFIO_LIB_FILE       the file cargo writes for it (lib<crate>.so) and
#   WAFIO_LIB_NAME       the name of the files in the output: <name>-linux-amd64-<piece>.so. All three or none. A static
#                        musl build cannot load a library, so --musl refuses them.
#
# Not a release: nothing is signed, uploaded or installed. The gnu target links the C library of the build
# host dynamically and needs the glibc symbol versions printed below (the highest one is the floor): a host
# with an older glibc cannot start it, and the bundle installers refuse such a host. The image of --container
# is AlmaLinux 8 (glibc 2.28, gcc 14), so the floor of its binary is the one of that image.
set -euo pipefail
open_root=$(cd "$(dirname "$0")/.." && pwd)
root=${WAFIO_WORKSPACE_DIR:-$open_root}
cd "$root"
package=${WAFIO_BIN_PACKAGE:-wafio-waf-agent}
bin=${WAFIO_BIN_NAME:-wafio-waf-agent-open}
notices=${WAFIO_NOTICES_SCRIPT:-$open_root/scripts/gen-notices.py}
lib_package=${WAFIO_LIB_PACKAGE:-}
lib_file=${WAFIO_LIB_FILE:-}
lib_name=${WAFIO_LIB_NAME:-}

# Pinned: images by digest (quay.io/pypa/manylinux_2_28_x86_64:2026.11.14-1 and rust:1.95.0-alpine3.23) and
# rustup-init by version and hash. The Rust version is the channel of rust-toolchain.toml: the glibc image installs
# it with rustup, the musl image carries it and the script stops when the two differ. A new image is a new digest
# here, in one commit.
image=quay.io/pypa/manylinux_2_28_x86_64@sha256:d086f64cddcace250ef0f0073583c51b8298159303290a730c9f59bd91edfd2c
musl_image=rust@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2
rustup_version=1.29.3
rustup_sha256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55

use_container=
musl=${WAFIO_MUSL:-}
while [ "${1:-}" = --container ] || [ "${1:-}" = --musl ]; do
  use_container=1
  [ "$1" != --musl ] || musl=1
  shift
done

{ [ -z "$lib_package$lib_file$lib_name" ] || { [ -n "$lib_package" ] && [ -n "$lib_file" ] && [ -n "$lib_name" ]; }; } || {
  echo "build-dist.sh: WAFIO_LIB_PACKAGE, WAFIO_LIB_FILE and WAFIO_LIB_NAME go together" >&2
  exit 2
}
[ -z "$lib_package" ] || [ -z "$musl" ] || {
  echo "build-dist.sh: a static musl build cannot load the engine library; build the glibc form" >&2
  exit 2
}
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || {
  echo "build-dist.sh: needs a linux/x86_64 host" >&2
  exit 1
}

suffix=${musl:+-musl}
out=${WAFIO_DIST_DIR:-$PWD/target/dist$suffix}
debug_dir=${WAFIO_DEBUG_DIR:-$HOME/wr/debug}
target=${CARGO_TARGET_DIR:-$PWD/target}
cargo_flags=${CARGO_FLAGS---locked}
export WAFIO_AGENT_VERSION=${WAFIO_VERSION:-dev}
case $debug_dir in /*) ;; *) echo "build-dist.sh: WAFIO_DEBUG_DIR must be an absolute path" >&2; exit 2 ;; esac
case $debug_dir/ in "$out"/*) echo "build-dist.sh: WAFIO_DEBUG_DIR must not be inside the output directory $out" >&2; exit 2 ;; esac

if [ -n "$use_container" ]; then
  command -v docker >/dev/null || { echo "build-dist.sh: --container needs docker" >&2; exit 1; }
  cache=${WAFIO_CACHE_DIR:-$HOME/.cache/wafio-dist}
  mkdir -p "$cache" "$out" "$target/container$suffix"
  # The checkout is mounted read-only at /src, so paths in the binary do not depend on the host. When it is not this
  # checkout, this one sits next to it at /wafio-agent-waf, where the path dependencies look for it.
  mounts=(-v "$root:/src:ro")
  here=/src
  script=/src/scripts/build-dist.sh
  notices_in=${notices/#$root//src}
  if [ "$root" != "$open_root" ]; then
    mounts+=(-v "$open_root:/wafio-agent-waf:ro")
    here=/wafio-agent-waf
    script=/wafio-agent-waf/scripts/build-dist.sh
    notices_in=${notices_in/#$open_root//wafio-agent-waf}
  fi
  # The script interpreter is a path dependency next to the open checkout (../uddin-lang-rs); in the container that is /uddin-lang-rs.
  uddin=${WAFIO_UDDIN_DIR:-$(dirname "$open_root")/uddin-lang-rs}
  [ -f "$uddin/Cargo.toml" ] || { echo "build-dist.sh: no checkout of uddin-lang-rs at $uddin (WAFIO_UDDIN_DIR)" >&2; exit 1; }
  mounts+=(-v "$uddin:/uddin-lang-rs:ro")
  if [ -n "$lib_package" ]; then
    mkdir -p "$debug_dir"
    mounts+=(-v "$debug_dir:/debug")
  fi
  common=(--rm --platform linux/amd64 "${mounts[@]}" -v "$cache:/cache" -v "$out:/dist" -v "$target/container$suffix:/target" -w /src
    -e WAFIO_IN_CONTAINER=1 -e "WAFIO_MUSL=$musl" -e HOME=/cache/home -e WAFIO_DIST_DIR=/dist -e WAFIO_DEBUG_DIR=/debug -e CARGO_TARGET_DIR=/target
    -e WAFIO_WORKSPACE_DIR=/src -e "WAFIO_BIN_PACKAGE=$package" -e "WAFIO_BIN_NAME=$bin" -e "WAFIO_NOTICES_SCRIPT=$notices_in"
    -e "WAFIO_LIB_PACKAGE=$lib_package" -e "WAFIO_LIB_FILE=$lib_file" -e "WAFIO_LIB_NAME=$lib_name"
    -e "WAFIO_VERSION=${WAFIO_VERSION:-dev}" -e "CARGO_FLAGS=$cargo_flags" -e CARGO_BUILD_JOBS)
  # Variables named in WAFIO_PASS_ENV go in by name, so their values stay off the docker command line.
  for name in ${WAFIO_PASS_ENV:-}; do
    [[ $name =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo "build-dist.sh: WAFIO_PASS_ENV: '$name' is not a variable name" >&2; exit 2; }
    common+=(-e "$name")
  done
  # shellcheck disable=SC2206 # WAFIO_DOCKER_ARGS is a word list
  extra=(${WAFIO_DOCKER_ARGS:-})
  if [ -z "$musl" ]; then
    exec docker run "${common[@]}" --user "$(id -u):$(id -g)" ${extra[@]+"${extra[@]}"} \
      "$image" nice -n 10 bash "$script" "$@"
  fi
  # The Alpine image has no bash, python or cmake. It starts as root, installs them with apk (the compiler and the
  # libc stay the ones of the image) and gives the files it wrote back to the calling user when it ends.
  exec docker run "${common[@]}" -e "WAFIO_OWNER=$(id -u):$(id -g)" ${extra[@]+"${extra[@]}"} \
    "$musl_image" sh -c 'apk add --no-cache bash cmake make python3 >/dev/null && exec nice -n 10 bash "$0" "$@"' "$script" "$@"
fi

if [ -n "${WAFIO_IN_CONTAINER:-}" ]; then
  mkdir -p "$HOME"
  channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)
  [ -n "$channel" ] || { echo "build-dist.sh: no channel in rust-toolchain.toml" >&2; exit 1; }
  # RUSTUP_TOOLCHAIN makes rustup ignore the component list of rust-toolchain.toml.
  export RUSTUP_TOOLCHAIN=$channel CARGO_HOME=/cache/cargo
  if [ -n "$musl" ]; then
    [ -d "${RUSTUP_HOME:-/usr/local/rustup}/toolchains/$channel-x86_64-unknown-linux-musl" ] || {
      echo "build-dist.sh: the image has no Rust $channel (rust-toolchain.toml); pin an image of that version" >&2
      exit 1
    }
    trap 'chown -R "$WAFIO_OWNER" /dist /target /cache' EXIT
  else
    export RUSTUP_HOME=/cache/rustup PATH=/cache/cargo/bin:$PATH
    if [ ! -x "$CARGO_HOME/bin/rustup" ]; then
      init=$HOME/rustup-init
      curl -fsSL -o "$init" "https://static.rust-lang.org/rustup/archive/$rustup_version/x86_64-unknown-linux-gnu/rustup-init"
      echo "$rustup_sha256  $init" | sha256sum -c -
      chmod +x "$init"
      "$init" -y --no-modify-path --profile minimal --default-toolchain none
      rm -f "$init"
    fi
    rustup toolchain install "$channel" --profile minimal --no-self-update
  fi
fi

mkdir -p "$out"
built=() # the files this run produced: SHA256SUMS lists these and nothing else

# The --remap-path-prefix flags (see the header) in $remap, and in $path_map the token and path of each source file of a
# workspace that is not this checkout. rustc takes the last flag that matches, so the files come after the directories.
remap=(--remap-path-scope=macro)
if [ -n "${WAFIO_IN_CONTAINER:-}" ]; then uddin_dir=/uddin-lang-rs; else uddin_dir=${WAFIO_UDDIN_DIR:-$(dirname "$open_root")/uddin-lang-rs}; fi
rustc_commit=$(rustc -vV | sed -n 's/^commit-hash: //p')
for pair in "$root=w" "$target=b" "$open_root=o" "$open_root/crates=o" "${CARGO_HOME:-$HOME/.cargo}=c" "$(rustc --print sysroot)=t" "/rustc/$rustc_commit=t" /rust/deps=t "$uddin_dir=u"; do
  remap+=("--remap-path-prefix=$pair")
done
path_map=
if [ "$root" != "$open_root" ]; then
  n=0
  while IFS= read -r f; do
    n=$((n + 1))
    tok=$(printf 'p%03d' "$n")
    # cargo gives rustc the path of a member of the workspace relative to the workspace root
    remap+=("--remap-path-prefix=$f=$tok" "--remap-path-prefix=$root/$f=$tok")
    path_map+=$tok$'\t'$f$'\n'
  done < <(LC_ALL=C find crates -path '*/src/*' -name '*.rs' | LC_ALL=C sort)
fi

# rustflags CPU: the flags of one piece for CARGO_ENCODED_RUSTFLAGS, which keeps a space in a path from splitting a flag.
rustflags() {
  local flags=(-C "target-cpu=$1" -C link-arg=-Wl,--build-id=sha1 "${remap[@]}")
  local IFS=$'\037'
  printf '%s' "${flags[*]}"
}

# keep_debug FILE: FILE as linked, with its symbols and line tables, and the token map, in the debug directory under the
# build id that FILE keeps when it is stripped.
keep_debug() {
  local id
  id=$(readelf -n "$1" | sed -n 's/^ *Build ID: *//p')
  [ -n "$id" ] || { echo "build-dist.sh: $1 has no build id" >&2; exit 1; }
  mkdir -p "$debug_dir"
  install -m 0644 "$1" "$debug_dir/$id.debug"
  printf '%s' "$path_map" >"$debug_dir/$id.paths"
  echo "[dist]   unstripped copy kept as $id.debug"
}

# agent NAME CPU: a release build with its own target directory. cargo does not strip; install -s does, on the copy that ships.
agent() {
  local file=$bin-linux-amd64-$1$suffix
  echo "[dist] $bin $1 (target-cpu=$2, version $WAFIO_AGENT_VERSION)"
  # shellcheck disable=SC2086 # CARGO_FLAGS is a word list
  CARGO_TARGET_DIR="$target/dist-$1" CARGO_ENCODED_RUSTFLAGS=$(rustflags "$2") CARGO_PROFILE_RELEASE_STRIP=none \
    cargo build --release $cargo_flags --manifest-path Cargo.toml -p "$package"
  install -s -m 0755 "$target/dist-$1/release/$bin" "$out/$file"
  built+=("$file")
  glibc_floor "$file"
  if [ -n "$lib_package" ]; then
    local libfile=$lib_name-linux-amd64-$1.so
    echo "[dist] $lib_name $1 (target-cpu=$2, version $WAFIO_AGENT_VERSION)"
    # shellcheck disable=SC2086 # CARGO_FLAGS is a word list
    CARGO_TARGET_DIR="$target/dist-$1" CARGO_ENCODED_RUSTFLAGS=$(rustflags "$2") CARGO_PROFILE_RELEASE_STRIP=none \
      cargo build --release $cargo_flags --manifest-path Cargo.toml -p "$lib_package"
    keep_debug "$target/dist-$1/release/$lib_file"
    install -s -m 0644 "$target/dist-$1/release/$lib_file" "$out/$libfile"
    built+=("$libfile")
    glibc_floor "$libfile"
  fi
}

# glibc_floor FILE: the highest glibc symbol version a file in the output directory names.
glibc_floor() {
  if command -v objdump >/dev/null; then
    local floor
    floor=$(objdump -T "$out/$1" 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -1 || true)
    if [ -n "$floor" ]; then echo "[dist]   needs glibc >= $floor"; else echo "[dist]   names no glibc version"; fi
  fi
}

for what in "${@:-baseline}"; do
  for w in $what; do
    case $w in
      baseline) agent baseline x86-64 ;;
      v3) agent v3 x86-64-v3 ;;
      *) echo "build-dist.sh: unknown piece '$w' (baseline, v3)" >&2; exit 2 ;;
    esac
  done
done

python3 "$notices" -o "$out/NOTICES.txt"

printf '%s\n' "$WAFIO_AGENT_VERSION" >"$out/VERSION"
(cd "$out" && rm -f SHA256SUMS && sha256sum "${built[@]}" >SHA256SUMS && cat SHA256SUMS)
