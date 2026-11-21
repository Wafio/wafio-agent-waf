#!/usr/bin/env bash
# Starts and stops Pebble, the ACME test server of Let's Encrypt, and pebble-challtestsrv, the DNS server it
# looks names up with, for the tests that order certificates from a real ACME server.
#
#   eval "$(scripts/pebble.sh up)"     starts both and sets what the tests read
#   scripts/pebble.sh down [RUN]       stops them (RUN is the run directory, default $WAFIO_PEBBLE_RUN)
#   scripts/pebble.sh down --all       stops every run of this user
#
# `up` prints these as `export` lines:
#   WAFIO_PEBBLE_DIRECTORY   the ACME directory (https; its certificate is signed by WAFIO_PEBBLE_ROOT)
#   WAFIO_PEBBLE_ROOT        the root certificate to trust for it (the tests give it to the agent as SSL_CERT_FILE)
#   WAFIO_PEBBLE_HTTP_PORT   the port Pebble connects to for an HTTP-01 validation
#   WAFIO_PEBBLE_TLS_PORT    the port Pebble connects to for a TLS-ALPN-01 validation
#   WAFIO_PEBBLE_RUN         the run directory, for `down`
# Pebble connects to every name at 127.0.0.1: the DNS server answers all names with that address, and gives no IPv6 one.
# The two validation ports are the ones the test's agent listens on; nothing here binds them.
#
# Both run from images pinned by digest, on the host network, with the ports of this run chosen free under a lock, so
# that runs started together do not meet. Certificates last two minutes. These variables of the caller are passed to
# Pebble as they are: PEBBLE_VA_NOSLEEP (default 1), PEBBLE_AUTHZREUSE (default 0), PEBBLE_VA_SLEEPTIME and any other
# PEBBLE_*. PEBBLE_WFE_NONCEREJECT is always 0: a nonce Pebble refuses at random makes a run that cannot be repeated.
#
# Needs docker (the user in the docker group), python3 and curl.
set -euo pipefail

pebble=ghcr.io/letsencrypt/pebble:2.10.3@sha256:0c81f05db371f436c97fb894bd6d2ab8fc9c8e2ce40f8bef8a8e15941bcd75ef
challtestsrv=ghcr.io/letsencrypt/pebble-challtestsrv:2.10.3@sha256:0152c8cb506e2ecba2900ed47d23932e27e3e6575a7d2c8ef93c7719ee3dea4c
base=${WAFIO_PEBBLE_STATE:-${XDG_RUNTIME_DIR:-/tmp}/wafio-pebble-$(id -u)}

down() {
  local run=$1 name
  name=$(basename "$run")
  docker rm -f "wafio-pebble-$name" "wafio-challtestsrv-$name" >/dev/null 2>&1 || true
  rm -rf "$run"
}

up() {
  mkdir -p "$base"
  chmod 700 "$base"
  local run
  run=$(mktemp -d "$base/run.XXXXXX")
  local name
  name=$(basename "$run")
  # Ports are picked and the containers started with the lock held, so that the next run picks others.
  exec 9>"$base/lock"
  flock 9
  local ports directory management dns challenge http tls
  # Six ports, free on TCP and UDP, held until all are chosen.
  ports=$(python3 - <<'PY'
import socket
held, ports = [], []
while len(ports) < 6:
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    port = tcp.getsockname()[1]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp.bind(("127.0.0.1", port))
    except OSError:
        tcp.close()
        continue
    held += [tcp, udp]
    ports.append(port)
print(*ports)
PY
  )
  read -r directory management dns challenge http tls <<<"$ports"

  cat >"$run/pebble-config.json" <<JSON
{
  "pebble": {
    "listenAddress": "127.0.0.1:$directory",
    "managementListenAddress": "127.0.0.1:$management",
    "certificate": "/test/certs/localhost/cert.pem",
    "privateKey": "/test/certs/localhost/key.pem",
    "httpPort": $http,
    "tlsPort": $tls,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "domainBlocklist": [],
    "retryAfter": {"authz": 1, "order": 1},
    "keyAlgorithm": "ecdsa",
    "profiles": {
      "default": {"description": "Certificates that last two minutes", "validityPeriod": 120}
    }
  }
}
JSON
  # The root that signs Pebble's own certificate, out of the image.
  local box
  box=$(docker create "$pebble")
  docker cp "$box:/test/certs/pebble.minica.pem" "$run/root.pem" >/dev/null
  docker rm "$box" >/dev/null

  docker run -d --rm --network host --name "wafio-challtestsrv-$name" "$challtestsrv" \
    -dnsserver "127.0.0.1:$dns" -management "127.0.0.1:$challenge" \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" -defaultIPv6 "" >/dev/null

  local env=(-e PEBBLE_WFE_NONCEREJECT=0 -e "PEBBLE_VA_NOSLEEP=${PEBBLE_VA_NOSLEEP:-1}" -e "PEBBLE_AUTHZREUSE=${PEBBLE_AUTHZREUSE:-0}")
  local var
  for var in $(compgen -e | grep '^PEBBLE_' | grep -v -e '^PEBBLE_WFE_NONCEREJECT$' -e '^PEBBLE_VA_NOSLEEP$' -e '^PEBBLE_AUTHZREUSE$'); do
    env+=(-e "$var=${!var}")
  done
  docker run -d --rm --network host --name "wafio-pebble-$name" "${env[@]}" \
    -v "$run/pebble-config.json:/config/pebble-config.json:ro" "$pebble" \
    -config /config/pebble-config.json -dnsserver "127.0.0.1:$dns" >/dev/null

  local i
  for i in $(seq 1 60); do
    if curl -sf --cacert "$run/root.pem" "https://localhost:$directory/dir" >/dev/null 2>&1; then
      printf 'export WAFIO_PEBBLE_RUN=%q\n' "$run"
      printf 'export WAFIO_PEBBLE_DIRECTORY=%q\n' "https://localhost:$directory/dir"
      printf 'export WAFIO_PEBBLE_ROOT=%q\n' "$run/root.pem"
      printf 'export WAFIO_PEBBLE_HTTP_PORT=%q\n' "$http"
      printf 'export WAFIO_PEBBLE_TLS_PORT=%q\n' "$tls"
      return 0
    fi
    sleep 0.5
  done
  docker logs "wafio-pebble-$name" >&2 || true
  down "$run"
  echo "pebble.sh: Pebble did not answer at https://localhost:$directory/dir" >&2
  return 1
}

case "${1:-}" in
  up) up ;;
  down)
    case "${2:-${WAFIO_PEBBLE_RUN:-}}" in
      --all)
        for run in "$base"/run.*; do [ -d "$run" ] && down "$run"; done
        ;;
      '') echo 'pebble.sh down: name the run (or set WAFIO_PEBBLE_RUN), or use --all' >&2; exit 2 ;;
      *) down "${2:-$WAFIO_PEBBLE_RUN}" ;;
    esac
    ;;
  *) echo 'usage: pebble.sh up | down [RUN | --all]' >&2; exit 2 ;;
esac
