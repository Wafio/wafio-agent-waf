#!/usr/bin/env bash
# Makes the certificates and keys the tests of crates/control and the agent use, in crates/control/tests/fixtures:
# a certificate authority, a server certificate for localhost, a client certificate with an EC key and one with an
# RSA key. They are test data only and are not in git: every checkout makes its own set. The key of the authority
# is deleted once the three certificates are signed.
#
#   scripts/gen-test-certs.sh           makes the set when a file of it is missing
#   scripts/gen-test-certs.sh --force   makes a new set
#
# Needs openssl.
set -euo pipefail
cd "$(dirname "$0")/../crates/control/tests/fixtures"

files=(ca.crt server.crt server.key client.crt client.key client-rsa.crt client-rsa.key)
if [ "${1:-}" != --force ]; then
  missing=
  for f in "${files[@]}"; do [ -s "$f" ] || missing=1; done
  [ -n "$missing" ] || { echo 'gen-test-certs: the set is there'; exit 0; }
fi
command -v openssl >/dev/null || { echo 'gen-test-certs: openssl is not installed' >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
days=36500

openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/ca.key"
openssl req -x509 -new -key "$tmp/ca.key" -sha256 -days "$days" -subj '/CN=WAFio Test Agent CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -out "$tmp/ca.crt"

sign() { # sign <name> <common name> <extended key usage> [subjectAltName]
  local ext="$tmp/$1.ext"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=%s\n' "$3" > "$ext"
  [ -z "${4:-}" ] || printf 'subjectAltName=%s\n' "$4" >> "$ext"
  openssl req -new -key "$tmp/$1.key" -subj "/CN=$2" -out "$tmp/$1.csr"
  openssl x509 -req -in "$tmp/$1.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial -sha256 -days "$days" \
    -extfile "$ext" -out "$tmp/$1.crt" 2>/dev/null
}

openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/server.key"
sign server localhost serverAuth 'DNS:localhost,IP:127.0.0.1'
# The EC key is written in the SEC1 form (BEGIN EC PRIVATE KEY), the RSA keys in PKCS#8: the agent reads both.
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/client.key"
sign client waf-agent-test clientAuth
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/client-rsa.key"
sign client-rsa waf-agent-rsa clientAuth

for f in "${files[@]}"; do cp "$tmp/$f" "$f"; done
chmod 600 ./*.key
echo 'gen-test-certs: made a new set'
