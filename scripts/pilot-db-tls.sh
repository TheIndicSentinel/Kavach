#!/usr/bin/env bash
# Creates the TLS certificate the pilot stack's Postgres serves, and the CA
# that Kavach verifies it with (sslmode=verify-full).
#
#   scripts/pilot-db-tls.sh [out-dir]    # default: deploy/pilot-db-tls
#
# Writes server.crt and server.key (for Postgres only) and ca.pem (for
# kavach-api and kavach-batch). The certificate names the compose service
# "postgres". The CA's private key is deleted once the certificate is
# signed: to rotate, create a new directory and restart the stack.
#
# A bank with its own PKI should issue the server certificate from it
# instead, and put that CA's certificate in ca.pem.
set -euo pipefail

out=${1:-deploy/pilot-db-tls}
if [[ -e "$out/server.key" || -e "$out/ca.pem" ]]; then
  echo "refusing to overwrite: $out already holds a certificate" >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

mkdir -p "$out"
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
  -subj "/CN=Kavach pilot database CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$work/ca.key" -out "$out/ca.pem" 2>/dev/null

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=postgres" -keyout "$out/server.key" -out "$work/server.csr" 2>/dev/null

printf 'subjectAltName=DNS:postgres\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n' \
  > "$work/server.ext"
openssl x509 -req -in "$work/server.csr" -CA "$out/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -CAserial "$work/ca.srl" -days 825 -extfile "$work/server.ext" \
  -out "$out/server.crt" 2>/dev/null

chmod 0644 "$out/ca.pem" "$out/server.crt"
chmod 0600 "$out/server.key"
openssl verify -CAfile "$out/ca.pem" "$out/server.crt" >/dev/null
echo "wrote $out/server.crt, $out/server.key (Postgres) and $out/ca.pem (Kavach); the CA key was not kept"
