#!/bin/sh
# The isolation stack's Postgres must refuse plaintext, and its certificate
# must verify only with the dev CA and only for the names it lists. Each
# check prints PASS or FAIL; the exit status is the result.
set -u
CREDENTIALS="kavach_auditor:kavach-isolation-auditor"
CA=/run/database-ca.pem
failures=0

check() {
  name=$1
  expect=$2
  url=$3
  if psql "$url" -Atqc 'select 1' > /tmp/probe.out 2>&1; then got=accepted; else got=refused; fi
  if [ "$got" = "$expect" ]; then
    echo "PASS $name ($got)"
  else
    echo "FAIL $name: expected $expect, got $got: $(head -c 300 /tmp/probe.out)"
    failures=$((failures + 1))
  fi
}

check "plaintext is refused by the server" refused \
  "postgresql://$CREDENTIALS@postgres:5432/kavach?sslmode=disable"
check "verify-full by name, with the dev CA" accepted \
  "postgresql://$CREDENTIALS@postgres:5432/kavach?sslmode=verify-full&sslrootcert=$CA"
check "verify-full by IP (listed on the certificate)" accepted \
  "postgresql://$CREDENTIALS@172.30.20.20:5432/kavach?sslmode=verify-full&sslrootcert=$CA"
check "a name not on the certificate is refused" refused \
  "postgresql://$CREDENTIALS@db-wrong-name:5432/kavach?sslmode=verify-full&sslrootcert=$CA"
check "a CA that did not sign the certificate is refused" refused \
  "postgresql://$CREDENTIALS@postgres:5432/kavach?sslmode=verify-full&sslrootcert=system"

echo "$failures checks failed"
[ "$failures" -eq 0 ]
