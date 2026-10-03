#!/usr/bin/env bash
# Prepares a throw-away SoftHSM2 token for the kavach-keys-pkcs11 tests and
# prints the environment they need (SOFTHSM2_CONF), one NAME=value per line,
# ready for $GITHUB_ENV or `export`. The token holds nothing until the tests
# make their own keys in it.
#
#   eval "export $(scripts/softhsm-test-token.sh /tmp/kavach-softhsm)"
#   KAVACH_TEST_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
#     cargo test -p kavach-keys-pkcs11
set -euo pipefail

dir=${1:-$(mktemp -d)}
mkdir -p "$dir/tokens"
conf="$dir/softhsm2.conf"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$dir" >"$conf"
SOFTHSM2_CONF="$conf" softhsm2-util --init-token --free --label kavach-test \
  --so-pin 0000 --pin 1234 >/dev/null
echo "SOFTHSM2_CONF=$conf"
