#!/usr/bin/env bash
# Checks that this machine's SoftHSM2 can do what the PKCS#11 key provider
# needs (KMS milestone, K1): Ed25519 keys generated inside the token
# (CKM_EC_EDWARDS_KEY_PAIR_GEN), never extractable, signing with CKM_EDDSA,
# and a signature that verifies outside the HSM. Exits non-zero otherwise.
#
# Uses a throw-away token in a temporary directory; no key leaves it.
set -euo pipefail

module=${SOFTHSM2_MODULE:-/usr/lib/softhsm/libsofthsm2.so}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export SOFTHSM2_CONF="$work/softhsm2.conf"
mkdir "$work/tokens"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' "$work" >"$SOFTHSM2_CONF"

softhsm2-util --version
softhsm2-util --init-token --free --label kavach-probe --so-pin 0000 --pin 1234 >/dev/null
p11() { pkcs11-tool --module "$module" --token-label kavach-probe --login --pin 1234 "$@"; }

echo "--- mechanisms"
pkcs11-tool --module "$module" --list-mechanisms --token-label kavach-probe | tee "$work/mechs"
grep -q "EC-EDWARDS-KEY-PAIR-GEN" "$work/mechs" || { echo "FAIL: no CKM_EC_EDWARDS_KEY_PAIR_GEN"; exit 1; }
grep -qE "^ *EDDSA" "$work/mechs" || { echo "FAIL: no CKM_EDDSA"; exit 1; }

echo "--- Ed25519 key generated in the token"
p11 --keypairgen --key-type EC:edwards25519 --label probe --id 01 --usage-sign >/dev/null
p11 --list-objects --type privkey | tee "$work/priv"
grep -q "never extractable" "$work/priv" || { echo "FAIL: key is not never-extractable"; exit 1; }
grep -q "sensitive" "$work/priv" || { echo "FAIL: key is not sensitive"; exit 1; }

echo "--- sign with CKM_EDDSA, verify outside the HSM"
printf 'kavach softhsm probe' >"$work/msg"
p11 --sign --mechanism EDDSA --id 01 --input-file "$work/msg" --output-file "$work/sig"
p11 --read-object --type pubkey --id 01 --output-file "$work/pub.der"
python3 - "$work" <<'PY'
import sys
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_der_public_key
w = Path(sys.argv[1])
key = load_der_public_key((w / "pub.der").read_bytes())
key.verify((w / "sig").read_bytes(), (w / "msg").read_bytes())  # raises if invalid
print("verified outside the HSM:", len((w / "sig").read_bytes()), "byte signature")
PY
echo "PASS: SoftHSM2 supports Ed25519 keys and CKM_EDDSA"
