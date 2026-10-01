#!/usr/bin/env bash
# Download the pinned cvc5 SMT solver (non-GPL static build, BSD-3-Clause) used
# by the CI-only agent policy analysis (crates/kavach-cedar-analysis).
# Verifies the published SHA-256 before extracting. Installs into .tools/cvc5.
#
#   ./scripts/fetch-cvc5.sh && export CVC5="$PWD/.tools/cvc5/bin/cvc5"
#   cargo run -p kavach-cedar-analysis
set -euo pipefail

VERSION="1.3.1"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  ASSET="cvc5-Linux-x86_64-static";  SHA="1a1cda20d2df4938fa4944a69f33ddc9172e319ece0eed0aa09c4d7abede3ed1" ;;
  Linux-aarch64) ASSET="cvc5-Linux-arm64-static";   SHA="fe2b661834a82fd8830f7a757c340f0e20041fa41e19b038fa02ace0eaf1c6f2" ;;
  Darwin-x86_64) ASSET="cvc5-macOS-x86_64-static";  SHA="e7fe4af9491bd7c0db7591c0a483775735bd1a98b23933fd337a73ae39c10ff9" ;;
  Darwin-arm64)  ASSET="cvc5-macOS-arm64-static";   SHA="a0e7f5b03b1bc4284fbfff7cdfb08c704801701cf7ece83a13f8a505e7581215" ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/.tools"
mkdir -p "$DEST"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Retries ride out transient GitHub 5xx (a required CI check failed on one).
curl -sSfL --retry 5 --retry-all-errors --retry-delay 5 --connect-timeout 20 -o "$TMP/cvc5.zip" \
  "https://github.com/cvc5/cvc5/releases/download/cvc5-${VERSION}/${ASSET}.zip"
if command -v sha256sum >/dev/null; then
  echo "${SHA}  $TMP/cvc5.zip" | sha256sum -c -
else
  echo "${SHA}  $TMP/cvc5.zip" | shasum -a 256 -c -
fi
unzip -q "$TMP/cvc5.zip" -d "$TMP"
rm -rf "$DEST/cvc5"
mv "$TMP/$ASSET" "$DEST/cvc5"
"$DEST/cvc5/bin/cvc5" --version | head -1
echo "export CVC5=\"$DEST/cvc5/bin/cvc5\""
