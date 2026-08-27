#!/usr/bin/env bash
# Local Phase 0 verification — mirrors CI
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f console/package.json ]]; then
  echo "==> build console"
  ./scripts/build-console.sh
fi

echo "==> cargo fmt --check"
cargo fmt --all -- --check

echo "==> cargo clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> cargo test"
cargo test --workspace --verbose

if command -v cargo-audit >/dev/null 2>&1; then
  echo "==> cargo audit"
  cargo audit
else
  echo "==> skip cargo audit (install: cargo install cargo-audit)"
fi

if command -v cargo-deny >/dev/null 2>&1; then
  echo "==> cargo deny"
  cargo deny check
else
  echo "==> skip cargo deny (install: cargo install cargo-deny)"
fi

echo "==> Kavach local verification passed"
