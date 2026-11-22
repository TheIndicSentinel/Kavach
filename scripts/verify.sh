#!/usr/bin/env bash
# Local Phase 0 verification — mirrors CI
set -euo pipefail
cd "$(dirname "$0")/.."

./scripts/disk-guard.sh --check-size

if [[ -f console/package.json ]]; then
  echo "==> build console"
  ./scripts/build-console.sh
fi

echo "==> cargo fmt --check"
cargo fmt --all -- --check

echo "==> cargo clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> cargo test"
cargo test --workspace --verbose --features kavach-api/test-support

if command -v initdb >/dev/null 2>&1 && command -v pg_ctl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  echo "==> HA shared-Postgres outage and recovery"
  ./scripts/test-ha-postgres-outage.sh
else
  echo "==> skip HA shared-Postgres outage test (install PostgreSQL server tools)"
fi

if docker compose version >/dev/null 2>&1; then
  echo "==> validate gated HA Compose reference"
  POSTGRES_PASSWORD=compose-check \
    KAVACH_RUNTIME_DB_PASSWORD=compose-check \
    KAVACH_OIDC_ISSUER=https://issuer.example.test \
    KAVACH_OIDC_AUDIENCE=kavach-api \
    docker compose \
      -f deploy/docker-compose.pilot.yml \
      -f deploy/docker-compose.ha-reference.yml \
      --profile ha-reference-gated config --quiet
else
  echo "==> skip gated HA Compose validation (install Docker Compose v2)"
fi

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

if [[ -n "${CVC5:-}" && -x "${CVC5}" ]]; then
  echo "==> agent policy analysis (cvc5: ${CVC5})"
  cargo run -q -p kavach-cedar-analysis
else
  echo "==> skip agent policy analysis (run ./scripts/fetch-cvc5.sh and export CVC5)"
fi

echo "==> Kavach local verification passed"
