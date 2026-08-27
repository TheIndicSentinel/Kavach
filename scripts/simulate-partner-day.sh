#!/usr/bin/env bash
# Simulate a partner bank day — automated real-world usage test (no manual JSON editing).
#
# Covers: overnight batch ingest, sync scoring API, idempotency, governance reads,
# fairness monitoring, and enforce cutover.
#
# Usage:
#   ./scripts/start-local-review.sh    # terminal 1 — start API
#   ./scripts/simulate-partner-day.sh  # terminal 2 — run simulation
set -euo pipefail
cd "$(dirname "$0")/.."

export PILOT_API_URL="${PILOT_API_URL:-http://localhost:8080}"
export KAVACH_DATABASE_URL="${KAVACH_DATABASE_URL:-${PILOT_DATABASE_URL:-postgres://kavach:change-me@localhost:5432/kavach}}"
export PILOT_PRINCIPAL="${PILOT_PRINCIPAL:-viewer-1}"
export PILOT_OPERATOR="${PILOT_OPERATOR:-admin-1}"
export PILOT_ACTOR="${PILOT_ACTOR:-admin-1}"
export PILOT_APPROVER="${PILOT_APPROVER:-admin-2}"

echo "Partner day simulation"
echo "  API:      ${PILOT_API_URL}"
echo "  Postgres: ${KAVACH_DATABASE_URL}"
echo ""

# Wait for API (up to 30s) unless skipped
if [[ "${SIM_SKIP_WAIT:-}" != "1" ]]; then
  for _ in $(seq 1 30); do
    if curl -fsS -H "X-Kavach-Principal: ${PILOT_PRINCIPAL}" "${PILOT_API_URL}/health" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
fi

exec python3 scripts/simulate_partner_day.py
