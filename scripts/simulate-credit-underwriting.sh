#!/usr/bin/env bash
# Credit underwriting policy simulation — git-friendly real-world test harness.
#
# Offline (CI / no API): batch + manifest assertions + fairness
# Live stack: set PILOT_API_URL + KAVACH_DATABASE_URL for sync + Postgres batch
#
# Usage:
#   ./scripts/simulate-credit-underwriting.sh
set -euo pipefail
cd "$(dirname "$0")/.."

export PILOT_API_URL="${PILOT_API_URL:-}"
export KAVACH_DATABASE_URL="${KAVACH_DATABASE_URL:-${PILOT_DATABASE_URL:-}}"
export CU_SIM_MANIFEST="${CU_SIM_MANIFEST:-partner/finance/scenarios/manifest.json}"
export CU_SIM_INPUT="${CU_SIM_INPUT:-partner/finance/scenarios/credit_underwriting_v1.ndjson}"

echo "Credit underwriting simulation"
echo "  manifest: ${CU_SIM_MANIFEST}"
echo "  input:    ${CU_SIM_INPUT}"
if [[ -n "${PILOT_API_URL}" ]]; then
  echo "  API:      ${PILOT_API_URL}"
fi
if [[ -n "${KAVACH_DATABASE_URL}" ]]; then
  echo "  Postgres: ${KAVACH_DATABASE_URL}"
fi
echo ""

exec python3 scripts/simulate_credit_underwriting.py
