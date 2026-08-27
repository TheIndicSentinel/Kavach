#!/usr/bin/env bash
# Partner pilot engagement sign-off — runs Phase 1–3 validators against a live pilot API.
#
# Prerequisites (pick one):
#   Docker:  docker compose -f deploy/docker-compose.pilot.yml up --build -d
#   Source:  Postgres + kavach-api with --evidence-store postgres --access-control cedar
#
# Usage:
#   export KAVACH_DATABASE_URL=postgres://kavach:change-me@localhost:5432/kavach
#   export PILOT_API_URL=http://localhost:8080
#   ./scripts/pilot-signoff.sh
#
# Optional:
#   PILOT_SKIP_WAIT=1          skip API readiness poll
#   PILOT_PRINCIPAL=viewer-1     read principal (Cedar)
#   PILOT_ACTOR=admin-1          dual-control actor
#   PILOT_APPROVER=admin-2       dual-control approver
set -euo pipefail
cd "$(dirname "$0")/.."

API="${PILOT_API_URL:-http://localhost:8080}"
READ_PRINCIPAL="${PILOT_PRINCIPAL:-viewer-1}"
ACTOR="${PILOT_ACTOR:-admin-1}"
APPROVER="${PILOT_APPROVER:-admin-2}"
DB_URL="${KAVACH_DATABASE_URL:-${PILOT_DATABASE_URL:-}}"
WAIT_SECS="${PILOT_WAIT_SECS:-60}"

export PILOT_API_URL="$API"
export PILOT_PRINCIPAL="$READ_PRINCIPAL"
export PILOT_ACTOR="$ACTOR"
export PILOT_APPROVER="$APPROVER"
export PILOT_EVAL_PRINCIPAL="${PILOT_EVAL_PRINCIPAL:-$ACTOR}"
if [[ -n "$DB_URL" ]]; then
  export KAVACH_DATABASE_URL="$DB_URL"
fi

health_args=()
if [[ -n "$READ_PRINCIPAL" ]]; then
  health_args+=(-H "X-Kavach-Principal: ${READ_PRINCIPAL}")
fi

echo "==> Pilot sign-off — configuration"
echo "api: ${API}"
echo "database: ${DB_URL:-<not set — Phase 1 batch jobs API check skipped>}"
echo "read principal: ${READ_PRINCIPAL}"
echo "dual control: ${ACTOR} / ${APPROVER}"

if [[ "${PILOT_SKIP_WAIT:-}" != "1" ]]; then
  echo "==> Waiting for pilot API (up to ${WAIT_SECS}s)"
  deadline=$((SECONDS + WAIT_SECS))
  until curl -fsS "${API}/health" "${health_args[@]}" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "FAIL: pilot API not reachable at ${API}" >&2
      echo "Start deploy/docker-compose.pilot.yml or kavach-api with Postgres + Cedar." >&2
      exit 1
    fi
    sleep 1
  done
  echo "API health OK"
fi

started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "==> Phase 1 — shadow batch"
./scripts/pilot-phase1.sh

echo "==> Phase 2 — governance review"
./scripts/pilot-phase2.sh

echo "==> Phase 3 — sync enforce"
./scripts/pilot-phase3.sh

finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo ""
echo "========================================"
echo "PILOT SIGN-OFF: PASS"
echo "started:  ${started_at}"
echo "finished: ${finished_at}"
echo "========================================"
echo "Manual follow-ups (see docs/PILOT_SIGNOFF.md):"
echo "  - Console review: /policies, /models, /audit, /batch, /fairness"
echo "  - IdP → Cedar principal mapping for bank operators"
echo "  - Evidence export + kavach-evidence verify on production exports"
echo "  - Partner field mapping sign-off (internal document)"
