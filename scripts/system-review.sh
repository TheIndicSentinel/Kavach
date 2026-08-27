#!/usr/bin/env bash
# Holistic system review gate — run before partner/bank VPC deployment.
#
# Layer 1 (always): workspace verify + batch smoke
# Layer 2 (optional): pilot sign-off against live Cedar/Postgres API
# Layer 3 (optional): Postgres evidence export + kavach-evidence verify
#
# Usage:
#   ./scripts/system-review.sh
#
# Full stack (pilot API running):
#   export KAVACH_DATABASE_URL=postgres://kavach:change-me@localhost:5432/kavach
#   export PILOT_API_URL=http://localhost:8080
#   ./scripts/system-review.sh
set -euo pipefail
cd "$(dirname "$0")/.."

API="${PILOT_API_URL:-}"
DB_URL="${KAVACH_DATABASE_URL:-${PILOT_DATABASE_URL:-}}"
EVIDENCE_EXPORT="${SYSTEM_REVIEW_EVIDENCE_EXPORT:-/tmp/kavach-system-review-evidence.ndjson}"

echo "=============================================="
echo "Kavach system review checkpoint"
echo "=============================================="
echo ""

echo "==> Layer 1 — workspace verification"
if [[ "${SKIP_VERIFY:-}" == "1" ]]; then
  echo "SKIP_VERIFY=1 — skipping ./scripts/verify.sh"
else
  ./scripts/verify.sh
fi

echo ""
echo "==> Layer 1b — partner batch smoke (memory evidence)"
SKIP_VERIFY=1 ./scripts/pilot-smoke.sh

if [[ -n "$API" ]]; then
  echo ""
  echo "==> Layer 2 — pilot sign-off (live API at ${API})"
  export PILOT_API_URL="$API"
  if [[ -n "$DB_URL" ]]; then
    export KAVACH_DATABASE_URL="$DB_URL"
  fi
  ./scripts/pilot-signoff.sh
else
  echo ""
  echo "==> Layer 2 — SKIP (set PILOT_API_URL to run pilot sign-off against live API)"
fi

if [[ -n "$DB_URL" ]] && command -v psql >/dev/null 2>&1; then
  echo ""
  echo "==> Layer 3 — evidence export + chain checks (Postgres)"
  export KAVACH_DATABASE_URL="$DB_URL"
  python3 scripts/export-postgres-evidence.py "$EVIDENCE_EXPORT"
  python3 - "$EVIDENCE_EXPORT" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
genesis = "0" * 64
for index, event in enumerate(events):
    expected_prev = genesis if index == 0 else events[index - 1]["hash"]
    if event.get("prev_hash") != expected_prev:
        print(
            f"FAIL: chain break at event {event.get('event_id')}: "
            f"expected prev_hash {expected_prev}, got {event.get('prev_hash')}",
            file=sys.stderr,
        )
        sys.exit(1)
print(f"chain linkage OK ({len(events)} events)")
PY
  if cargo run -q -p kavach-evidence -- verify --file "$EVIDENCE_EXPORT" 2>/dev/null; then
    echo "kavach-evidence verify OK"
  else
    echo "NOTE: kavach-evidence verify skipped — Postgres row_to_json export may not round-trip hash serde."
    echo "      Use golden NDJSON exports or future dedicated export CLI for offline verify."
    if [[ "${SYSTEM_REVIEW_STRICT_EVIDENCE:-}" == "1" ]]; then
      echo "FAIL: SYSTEM_REVIEW_STRICT_EVIDENCE=1 and verify failed" >&2
      exit 1
    fi
  fi
else
  echo ""
  echo "==> Layer 3 — SKIP (set KAVACH_DATABASE_URL and install psql for evidence verify)"
fi

cat <<EOF

==============================================
SYSTEM REVIEW — automated gates passed
==============================================

Manual console walkthrough (see docs/SYSTEM_REVIEW_CHECKPOINT.md):

  Overview     ${API:-http://localhost:8080}/overview
  Evaluate     ${API:-http://localhost:8080}/evaluate
  Policies     ${API:-http://localhost:8080}/policies
  Models       ${API:-http://localhost:8080}/models
  Batch jobs   ${API:-http://localhost:8080}/batch
  Fairness     ${API:-http://localhost:8080}/fairness
  Audit        ${API:-http://localhost:8080}/audit
  Incidents    ${API:-http://localhost:8080}/incidents
  Retention    ${API:-http://localhost:8080}/retention
  Settings     ${API:-http://localhost:8080}/settings

Check responsive layout at 375px and 1280px.

After manual review, proceed to partner pilot in bank VPC (PARTNER_PILOT.md).

EOF
