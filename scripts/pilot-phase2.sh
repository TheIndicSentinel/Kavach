#!/usr/bin/env bash
# Partner pilot Phase 2 — governance API review and maker-checker smoke.
set -euo pipefail
cd "$(dirname "$0")/.."

API="${PILOT_API_URL:-http://localhost:8080}"
ACTOR="${PILOT_ACTOR:-admin-1}"
APPROVER="${PILOT_APPROVER:-admin-2}"
READ_PRINCIPAL="${PILOT_PRINCIPAL:-}"
TARGET_RETENTION_DAYS="${PILOT_RETENTION_DAYS:-180}"
RESTORE_RETENTION_DAYS="${PILOT_RESTORE_RETENTION_DAYS:-365}"

read_args=(-H "X-Kavach-Pilot: phase2")
if [[ -n "${PILOT_TOKEN:-}" ]]; then
  read_args=(-H "Authorization: Bearer ${PILOT_TOKEN}")
elif [[ -n "${READ_PRINCIPAL}" ]]; then
  read_args=(-H "X-Kavach-Principal: ${READ_PRINCIPAL}")
fi

# shellcheck source=lib/change-request.sh
source "scripts/lib/change-request.sh"

echo "==> Phase 2.1 — API health"
curl -fsS "${API}/health" "${read_args[@]}" | python3 -c 'import json,sys; print(json.load(sys.stdin))'

echo "==> Phase 2.2 — governance read APIs"
runtime="$(curl -fsS "${API}/v1/runtime" "${read_args[@]}")"
python3 -c 'import json,sys; r=json.loads(sys.argv[1]); print("runtime:", r["model_id"], r["governance_mode"])' "$runtime"

pack_count="$(curl -fsS "${API}/v1/packs" "${read_args[@]}" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
model_count="$(curl -fsS "${API}/v1/models" "${read_args[@]}" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
echo "packs listed: ${pack_count}"
echo "models listed: ${model_count}"

echo "==> Phase 2.3 — maker-checker: the proposer cannot approve"
pending="$(propose_change update_retention "{\"evidence_retention_days\":${TARGET_RETENTION_DAYS}}")"
if approve_change "$pending" "${actor_auth[@]}" >/dev/null 2>&1; then
  echo "FAIL: expected the proposer's own approval to be refused" >&2
  exit 1
fi
cancel_change "$pending"
echo "self-approval refused; request cancelled"

echo "==> Phase 2.4 — retention update (propose, then approve)"
applied="$(apply_change update_retention "{\"evidence_retention_days\":${TARGET_RETENTION_DAYS}}")"
python3 -c 'import json,sys; r=json.loads(sys.argv[1]); assert r["status"]=="applied", r; print("retention set to", r["outcome"]["evidence_retention_days"], "days")' "$applied"

echo "==> Phase 2.5 — audit log contains retention mutation"
audit="$(curl -fsS "${API}/v1/admin/audit?limit=20" "${actor_auth[@]}")"
python3 - "$audit" "$ACTOR" "$APPROVER" <<'PY'
import json
import sys

audit, actor, approver = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]
matches = [
    row
    for row in audit
    if row.get("action") == "update_retention"
    and row.get("actor_principal") == actor
    and row.get("approver_principal") == approver
]
if not matches:
    print("FAIL: update_retention not found in audit log", file=sys.stderr)
    sys.exit(1)
print(f"audit entries matched: {len(matches)}")
PY

echo "==> Phase 2.6 — restore retention default"
apply_change update_retention "{\"evidence_retention_days\":${RESTORE_RETENTION_DAYS}}" >/dev/null
echo "retention restored to ${RESTORE_RETENTION_DAYS} days"

echo "PASS: Phase 2 governance review exit criteria met (API path)"
echo "Manual: review console /policies, /models, /changes, /audit, /retention on tablet/desktop"
