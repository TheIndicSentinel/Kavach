#!/usr/bin/env bash
# Partner pilot Phase 2 — governance API review and dual-control smoke.
set -euo pipefail
cd "$(dirname "$0")/.."

API="${PILOT_API_URL:-http://localhost:8080}"
ACTOR="${PILOT_ACTOR:-admin-1}"
APPROVER="${PILOT_APPROVER:-admin-2}"
READ_PRINCIPAL="${PILOT_PRINCIPAL:-}"
TARGET_RETENTION_DAYS="${PILOT_RETENTION_DAYS:-180}"
RESTORE_RETENTION_DAYS="${PILOT_RESTORE_RETENTION_DAYS:-365}"

read_args=()
if [[ -n "${READ_PRINCIPAL}" ]]; then
  read_args+=(-H "X-Kavach-Principal: ${READ_PRINCIPAL}")
fi

echo "==> Phase 2.1 — API health"
curl -fsS "${API}/health" "${read_args[@]}" | python3 -c 'import json,sys; print(json.load(sys.stdin))'

echo "==> Phase 2.2 — governance read APIs"
runtime="$(curl -fsS "${API}/v1/runtime" "${read_args[@]}")"
python3 -c 'import json,sys; r=json.loads(sys.argv[1]); print("runtime:", r["model_id"], r["governance_mode"])' "$runtime"

pack_count="$(curl -fsS "${API}/v1/packs" "${read_args[@]}" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
model_count="$(curl -fsS "${API}/v1/models" "${read_args[@]}" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
echo "packs listed: ${pack_count}"
echo "models listed: ${model_count}"

echo "==> Phase 2.3 — dual-control rejection (actor equals approver)"
if curl -fsS -X PATCH "${API}/v1/admin/retention" \
  -H "Content-Type: application/json" \
  -H "X-Kavach-Principal: ${ACTOR}" \
  -H "X-Kavach-Approver: ${ACTOR}" \
  -d "{\"evidence_retention_days\":${TARGET_RETENTION_DAYS}}" >/dev/null 2>&1; then
  echo "FAIL: expected dual-control rejection when actor equals approver" >&2
  exit 1
fi
echo "dual-control guard OK"

echo "==> Phase 2.4 — retention update (dual control)"
updated="$(curl -fsS -X PATCH "${API}/v1/admin/retention" \
  -H "Content-Type: application/json" \
  -H "X-Kavach-Principal: ${ACTOR}" \
  -H "X-Kavach-Approver: ${APPROVER}" \
  -d "{\"evidence_retention_days\":${TARGET_RETENTION_DAYS}}")"
python3 -c 'import json,sys; print("retention set to", json.loads(sys.argv[1])["evidence_retention_days"], "days")' "$updated"

echo "==> Phase 2.5 — audit log contains retention mutation"
audit="$(curl -fsS "${API}/v1/admin/audit?limit=20" -H "X-Kavach-Principal: ${ACTOR}")"
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
curl -fsS -X PATCH "${API}/v1/admin/retention" \
  -H "Content-Type: application/json" \
  -H "X-Kavach-Principal: ${ACTOR}" \
  -H "X-Kavach-Approver: ${APPROVER}" \
  -d "{\"evidence_retention_days\":${RESTORE_RETENTION_DAYS}}" >/dev/null
echo "retention restored to ${RESTORE_RETENTION_DAYS} days"

echo "PASS: Phase 2 governance review exit criteria met (API path)"
echo "Manual: review console /policies, /models, /audit, /retention on tablet/desktop"
