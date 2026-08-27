#!/usr/bin/env bash
# Partner pilot Phase 3 — sync enforce evaluate and decision parity check.
set -euo pipefail
cd "$(dirname "$0")/.."

API="${PILOT_API_URL:-http://localhost:8080}"
ACTOR="${PILOT_ACTOR:-admin-1}"
APPROVER="${PILOT_APPROVER:-admin-2}"
EVAL_PRINCIPAL="${PILOT_EVAL_PRINCIPAL:-}"
MODEL_ID="${PILOT_MODEL_ID:-credit-underwriting-v1}"
REQUEST_TEMPLATE="${PILOT_EVAL_REQUEST:-partner/finance/credit_underwriting_v1_request.json}"
EVAL_BODY_FILE="${PILOT_EVAL_BODY:-/tmp/kavach-pilot-phase3-eval.json}"

echo "==> Phase 3.1 — capture runtime posture"
runtime="$(curl -fsS "${API}/v1/runtime")"
original_mode="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["governance_mode"])' "$runtime")"
echo "active model: ${MODEL_ID}, current mode: ${original_mode}"

echo "==> Phase 3.2 — promote to enforce (dual control)"
if [[ "${original_mode}" != "enforce" ]]; then
  curl -fsS -X PATCH "${API}/v1/models/${MODEL_ID}" \
    -H "Content-Type: application/json" \
    -H "X-Kavach-Principal: ${ACTOR}" \
    -H "X-Kavach-Approver: ${APPROVER}" \
    -d '{"governance_mode":"enforce"}' >/dev/null
  echo "governance_mode set to enforce"
else
  echo "already in enforce mode"
fi

echo "==> Phase 3.3 — build evaluate request (fresh timestamps)"
python3 - "$REQUEST_TEMPLATE" "$EVAL_BODY_FILE" <<'PY'
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

template = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
suffix = uuid.uuid4().hex[:8]
template["decision_time"] = now
template["consent"]["timestamp"] = now
template["correlation_id"] = f"pilot-phase3-{suffix}"
template["idempotency_key"] = f"pilot-phase3-{suffix}"
Path(sys.argv[2]).write_text(json.dumps(template), encoding="utf-8")
print("correlation_id:", template["correlation_id"])
PY

evaluate_args=(-fsS -X POST "${API}/v1/evaluate" -H "Content-Type: application/json" --data-binary "@${EVAL_BODY_FILE}")
if [[ -n "${EVAL_PRINCIPAL}" ]]; then
  evaluate_args+=(-H "X-Kavach-Principal: ${EVAL_PRINCIPAL}")
fi
if [[ -n "${PILOT_HMAC_SECRET:-}" ]]; then
  signature="$(PILOT_HMAC_SECRET="${PILOT_HMAC_SECRET}" python3 - "$EVAL_BODY_FILE" <<'PY'
import hashlib
import hmac
import os
import sys
from pathlib import Path

secret = os.environ["PILOT_HMAC_SECRET"].encode()
body = Path(sys.argv[1]).read_bytes()
digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
print(f"sha256={digest}")
PY
)"
  evaluate_args+=(-H "X-Kavach-Signature: ${signature}")
fi

echo "==> Phase 3.4 — sync evaluate"
response="$(curl "${evaluate_args[@]}")"
python3 - "$response" <<'PY'
import json
import sys

result = json.loads(sys.argv[1])
policy = result.get("policy_decision")
returned = result.get("returned_decision")
evidence_id = result.get("evidence_id")
print("policy_decision:", policy)
print("returned_decision:", returned)
print("evidence_id:", evidence_id)
if policy != returned:
    print("FAIL: enforce mode requires policy_decision == returned_decision", file=sys.stderr)
    sys.exit(1)
if not evidence_id:
    print("FAIL: expected evidence_id in enforce evaluate response", file=sys.stderr)
    sys.exit(1)
print("decision parity OK")
PY

if [[ "${PILOT_SKIP_RESTORE:-}" != "1" && "${original_mode}" != "enforce" ]]; then
  echo "==> Phase 3.5 — restore governance mode (${original_mode})"
  curl -fsS -X PATCH "${API}/v1/models/${MODEL_ID}" \
    -H "Content-Type: application/json" \
    -H "X-Kavach-Principal: ${ACTOR}" \
    -H "X-Kavach-Approver: ${APPROVER}" \
    -d "{\"governance_mode\":\"${original_mode}\"}" >/dev/null
  echo "restored governance_mode to ${original_mode}"
fi

echo "PASS: Phase 3 sync enforce exit criteria met (API path)"
echo "Manual: enable Cedar/mTLS/HMAC in production; run kavach-evidence verify on exported chain"
