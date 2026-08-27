#!/usr/bin/env bash
# Partner pilot Phase 1 — shadow batch validation and exit-criteria report.
set -euo pipefail
cd "$(dirname "$0")/.."

INPUT="${PILOT_BATCH_INPUT:-partner/finance/credit_underwriting_v1_batch.ndjson}"
OUTPUT="${PILOT_BATCH_OUTPUT:-/tmp/kavach-pilot-phase1-out.ndjson}"
MIN_SUCCESS_RATE="${PILOT_MIN_SUCCESS_RATE:-0.99}"

echo "==> Phase 1.1 — contract validation (partner finance samples)"
cargo test -q -p kavach-domain partner_finance

echo "==> Phase 1.2 — shadow batch run"
phase1_smoke_env=(PILOT_BATCH_OUTPUT="$OUTPUT" SKIP_VERIFY=1)
if [[ -n "${KAVACH_DATABASE_URL:-${PILOT_DATABASE_URL:-}}" ]]; then
  phase1_smoke_env+=(PILOT_EVIDENCE_STORE=postgres)
fi
if [[ -n "${PILOT_PRINCIPAL:-}" ]]; then
  phase1_smoke_env+=(PILOT_PRINCIPAL="$PILOT_PRINCIPAL")
fi
env "${phase1_smoke_env[@]}" ./scripts/pilot-smoke.sh

echo "==> Phase 1.3 — batch result summary"
python3 - "$OUTPUT" "$MIN_SUCCESS_RATE" <<'PY'
import json
import sys
from collections import Counter

output_path, min_rate_str = sys.argv[1], sys.argv[2]
min_rate = float(min_rate_str)

status_counts: Counter[str] = Counter()
policy_counts: Counter[str] = Counter()
returned_counts: Counter[str] = Counter()
total = 0

with open(output_path, encoding="utf-8") as handle:
    for line in handle:
        row = json.loads(line)
        total += 1
        status_counts[row.get("status", "unknown")] += 1
        if row.get("policy_decision"):
            policy_counts[row["policy_decision"]] += 1
        if row.get("returned_decision"):
            returned_counts[row["returned_decision"]] += 1

ok = status_counts.get("ok", 0)
success_rate = ok / total if total else 0.0

print(f"rows: {total}")
print(f"status: {dict(status_counts)}")
print(f"policy_decision: {dict(policy_counts)}")
print(f"returned_decision: {dict(returned_counts)}")
print(f"success_rate: {success_rate:.1%} (threshold {min_rate:.0%})")

if success_rate < min_rate:
    print("FAIL: success rate below Phase 1 exit threshold", file=sys.stderr)
    sys.exit(1)

non_pass_policy = sum(
    count for decision, count in policy_counts.items() if decision != "PASS"
)
if non_pass_policy:
    print(
        f"NOTE: {non_pass_policy} row(s) with non-PASS policy_decision — "
        "review reason_codes before production enforce."
    )

print("PASS: Phase 1 shadow batch exit criteria met")
PY

if [[ "${PILOT_API_URL:-}" != "" ]]; then
  echo "==> Phase 1.4 — batch jobs API (Postgres pilot)"
  batch_jobs_principal="${PILOT_BATCH_JOBS_PRINCIPAL:-${PILOT_ACTOR:-admin-1}}"
  jobs="$(curl -fsS "${PILOT_API_URL}/v1/admin/batch-jobs?limit=5" \
    -H "X-Kavach-Principal: ${batch_jobs_principal}")"
  count="$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' <<<"$jobs")"
  echo "batch jobs visible: $count"
  if [[ "$count" -lt 1 ]]; then
    if [[ -n "${KAVACH_DATABASE_URL:-${PILOT_DATABASE_URL:-}}" ]]; then
      echo "FAIL: no batch jobs in API after Postgres batch run" >&2
      exit 1
    fi
    echo "WARN: no batch jobs in API — set KAVACH_DATABASE_URL for Postgres pilot batch" >&2
  else
    echo "batch jobs API OK"
  fi
fi

echo "==> Phase 1 complete — review output at $OUTPUT"
