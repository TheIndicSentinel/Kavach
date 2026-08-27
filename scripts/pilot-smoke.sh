#!/usr/bin/env bash
# Partner pilot smoke — mirrors the first-week integration path (no Docker required).
set -euo pipefail
cd "$(dirname "$0")/.."

PACK="${KAVACH_PACK_PATH:-packs/finance/v0.yaml}"
MODEL="${KAVACH_MODEL_PATH:-models/finance/credit-underwriting-v1.yaml}"
INPUT="${PILOT_BATCH_INPUT:-partner/finance/credit_underwriting_v1_batch.ndjson}"
OUTPUT="${PILOT_BATCH_OUTPUT:-/tmp/kavach-pilot-out.ndjson}"
STAMPED_INPUT="${PILOT_BATCH_STAMPED:-/tmp/kavach-pilot-input.ndjson}"

echo "==> refresh partner batch timestamps (clock-skew window)"
python3 - "$INPUT" "$STAMPED_INPUT" <<'PY'
import json
import sys
from datetime import UTC, datetime

source, dest = sys.argv[1], sys.argv[2]
now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
with open(source, encoding="utf-8") as handle, open(dest, "w", encoding="utf-8") as out:
    for line in handle:
        row = json.loads(line)
        row["decision_time"] = now
        row["consent"]["timestamp"] = now
        out.write(json.dumps(row, separators=(",", ":")) + "\n")
PY

echo "==> build console (embedded in API)"
./scripts/build-console.sh

echo "==> workspace verification"
./scripts/verify.sh

echo "==> batch shadow smoke (memory evidence)"
cargo run -q -p kavach-batch -- run \
  --input "$STAMPED_INPUT" \
  --output "$OUTPUT" \
  --pack "$PACK" \
  --model "$MODEL"

if [[ -f "$OUTPUT" ]]; then
  lines="$(wc -l < "$OUTPUT" | tr -d ' ')"
  ok_rows="$(python3 - "$OUTPUT" <<'PY'
import json, sys
ok = 0
with open(sys.argv[1], encoding="utf-8") as handle:
    for line in handle:
        if json.loads(line).get("status") == "ok":
            ok += 1
print(ok)
PY
)"
  echo "==> batch output: $OUTPUT ($lines rows, $ok_rows ok)"
  if [[ "$ok_rows" -lt 1 ]]; then
    echo "expected at least one successful batch row" >&2
    exit 1
  fi
else
  echo "batch output missing: $OUTPUT" >&2
  exit 1
fi

if [[ "${PILOT_API_URL:-}" != "" ]]; then
  echo "==> API health: $PILOT_API_URL/health"
  curl -fsS "${PILOT_API_URL}/health" >/dev/null
  echo "==> API health OK"
fi

echo "==> partner pilot smoke passed"
