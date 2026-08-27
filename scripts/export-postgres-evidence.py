#!/usr/bin/env python3
"""Export decision_events from Postgres to NDJSON for kavach-evidence verify."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

COLUMNS = """
    schema_version,
    event_id,
    evidence_id,
    prev_hash,
    hash,
    pack_id,
    pack_version,
    sector,
    model_id,
    model_version,
    model_origin,
    governance_mode,
    policy_decision,
    returned_decision,
    reason_codes,
    policy_hits,
    pii_tokens,
    input_digest,
    latency_ms,
    decision_time,
    evaluated_at,
    service_identity_id,
    correlation_id,
    idempotency_key
""".strip()


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <output.ndjson>", file=sys.stderr)
        return 2

    database_url = os.environ.get("KAVACH_DATABASE_URL") or os.environ.get("PILOT_DATABASE_URL")
    if not database_url:
        print("KAVACH_DATABASE_URL or PILOT_DATABASE_URL is required", file=sys.stderr)
        return 1

    output = Path(sys.argv[1])
    query = (
        "SELECT row_to_json(t) "
        f"FROM (SELECT {COLUMNS} FROM decision_events ORDER BY created_at ASC) t"
    )
    result = subprocess.run(
        ["psql", database_url, "-t", "-A", "-c", query],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(result.stderr or result.stdout, file=sys.stderr)
        return result.returncode

    rows = 0
    with output.open("w", encoding="utf-8") as handle:
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
            rows += 1

    print(f"exported {rows} event(s) to {output}")
    return 0 if rows > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
