#!/usr/bin/env python3
"""Credit underwriting policy simulation — batch + optional sync API against manifest."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = ROOT / "partner/finance/scenarios"
DEFAULT_MANIFEST = SCENARIOS_DIR / "manifest.json"
DEFAULT_INPUT = SCENARIOS_DIR / "credit_underwriting_v1.ndjson"


@dataclass
class StepResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Report:
    steps: list[StepResult] = field(default_factory=list)

    def record(self, name: str, ok: bool, detail: str = "") -> None:
        tag = "PASS" if ok else "FAIL"
        print(f"  [{tag}] {name}" + (f" — {detail}" if detail else ""))
        self.steps.append(StepResult(name, ok, detail))

    def exit_code(self) -> int:
        return 0 if all(s.ok for s in self.steps) else 1


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stamp_input(source: Path, dest: Path) -> None:
    ts = now_iso()
    lines = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        row["decision_time"] = ts
        row["consent"]["timestamp"] = ts
        lines.append(json.dumps(row, separators=(",", ":")))
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_batch(input_path: Path, output_path: Path, evidence_store: str, db_url: str | None) -> int:
    cmd = [
        "cargo",
        "run",
        "-q",
        "-p",
        "kavach-batch",
        "--",
        "run",
        "--input",
        str(input_path),
        "--output",
        str(output_path),
        "--pack",
        "packs/finance/v0.yaml",
        "--model",
        "models/finance/credit-underwriting-v1.yaml",
    ]
    if evidence_store == "postgres":
        cmd.extend(["--evidence-store", "postgres"])
    env = os.environ.copy()
    if db_url:
        env["KAVACH_DATABASE_URL"] = db_url
    proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stderr or proc.stdout, file=sys.stderr)
    return proc.returncode


def load_results(path: Path) -> dict[str, dict[str, Any]]:
    by_correlation: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        cid = row.get("correlation_id")
        if cid:
            by_correlation[cid] = row
    return by_correlation


def check_expect(actual: dict[str, Any], expect: dict[str, Any]) -> tuple[bool, str]:
    for key in ("status", "policy_decision", "returned_decision"):
        if key in expect and actual.get(key) != expect[key]:
            return False, f"{key}: expected {expect[key]!r}, got {actual.get(key)!r}"

    if "reason_codes" in expect:
        actual_codes = actual.get("reason_codes") or []
        if actual_codes != expect["reason_codes"]:
            return False, f"reason_codes: expected {expect['reason_codes']}, got {actual_codes}"

    if "reason_codes_contains" in expect:
        actual_codes = set(actual.get("reason_codes") or [])
        missing = [c for c in expect["reason_codes_contains"] if c not in actual_codes]
        if missing:
            return False, f"missing reason_codes: {missing}"

    return True, ""


def api_evaluate(api: str, principal: str, body: dict[str, Any]) -> tuple[int, Any]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{api}/v1/evaluate",
        data=data,
        headers={"Content-Type": "application/json", "X-Kavach-Principal": principal},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as err:
        raw = err.read().decode()
        try:
            return err.code, json.loads(raw)
        except json.JSONDecodeError:
            return err.code, {"error": raw}


def simulate_sync_shadow(
    report: Report,
    manifest: dict[str, Any],
    stamped_input: Path,
    api: str,
    principal: str,
) -> None:
    shadow_returned = manifest.get("sync_shadow", {}).get("returned_decision", "PASS")
    for scenario in manifest["scenarios"]:
        expect = scenario["expect"]
        if expect.get("status") != "ok":
            continue
        row = None
        for line in stamped_input.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            parsed = json.loads(line)
            if parsed.get("correlation_id") == scenario["correlation_id"]:
                row = parsed
                break
        if row is None:
            report.record(f"sync: {scenario['id']}", False, "request row missing")
            continue

        status, result = api_evaluate(api, principal, row)
        ok = (
            status == 200
            and isinstance(result, dict)
            and result.get("policy_decision") == expect["policy_decision"]
            and result.get("returned_decision") == shadow_returned
        )
        detail = ""
        if isinstance(result, dict):
            detail = f"policy={result.get('policy_decision')} returned={result.get('returned_decision')}"
        elif status != 200:
            detail = str(result)
        report.record(f"sync shadow: {scenario['name']}", ok, detail)


def main() -> int:
    manifest_path = Path(os.environ.get("CU_SIM_MANIFEST", DEFAULT_MANIFEST))
    input_source = Path(os.environ.get("CU_SIM_INPUT", DEFAULT_INPUT))
    stamped = Path(os.environ.get("CU_SIM_STAMPED", "/tmp/kavach-cu-sim-input.ndjson"))
    batch_out = Path(os.environ.get("CU_SIM_OUTPUT", "/tmp/kavach-cu-sim-output.ndjson"))
    api = os.environ.get("PILOT_API_URL", "")
    db_url = os.environ.get("KAVACH_DATABASE_URL") or os.environ.get("PILOT_DATABASE_URL")
    principal = os.environ.get("PILOT_OPERATOR", os.environ.get("PILOT_ACTOR", "admin-1"))
    evidence_store = "postgres" if db_url else "memory"

    manifest_path = manifest_path.resolve()
    input_source = input_source.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report = Report()

    print("==============================================")
    print("Credit underwriting policy simulation")
    print(f"  manifest: {manifest_path.relative_to(ROOT)}")
    print(f"  pack:     {manifest['pack_id']} @ {manifest['pack_version']}")
    print(f"  evidence: {evidence_store}")
    if api:
        print(f"  API:      {api} (sync shadow checks)")
    print("==============================================\n")

    print("==> golden policy fixtures")
    proc = subprocess.run(
        ["cargo", "test", "-q", "-p", "kavach-policy", "golden_v0"],
        cwd=ROOT,
    )
    report.record("CEL golden fixtures (kavach-policy)", proc.returncode == 0)

    print("\n==> stamp LOS export timestamps")
    stamp_input(input_source, stamped)
    report.record("timestamp refresh", stamped.exists())

    print("\n==> overnight batch ingest (LOS NDJSON)")
    rc = run_batch(stamped, batch_out, evidence_store, db_url)
    report.record("batch run", rc == 0, str(batch_out))

    print("\n==> assert batch outcomes vs manifest")
    results = load_results(batch_out)
    for scenario in manifest["scenarios"]:
        cid = scenario["correlation_id"]
        actual = results.get(cid)
        if actual is None:
            report.record(f"batch: {scenario['name']}", False, f"missing correlation_id {cid}")
            continue
        ok, detail = check_expect(actual, scenario["expect"])
        policy = actual.get("policy_decision", "?")
        report.record(f"batch: {scenario['name']}", ok, detail or f"policy={policy}")

    if api:
        print("\n==> sync scoring API (shadow semantics)")
        try:
            req = urllib.request.Request(
                f"{api}/health",
                headers={"X-Kavach-Principal": principal},
            )
            urllib.request.urlopen(req, timeout=10)
            report.record("API reachable", True)
            simulate_sync_shadow(report, manifest, stamped, api, principal)
        except urllib.error.URLError as err:
            report.record("API reachable", False, str(err))
    else:
        print("\n==> SKIP sync API (set PILOT_API_URL for live shadow checks)")

    print("\n==> fairness monitoring (cohort disparity)")
    if batch_out.exists():
        proc = subprocess.run(
            [
                "cargo",
                "run",
                "-q",
                "-p",
                "kavach-batch",
                "--",
                "fairness",
                "--requests",
                str(stamped),
                "--results",
                str(batch_out),
                "--report",
                "disparity",
                "--attribute",
                "input.customer_segment",
                "--output",
                "/tmp/kavach-cu-sim-disparity.json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            report.record("fairness disparity report", False, proc.stderr.strip())
        else:
            data = json.loads(Path("/tmp/kavach-cu-sim-disparity.json").read_text())
            n = len(manifest["scenarios"])
            ok = data.get("total_evaluated") == n
            report.record(
                "fairness disparity report",
                ok,
                f"evaluated={data.get('total_evaluated')}/{n}",
            )

    passed = sum(1 for s in report.steps if s.ok)
    total = len(report.steps)
    print("\n==============================================")
    print(f"CREDIT UNDERWRITING SIMULATION: {passed}/{total} passed")
    print("==============================================")
    if report.exit_code() == 0:
        print("Policy pack behaviour matches manifest — safe to merge PR.")
    else:
        print("Update packs/finance/v0.yaml and/or partner/finance/scenarios/ together.")
    return report.exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
