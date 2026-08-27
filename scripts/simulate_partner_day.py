#!/usr/bin/env python3
"""Simulate a partner bank day — batch ingest, sync scoring, governance, fairness."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class StepResult:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class SimulationReport:
    steps: list[StepResult] = field(default_factory=list)

    def record(self, name: str, ok: bool, detail: str = "") -> None:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
        self.steps.append(StepResult(name, ok, detail))

    def exit_code(self) -> int:
        return 0 if all(step.ok for step in self.steps) else 1


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def api_request(
    method: str,
    url: str,
    *,
    principal: str | None = None,
    approver: str | None = None,
    body: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    headers = {"Content-Type": "application/json"}
    if principal:
        headers["X-Kavach-Principal"] = principal
    if approver:
        headers["X-Kavach-Approver"] = approver
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as err:
        raw = err.read().decode()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"error": raw}
        return err.code, payload


def build_evaluate(overrides: dict[str, Any] | None = None, suffix: str | None = None) -> dict[str, Any]:
    tag = suffix or uuid.uuid4().hex[:8]
    ts = now_iso()
    payload: dict[str, Any] = {
        "model_id": "credit-underwriting-v1",
        "model_version": "1.0.0",
        "purpose": "credit_decision",
        "consent": {"purpose_id": "credit_decision", "timestamp": ts},
        "input": {
            "application_ref": f"SIM-{tag}",
            "product_code": "personal_loan_unsecured",
            "customer_segment": "salaried",
            "state_code": "MH",
            "bureau_score": 712,
            "credit_score": 712,
            "monthly_income_inr": 92000,
            "income": 92000,
            "existing_emi_inr": 18500,
            "proposed_emi_inr": 11200,
            "loan_amount": 450000,
            "tenure_months": 48,
            "employment_years": 4,
            "employment_type": "private_sector",
            "debt_ratio": 0.322,
            "bureau_pull_date": "2026-08-14",
            "informal_sector": False,
        },
        "score": 0.74,
        "confidence": 0.82,
        "decision_time": ts,
        "correlation_id": f"sim-sync-{tag}",
        "idempotency_key": f"sim-sync-{tag}",
    }
    if overrides:
        _deep_merge(payload, overrides)
    return payload


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> None:
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def run_batch_ingest(
    report: SimulationReport, db_url: str, input_path: Path, output: Path
) -> str | None:
    source = ROOT / "partner/finance/credit_underwriting_v1_batch.ndjson"
    ts = now_iso()
    lines = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        row["decision_time"] = ts
        row["consent"]["timestamp"] = ts
        lines.append(json.dumps(row, separators=(",", ":")))
    input_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    env = os.environ.copy()
    env["KAVACH_DATABASE_URL"] = db_url
    proc = subprocess.run(
        [
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
            str(output),
            "--pack",
            "packs/finance/v0.yaml",
            "--model",
            "models/finance/credit-underwriting-v1.yaml",
            "--evidence-store",
            "postgres",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        report.record("overnight batch ingest", False, proc.stderr.strip() or proc.stdout.strip())
        return None

    job_id = None
    for line in proc.stderr.splitlines():
        if "job=" in line:
            job_id = line.split("job=")[1].split()[0]
    report.record("overnight batch ingest", True, f"job={job_id}, output={output}")
    return job_id


def simulate_sync_day(report: SimulationReport, api: str, operator: str) -> None:
    scenarios = [
        (
            "morning salaried approval (PASS)",
            {},
            {"policy": "PASS", "returned": "PASS", "reasons": ["CONSENT_OK"]},
        ),
        (
            "high DTI application (ALERT in shadow)",
            {"input": {"debt_ratio": 0.55}},
            {"policy": "ALERT", "returned": "PASS", "reasons": ["CONSENT_OK", "RBI_DTI_EXCEEDED"]},
        ),
        (
            "informal MSME (HUMAN_REVIEW in shadow)",
            {"input": {"informal_sector": True, "customer_segment": "informal"}},
            {
                "policy": "HUMAN_REVIEW",
                "returned": "PASS",
                "reasons": ["CONSENT_OK", "INFORMAL_ECONOMY_REVIEW"],
            },
        ),
        (
            "low model confidence (HUMAN_REVIEW in shadow)",
            {"confidence": 0.4},
            {
                "policy": "HUMAN_REVIEW",
                "returned": "PASS",
                "reasons": ["CONSENT_OK", "LOW_CONFIDENCE_GATE"],
            },
        ),
    ]

    for label, overrides, expected in scenarios:
        body = build_evaluate(overrides)
        status, result = api_request("POST", f"{api}/v1/evaluate", principal=operator, body=body)
        ok = (
            status == 200
            and isinstance(result, dict)
            and result.get("policy_decision") == expected["policy"]
            and result.get("returned_decision") == expected["returned"]
            and result.get("reason_codes") == expected["reasons"]
            and bool(result.get("evidence_id"))
        )
        detail = ""
        if isinstance(result, dict):
            detail = (
                f"policy={result.get('policy_decision')} "
                f"returned={result.get('returned_decision')} "
                f"evidence={result.get('evidence_id', '')[:8]}..."
            )
        elif status != 200:
            detail = str(result)
        report.record(f"sync score: {label}", ok, detail)


def simulate_idempotency(report: SimulationReport, api: str, operator: str) -> None:
    body = build_evaluate(suffix="idempotent")
    status1, result1 = api_request("POST", f"{api}/v1/evaluate", principal=operator, body=body)
    status2, result2 = api_request("POST", f"{api}/v1/evaluate", principal=operator, body=body)
    ok = (
        status1 == 200
        and status2 == 200
        and isinstance(result1, dict)
        and isinstance(result2, dict)
        and result1.get("evidence_id") == result2.get("evidence_id")
    )
    detail = ""
    if isinstance(result1, dict) and isinstance(result2, dict):
        detail = f"evidence_id={result1.get('evidence_id')}"
    report.record("LOS idempotency replay", ok, detail)


def simulate_governance_review(report: SimulationReport, api: str, viewer: str, admin: str) -> None:
    status, runtime = api_request("GET", f"{api}/v1/runtime", principal=viewer)
    ok = status == 200 and isinstance(runtime, dict) and runtime.get("model_id")
    report.record(
        "compliance runtime read",
        ok,
        f"mode={runtime.get('governance_mode')}" if isinstance(runtime, dict) else str(runtime),
    )

    status, jobs = api_request(
        "GET", f"{api}/v1/admin/batch-jobs?limit=5", principal=admin
    )
    count = len(jobs) if isinstance(jobs, list) else 0
    report.record("ops batch job inventory", status == 200 and count >= 1, f"{count} job(s)")

    status, audit = api_request("GET", f"{api}/v1/admin/audit?limit=5", principal=admin)
    audit_ok = status == 200 and isinstance(audit, list)
    report.record("audit trail readable", audit_ok, f"{len(audit) if audit_ok else 0} entries")


def simulate_fairness_monitoring(
    report: SimulationReport, batch_input: Path, batch_output: Path
) -> None:
    disparity_out = Path("/tmp/kavach-sim-disparity.json")
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
            str(batch_input),
            "--results",
            str(batch_output),
            "--report",
            "disparity",
            "--output",
            str(disparity_out),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        report.record("model risk fairness report", False, proc.stderr.strip())
        return
    report_data = json.loads(disparity_out.read_text(encoding="utf-8"))
    ok = report_data.get("report_type") == "disparity" and report_data.get("total_evaluated", 0) >= 1
    report.record(
        "model risk fairness report",
        ok,
        f"groups={len(report_data.get('groups', []))} flagged={len(report_data.get('flagged', []))}",
    )


def simulate_enforce_cutover(
    report: SimulationReport, api: str, actor: str, approver: str, operator: str
) -> None:
    status, runtime = api_request("GET", f"{api}/v1/runtime", principal=actor)
    if status != 200 or not isinstance(runtime, dict):
        report.record("enforce cutover", False, "runtime unavailable")
        return
    original = runtime.get("governance_mode", "shadow")

    if original != "enforce":
        status, _ = api_request(
            "PATCH",
            f"{api}/v1/models/credit-underwriting-v1",
            principal=actor,
            approver=approver,
            body={"governance_mode": "enforce"},
        )
        if status != 200:
            report.record("enforce cutover", False, f"promote failed HTTP {status}")
            return

    body = build_evaluate({"input": {"debt_ratio": 0.55}}, suffix="enforce")
    status, result = api_request("POST", f"{api}/v1/evaluate", principal=operator, body=body)
    ok = (
        status == 200
        and isinstance(result, dict)
        and result.get("policy_decision") == result.get("returned_decision") == "ALERT"
    )
    report.record(
        "production enforce scoring",
        ok,
        f"policy=returned={result.get('policy_decision')}" if isinstance(result, dict) else str(result),
    )

    if original != "enforce":
        api_request(
            "PATCH",
            f"{api}/v1/models/credit-underwriting-v1",
            principal=actor,
            approver=approver,
            body={"governance_mode": original},
        )


def main() -> int:
    api = os.environ.get("PILOT_API_URL", "http://localhost:8080")
    db_url = os.environ.get("KAVACH_DATABASE_URL") or os.environ.get("PILOT_DATABASE_URL")
    viewer = os.environ.get("PILOT_PRINCIPAL", "viewer-1")
    operator = os.environ.get("PILOT_OPERATOR", "admin-1")
    admin = os.environ.get("PILOT_ACTOR", "admin-1")
    approver = os.environ.get("PILOT_APPROVER", "admin-2")
    skip_enforce = os.environ.get("SIM_SKIP_ENFORCE", "") == "1"

    report = SimulationReport()
    print("==============================================")
    print("Kavach partner day simulation")
    print(f"API: {api}")
    print("==============================================\n")

    print("==> 06:00 — contract validation (partner payloads)")
    proc = subprocess.run(
        ["cargo", "test", "-q", "-p", "kavach-domain", "partner_finance"],
        cwd=ROOT,
    )
    report.record("partner schema contracts", proc.returncode == 0)

    batch_input = Path("/tmp/kavach-sim-batch-input.ndjson")
    batch_output = Path("/tmp/kavach-sim-batch-out.ndjson")
    if db_url:
        print("\n==> 06:30 — overnight LOS export → batch worker (Postgres)")
        run_batch_ingest(report, db_url, batch_input, batch_output)
    else:
        print("\n==> 06:30 — SKIP batch ingest (set KAVACH_DATABASE_URL)")
        report.record("overnight batch ingest", False, "KAVACH_DATABASE_URL not set")

    print("\n==> 09:00–17:00 — real-time sync scoring API (shadow)")
    status, _ = api_request("GET", f"{api}/health", principal=viewer)
    if status != 200:
        report.record("API reachable", False, f"health HTTP {status}")
        print("\n==============================================")
        print("SIMULATION FAILED — start API first (./scripts/start-local-review.sh)")
        print("==============================================")
        return 1
    report.record("API reachable", True)
    simulate_sync_day(report, api, operator)
    simulate_idempotency(report, api, operator)

    print("\n==> 17:30 — governance review (compliance + ops)")
    simulate_governance_review(report, api, viewer, admin)

    if batch_output.exists() and batch_input.exists():
        print("\n==> 18:00 — model risk fairness monitoring")
        simulate_fairness_monitoring(report, batch_input, batch_output)

    if not skip_enforce:
        print("\n==> 18:30 — optional production enforce cutover test")
        simulate_enforce_cutover(report, api, admin, approver, operator)
    else:
        print("\n==> 18:30 — SKIP enforce cutover (SIM_SKIP_ENFORCE=1)")

    passed = sum(1 for step in report.steps if step.ok)
    total = len(report.steps)
    print("\n==============================================")
    print(f"SIMULATION: {passed}/{total} steps passed")
    print("==============================================")
    if report.exit_code() != 0:
        print("Fix failures above, or run ./scripts/start-local-review.sh and retry.")
    else:
        print("Real-world path validated — console manual review is optional.")
    return report.exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
