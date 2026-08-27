# Credit underwriting policy simulation

Git-friendly **real-world simulation** for the finance credit-underwriting policy pack. Use this when changing `packs/finance/v0.yaml`, partner LOS-shaped payloads, or governance expectations — without hand-editing JSON in the console.

## What it validates

| Step | Tool | Purpose |
|---|---|---|
| CEL golden fixtures | `cargo test -p kavach-policy golden_v0` | Pack rules match checked-in oracles |
| Timestamp refresh | `simulate_credit_underwriting.py` | LOS export rows pass clock-skew |
| Overnight batch | `kavach-batch run` | NDJSON ingest + evidence |
| Manifest assertions | `partner/finance/scenarios/manifest.json` | Each scenario's `policy_decision`, `returned_decision`, `reason_codes` |
| Sync shadow (optional) | `POST /v1/evaluate` | Live API returns `returned_decision=PASS` in shadow mode |
| Fairness monitoring | `kavach-batch fairness` | Cohort disparity report over simulated day |

Offline (CI): batch + manifest + fairness in memory evidence — no Postgres or API required.

Live stack: set `PILOT_API_URL` and `KAVACH_DATABASE_URL` for Postgres batch jobs and sync shadow checks.

## One-command run

```bash
# Offline — same path CI runs on every PR
./scripts/simulate-credit-underwriting.sh

# Live stack (API must be up)
./scripts/start-local-review.sh   # terminal 1
export PILOT_API_URL=http://localhost:8080
export KAVACH_DATABASE_URL=postgres://kavach:change-me@localhost:5432/kavach
./scripts/simulate-credit-underwriting.sh   # terminal 2
```

Expected end:

```
CREDIT UNDERWRITING SIMULATION: N/N passed
Policy pack behaviour matches manifest — safe to merge PR.
```

## Git workflow (policy change in one PR)

Treat **pack + scenarios + manifest** as a single atomic change. CI blocks merge if they drift.

```bash
git checkout main && git pull
git checkout -b cursor/feat-policy-dti-threshold-4a07

# 1. Edit policy rules
$EDITOR packs/finance/v0.yaml

# 2. Add or update LOS-shaped rows (synthetic data only)
$EDITOR partner/finance/scenarios/credit_underwriting_v1.ndjson

# 3. Record expected outcomes for each correlation_id
$EDITOR partner/finance/scenarios/manifest.json

# 4. Update golden fixtures if CEL behaviour changed
$EDITOR golden/finance/v0/

# 5. Verify locally
./scripts/simulate-credit-underwriting.sh
cargo test --workspace

git add packs/finance/ partner/finance/scenarios/ golden/finance/
git commit -m "policy: tighten DTI threshold and add scenario coverage"
git push -u origin cursor/feat-policy-dti-threshold-4a07
```

Open a PR to `main`. GitHub CI runs `simulate-credit-underwriting.sh` after unit tests. Reviewers compare manifest expectations to pack diff — no manual Evaluate JSON editing.

### Scenario catalog layout

```
partner/finance/scenarios/
├── manifest.json                  # expected outcomes per correlation_id
└── credit_underwriting_v1.ndjson  # LOS export (one EvaluateRequest per line)
```

Each manifest scenario entry:

```json
{
  "id": "sim-cu-dti-alert-002",
  "name": "High DTI salaried (RBI threshold)",
  "correlation_id": "sim-cu-dti-alert-002",
  "expect": {
    "status": "ok",
    "policy_decision": "ALERT",
    "returned_decision": "ALERT",
    "reason_codes": ["CONSENT_OK", "RBI_DTI_EXCEEDED"]
  }
}
```

Use `reason_codes_contains` when order or extra codes may vary (e.g. `INFORMAL_ECONOMY_REVIEW`).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `CU_SIM_MANIFEST` | `partner/finance/scenarios/manifest.json` | Expected outcomes |
| `CU_SIM_INPUT` | `partner/finance/scenarios/credit_underwriting_v1.ndjson` | LOS NDJSON source |
| `PILOT_API_URL` | *(unset)* | Enable sync shadow checks |
| `KAVACH_DATABASE_URL` | *(unset)* | Postgres evidence + batch jobs |
| `PILOT_OPERATOR` | `admin-1` | Principal for sync evaluate |

## Relationship to other scripts

| Script | Scope |
|---|---|
| `simulate-credit-underwriting.sh` | **Policy pack** — manifest-driven batch + optional sync shadow |
| `simulate-partner-day.sh` | **Platform usage** — governance, idempotency, enforce cutover |
| `pilot-smoke.sh` | CI smoke on legacy `partner/finance/credit_underwriting_v1_batch.ndjson` |
| `pilot-signoff.sh` | Pilot Phase 1–3 exit criteria |

Run credit underwriting simulation on every policy PR. Run partner-day simulation before bank VPC pilot or system review.

## Privacy

Scenarios use synthetic identifiers only. Do not commit real PAN, Aadhaar, phone numbers, or account numbers. Kavach stores `input_digest` in evidence, not raw `input` (ADR-001 §8).
