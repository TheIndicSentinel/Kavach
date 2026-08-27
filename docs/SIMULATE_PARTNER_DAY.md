# Simulate partner day (automated real-world test)

Replaces manual Evaluate JSON editing with an **automated day-in-the-life simulation** of how a partner bank uses Kavach.

## What it simulates

| Time (narrative) | Real-world activity | Automated check |
|---|---|---|
| 06:00 | Partner payloads validated at CI | `cargo test` partner finance contracts |
| 06:30 | Overnight LOS NDJSON export ingested | `kavach-batch run` → Postgres evidence + batch job |
| 09:00–17:00 | Real-time scoring API calls | 4 sync evaluate scenarios (PASS, ALERT, HUMAN_REVIEW) |
| — | LOS retries same application | Idempotency (same `evidence_id`) |
| 17:30 | Compliance + ops review | Runtime, batch jobs, audit APIs |
| 18:00 | Model risk fairness monitoring | `kavach-batch fairness` disparity report |
| 18:30 | Production enforce cutover | Promote to enforce, verify `policy == returned`, restore |

No manual console JSON editing required.

## One-command run

```bash
# Start API first (once)
./scripts/start-local-review.sh

# Run simulation (separate terminal or after start script)
./scripts/simulate-partner-day.sh
```

Expected end:

```
SIMULATION: N/N steps passed
Real-world path validated — console manual review is optional.
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PILOT_API_URL` | `http://localhost:8080` | Live API |
| `KAVACH_DATABASE_URL` | `postgres://kavach:change-me@localhost:5432/kavach` | Postgres batch path |
| `PILOT_OPERATOR` | `admin-1` | Sync evaluate principal |
| `PILOT_ACTOR` / `PILOT_APPROVER` | `admin-1` / `admin-2` | Enforce cutover dual control |
| `SIM_SKIP_ENFORCE` | — | Set `1` to skip enforce cutover step |
| `SIM_SKIP_WAIT` | — | Set `1` to skip API readiness poll |

## Relationship to other scripts

| Script | Scope |
|---|---|
| `simulate-credit-underwriting.sh` | **Policy pack** — manifest-driven batch + optional sync shadow ([CREDIT_UNDERWRITING_SIMULATION.md](CREDIT_UNDERWRITING_SIMULATION.md)) |
| `simulate-partner-day.sh` | **Real-world usage** — batch + sync + governance + fairness |
| `pilot-signoff.sh` | Pilot Phase 1–3 exit criteria |
| `system-review.sh` | Full engineering gate (verify + sign-off + evidence) |

## Console UI testing

The simulation validates **API and worker behaviour**. Use the console separately for visual/UI review at [SYSTEM_REVIEW_CHECKPOINT.md](SYSTEM_REVIEW_CHECKPOINT.md).

After simulation passes, spot-check **Batch jobs** and **Audit** in the console to see the artifacts the simulation created.
