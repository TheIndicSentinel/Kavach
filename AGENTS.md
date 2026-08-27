# Kavach — agent map

## Product

On-prem AI governance platform. v1 wedge: Indian structured credit decision APIs. Sector-agnostic engine; rules in `packs/{sector}/`.

## Repo

- **Path:** `KavachX/` (local) → **Remote:** https://github.com/TheIndicSentinel/Kavach.git
- **Reference MVP:** `../kavach/` (Python) — golden fixtures + console IA only; do not extend.

## Build & verify

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI runs the same on push/PR (`.github/workflows/ci.yml`).

## Layout

| Path | Purpose |
|---|---|
| `docs/ADR-001-evaluate-semantics.md` | Evaluate path — source of truth |
| `schemas/` | JSON Schema contracts |
| `proto/` | gRPC contracts |
| `packs/` | Policy packs (CEL) |
| `golden/` | Executable test oracles |
| `partner/` | Partner-shaped payload samples (not test oracles) |
| `crates/kavach-domain/` | Domain types (no I/O) |
| `crates/kavach-policy/` | CEL pack loader and evaluator |
| `crates/kavach-evidence/` | Hash chain, memory store, verify CLI |
| `crates/kavach-evaluate/` | Evaluate pipeline orchestration |
| `crates/kavach-storage/` | Postgres evidence chain, incidents, batch jobs |
| `crates/kavach-auth/` | Cedar RBAC policies and authorizer |
| `console/` | React governance console (static, embedded in API) — see `console/DESIGN.md` |
| `crates/kavach-api/` | HTTP/gRPC sync evaluate, health, auth |
| `crates/kavach-batch/` | NDJSON batch ingest worker |

## Phase

- **Done:** Milestone A + B, pilot Phase 1–3 validators, fairness console viewer, pilot sign-off script
- **You are here:** **System review checkpoint** — holistic review before bank VPC deployment ([SYSTEM_REVIEW_CHECKPOINT.md](docs/SYSTEM_REVIEW_CHECKPOINT.md))
- **Automated real-world test:** `./scripts/simulate-partner-day.sh` ([SIMULATE_PARTNER_DAY.md](docs/SIMULATE_PARTNER_DAY.md))
- **Next:** Partner pilot in bank VPC; production hardening (HMAC, mTLS, Helm)

See [docs/MILESTONE_A_EXIT.md](docs/MILESTONE_A_EXIT.md), [docs/MILESTONE_B_EXIT.md](docs/MILESTONE_B_EXIT.md), [docs/PARTNER_PILOT.md](docs/PARTNER_PILOT.md), [docs/PILOT_SIGNOFF.md](docs/PILOT_SIGNOFF.md), and [docs/SYSTEM_REVIEW_CHECKPOINT.md](docs/SYSTEM_REVIEW_CHECKPOINT.md).

Branching: see [docs/BRANCHING.md](docs/BRANCHING.md).

## Invariants

- Four decisions only: `PASS | ALERT | BLOCK | HUMAN_REVIEW`
- `ModelRecord.governance_mode` is authoritative; callers cannot set mode
- Evidence: `policy_decision` vs `returned_decision` (ADR-001)
- No raw `input` in persistence — `input_digest` only
- Modular monolith (ADR-002); not microservices in v1
