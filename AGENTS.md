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
| `crates/kavach-domain/` | Domain types (no I/O) |

## Phase

- **Done:** Phase 0 scaffolding (docs, contracts, domain crate, CI config)
- **Next:** Milestone A — `kavach-policy` → `kavach-evidence` → `kavach-evaluate` → `kavach-api` → `kavach-batch`

## Invariants

- Four decisions only: `PASS | ALERT | BLOCK | HUMAN_REVIEW`
- `ModelRecord.governance_mode` is authoritative; callers cannot set mode
- Evidence: `policy_decision` vs `returned_decision` (ADR-001)
- No raw `input` in persistence — `input_digest` only
- Modular monolith (ADR-002); not microservices in v1
