# Phase 0 Exit Gate

Sign off before starting Milestone A (`kavach-policy`).

## Documentation

- [x] ADR-001 evaluate semantics frozen
- [x] ADR-002 modular monolith deployment model
- [x] DecisionEvent compatibility policy
- [x] DATA_AND_FAIRNESS skeleton
- [x] THREAT_MODEL skeleton
- [x] CONTROLS mapping skeleton

## Contracts

- [x] JSON Schema: EvaluateRequest, DecisionEvent, PolicyPack, ModelRecord
- [x] Protobuf: `proto/evaluate.proto` aligned with domain types
- [x] Finance pack v0: `packs/finance/v0.yaml`
- [x] Model record: `models/finance/credit-underwriting-v1.yaml`

## Test oracles

- [x] `golden/finance/v0/` — production-shaped fixtures (4)
- [x] `golden/finance/mvp_mechanics/` — MVP-only fixtures (1)

## Code

- [x] `kavach-domain` — types, decision mapping, golden loader
- [x] Contract validation tests (schema + pack + model)
- [x] CI: fmt, clippy, test, audit, deny

## Verification

- [ ] `cargo test --workspace` green locally
- [ ] CI green on GitHub `main`
- [ ] No API server, Postgres, or React in repo

## Explicitly not Phase 0

- Partner real payload sample (required for Milestone A **exit**, not Phase 0)
- `kavach-policy`, `kavach-evidence`, `kavach-api`
- Console / Helm

## Sign-off

When all boxes above are checked, begin Milestone A in order:

1. `kavach-policy`
2. `kavach-evidence`
3. `kavach-evaluate`
4. `kavach-api`
5. `kavach-batch`

**Phase 0 status:** Complete pending CI green on GitHub and local `cargo test`.
