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
| `crates/kavach-auth/` | Cedar RBAC policies and authorizer (API access) |
| `crates/kavach-ports/` | Port traits + typed errors (ADR-006) |
| `crates/kavach-ports-testkit/` | Test doubles + conformance suites |
| `crates/kavach-keys/` | Ed25519 key providers, pack signatures, `kavach-keys` CLI |
| `crates/kavach-mandate/` | Task Mandates: SoR events, issuance, delegation, revocation (library) |
| `crates/kavach-authz/` | Agent authorization: Cedar `Kavach::Agent` policies + combiner (library) |
| `crates/kavach-cedar-analysis/` | CI-only formal proofs of agent policies (cvc5) |
| `console/` | React governance console (static, embedded in API) — see `console/DESIGN.md` |
| `crates/kavach-api/` | HTTP/gRPC sync evaluate, health, auth |
| `crates/kavach-batch/` | NDJSON batch ingest worker |

## Phase

- **Done:** Partner pilot Phases 1–3; MVP M0 (docs, hardening) and M1.1–M1.5 (ports, governed startup, signed packs, mandates, agent authz, CI proofs) — see [PRD.md](docs/PRD.md)
- **In progress:** Hardening track H0–H4 (doc corrections, evidence correctness, authenticated principals, real dual control, mandate/authz hardening) before M1.6
- **Next:** H5 = M1.6 reshaped as a thin enforced vertical slice (`send_reminder` end to end)
- **Security claims:** [SECURITY_PROPERTIES.md](docs/SECURITY_PROPERTIES.md) — updated in the same PR as any guarantee change

See [docs/MILESTONE_A_EXIT.md](docs/MILESTONE_A_EXIT.md), [docs/MILESTONE_B_EXIT.md](docs/MILESTONE_B_EXIT.md), and [docs/PARTNER_PILOT.md](docs/PARTNER_PILOT.md).

Branching: see [docs/BRANCHING.md](docs/BRANCHING.md).

## Invariants

- Four decisions only: `PASS | ALERT | BLOCK | HUMAN_REVIEW`
- `ModelRecord.governance_mode` is authoritative; callers cannot set mode
- Evidence: `policy_decision` vs `returned_decision` (ADR-001)
- No raw `input` in persistence — `input_digest` only
- Modular monolith (ADR-002); not microservices in v1
- Agent authority comes only from mandates issued from signed system-of-record events (ADR-004); model output never grants authority
