# Kavach — agent map

## Product

On-prem AI governance platform. v1 wedge: Indian structured credit decision APIs. Sector-agnostic engine; rules in `packs/{sector}/`.

## Repo

- **Remote:** https://github.com/TheIndicSentinel/Kavach.git
- **Reference MVP:** `../kavach/` (Python) — golden fixtures + console IA only; do not extend.

## Build & verify

```bash
./scripts/verify.sh   # fmt, clippy (pedantic, -D warnings), tests, audit/deny
```

CI runs the same on push/PR (`.github/workflows/ci.yml`), plus Postgres tests, cvc5 policy proofs, the trusted-time probe and the independent `jose` credential check. Local setup: [docs/DEVELOPING.md](docs/DEVELOPING.md). Toolchain pinned in `rust-toolchain.toml`.

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
| `crates/kavach-evidence/` | Hash chain, memory store, v1 verification (library) |
| `crates/kavach-evidence-cli/` | The `kavach-evidence` binary: `verify`, evidence bundle writer |
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
| `crates/kavach-batch/` | NDJSON batch ingest worker (Polars; not a default member) |
| `crates/kavach-jws/` | Strict canonical JWS codec |
| `crates/kavach-clocksync/` | Kernel clock sync status (trusted time) |
| `crates/kavach-dataplane/` | Agent data plane: tool registry, authorization core, reference resolver fixture |
| `crates/kavach-credential/` | Resource credentials: signed-then-encrypted JOSE broker, provider-side checks, vectors |
| `crates/kavach-mock-provider/` | PROTOCOL FIXTURE: mock messaging provider (not shipped) |
| `tools/` | Signed agent tool registry |

## Phase

- **Done:** Partner pilot Phases 1–3; MVP M0 (docs, hardening) and M1.1–M1.5 (ports, governed startup, signed packs, mandates, agent authz, CI proofs) — see [PRD.md](docs/PRD.md)
- **Done:** Hardening track H0–H5b (clock sync, Postgres mandates, tracked migrations, signed agent evidence, authorization core, agent listener, signed tool registry, credential broker, gateway, network isolation); evidence E1–E4 (checkpoints, signed bundles, offline verification); Postgres TLS; HSM-backed signing keys with rotation
- **Done:** CLI v0.1 (`init`, `dev up`, `authorize`, `call`, `why`, `attack`, `demo`, `simulate` S1–S3, `evidence`, release tooling); revocation by system-of-record event (ADR-012): evidence records, bundle format 2, attack catalog v4, simulated payments and disputes
- **In progress:** Phase 0 hygiene (docs, graceful shutdown, alert rules), then the agent kill switch (ADR-013)
- **Next:** pilot blockers (real-provider mode, a HUMAN_REVIEW resolution path, consent and reference stores, an HA reference, the reference-machine benchmark, a DR drill), then a managed single-tenant SaaS foundation. Pre-alpha. Open core boundary: [OPEN_CORE.md](OPEN_CORE.md)
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
- Privacy by default: no telemetry; raw personal data is never logged, recorded or returned (redacting types, pseudonyms)
- Commits are signed off (DCO); licence Apache-2.0
