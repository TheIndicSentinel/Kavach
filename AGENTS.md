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
| `crates/kavach-batch/` | NDJSON batch ingest worker (Polars; not a default member) |
| `crates/kavach-jws/` | Strict canonical JWS codec |
| `crates/kavach-clocksync/` | Kernel clock sync status (trusted time) |
| `crates/kavach-dataplane/` | Agent data plane: tool registry, authorization core, reference resolver fixture |
| `crates/kavach-credential/` | Resource credentials: signed-then-encrypted JOSE broker, provider-side checks, vectors |
| `crates/kavach-mock-provider/` | PROTOCOL FIXTURE: mock messaging provider (not shipped) |
| `tools/` | Signed agent tool registry |

## Phase

- **Done:** Partner pilot Phases 1–3; MVP M0 (docs, hardening) and M1.1–M1.5 (ports, governed startup, signed packs, mandates, agent authz, CI proofs) — see [PRD.md](docs/PRD.md)
- **Done:** Hardening track H0–H4; H5a (clock sync, Postgres mandates, tracked migrations, signed agent evidence, authorization core, agent surfaces); H5b-1 steps 1–7 (`kavach-jws`, agent listener, signed tool registry, credential broker, reference resolver, mock provider)
- **In progress:** H5b-1 step 8 (gateway `POST /v1/tools/{tool}`), then step 9 (end-to-end) and H5b-2 (network isolation)
- **Next:** v0.1 developer preview (CLI first: `kavach init`, `dev up`, offline `authorize`/`why`, `attack`); TUI in v0.2. Open core boundary: [OPEN_CORE.md](OPEN_CORE.md)
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
