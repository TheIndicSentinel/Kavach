# Kavach on-prem install guide

Bank deployment model per [ADR-002](ADR-002-deployment-architecture.md): **two application containers**, **one PostgreSQL database**, and your existing **IdP** for operator identity. No service mesh.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐
│  Partner LOS /  │────▶│  kavach-batch    │──┐
│  data pipeline  │ NDJSON                 │  │
└─────────────────┘     └──────────────────┘  │
                                              ▼
┌─────────────────┐     ┌──────────────────┐  ┌─────────────┐
│  Scoring API /  │────▶│  kavach-api      │─▶│ PostgreSQL  │
│  underwriter UI │ HTTP/gRPC              │  │ evidence +  │
└─────────────────┘     └──────────────────┘  │ batch_jobs  │
         │                      │            └─────────────┘
         │                      ▼
         │               React console (static, embedded)
         ▼
    Corporate IdP ──▶ X-Kavach-Principal (Cedar RBAC, optional)
```

**Recommended first path:** batch shadow ingest (ADR-001 §6). Partners export daily NDJSON; `kavach-batch` writes governance results and evidence without blocking loan RPCs.

## Prerequisites

| Component | Version / notes |
|---|---|
| Rust toolchain | stable (`rustup.rs`) — build from source |
| PostgreSQL | 14+ with a dedicated database and role |
| Node.js | 22+ — only to build the governance console |
| TLS certificates | Required for production; mTLS optional for service-to-service |
| IdP | Maps users/groups to `X-Kavach-Principal` when Cedar RBAC is enabled |

## Build

```bash
git clone https://github.com/TheIndicSentinel/Kavach.git
cd Kavach

# Console static assets (embedded in kavach-api at build time)
./scripts/build-console.sh

# Release binaries
cargo build --release -p kavach-api -p kavach-batch -p kavach-evidence
```

Binaries: `target/release/kavach-api`, `target/release/kavach-batch`, `target/release/kavach-evidence`.

## PostgreSQL

Create database and user:

```sql
CREATE USER kavach WITH PASSWORD 'change-me';
CREATE DATABASE kavach OWNER kavach;
```

Set connection URL:

```bash
export KAVACH_DATABASE_URL="postgres://kavach:change-me@db.internal:5432/kavach"
```

Migrations (`evidence_chain_meta`, `decision_events`, `evaluate_incidents`, `batch_jobs`) run automatically on first API or batch Postgres connection.

## Configuration reference

Paths default via env vars; CLI flags override.

| Variable / flag | Required | Description |
|---|---|---|
| `KAVACH_PACK_PATH` / `--pack` | yes | Policy pack YAML (e.g. `packs/finance/v0.yaml`) |
| `KAVACH_MODEL_PATH` / `--model` | yes | Model record YAML (governance mode is authoritative) |
| `KAVACH_DATABASE_URL` / `--database-url` | prod | Postgres URL when `--evidence-store postgres` |
| `KAVACH_HMAC_SECRET` | optional | When set, HTTP evaluate requires `X-Kavach-Signature: sha256=<hex>` over raw body |
| `KAVACH_TLS_CERT`, `KAVACH_TLS_KEY` | prod | Server TLS for HTTP and gRPC |
| `KAVACH_TLS_CLIENT_CA` | optional | When set with cert/key, enables mTLS (client cert required) |
| `KAVACH_CEDAR_POLICY` | Cedar | Cedar policy file |
| `KAVACH_CEDAR_ENTITIES` | Cedar | Cedar entities JSON |

### kavach-api

```bash
./target/release/kavach-api \
  --listen 0.0.0.0:8080 \
  --grpc-listen 0.0.0.0:50051 \
  --pack packs/finance/v0.yaml \
  --model models/finance/credit-underwriting-v1.yaml \
  --evidence-store postgres \
  --access-control cedar \
  --cedar-policy crates/kavach-auth/policies/kavach.cedar \
  --cedar-entities crates/kavach-auth/policies/entities.example.json
```

**Endpoints**

| Path | Method | Auth (Cedar) | Purpose |
|---|---|---|---|
| `/health` | GET | `read_health` | Liveness |
| `/metrics` | GET | `read_metrics` | Prometheus text |
| `/v1/evaluate` | POST | `evaluate` | Sync evaluate |
| `/v1/runtime` | GET | `read_governance` | Active pack/model |
| `/v1/packs` | GET | `read_governance` | Policy pack inventory |
| `/v1/packs/{id}` | GET | `read_governance` | Policy pack detail |
| `/v1/packs/{id}/activate` | POST | `activate_pack` | Dual-control pack activate |
| `/v1/packs/rollback` | POST | `rollback_pack` | Dual-control pack rollback |
| `/v1/models` | GET | `read_governance` | Model inventory |
| `/v1/models/{id}` | GET | `read_governance` | Model detail |
| `/v1/models/{id}` | PATCH | `update_model` | Dual-control model promotion |
| `/v1/admin/audit` | GET | `read_audit` | Admin audit log |
| `/` | GET | — | Governance console (when built) |

Lifecycle mutations require `X-Kavach-Principal` (actor) and `X-Kavach-Approver` (distinct admin).

gRPC: `EvaluateService` on `--grpc-listen` (default `50051`). Pass principal via metadata `x-kavach-principal`.

**PoC / dev (memory evidence, no Cedar):**

```bash
cargo run -p kavach-api -- \
  --pack packs/finance/v0.yaml \
  --model models/finance/credit-underwriting-v1.yaml
```

### kavach-batch

```bash
./target/release/kavach-batch run \
  --input /data/in/applications.ndjson \
  --output /data/out/results.ndjson \
  --pack packs/finance/v0.yaml \
  --model models/finance/credit-underwriting-v1.yaml \
  --evidence-store postgres
```

Input: one `EvaluateRequest` JSON object per line (NDJSON).  
Output: one result row per input line (`status`, `policy_decision`, `returned_decision`, `evidence_id`, …).

Partner-shaped sample files: [`partner/finance/`](../partner/finance/).

### Evidence verification

Export the evidence chain to NDJSON, then:

```bash
./target/release/kavach-evidence verify --file /path/to/export.ndjson
```

## Container deployment (outline)

Run two containers from the same image (different `CMD`):

1. **kavach-api** — ports 8080 (HTTP) and 50051 (gRPC); mount pack/model YAML or bake into image.
2. **kavach-batch** — invoked as a CronJob or workflow step; no inbound ports.

Both containers share `KAVACH_DATABASE_URL` and pack/model paths. Place Postgres in the same VPC subnet as the apps (ADR-001 latency SLO).

Reverse proxy / API gateway terminates TLS and forwards `X-Kavach-Principal` from the IdP JWT or service account mapping.

## Partner integration checklist

1. Map LOS export fields to `EvaluateRequest` (see `partner/finance/credit_underwriting_v1_request.json`).
2. Validate against `schemas/evaluate-request.schema.json`.
3. Run batch shadow with `models/finance/credit-underwriting-v1.yaml` (`governance_mode: shadow`).
4. Review `policy_decision` in batch output before switching sync enforce on the scoring API path.
5. Enable Postgres evidence and periodic `kavach-evidence verify` on exports.

## Verify install

```bash
./scripts/verify.sh

curl -s http://localhost:8080/health
# With Cedar: curl -s -H 'X-Kavach-Principal: viewer-1' http://localhost:8080/health
```

## Related docs

- [ADR-001 evaluate semantics](ADR-001-evaluate-semantics.md)
- [ADR-002 deployment architecture](ADR-002-deployment-architecture.md)
- [Milestone A exit gate](MILESTONE_A_EXIT.md)
- [Partner payload samples](../partner/README.md)
