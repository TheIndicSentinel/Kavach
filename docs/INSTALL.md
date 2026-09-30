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
    Corporate IdP ──▶ OIDC access token (Cedar RBAC principal)
```

**Recommended first path:** batch shadow ingest (ADR-001 §6). Partners export daily NDJSON; `kavach-batch` writes governance results and evidence without blocking loan RPCs.

## Prerequisites

| Component | Version / notes |
|---|---|
| Rust toolchain | stable (`rustup.rs`) — build from source |
| PostgreSQL | 14+ with a dedicated database and role |
| Node.js | 22+ — only to build the governance console |
| TLS certificates | Required for production; mTLS optional for service-to-service |
| IdP | Issues OIDC access tokens (principal + groups) for Cedar RBAC (ADR-008) |

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
| `KAVACH_MTLS_PRINCIPAL_SAN` | optional | `uri` or `dns`: the client certificate SAN becomes the principal (needs `KAVACH_TLS_CLIENT_CA`) |
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
  --cedar-entities /etc/kavach/entities.json \
  --oidc-issuer https://idp.bank.example/realms/kavach \
  --oidc-audience kavach-api \
  --oidc-jwks-file /etc/kavach/jwks.json
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
| `/v1/admin/retention` | GET | `read_retention` | Retention policy |
| `/v1/admin/retention` | PATCH | `update_retention` | Dual-control retention update |
| `/v1/admin/retention/apply` | POST | `apply_retention` | Apply retention tombstones |
| `/v1/admin/evidence/{id}/erase` | POST | `erase_evidence` | DPDP erasure tombstone |
| `/v1/admin/tombstones` | GET | `read_tombstones` | Tombstone list |
| `/v1/admin/incidents` | GET | `read_incidents` | Evaluate incident log |
| `/v1/admin/batch-jobs` | GET | `read_batch_jobs` | Batch job inventory |
| `/v1/admin/batch-jobs/{job_id}` | GET | `read_batch_jobs` | Batch job detail |
| `/` | GET | — | Governance console (when built) |

Every route except `/` needs `Authorization: Bearer <access token>` when Cedar is on. Lifecycle mutations also need `X-Kavach-Approver` (a different admin; still self-asserted until H3). The actor is the token's principal.

gRPC: `EvaluateService` on `--grpc-listen` (default `50051`). Pass the token in metadata `authorization: Bearer <token>`.

**Secure defaults.** `--access-control` defaults to `cedar` (env `KAVACH_ACCESS_CONTROL`). Running without access control requires the explicit `--insecure-dev` flag (env `KAVACH_INSECURE_DEV`); the API then allows every request and prints a warning at startup. Never use it outside local development.

**Pack integrity pinning.** At startup the API logs the SHA-256 of the active pack (`pack_sha256=sha256:<hex>`) and `/v1/runtime` returns it. Pass `--pack-sha256 <digest>` (env `KAVACH_PACK_SHA256`; also supported by `kavach-batch run`) to refuse startup if the pack file differs. Activation records the digest; rollback and model updates refuse to reload a pack file whose digest changed since it was pinned (HTTP 409 `pack_digest_mismatch`, recorded in the admin audit log). Compute a digest with `shasum -a 256 packs/finance/v0.yaml`.

- Integrity is **byte-level**: any change to a pack file, including comments, requires dual-control re-activation before rollback or model update will reload it.
- Start `kavach-api` and `kavach-batch` with the **same** `--pack-sha256` so both evaluate identical bytes.
- Without `--pack-sha256`, a restart in **memory mode** loads whatever is at `--pack` and reports its digest; the pin is what makes restart fail on substituted bytes.
- **Postgres mode:** the governed runtime pointer decides the startup pack. The first start in a new database records `--pack` as the baseline (audited `startup_baseline_recorded`). Afterwards, `kavach-api` and `kavach-batch` refuse to start if `--pack` is a different path or its bytes differ from the digest recorded at activation — change packs through dual-controlled activate. For recovery only, `kavach-api --bootstrap-pack` (env `KAVACH_BOOTSTRAP_PACK`) starts anyway and records `startup_bootstrap_override` in the audit log.
- **Pack limits:** ≤ 256 KiB, ≤ 200 rules, expressions ≤ 2048 characters, `cel_runtime_limits.timeout_ms` 1–1000. `max_alloc_bytes` is accepted but advisory.

**Signed packs.** Configure trusted signers to require a valid detached signature for every pack load (startup, activate, rollback, model update, and `kavach-batch run`):

```bash
# On a signing workstation (not the API host)
kavach-keys generate   --dir ./signing-keys --kid pack-signer-1
kavach-keys public-key --dir ./signing-keys --kid pack-signer-1   # -> signers.json entry
kavach-keys sign-pack  --dir ./signing-keys --kid pack-signer-1 --pack packs/finance/v0.yaml
kavach-keys verify-pack --signers signers.json --pack packs/finance/v0.yaml
```

`signers.json`: `{"signers":[{"kid":"pack-signer-1","public_key":"<hex>"}]}`. Deploy the `.sig` file next to each pack and start with `--pack-signers signers.json` (env `KAVACH_PACK_SIGNERS`). Without `--pack-signers`, behaviour is unchanged. Any byte change to a pack requires re-signing.

**Caller authentication (OIDC access tokens, ADR-008).** With Cedar on, the API needs an authenticated principal source; startup fails without one unless `--insecure-dev` is set.

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--oidc-issuer` | `KAVACH_OIDC_ISSUER` | — | Expected `iss` |
| `--oidc-audience` | `KAVACH_OIDC_AUDIENCE` | — | Expected `aud` |
| `--oidc-jwks-file` | `KAVACH_OIDC_JWKS_FILE` | — | JWKS on disk (offline) |
| `--oidc-jwks-url` | `KAVACH_OIDC_JWKS_URL` | — | JWKS over HTTPS; refreshed every 10 min and on an unknown `kid` |
| `--oidc-principal-claim` | `KAVACH_OIDC_PRINCIPAL_CLAIM` | `sub` | Claim used as the Cedar principal id |
| `--oidc-groups-claim` | `KAVACH_OIDC_GROUPS_CLAIM` | `groups` | Array claim mapped to Cedar groups |
| `--oidc-leeway-seconds` | `KAVACH_OIDC_LEEWAY_SECONDS` | `60` | Clock skew for `exp`/`nbf` |

Issuer, audience and one JWKS source must be set together. Tokens must be signed with RS256, PS256, ES256 or EdDSA and carry a `kid`. Token groups become Cedar `Kavach::Group` parents (for example `admins`, `viewers`, `operators`), merged with memberships in `--cedar-entities`; name IdP groups to match your Cedar groups, or list users in the entities file. `X-Kavach-Principal` is refused (401) unless `--insecure-dev`; sending it together with a token is a 400.

*Keycloak (development):* create a realm and a confidential client with the service-account flow, add an audience mapper for `kavach-api` and a *Group Membership* mapper named `groups` (full path off). Then `--oidc-issuer http(s)://<host>/realms/<realm>`, `--oidc-jwks-url https://<host>/realms/<realm>/protocol/openid-connect/certs` (or save that JSON as the JWKS file), and get a token with `curl -d grant_type=client_credentials -d client_id=... -d client_secret=... https://<host>/realms/<realm>/protocol/openid-connect/token`.

**mTLS principals (machine callers).** With `--tls-cert`, `--tls-key`, `--tls-client-ca` and `--mtls-principal-san uri` (env `KAVACH_MTLS_PRINCIPAL_SAN`; `dns` also supported), the client certificate's single URI SAN is the Cedar principal on HTTP and gRPC. Add that id to the entities file with its groups, for example:

```json
{ "uid": { "type": "Kavach::User", "id": "spiffe://bank.example/los" }, "attrs": {},
  "parents": [{ "type": "Kavach::Group", "id": "operators" }] }
```

A certificate with no SAN, or several SANs, of the configured type gets 401. A bearer token, when also sent, takes precedence. Client certificates are not checked for revocation; issue short-lived ones. Without `--mtls-principal-san`, mTLS only restricts who can connect.

**HMAC v2 on `/v1/evaluate`.** With `--hmac-secret`, send `X-Kavach-Timestamp` (unix seconds, ±300 s), `X-Kavach-Nonce` (16–128 characters `[A-Za-z0-9_-]`, single use) and `X-Kavach-Signature: sha256=<hex HMAC-SHA256>` over `v2\n{ts}\n{nonce}\n{METHOD}\n{path?query}\n` followed by the raw body. `scripts/pilot-phase3.sh` shows a working signer.

**Upgrading from M1.5 (breaking).** Callers that sent only `X-Kavach-Principal` now get 401: issue access tokens, or run `--insecure-dev` locally. Body-only HMAC signatures are rejected; sign v2. The pilot compose file now requires `POSTGRES_PASSWORD`, `KAVACH_OIDC_ISSUER`/`KAVACH_OIDC_AUDIENCE`, and a `deploy/pilot-config/` directory with `entities.json` and `jwks.json`; Postgres is no longer published on the host.

**PoC / dev (memory evidence, no Cedar — insecure, local only):**

```bash
cargo run -p kavach-api -- \
  --pack packs/finance/v0.yaml \
  --model models/finance/credit-underwriting-v1.yaml \
  --access-control none --insecure-dev
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

**Historical exports:** add `--decision-from 2026-09-01T00:00:00Z --decision-to 2026-09-30T23:59:59Z` to accept rows whose `decision_time` falls inside the declared window (inclusive). Without these flags each row must be within ±300 s of the current time.

**Idempotency:** a row whose `(model_id, correlation_id)` was already evaluated with *different* input fails with an idempotency conflict; an identical row returns the stored decision.

Input: one `EvaluateRequest` JSON object per line (NDJSON).  
Output: one result row per input line (`status`, `policy_decision`, `returned_decision`, `evidence_id`, …).

Partner-shaped sample files: [`partner/finance/`](../partner/finance/).

Fairness reports (paired request + result NDJSON):

```bash
./target/release/kavach-batch fairness \
  --requests /data/in/applications.ndjson \
  --results /data/out/results.ndjson \
  --report disparity \
  --attribute input.customer_segment \
  --output /data/out/disparity_report.json
```

Use `--report inclusion` with `--inclusion-field input.informal_sector` for PSL/inclusion monitoring.

### Evidence verification

Export the evidence chain to NDJSON, then:

```bash
./target/release/kavach-evidence verify --file /path/to/export.ndjson
```

### Agent policy analysis (development / CI)

The agent authorization policies (`crates/kavach-authz/policies/`) are formally analysed on every CI run. To run the analysis locally:

```bash
./scripts/fetch-cvc5.sh                      # pinned cvc5 1.3.1 (BSD build), SHA-256 verified, into .tools/
export CVC5="$PWD/.tools/cvc5/bin/cvc5"
cargo run -p kavach-cedar-analysis          # PROVEN / CAUGHT lines; exit code 1 on any failure
```

`./scripts/verify.sh` runs the analysis when `CVC5` is set. Any change to the agent schema or policies must keep this job green.

## Container deployment (outline)

Run two containers from the same image (different `CMD`):

1. **kavach-api** — ports 8080 (HTTP) and 50051 (gRPC); mount pack/model YAML or bake into image.
2. **kavach-batch** — invoked as a CronJob or workflow step; no inbound ports.

Both containers share `KAVACH_DATABASE_URL` and pack/model paths. Place Postgres in the same VPC subnet as the apps (ADR-001 latency SLO).

Reverse proxy / API gateway terminates TLS and passes the caller's `Authorization: Bearer` access token through unchanged (a trusted-proxy identity header is not supported yet; ADR-008).

## Partner integration checklist

See [PARTNER_PILOT.md](PARTNER_PILOT.md) for the full pilot playbook. Quick path:

1. Map LOS export fields to `EvaluateRequest` (see `partner/finance/credit_underwriting_v1_request.json`).
2. Validate against `schemas/evaluate-request.schema.json`.
3. Run batch shadow with `models/finance/credit-underwriting-v1.yaml` (`governance_mode: shadow`).
4. Review `policy_decision` in batch output before switching sync enforce on the scoring API path.
5. Enable Postgres evidence and periodic `kavach-evidence verify` on exports.

## Verify install

```bash
./scripts/verify.sh

curl -s http://localhost:8080/health
# With Cedar: curl -s -H "Authorization: Bearer ${TOKEN}" http://localhost:8080/health
```

## Related docs

- [ADR-001 evaluate semantics](ADR-001-evaluate-semantics.md)
- [ADR-002 deployment architecture](ADR-002-deployment-architecture.md)
- [Milestone A exit gate](MILESTONE_A_EXIT.md)
- [Partner pilot playbook](PARTNER_PILOT.md)
- [Partner payload samples](../partner/README.md)
