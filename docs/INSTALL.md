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

## Try it on one machine: `scripts/demo.sh`

To see the console work before a real install, `scripts/demo.sh` runs a seeded Kavach on your machine, signed in through a local test identity provider. It is for trying Kavach out, not a deployment: everything listens on 127.0.0.1, runs with `--insecure-dev`, and the identity provider signs in whoever picks a name.

**1. A Postgres it can reach (14 or newer; no Docker needed).** demo.sh never starts or stops Postgres. If it cannot reach one, it says so and prints the start command. One way, with the PostgreSQL server binaries installed (from a package manager or a relocatable build):

```bash
initdb -D ~/kavach-pg/data -U kavach --auth=trust      # once; trust is for loopback development only
pg_ctl -D ~/kavach-pg/data -l ~/kavach-pg/pg.log \
  -o '-p 55433 -k /tmp -c listen_addresses=127.0.0.1' start
```

That matches demo.sh's default, `postgres://kavach@127.0.0.1:55433/postgres`. For another Postgres, set `KAVACH_DEMO_DATABASE_URL` (and give `stop` the same value). Each run creates its own schema, `kavach_demo_<epoch seconds>`. `stop` drops it, and drops no other schema.

**2. Run it** from the repository root. It needs cargo, npm, curl, psql and pg_isready.

```bash
scripts/demo.sh
```

It builds the console and then kavach-api (which embeds the console), the OIDC test double, `kavach-dev` and the mock provider; the first build takes a while. It then:

1. generates a development bundle in `.demo/` (owner-only; keys, tokens, logs, pids);
2. starts the test identity provider on `:9400` and the mock delivery provider on `:8443`;
3. starts kavach-api on `:8080`, with Postgres evidence, Cedar and console sign-in;
4. seeds what the console's real-stack tests use: a mandate, agent calls under it (allowed or blocked), a call with a forged mandate, a call by another agent, then the mandate's revocation and a call after it.

**3. Open the URL it prints,** `http://127.0.0.1:8080/`: the console kavach-api serves, not a Vite dev server. Use `127.0.0.1`, not `localhost`: the sign-in returns to the address it was given. Choose **Sign in**. The test identity provider asks who to sign in as, on every sign-in:

| User | Group | What Cedar lets the group do |
|---|---|---|
| `demo-admin` | `admins` | every proposal, stop and read |
| `demo-approver` | `change-approvers` | approve or reject change requests |
| `demo-operator` | `operators` | evaluate; read governance |
| `demo-viewer` | `viewers` | read governance and health |

A page that a user's group may not read shows "Not permitted"; the server decides. To switch users, sign out and sign in again.

**4. Stop:** `scripts/demo.sh stop` stops what it started and drops its schema. `scripts/demo.sh status` says whether it runs. A second `scripts/demo.sh` while one runs is refused.

**"The Kavach API is not reachable"** in a console served by `npm run dev` means nothing listens on `:8080` behind the Vite proxy: start `scripts/demo.sh`, or kavach-api yourself.

## Build

```bash
git clone https://github.com/TheIndicSentinel/Kavach.git
cd Kavach

# Console static assets (embedded in kavach-api at build time)
./scripts/build-console.sh

# Release binaries
cargo build --release -p kavach-api -p kavach-batch -p kavach-evidence-cli
```

Binaries: `target/release/kavach-api`, `target/release/kavach-batch`, `target/release/kavach-evidence`.

## PostgreSQL

Use **two roles** (ADR-005 §1): an owner that runs migrations, and a least-privilege runtime role the API and batch serve as.

```sql
CREATE USER kavach WITH PASSWORD 'owner-secret';             -- owner: migrations only
CREATE DATABASE kavach OWNER kavach;
CREATE ROLE kavach_runtime LOGIN PASSWORD 'runtime-secret';   -- the API and batch
```

```bash
export KAVACH_MIGRATION_DATABASE_URL="postgres://kavach:owner-secret@db.internal:5432/kavach"
export KAVACH_DATABASE_URL="postgres://kavach_runtime:runtime-secret@db.internal:5432/kavach"
```

- **TLS to Postgres is required.** Every connection (`kavach-api`, `kavach-batch`, `kavach-evidence export` and `checkpoints`) uses TLS, verifies the server's certificate chain and checks its host name: `sslmode=verify-full`, which is also what a URL without `sslmode` gets.
  - The server certificate must name the host you connect to. Prefer a DNS name in the URL and in the certificate; an IP address works only if the certificate lists that address.
  - A private CA: `--database-ca /etc/kavach/db-ca.pem` (`KAVACH_DATABASE_CA`), trusted in addition to the system roots. `sslrootcert=` in the URL also works.
  - A URL that asks for a weaker mode (`disable`, `allow`, `prefer`, `require`, `verify-ca`) **refuses startup**. `PGSSLMODE` in the environment cannot weaken a connection: the mode is always set from the URL or the default.
  - **Development only:** plaintext needs both `--insecure-dev` (for the export commands: `--allow-plaintext-database`) **and** `sslmode=disable` in the URL. The flag alone downgrades nothing, and a warning is logged.
  - On the server: `ssl = on` with a certificate and key, and `hostssl` (not `host`) lines in `pg_hba.conf`, so Postgres itself refuses plaintext clients. `deploy/postgres/pg_hba.conf` and `deploy/postgres/tls-entrypoint.sh` do this for the official Postgres image; the pilot stack uses them with a certificate from `scripts/pilot-db-tls.sh`.
- On start, `kavach-api` applies pending migrations as the owner, then serves as `kavach_runtime` and never migrates with it. Applied migrations are tracked with checksums (`_sqlx_migrations`), so each runs once and an edited migration is refused. A database created by an earlier release adopts tracking on its first start.
- Migrations grant `kavach_runtime` only what the application uses. Evidence and audit tables (`decision_events`, `admin_audit_log`, `evaluate_incidents`, `evidence_tombstones`) are insert-only. Nothing gets `TRUNCATE`, and the runtime role cannot alter tables or drop the immutability triggers.
- Contributors: how a migration is written (grants, append-only triggers, `NOT VALID` then `VALIDATE`) is in [MIGRATIONS.md](MIGRATIONS.md).
- If you create `kavach_runtime` **after** migrations already ran, grant it: `psql -U kavach -d kavach -c 'SELECT kavach_grant_runtime();'`.
- `kavach-batch` never migrates unless given `--migration-database-url`; start `kavach-api` first.
- **Development only:** with just `KAVACH_DATABASE_URL` (no migration URL), one role both migrates and serves, and it owns its tables.
- **Evidence export role (optional).** Create a third, read-only role for whoever exports agent evidence:
  ```sql
  CREATE ROLE kavach_auditor LOGIN PASSWORD 'auditor-secret';   -- kavach-evidence export
  ```
  Migrations grant it `SELECT` on the agent evidence tables only (`agent_decisions`, `agent_outcomes`, `evidence_checkpoints`, `agent_evidence_chains`): it can write nothing and read nothing else, so an export cannot change what it reads. If you create it **after** migrations already ran, grant it: `psql -U kavach -d kavach -c 'SELECT kavach_grant_auditor();'`. The compose init script creates it when `KAVACH_AUDITOR_DB_PASSWORD` is set. Give this role's credentials to the auditor, not to the API.
- **Export key.** Evidence bundles are signed by the person who exports them, with a key of their own whose id starts with `export-` (`kavach-keys generate --dir <their dir> --kid export-<name>-1`). Keep it off the API host. The API refuses to start if one of its own keys is named `export-…` ([EVIDENCE_BUNDLE.md](EVIDENCE_BUNDLE.md)).
- The pilot compose stack creates `kavach_runtime` on first init (`deploy/postgres/init`); set `KAVACH_RUNTIME_DB_PASSWORD` in `deploy/.env`.

## Configuration reference

Paths default via env vars; CLI flags override.

| Variable / flag | Required | Description |
|---|---|---|
| `KAVACH_PACK_PATH` / `--pack` | yes | Policy pack YAML (e.g. `packs/finance/v0.yaml`) |
| `KAVACH_MODEL_PATH` / `--model` | yes | Model record YAML (governance mode is authoritative) |
| `KAVACH_DATABASE_URL` / `--database-url` | prod | Postgres URL when `--evidence-store postgres` — the least-privilege `kavach_runtime` role in production |
| `KAVACH_MIGRATION_DATABASE_URL` / `--migration-database-url` | prod | Owner role that runs migrations; when set, the runtime URL never migrates |
| `KAVACH_DATABASE_POOL_SIZE` / `--database-pool-size` | optional | Connections in the API's runtime Postgres pool (default 5; 1–256) |
| `KAVACH_DATABASE_CA` / `--database-ca` | optional | CA certificates (PEM) trusted for the Postgres server certificate, besides the system roots. Connections always use `sslmode=verify-full`; a weaker `sslmode` in a URL refuses startup outside `--insecure-dev` |
| `KAVACH_HMAC_SECRET` | optional | When set, HTTP evaluate requires `X-Kavach-Signature: sha256=<hex>` over raw body. At least 32 bytes (`openssl rand -hex 32`); a shorter secret stops the start |
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
| `/v1/models` | GET | `read_governance` | Model inventory |
| `/v1/models/{id}` | GET | `read_governance` | Model detail |
| `/v1/change-requests` | POST | `propose_<kind>` | Propose a governance change |
| `/v1/change-requests` | GET | `read_change_requests` | List (`?status=pending`) |
| `/v1/change-requests/{id}` | GET | `read_change_requests` | Detail |
| `/v1/change-requests/{id}/approve` | POST | `approve_<kind>` | Approve and apply (`{"change_digest": …}`) |
| `/v1/change-requests/{id}/reject` | POST | `approve_<kind>` | Reject (`{"reason": …}`) |
| `/v1/change-requests/{id}/cancel` | POST | `propose_<kind>` | Proposer withdraws |
| `/v1/admin/audit` | GET | `read_audit` | Admin audit log |
| `/v1/agent-decisions/{record_id}` | GET | `read_evidence` | One agent decision record and its outcome (`kavach why`). Record ids are sequential, so the protection is the role, a rate limit (5/s, burst 20) and an audit entry for every read, found or not; a read that cannot be audited is refused |
| `/v1/decision-events/{evidence_id}` | GET | `read_evidence` | One evaluate decision event (`kavach why`), as export views show it: the input only as `input_digest`, a tombstoned event redacted and marked. Same rate limit and per-read audit as agent records |
| `/v1/admin/retention` | GET | `read_retention` | Retention policy |
| `/v1/admin/tombstones` | GET | `read_tombstones` | Tombstone list |
| `/v1/admin/incidents` | GET | `read_incidents` | Evaluate incident log |
| `/v1/admin/batch-jobs` | GET | `read_batch_jobs` | Batch job inventory |
| `/v1/admin/batch-jobs/{job_id}` | GET | `read_batch_jobs` | Batch job detail |
| `/` | GET | — | Governance console (when built) |

Every route except `/` needs `Authorization: Bearer <access token>` when Cedar is on.

**Governance changes (maker-checker, ADR-009).** Pack activation and rollback, model status/mode, the retention period, DPDP erasure and retention runs are **change requests**: one principal proposes, a different principal approves, and approval applies the change.

| `kind` | `params` |
|---|---|
| `activate_pack` | `{"pack_id": "finance-v1"}` |
| `rollback_pack` | `{}` |
| `update_model` | `{"model_id": "…", "status": "production", "governance_mode": "enforce"}` (either field) |
| `update_retention` | `{"evidence_retention_days": 180}` |
| `erase_evidence` | `{"evidence_id": "…"}` |
| `apply_retention` | `{}` — freezes the cutoff and the set of evidence it will tombstone |
| `activate_model` | `{"model_id": "…", "version": "1.1.0"}` (`"allow_downgrade": true` for a lower version) |

```bash
REQ=$(curl -s -X POST $API/v1/change-requests -H "Authorization: Bearer $MAKER" \
  -H 'content-type: application/json' -d '{"kind":"activate_pack","params":{"pack_id":"finance-v1"}}')
curl -s -X POST "$API/v1/change-requests/$(jq -r .id <<<"$REQ")/approve" -H "Authorization: Bearer $CHECKER" \
  -H 'content-type: application/json' -d "{\"change_digest\":$(jq .change_digest <<<"$REQ")}"
```

- The approver needs `approve_<kind>` in Cedar (example policy: group `change-approvers`; proposers: `admins`), an **OIDC token** (certificate principals cannot approve), and a different identity from the proposer. Keep `admins` and `change-approvers` disjoint in production and assign the approver group only to people.
- Approval fails (`409`, request `failed`) if the state it was proposed against changed: another change moved the runtime pointer, the pack bytes changed, the retention value changed, or the evidence set for a retention run differs.
- Pending requests expire after `--change-request-ttl-hours` (env `KAVACH_CHANGE_REQUEST_TTL_HOURS`, default 24, 1–168).
- **No break-glass:** every change needs two people. Plan approver cover (holidays, incidents), including for DPDP erasure deadlines.
- `/v1/runtime` shows `pointer_version`, `stored_pointer_version` and `pointer_drift`; a replica with drift serves an older pack until restarted.
- Postgres 14 or newer is required (`CREATE OR REPLACE TRIGGER`).

**Development keys.** Key ids starting `dev-` (as generated by `kavach-dev generate`) are refused for the mandate, evidence, credential and system-of-record issuer keys unless `--insecure-dev`, and the offline evidence verifier refuses evidence they signed. Never copy a development bundle into a deployment.

**Logging and correlation.** `kavach-api` writes one line per request (method, route template, status, latency) and one per gateway call (tool, agent, decision, outcome and reason, record id), to stderr only (no telemetry export).
- `--log-format text|json` (env `KAVACH_LOG_FORMAT`, default `text`; `json` is one object per line for log shippers). Filter with `KAVACH_LOG` (`tracing` directives, default `info`, e.g. `KAVACH_LOG=info,kavach_api=debug`).
- **Every line is redacted before it is written**: phone-like numbers in any script, JWS/JWE/JWT tokens, `Bearer`/`Kavach-Credential` values, PAN-shaped identifiers and email addresses. Two kinds of span are left whole, matched strictly: canonical UUIDs (record, mandate and request ids) and full RFC 3339 timestamps with a zone. Everything around them is still masked. This backs up, and does not replace, the rule that personal data and secrets never reach a log call.
- **Correlation ids:** send `x-request-id` (`[A-Za-z0-9._-]{1,64}`) to have it used on every log line of the request and echoed in the response; anything else is replaced by a fresh UUID.

**Listener limits.** Every listener (operator HTTP, gRPC, agent, system of record) applies the same four limits. No setting turns a limit off: each value has bounds, and a value outside them stops the start with a message naming the flag.

| Flag | Env | Default | Bounds | What it does |
|---|---|---|---|---|
| `--request-timeout-seconds` | `KAVACH_REQUEST_TIMEOUT_SECONDS` | 30 | 1–300 | A request that has not produced its response in this time (reading its body included) is answered `503` with an RFC 9457 problem (`unavailable`, with `request_id` and `Retry-After: 5`); gRPC answers `CANCELLED`. With the agent surfaces it must exceed `--provider-timeout-ms` and `--hsm-timeout-ms`, or the start is refused |
| `--header-read-timeout-seconds` | `KAVACH_HEADER_READ_TIMEOUT_SECONDS` | 10 | 1–120 | A connection with no request in progress must deliver a complete request head within this time of being accepted (TLS handshake included) or of its last response bytes; otherwise it is closed. Sending a few bytes at a time does not extend it. It is also the keep-alive idle time, and a response the client stops reading for this long closes the connection |
| `--tls-handshake-timeout-seconds` | `KAVACH_TLS_HANDSHAKE_TIMEOUT_SECONDS` | 10 | 1–60 | A TLS handshake not finished in this time closes the connection |
| `--max-in-flight-requests` | `KAVACH_MAX_IN_FLIGHT_REQUESTS` | 256 | 1–65536 | Requests each listener handles at once. One over the cap is answered `503` with `Retry-After: 5` at once (gRPC: `UNAVAILABLE` with `retry-after` metadata); nothing is queued |

- **A timed-out request is never a partial decision.** The `503` is sent instead of the handler's answer, and the handler is dropped. Work it runs without pausing (policy evaluation, the evidence write) cannot be interrupted part-way; a gateway call runs in a task of its own and completes as before (forward, outcome); a retry with the same `request_id` gets `409 in_flight` until it has finished, then its stored reply.
- **Clients.** Set client timeouts above `--request-timeout-seconds`. Keep-alive and gRPC channels that stay idle longer than `--header-read-timeout-seconds` are closed by the server; clients reconnect. Retry a `503` after `Retry-After`.
- Size `--max-in-flight-requests` against `--database-pool-size`: requests over the pool wait for a connection inside the cap.

**Governed model record (ADR-010, Postgres).** The runtime pointer pins the active model file (path and SHA-256); `status` and `governance_mode` are governed state changed only by `update_model`, and are used by both `kavach-api` and `kavach-batch`. After the first start the YAML's own status and mode are ignored (a startup warning shows any difference).

- To use a new model version or an edited model file, propose `activate_model`. Starting with a different or edited file is refused.
- `--bootstrap-model` (env `KAVACH_BOOTSTRAP_MODEL`, Postgres only, audited) starts with a changed file and re-pins its path and digest; it never changes status or mode.
- Start `kavach-api` before `kavach-batch`: batch never records a baseline and refuses to run on an ungoverned or changed model.
- **Upgrading from H3a:** the first start pins the model file and records its state. If an approved `update_model` in the audit log differs from the YAML (H3a did not persist it), startup is refused; restart with `--bootstrap-model` to restore the approved values, then check `/v1/runtime`.
- **Model signatures:** when `--pack-signers` is set, model files must be signed too. Give the signer the model role (`"roles": ["pack", "model"]` in `signers.json`; entries without `roles` stay pack-only) and run `kavach-keys sign-model --dir ./signing-keys --kid <kid> --model models/finance/credit-underwriting-v1.yaml`.

**Upgrading from H2 (breaking).** `POST /v1/packs/{id}/activate`, `POST /v1/packs/rollback`, `PATCH /v1/models/{id}`, `PATCH /v1/admin/retention`, `POST /v1/admin/retention/apply`, `POST /v1/admin/evidence/{id}/erase` and the `X-Kavach-Approver` header are removed. Cedar actions `activate_pack` … `apply_retention` are replaced by `propose_*` / `approve_*` / `read_change_requests`; update custom policy files (see `crates/kavach-auth/policies/kavach.cedar`) and add approvers to a `change-approvers` group.

gRPC: `EvaluateService` on `--grpc-listen` (default `50051`). Pass the token in metadata `authorization: Bearer <token>`.

**Secure defaults.** `--access-control` defaults to `cedar` (env `KAVACH_ACCESS_CONTROL`). Running without access control requires the explicit `--insecure-dev` flag (env `KAVACH_INSECURE_DEV`); the API then allows every request and prints a warning at startup. Never use it outside local development.

**Pack integrity pinning.** At startup the API logs the SHA-256 of the active pack (`pack_sha256=sha256:<hex>`) and `/v1/runtime` returns it. Pass `--pack-sha256 <digest>` (env `KAVACH_PACK_SHA256`; also supported by `kavach-batch run`) to refuse startup if the pack file differs. Activation records the digest; rollback and model updates refuse to reload a pack file whose digest changed since it was pinned (HTTP 409 `pack_digest_mismatch`, recorded in the admin audit log). Compute a digest with `shasum -a 256 packs/finance/v0.yaml`.

- Integrity is **byte-level**: any change to a pack file, including comments, requires an approved re-activation (change request) before rollback or model update will reload it.
- Start `kavach-api` and `kavach-batch` with the **same** `--pack-sha256` so both evaluate identical bytes.
- Without `--pack-sha256`, a restart in **memory mode** loads whatever is at `--pack` and reports its digest; the pin is what makes restart fail on substituted bytes.
- **Postgres mode:** the governed runtime pointer decides the startup pack. The first start in a new database records `--pack` as the baseline (audited `startup_baseline_recorded`). Afterwards, `kavach-api` and `kavach-batch` refuse to start if `--pack` is a different path or its bytes differ from the digest recorded at activation — change packs through an approved `activate_pack` change request. For recovery only, `kavach-api --bootstrap-pack` (env `KAVACH_BOOTSTRAP_PACK`) starts anyway and records `startup_bootstrap_override` in the audit log.
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

**Operator roles: the first two superadmins (ADR-019).** Role bindings are stored per tenant (`--tenant-id`, `KAVACH_TENANT_ID`, default `default`). Every grant needs two people who already hold roles, so the first `superadmin` bindings are written once, at startup, outside the change-request flow, and always two at a time:

```bash
kavach-api ... --oidc-issuer https://idp.bank.example/realms/kavach \
  --bootstrap-superadmins 'https://idp.bank.example/realms/kavach#<subject-1>,https://idp.bank.example/realms/kavach#<subject-2>'
# or KAVACH_BOOTSTRAP_SUPERADMINS='...'
```

- Each entry is `<issuer>#<subject>`: the configured `--oidc-issuer`, then the person's OIDC `sub` (the subject may itself contain `#`). The two must be different people. One entry, three, a repeat, another issuer, or no operator OIDC stops the start with an error.
- It writes only while the tenant has no active `superadmin` binding. The write is two bindings plus one audit row each (`bootstrap_superadmin`, flagged `acting_as_superadmin`), in one transaction. A later start with the setting still present writes nothing and logs a warning: remove the setting once it has run.
- The log names nobody; the audit rows hold the subjects.
- Roles decide requests together with groups: a request is allowed if the person's roles or groups allow it. The `admins`, `change-approvers`, `operators` and `viewers` groups keep their permissions. Bindings are read on every request; if they cannot be read, the request is refused with 503 rather than decided on groups alone.
- A person binding matches the token's `sub` under the configured `--oidc-issuer`. A token without `sub` gets only its group bindings. Certificate (mTLS) principals are never bound to a role.
- A decision that only the `superadmin` role allows is recorded with `acting_as_superadmin` set on its audit row.
- After the bootstrap, roles change only through change requests, approved by a second person (`superadmin` or `user_admin`; only a `superadmin` for `superadmin`):

  ```bash
  # propose (as one person) ...
  curl -sS -X POST "$KAVACH/v1/change-requests" -H "authorization: Bearer $TOKEN_A" \
    -H 'content-type: application/json' \
    -d '{"kind":"grant_role","params":{"role":"approver","subject":{"kind":"principal","issuer":"https://idp.bank.example/realms/kavach","value":"<subject>"}}}'
  # ... approve (as another), with the change_digest the proposal returned
  curl -sS -X POST "$KAVACH/v1/change-requests/<id>/approve" -H "authorization: Bearer $TOKEN_B" \
    -H 'content-type: application/json' -d '{"change_digest":"<digest>"}'
  ```

  A `group` subject names an IdP group under the same issuer. `revoke_role` takes `{"binding_id":"rb_..."}`. Nobody may grant a role to themselves or to a group in their token, and the last active person `superadmin` or `user_admin` cannot be revoked (409).
- To review who holds what (`superadmin`, `user_admin` or `auditor`):

  ```bash
  curl -sS "$KAVACH/v1/role-bindings" -H "authorization: Bearer $TOKEN"     # add ?include=ended for history
  curl -sS "$KAVACH/v1/principals?q=asha" -H "authorization: Bearer $TOKEN" # people who have signed in
  curl -sS -o access-review.csv "$KAVACH/v1/access-review?format=csv" -H "authorization: Bearer $TOKEN"
  ```

  The access review has one row per active binding: who proposed and approved it, and when the person was last seen. A person not seen for `--access-review-stale-days` (`KAVACH_ACCESS_REVIEW_STALE_DAYS`, default 90) or never is marked `stale`. Members of the alias groups are in the IdP and are not listed; review them there. Each export writes an `export_access_review` audit row, and an export that cannot be audited is refused. `GET /v1/me` returns the caller's own roles to anyone signed in.

*Recovery when every superadmin is gone* (for example both IdP accounts were deleted): this is a database-operator procedure, run as the owner role. End the dead bindings, then start once with `--bootstrap-superadmins` naming two current people:

```sql
UPDATE role_bindings SET ended_at = now()
 WHERE tenant_id = '<tenant>' AND role = 'superadmin' AND ended_at IS NULL;
```

The rows stay (ended, with no change request), and the new bootstrap's audit rows record the recovery.

**Console sign-in (ADR-018).** Off unless `--console-client-id` is set. With it, the console signs in through `kavach-api`: the API runs the authorization code flow with PKCE against your IdP as a confidential client, keeps the tokens on the server, and gives the browser only an `HttpOnly` session cookie. It needs operator OIDC (above) on the same issuer: the access tokens the API gets for a console user must pass the same issuer, audience and JWKS checks as a CLI token, so a person is the same Cedar principal either way. Sessions live in the API process's memory: a restart signs everyone out, and with several replicas a user's requests must reach the replica that holds their session.

For the D17 step-up flow, `--console-step-up-acr` stores the IdP ACR value that the realm must map to the required WebAuthn/passkey authentication flow. The value is bounded and validated at startup. The initiation endpoint (`POST /auth/step-up/{record_id}`) and callback (`GET /auth/step-up/callback`) are mounted. Callback verification stores a short-lived exact-action proof on the initiating server-side session; the console decision controls use that proof to create an audited, short-lived approve/reject record. Approved agent calls carry the returned `approval_id` and `execution_id` with the original request and unchanged action parameters. The gateway consumes the release and the core binds its single-use credential ID into signed authorization evidence. Register `https://<console host>/auth/step-up/callback` with the IdP in addition to `/auth/callback`. The realm must map the configured ACR to WebAuthn/passkey authentication; test that mapping and front-channel PAR/request-object protection before production use.

The D17 review-snapshot encryption key is configured with `--review-snapshot-key-file` (a dedicated 32-byte key encoded as 64 hex characters) and `--review-snapshot-key-id` (default `review-snapshot-1`). Keep the key file owner-only, back it up separately from the database, and preserve the key id when restarting. Generate a key with `umask 077 && openssl rand -hex 32 > review-snapshot.key`; use a protected path outside the repository. `--require-hardening` checks the file is readable only by its owner. During rotation, `--review-snapshot-previous-key OLD_ID=/protected/old.key` may be repeated: the active key encrypts new snapshots, while previous keys are decrypt-only for live snapshots. For multiple replicas, first deploy the new key as previous on every replica while keeping the old key active; then switch every replica to the new active key with the old key listed as previous. Keep the old key through the 30-minute snapshot lifetime plus rollout/cleanup margin, then remove it and restart all replicas. Key IDs and key material must be unique. When configured, the gateway encrypts and stores committed `HUMAN_REVIEW` action projections for 30 minutes; retries decrypt and compare existing snapshots using the envelope's key id. The API removes expired snapshots at startup and every 60 seconds, and stops cleanup during graceful shutdown. `GET /auth/human-review/{record_id}` requires a live console session and `approve_human_review`, audits the read, and returns a minimal projection only after checking the record signature and action binding. The `propose_plan` proposal tool commits decision evidence without provider dispatch, and acceptance scenario 6 verifies encrypted snapshot persistence; the complete approval-to-agent-call chain remains partial. Approval, release consumption and credential authorization are implemented.

*At the IdP*, register one client for the console:

- confidential client (client secret), standard flow (authorization code) only, with **PKCE S256 required**; no implicit flow, no direct-access grants, no service account;
- client authentication `client_secret_basic`;
- exactly one redirect URI, `https://<console host>/auth/callback` (the console host is where the operator listener is reached); no wildcards;
- a post-logout redirect URI `https://<console host>/signin` if you turn on `--console-idp-logout`;
- access tokens for this client must carry the operator audience (`--oidc-audience`, for example with a Keycloak audience mapper) and the groups claim; the client id itself must differ from the operator and agent audiences;
- a refresh token for the session (in Keycloak, the default for the standard flow); `offline_access` is refused.

Put the client secret alone on one line in a file only the API's user can read (`chmod 600`; `--require-hardening` refuses a file readable by group or others).

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--console-client-id` | `KAVACH_CONSOLE_CLIENT_ID` | — | The console's client id; turns console sign-in on |
| `--console-client-secret-file` | `KAVACH_CONSOLE_CLIENT_SECRET_FILE` | — | File holding the client secret (one line) |
| `--console-redirect-uri` | `KAVACH_CONSOLE_REDIRECT_URI` | — | The registered redirect URI, exactly `https://<host>/auth/callback` (`http://localhost`, `127.0.0.1` or `[::1]` only with `--insecure-dev`). Its scheme, host and port are the console origin that cookie requests must come from |
| `--console-authorization-endpoint`, `--console-token-endpoint` | `KAVACH_CONSOLE_AUTHORIZATION_ENDPOINT`, `KAVACH_CONSOLE_TOKEN_ENDPOINT` | discovery | Set both to skip discovery; otherwise read once at startup from `{issuer}/.well-known/openid-configuration`, which must name the same issuer and support S256. HTTPS only outside `--insecure-dev` |
| `--console-revocation-endpoint` | `KAVACH_CONSOLE_REVOCATION_ENDPOINT` | discovery | RFC 7009 endpoint; logout (and a sign-in refused because the session table is full) revokes the refresh token there |
| `--console-end-session-endpoint` | `KAVACH_CONSOLE_END_SESSION_ENDPOINT` | discovery | Used only with `--console-idp-logout` |
| `--console-scope` | `KAVACH_CONSOLE_SCOPE` | `openid` | Space-separated; must include `openid`, must not include `offline_access` |
| `--console-session-idle-minutes` | `KAVACH_CONSOLE_SESSION_IDLE_MINUTES` | `15` | A session ends after this long without a request (5–60) |
| `--console-session-absolute-minutes` | `KAVACH_CONSOLE_SESSION_ABSOLUTE_MINUTES` | `480` | A session ends this long after sign-in, whatever happens (at least the idle limit, at most 720). A token refresh never extends it |
| `--console-idp-logout` | `KAVACH_CONSOLE_IDP_LOGOUT` | off | Logout also returns the IdP's end-session URL (with `client_id` and `post_logout_redirect_uri`, never `id_token_hint`), so the console signs the user out of the IdP too |
| `--console-max-sessions` | `KAVACH_CONSOLE_MAX_SESSIONS` | `1000` | Most live sessions (1–10000); when full, new sign-ins are refused (`sessions_full`) and existing sessions keep working |
| `--console-step-up-acr` | `KAVACH_CONSOLE_STEP_UP_ACR` | — | Optional expected ACR for the D17 WebAuthn/passkey flow; must match the IdP realm configuration |
| `--review-snapshot-key-file` | `KAVACH_REVIEW_SNAPSHOT_KEY_FILE` | — | Dedicated 32-byte hex key for D17 encrypted review projections; owner-only, stable across restarts |
| `--review-snapshot-key-id` | `KAVACH_REVIEW_SNAPSHOT_KEY_ID` | `review-snapshot-1` | Rotation id authenticated into D17 snapshot envelopes |
| `--review-snapshot-previous-key` | — | — | Repeatable `KEY_ID=PATH`; decrypt-only overlap keys for live D17 snapshots |

Startup refuses a partial configuration, a value outside its bounds, a client id equal to an audience, a non-HTTPS redirect URI or endpoint outside `--insecure-dev`, and discovery that names another issuer. The routes are `GET /auth/config`, `GET /auth/login`, `GET /auth/callback`, `GET /auth/session` and `POST /auth/logout` on the operator listener (see `docs/openapi.yaml`). A request with the session cookie must also send `X-Kavach-Console: 1` and come from the console origin; with the cookie and `Authorization` (or `X-Kavach-Principal`) together it is refused.

*Development IdP.* `cargo run -p kavach-api --example oidc_double -- --client-secret-file <dir>/console.secret --jwks-out <dir>/jwks.json [--listen 127.0.0.1:9400] [--sub dev-admin] [--groups admins]` starts the OIDC test double the Rust tests use: it signs in the one configured user without asking, writes a new JWKS each run (and a random client secret, owner-only, if the file is missing), and prints the `kavach-api` flags to use. Its URLs are plain-HTTP loopback, so `kavach-api` needs `--insecure-dev` with it, and the redirect URI must be `http://127.0.0.1:<port>/auth/callback` (or `localhost`). Never point a deployment at it.

**mTLS principals (machine callers).** With `--tls-cert`, `--tls-key`, `--tls-client-ca` and `--mtls-principal-san uri` (env `KAVACH_MTLS_PRINCIPAL_SAN`; `dns` also supported), the client certificate's single URI SAN is the Cedar principal on HTTP and gRPC. Add that id to the entities file with its groups, for example:

```json
{ "uid": { "type": "Kavach::User", "id": "spiffe://bank.example/los" }, "attrs": {},
  "parents": [{ "type": "Kavach::Group", "id": "operators" }] }
```

A certificate with no SAN, or several SANs, of the configured type gets 401. A bearer token, when also sent, takes precedence. Client certificates are not checked for revocation; issue short-lived ones. Without `--mtls-principal-san`, mTLS only restricts who can connect.

**HMAC v2 on `/v1/evaluate`.** With `--hmac-secret`, send `X-Kavach-Timestamp` (unix seconds, ±300 s), `X-Kavach-Nonce` (16–128 characters `[A-Za-z0-9_-]`, single use) and `X-Kavach-Signature: sha256=<hex HMAC-SHA256>` over `v2\n{ts}\n{nonce}\n{METHOD}\n{path?query}\n` followed by the raw body. `scripts/pilot-phase3.sh` shows a working signer.

**Upgrading from M1.5 (breaking).** Callers that sent only `X-Kavach-Principal` now get 401: issue access tokens, or run `--insecure-dev` locally. Body-only HMAC signatures are rejected; sign v2. The pilot compose file now requires `POSTGRES_PASSWORD`, `KAVACH_OIDC_ISSUER`/`KAVACH_OIDC_AUDIENCE`, and a `deploy/pilot-config/` directory with `entities.json` and `jwks.json`; Postgres is no longer published on the host.

**Agent surfaces (ADR-007, H5a).** Enabled by `--agent-oidc-audience`. They use **two extra listeners**:

- **Agent listener** (`--agent-listen`, default `127.0.0.1:8091`). Serves `POST /v1/tools/{tool}` (the **gateway**: decide and record, then on an allow resolve the destination, issue a credential, forward once and record the outcome), `POST /v1/authorize` (an agent-only **pre-check**: the decision the gateway would make, reserving and recording nothing) and `/health`. It is the only listener to attach to the agent network; it never serves operator, admin, change-request, metrics or system-of-record routes, and the operator listener does not serve agent routes.
- **System-of-record listener** (`--sor-listen`, default `127.0.0.1:8090`). Serves `POST /v1/sor/events`; bind it to the backend network only.

| Flag / env | Meaning |
|---|---|
| `--agent-oidc-audience` / `KAVACH_AGENT_OIDC_AUDIENCE` | Audience of agent access tokens. Same IdP (issuer, JWKS) as operators, **different audience**; startup refuses the same audience |
| `--agent-id-claim` / `KAVACH_AGENT_ID_CLAIM` | Claim naming the agent (default `azp`, the Keycloak client id). An agent without a passport is refused (403) |
| `--mandate-config` / `KAVACH_MANDATE_CONFIG` | JSON: `issuer_id`, `signing_kid`, `sor_issuers` (`tenant_id`, `system`, `kid`, hex `public_key`; each key is registered for one tenant and one system, and the same key material twice is refused), `templates`, `passports`, `event_freshness_seconds`, `replay_window_seconds`. Invalid templates refuse startup (ADR-011) |
| `--mandate-keys-dir` / `KAVACH_MANDATE_KEYS_DIR` | Holds `<signing_kid>.ed25519` (create with `kavach-keys generate`) |
| `--evidence-keys-dir`, `--evidence-key-id` | The evidence signing key (default id `kavach-evidence-1`). It signs agent evidence only; keep it separate from the mandate key |
| `--checkpoint-keys-dir`, `--checkpoint-key-id` / `KAVACH_CHECKPOINT_KEYS_DIR`, `KAVACH_CHECKPOINT_KEY_ID` | The checkpoint signing key (default id `kavach-checkpoint-1`; create with `kavach-keys generate`). **Required**: there is no mode without checkpoints. It signs evidence checkpoints only; startup refuses an id shared with the mandate, evidence or credential key, and key material shared with the evidence key |
| `--checkpoint-interval-seconds` / `KAVACH_CHECKPOINT_INTERVAL_SECONDS` | New agent records get a signed checkpoint at least this often (default 60; 1–3600), or after 1,000 records, whichever comes first |
| `--checkpoint-stall-seconds` / `KAVACH_CHECKPOINT_STALL_SECONDS` | Records without a checkpoint for this long raise an alert (default 600; must exceed the interval) |
| `--subject-pseudonym-key` / `KAVACH_SUBJECT_PSEUDONYM_KEY` | Owner-only file with a 32-byte hex secret (`openssl rand -hex 32`). Pseudonymises borrowers in evidence and counters. Treat it like a signing key. Rotating it resets the day's contact counters, so rotate only at IST midnight |
| `--consents` / `KAVACH_CONSENTS` | Consent fixture JSON (list of consent records; PRD D7) |
| `--contact-preferences` / `KAVACH_CONTACT_PREFERENCES` | Optional no-database development fixture; missing preference records fail closed before gateway destination resolution |
| `--sor-rate-per-second` | System-of-record events accepted per second (default 20); excess gets 429. Bodies over 16 KiB get 413 |
| `--tool-registry` / `KAVACH_TOOL_REGISTRY` | The agent tool registry (`tools/agent-tools.yaml`): which tools exist, which parameters are reference-only, which values are allowed. **Must be signed** unless `--insecure-dev` |
| `--tool-signers` / `KAVACH_TOOL_SIGNERS` | Trusted signers for the registry (signer role `tool`). Defaults to `--pack-signers` |
| `--tool-registry-sha256` / `KAVACH_TOOL_REGISTRY_SHA256` | Optional pin of the registry file digest |
| `--hsm-keys`, `--hsm-module`, `--hsm-token-label`, `--hsm-pin-file`, `--hsm-sessions` | Signing keys held in an HSM through its PKCS#11 module (KMS milestone). `--hsm-keys` lists the roles, comma separated: `mandate`, `evidence`, `checkpoint`, `credential`; each role's key id is its HSM label, and that role needs no key directory. Keys must have been generated in the HSM (sensitive, never extractable) unless `--insecure-dev`. The PIN comes only from an owner-only file. Put the mandate and checkpoint keys in the HSM first; measure signing latency on your HSM before listing `evidence` or `credential` (they sign on every recorded or delivered call). `/v1/runtime` shows `hsm.roles` and `hsm.healthy`. `--hsm-timeout-ms` (`KAVACH_HSM_TIMEOUT_MS`, default 5000, 100–60000) bounds each sign or health call: a token that does not answer in time fails closed (the decision is a BLOCK, nothing is forwarded; the HSM shows unhealthy). A call that timed out keeps its thread and session until the token answers |
| `--credential-keys-dir`, `--credential-key-id` | The credential signing key (default id `kavach-credential-1`; create with `kavach-keys generate`). It signs resource credentials only. Startup refuses an id or key material shared with the mandate or evidence key |
| `--references` / `KAVACH_REFERENCES` | Reference fixture JSON `{"references": [{"tenant_id", "subject_ref", "destinations": {"<channel>": "<number>"}}]}`: what the gateway resolves a capability reference to, after an allow. **Synthetic numbers only** (`+910` and nine digits, never assigned to an Indian mobile); anything else refuses startup. A reference vault replaces it in M2 |
| `--providers` / `KAVACH_PROVIDERS` | JSON `{"providers": [{"audience", "kid", "x25519_public_key", "endpoint"}]}`: each resource provider's encryption key (hex X25519 public key, generated by the provider; credentials are encrypted to it) and base URL (the gateway posts to `<endpoint>/v1/messages`). Every `provider` named in the tool registry must be listed. **Use HTTPS**; plain HTTP is accepted with a startup warning for an isolated backend network only |
| `--provider-ca` / `KAVACH_PROVIDER_CA` | CA certificates (PEM) the gateway trusts for provider TLS, in addition to the system roots (e.g. a private CA for internal providers). An untrusted certificate fails the handshake and nothing is sent (`failed`) |
| `--provider-connect-timeout-ms`, `--provider-timeout-ms` | Gateway → provider timeouts (defaults 2000 and 5000). No retries. Both must stay below the 15 s credential lifetime |

- **Tool registry.** The registry is security-critical configuration: editing it could turn the reference-only protection off. Sign it with a key that has the `tool` role (`"roles": ["tool"]` in the signers file) and run `kavach-keys sign-tools --dir ./signing-keys --kid <kid> --registry tools/agent-tools.yaml`, which writes `<registry>.sig`. Startup refuses an unsigned registry, one changed after signing, one signed by a key without the `tool` role, and one that differs from the pin. Its digest is printed at startup and recorded in every agent decision record (`policy_versions.tools`).
- **Pre-check body (breaking from H5a).** `POST /v1/authorize` takes `{"tool", "mandate_id", "request_id", "params": {...}}`, the same request the gateway will take, and runs the same registry extraction. A malformed body, an unknown tool or parameter (including an agent-supplied `timestamp` or free text), a missing parameter or a wrong type returns 400, and nothing is recorded. A raw value in a reference-only parameter, or a value outside its allowlist or range, is a BLOCK decision.
- **Gateway calls (`POST /v1/tools/{tool}`).** The body is `{"mandate_id", "request_id", "params"}`. The reply always has `decision`, `reasons`, `request_id`, `replayed`, `outcome_recorded`, and after an allow `outcome` (`delivered`, `refused`, `failed`, `not_executed` or `unknown`), `outcome_reason` and (if the provider gave one) `provider_message_id`; never the destination or the credential.
  - Retrying the same `request_id` never mints a credential or sends again. While the earlier call is still running, the retry gets **409 `in_flight`**. Once its outcome is recorded, the retry gets that stored outcome with `replayed: true`, **including `unknown`** (sent, result not known). An `unknown` is settled by reconciliation, not by retrying. Use a new `request_id` for a new attempt (it counts against the daily cap).
  - Malformed requests get 400 and are not recorded; tools that are not `external_effect` get 501 for now.
  - Metrics on the operator listener: `kavach_gateway_calls_total{tool,decision,outcome}`, `kavach_gateway_malformed_total`, and the alerts `kavach_gateway_jti_conflicts_total` and `kavach_gateway_outcome_write_failures_total`.
  - `kavach_gateway_stage_seconds{stage}` is a histogram of how long each stage of a call takes: `decide` (mandate, policy and parameter checks), `commit` (the evidence record), `resolve`, `credential`, `forward` (until the provider replies) and `outcome`. The label is only the stage name.
- **Evidence checkpoints.** A background task signs a checkpoint of the agent chain on the schedule above ([EVIDENCE_BUNDLE.md](EVIDENCE_BUNDLE.md)). It never blocks or fails a decision, and `/health` does not depend on it.
  - **Watch it.** `GET /v1/runtime` reports `checkpoint_lag_seconds`, `checkpoint_stalled`, `checkpoint_last_seq` and `checkpoint_uncovered_records`. Metrics: `kavach_checkpoints_written_total`, `kavach_checkpoints_skipped_total{reason}`, `kavach_checkpoint_uncovered_records`, `kavach_checkpoint_stalled` and `kavach_checkpoint_last_covered_timestamp_seconds`. Alert when `time() - kavach_checkpoint_last_covered_timestamp_seconds` exceeds your threshold: that also catches a writer that has stopped.
  - **Logs.** A stall and its recovery are logged, the stall as an error starting `ALERT evidence checkpoints stalled`. A checkpoint that covers a record the chain no longer has is logged as `ALERT evidence checkpoint: … records were removed`.
  - **Copy checkpoints off-host.** A checkpoint protects nothing until a copy is somewhere the deployment cannot write. On a schedule, as the read-only `kavach_auditor` role: `kavach-evidence checkpoints --latest >> /mnt/offsite/kavach-checkpoints.jsonl`. `kavach-evidence export` writes the chain itself as a signed bundle, and `kavach-evidence verify-bundle <dir> --keys <your keys> --expect-checkpoint <kept file>` checks one offline; it exits non-zero for a failure (`1`) and for a bundle that verifies but is not fully protected (`2`) ([EVIDENCE_BUNDLE.md](EVIDENCE_BUNDLE.md)).
- **Revocation evidence.** Each revocation by a system-of-record event (`loan.paid`, `loan.disputed`) is also a signed record in the agent evidence chain. The request that revokes writes it at once. If it cannot (the evidence store is down), the revocation still stands and a background reconciler writes the record within about a minute, once per event.
  - **Watch it.** `kavach_revocation_records_missing` is the number of revocations still without their record after the last pass: alert when it is above 0. `kavach_revocation_records_reconciled_total` counts records the reconciler had to write. Alert when `time() - kavach_revocation_reconcile_last_pass_timestamp_seconds` exceeds a few minutes: that catches a reconciler that has stopped.
  - **Logs.** Missing records are logged as an error starting `ALERT revocation evidence missing`, with the event ids.
  - **Export.** Revocation records are exported and verified with the decisions (bundle format 2, [EVIDENCE_BUNDLE.md](EVIDENCE_BUNDLE.md)). Bundles written before it (format 1) still verify; a verifier older than format 2 refuses a format 2 bundle rather than misread it.
- **Stopping an agent (the kill switch, ADR-013).** On the operator listener: `POST /v1/agents/{agent_id}/restrict | quarantine | revoke` with `{ "reason_code": "...", "note": "..." }`, `GET /v1/agents/{agent_id}`, and `GET /v1/agents?state=&limit=&cursor=` for every agent a passport names in the tenant with its state, by agent id, at most 200 a page. From the command line: `kavach agent status | restrict | quarantine | revoke | reinstate <agent>`.
  - **Who.** The Cedar action `stop_agent` (admins in the bundled policy; it is its own action so an on-call responder role is a policy edit). One principal stops; **bringing an agent back is a change request** (`reinstate_agent`) another principal approves, and `revoked` cannot be brought back (issue a new passport with a new agent id).
  - **What each does.** Restricted: reads within the mandate, nothing with an external effect. Quarantined: nothing; its mandates are suspended, not revoked, and work again, unchanged, when it is reinstated (a mandate that expired meanwhile stays expired). Revoked: the state first, then every mandate it holds is revoked; repeat the command if it reports mandates not revoked. A stop only ever tightens, and takes effect from the agent's next call on every replica; a call already past authorization is caught before its credential is minted, and no credential outlives a stop by more than 15 seconds.
  - **Two principals** means two source-qualified identities, as for every change request: a person with two OIDC subjects is two principals to Kavach.
  - **Watch it.** `kavach_agent_state_changes_total{to,result}`; alerts `KavachAgentStopped`, `KavachAgentStopBurst` (a real incident and a stolen operator credential look alike: there is no bulk stop and stops share a global limit), `KavachAgentStopForbidden`. Every attempt is in the audit log (`stop_agent`, `stop_agent_refused`). The operator's `note` stays in the store and the audit log; the evidence chain holds a closed reason code and a keyed digest of it.
- **Agent state evidence.** Each change of an agent's state is a signed `agent_state` record in the same chain (bundle format 3). A stop takes effect first and its record follows; a reinstatement is written with its record in one transaction or not at all.
  - **Watch it.** `kavach_agent_state_records_missing` is the number of changes still without their record after the last pass: alert when above 0. `kavach_agent_state_records_reconciled_total` counts records the reconciler had to write. Alert when `time() - kavach_agent_state_reconcile_last_pass_timestamp_seconds` exceeds a few minutes.
  - **Logs.** `ALERT agent state evidence missing`, with the agent, the change number and why.
  - **Privacy.** The chain holds a closed reason code and a keyed digest of the operator's note, never the note.
- **Agent credentials.** Agents send `Authorization: Bearer <agent token>`. `X-Kavach-Principal` is never accepted on agent routes, not even with `--insecure-dev`. Operator tokens are refused on agent routes, and agent tokens on operator routes.
- **System-of-record events.**
  - The body is `{"event": "<signed JWS>"}`; a new event returns 201 with the mandate id.
  - A retry of the same event returns 200 with the same mandate id. The same event id with other content returns 409.
  - An event for a tenant other than the one the stack serves is refused (400) before it is verified or acted on.
  - The evidence record of a revocation is read like an agent record: `GET /v1/agent-revocations/{system}/{event_id}` on the operator listener, for `read_evidence` holders only, rate limited, and audited before anything is returned.
- **Agent-only mode.** `--agent-only` (`KAVACH_AGENT_ONLY`) serves the agent surfaces and the operator surface of the agent path only: health, metrics, runtime, the audit log, change requests, agent state and the stop actions, the closed-records reconciliation and the evidence reads. There is no evaluate, pack, model, decision-event, retention, tombstone, incident or batch route, no gRPC evaluate service, and no credit-track change request. The console is served without its credit-track pages: `GET /v1/runtime` reports `agent_only: true`, and the console leaves those pages out of its navigation. It refuses to start without the agent surfaces. Use it for any hosted build (the credit track is frozen, ADR-014); `deploy/agent-stack` runs with it.
- **Alerts and a dashboard.** Prometheus rules and a Grafana dashboard for these metrics ship in [`deploy/monitoring/`](../deploy/monitoring/README.md); a test keeps them in step with the code.
- **Stopping.** On SIGTERM or Ctrl-C `kavach-api` stops accepting connections at once, lets requests in flight finish, waits for every gateway call that has started, then writes a final checkpoint and exits.
  - **Deadline:** `--shutdown-grace-seconds` (default 30, 1–600). It must exceed the provider timeout, which bounds a gateway call.
  - **Exit status:** 0 when every listener drained, every call finished and the evidence is covered. Otherwise 1, after an `ALERT shutdown was not clean` log line. A call cut off between send and outcome is reported as `outcome_missing`.
  - **Your orchestrator's grace period must be longer** than `--shutdown-grace-seconds` (Kubernetes `terminationGracePeriodSeconds`; Docker Compose `stop_grace_period`, default 10 s), or it sends SIGKILL first.
  - **A call survives its client.** Once a call's decision is recorded it completes (forward, outcome) even if the client disconnects. A retry gets the stored reply and is never sent again.
  - **Not covered:** a load balancer should stop sending traffic before the stop (a readiness drain is not built), and SIGKILL or a crash is not an orderly stop: its records are covered by the next checkpoint after restart.
- **Production shape.** Without `--insecure-dev`, startup requires the Postgres evidence store and a readable kernel clock. Contacts are blocked while the clock is unsynced. `--insecure-dev` instead uses in-memory stores and treats the system clock as synced, for development only.

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
