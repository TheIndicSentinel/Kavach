# Partner pilot playbook

On-prem pilot for Indian structured-credit integrations. This is the **first production-shaped path** after Milestone B: batch shadow ingest, governance console review, then optional sync enforce.

## Audience

| Role | Responsibility |
|---|---|
| Partner integration engineer | LOS → `EvaluateRequest` mapping, NDJSON export, field validation |
| Bank model risk / compliance | Shadow review, promotion to enforce, dual-control sign-off |
| Bank platform ops | Postgres, containers, IdP → `X-Kavach-Principal`, CronJob for batch |

## Pilot phases

### Phase 1 — Shadow batch (week 1)

1. Deploy pilot stack ([deploy/docker-compose.pilot.yml](../deploy/docker-compose.pilot.yml)) or bank VPC equivalent.
2. Map LOS export to [`partner/finance/credit_underwriting_v1_request.json`](../partner/finance/credit_underwriting_v1_request.json).
3. Validate against [`schemas/evaluate-request.schema.json`](../schemas/evaluate-request.schema.json).
4. Run `kavach-batch run` with `governance_mode: shadow` on the active model record.
5. Review batch output NDJSON: `policy_decision`, `returned_decision`, `reason_codes`.
6. Confirm batch jobs appear in console **Governance → Batch jobs** (Postgres evidence store).

**Exit criteria:** Partner sample batch completes with &gt;99% row success; no unexpected `BLOCK`/`HUMAN_REVIEW` spikes vs business expectations.

### Phase 2 — Governance review (week 2)

1. Operators use governance console (responsive on tablet for field review).
2. Review active pack rules (`/policies`) and model posture (`/models`).
3. Exercise dual-control: pack activate/rollback and model promotion in **Settings** with distinct actor/approver principals.
4. Review admin audit log (`/audit`).
5. Configure retention policy (`/retention`) per bank DPDP posture.

**Automated API path:**

```bash
# Cedar pilot (default entities include admin-1 / admin-2)
export PILOT_API_URL=http://localhost:8080
export PILOT_PRINCIPAL=viewer-1
export PILOT_ACTOR=admin-1
export PILOT_APPROVER=admin-2
./scripts/pilot-phase2.sh
```

**Exit criteria:** Audit log captures all mutations; retention settings persisted; principals mapped from IdP.

### Phase 3 — Sync enforce (optional, week 3+)

1. Promote model to `production` if vendor (`origin: vendor`) before enforce.
2. Switch model `governance_mode` to `enforce` via dual-control PATCH.
3. Enable HMAC on HTTP evaluate (`KAVACH_HMAC_SECRET`) for scoring API path.
4. Enable Cedar RBAC and mTLS per [INSTALL.md](INSTALL.md).

**Exit criteria:** Sync evaluate returns `policy_decision == returned_decision`; evidence chain verifies with `kavach-evidence verify`.

## Quick start (Docker pilot)

```bash
cp deploy/pilot.env.example deploy/.env
docker compose -f deploy/docker-compose.pilot.yml up --build -d

# Health (Cedar enabled in pilot image — use example principal)
curl -s -H 'X-Kavach-Principal: viewer-1' http://localhost:8080/health

# Console
open http://localhost:8080/

# One-shot batch shadow
docker compose -f deploy/docker-compose.pilot.yml --profile batch run --rm batch-shadow
```

## Quick start (source build, no Docker)

```bash
./scripts/pilot-phase1.sh

# Postgres-backed API (separate terminal) — then re-run with API check:
# export PILOT_API_URL=http://localhost:8080 PILOT_PRINCIPAL=admin-1
# ./scripts/pilot-phase1.sh
export KAVACH_DATABASE_URL=postgres://kavach:change-me@localhost:5432/kavach
cargo run -p kavach-api -- \
  --pack packs/finance/v0.yaml \
  --model models/finance/credit-underwriting-v1.yaml \
  --evidence-store postgres \
  --access-control cedar \
  --cedar-policy crates/kavach-auth/policies/kavach.cedar \
  --cedar-entities crates/kavach-auth/policies/entities.example.json
```

## Deliverables checklist

- [ ] Partner field mapping document (internal — not in repo)
- [ ] NDJSON export job scheduled (CronJob / workflow)
- [ ] Postgres backups and retention policy agreed
- [ ] IdP group → Cedar principal mapping (`operators`, `admins`, `viewers`)
- [ ] Incident runbook: query `/v1/admin/incidents` by `correlation_id`
- [ ] Evidence export + `kavach-evidence verify` on a sample chain

## Artifacts in this repo

| Path | Purpose |
|---|---|
| [`partner/`](../partner/) | Production-shaped request + batch NDJSON samples |
| [`deploy/Dockerfile`](../deploy/Dockerfile) | Pilot container image |
| [`deploy/docker-compose.pilot.yml`](../deploy/docker-compose.pilot.yml) | Postgres + API + batch profile |
| [`scripts/pilot-phase1.sh`](../scripts/pilot-phase1.sh) | Phase 1 exit-criteria validator (schema + batch + report) |
| [`scripts/pilot-phase2.sh`](../scripts/pilot-phase2.sh) | Phase 2 governance API + dual-control smoke |
| [`scripts/pilot-smoke.sh`](../scripts/pilot-smoke.sh) | CI/local batch smoke without Docker |
| [INSTALL.md](INSTALL.md) | Full on-prem install reference |
| [MILESTONE_B_EXIT.md](MILESTONE_B_EXIT.md) | Milestone B sign-off gate |

## Privacy and data handling

- Do not load production PAN, Aadhaar, phone, or account numbers into pilot NDJSON.
- Kavach stores `input_digest` in evidence, not raw `input` (ADR-001 §8).
- Erasure uses tombstone APIs — see retention admin routes in INSTALL.md.

## Support escalation

1. **Batch row failures** — inspect output `error` field; check clock-skew on `decision_time` / `consent.timestamp`.
2. **Vendor enforce blocked** — promote model to `production` before enforce mode.
3. **Shadow sync incidents** — `GET /v1/admin/incidents` with `correlation_id` from LOS.

## Related

- [ADR-001 evaluate semantics](ADR-001-evaluate-semantics.md)
- [ADR-002 deployment architecture](ADR-002-deployment-architecture.md)
- [Partner payload README](../partner/README.md)
