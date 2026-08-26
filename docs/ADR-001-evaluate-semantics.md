# ADR-001: Evaluate Semantics

**Status:** Accepted  
**Date:** 2026-08-27  
**Deciders:** Kavach product/engineering  
**Supersedes:** All prior informal evaluate descriptions  

## Context

Kavach is an on-prem AI governance platform. v1 proves the engine on **Indian structured credit decision APIs**. The architecture is sector-agnostic (pack-driven rules); go-to-market is finance-only until Milestone C.

This ADR freezes evaluate-path behaviour so Milestone A implements one product, not two.

## Decision

### 1. Decision enum (frozen)

Four values only: `PASS`, `ALERT`, `BLOCK`, `HUMAN_REVIEW`. No fifth state without a schema migration.

### 2. Two decision fields in evidence

| Field | Meaning |
|---|---|
| `policy_decision` | Always the CEL/pack outcome |
| `returned_decision` | What the **sync RPC** returned to the caller |

Rules:

- **Enforce mode** and **batch jobs:** `policy_decision == returned_decision`.
- **Sync shadow mode:** `policy_decision` = would-be outcome; `returned_decision` = `PASS` unless the request failed validation/auth (401/400).
- Auditors and compliance dashboards query **`policy_decision`**.
- LOS incident reviews query **`returned_decision`**.
- Metrics and exports **never mix** shadow sync traffic with enforce traffic.

### 3. Sync RPC semantics by outcome

| `policy_decision` | Sync RPC returns immediately | Side effects |
|---|---|---|
| `PASS` | `returned_decision: PASS` | Evidence row |
| `ALERT` | `returned_decision: PASS` | Evidence + alert queue (non-blocking) |
| `BLOCK` | `returned_decision: BLOCK` | Evidence row |
| `HUMAN_REVIEW` | `returned_decision: HUMAN_REVIEW` | Review ticket; **no long-poll** |

`human_review_hold_policy` on `ModelRecord` documents how the **LOS** interprets `HUMAN_REVIEW` (hold disbursement vs deny scoring). Kavach does not implement payout.

### 4. Governance mode authority

- `ModelRecord.governance_mode` (`shadow` | `enforce`) is **authoritative**.
- Callers **cannot** set mode. Drop `mode` from public `EvaluateRequest` v1.
- Optional future: privileged dry-run header may **downgrade** to shadow only, never upgrade to enforce.

### 5. Shadow vs fail-closed matrix

#### Policy outcomes

| Situation | Enforce | Sync shadow |
|---|---|---|
| Policy → BLOCK / HUMAN_REVIEW / ALERT | Return actual `returned_decision` | Caller sees `PASS`; evidence records real `policy_decision` |
| Auth failure | `401` | `401` — not disguised as PASS |
| Schema / validation failure | `400` | `400` — not disguised as PASS |
| Oversized body | `413` | `413` |

#### Infrastructure failures

| Situation | Enforce | Sync shadow |
|---|---|---|
| Evidence write / Postgres / pack load / CEL sandbox failure | `returned_decision: BLOCK` | Caller sees `PASS`; **no chain row** |
| Infra failure handling | Fail-closed | Metric + dead-letter/local spill + page on-call; record **incident** with `correlation_id` |

**Shadow means governance policy does not deny credit.** It does **not** mean invalid requests look healthy, and it does **not** mean infra failure is invisible or faked as a healthy `DecisionEvent`.

Missing evidence on sync shadow is an **incident**, not a `DecisionEvent` with `policy_decision: PASS`.

### 6. Batch vs sync shadow

| Path | Job / export shows | Evidence |
|---|---|---|
| **Sync shadow** | Caller always `PASS` (except 4xx) | `policy_decision` = would-be; `returned_decision` = PASS |
| **Batch shadow** | **Actual** `policy_decision` in results | `mode: shadow`; no loan RPC to protect |

Batch is the expected first partner install path.

### 7. Evaluate pipeline (hot path)

Per request, in order:

1. Auth (mTLS or HMAC — Milestone A)
2. Schema validation (`ModelRecord.input_schema`)
3. Clock skew check: reject if `|decision_time - server_now| > 5m` (configurable)
4. Consent: **presence + purpose match** only (not a DPDP Consent Manager)
5. CEL policy rules on **this record only** (DTI, prohibited field use if present, thresholds)
6. Aggregate `policy_decision`
7. Map to `returned_decision` per governance mode
8. Evidence write in same transaction (enforce); shadow sync on failure → incident path

**Not on hot path:** cohort disparity, inclusion monitoring, ML guardrails. Those are Polars batch jobs in Milestone B.

### 8. Input handling

- `input` is **RAM-only** for CEL evaluation.
- Evidence stores `input_digest` (SHA-256 of canonical JSON) and `pii_tokens[]` only.
- Never persist raw `input` in Postgres for debug.

### 9. Consent

- Engine checks: consent object present; `purpose` matches request `purpose`.
- Ignore `consent.valid` in v1 (field reserved, not evaluated).
- Kavach is **not** a Consent Manager.

### 10. Policy pack `fail_mode`

- Pack `fail_mode` applies to **CEL/runtime limits only** (expression errors, timeout).
- Must **not** override `ModelRecord.governance_mode` or the matrices in §5.

### 11. Idempotency

- Key: `correlation_id` + `model_id` (+ optional explicit `idempotency_key`).
- Retry with same key → same `evidence_id` and decisions; no duplicate chain entries.

### 12. Pack versioning time

- Active pack version = version **effective at `decision_time`**, not server clock at evaluate time.

### 13. Latency SLO (design targets)

| Segment | p99 target |
|---|---|
| Policy + CEL (in-process) | < 5 ms |
| End-to-end including evidence commit (same-rack Postgres) | < 50 ms |

Tune with partner measurements. Do not RFP 20 ms until measured.

### 14. Tenancy

- v1: single-tenant on-prem, no `org_id`.
- Domain types use `sector: String` (extensible enum later).

## Consequences

- Golden tests must assert both `policy_decision` and `returned_decision` where they differ.
- Dashboards require `mode` and `governance_mode` dimensions on every metric.
- Shadow infra failure requires an incident table/API, not a fake evidence row.
- MVP `caste_proxy_score` scenarios live in `golden/finance/mvp_mechanics/` only, not in `packs/finance/v0.yaml`.

## References

- `schemas/*.json`, `proto/evaluate.proto`
- `docs/DATA_AND_FAIRNESS.md`
- `docs/ADR-002-deployment-architecture.md`
