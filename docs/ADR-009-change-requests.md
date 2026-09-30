# ADR-009: Maker-Checker Change Requests

**Status:** Accepted  
**Date:** 2026-09-30  
**Deciders:** Kavach product/engineering  
**Related:** ADR-001, ADR-005, ADR-008, [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md), [THREAT_MODEL.md](THREAT_MODEL.md)

## Context

Six operations change live governance: activate a policy pack, roll back, update the model record (status, governance mode), change the retention period, erase evidence (DPDP) and run retention. Until H3 each was one request carrying two names — the authenticated actor and an `X-Kavach-Approver` header the same caller typed — so one person could make any of these changes alone.

Banks already run maker-checker for such changes: one person proposes, a different, authorised person approves exactly what was proposed, and both are recorded.

## Decision

### 1. Lifecycle

`POST /v1/change-requests {kind, params, reason?}` creates a **pending** request. Approval **applies** it; there is no separate apply step.

`pending → applied | failed | rejected | cancelled | expired`. Decided requests are immutable (a database trigger refuses updates and deletes).

| Endpoint | Who |
|---|---|
| `POST /v1/change-requests` | Principal allowed `propose_<kind>` |
| `POST /v1/change-requests/{id}/approve {change_digest}` | A **different** principal allowed `approve_<kind>`, with an **OIDC token** |
| `POST /v1/change-requests/{id}/reject {reason?}` | A principal allowed `approve_<kind>`, other than the proposer |
| `POST /v1/change-requests/{id}/cancel` | The proposer |
| `GET /v1/change-requests[?status=]`, `GET /v1/change-requests/{id}` | `read_change_requests` |

The direct mutation endpoints and `X-Kavach-Approver` are removed.

### 2. What is frozen at proposal

Each kind's `params` are validated (unknown fields refused) and the change is **prepared**: every check that approval would run (pack exists and its `id` matches, signature and digest pin, model schema, **supplier controls**, evidence exists, …) runs at proposal too. The request records a `binding` — the state the change was computed against:

| Kind | Binding |
|---|---|
| `activate_pack`, `rollback_pack`, `update_model` | Runtime pointer `version`, plus pack id/path/digest or the model's current status and mode |
| `update_retention` | Current retention days |
| `erase_evidence` | Evidence id (must exist, not yet tombstoned) |
| `apply_retention` | A **frozen cutoff** plus the count and SHA-256 of the untombstoned evidence older than it |

`change_digest` = SHA-256 over the RFC 8785 canonical JSON of id, tenant, kind, params, binding, proposer key and times. The approver must **echo** it, so what a console shows is what is approved.

### 3. Approval

1. Authorise `approve_<kind>`; the approver must authenticate with an **OIDC token** (certificate principals are workloads, not people); the header path is allowed only in `--insecure-dev`.
2. Distinctness: source-qualified identity (`oidc:<iss>#<sub>`, `mtls:<san>`) **and** display id must differ from the proposer's.
3. Not expired (server time; default TTL 24 h, `--change-request-ttl-hours` 1–168).
4. Re-prepare; the fresh binding must equal the frozen one, otherwise the request is **failed**.
5. One transaction: lock the request (`FOR UPDATE`, still `pending`), lock the pointer row and compare `version`, re-check the effect (retention set, tombstones, retention days), write the effect, append the audit row, mark `applied`. Concurrent approvals — including on different replicas — apply once; the loser gets `409`.
6. After commit, swap the live evaluator (prechecked, so it cannot fail on validation; otherwise a restart converges on the committed pointer).

A retry of a successful approval by the same approver returns the applied request.

### 4. Separation of duties

Cedar has `propose_*` and `approve_*` actions per kind. The example policy lets `admins` propose and a separate `change-approvers` group approve; banks should keep the groups disjoint and assign `change-approvers` only to people.

### 5. Runtime pointer version

`runtime_pointers.version` increments on every write. `/v1/runtime` reports the version this process serves, the stored version and `pointer_drift` (another replica applied a change this one has not loaded — restart it).

## Consequences

- One person can no longer change governance alone, provided the IdP gives each person one identity and the approver group only to people.
- Every change needs two people: with only one admin available, nothing can change — including urgent DPDP erasure. There is no break-glass.
- **Breaking:** the six mutation endpoints and `X-Kavach-Approver` are gone; clients propose and approve. Pilot scripts use `PILOT_ACTOR_TOKEN` and `PILOT_APPROVER_TOKEN`.
- Model status and governance mode remain runtime-only (lost on restart) until the governed model record (H3b). *Resolved by ADR-010:* `update_model` persists, and `activate_model` is a seventh kind.

## Deferred

- Governed model record, model YAML pin and signatures, `activate_model` kind (H3b).
- N-of-M approvals; break-glass with alerting.
- Change requests as governance events on the evidence chain (ADR-005).
- Replicas reloading on pointer change (P1 HA).
