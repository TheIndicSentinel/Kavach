# ADR-012: Revocation by Signed System-of-Record Event

**Status:** Accepted (2026-10-06)  
**Date:** 2026-10-06  
**Deciders:** Kavach product/engineering  
**Related:** ADR-004 (mandates), ADR-007 (forward-once), ADR-011, PRD FR-9, [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md)

## Context

PRD FR-9: a payment, a dispute, a consent withdrawal, a quarantine or a manual kill must revoke the mandate **and the credentials** it authorises. Today:

- `MandateService::revoke` exists. It revokes a mandate and every mandate delegated from it, atomically in the store, and publishes `MandateRevoked`. `RevocationReason` already has `Payment` and `Dispute`.
- Nothing reaches it. No HTTP route calls it and no system-of-record event triggers it. The only SoR event is `loan.dpd30`, which *issues* a mandate.
- A borrower who pays keeps being contacted until the mandate expires (seven days). That is the product's central failure case.

## Decision

### 1. Two signed event types revoke
`loan.paid` and `loan.disputed`, sent to `POST /v1/sor/events` like `loan.dpd30`. They are verified the same way:
- a registered issuer key for the event's `system`;
- the freshness window (300 s);
- the replay guard (24 h);
- the event's own `event_id` is single-use.

### 2. What they revoke
Every **live** mandate issued from an event of the same `system`, `tenant_id` and `record_ref` (the loan), with its delegated children, via the existing `revoke_tree`. The reason is `Payment` or `Dispute`.

A revocation event names no agent and issues nothing.

### 3. Ordering: a revocation never reaches forward in time
A revocation applies only to mandates **issued at or before** the revocation's `occurred_at` (by the mandate's `nbf`, its issue time; an issuing event is accepted only within the 300 s freshness window, so this is its event's time within that window). A mandate issued at the same instant is revoked: when in doubt, contact stops. If the loan defaults again after a payment, the new `loan.dpd30` mandate is not revoked by the old `loan.paid`, even if that event is replayed within the window. The replay guard also refuses it.

### 4. The reply
- `200` with `{ "revoked": [mandate ids], "replayed": bool }`.
- Idempotent: the same event again returns the same set with `replayed: true` and revokes nothing new.
- A revocation that matches nothing is still `200` with an empty list, and is recorded. It is not an error, because the SoR may send it before Kavach ever issued.

### 5. Credentials: closing the check-to-send window
A resource credential is minted by the gateway inside the same request that forwards it, and the agent never holds one. The remaining window is between the authorize decision and the forward. The gateway **re-reads the mandate's status immediately before forwarding**:
- A mandate revoked in between leaves the call's record as decided (allowed) and ends it with outcome `not_executed` (`mandate_revoked`). No credential is minted and nothing is sent. If the mandate store cannot be read, the call ends the same way (`mandate_unavailable`): when in doubt, contact stops.
- The credential's single use and ≤15 s life remain the backstop.

### 6. Evidence and audit
- Each revocation is an admin audit entry: the event id, the record, the reason and the revoked ids.
- `MandateRevoked` is published per mandate, as today.
- A later call under a revoked mandate is a recorded BLOCK, as today, because verification refuses revoked mandates.

### 7. Revocations are evidence
Each revocation is also a signed record in the agent evidence chain (kind `mandate_revocation`, as ADR-013 adds `agent_state`): the event id, the record, the reason and the revoked ids. It is exported and verified with the decisions.

*Amended on acceptance (R1b):*
- **The record** holds the event (system, id, type, content hash, `occurred_at`), the revoked ids, `revoked_at` (when Kavach revoked) and `recorded_at` (when the record was written). The loan is named only by a keyed pseudonym, under a key of its own.
- **Revoke first, record second.** The request that revokes writes the record at once. It does not rely on the system of record retrying: a background reconciler pages through the stored revocations and writes any record still missing, idempotently by event id (one record per event, enforced by the database). Missing records are a metric and an alert.
- **One table.** Records of every kind share the chain's positions (migration 015). A reader refuses a kind it does not know rather than skipping it.

### 8. Attacks (catalog version 4)
- `forged-revocation`: a bad signature is refused.
- `replayed-revocation`: the replay guard refuses it.
- `stale-revocation`: outside the freshness window, refused.
- `revocation-for-another-tenant`: changes nothing.
- `revocation-reaches-forward`: an old `loan.paid` against a newer mandate leaves it live.

## Consequences

- **The pay-and-stop case works end to end.** `kavach simulate` gains its scenarios 4 (payment) and 5 (dispute), and the oracle models revocation.
- **A stolen SoR issuer key can now revoke as well as issue.** Revocation fails safe (contact stops), so the impact is denial of service, not unauthorised contact. Key rotation and the SoR key's custody (KEY_RUNBOOK) cover it.
- **The gateway does one more store read per forwarded call.** It's a primary-key lookup and negligible next to the provider round trip.
- SECURITY_PROPERTIES gains a row: "a payment or dispute event stops contact for that loan, including a call already authorised but not yet sent".

## Not addressed here

- **Consent withdrawal:** needs runtime consent changes, which have their own ADR.
- **Quarantine and manual kill:** ADR-013. A quarantine *suspends* mandates (reversible); only revoking an agent, or this ADR's events, revokes them.
- **Revocation propagation to other replicas' caches:** there are none today, because mandates are read from the store on every call.
- **An outbox for `MandateRevoked`:** FR-9's Postgres outbox, which comes with the event bus work.
