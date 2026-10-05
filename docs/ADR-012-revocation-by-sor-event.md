# ADR-012: Revocation by Signed System-of-Record Event

**Status:** Proposed  
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
A revocation applies only to mandates whose issuing event `occurred_at` is **earlier** than the revocation's `occurred_at`. If the loan defaults again after a payment, the new `loan.dpd30` mandate is not revoked by the old `loan.paid`, even if that event is replayed within the window. The replay guard also refuses it.

### 4. The reply
- `200` with `{ "revoked": [mandate ids], "replayed": bool }`.
- Idempotent: the same event again returns the same set with `replayed: true` and revokes nothing new.
- A revocation that matches nothing is still `200` with an empty list, and is recorded. It is not an error, because the SoR may send it before Kavach ever issued.

### 5. Credentials: closing the check-to-send window
A resource credential is minted by the gateway inside the same request that forwards it, and the agent never holds one. The remaining window is between the authorize decision and the forward. The gateway **re-reads the mandate's status immediately before forwarding**:
- A mandate revoked in between makes the call a recorded BLOCK (`mandate_revoked`) with outcome `not_executed`. Nothing is sent.
- The credential's single use and ≤15 s life remain the backstop.

### 6. Evidence and audit
- Each revocation is an admin audit entry: the event id, the record, the reason and the revoked ids.
- `MandateRevoked` is published per mandate, as today.
- A later call under a revoked mandate is a recorded BLOCK, as today, because verification refuses revoked mandates.

### 7. Attacks (catalog version 4)
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
- **Quarantine and manual kill:** ADR-013.
- **Revocation propagation to other replicas' caches:** there are none today, because mandates are read from the store on every call.
- **An outbox for `MandateRevoked`:** FR-9's Postgres outbox, which comes with the event bus work.
