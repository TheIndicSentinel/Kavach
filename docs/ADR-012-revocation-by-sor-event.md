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
- **Bundle format 2** carries every kind; format 1 bundles (decisions only) still verify, and the format 1 test vector is kept byte-identical.

### 8. Attacks (catalog version 4)
- `forged-revocation`: a bad signature is refused.
- `replayed-revocation`: the replay guard refuses it.
- `stale-revocation` (superseded by `late-revocation` in catalog 7, see the addendum): outside the freshness window, refused.
- `revocation-for-another-tenant`: changes nothing.
- `revocation-reaches-forward`: an old `loan.paid` against a newer mandate leaves it live.

*Amended on acceptance (R1c):*
- **Three more attacks:**
  - `future-revocation`: dated beyond the freshness window, refused.
  - `unknown-event-type`: a validly signed event of an unregistered type, refused and revokes nothing.
  - `revocation-wrong-loan`: a valid payment for another loan leaves the attack mandate live.
- **Ground truth:** every attack is judged on the attack mandate (a pre-check) and on the evidence chain, not only the reply. A refused event adds no `mandate_revocation` record, and the replay adds no second one. An accepted event that should have been refused is a breach, whatever it revoked.
- **`revocation-for-another-tenant`:** the tenant is part of the signed event and every revocation is scoped by it. A stack serves one tenant and now refuses an event for any other (400) before acting on it.
- **`replayed-revocation`:** the replay returns the stored result (`replayed: true`); the replay guard is not what answers a retry.

*Amended (B1, late revocations):*
- **A revoking event has no maximum age.** Freshness (300 s) applies to *issuing* events and to the future bound of every event. A `loan.paid` or `loan.disputed` that reaches Kavach ten minutes, or a day, late is accepted and revokes: before this, such an event was refused and nothing retried it, so contact continued after a payment (fail open).
- **Why it is safe:** a revocation only tightens; it is signed by a registered issuer key bound to the tenant and system; it is scoped by its own `occurred_at` (a mandate issued after it stays live); and a repeat is answered from the stored revocation for `(tenant_id, system, event_id)`, which does not expire.
- **Attack catalog 7:** `stale-revocation` becomes `late-revocation`: a payment dated 15 minutes ago is *accepted* and revokes nothing issued after it. `future-revocation` stays refused.
- **Still open (B2):** a payment that arrives before the default it follows does not yet stop that default's mandate.

*Amended (B3, one-step apply):*
- **Revoke and record are one step.** The store's `apply_revocation` revokes every active root of the record with `nbf <= occurred_at` and its delegations, and writes the revocation row, in one transaction. A crash leaves all of it or none of it; before, each root was revoked in its own transaction and the row written afterwards, so a crash could leave some mandates live and the revocation unrecorded.
- **A revoking event spends no time-limited guard.** Its single use is the stored revocation, applied in that same step. A retry after any failure therefore completes the revocation instead of looking like a replay. Issuing events keep the 24 h replay guard.
- **Idempotent by event id.** The same event again returns the stored result (`replayed`) and changes nothing; the same id with other content is refused, and revokes nothing.
- **Lock.** The step holds the tenant's mandate lock, the one delegation and `revoke_tree` already take, so it serialises with every other mandate write. A per-record lock would not have excluded those; it becomes useful only once issuance takes the same lock (B2).
- **Publication** of `MandateRevoked` stays after the commit; a lost notification does not undo it.

*Amended (S4, clock gating):*
- **Issuing and delegating authority need a synchronised clock.** Freshness, `nbf` and `exp` rest on Kavach's trusted time. `issue_from_event` and `delegate` call `require_synced(max_clock_error_ms)` (500 ms, the bound the gateway holds a decision to) and fail closed with `Unavailable` otherwise. Nothing is spent: the event is retried once the clock is back.
- **Revoking applies on any clock.** Stopping contact is the safe direction, so it is flagged rather than refused. On an unsynchronised clock the future bound is **not evaluated** either: it would be measured against a time that cannot be trusted, and a clock that is behind would make a genuine payment look future-dated and leave contact running. The event is applied, with the same signature, issuer, scope and idempotency checks.
- **The flag is stored with the revocation.** `mandate_revocations.clock_synced` (migration 020, additive and nullable; `NULL` is a row written before it, unknown), returned as `RevokedByEvent.clock_synced` (the value from when it was *applied*, also on a retry), and written to the admin audit entry and a warning log. Because it is on the row, an audit entry derived from the row later (S3) says the same.
- **It is not in the evidence record.** The `mandate_revocation` record has its own `time_sync`, taken from the clock when the record was *written* (possibly by the reconciler, later). `clock_synced` on the row is the only application-time flag; putting it in the signed record would be a format change.
- **A signal.** `kavach_sor_events_unavailable_total{kind}` counts events answered 503, and the `KavachSorEventsUnavailable` alert fires when it keeps rising: refused issuance would otherwise stop new mandates silently.
- **One bar.** The 500 ms bound is `DEFAULT_MAX_CLOCK_ERROR_MS`, used by the data plane's `AuthorizeConfig` and by the mandate service.

*Amended (S3, the audit entry is derived from the row):*
- **The admin audit entry of a revocation is a function of its stored row** (`event_id`, `event_type`, `revoked`, `clock_synced`; the loan is the resource). It is written once per `(tenant, system, event id)` (`append_audit_once`, migration 021: a nullable unique `idempotency_key` on `admin_audit_log`; entries without a key are unaffected).
- **Two writers, one entry.** The request writes it after the commit; a reconciler pages through the stored revocations and writes any that is missing. Whichever is first wins and the content is the same, so a crash or a failed write between the commit and the entry no longer leaves the audit log short. `revocation audit entry missing` is logged as an alert if the entry cannot be written.
- **Limits.** The reconciler scans from the start after a restart (idempotent, one attempt per stored row); at very large volumes that wants a persisted watermark, which is deferred. Entries for revocations applied before migration 021 are written on the first pass with `clock_synced: null` where unknown.

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
