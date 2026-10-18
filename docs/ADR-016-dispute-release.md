# ADR-016: Releasing a dispute hold

**Status:** Proposed. Not decided: it cannot be finalised until a lender says what ends a dispute (open questions below). Do not implement from this text.

## Context

ADR-012 (B2 amendment) holds a loan against new mandates for as long as a `loan.disputed` is recorded for it, and a payment does not release it. The hold is derived from the stored revocation, so it needs no state of its own, and there is **no release path**: a held loan stays held. That is the safe direction (contact does not resume by accident) and it is incomplete: a real lender resolves disputes, and a loan that can never be contacted again is a defect of the product, not a property.

The kill switch (ADR-013) already settled the shape for the same problem on agents: **tightening is automatic and immediate; loosening is deliberate, needs a second person, and is recorded.** This ADR applies it to a loan.

## What a release must and must not do

- **Never resurrect authority.** A dispute *revokes* mandates (unlike an agent quarantine, which suspends them). A release does not bring them back. After a release the loan is open to **new** issuing events only, through the normal path (template, consent, passport, freshness, closure rule).
- **Facts before the release stay closed.** A release records a *release barrier* at its own time `R`. An issuing event that occurred at or before `R` plus the skew margin is refused, so a default that preceded the resolution cannot be replayed into a live mandate. A default that occurs after `R` is a new default.
- **A later dispute holds again.** The hold is "the latest recorded dispute is later than the latest release", not "a dispute was ever recorded".
- **No automatic expiry.** A hold that clears by itself after a time is a bypass: contact would resume without a decision.
- **Releasing an unheld loan is not an error that changes anything**: it is refused (404/409), recorded as an attempt, and revokes and issues nothing.

## Options

| | A. Operator release as a change request | B. A signed resolution event from the system of record | C. Both |
|---|---|---|---|
| Mechanism | A new change-request kind (ADR-009), proposed by one principal and approved by a different human identity, exactly like `reinstate_agent` | A new revoking-class event type (`loan.dispute_resolved`) signed by a registered issuer key, bound to its tenant and system | A for exceptions and recovery, B as the normal path |
| Authority that releases | Two people at the lender or the operator | The lender's own system, which is the authority on the loan | Both, each recorded as such |
| New protocol surface | None (reuses the change-request machinery, a Cedar action, an audit trail) | A new event type: spec text, test vectors, verifier changes, an attack or two | Both |
| Needs the lender's definition | Only who may release | **What ends a dispute** and what the event means | Both |
| Failure mode | A person releases wrongly (mitigated: two people, recorded) | The source emits it wrongly or replays it (mitigated: signature, binding, idempotency, release barrier) | Both |
| Recommended | **First** | After the lender defines it | The end state |

## Proposed decision (when the questions are answered)

1. **Ship A first.** `release_dispute_hold` as a change-request kind: proposal names the loan (system, record reference), a reason code from a closed vocabulary and a keyed digest of the free-text note (the note itself is never in the chain, as for agent state changes); approval needs a human identity different from the proposer's; a Cedar action of its own, so the role is a policy-only change later; every attempt audited, including refusals; a global rate limit and an alert.
2. **Semantics as above:** a release barrier at the approval time; the hold is derived from "latest dispute later than latest release".
3. **Storage:** a small append-only table of releases keyed by tenant, system and record, written in the same transaction as the approval, under the tenant mandate lock that issuance and revocation already take, so a release cannot interleave with an issuing check.
4. **Evidence:** for the pilot the change request's audit trail is the record. If a lender needs an auditor to see *why* contact resumed, a release becomes an evidence-chain record kind (a new bundle format version, with the specification, vectors and both verifiers updated). If it is built together with ADR-017's outcome-resolution rows, both share **one** bundle format bump (format 4), not two. Until then an auditor sees a recorded dispute and later allowed decisions with no record in the chain between them. That is a known gap, and it must be said in the property row, not left implied.
5. **B afterwards**, only when the lender defines the event, with its own ADR amendment, spec text and vectors.

## Attacks (catalog additions when built)

`release-without-approval` (a proposal alone releases nothing), `self-approved-release` (the proposer cannot approve), `release-reaches-back` (a default at or before the release time is still refused), `dispute-after-release-holds-again`, `release-of-an-unheld-loan` (changes nothing), and for B `resolution-event-for-another-tenant`.

## Open questions for the lender (these decide B and the role)

1. What ends a dispute: a resolution recorded in the system of record, a statement from a named function, a regulator's or ombudsman's decision?
2. Does a payment ever end it, or does a payment during a dispute leave it open?
3. Who may release, and is two people the right bar?
4. Does regulation or the lender's own conduct policy set a minimum time before contact may resume, or a required notification to the borrower?
5. Can a dispute be withdrawn by the borrower, and is that the same event?

## Consequences

- A held loan has a way out that cannot be used by one person, cannot raise a dead mandate, and cannot reach back.
- Option A needs no change to the SoR contract, so it can be rehearsed before a lender is in the loop.
- Without a release-time record in the evidence chain, the auditor-visible story of a resumed loan is the weakest part of A; that is deliberate and recorded, and is the reason to keep B and the evidence kind on the list.
- Until this is accepted and built, the B2 behaviour stands: **a disputed loan stays held**.
