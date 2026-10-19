# ADR-017: Reconciling unknown outcomes

**Status:** Accepted (with the owner's decisions and amendments, 2026-10-18). **Implementation is gated:** it starts after the permanent Rust-versus-Python verifier-agreement test exists (because it changes the bundle format and both verifiers must keep agreeing), in the phases below, against the mock provider only. Nothing here is a claim about a real provider.

## Context

A call the gateway allowed and forwarded can end `unknown`: the request was sent and the result is not known (a timeout or loss after sending, a 408, a 5xx, a `jti` conflict) (ADR-005 §12, ADR-007 §6). The gateway never retries it (forward-once), because a retry could send twice. The outcome is a signed row, **written once**, off-chain.

Two consequences follow, and this ADR exists for them:

1. **Every recorded outcome of an `unknown` call stays "reported", forever.** There is no way to say what happened. The verifier lists them (`outcome_unknown`) and nothing can take them off the list. An auditor asking "was this borrower contacted?" gets "we don't know" for ever.
2. **Nothing can age out.** An alert on *how long* a call has been unknown would only grow, which is why the monitoring work stopped at a rate alert.

The mock provider already has the property that makes a resolution possible: it stores the result by `jti` and returns it for an exact repeat (200 `replayed`). Its status contract has no *query* though: today the only way to learn the result is to send again, which the gateway must never do.

## What a resolution must and must not do

- **Never resend.** The reconciler has no send path. It asks a *status* question; it does not forward anything. If the answer is "not delivered", the loan is not contacted again by this mechanism: a new contact is a new agent call, decided afresh under the mandate, the window, the cap and the state of the loan.
- **Never rewrite the outcome.** The `unknown` row is signed and written once; it stays as it is. A resolution is a **second signed row** that refers to it. The history ("it was unknown, then it was confirmed delivered, by whom, from what") is the evidence.
- **Say how it is known.** A resolution carries its source: the provider's status answer (`provider_status`, with a digest of the answer) or a person's attestation (`operator_attested`, with a reference). The two are not equal and are never merged into one label.
- **"Ambiguous" is an honest answer.** If the provider cannot say, or answers inconsistently, or the horizon passes, the resolution is `ambiguous` and the call stays on the list, now with a reason. It is never silently promoted to delivered or not delivered.
- **The contact cap is not released by a resolution.** The slot reserved at commit stays counted whatever is learned, including `confirmed_not_delivered`. Releasing it would let a later contact exceed the daily cap on the strength of an answer that may be wrong. (Open question 4.)

## Options

| | A. Separate signed resolution rows (proposed) | B. Replace the outcome | C. A kind in the evidence chain |
|---|---|---|---|
| Mechanism | A new append-only table of signed resolutions keyed by `credential_id` and the outcome row's hash; the latest governs, earlier ones stay | Update the `unknown` row | A chain record kind (like `agent_state`) |
| Keeps the original outcome | Yes | **No** (breaks write-once and the signature meaning) | Yes |
| History visible to an auditor | Yes (every resolution, in time order) | No | Yes, ordered with decisions |
| Format change | A new file in the bundle (`resolutions.jsonl`), so a new bundle format version and both verifiers | None, but unacceptable | A new record kind, so a new bundle version |
| Cost | Moderate | Low | Higher (chain lock, partition ordering) |
| Verdict | **Chosen** (a separate signed list is enough for now) | Rejected | Deferred, only if an auditor needs resolutions ordered against decisions |

## Decision

1. **Data.** `outcome_resolution`: `tenant`, `credential_id`, `outcome_ref` (the hex SHA-256 of the outcome row's `sig`, so it names *that* row), `state` (`confirmed_delivered`, `confirmed_not_delivered`, `ambiguous`), `source`, a closed reason code, a digest of the provider's answer or of the operator's reference (never the thing itself), the people involved, a time, signed with the evidence key under its own prefix (`kavach-outcome-resolution-sig-v1:`). The sources are `provider_status`, `operator_attested`, `conflict_resolution` (the two-person closure below) and `reconciler` (the reconciler's own statement that nothing could be learned: `ambiguous` only). One row per `(source, state)` for an outcome (a repeat is a no-op); only an `unknown` outcome is resolved. Many per outcome; the governing state is computed from all of them (see Conflicts), never from the latest. **Built in R1a**: the types, the signing, the form rules (who may say what, enforced by the store), the governing-state function, the append-only table (migration 023, with the runtime role insert-and-read and the auditor role read-only) and the store contract on memory and Postgres.
2. **Status contract (mock first).** The provider answers `GET /v1/messages/{jti}` with only the stored status (`delivered`, `not_delivered`, `unknown`), authenticated by the same credential binding as the send, and never the destination. The mock gains it. **A status lookup is a hypothesis about real providers, not an assumption**: many will not offer one by an idempotency key, so for them the common outcomes will be `operator_attested` and `ambiguous`, and the design must be as honest and as usable on those paths as on the mock's. A real provider's mapping is ADR-015's work.
3. **Reconciler.** A background task, like the revocation reconcilers, reads `unknown` outcomes with no governing resolution, asks the status question with back-off for **up to an hour** after the outcome (`UNKNOWN_OUTCOME_POLL_WINDOW`, one hour), is rate limited, and writes the resolution when it gets a confirmed answer. If there is no confirmed answer **24 hours** after the outcome (`UNKNOWN_OUTCOME_AMBIGUOUS_AFTER`, 24 hours), it writes `ambiguous`. Between the two the call stays unresolved and is not polled; a person may attest at any time. Both are named constants for now, not settings.
4. **Operator attestation follows the rule used elsewhere: tightening is one person, loosening is two.** Attesting that a contact **was delivered** (the record grows, nothing is hidden) needs one person: a change request with a reference and a reason code, audited. Attesting that a contact was **not delivered** needs **two**, a proposer and a different approver, as for agent reinstatement, because it lowers the recorded contact and could hide a violation. "Two different people" means two different **authenticated human identities**, compared by their whole source-qualified keys (the same comparison the change requests use, for example `oidc:<issuer>#<subject>`); a certificate principal cannot attest. The store checks the keys differ; that the caller really authenticated is the route's job (R3). The usual limit stands: one person holding two accounts at the identity provider passes as two.
5. **Verifier and bundle.** `outcome_unknown` becomes "unknown and unresolved"; resolved ones are listed with their resolution and its source; a conflicted outcome is its own list; an unsigned or inconsistent resolution is a failure (as a bad outcome signature is), not a gap. **One bundle format bump (format 4)** covers this and the dispute-release record of ADR-016 if both are built, not two; the specification, vectors and both verifiers move together.
6. **Signals.** The unresolved count and **the age of the oldest unresolved** (meaningful now), the ambiguous count, and resolutions written by source; alerts on the age and on ambiguous resolutions.
7. **Attacks and simulation.** A resolution cannot be forged without the key; a reconciler that is made to resend is caught (it has no path, and a test shows the gateway's forward-once still holds); the simulator's oracle gains the resolved states from its own ground truth, not from Kavach's records.

## Conflicts: no "latest wins"

A silent flip would hide exactly what an auditor needs to see, so the governing state is computed from **all** of an outcome's resolutions, never from the latest:

- Take the distinct *confirmed* states among them (`confirmed_delivered`, `confirmed_not_delivered`).
- **None:** the outcome is `ambiguous` if there is an ambiguous row, else unresolved.
- **One:** that state governs. If it was reached by a provider status and by an attestation alike, the **provider status outranks the attestation** as the stated source.
- **Two, different:** the outcome is **`conflicted`**. It raises an alert, appears in the verifier's conflicted list, and is closed only by a **two-person** resolution (a change request that names the governing state and why). Until then, neither state is reported as true.
- **An `ambiguous` row never overrides a confirmed one**, whenever it was written; it is kept as history and ignored for the governing state.

## Phases (each its own change, against the mock only)

R1 the data, signing, store (**R1a, built**) and the verifier and bundle (**R1b, built**, bundle format 4). R2 the mock status endpoint (**R2a, built**) and the reconciler (**R2b, built**: `kavach-dataplane::outcome_reconciler`, run every 15 seconds by `kavach-api::outcome_reconciler`; questions limited to 8 per outcome with 30 s to 10 min back-off and 20 per pass; the constants are `UNKNOWN_OUTCOME_POLL_WINDOW`, `UNKNOWN_OUTCOME_AMBIGUOUS_AFTER` and friends, not settings). R3 operator attestation, signals, attacks and the simulator.

### Amendment, R2a: how the status question is authenticated

Decision 2 says the question is "authenticated by the same credential binding as the send". The gateway cannot present the send credential: it does not keep it (the credential holds the destination, and a stored one would put the recipient at rest), and it records only the `jti`. So the question is **its own signed token**, not the send credential:

- A compact JWS, `typ: kavach-status+jws`, signed by the **same credential key** as the send, so a provider that already trusts that key needs nothing new. Claims: `iss`, `tenant`, `aud` (the provider), `jti` (the send asked about), `iat`, `exp` (at most 60 seconds). **No destination, channel or template.**
- Sent as `GET /v1/messages/{jti}` with `Authorization: Kavach-Status <JWS>` and no body. The provider verifies the signature and audience, checks that the `jti` in the path is the one in the claims and that the tenant is the one the send was made for, and answers `{"status": "delivered" | "not_delivered" | "unknown"}` and nothing else. `unknown` is also the answer for a `jti` it never stored.
- Because it is a different `typ`, a send credential is not accepted as a status question and a status question is not accepted as a send credential (tested both ways, in the credential crate and at the mock provider). **A provider MUST check the type marker** (`typ: kavach-status+jws`) and the claim set (`deny_unknown_fields`) before it answers, and MUST check that the `jti` in the path is the one in the claims and the tenant is the one the send was made for. The signing key is the broker's, but a status question has its own type marker, its own claims and a lifetime of at most 60 seconds, and carries no destination.
- The gateway side is a separate trait, `StatusAsker`, whose method takes a status question and never a credential: **the code that reconciles has no value it could send with, and no send method to call.** An answer outside the contract (another word, extra members, a non-200, a redirect, no answer) is no answer and never becomes a confirmed state. The evidence digest in the resolution is the SHA-256 of the answer body.

This is a hypothesis about real providers, as decision 2 says; it does not change how a real provider is mapped (ADR-015).

## Decisions on the open questions (owner, 2026-10-18)

1. **Real providers:** assume nothing. A provider status lookup is a hypothesis; build against the mock only. `operator_attested` and `ambiguous` will probably be the common outcomes outside it, and the ADR says so (Decision 2).
2. **Horizon:** ask with back-off for up to an hour; write `ambiguous` at 24 hours without an answer; named constants.
3. **Attestation:** delivered needs one person; not delivered needs two (Decision 4).
4. **The contact slot:** a resolution **never** releases it. Any release is a separate, two-person decision, out of scope here.
5. **Ordering against decisions:** a separate signed list is enough; option C is deferred.

## Consequences

- An unknown outcome gains a way to become known, with its history, without any path that can send again.
- Every claim about delivery has to say its source (`provider_status` or `operator_attested`); neither is "proof of delivery".
- A bundle format version and both verifiers change, as for the kill switch.
- Until this is built, **every unknown outcome stays reported and unresolved**, and the monitoring work does not measure its age. Once R1 and R2 exist, the age of the oldest unresolved outcome and the conflicted count become meaningful alerts (R3).
- Two different non-ambiguous answers for one outcome are an incident, not a tie to break.
