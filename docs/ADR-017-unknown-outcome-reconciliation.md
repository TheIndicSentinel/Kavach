# ADR-017: Reconciling unknown outcomes

**Status:** Proposed. Not decided, and not to be implemented from this text. It needs the owner's choice between the options below and the answers to the open questions; it can be built and tested against the mock provider only.

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
| Verdict | **Proposed** | Rejected | Later, only if an auditor needs resolutions ordered against decisions |

## Proposed decision (when the questions are answered)

1. **Data.** `outcome_resolution`: `tenant`, `credential_id`, the hash of the outcome row it resolves, `state` (`confirmed_delivered`, `confirmed_not_delivered`, `ambiguous`), `source` (`provider_status`, `operator_attested`), a closed reason code, a digest of the provider's answer or an operator reference, `resolved_at`, signed under its own prefix. Many per outcome; the latest in time governs.
2. **Status contract (mock first).** The provider answers `GET /v1/messages/{jti}` with only the stored status (`delivered`, `not_delivered`, `unknown`), authenticated by the same credential binding as the send, and never the destination. The mock gains it; a real provider's mapping is ADR-015's work, not assumed here.
3. **Reconciler.** A background task, like the revocation reconcilers, reads `unknown` outcomes with no governing resolution, asks the status question with bounded retries and back-off, is rate limited, and writes the resolution. After a horizon (open question 2) without an answer it writes `ambiguous` and stops asking.
4. **Operator attestation.** A person may attest an outcome from outside Kavach (for example the provider's console): a change request kind, with the reference and a reason code, audited; whether it needs a second person is open question 3.
5. **Verifier and bundle.** `outcome_unknown` becomes "unknown and unresolved"; resolved ones are listed with their resolution; an unsigned or inconsistent resolution is a failure (as a bad outcome signature is), not a gap. Bundle format 4, the specification, vectors and both verifiers move together.
6. **Signals.** The unresolved count and **the age of the oldest unresolved** (meaningful now), the ambiguous count, and resolutions written by source; alerts on the age and on ambiguous resolutions.
7. **Attacks and simulation.** A resolution cannot be forged without the key; a reconciler that is made to resend is caught (it has no path, and a test shows the gateway's forward-once still holds); the simulator's oracle gains the resolved states from its own ground truth, not from Kavach's records.

## Phases (each its own change, against the mock only)

R1 the data, signing, store and verifier (bundle format 4). R2 the mock status endpoint and the reconciler. R3 operator attestation, signals, attacks and the simulator.

## Open questions

1. Which real providers expose a status lookup by an idempotency key or message id, and with what latency and retention? (This decides whether `provider_status` is ever available outside the mock.)
2. How long before an unresolved call is `ambiguous`: minutes, hours, the provider's retention window?
3. Who may attest an outcome, and is one person enough? (A delivered contact and a not-delivered contact have different consequences for a borrower and for the lender's conduct record.)
4. Does a `confirmed_not_delivered` ever release the contact slot, and under whose authority? (Proposed: never automatically.)
5. Does an auditor need resolutions ordered against decisions in the chain (option C), or is a separate signed list enough?

## Consequences

- An unknown outcome gains a way to become known, with its history, without any path that can send again.
- Every claim about delivery has to say its source (`provider_status` or `operator_attested`); neither is "proof of delivery".
- A bundle format version and both verifiers change, as for the kill switch.
- Until this is accepted and built, **every unknown outcome stays reported and unresolved**, and the monitoring work does not measure its age.
