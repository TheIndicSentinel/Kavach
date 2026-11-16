# Design: Splitting the Two Meanings of `Rejected` (L17)

**Status: Proposal. Needs the owner's go before any code changes.** It touches the dataplane, the mandate service and the evidence stores, which are all second-review areas ([SECOND_REVIEW.md](../SECOND_REVIEW.md)). It would also amend ADR-006 §3.

**Finding L17** (backlog issue #218): in `crates/kavach-dataplane/src/outcome_reconciler.rs:175`, a `Rejected` from `record_outcome` is taken to mean "the call itself wrote the outcome in the meantime". Its other causes are not checked. The owner's decision on #218 was "a read-only check before any fix". This note is that check, plus a proposal.

**Summary.**
- `Rejected` means two things today: "the answer is no" and "a row for this key already exists".
- Callers that need to tell them apart do it by string matching, by re-reading the row, or not at all (L17).
- The proposal adds a fourth error class, `Conflict`, for the second meaning.
- `Rejected` is an internal error class, not a value in any evidence record, bundle, checkpoint or `DecisionEvent`. The split is therefore **not** a breaking evidence change, provided the rule in section 4 holds: every reason code, problem type, audit `why` and metric label written today stays the same.
- The brief expected a breaking evidence change; the code shows the impact is narrower.

## 1. Where `Rejected` is

`ErrorClass` (`crates/kavach-ports/src/error.rs`) has three classes: `Unavailable`, `Rejected` and `Invalid`. ADR-006 §3 defines `Rejected` as "Dependency answered 'no' (bad signature, revoked, replay)", handled as "`BLOCK` with reason code".

Searched with `grep -rn 'PortError::rejected\|ErrorClass::Rejected' crates/ --include='*.rs'`. That finds 212 lines in 45 files, 153 of them outside tests and `kavach-ports-testkit`. The 134 that create a `Rejected` outside tests (`PortError::rejected`), by file:

| File | Count |
|---|---|
| kavach-mandate/src/service.rs | 36 |
| kavach-credential/src/lib.rs | 15 |
| kavach-storage/src/postgres/mandates.rs | 11 |
| kavach-keys-pkcs11/src/lib.rs | 10 |
| kavach-mandate/src/memory.rs | 8 |
| kavach-keys/src/lib.rs | 6 |
| kavach-storage/src/postgres/agent_evidence.rs | 6 |
| kavach-mandate/src/delegation.rs | 5 |
| kavach-ports/src/checkpoint.rs | 5 |
| kavach-storage/src/agent_evidence.rs | 5 |
| kavach-keys/src/pack_sig.rs, kavach-ports/src/agent_state.rs, kavach-ports/src/outcome_resolution.rs | 4 each |
| kavach-credential/src/jwe.rs | 3 |
| kavach-api/src/dataplane.rs, kavach-dataplane/src/tools.rs, kavach-keys/src/model_sig.rs, kavach-keys/src/tool_sig.rs | 2 each |
| kavach-dataplane/src/authorize.rs, kavach-dataplane/src/resolve.rs, kavach-jws/src/lib.rs, kavach-ports/src/keys.rs | 1 each |

**Not in scope:**
- `ChangeStatus::Rejected` (`crates/kavach-storage/src/change_requests.rs:73`, `'rejected'` in migration 006, `status` enum in `docs/openapi.yaml`) is a change request that a second principal turned down (`reject_change`, `crates/kavach-api/src/state_changes.rs:428`). It has one meaning, is stored and on the wire, and this proposal leaves it unchanged.
- `Outcome` (`crates/kavach-ports/src/agent_evidence.rs:329`) has no `Rejected` variant. A provider's refusal is `Refused`, and that is unaffected.

## 2. The two meanings

**Meaning A: refused.** The dependency checked the request and said no. Retrying the same request gets the same answer. Examples, by message:
- Signatures and keys: "unknown signing key {kid}" (keys, HSM), the JWS and JWE verification failures, and `UNTRUSTED_ISSUER`.
- Mandates: "unknown mandate", "mandate {} is revoked", "is not valid at this time", "parent mandate … is not active", the delegation and consent checks, and the dispute hold ("held after a dispute"), among others.
- Agent state rules: "loosening an agent's state needs a second principal's approval", "the approver must be a different principal", "the agent is already {}".
- Evidence links: "no allowed record for this credential" (`record_outcome`), "no record with this seq and hash to checkpoint", "checkpoint does not advance past the latest checkpoint", and the four outcome-resolution rules (`outcome_resolution.rs:287–302`).
- Replay: "replayed identifier {key}" (`kavach-api/src/dataplane.rs:375`, `postgres/mandates.rs:659`). This stays a refusal: a replayed nonce is not the caller's own earlier write, and re-reading does not make it acceptable.

**Meaning B: a row for this key already exists.** A write lost to an earlier write of the same unique key. The earlier write may have been the caller's own (a retry after a lost answer), a concurrent replica's, or one with different content. The caller can re-read the stored row to decide what to do. The producers:

| Message | Where |
|---|---|
| "outcome already recorded" | `kavach-storage/src/agent_evidence.rs:169`; `postgres/agent_evidence.rs:536` (unique violation) |
| "this event's revocation is recorded with different content" | `agent_evidence.rs:355`; `postgres/agent_evidence.rs:168` |
| "this change of the agent's state is recorded with different content" / `STATE_RECORD_EXISTS` | `agent_evidence.rs:726`; `postgres/agent_evidence.rs:134, 1182` |
| "mandate {} exists" / "mandate {} exists, or event {} already issued a mandate" | `kavach-mandate/src/memory.rs:50`; `postgres/mandates.rs:147` (unique violation) |
| "event {} was already used with different content" | `memory.rs:157`; `service.rs:347, 677`; `postgres/mandates.rs:362` |
| "revocation event {} was recorded already" | `memory.rs:452`; `postgres/mandates.rs:543` (unique violation) |

The test kit pins meaning B as `Rejected`. For example, `one_outcome_per_credential_under_concurrency` (`kavach-ports-testkit/src/agent_evidence.rs:576`) requires that "a loser is Rejected". The `append_revocation` contract (`agent_evidence.rs:243–248`) requires "other content for the same event: refused".

## 3. How callers tell the meanings apart today

| Caller | What it does | Problem |
|---|---|---|
| `outcome_reconciler.rs:175`, `recover_stuck_allows` | Every `Rejected` from `record_outcome` counts as "written by the call itself", so it is neither recorded nor reported | **L17.** Meaning A is hidden as well. See below. |
| `gateway.rs:377`, `record_outcome_retrying` | After an `Unavailable` attempt, it re-reads the stored outcome on `Rejected` and accepts it only if the stored outcome matches | Correct, but only because it re-reads. A first-attempt `Rejected` of either meaning is returned as an error. |
| `kavach-api/src/dataplane.rs:1857, 1932` (system-of-record events) | Re-reads the existing mandate or revocation, then returns 409 when `conflict.message.contains("different content")` | Depends on the exact wording of an error message. Rewording the message would silently turn a 409 into a 422. |
| `kavach-api/src/agents.rs:319`, `state_changes.rs:702` | `Rejected` and `Invalid` both become "the agent's state changed or the change is invalid" (409) | Deliberately merged. No harm, but nothing distinguishes the cases. |
| `authorize.rs:567` (`still_authorised`), `authorize.rs:625` (decide) | Every non-`Unavailable` failure becomes `mandate_revoked` or `mandate_invalid` | Meaning B cannot come from a mandate verification. No change is needed. |
| `gateway.rs:431, 478` | `Rejected` from the resolver or broker becomes `no_destination` or `credential_refused` | Meaning A only. No change is needed. |
| `kavach-mandate/src/service.rs:705` | A JWS `Rejected` is collapsed into `UNTRUSTED_ISSUER` | Meaning A only. No change is needed. |

**What L17 hides.** `recover_stuck_allows` signs an `unknown` outcome (`AuthorizeCore::record_outcome`, `authorize.rs:339`) and writes it. A `Rejected` can come from three places:
1. **Meaning B, expected.** The call itself, or another reconciler pass, wrote the outcome after `stuck_allows` was read. `a_second_replica_recovering_the_same_allow_loses_cleanly` (`kavach-dataplane/tests/gateway_faults.rs:778`) covers this case.
2. **Meaning A: "no allowed record for this credential".** The stored record's hash for that credential differs from the hash of the record the reconciler holds, or no such row exists. Evidence rows are append-only, so this points to a store fault or tampering. It is exactly the signal that should not be dropped.
3. **Meaning A: the signer.** `sign_outcome` calls `EvidenceSigner::sign`. The HSM signer returns `Rejected` for "unknown signing key {kid}" (`kavach-keys-pkcs11/src/lib.rs:389`). The file-key signer never fails.

In cases 2 and 3 the pass reports nothing: `recovered` does not move and `problems` stays empty. The same allow is tried, and silently dropped, on every pass until it is older than `STUCK_OUTCOME_LOOKBACK`, when `beyond_lookback` counts it. It is never lost from the evidence: a bundle still reports it as `outcome_missing`. The gap is in the reconciler's signals, not in the chain.

## 4. Proposal

### 4.1 Names

Add a fourth class to `ErrorClass`:

| Class | Meaning | Default handling |
|---|---|---|
| `Unavailable` | Unchanged | Unchanged |
| `Rejected` | The dependency checked the request and said no; retrying gets the same answer. This includes replays. | Unchanged: `BLOCK` with a reason code |
| `Conflict` (new) | A write lost to an existing row with the same unique key, from this caller, another replica or another writer. The stored row decides what happens next. | Re-read the row. The same content is success; different content is a refusal (409 on the API). |
| `Invalid` | Unchanged | Unchanged |

`PortError::conflict(message)` is added alongside the existing constructors.

The criterion for `Conflict`: the store found an existing row for the key it was asked to write, so a re-read can show what is there. Anything else stays `Rejected`, replays included.

**Names considered:**
- `AlreadyExists`: accurate, but long in match arms.
- `Exists`: reads poorly as an error class.
- `Duplicate`: suggests the content is the same, which is often not true.

`Conflict` matches the HTTP status the API already returns for the different-content case.

**Not proposed:** separate classes for "same content" and "different content". The stores that can compare content cheaply already return `Ok` for the same content (`append_revocation` and `append_agent_state` return the stored record). For the rest, the caller re-reads, as the gateway already does.

### 4.2 Code changes, in order

1. **Ports** (`kavach-ports/src/error.rs`): add the variant and the constructor, and update the port docs that name `Rejected` for a meaning-B case (`agent_evidence.rs:510, 568, 587`, `mandate.rs:265, 273`).
2. **Producers** (the table in section 2, meaning B): the memory and Postgres stores for agent evidence and mandates, and the `service.rs` different-content checks. Nothing else changes class.
3. **Consumers.** Adding a variant breaks every exhaustive `match` on `ErrorClass` at compile time, which lists the sites for review:
   - `outcome_reconciler.rs:175` (the L17 fix): treat `Conflict` as "written meanwhile; nothing to do". Push `Rejected` into `report.problems` as `recovering an outcome: …`.
   - `gateway.rs:377`: re-read on `Conflict` instead of `Rejected`. A `Rejected` is returned as is.
   - `kavach-api/src/dataplane.rs:1857, 1932`: decide the 409 on `Conflict` from `existing_for_event` and `existing_revocation`, not on the message text. `event_refusal` maps `Conflict` to the same 409 response returned today.
   - `agents.rs:319`, `state_changes.rs:702`: `Rejected | Conflict | Invalid` map to the same refusal as today.
   - `authorize.rs:567, 625`, `gateway.rs:431, 478`: `Conflict` maps to the same value as `Rejected` (`MandateGone`, `mandate_invalid`, `no_destination`, `credential_refused`). It cannot occur on these paths, and treating it as a refusal is the fail-closed choice.
4. **ADR-006 §3**: add the `Conflict` row to the table, as an amendment dated with the owner's go.

### 4.3 Narrower alternative: fix L17 only

Leave `ErrorClass` alone. In `recover_stuck_allows`, on `Rejected`, re-read `core.outcome(credential_id)`, as `record_outcome_retrying` does:
- If an outcome is stored, it was written meanwhile: nothing to do.
- If none is stored, push the error into `problems`.

This changes one function, with no port or API change. It fixes L17's effect but not the cause: the message-text match in `dataplane.rs` and the overloaded test-kit contract stay as they are.

**Recommendation:**
- First the narrow fix (4.3), as its own small PR, because it closes the reconciler signal gap without touching the ports.
- Then the split (4.1 and 4.2) as a separate PR, if the owner wants the message-text match removed and the class to say what it means.

Both are second-review changes.

## 5. Wire, evidence and storage compatibility

The rule this proposal depends on is that **no value written outside the process changes**. Checked one by one:

| Surface | Derived from `ErrorClass`? | Change |
|---|---|---|
| Agent evidence records, outcomes, checkpoints, bundles (EVIDENCE_BUNDLE.md, bundle format version 2) | Only through the outcome `reason` codes (`no_destination`, `credential_refused`, …) and decision reasons (`mandate_invalid`, `dependency_unavailable`) | None. `Conflict` maps to the codes `Rejected` maps to (4.2, step 3). Outcome reasons are a free `[a-z0-9_]{1,64}` code, not a list the verifiers check, so even a new code would not break the format. None is proposed. |
| `DecisionEvent` (credit track; [DECISION_EVENT_COMPAT.md](../DECISION_EVENT_COMPAT.md)) | No | None. No field changes, and no `schema_version` bump is needed. |
| HTTP problem types and statuses (`docs/openapi.yaml`): `event_rejected` 422, the different-content 409, the agent-state 409 | Yes | None. Each is mapped as today. The SoR 409 now rests on the class rather than the message text, so the result is the same with less risk. |
| Admin audit log: `stop_agent_refused` with `why: "refused"` (`agents.rs:129–133`) | Yes, through `CHANGED` | None |
| Metric labels, for example `result="refused"` on the agent-state metric | Yes, through `CHANGED` | None |
| Postgres schema | No: no column stores an `ErrorClass` | None |
| Log lines | `PortError`'s `Display` is `"{class:?}: {message}"` | Meaning-B lines read `Conflict: …` instead of `Rejected: …`. Logs are not a contract, and nothing in `deploy/monitoring` matches on these strings (checked with `grep -rn Rejected deploy/`). |

**Migration:** none. No stored data changes, and no database migration is needed.

**Mixed versions:** none to handle. `ErrorClass` does not cross a process boundary: the API, batch and CLI each map it locally. A deployment running the old and new binaries side by side (not supported today; single instance) would still write the same codes.

**What would make it a breaking change:** choosing to expose the split, for example a new problem type `event_conflict`, a new audit `why`, or a new outcome reason code. That is not proposed. If the owner wants it later:
- A new API problem type is an openapi change.
- A new reason code is a vocabulary addition that verifiers accept.
- Neither changes the bundle or `DecisionEvent` format.

## 6. Tests

Each item below should fail when the change it covers is reverted.

1. **L17, refusal reported.** In `kavach-dataplane/tests/gateway_faults.rs`, a stuck allow whose `record_outcome` returns a meaning-A refusal must give `problems.len() == 1` and `recovered == 0`. Two variants:
   - The first uses a test-kit store fault that returns `Rejected` (a new option in `kavach-ports-testkit/src/faulty_store.rs`; today `Faults::hit` returns only `Unavailable`).
   - The second uses a signer that refuses.
   Today both pass silently with an empty `problems`, so the test fails before the fix.
2. **L17, lost race still clean.** `a_second_replica_recovering_the_same_allow_loses_cleanly` must keep passing unchanged.
3. **Test-kit contracts, both stores** (memory and Postgres):
   - The concurrency losers in `one_outcome_per_credential_under_concurrency` are `Conflict`.
   - `append_revocation` and `append_agent_state` with other content are `Conflict`.
   - `record_outcome` with no matching record is `Rejected`.
   - A replayed identifier is `Rejected`.
   - The mandate-store tests for an existing mandate and a reused event are `Conflict`.
4. **Gateway retry.** In `record_outcome_retrying`, an `Unavailable` followed by `Conflict` with the same stored outcome returns `Ok`. A first-attempt `Conflict` with a different stored outcome returns the error.
5. **API, unchanged wire.**
   - A system-of-record event reused with different content returns 409.
   - A revocation event recorded with other content returns 409.
   - A refused event returns 422 `event_rejected`.
   - A refused agent-state change returns 409 with `why: "refused"` in the audit log.
   Existing tests that pin these must pass without edits. Any test that needed an edit would show a wire change.
6. **Evidence unchanged.** The bundle and checkpoint test vectors (`kavach-ports/tests/vectors`) and the conformance agreement tests (`kavach-evidence-cli/tests/agreement_generator.rs`, `conformance/kavach_verify.py`) must pass with no regenerated vectors.

## 7. For the owner

1. Go or no-go for the narrow L17 fix (4.3) as its own PR.
2. Go or no-go for the split (4.1 and 4.2), and the name: `Conflict`, or one of the alternatives in 4.1.
3. Confirm that no wire or evidence surface should expose the split for now (section 5, "What would make it a breaking change").
4. Who does the second review: this touches the dataplane, the mandate service and the evidence stores.
