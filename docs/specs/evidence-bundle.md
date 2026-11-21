# Evidence bundle, versions 1 to 5 (normative)

This document defines the evidence a Kavach deployment writes and exactly what a verifier checks. It is self-contained: an implementer needs nothing else. [`docs/EVIDENCE_BUNDLE.md`](../EVIDENCE_BUNDLE.md) explains how an operator uses it.

Conventions are in [README.md](README.md). A verifier written from this text is in [`conformance/`](../../conformance/README.md).

## 1. What it proves and does not prove

A verifier that returns *verified* shows only this: the records, outcomes and checkpoints in the bundle are internally consistent, were signed by the keys the operator trusts, and (given a checkpoint the operator kept elsewhere) match what the deployment attested at that time. It does **not** show that the deployment made the right decisions, that nothing happened outside the chain, or that the records are not newer than the newest kept checkpoint. See [SECURITY_PROPERTIES.md](../SECURITY_PROPERTIES.md).

## 2. Encoding

### 2.1 JSON
- Every file line is one JSON value (RFC 8259) in UTF-8, ended by a line feed (`0x0A`). The last line is ended too. A line is at most 1,048,576 bytes.
- A JSON object MUST NOT repeat a member name. A verifier MUST refuse a line that does.
- A line MUST NOT hold a member this specification does not define for it: a record the members of §4.1 and its kind's section (and, inside `time_sync`, `actor` and `policy_versions`, only theirs), an outcome those of §5, a checkpoint those of §6, a resolution those of §5.3. A verifier MUST refuse a line that does, as unreadable (`read`, §10.3), before any hash or signature is checked. A record's extra member would be inside its hash, but an outcome's or a checkpoint's is outside every hash and signature: unsigned data that rides through an audit trail. The rule is one explicit list per file and record kind, not a comparison of the line with what a reader makes of it.
- A file with no lines is empty (zero bytes).

### 2.2 Canonical form
Hashes are taken over the **canonical form** (RFC 8785, JCS) of a JSON value. The bytes of a stored line need not be canonical.

For the values in this document:
- **Numbers** are integers with absolute value at most 2^53 − 1. A verifier MUST refuse any other number.
- **Strings** are escaped as RFC 8785 requires: `"` and `\` are escaped, the control characters U+0008, U+0009, U+000A, U+000C, U+000D as `\b \t \n \f \r`, the rest below U+0020 as `\u00xx` in lowercase hex, and every other character literally in UTF-8 (including `/`, U+007F and non-ASCII).
- **Object members** are sorted by their names as sequences of UTF-16 code units. No whitespace appears.

A verifier MUST compute every hash over the value **as received**: it MUST NOT add, drop or reorder members, and members it does not know are part of the value and of the hash.

### 2.3 Times
A time is a string `YYYY-MM-DDTHH:MM:SS[.f]Z` (UTC, `Z` suffix, at most nine fractional digits as received). Kavach writes at most six. Where a time is part of a signed *message* (outcomes, §5.2) it is rendered with **exactly six** fractional digits, whatever its text in the JSON.

### 2.4 Identifiers
- A **hash** is 64 lowercase hex characters (a SHA-256 value).
- A **signature** is 128 lowercase hex characters (an Ed25519 signature).
- **Genesis** is 64 `0` characters. It is the `prev_hash` of the first record and the `prev_checkpoint_hash` of the first checkpoint.

## 3. The bundle

A bundle is a directory holding exactly these regular files and nothing else: four in versions 1 to 3, five in versions 4 and 5.

| File | Contents | Versions |
|---|---|---|
| `manifest.json` | One JSON object (§7): what the bundle is and the SHA-256 of the other files | 1 to 5 |
| `records.jsonl` | The segment's records (§4), in `seq` order, one per line | 1 to 5 |
| `outcomes.jsonl` | Outcomes (§5), in the order of their records, one per line | 1 to 5 |
| `checkpoints.jsonl` | Checkpoints (§6) from the segment's start, in `seq` order, one per line | 1 to 5 |
| `resolutions.jsonl` | Resolutions (§5.3) of `unknown` outcomes, one per line; empty when there are none | 4 and 5 |

A `resolutions.jsonl` in a bundle of version 1, 2 or 3 is a layout failure, and so is a version 4 or 5 bundle without one: a resolution is never accepted inside a format that did not define it, and never skipped.

The `manifest.json` file is one JSON value, followed by an optional line feed.

A bundle holds **no keys**. The verifier is given trusted public keys by the operator (§8), kept apart from the bundle.

## 4. Records

A record is a JSON object. Its **payload** is the record without its `hash` and `sig` members.

```
hash = hex( SHA-256( "kavach-evidence-v2" || ASCII(payload.prev_hash) || JCS(payload) ) )
sig  = hex( Ed25519_sign( evidence_key, "kavach-agent-evidence-sig-v1:" || ASCII(hash) ) )
```

`||` is plain concatenation of bytes, with no separator. `ASCII(x)` is the 64 characters of `x` as bytes.

### 4.1 Members every record has

| Member | Type | Meaning |
|---|---|---|
| `kind` | string | The record kind (§4.2). Inside the signed payload, so a record cannot be passed off as another kind |
| `record_id` | string | An identifier of the record |
| `tenant_id` | string | Tenant. MUST equal the manifest's |
| `partition_id` | integer | Partition. MUST equal the manifest's |
| `seq` | integer ≥ 1 | Position in the chain |
| `prev_hash` | hash | `hash` of the record before it; genesis for the first record of a chain |
| `hash_alg` | string | MUST be `v2` |
| `key_id` | string | The evidence key that signed it. Inside the payload, so a signature cannot be paired with another key id |
| `time_sync` | object | `{ "status": string, "max_error_ms": integer or null }`. `status` is `synced`, `unsynced`, `unknown` or `dev_fixed` |
| `hash`, `sig` | | As above; not part of the payload |

### 4.2 Kinds (the registry)

| `kind` | Defined in | Bundle versions |
|---|---|---|
| `agent_decision` | §4.3 | 1 to 5 |
| `mandate_revocation` | §4.4 | 2 to 5 |
| `agent_state` | §4.5 | 3 to 5 |
| `model_invocation` | §4.6 | 5 |
| `model_outcome` | §4.7 | 5 |

**A verifier MUST refuse a record whose `kind` is not in the registry for the bundle's version, and MUST NOT skip it.** A bundle of version 1 may hold `agent_decision` records only, and a bundle of version 2 `agent_decision` and `mandate_revocation` records only. Version 3 adds `agent_state`, version 4 adds resolutions, and version 5 adds the model evidence records. A verifier that does not know a record kind fails rather than misreading it.

### 4.3 `agent_decision`

An agent's request and the decision on it. Members besides §4.1 (all are part of the hash; a verifier needs only the ones used in §9):

| Member | Type | Used by a verifier for |
|---|---|---|
| `credential_id` | string or null | Linking the record to its outcome (§5). Present only on an allow |
| `returned_decision` | string | `PASS` and `ALERT` are allows; `BLOCK` and `HUMAN_REVIEW` are not |
| `credential_expires_at` | time or null | When an allow's credential expired (§9.6) |
| `ts` | time | When it was decided |

Other members (`actor`, `chain`, `mandate_id`, `purpose`, `consent_refs`, `action`, `request_id`, `subject_pseudonym`, `params_mac`, `policy_versions`, `signals`, `pre_commit_decision`, `policy_decision`, `obligations`, `send_by`) describe the decision (ADR-005 §4). A verifier hashes them and need not interpret them.

### 4.4 `mandate_revocation`

Mandates revoked by a system-of-record event (ADR-012 §7).

| Member | Meaning |
|---|---|
| `source_system`, `event_id`, `event_type` | The event (`loan.paid`, `loan.disputed`) |
| `event_digest` | The event's digest: `sha256-jcs-v1:` followed by 64 lowercase hex characters, the SHA-256 of the event's RFC 8785 bytes (the payload of the signed token; [mandate-and-sor-event.md](mandate-and-sor-event.md) section 5) |
| `event_sha256` | **Legacy.** 64 lowercase hex characters. Written before `event_digest`; the digest of the event's members in the order of a Rust struct, which a second implementation cannot reproduce from this specification. Never written now; read and verified as an ordinary member |
| `record_pseudonym` | A keyed pseudonym of the loan. A bundle never holds the loan reference |
| `occurred_at` | When the event says it happened |
| `revoked` | The mandate ids revoked (an array of strings) |
| `revoked_at` | When Kavach revoked them |
| `recorded_at` | When this record was written. Used as the record's time in §8.2 |

A record MUST state **exactly one** of `event_digest` and `event_sha256`, well formed as above. A record with both, neither, a tag other than `sha256-jcs-v1:`, or hex that is short or upper case is refused (§9), even if its hash and signature are genuine. A bundle verifier cannot recompute either digest (it does not hold the event); it checks the form and that the signature covers it.

### 4.5 `agent_state`

A change of an agent's state (ADR-013 §4): an agent was restricted, quarantined, revoked or reinstated. Members besides §4.1:

| Member | Type | Meaning |
|---|---|---|
| `agent_id` | string | The agent whose state changed. A record names the agent, never a borrower |
| `change_no` | integer | 1 for the agent's first change, then 2, 3, …. With `tenant_id` and `agent_id` it identifies the change; a chain holds at most one record for it |
| `from_state`, `to_state` | string | One of `active`, `restricted`, `quarantined`, `revoked`. Different from each other |
| `reason_code` | string | One of `rogue_behaviour`, `compromise_suspected`, `policy_violation`, `customer_complaint`, `operator_request`, `reviewed`, `other`. A closed set: the chain never holds an operator's free text, which could name a borrower and cannot be erased |
| `reason_digest` | string or `null` | `mac:` and 64 lowercase hex: a keyed digest of the operator's free text, which is kept outside the chain; `null` when there was none. A verifier cannot recompute it (it does not hold the key or the text); it checks the form |
| `changed_by` | string | The principal who made the change |
| `change_request_id` | string, optional | The change request (ADR-009) that carried out a loosening, 1 to 128 characters without control characters. **Absent** for an operator's stop, and MUST be absent from a tightening. Written only when present, so a record without it hashes as it always did |
| `approved_by` | string or `null` | The second principal. Present, and different from `changed_by`, **exactly when the change loosens** |
| `changed_at` | time | When the state changed |
| `recorded_at` | time | When this record was written: later than `changed_at` when it was written after the fact. Used as the record's time in §8.2 |

Severity orders the states `active` < `restricted` < `quarantined` < `revoked`. A change **tightens** when `to_state` is more severe than `from_state` and **loosens** when it is less severe. A verifier MUST refuse (§9) a record that breaks any of these, even if its hash and signature are genuine:

- `change_no` is at least 1;
- `from_state` differs from `to_state`, and `from_state` is not `revoked` (a revoked agent is never changed);
- `reason_code` is in the set above, and `reason_digest` is `null` or well formed;
- a tightening has `approved_by` `null`, and a loosening has an `approved_by` that is not empty and not equal to `changed_by`.

A stop is written **after** it takes effect (so stopping never waits on the chain), so a record's `recorded_at` can be later than `changed_at` and its position in the chain later than decisions made after the stop. That is why the record carries `changed_at`.

### 4.6 `model_invocation` (version 5)

Signed authorization evidence written before a governed local model call. It proves which agent, mandate, role, action and prompt digest were authorized; it does not prove the model's semantic correctness.

Besides §4.1, it has: `actor` (`agent_id`, `identity_key`); `mandate_chain`; `mandate_id`; `action`; `request_id`; `subject_pseudonym`; `model_role` (`collections` or `translation`); `model_digest` (`sha256:` plus 64 lowercase hex); `prompt_digest` (64 lowercase hex); `policy_versions`; `policy_decision`; `returned_decision`; `signals`; and `recorded_at` (the record time). An authorized or policy-evaluated request has a non-empty mandate chain ending in `mandate_id`. If mandate verification fails before a chain is available, an empty chain is valid only when both decisions are `BLOCK` and `signals` contains `mandate_invalid` or `dependency_unavailable`; this records the refused attempt without implying that its mandate was verified.

`collections` MUST use `invoke_collections_model`; `translation` MUST use `invoke_translation_model`. The prompt and completion are transient and MUST NOT be included in the record.

### 4.7 `model_outcome` (version 5)

Signed outcome metadata linked to the prior invocation by `invocation_record_id` and its signed `invocation_hash`. It also has `agent_id`, `request_id`, `status`, `response_digest`, `duration_ms`, and `recorded_at`. `duration_ms` is an integer in the range 0 to 4,294,967,295.

`status` is `completed`, `failed` or `unknown`. A completed record MUST carry `response_digest`, a SHA-256 hash in 64 lowercase hex. A failed or unknown record MUST carry `response_digest: null`. An ambiguous timeout is `unknown`; it MUST NOT trigger an automatic retry under the same request ID. Response text and error text are never evidence fields.

When the corresponding invocation is in the same bundle segment, a verifier MUST check that the tenant, agent, request ID, invocation record ID and invocation hash match. A segment may begin after that invocation; in that case the signed outcome alone cannot establish the earlier invocation's contents.

## 5. Outcomes

What happened after an allow. An outcome is a JSON object, **off the chain**:

| Member | Type | Meaning |
|---|---|---|
| `tenant_id` | string | MUST equal the manifest's |
| `credential_id` | string | The `credential_id` of the record it belongs to |
| `record_hash` | hash | The `hash` of that record |
| `outcome` | string | `delivered`, `failed`, `refused`, `not_executed` or `unknown` |
| `reason` | string, optional | `[a-z0-9_]{1,64}`. Absent only on outcomes written before reason codes existed |
| `ts` | time | When it was recorded |
| `key_id` | string | The evidence key that signed it |
| `sig` | signature | See §5.2 |

### 5.1 Meaning
`delivered`, `failed`, `refused` and `not_executed` are final. For an agent delivery outcome, `unknown` means the request was sent and its result is not known; it is never retried. In versions 1 to 3 nothing can settle it. In versions 4 and 5 a **resolution** (§5.3) may, without changing the outcome. This is separate from the `model_outcome` record status in §4.7.

### 5.2 Signature
Let `T` be `ts` rendered per §2.3 with exactly six fractional digits (for example `2026-10-02T05:30:12.000000Z`). The signed message is the concatenation of the prefix and the body:

| When | Prefix | Body (lines joined by `0x0A`, no final line feed) |
|---|---|---|
| `reason` is present | `kavach-agent-outcome-sig-v2:` | `credential_id`, `record_hash`, `outcome`, `reason`, `T` |
| `reason` is absent | `kavach-agent-outcome-sig-v1:` | `credential_id`, `record_hash`, `outcome`, `T` |

`sig = hex( Ed25519_sign( evidence_key, message ) )`. An outcome whose `reason` is present but not of the form above MUST be refused.

### 5.3 Resolutions (versions 4 and 5)

A resolution is a second signed row that refers to an `unknown` outcome. It never replaces the outcome (which stays as written) and it never causes anything to be sent. A resolution is a JSON object, **off the chain**, with exactly these members; a member not listed here makes the line invalid, so that nothing unsigned can ride along:

| Member | Type | Meaning |
|---|---|---|
| `tenant_id` | string | MUST equal the manifest's |
| `credential_id` | string | The `credential_id` of the outcome it resolves |
| `outcome_ref` | hash | The outcome it resolves: the SHA-256, in lowercase hex, of the **text** of that outcome's `sig` member (its 128 hex characters, as ASCII) |
| `state` | string | `confirmed_delivered`, `confirmed_not_delivered` or `ambiguous` |
| `source` | string | `provider_status`, `operator_attested`, `conflict_resolution` or `reconciler` |
| `reason` | string | `[a-z0-9_]{1,64}`: a code, never a value |
| `evidence_digest` | hash, optional | The SHA-256 of the provider's answer or of the operator's reference; never the thing itself |
| `resolved_by` | string, optional | The identity (source-qualified key) of the person who attested or proposed, 1 to 128 characters without control characters |
| `approved_by` | string, optional | The identity of the different person who approved |
| `ts` | time | When it was recorded |
| `key_id` | string | The evidence key that signed it |
| `sig` | signature | See §5.3.1 |

**§5.3.1 Signature.** Let `T` be `ts` rendered per §2.3 with exactly six fractional digits. The signed message is the prefix `kavach-outcome-resolution-sig-v1:` followed by these ten values joined by `0x0A` (no final line feed): `tenant_id`, `credential_id`, `outcome_ref`, `state`, `source`, `reason`, then `evidence_digest`, `resolved_by` and `approved_by`, each written as `none` when absent and `some:` followed by the value when present (so an absent member is never confused with a value), then `T`. `sig = hex( Ed25519_sign( evidence_key, message ) )`.

**§5.3.2 Form.** Who may say what. A line that breaks any of these is invalid:

| `source` | `state` allowed | `evidence_digest` | `resolved_by` | `approved_by` |
|---|---|---|---|---|
| `reconciler` | `ambiguous` only | absent | absent | absent |
| `provider_status` | `confirmed_delivered` or `confirmed_not_delivered` | present | absent | absent |
| `operator_attested` | `confirmed_delivered` | present | present | **absent** (one person) |
| `operator_attested` | `confirmed_not_delivered` | present | present | **present and different** from `resolved_by` (two people) |
| `conflict_resolution` | `confirmed_delivered` or `confirmed_not_delivered` | present | present | **present and different** |

`ambiguous` is the reconciler's statement and nobody else's: a line with that state from any other source is invalid. "Different" is a comparison of the whole strings. Where `approved_by` and `resolved_by` are both required, a line without both, or with equal ones, is invalid.

**§5.3.3 The governing state.** What a bundle says about an `unknown` outcome is computed from **all** its resolutions, never from the latest:

1. Take the distinct states among the `conflict_resolution` lines. If there is exactly one, **that state governs**. If there are two, the outcome is **conflicted**.
2. Otherwise take the distinct *confirmed* states (`confirmed_delivered`, `confirmed_not_delivered`) among all the lines. If there is none, the outcome is **ambiguous** when any line is `ambiguous` and **unresolved** when there are no lines. If there is one, it governs; its stated source is `provider_status` if any line with that state has it, otherwise `operator_attested`. If there are two, the outcome is **conflicted**.
3. An `ambiguous` line never overrides a confirmed state, whenever it was written.

## 6. Checkpoints

A signed statement: "record `seq` of this chain has hash `head_hash`". One JSON object per line.

| Member | Type | Meaning |
|---|---|---|
| `kind` | string | MUST be `evidence_checkpoint` |
| `version` | integer | MUST be `1` |
| `tenant_id`, `partition_id` | | MUST equal the manifest's |
| `chain` | string | MUST equal the manifest's (`agent_decisions`) |
| `seq` | integer ≥ 1 | The newest record covered |
| `head_hash` | hash | `hash` of record `seq` |
| `prev_checkpoint_hash` | hash | `hash` of the previous checkpoint of this chain; genesis for the first |
| `key_id` | string | The checkpoint key |
| `time_sync` | object | As §4.1 |
| `ts` | time | Trusted time |
| `hash`, `sig` | | Not part of the payload |

```
hash = hex( SHA-256( "kavach-evidence-checkpoint-v1" || JCS(payload) ) )
sig  = hex( Ed25519_sign( checkpoint_key, "kavach-evidence-checkpoint-v1:" || ASCII(hash) ) )
```

There is **no** `prev_hash` here: a checkpoint's hash covers the canonical payload only.

## 7. The manifest

| Member | Type | Meaning |
|---|---|---|
| `format` | string | MUST be `kavach-evidence-bundle` |
| `version` | integer | `1` to `5`. A verifier MUST refuse any other. An export writes `5` |
| `tenant_id`, `partition_id`, `chain` | | The chain the segment belongs to |
| `segment` | object | `after_seq` (integer ≥ 0), `after_hash` (hash), `last_seq` (integer ≥ `after_seq`), `head_hash` (hash) |
| `files` | object | `records`, `outcomes`, `checkpoints` and, in versions 4 and 5, `resolutions`, each `{ "sha256": hash, "count": integer ≥ 0 }`. A `resolutions` member in a manifest of version 1 to 3, or its absence in version 4 or 5, is refused |
| `exported_at` | time | The exporter's own clock. Not trusted time |
| `exporter` | object | `tool`, `version` (strings) |
| `key_id` | string | The export key. **Absent** on an unsigned bundle |
| `hash`, `sig` | | Not part of the payload. `sig` is **absent** on an unsigned bundle |

```
hash = hex( SHA-256( "kavach-evidence-bundle-v1" || JCS(payload) ) )
sig  = hex( Ed25519_sign( export_key, "kavach-evidence-bundle-v1:" || ASCII(hash) ) )
```

The prefixes say `v1` in both bundle versions: they name the manifest hashing scheme, which did not change.

Constraints:
- `segment.after_seq = 0` ⇔ `segment.after_hash` is genesis.
- `files.records.count` = `segment.last_seq − segment.after_seq`.
- An empty segment (`last_seq = after_seq`) has `head_hash = after_hash`.
- `key_id` and `sig` are both present or both absent.
- A `key_id` MUST start with `export-` (or `dev-export-` on a development stack).

## 8. Trust

### 8.1 Keys
The operator supplies a JSON file:

```json
{ "keys": [ { "kid": "kavach-evidence-1", "alg": "Ed25519", "public_key": "<64 hex>" } ] }
```

`alg` MUST be `Ed25519` and `public_key` the 32-byte public key in hex. A verifier selects a key by the `key_id` a record, outcome, checkpoint or manifest names. An unknown `key_id` is a failure.

**Development keys.** A `key_id` starting with `dev-` is refused, and so is any record or checkpoint whose `time_sync.status` is `dev_fixed`, unless the verifier was told it is verifying a development stack.

### 8.2 Limits
An entry may carry limits for a retired or compromised key:

| Member | Meaning |
|---|---|
| `valid_until_seq` | Something this key signed for a record with `seq` greater than this is refused, **unless** a kept checkpoint (§9.9) has `seq` at least that large |
| `not_before`, `not_after` | Something this key signed with a time `ts` such that `ts < not_before` or `ts >= not_after` is refused |

The `seq` and time used are: for a record, its `seq` and its `ts` (`recorded_at` for a `mandate_revocation` or an `agent_state`); for an outcome, its record's `seq` and its `ts`; for a checkpoint, its `seq` and `ts`; for the manifest, `segment.last_seq` and `exported_at`. A signature beyond a limit fails verification.

## 9. Verification

A verifier is given the bundle directory, the trusted keys, optionally a kept checkpoint, whether it is verifying a development stack, and a reference time `now` for §9.6 (default: the verifier's clock, never the bundle's `exported_at`).

1. **Layout.** The directory holds exactly the files of §3 for the manifest's `version` (four in versions 1 to 3, five in versions 4 and 5), as regular files. The keys file is not inside it.
2. **Manifest.** Parse it. Refuse an unknown `format` or `version`, a member that breaks §7, or a count that does not match the segment.
3. **Manifest hash and signature.** Recompute `hash`. If signed: the `key_id` is an export key, a `dev-` key only when development is allowed, and `sig` verifies. If unsigned, report `unsigned`.
4. **Files.** For each file the manifest lists (three, or four in versions 4 and 5): the SHA-256 of its bytes equals `files.<name>.sha256`, and its number of lines equals `files.<name>.count`.
5. **Records.** In file order, starting with `expected_seq = after_seq + 1` and `prev = after_hash`, for each line:
   1. Parse it; refuse duplicate member names (§2.1).
   2. `tenant_id` and `partition_id` equal the manifest's.
   3. `kind` is in the registry for the manifest's `version` (§4.2). For `model_outcome`, if the matching invocation appears earlier in this segment, the tenant, agent, request ID, invocation record ID and invocation hash MUST match. If the segment begins after the invocation, the segment cannot verify the earlier record.
   4. Unless development is allowed: `key_id` does not start with `dev-` and `time_sync.status` is not `dev_fixed`.
   5. `hash_alg` is `v2`; `seq` equals `expected_seq`; `prev_hash` equals `prev`.
   6. `hash` recomputes (§4) and `sig` verifies with the key `key_id` names.
   7. Key limits (§8.2) hold.
   8. Set `prev` to `hash` and increment `expected_seq`.

   After the last record, `prev` equals `segment.head_hash`, and `expected_seq − 1` equals `segment.last_seq`.
6. **Outcomes.** Go through the records in order. For each `agent_decision` whose `credential_id` is not null: if the next unread outcome has that `credential_id`, consume it, and then:
   1. its `tenant_id` equals the manifest's and its `record_hash` equals the record's `hash`;
   2. unless development is allowed, its `key_id` does not start with `dev-`;
   3. its `reason`, if present, is well formed (§5), and its `sig` verifies (§5.2) with the key `key_id` names;
   4. key limits hold.

   If the next outcome is for another record, this record has no outcome. If it is an allow (`returned_decision` `PASS` or `ALERT`) and its `credential_expires_at` is null or at or before `now`, report `outcome_missing` with its `credential_id`. After all records, **no outcome may remain**: a remaining or out-of-order or repeated outcome fails the bundle. For each consumed outcome of `unknown`: in versions 1 to 3, report `outcome_unknown`; in versions 4 and 5, apply step 6a first and report by the governing state (§5.3.3): `outcome_unknown` when it is *unresolved* or *ambiguous*, `outcome_conflicted` when it is *conflicted*, and nothing when a confirmed state governs (the verifier SHOULD list those as resolved, with the state and its source).

   **6a. Resolutions (versions 4 and 5).** For each line of `resolutions.jsonl`, in file order:
   1. Parse it; refuse duplicate member names (§2.1) and any member not listed in §5.3.
   2. `tenant_id` equals the manifest's.
   3. It refers to an outcome of this bundle: an outcome with its `credential_id` whose `outcome` is `unknown`, and whose `sig` hashes to `outcome_ref` (§5.3). Otherwise the bundle fails: a resolution of a settled outcome, of another row, or of an outcome that is not in the bundle is not accepted.
   4. Its form holds (§5.3.2) and its `reason` is well formed.
   5. Unless development is allowed, its `key_id` does not start with `dev-`; its `sig` verifies (§5.3.1) with the key `key_id` names; key limits (§8.2) hold.
   6. Its `ts` is not before the outcome's `ts`.
   7. No two lines have the same `credential_id`, `source` and `state`.

   A bundle of version 1 to 3 has no step 6a and refuses a resolutions file at step 1.
7. **Checkpoints.** For each, in file order: `kind` and `version` are as §6; tenant, partition and chain equal the manifest's; unless development is allowed the key is not `dev-` and `time_sync.status` is not `dev_fixed`; `hash` recomputes and `sig` verifies; key limits hold; `seq` is greater than the previous checkpoint's, and `prev_checkpoint_hash` equals the previous checkpoint's `hash` (genesis for the first, **when the segment starts at the first record**). Then compare with the records:
   - `seq` at most `after_seq`: if equal, `head_hash` MUST equal `segment.after_hash`; if less, it is not compared.
   - `seq` within the segment: `head_hash` MUST equal that record's `hash`. A different hash means the chain was rewritten.
   - `seq` greater than `last_seq`: the records were removed. The bundle fails.
   - A checkpoint whose `ts` is before the previous checkpoint's is reported `clock_stepped_back`, not failed.
8. **The segment's start is never trusted on its own.** When `after_seq` is not `0`, a checkpoint with `seq = after_seq` and `head_hash = after_hash` MUST be among the bundle's checkpoints or be the kept checkpoint. Otherwise the bundle fails.
9. **A kept checkpoint**, if given, is one checkpoint object kept by the operator outside the deployment. It MUST verify as §7 does (its tenant, partition and chain match). If its `seq` is within the segment its `head_hash` MUST equal that record's `hash`. If the segment ends before its `seq`, the bundle fails (records were removed). If its `seq` is at most `last_seq` and above `after_seq`, and the bundle has checkpoints covering that `seq`, it MUST be among them.
10. **Coverage.** Let `covered` be the largest `seq` of a verified checkpoint within the segment, or `after_seq` if none. If `last_seq − covered` is greater than zero, report `uncovered_records` with that count.
11. If no kept checkpoint was given, report `no_kept_checkpoint`.

### 9.1 Results

The findings `outcome_missing`, `outcome_unknown` and `outcome_conflicted` are about individual credentials, so there can be a great many. A verifier MAY report each of the three **once**, with the exact number of credentials and some of their `credential_id`s (the Rust verifier does, to bound its output), or once per credential (the Python verifier does). What must agree is the count: the number of credentials reported for each kind. The generated-history test (`tests/agreement_generator.rs`) compares those counts.

| Result | Meaning |
|---|---|
| **fail** | Any refusal above. The bundle does not verify |
| **verified, with warnings** | It verifies, but something is not protected: the reports `unsigned`, `no_kept_checkpoint`, `uncovered_records`, `outcome_missing`, `outcome_unknown`, `outcome_conflicted` (versions 4 and 5), `clock_stepped_back` |
| **verified** | It verifies and none of those apply |

A script that tests only for success MUST treat *verified, with warnings* as not verified, unless it names the warning it accepts.

## 10. Test vectors

| Vector | Expected result |
|---|---|
| `crates/kavach-evidence-cli/tests/vectors/bundle-v3` with `bundle-v2.keys.json` | Verified, with warnings: `no_kept_checkpoint`, `outcome_missing` (`cred-4`), `outcome_unknown` (`cred-3`). Seven records: four decisions, the revocation (by `event_digest`), then a quarantine of `collections-agent` (record 6, a tightening, with a `reason_digest`) and its reinstatement (record 7, a loosening approved by `ops-kat-2`). Three checkpoints, the last covering record 7 |
| `crates/kavach-evidence-cli/tests/vectors/bundle-v2-digest` with `bundle-v2.keys.json` | The same run with the revocation stating its event by `event_digest`. Same warnings as `bundle-v2` |
| `crates/kavach-evidence-cli/tests/vectors/bundle-v2` with `bundle-v2.keys.json` | Verified, with warnings: `no_kept_checkpoint`, `outcome_missing` (`cred-4`), `outcome_unknown` (`cred-3`). Five records, two outcomes, three checkpoints, the last covering record 5, so no uncovered records |
| `crates/kavach-evidence-cli/tests/vectors/bundle-v1` with `bundle-v1.keys.json` | Verified, with warnings: `no_kept_checkpoint`, `outcome_missing` (`cred-4`), `outcome_unknown` (`cred-3`), and `uncovered_records` = 1 (four records; the last checkpoint covers record 3). Both keys files hold test-only keys that are not `dev-` keys, so no `--dev` flag is needed |
| `crates/kavach-ports/tests/vectors/jcs-v1.json` | Canonicalization (§2.2) |
| `crates/kavach-ports/tests/vectors/checkpoint-v1.json` | Checkpoint hash and signature (§6) |

The verifier's reference time for the table above is `2026-10-02T07:00:00Z` or later (every credential in the run has expired by then).

Version 4 vectors (`crates/kavach-evidence-cli/tests/vectors/bundle-v4`, with `bundle-v2.keys.json`) are listed in §10.1 below.

A verifier MUST also refuse, at least: a changed byte in any file; a record of an unknown kind; a `mandate_revocation` in a bundle of `version` 1; an `agent_state` in a bundle of `version` 1 or 2; an `agent_state` record that breaks §4.5; a removed or repeated record; a removed or repeated outcome; a checkpoint at a different hash; a signature by a key that is not trusted; a duplicate member name.

### 10.1 Version 4 vectors

`bundle-v4` has seven records and three checkpoints, three outcomes (`cred-1` settled; `cred-3` and `cred-4` both `unknown`) and three resolutions in `resolutions.jsonl`:

| Outcome | Resolutions | Governing state (§5.3.3) | Report |
|---|---|---|---|
| `cred-3` | a `provider_status` `confirmed_delivered` | `confirmed_delivered` from `provider_status` | none (counted as resolved) |
| `cred-4` | a `provider_status` `confirmed_delivered` and an `operator_attested` `confirmed_not_delivered` (two people) | conflicted | `outcome_conflicted` |

The expected result is *verified, with warnings*: `no_kept_checkpoint` and `outcome_conflicted` (`cred-4`), with no `outcome_unknown` and no `outcome_missing`.

Refusal vectors for version 4, each a bundle (or a line) that MUST fail, for the reason named: a `resolutions.jsonl` inside a version 3 bundle (layout); a version 4 manifest without a `resolutions` file entry (layout); a resolution of a settled outcome; with an `outcome_ref` that does not match; for a credential with no outcome; with a member not in §5.3; "not delivered" attested by one person; "not delivered" approved by the same person; the reconciler stating a confirmed state; a conflict closed by one person; a duplicate `(credential_id, source, state)`; a `ts` before its outcome's; a forged `sig`; a `dev-` key without development allowed.

### 10.2 Version 5 vector

`crates/kavach-evidence-cli/tests/vectors/bundle-v5` contains a signed `model_invocation` followed by a signed linked `model_outcome`, plus a checkpoint covering the segment. Both Rust and independent Python verifiers MUST accept it. They MUST refuse its model record kinds under bundle version 4, and refuse an outcome whose invocation hash does not match an earlier invocation in the same segment.

### 10.3 Failure classes

Two verifiers that both refuse a bundle can still disagree about *why*, and then one of them is wrong about what it checked. So a verifier that reports a failure SHOULD report one of these classes besides its reason (the reference verifiers do: `VerifyError::class()` and the `class` member of the Python verifier's JSON), and the two MUST report the same class for the same damage. The wording of the reason is free; the class is not.

| Class | Meaning |
|---|---|
| `input` | The operator's inputs are unusable: the trusted keys file (or one inside the bundle), the kept checkpoint, an unreadable file |
| `layout` | The directory is not laid out as §3 for the manifest's version (a file missing, extra, or not a regular file; a resolutions file in a version 1 to 3 bundle; a manifest that is not JSON) |
| `manifest` | The manifest breaks §7 or its hash or signature does not verify (steps 2 and 3) |
| `digest` | A file's SHA-256 or line count does not match the manifest (step 4) |
| `read` | A line does not parse as the shape its file requires: not JSON or not UTF-8, a repeated or unknown member, a record of a kind not in the registry (§4.2) |
| `chain` | A record breaks step 5: sequence, link, hash, signature, head, tenant or partition, development key or clock |
| `outcome` | An outcome breaks step 6 |
| `resolution` | A resolution breaks step 6a |
| `checkpoint` | A checkpoint breaks §6 or step 7 |
| `segment` | The segment is not vouched for, or differs from the kept checkpoint |
| `key_validity` | A trusted key signed beyond the limits the operator set for it (§8.2) |

The classes follow the order of §9: a verifier reports the class of the **first** step that fails, so a bundle damaged in several ways is classed by the earliest one. In particular the manifest (steps 2 and 3) is checked before the file digests (step 4), so an edited manifest is `manifest`, not `digest`. The agreement test (`crates/kavach-cli/tests/cli.rs`) requires both verifiers to report the expected class for each damaged copy.
