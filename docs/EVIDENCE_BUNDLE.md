# Evidence checkpoints and bundles

How Kavach's agent evidence is checkpointed, exported and verified offline. The decisions are in [ADR-005](ADR-005-evidence-v2.md) §13.

## Status

| Part | Status |
|---|---|
| Checkpoint format v1 and its verification logic (library, test vectors) | Done (E1) |
| Segment verification: a chain checked from a checkpoint instead of from the first record | Done (E1) |
| Checkpoint storage: append-only table, one unforked line of checkpoints per chain | Done (E2a) |
| Writing checkpoints in a running deployment | Not yet (E2b) |
| Export command and bundle layout | Not yet (E3) |
| `verify-bundle` command | Not yet (E4) |
| Detecting a deleted outcome row | Not yet (E5, only if a benchmark shows the lock is cheap) |

Until E2b ships, **no deployment writes checkpoints**, and the limits in [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md) are unchanged.

## What a checkpoint does and does not prove

A checkpoint is a signed statement: "record `seq` of this chain has hash `head_hash`".

- It is written by the same deployment that writes the records. Someone who holds both the database and the keys can rewrite the records and sign new checkpoints to match.
- **A checkpoint only helps once a copy has left the system.** A verifier given a checkpoint that was kept elsewhere detects a chain cut short or rewritten below that point.
- Operators should therefore **copy checkpoints off-host on a schedule**, to storage the deployment cannot write to. Anything newer than the last kept checkpoint is not protected against that attacker.

## Checkpoint format, version 1

One JSON object. In files, one object per line.

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `evidence_checkpoint` |
| `version` | integer | `1`. A verifier refuses a version it does not know. |
| `tenant_id` | string | Tenant |
| `partition_id` | integer | Partition of the chain |
| `chain` | string | `agent_decisions` |
| `seq` | integer ≥ 1 | The newest record covered |
| `head_hash` | 64 lowercase hex | Hash of record `seq` |
| `prev_checkpoint_hash` | 64 lowercase hex | `hash` of the previous checkpoint of this chain; 64 zeros for the first |
| `key_id` | string | The checkpoint key |
| `time_sync` | object | `status` (`synced`, `unsynced`, `unknown`) and `max_error_ms` (integer or null) |
| `ts` | string | Trusted time, RFC 3339 UTC, at most microseconds |
| `hash` | 64 lowercase hex | See below; not part of the hashed content |
| `sig` | 128 hex | See below; not part of the hashed content |

**Hash.** Remove `hash` and `sig`, serialise the rest with RFC 8785 (JCS), then:

```
hash = lowercase_hex( SHA-256( "kavach-evidence-checkpoint-v1" || canonical_json ) )
```

**Signature.** Ed25519 (RFC 8032) with the checkpoint key:

```
sig = hex( Ed25519_sign( "kavach-evidence-checkpoint-v1:" || hash_as_ASCII ) )
```

The checkpoint key is separate from the evidence key and signs nothing else. The prefixes differ from those of records and outcomes, so a signature of one kind is never valid as another.

## Verifying checkpoints

Given the records of a chain (or a segment of it), its checkpoints in `seq` order, and trusted public keys:

1. **Keys come from the operator, never from the material being verified.**
2. Each checkpoint: known `kind` and `version`; the expected tenant, partition and chain; `hash` recomputes; `sig` verifies with the key named by `key_id`.
3. A key id starting with `dev-` is refused unless a development stack is being verified.
4. `seq` strictly increases, and each `prev_checkpoint_hash` equals the previous checkpoint's `hash`. When the records start at the first record, the first checkpoint must have 64 zeros.
5. The record at each checkpoint's `seq` has hash `head_hash`.
   - A different hash: the chain was rewritten.
   - No such record because the chain ends earlier: records were removed.
   - Older than the segment being verified: counted, not compared.
6. Report how many records are newer than the last checkpoint. They are not covered by any checkpoint.
7. With a kept checkpoint: it must verify (step 2), pass step 5, and be among the supplied checkpoints whenever they cover its `seq`.

A checkpoint dated before the one preceding it is a warning (the clock stepped back), not an integrity failure.

## Test vectors

[`crates/kavach-ports/tests/vectors/checkpoint-v1.json`](../crates/kavach-ports/tests/vectors/checkpoint-v1.json) holds two linked checkpoints signed with a test-only key, the public key, the record hashes they cover and, for each checkpoint, the exact canonical bytes that were hashed. An independent implementation should reproduce `hash` from `canonical_payload` and verify `sig`.

## Bundle layout

Defined with the export command (E3). It will carry a format version from its first release.
