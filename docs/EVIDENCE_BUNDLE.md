# Evidence checkpoints and bundles

How Kavach's agent evidence is checkpointed, exported and verified offline. The decisions are in [ADR-005](ADR-005-evidence-v2.md) §13.

## Status

| Part | Status |
|---|---|
| Checkpoint format v1 and its verification logic (library, test vectors) | Done (E1) |
| Segment verification: a chain checked from a checkpoint instead of from the first record | Done (E1) |
| Checkpoint storage: append-only table, one unforked line of checkpoints per chain | Done (E2a) |
| Writing checkpoints in a running deployment (background writer, mandatory key, metrics, stall alert) | Done (E2b) |
| Bundle format v1: manifest, writer, export key rules, test vector; read-only `kavach_auditor` database role | Done (E3a) |
| Export command (`kavach-evidence export`, `checkpoints`) | Done (E3b) |
| `verify-bundle` command (offline, fail-closed, constant memory) | Done (E4a) |
| Export and verify from a deployed stack in CI (the required isolation job) | Done (E4b) |
| Detecting a deleted outcome row | Not yet (E5, only if a benchmark shows the lock is cheap) |

With a checkpoint kept off-host, `kavach-evidence verify-bundle --expect-checkpoint` detects a chain that was cut short or rewritten, also by someone who holds the database and the keys. Without a kept checkpoint it cannot, and it says so. The exact property and its conditions are in [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md).

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

## How checkpoints are written

- A background task in the API process checks once a second. It writes a checkpoint when records are uncovered and either 1,000 of them have accumulated or they have been uncovered for the interval (default 60 seconds). The record count is checked by polling, so a busy system can pass 1,000 before the next check.
- It reads the chain head without taking the commit lock, and never blocks or fails a decision.
- Several replicas may run it. The store keeps one line of checkpoints: a replica that loses the race writes nothing and reads the winner's checkpoint on its next check.
- The checkpoint is dated by trusted time, under the same clock-error bound as decisions. If trusted time is unavailable the checkpoint is skipped and counted; it is never dated by a guess.
- If records stay uncovered past the stall threshold (default 10 minutes), an alert is logged and shown in `/v1/runtime` and the metrics. `/health` and decisions are unaffected.
- The task is restarted if it ever exits, and a panic is logged.
- The server has no graceful shutdown yet, so no final checkpoint is written when it stops. Records written after the last checkpoint are covered after the next start.
- The checkpoint key is separate from every other key by id and from the evidence key by material. By default it sits in a directory beside the other keys, so the separation only becomes a real boundary when keys move to a KMS or HSM.

## Bundle format, version 1

A bundle is one export of one chain segment. It is a directory with exactly four files; the names are fixed, and a manifest never names a path.

| File | Contents |
|---|---|
| `manifest.json` | What the bundle is, the segment it covers and the SHA-256 of the other three files |
| `records.jsonl` | The segment's Agent Decision Records, one JSON object per line, in `seq` order |
| `outcomes.jsonl` | The outcomes of those records, one per line, in the order of their records |
| `checkpoints.jsonl` | The checkpoints from the segment's start, one per line, in `seq` order |

A bundle contains **no public keys**. A verifier gets its keys from the operator (see "Trusted keys").

**What is in a bundle.** Agent, mandate and request identifiers, decisions, signals, reason codes, times, a keyed pseudonym of the subject and a keyed MAC of the parameters. It holds no destination (phone number) and no raw subject reference; a test fails the build if either reaches a bundle. It is still evidence about people's cases: the writer creates the directory and files readable by their owner only, and a bundle should be stored and shared accordingly.

### Manifest

| Field | Type | Meaning |
|---|---|---|
| `format` | string | `kavach-evidence-bundle` |
| `version` | integer | `1`. A verifier refuses a version it does not know. |
| `tenant_id`, `partition_id`, `chain` | | The chain, as in a checkpoint |
| `segment.after_seq` | integer ≥ 0 | The record the segment follows; `0` when it starts at the first record |
| `segment.after_hash` | 64 lowercase hex | Hash of that record; 64 zeros when `after_seq` is `0` |
| `segment.last_seq` | integer | The newest record in the bundle; equals `after_seq` when the segment is empty |
| `segment.head_hash` | 64 lowercase hex | Hash of record `last_seq` |
| `files.records`, `files.outcomes`, `files.checkpoints` | object | `sha256` (lowercase hex of the file's bytes) and `count` (its number of lines) |
| `exported_at` | string | RFC 3339 UTC, at most microseconds. The exporter's own clock, not trusted time |
| `exporter` | object | `tool` and `version` |
| `key_id` | string | The export key. Absent on an unsigned bundle |
| `hash` | 64 lowercase hex | See below; not part of the hashed content |
| `sig` | 128 hex | See below; not part of the hashed content. Absent on an unsigned bundle |

`files.records.count` always equals `last_seq − after_seq`.

**Hash.** Remove `hash` and `sig`, serialise the rest with RFC 8785 (JCS), then:

```
hash = lowercase_hex( SHA-256( "kavach-evidence-bundle-v1" || canonical_json ) )
```

**Signature.** Ed25519 with the export key:

```
sig = hex( Ed25519_sign( "kavach-evidence-bundle-v1:" || hash_as_ASCII ) )
```

### Why the manifest is signed, and by whom

Records and checkpoints carry their own signatures, so an unsigned manifest cannot hide a forged record. Outcomes are different: each row is signed, but nothing signs them as a set, so a missing outcome cannot be seen from the rows. The manifest signature closes that gap for the bundle: it states "this is what the exporter saw", including how many outcomes there were and the digest of the file that holds them.

- The **export key** belongs to whoever runs the export (an auditor or operator) and lives with them, **not on the API host**.
- Its key id must start with `export-` (`dev-export-` for a development key). A manifest signed under any other key id is refused, even if the operator's key list contains it. The API refuses to start with a mandate, evidence, checkpoint or credential key whose id starts with `export-`. So one key can never do both jobs.
- Signing is the default. A bundle is unsigned only when the exporter asks for it explicitly, and a verifier must report an unsigned bundle as such.

### Records, outcomes and checkpoints

Each line is the JSON of one object, as stored: an Agent Decision Record or an outcome (ADR-005 §12), or a checkpoint (above). Lines end with a line feed; the last line too. A verifier parses each line and checks its hash and signature from its content, so the bytes of a line need not be canonical, but the file's bytes must match the digest in the manifest.

### Trusted keys

The operator gives the verifier a JSON file of public keys, kept apart from any bundle:

```json
{ "keys": [ { "kid": "kavach-evidence-1", "alg": "Ed25519", "public_key": "<64 hex>" } ] }
```

It lists the evidence key, the checkpoint key and the export key (and earlier ones after a rotation).

### Verifying a bundle

```sh
kavach-evidence verify-bundle ./bundle-2026-10-02 \
  --keys ~/kavach-trusted-keys.json \
  --expect-checkpoint /mnt/offsite/kavach-checkpoints.jsonl
```

It needs no database and no network, and reads the files as streams, so its memory use does not grow with the chain.

**Three results, three exit statuses.**

| Exit | Meaning |
|---|---|
| `0` | Verified, and nothing is left unprotected |
| `2` | Verified, **but something is not protected** (listed first in the report). This is a failure unless `--allow-warnings` is given, which makes it exit `0` |
| `1` | Does not verify, or could not be read |

The verifier fails closed: a script that only tests for a non-zero status treats a warning as a failure. What counts as "not protected":

| Kind | Meaning |
|---|---|
| `unsigned` | The manifest is unsigned: a removed outcome would not be noticed |
| `no_kept_checkpoint` | No `--expect-checkpoint`: a chain cut short or rewritten by someone holding the keys would not be noticed |
| `uncovered_records` | Records newer than the last checkpoint (or no checkpoint at all) |
| `outcome_missing` | Allows whose credential has expired with no recorded outcome |
| `outcome_unknown` | Outcomes recorded as `unknown` (sent, result not known) |
| `clock_stepped_back` | A checkpoint dated before the one preceding it |

Other options: `--json` (the same report for programs), `--at <time>` (the reference time for "expired"; the default is now, never the bundle's own `exported_at`), `--dev` (accept `dev-` keys: a development stack).

**The first export.** Until a checkpoint has been kept off-host there is nothing to compare a chain with, so the first verification of a deployment's evidence reports `no_kept_checkpoint` and exits `2`. Nothing that happened before that moment can be checked against an earlier state; this is where protection starts.

```sh
# 1. Keep the newest checkpoint off-host. This is the anchor from now on.
kavach-evidence checkpoints --latest >> /mnt/offsite/kavach-checkpoints.jsonl

# 2. Export, and verify once with warnings allowed. Read the report:
#    `no_kept_checkpoint` should be the only thing listed as not protected.
kavach-evidence export --out ./bundle-first --key-dir … --key-id export-…
kavach-evidence verify-bundle ./bundle-first --keys ~/kavach-trusted-keys.json --allow-warnings

# 3. Every later verification names the kept file, without --allow-warnings.
kavach-evidence verify-bundle ./bundle-next --keys ~/kavach-trusted-keys.json \
  --expect-checkpoint /mnt/offsite/kavach-checkpoints.jsonl
```

- `--allow-warnings` accepts every kind of warning, so do not leave it in a scheduled job. A script that must accept exactly one kind can read `--json` and compare `not_protected[].kind` with what it expects.
- Keep appending the newest checkpoint on a schedule (step 1). A verification is only as recent as the last line of that file: records newer than it are reported as uncovered or are simply not compared.
- A bundle older than the kept checkpoint fails with "records after it were removed". That is correct for a chain, and expected for an old bundle: verify old bundles with the checkpoint that was newest when they were exported.

**The steps.**

1. The directory holds exactly the four files, as plain files. The keys file must not be inside it.
2. Read `manifest.json`. Refuse an unknown `format` or `version`, bounds out of order, or a record count that does not match the segment.
3. Recompute `hash`. If the manifest is signed: refuse a `key_id` that is not an export key, refuse a `dev-` key unless verifying a development stack, and verify `sig` with the operator's key. If it is unsigned, report it. `key_id` without `sig`, or the reverse, is malformed.
4. For each of the three files: its SHA-256 and line count match the manifest. No line is longer than a megabyte.
5. Records: `seq` runs from `after_seq + 1` to `last_seq`; each links to the one before (the first to `after_hash`); each hash and signature verifies; the last hash is `head_hash`.
6. Outcomes, in the order of their records: each belongs to the record whose credential it names (same tenant, that record's hash) and its signature verifies. An outcome that belongs to no record of the segment, is out of order, is repeated or does not verify fails the bundle. Allows whose credential has expired with no outcome are reported.
7. Checkpoints, in `seq` order: as in "Verifying checkpoints". A checkpoint newer than the newest record means records were removed.
8. **A segment's start is never trusted on its own.** When `after_seq` is not `0`, a checkpoint at `after_seq` naming `after_hash` must be in the bundle, or be the kept checkpoint. Otherwise the bundle fails.
9. With a kept checkpoint (one JSON object, or the last line of a file of them): it must verify; the record at its `seq` must have its hash; if the chain ends before it, records were removed; and when the bundle's checkpoints cover its `seq` it must be among them.

## Exporting

```sh
export KAVACH_AUDITOR_DATABASE_URL='postgres://kavach_auditor:…@db.internal:5432/kavach'

# The whole chain, signed with the exporter's own key.
kavach-evidence export --out ./bundle-2026-10-02 --key-dir ~/kavach-export-keys --key-id export-asha-1

# Only what follows the checkpoint at record 12000.
kavach-evidence export --out ./bundle-next --after-checkpoint 12000 --key-dir … --key-id …

# Checkpoints to keep off-host: the newest, or all after a record.
kavach-evidence checkpoints --latest >> /mnt/offsite/kavach-checkpoints.jsonl
kavach-evidence checkpoints --after 12000
```

- **One snapshot.** Everything is read in one read-only `REPEATABLE READ` transaction, in pages: records, outcomes and checkpoints agree with each other, and a write made during the export is not in it.
- **A read-only role.** The command refuses a database role that could change the evidence (the API's own role, or the owner); use `kavach_auditor`. `--allow-write-role` overrides this for development stacks.
- **A whole bundle or nothing.** The target directory must not exist. If the stored evidence is not one consistent segment (records that do not link, a head that does not match, a checkpoint newer than the chain), the export fails and writes nothing.
- **Signing.** `--key-dir` and `--key-id` (an `export-` key, in an owner-only file) or, explicitly, `--unsigned`. One of the two must be given.
- **A segment** starts after an existing checkpoint (`--after-checkpoint <seq>`) and carries that checkpoint and the later ones.
- The export reports how many records are newer than the last checkpoint. It does not verify signatures; that is `verify-bundle`'s job.
- The database password is read from the environment and never printed. Connections to Postgres are not encrypted by this build, so run the export on the database's network.
- A build with `--no-default-features` leaves out `export` and `checkpoints`, and with them all database and network code; `verify` and `verify-bundle` remain.

## Test vectors

- **A bundle:** [`crates/kavach-evidence-cli/tests/vectors/bundle-v1/`](../crates/kavach-evidence-cli/tests/vectors/bundle-v1/) is a complete bundle of four records (one of them a block), two outcomes and two checkpoints, with its trusted keys in [`bundle-v1.keys.json`](../crates/kavach-evidence-cli/tests/vectors/bundle-v1.keys.json) beside it. Verifying it should report one allow with no outcome (`cred-4`), one outcome recorded as `unknown` (`cred-3`) and one record newer than the last checkpoint.
- **Checkpoints:** [`crates/kavach-ports/tests/vectors/checkpoint-v1.json`](../crates/kavach-ports/tests/vectors/checkpoint-v1.json) holds two linked checkpoints signed with a test-only key, the public key, the record hashes they cover and, for each checkpoint, the exact canonical bytes that were hashed. An independent implementation should reproduce `hash` from `canonical_payload` and verify `sig`.
