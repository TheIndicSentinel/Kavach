# ADR-005: Evidence v2 — Partitioned Chains, Signing, Crypto-Shredding and Tenancy Migration

**Status:** Accepted  
**Date:** 2026-09-29  
**Deciders:** Kavach product/engineering  
**Related:** ADR-001 (fail-closed evidence), ADR-002 (requires a new ADR before changing the evidence chain), ADR-003, ADR-004, ADR-006, [PRD](PRD.md) D9, FR-7, FR-14, NFR-3, NFR-4; PRD open question 5

## Context

The current evidence implementation (Milestones A/B) works for single-tenant Decision Governance but cannot carry the MVP's agent evidence requirements or scale without rework:

- **One global chain.** A singleton row `evidence_chain_meta (id = 1, head_hash)` is locked `FOR UPDATE` on every append (`crates/kavach-storage/src/postgres/evidence.rs:31-139`), serialising all writes.
- **No sequence numbers.** Order comes only from `prev_hash` links plus `created_at`; IDs are random UUIDv4.
- **No signatures or key management** anywhere in the evidence path.
- **Non-canonical hashing.** `hash = SHA-256(prev_hash_hex ‖ serde_json(HashPayload))` (`crates/kavach-evidence/src/canonical.rs`, `chain.rs`) depends on Rust struct field order and chrono's formatting — not a cross-language canonical form.
- **Redaction breaks verification.** Tombstoned/redacted exports blank hashed fields (`tombstone.rs`), so recomputed hashes cannot match.
- **Verify CLI** (`kavach-evidence verify`) only walks from genesis; no segments or checkpoints.
- **Migrations** are embedded SQL split naively on `;` with no tracking table (`postgres/migrate.rs:18-33`).
- **No `tenant_id`** in any table; `tenant_settings` and `runtime_pointers` are singletons.
- **Compatibility tension:** `DECISION_EVENT_COMPAT.md` says consumers ignore unknown fields, but `schemas/decision-event.schema.json` sets `additionalProperties: false` and `schema_version` as a `const`.

Existing partner-pilot consumers depend on the v1 `DecisionEvent` format and its hashes; those must not change.

## Decision

### 1. Tracked migrations

Adopt `sqlx` migrations (MIT/Apache-2.0) with a tracking table. The existing `001`–`004` scripts become the recorded baseline unchanged; all new schema changes are additive, numbered migrations.

### 2. Tenancy

Add `tenant_id TEXT NOT NULL DEFAULT 'default'` to every table. Singleton tables (`evidence_chain_meta`, `runtime_pointers`, `tenant_settings`) are re-keyed by `tenant_id`. The MVP runs one tenant (`default`); no code path assumes a single tenant.

### 3. Partitioned chains

- New table `evidence_chains (tenant_id, partition_id, head_hash, head_seq)`.
- Evidence records gain `tenant_id`, `partition_id`, `seq` with `UNIQUE (tenant_id, partition_id, seq)`.
- An append locks **only its own partition row**, so partitions append in parallel.
- The existing chain becomes partition `('default', 0)`. `seq` is backfilled by walking `prev_hash` links from genesis. **Existing hashes are never recomputed.**
- The MVP uses one partition; adding partitions is configuration, not code.

### 4. Record kinds on one chain

| Kind | Format | Hash algorithm |
|---|---|---|
| `decision_event` | v1 `DecisionEvent`, unchanged | `v1` — existing struct-order serde payload (partner compatibility) |
| `agent_decision` | Agent Decision Record v1 | `v2` — SHA-256 over a domain-separation prefix `kavach-evidence-v2` ‖ `prev_hash` ‖ RFC 8785 (JCS) canonical payload |
| `governance_event` | Governance Event v1 (§11) | `v2` |

Every record carries `kind` and `hash_alg`. Records of all kinds link into the same partition chain through `prev_hash`.

`policy_versions.packs` identifies each pack by `id`, `version` **and `sha256`** (digest of the pack file bytes), so every agent decision is bound to the exact rules that produced it. v1 `decision_event` records keep identifying packs by label only (partner compatibility); an auditor links them to pack bytes through the governance events in §11.

Agent Decision Record v1 fields: `record_id, tenant_id, partition_id, seq, prev_hash, kind, hash_alg, actor, chain[], mandate_id, purpose, consent_refs, action, resource_ref_ct (ciphertext, §7), params_hash, policy_versions {cedar, cel, packs}, signals[], policy_decision, returned_decision, obligations[], approval_ref?, credential_id?, time_sync, ts, hash, sig`.

### 5. Signing and checkpoints

- Each `agent_decision` record is signed individually (Ed25519, key from `KeyProvider`, ADR-006).
- Per-partition **signed checkpoints** are written to `evidence_checkpoints (tenant_id, partition_id, seq, head_hash, ts, sig)` every 1,000 records or 60 seconds, whichever comes first. Checkpoints cover v1 `decision_event` records, which are not individually signed.
- A signed Merkle root over the latest checkpoint of every partition gives a single tenant-wide root. It can optionally be published through the `EvidenceAnchor` port (off by default; PRD D6).

### 6. Two-phase write for critical actions

- **Phase 1 (synchronous):** the minimal, signed Agent Decision Record is appended in the same transaction as the partition head update, **before** any credential is issued (PRD FR-7). If Phase 1 fails, the ADR-001 fail-closed matrix applies (enforce → `BLOCK`).
- **Phase 2 (asynchronous):** enrichment (detector detail, rendered approval view, timings) is stored in `evidence_enrichments (record_id, payload, sig)` — signed and integrity-protected, but not part of the chain.
- Low-risk actions may batch Phase 1 writes asynchronously, per the risk policy.

### 7. Crypto-shredding instead of redaction

- Subject references in agent records are stored as AEAD ciphertext (`resource_ref_ct`) under a per-(tenant, subject) data key.
- Data keys live in `subject_keys`, wrapped by a tenant key-encryption key from `KeyProvider`.
- The record hash covers the ciphertext, so destroying a subject's key makes the reference unreadable while the chain still verifies.
- Erasure destroys the key and appends a tombstone record to the chain.
- **v1 records:** existing redacted exports are documented as "link-verified only" — the verifier checks `prev_hash` links but cannot recompute hashes of redacted rows.

### 8. Retention

Records are never deleted from the middle of a chain. Segments older than the retention period (set per pack; 6 months for recovery records) are archived as a unit ending at a signed checkpoint, and verification of the live chain restarts from that checkpoint.

### 9. Compatibility fix

- **Producer schemas** stay strict for each exact version (`additionalProperties: false`), used to validate what Kavach emits.
- **Consumer schemas** are published separately with `additionalProperties: true`, honouring the "ignore unknown fields" rule in `DECISION_EVENT_COMPAT.md`.
- `DECISION_EVENT_COMPAT.md` is updated to state this split and to document the new `kind`, `hash_alg`, `tenant_id`, `partition_id` and `seq` fields as additive.

### 10. Offline verifier

The verify CLI is extended to:

- verify both kinds and both hash algorithms;
- verify record signatures and checkpoint signatures against a supplied public-key set;
- verify a segment starting from a signed checkpoint (not only from genesis);
- verify the tenant-wide Merkle root;
- run fully offline.

### 11. Governance events on the chain

Pack activation, rollback and model-record changes are appended to the tenant's chain as `governance_event` records (actor, approver, action, pack/model identifiers and digests), signed like agent records. This makes changes to the runtime pointer row tamper-evident: the pointer row in Postgres is a cache of the latest governance event, not an independent source of truth.

### 12. Amendment (H5a-3b): first agent records

The first Agent Decision Records ship ahead of the full evidence v2, with these deliberate deviations until M2:

- **Own chain.** Agent records chain in `agent_decisions` with a head per `(tenant, partition)` in `agent_evidence_chains`. They are **not** linked into the v1 `decision_events` chain, so there is no single tenant chain yet. The merge (one chain, `kind`/`hash_alg` per record) is M2. `kind`, `hash_alg`, `partition_id`, `seq` and the v2 hash already follow §3–§4, so the merge needs no rehashing.
- **Pseudonym instead of ciphertext.** `subject_pseudonym` is an HMAC of the subject reference under a tenant-bound key derived from one 32-byte secret. A second derived key produces `params_mac`, so raw identifiers are never hashed unkeyed (low-entropy values like phone numbers would be reversible).
  - A tenant-wide key **cannot shred one subject**. Destroying it unlinks every subject, and an auditor can only recompute a pseudonym for a known reference.
  - Per-subject crypto-shredding (§7) remains M2.
  - The same pseudonym keys the daily contact counter, so the raw reference is never stored.
  - Rotating the secret changes every pseudonym and resets the day's counters, so rotate only at IST midnight (dual-key rotation is M2).
- **Signatures.**
  - Each record is signed with a dedicated evidence key over `kavach-agent-evidence-sig-v1:` ‖ hash. `key_id` is inside the hashed payload.
  - The evidence key signs nothing else, and is held in memory, not read from disk per record.
- **One commit transaction (phase 1):** lock the partition head, then (allow only, lock order head → counter) re-check trusted time against `send_by` and reserve a contact slot, then build, sign, append and advance the head.
  - A lost cap race or a passed deadline becomes `BLOCK` (`contact_cap_reached`, `window_closed`, `trusted_time_unavailable`) before the record is built. The record shows `pre_commit_decision` and the final decision.
  - A converted allow carries no `credential_id`.
  - The `credential_id` (`jti`) is allocated before the commit and recorded with the allow.
- **Idempotency.** `(tenant, agent, mode, request_id)` is unique and bound to the action, `params_mac`, subject pseudonym and mandate. A retry returns the stored record; other content under the same id is a conflict.
- **Pre-checks are not on the chain.** They authorise nothing and would let an agent load the partition lock; they are counted in metrics only. Denied commit attempts are recorded.
- **Outcomes** are signed rows in `agent_outcomes`, linked by `credential_id` and record hash, written once and off-chain:
  - `delivered`; `refused` (the provider refused: provably not delivered); `failed` (the connection failed before anything was sent); `not_executed` (allowed, but nothing was sent: resolver or broker failure, or `send_by` passed before forwarding); `unknown` (sent, result not known: timeout or loss after sending, 408, 5xx, a `jti` conflict; never retried).
  - Each carries a **reason code** (`[a-z0-9_]{1,64}`, e.g. `provider_409`, `timeout_after_send`, `send_by_passed`), signed under `kavach-agent-outcome-sig-v2:`. Rows written before H5b have no reason and verify under v1; a v1 row cannot gain a reason without failing verification.
  - The verifier reports three lists: *outcome missing* (an allow past its credential lifetime with no valid outcome, e.g. a crash between commit and forward), *outcome unknown* (recorded `unknown`) and *outcome invalid* (a signature that does not verify; that allow also counts as missing). A deleted outcome row shows up as missing. Reconciliation of missing and unknown outcomes against provider records is a P1 follow-up.
  - **Forward-once ownership:** only the call that created a record (`Committed`, `Decided::created()`) may forward; replays, including concurrent duplicates, never do.
- **Verification limits.** Without an out-of-band head (`expected_head`), truncating the chain tail is undetectable. Someone holding both the database and the evidence key can rewrite history until signed checkpoints and anchoring (§5, M2).
- **Throughput.** One partition serialises every agent commit; this is the NFR-2 ceiling of the MVP configuration, and adding partitions is configuration.

## Consequences

- Appends scale by partition; the global serialisation point is removed.
- Partner-pilot consumers see only additive fields; v1 hashes are untouched.
- The PRD requirement "no raw personal data on the chain" is met by construction for agent records.
- This ADR satisfies ADR-002's requirement for a new ADR before the evidence chain changes.
- Key management becomes a hard dependency: loss of the tenant KEK makes subject references unreadable (by design for erasure; by accident is a disaster-recovery concern for Stage 2 HSM work).
- PRD open question 5 (tenant migration) is resolved here.

## References

- [PRD](PRD.md) D9, FR-7, FR-14, NFR-4; acceptance scenarios 10, 12, 13
- ADR-001 §5 (fail-closed matrix); ADR-002 (evidence chain change requires an ADR)
- `crates/kavach-storage/migrations/001_evidence.sql`, `crates/kavach-storage/src/postgres/evidence.rs`, `crates/kavach-storage/src/postgres/migrate.rs`
- `crates/kavach-evidence/src/{canonical.rs, chain.rs, verify.rs, tombstone.rs}`
- `schemas/decision-event.schema.json`, `docs/DECISION_EVENT_COMPAT.md`
- RFC 8785 (JSON Canonicalization Scheme), RFC 8032 (Ed25519)
