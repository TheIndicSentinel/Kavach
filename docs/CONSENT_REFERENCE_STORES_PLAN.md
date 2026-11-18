# Consent and reference stores — proposed pilot plan

**Status:** Proposed; implementation choices below require owner approval before runtime or schema changes.
**Scope:** The next pilot blocker in `AGENTS.md`; PRD D7/FR-8, ADR-004 §5/§7 and ADR-006 §4. Tier 1 remains one tenant per stack (ADR-014). This plan uses local Postgres and file-held keys, with no paid service dependency.

## Current boundary

- `ConsentSource` reads a startup JSON fixture. `ConsentRecord` has a tenant, subject reference, purposes, expiry and active flag. Mandate issuance checks active status, subject, purpose and expiry.
- `ReferenceResolver` reads a startup JSON fixture and accepts synthetic destinations only. The gateway resolves after authorization and never returns the destination to the agent.
- A pilot needs live changes and real destinations. Reading files once at startup cannot enforce a later withdrawal or opt-out. Storing a real destination as plaintext would break the repo's privacy rule.

## Proposed implementation order

1. **Consent contract.** Define the local consent artefact subset and contact preferences without claiming to implement the full ReBIT API. Keep existing fixture fields readable. Add explicit validity start, information types, data date range and status; reject malformed intervals and unknown status values at load. The status used to authorize a mandate is derived from the stored record, never from an agent request.
2. **Persistent consent and preferences.** Add tenant-scoped Postgres records behind `ConsentSource` and a separate channel opt-out lookup. A missing, expired, withdrawn or unreadable required record fails closed. An opt-out blocks contact on that channel. Use immutable change history plus a current-state projection, and test tenant separation and concurrent withdrawal against issuance and execution.
3. **Signed updates.** Accept consent grants, withdrawals and preference changes only from an authenticated, tenant-bound system-of-record source. A withdrawal revokes affected mandates through the existing revocation path. Replayed update IDs are idempotent; conflicting payloads are refused. Fixture loading remains available for local development only.
4. **Encrypted reference vault.** Store tenant/subject/channel indexes separately from AES-256-GCM encrypted destinations. Bind ciphertext to tenant, subject reference, channel, version and key id as authenticated data. Use a dedicated owner-readable local key file initially, with an adapter boundary for HSM/KMS. Reject a missing or unknown key; never log or return plaintext outside the gateway's existing `Destination` type. Keep keys available for live ciphertext during rotation, and document retirement and restore steps.
5. **Gateway wiring.** Select persistent adapters at startup for pilot mode. Resolve only after the existing authorization and current consent/preference checks. Keep fixture adapters limited to explicit development mode. Run memory/Postgres port conformance, fault tests, migration tests and a live withdrawal/opt-out acceptance path before enabling real destinations.

## Decisions to approve

1. **Authority for updates (recommended):** signed, tenant-bound system-of-record events; no direct operator edit of consent or destination values.
2. **Reference encryption (recommended):** a dedicated local AES-256-GCM key file and explicit decrypt-only previous keys, following the review-snapshot key rotation pattern. No reuse of the review-snapshot key.
3. **Missing contact preference (recommended):** fail closed for outbound contact until the authoritative source has supplied a current preference record. This is stricter than the current fixture behavior and requires seeding for pilots.

After approval, the first code slice is the backward-compatible consent contract and fixture validation. Persistent stores and gateway selection follow in separate reviewed commits. Security claims, migration guidance and acceptance status change with the slice that changes their guarantees.

## References

- [PRD](PRD.md) D7 and FR-8; [ADR-004](ADR-004-task-mandate-format.md) §5/§7; [ADR-006](ADR-006-ports-and-adapters.md) §4; [ADR-014](ADR-014-tenancy-tiers.md) §2/§3.
- [ReBIT Account Aggregator API specifications](https://api.rebit.org.in/spec/aa) for the source format; the local subset and its authorization semantics are specified by Kavach, not by the external API.
