# DecisionEvent Schema Compatibility

**Policy:** Additive-only evolution within a major `schema_version`.

## Rules

1. Every `DecisionEvent` includes required `schema_version` (semver string, e.g. `1.0.0`).
2. Minor/patch: new optional fields only. Consumers must ignore unknown fields.
3. Major: breaking change → new major version; support N and N-1 in API for one release.
4. Never rename or change type of existing fields without a major bump.
5. Golden tests pin expected `schema_version`.

## Behaviour notes (no schema change)

- **`pack_id` is the loaded pack's id** (H1). Earlier releases wrote the model record's declared `pack_id`, which was wrong after activating a different pack. Consumers comparing `pack_id` to the model binding should expect them to differ when a non-default pack is active.
- **`POLICY_EVALUATION_ERROR`** may appear in `reason_codes` with `policy_decision: BLOCK` when a pack rule fails at runtime (H1).

- **Pack-effective selection uses trusted server time** (ADR-003 §8, M1.2). `decision_time` remains required, is validated against server time (±300 s by default) and is still recorded in `decision_time`; `evaluated_at` is the server time used for the decision. A pack whose `effective_from` is after server time is not effective even if the client's `decision_time` is later.

- **Schema 1.1.0: timestamps are kept at microsecond precision** (2026-10). `decision_time` and `evaluated_at` are truncated to whole microseconds, the precision Postgres stores, **before** the event is hashed. The hash rule is unchanged: `SHA256(prev_hash ‖ canonical payload)`, over the same fields in the same canonical order. What changed is the canonical form of these two values, so `schema_version` is `1.1.0`.
  - **Records at 1.1.0 or later must re-verify exactly.** Any mismatch means the record was changed.
  - **Records before 1.1.0** were hashed over nanoseconds. Wherever their nanoseconds survive (an export written from memory, any JSON copy), they still verify under the same rule, and chains that mix them with 1.1.0 records verify. Nothing is re-fingerprinted.
  - **Read back from Postgres, a pre-1.1.0 record cannot be re-checked**: its nanoseconds were never stored. If its hash fails and its timestamps are whole microseconds, verifiers report it as **legacy precision: cannot be re-checked**. That is a warning (exit 2), never "verified", and it is also not proof of tampering. A record that was changed as well would look the same, which is why it is never passed. A pre-1.1.0 mismatch that precision cannot explain (timestamps that still carry nanoseconds) is reported as tampering.
  - **No downgrade.** A pre-1.1.0 record after a 1.1.0 record in the same chain is refused.
  - **Pre-alpha pilots should re-baseline:** export the existing chain, then start a fresh one. Chains that began before 1.1.0 can't be fully re-checked from Postgres.
  - **Anyone computing these hashes independently** must truncate both timestamps to microseconds first.

## Current version

`1.1.0` — timestamps hashed at microsecond precision (2026-10). Previous: `1.0.0`, the initial frozen schema (Phase 0).
