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

## Current version

`1.0.0` — initial frozen schema (Phase 0).
