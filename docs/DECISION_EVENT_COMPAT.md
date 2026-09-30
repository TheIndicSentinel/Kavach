# DecisionEvent Schema Compatibility

**Policy:** Additive-only evolution within a major `schema_version`.

## Rules

1. Every `DecisionEvent` includes required `schema_version` (semver string, e.g. `1.0.0`).
2. Minor/patch: new optional fields only. Consumers must ignore unknown fields.
3. Major: breaking change → new major version; support N and N-1 in API for one release.
4. Never rename or change type of existing fields without a major bump.
5. Golden tests pin expected `schema_version`.

## Behaviour notes (no schema change)

- **Pack-effective selection uses trusted server time** (ADR-003 §8, M1.2). `decision_time` remains required, is validated against server time (±300 s by default) and is still recorded in `decision_time`; `evaluated_at` is the server time used for the decision. A pack whose `effective_from` is after server time is not effective even if the client's `decision_time` is later.

## Current version

`1.0.0` — initial frozen schema (Phase 0).
