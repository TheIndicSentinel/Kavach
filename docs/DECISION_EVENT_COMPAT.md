# DecisionEvent Schema Compatibility

**Policy:** Additive-only evolution within a major `schema_version`.

## Rules

1. Every `DecisionEvent` includes required `schema_version` (semver string, e.g. `1.0.0`).
2. Minor/patch: new optional fields only. Consumers must ignore unknown fields.
3. Major: breaking change → new major version; support N and N-1 in API for one release.
4. Never rename or change type of existing fields without a major bump.
5. Golden tests pin expected `schema_version`.

## Current version

`1.0.0` — initial frozen schema (Phase 0).
