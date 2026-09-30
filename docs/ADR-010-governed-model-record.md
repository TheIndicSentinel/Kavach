# ADR-010: Governed Model Record

**Status:** Accepted  
**Date:** 2026-10-01  
**Deciders:** Kavach product/engineering  
**Related:** ADR-001, ADR-009, [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md)

## Context

Governance mode (shadow or enforce) decides whether Kavach's decision reaches the lender's flow (ADR-001). Until H3b the mode lived in the model YAML: an approved `update_model` change applied only in memory and was lost on restart, anyone who could edit the YAML could flip the mode by restarting, and `kavach-batch` read the YAML directly, so batch and API could run in different modes.

## Decision

### 1. One authority per fact

| Fact | Authority |
|---|---|
| Which model file is active | `runtime_pointers.model_path`, with its SHA-256 pinned in `runtime_pointers.model_sha256` |
| Fixed model fields (schema, purpose, origin, pack binding, …) | The pinned YAML |
| `status`, `governance_mode` | `model_state` (per `tenant_id`, `model_id`), written only by approved change requests |

Every runtime change — pack or model — advances the single `runtime_pointers.version`, so all change requests bind to one counter.

### 2. One effective model for API and batch

`kavach_storage::govern_model()` returns the pinned YAML with governed status and mode. The API and batch both use it; evidence and batch-job rows therefore record the governed mode. After the baseline, status and mode in the YAML are ignored, with a startup warning when they disagree.

### 3. Startup (Postgres)

- **First start:** the API records the pointer (pack and model, with digests) and the model's state from the YAML — each with insert-if-absent, so concurrent first starts record one baseline.
- **Later starts:** the model path and bytes must match the pin; otherwise startup is refused.
- **Upgrade from H3a:** if the pointer has no model digest yet, the API pins it. If the model has no governed state but the audit log holds an approved `update_model` whose status or mode differs from the YAML, the baseline is **refused** — an approved change must not silently revert. `--bootstrap-model` then restores the last approved values.
- **`--bootstrap-model`** (API, Postgres only, audited): re-pins a changed model **path and digest only**; it never changes status or mode.
- **Batch never writes governance state:** it refuses to run when nothing is governed yet, when the model file differs from the pin, or when the model has no governed state.

### 4. Change requests

- **`update_model`** writes `model_state` in the approval transaction. It is refused for a model with no governed state.
- **`activate_model {model_id, version, allow_downgrade?}`** makes a model file active: a new version, or the edited file of the active one.
  - The model file must carry a valid model signature when signers are configured.
  - Schema and supplier controls run at proposal and at approval.
  - A model with governed state keeps it. Otherwise its YAML status and mode become governed, and the binding says so (`state_source`).
  - **Downgrade:** activating a lower version of the *same* `model_id` needs `allow_downgrade: true`, which is part of the change digest. Versions that are not dotted numbers count as a downgrade whenever they differ. There is no prior version at first baseline, so the check cannot protect it.
  - **Pack binding:** `model.pack_id` is not required to equal the active pack (a new pack and a new model could otherwise never be switched). The binding shows both ids and a `warning` when they differ. `/v1/runtime` reports `model_pack_mismatch`, `kavach_model_pack_mismatch` exposes it as a metric, and the console shows a banner. Evidence records the pack actually used.

### 5. Model signatures and signer roles

- `<model>.sig` signs `kavach-model-signature-v1:` + model id + version + file SHA-256. The prefix differs from packs, so one cannot pass as the other.
- `signers.json` entries take `roles: ["pack", "model"]`. An entry without `roles` stays pack-only, and `roles: []` or an unknown role is refused.
- With signers configured, the API (startup and `activate_model`) and batch require model signatures from a `model` signer.

### 6. Visibility

- `/v1/models` shows governed status and mode, and `governed: false` for model files with no state; `update_model` refuses those until `activate_model` runs.
- Migrations are serialized with a Postgres advisory lock, so replicas starting together do not race.

## Consequences

- Approved mode changes survive restarts, and editing the YAML no longer changes the mode.
- Operators who configure signers must now sign model files too (`kavach-keys sign-model`), with a key that has the `model` role.
- A legitimate YAML edit needs an `activate_model` change (or the audited override for recovery).

## Deferred

- A combined pack-and-model change kind.
- Governance events on the evidence chain (ADR-005); insert-only database roles (P1).
