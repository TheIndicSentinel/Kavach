# Writing a migration

How schema changes are made. Operators: how migrations run is in [INSTALL.md](INSTALL.md).

## How they run
- Files are `crates/kavach-storage/migrations/NNN_name.sql`, embedded in the binary (`sqlx::migrate!`) and applied at startup by the **owner** role, never by the runtime role.
- Give every file a unique numeric version. The storage build script watches `migrations/` so adding or renaming a file refreshes the embedded list during incremental builds.
- Each applied migration is tracked with its checksum in `_sqlx_migrations`. **Never edit a migration that has shipped.** Add a new one.
- D17 migrations 029–031 replace the colliding later 026–028 filenames. Migration 032 restores snapshot and challenge grants in the complete `kavach_grant_runtime()` helper; check an existing database's `_sqlx_migrations` history before upgrading if it was created from the colliding pre-alpha files.
- Migration 038 expands signed authority-update history for destination metadata and grants only the required runtime insert and ciphertext/version column updates. It is security relevant and requires independent review; the runtime role cannot update the pinned `source_system` or delete destination rows.
- Migration 044 adds tenant attribution to existing credit evidence, chain heads and retention rows. It preserves legacy rows under `default` and v1 event hashes. The migration adds no table; its two runtime `INSERT` grants allow lazy initialization of tenant-scoped heads/settings and remain protected by the active-write guards.
- Migration 045 re-keys the governed runtime pointer singleton by tenant, retaining the existing row under `default`; API, batch and approved change-request operations select the configured or request tenant.
- Migration 046 backfills credit decision-event partition `0` and `seq` by traversing existing `prev_hash` links, refuses disconnected/forked chains or a mismatched head, and introduces independently locked `(tenant_id, partition_id)` heads. Existing event hashes stay unchanged. It grants the runtime role writes only to the guarded new head table and leaves the old head read-only. Live Postgres migration/backfill verification is required before relying on this migration in a deployment.
- Migration 047 creates `kavach_grant_credit_auditor()`, granting the separate `kavach_credit_auditor` role `SELECT` only on `decision_events` and `evidence_chains`. The existing agent-only `kavach_auditor` grants are unchanged. Create the optional login before migrations or run the helper after creating it. Live Postgres privilege verification is required before deployment.
- Migration 048 expands the checkpoint chain constraint to include `decision_events` and grants the credit auditor `SELECT` on `evidence_checkpoints`, so checkpoint signatures can be exported. The role remains read-only; `kavach_auditor` is unchanged. The API writes both chains when agent surfaces are configured; Postgres credit-only startup now configures the credit chain writer independently and requires the dedicated checkpoint key.
- Postgres tests (`crates/kavach-storage/tests/`) run every migration on a fresh database and on one built by the older runner (`migrations_apply_once_on_fresh_and_upgraded_databases`). They need `KAVACH_TEST_DATABASE_URL`, and CI sets it.

## Rules every migration follows
1. **Grants.**
   - `kavach_grant_runtime()` is redefined in full by every migration that adds a table, and the migration ends with `SELECT kavach_grant_runtime();`.
   - Evidence and audit tables get `SELECT, INSERT` only.
   - Change no other role's rights without a line in the PR saying so.
2. **Append-only tables** keep their `BEFORE UPDATE OR DELETE` and `BEFORE TRUNCATE` triggers (`kavach_append_only()`). A column added to one cannot be backfilled with `UPDATE`: use a constant `DEFAULT`, which rewrites nothing.
3. **Tenant.** A new table is keyed by `tenant_id`. Anything without it is single-tenant by construction, and the PR says so.
4. **Constraints on existing tables: add as `NOT VALID`, then `VALIDATE`.**

   ```sql
   ALTER TABLE agent_decisions
       ADD CONSTRAINT agent_records_kind_known CHECK (kind IN ('agent_decision', 'mandate_revocation')) NOT VALID;
   ALTER TABLE agent_decisions VALIDATE CONSTRAINT agent_records_kind_known;
   ```

   - `ADD CONSTRAINT … NOT VALID` takes its lock briefly and scans nothing. New rows are checked from that moment.
   - `VALIDATE CONSTRAINT` scans the existing rows under a lock that does not block reads or writes.
   - A plain `ADD CONSTRAINT … CHECK` scans the whole table while holding a lock that blocks writes. That is acceptable on an empty table, not on one holding a tenant's evidence.
   - **This is the rule for every migration from the next one on.** Migration 015 added its CHECKs validated, on tables small enough at the time.
5. **Expand, then contract.** A change old code cannot run against is split across releases: first add what the new code needs, ship, then remove what only the old code used.
6. **A security-relevant migration goes on the second-review list** ([SECOND_REVIEW.md](SECOND_REVIEW.md)): grants, triggers, anything that changes what the runtime role can do.

## Not decided yet
- Index builds on large tables (`CREATE INDEX CONCURRENTLY` cannot run inside a transaction). Decide it when the first migration needs one.
- A way to roll a deployment back past a migration. Today a migration is forward-only.
