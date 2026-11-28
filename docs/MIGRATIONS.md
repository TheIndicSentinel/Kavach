# Writing a migration

How schema changes are made. Operators: how migrations run is in [INSTALL.md](INSTALL.md).

## How they run
- Files are `crates/kavach-storage/migrations/NNN_name.sql`, embedded in the binary (`sqlx::migrate!`) and applied at startup by the **owner** role, never by the runtime role.
- Give every file a unique numeric version. The storage build script watches `migrations/` so adding or renaming a file refreshes the embedded list during incremental builds.
- Each applied migration is tracked with its checksum in `_sqlx_migrations`. **Never edit a migration that has shipped.** Add a new one.
- D17 migrations 029–031 replace the colliding later 026–028 filenames. Migration 032 restores snapshot and challenge grants in the complete `kavach_grant_runtime()` helper; check an existing database's `_sqlx_migrations` history before upgrading if it was created from the colliding pre-alpha files.
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

## Notes per migration

From 025 on, each migration that lands records here its lock level, expected duration and how to roll back (remediation plan §1.4). Durations are reasoning from what each statement touches, not measurements. Rollback is always "run the previous binary against the new schema" unless a note says otherwise: these migrations only add, so older code ignores what they create.

| Migration | What it does | Locks | Duration | Rollback |
|---|---|---|---|---|
| 025 `human_review_approvals` | New table of D17 review decisions; four CHECKs added `NOT VALID` then validated; immutability, no-delete and no-truncate triggers; `kavach_grant_runtime()` redefined to add `SELECT, INSERT` and `UPDATE (consumed_at)` | Only the new, empty table. The grant function's `REVOKE`/`GRANT` change catalog rows for every table, with no scan or rewrite | Milliseconds | Previous binary; the table stays and is unused |
| 026 `human_review_step_up_challenges` | New table of one-use step-up challenges (digests of state and nonce only); CHECKs inline (new table); immutability trigger that lets only expired rows be deleted; no-truncate trigger; runtime grants in a `DO` block | Only the new, empty table | Milliseconds | Previous binary; the table stays and is unused |
| 027 `human_review_snapshots` | New table of the exact action a reviewer is shown (tenant-keyed); expiry index; guard trigger that lets only expired rows be deleted; no-truncate trigger; runtime grants in a `DO` block (same gap as 026, closed by 032) | Only the new, empty table | Milliseconds | Previous binary; the table stays and is unused |
| 029 `human_review_release_records` | Adds nullable `review_record_id` and `execution_id` to `human_review_approvals` (catalog-only, no rewrite); a CHECK added `NOT VALID` then validated; replaces the approvals guard function; unique index on `(tenant_id, execution_id)`; new append-only `human_review_releases` table with guard and no-truncate triggers; `kavach_grant_runtime()` redefined | `ACCESS EXCLUSIVE` on `human_review_approvals` for the column adds (brief); `SHARE` on it while the unique index builds, which blocks writes to that table only | Milliseconds to seconds: the index scans the approvals table, one row per human review | Previous binary; the columns and table stay and are unused |
| 030 `agent_execution_idempotency` | Adds nullable `idempotency_key` to `agent_decisions` (catalog-only); a CHECK added `NOT VALID` and **left unvalidated**; replaces the per-request unique index with one on `(tenant_id, agent_id, mode, COALESCE(idempotency_key, request_id))` | `ACCESS EXCLUSIVE` on `agent_decisions` for the column and constraint adds (brief, no scan); `SHARE` while the new index builds, which blocks agent decision writes until it finishes | One index build over `agent_decisions`, no rewrite: seconds per million rows. Pick a quiet window on a large deployment | Previous binary. Older code inserts no `idempotency_key`, which the CHECK refuses, so agent decisions fail closed until the new binary is back: roll back only if they can pause |
| 031 `human_review_release_credential` | Adds `single_use_credential_id` to `human_review_releases`, copied from the approval (the `UPDATE` matches no rows: the table is new in the same slice), then `SET NOT NULL`; a CHECK added `NOT VALID` then validated; unique index; insert guard trigger that ties a release to an approval consumed in the same transaction | `ACCESS EXCLUSIVE` on the new, empty `human_review_releases` | Milliseconds | Previous binary; the column stays and is unused |
| 032 `human_review_runtime_grants` | Redefines `kavach_grant_runtime()` in full, adding back the 026 and 027 tables, and runs it | Catalog rows only, no scan | Milliseconds | Previous binary; the grants stay |

**030 does not backfill (rule 2).** `agent_decisions` is append-only, so the first draft's `UPDATE … SET idempotency_key = request_id` failed on any database holding agent evidence. It was rewritten before it reached `main`: decisions written before 030 keep `idempotency_key` NULL and stay keyed by `request_id` through the `COALESCE` index, and the commit lookup uses the same expression. The CHECK cannot be validated over those rows, so it binds new rows only (the exception to rule 4; test `agent_evidence_recorded_before_migration_030_survives_the_upgrade`). A pre-alpha database that applied the first draft has a different checksum in `_sqlx_migrations`: recreate it.

**Known gap (026):** it grants in a `DO` block instead of redefining `kavach_grant_runtime()` (rule 1). The next redefinition, in 029, leaves the table out, so the runtime loses its rights until 032 adds them back. 029–032 land together in one slice and apply in one startup run, so no release runs between them. Any new migration must keep `human_review_step_up_challenges` in the function.

## Not decided yet
- Index builds on large tables (`CREATE INDEX CONCURRENTLY` cannot run inside a transaction). Decide it when the first migration needs one.
- A way to roll a deployment back past a migration. Today a migration is forward-only.
