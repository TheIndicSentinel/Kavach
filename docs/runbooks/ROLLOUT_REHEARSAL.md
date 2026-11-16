# Runbook: Rehearsing an Upgrade

**Status: Draft, not yet rehearsed.** No step here has been run end to end. The first rehearsal is a later task; it will correct this text and record its results in section 7.

**For:** the operator of a single-instance `kavach-api` with Postgres. **Goal:** upgrade from one release to the next on a copy of the deployment first, with migrations, with any key change accounted for, with checks before and after, and with a rollback that has been tried.

Related: [MIGRATIONS.md](../MIGRATIONS.md) (how migrations are written and run), [KEY_RUNBOOK.md](../KEY_RUNBOOK.md) (keys), [INSTALL.md](../INSTALL.md) (flags, roles, stopping), [EVIDENCE_BUNDLE.md](../EVIDENCE_BUNDLE.md) (export and verify), [RESTORE_DRILL.md](RESTORE_DRILL.md) (restoring a backup), [deploy/monitoring](../../deploy/monitoring/README.md) (alerts).

## What exists and what does not

Used below, and present in the code:

- `kavach-api` applies pending migrations at startup as the owner role (`--migration-database-url` / `KAVACH_MIGRATION_DATABASE_URL`), then serves as the runtime role (`--database-url`). Applied migrations are tracked with checksums in `_sqlx_migrations` (`crates/kavach-storage/src/postgres/migrate.rs`).
- `--require-hardening` refuses to start while any relaxation is active; `--shutdown-grace-seconds` (default 30) bounds the orderly stop.
- `GET /health` (both listeners), `GET /v1/runtime` and `GET /metrics` on the operator listener.
- `kavach-evidence checkpoints`, `export` and `verify-bundle` (`crates/kavach-evidence-cli`), and the independent verifier `conformance/kavach_verify.py`.

**Not built** (each step that would need one says so):

- A migrate-only command. Migrations run only as part of starting `kavach-api` (or `kavach-batch` given `--migration-database-url`).
- A way to roll a migration back. Migrations are forward-only (MIGRATIONS.md, "Not decided yet").
- A version or commit in `kavach-api --version` or in `/v1/runtime`. Record the image digest or build commit yourself.
- A readiness route, and a readiness drain before stopping (INSTALL.md, "Stopping": "a readiness drain is not built").
- A canary or smoke command for a deployment. The `kavach` CLI (`kavach call`, `kavach agent`) targets a development stack's project directory, not a deployment.
- Backup tooling. Postgres backups are the deployment's own (for example `pg_dump`); Kavach ships none.

## 1. Before the rehearsal (read, decide)

1. **List the migrations the upgrade adds.** In a checkout of the source:

   ```sh
   git diff --name-only <old-tag>..<new-tag> -- crates/kavach-storage/migrations/
   ```

   For each new file, check it against MIGRATIONS.md: constraints added `NOT VALID` then `VALIDATE`; no `UPDATE` backfill on an append-only table; grants redefined by `kavach_grant_runtime()`; anything that changes what the runtime role can do is on the second-review list. A plain `ADD CONSTRAINT … CHECK` or an index build on a large evidence table is the step most likely to block writes: time it in the rehearsal.
2. **Expand, then contract.** If the release notes say a migration is the "contract" half of a change, the previous release must already be running everywhere. Do not skip a release.
3. **Keys ([KEY_RUNBOOK.md](../KEY_RUNBOOK.md)).** Do not combine a key rotation with an upgrade. Before you start, answer:
   - Is a mandate-key overlap in progress (`previous_mandate_keys` set)? Then the new release must start with the same mandate configuration, or mandates signed with the old key stop verifying and agents are blocked (fail closed).
   - Does the release add or rename a key role or a key flag? Then the new public keys go into the verifiers' trusted keys file **before** the switch, as for a rotation.
   - Is `valid_until_seq` set on any key in the trusted keys file after a compromise? The post-upgrade verification (step 5.6) uses the same file; keep it unchanged.
   - HSM: `--hsm-keys` and the key labels do not change across an upgrade.
4. **Orchestrator grace.** Its stop timeout must exceed `--shutdown-grace-seconds` (INSTALL.md, "Stopping"); otherwise the old process is killed mid-drain and calls cut between send and outcome are reported `outcome_missing`.
5. **Decide the rollback trigger** before you start (section 6): which failed check means "roll back", and who decides.

## 2. The rehearsal environment

Rehearse on a copy, never on the live deployment:

- A scratch Postgres restored from a recent backup of the deployment ([RESTORE_DRILL.md](RESTORE_DRILL.md), sections 1 to 3), so the migrations run against real table sizes.
- The same `kavach-api` flags as the deployment, with the scratch database URLs, the deployment's key ids, and `--require-hardening`. Signing keys: a rehearsal that signs with the deployment's evidence or checkpoint keys writes records that verify as the deployment's. Prefer separate rehearsal keys with new ids (`kavach-keys generate --dir <dir> --kid <id>`) and a rehearsal trusted keys file; note in the results which you used.
- No agent traffic from production, and no provider endpoint that sends real messages: point `--providers` at the mock provider (`kavach-mock-provider`) or at a provider's test endpoint.
- Start the **old** release on the scratch database first, so the rehearsal starts from the same state as production.

## 3. Checks before the upgrade

Record each result in section 7. `$OP` is the operator listener (for example `https://kavach-api.internal:8080`); `auth.hdr` is an owner-only file holding one line, `Authorization: Bearer <operator token>`, so the token is not on the command line.

1. **Version:** record the old image digest or build commit (not reported by the binary).
2. **Health:** `curl -sf -H @auth.hdr "$OP/health"` and the agent listener's `GET /health` both return `{"status":"ok"}`.
3. **Runtime:** `curl -sf -H @auth.hdr "$OP/v1/runtime"`. Record `pack_sha256`, `model_sha256`, `pointer_version`, `stored_pointer_version`, `pointer_drift` (expect `false`), `relaxations` (expect `[]`), `require_hardening` (expect `true`), `checkpoint_stalled` (expect `false`), `checkpoint_last_seq`, and `hsm` if present.
4. **Alerts and gauges:** no alert from `kavach-alerts.rules.yml` firing. In `/metrics`: `kavach_revocation_records_missing`, `kavach_agent_state_records_missing`, `kavach_revocation_audit_entries_missing` and `kavach_outcomes_conflicted` are 0.
5. **Keep a checkpoint off-host,** as the read-only auditor role:

   ```sh
   export KAVACH_AUDITOR_DATABASE_URL='postgres://kavach_auditor:…@<db>:5432/kavach'
   kavach-evidence checkpoints --latest >> <kept-dir>/kavach-checkpoints.jsonl
   ```

   Note its `seq`: this is the pre-upgrade anchor.
6. **Baseline export and verification:**

   ```sh
   kavach-evidence export --out ./pre-upgrade --key-dir <export-key-dir> --key-id export-<you>-<n>
   kavach-evidence verify-bundle ./pre-upgrade --keys <trusted-keys.json> \
     --expect-checkpoint <kept-dir>/kavach-checkpoints.jsonl
   ```

   Expect exit 0. Exit 2 lists what is not protected first; record it and decide before going on.
7. **Backup:** take a backup of the database with the deployment's own tool and record its time. On the live upgrade this is the rollback point (section 6).
8. **Migrations already applied** (owner role):

   ```sh
   psql "$KAVACH_MIGRATION_DATABASE_URL" -c \
     'SELECT version, description, success FROM _sqlx_migrations ORDER BY version DESC LIMIT 5;'
   ```

## 4. The upgrade

1. Stop sending agent traffic, if your load balancer can (a readiness drain in Kavach is not built).
2. Send SIGTERM to the old `kavach-api`. Expect exit status 0. Exit 1 follows an `ALERT shutdown was not clean` log line: record it; a call cut between send and outcome will show as `outcome_missing` in the next verification.
3. Start the new release with the same flags and `--require-hardening`. Note the time the migrations start and end in the startup log; that is the write outage a migration adds on the live upgrade.
4. If startup refuses (exit 78 under `--require-hardening` lists every failed condition at once), do not loosen a flag to get past it. Read the message, fix the configuration, or roll back.

## 5. Checks after the upgrade

1. **Version:** the new image digest or commit is the one running.
2. **Migrations:** the query of step 3.8 shows the new versions, each `success = t`.
3. **Health** on both listeners, as step 3.2.
4. **Runtime,** as step 3.3: `pack_sha256` and `model_sha256` unchanged, `pointer_drift` `false`, `relaxations` `[]`, `require_hardening` `true`, `checkpoint_stalled` `false`.
5. **A new checkpoint** after the first records: `kavach-evidence checkpoints --latest` shows a `seq` greater than the pre-upgrade anchor once there has been traffic. With no traffic there is nothing new to cover.
6. **The chain continues across the upgrade:**

   ```sh
   kavach-evidence checkpoints --latest >> <kept-dir>/kavach-checkpoints.jsonl
   kavach-evidence export --out ./post-upgrade --after-checkpoint <pre-upgrade seq> \
     --key-dir <export-key-dir> --key-id export-<you>-<n>
   kavach-evidence verify-bundle ./post-upgrade --keys <trusted-keys.json> \
     --expect-checkpoint <kept-dir>/kavach-checkpoints.jsonl
   python3 -I conformance/kavach_verify.py bundle ./post-upgrade --keys <trusted-keys.json> \
     --expect-checkpoint <kept-dir>/kavach-checkpoints.jsonl
   ```

   Both verifiers exit 0 and agree. If the release changes the bundle format, the release notes say which verifier versions read it; an older verifier refuses a newer format rather than misread it.
7. **A gateway call and a stop,** with the rehearsal's own test agent and the mock provider: one allowed call ends `delivered`; `POST $OP/v1/agents/<test-agent>/quarantine` with a reason code, then the agent's next call is `BLOCK`; reinstate it through a change request approved by a second principal. A shipped canary command for this is not built.
8. **Alerts and gauges** as step 3.4, after at least one pass of each reconciler (wait one interval of the slowest): every `*_last_pass_timestamp_seconds` has moved.

## 6. Rollback

**Rolling the binary back is safe only if the upgrade added no migration.** Then: SIGTERM the new release, start the old one with the same flags, and run section 5 against it.

**After a migration has run, the old binary is expected to refuse to start** while it runs migrations: sqlx, which runs them, refuses a database that has an applied migration the binary does not know, and `migrate.rs` does not override that default. Confirm this in the rehearsal (start the old binary against the migrated scratch database and record the message). There is no down-migration. The rollback is then:

1. Stop the new release (SIGTERM).
2. Restore the backup taken in step 3.7 ([RESTORE_DRILL.md](RESTORE_DRILL.md)) and start the old release on it.
3. **Know what is lost.** Every record written by the new release after the backup is gone: decisions, outcomes, revocations, agent-state changes and checkpoints. Off-host checkpoints taken after the backup now name records the restored chain does not have, so a verification against the newest kept checkpoint fails with "records after it were removed". That is correct. Verify the restored chain against the newest kept checkpoint at or before the backup (RESTORE_DRILL.md, step 4.2), and keep the post-upgrade export of step 5.6 as the only evidence of what happened in between.
4. Mandates issued, revoked or suspended after the backup are lost too. Ask the system of record to resend its events from the backup time; an agent stopped after the backup must be stopped again.

Because of steps 3 and 4, on the live upgrade keep the time between the backup and the rollback decision as short as possible, and take the decision before agent traffic resumes if you can.

## 7. Results (filled in by the rehearsal)

| Item | Result |
|---|---|
| Date, operator | |
| Old and new release (digest or commit) | |
| Migrations added, and how long each took | |
| Keys used (rehearsal or deployment ids) | |
| Checks 3.1 to 3.8 | |
| Old process exit status | |
| Checks 5.1 to 5.8, both verifiers' exit status | |
| Rollback tried; the old binary's message against the migrated database | |
| Rollback by restore: time taken, records lost | |
| Corrections to this runbook | |
