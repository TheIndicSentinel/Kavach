# Runbook: Restore Drill

**Status: Draft.** A synthetic-only local rehearsal passed on 2026-11-19 (recorded below); the deployment restore drill has not been run. The synthetic rehearsal does not measure deployment recovery objectives or satisfy SLO E-6.

**For:** the operator of a single-instance `kavach-api` with Postgres. **Goal:** show that a backup of the deployment's database can be restored into a scratch instance, that the restored evidence chain verifies against a checkpoint kept off-host, and how much was lost (recovery point) and how long it took (recovery time).

Related: [INSTALL.md](../INSTALL.md) (roles, TLS), [EVIDENCE_BUNDLE.md](../EVIDENCE_BUNDLE.md) (checkpoints, export, verify), [KEY_RUNBOOK.md](../KEY_RUNBOOK.md) ("Backups"), [ROLLOUT_REHEARSAL.md](ROLLOUT_REHEARSAL.md) (which uses this drill for its scratch copy and its rollback), and `docs/SLO.md` (proposed evidence-durability objectives; drafted in a separate change).

## What exists and what does not

Used below, and present in the code:

- `kavach-evidence checkpoints`, `export` and `verify-bundle` (`crates/kavach-evidence-cli`); the independent verifier `conformance/kavach_verify.py` (Python standard library only).
- The grant helpers `kavach_grant_runtime()` and `kavach_grant_auditor()` that the migrations define.
- `scripts/pilot-db-tls.sh`, which makes a CA and a server certificate for a Postgres reached as host `postgres`.
- Evidence tables refuse `UPDATE` and `DELETE` by trigger; they accept `INSERT`, so a restore can load them.

**Not built:**

- Backup tooling. Kavach ships no backup or restore command; this drill uses Postgres's own `pg_dump` and `pg_restore`. A deployment with another method (volume snapshots, continuous archiving) substitutes its own steps 1 and 3.
- An export of the `decision_events` chain (the evaluate track) as the NDJSON file that `kavach-evidence verify --file` reads. This drill verifies the agent evidence chain only, through bundles.
- A row-count or consistency check of the non-evidence tables (mandates, revocations, agent states, change requests) after a restore. Step 4.5 compares counts by hand.

## Before the drill

- **Where the backup comes from.** Take a fresh one (step 1) or use the newest scheduled one; the drill should test the backups the deployment really keeps.
- **Kept checkpoints.** The file of checkpoints copied off-host (EVIDENCE_BUNDLE.md, "What a checkpoint does and does not prove"), for example `/mnt/offsite/kavach-checkpoints.jsonl`. Without one, step 4 can show the restored chain is consistent with itself, not that it is the chain the deployment wrote.
- **Trusted keys file** with the public keys of the evidence, checkpoint and export keys (KEY_RUNBOOK.md). Unchanged from what auditors use.
- **An export key** of your own, id starting `export-`, kept off the API host (`kavach-keys generate --dir <dir> --kid export-<you>-<n>`).
- **The subject pseudonym key.** KEY_RUNBOOK.md, "Backups": it is the one key that needs a backup. A restored database is complete for verification without it, but a deployment restored for service needs it to link new records to old subjects. Check that its backup exists; do not copy it to the scratch host.
- **The scratch host.** Separate from the deployment, with no route to the providers. It will hold a full copy of the evidence, which contains pseudonymised subject identifiers: treat it with the same access rules as the deployment, and delete it after the drill (step 7).

## 1. Take the backup

As the owner role (it owns every table), in Postgres's custom format:

```sh
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
pg_dump --format=custom --file=kavach-<date>.dump "$KAVACH_MIGRATION_DATABASE_URL"
echo "backup started $start"
```

Record the start time. `pg_dump` takes a consistent snapshot as of its start; records written after that are not in the backup.

Roles are not in the dump (they belong to the Postgres cluster): step 3 creates them.

## 2. Start a scratch Postgres

Use the same Postgres major version as the deployment.

**With TLS** (as the deployment): make a certificate and start Postgres with it, as the pilot stack does:

```sh
scripts/pilot-db-tls.sh ./scratch-db-tls
```

The certificate names the host `postgres` only (`subjectAltName=DNS:postgres`), so clients must reach the scratch database by that name: run them on the same container network, or map `postgres` to the scratch host in the client's hosts file. Start the official Postgres image with `deploy/postgres/tls-entrypoint.sh` and `deploy/postgres/pg_hba.conf`, as the pilot compose file does. Clients pass `--database-ca ./scratch-db-tls/ca.pem`.

**Without TLS** (loopback only, a drill host nobody else uses): the export commands need both `--allow-plaintext-database` and `sslmode=disable` in the URL (INSTALL.md, "PostgreSQL"). Record in the results that the drill ran without TLS; this is a relaxation, not how the deployment runs.

## 3. Restore

1. Create the roles and the database, as INSTALL.md does, with new passwords for the scratch instance:

   ```sql
   CREATE USER kavach WITH PASSWORD '<scratch owner password>';
   CREATE DATABASE kavach OWNER kavach;
   CREATE ROLE kavach_runtime LOGIN PASSWORD '<scratch runtime password>';
   CREATE ROLE kavach_auditor LOGIN PASSWORD '<scratch auditor password>';
   ```

2. Restore as the owner, keeping ownership and grants, and time it:

   ```sh
   time pg_restore --exit-on-error --dbname="$SCRATCH_OWNER_URL" kavach-<date>.dump
   ```

   `--exit-on-error` stops at the first error rather than leaving a partial copy that looks complete. If it fails, record the message.
3. Re-apply the grants, so both roles have exactly what the migrations give them:

   ```sh
   psql "$SCRATCH_OWNER_URL" -c 'SELECT kavach_grant_runtime();' -c 'SELECT kavach_grant_auditor();'
   ```

4. Check that the migrations table came with the data:

   ```sh
   psql "$SCRATCH_OWNER_URL" -c \
     'SELECT version, description, success FROM _sqlx_migrations ORDER BY version DESC LIMIT 3;'
   ```

   The newest version should be the one the deployment's release applies.

Do not start `kavach-api` on the scratch database for this drill: verification needs only the read-only auditor role. (The rollout rehearsal does start one; see ROLLOUT_REHEARSAL.md, section 2, about signing keys.)

## 4. Verify the restored evidence

All commands as the auditor role against the scratch instance:

```sh
export KAVACH_AUDITOR_DATABASE_URL='postgres://kavach_auditor:<scratch auditor password>@postgres:5432/kavach'
```

Add `--tenant` and `--partition` if the deployment uses other than `default` and `0`.

1. **The restored head.**

   ```sh
   kavach-evidence checkpoints --latest
   ```

   Record its `seq`: the newest checkpoint in the backup. The restored chain may hold records after it (not yet covered when the backup was taken).
2. **Pick the kept checkpoint to verify against.** Both verifiers read the **last** line of the `--expect-checkpoint` file. A kept checkpoint newer than the restored chain fails, correctly, with "records after it were removed" (EVIDENCE_BUNDLE.md). Use the newest kept checkpoint whose `seq` is at or below the restored chain's last record, in a file of its own:

   ```sh
   jq -c 'select(.seq <= <restored head seq>)' /mnt/offsite/kavach-checkpoints.jsonl | tail -n 1 > kept-for-drill.jsonl
   ```

   If no kept checkpoint qualifies, record that: the backup is older than every checkpoint kept, and step 3 below can show only that the chain is consistent with itself.
3. **Export and verify.**

   ```sh
   kavach-evidence export --out ./restored-bundle \
     --key-dir <export-key-dir> --key-id export-<you>-<n> \
     --database-ca ./scratch-db-tls/ca.pem
   kavach-evidence verify-bundle ./restored-bundle --keys <trusted-keys.json> \
     --expect-checkpoint kept-for-drill.jsonl --json > verify-restored.json
   echo "verify-bundle exit $?"
   python3 -I conformance/kavach_verify.py bundle ./restored-bundle --keys <trusted-keys.json> \
     --expect-checkpoint kept-for-drill.jsonl
   echo "kavach_verify.py exit $?"
   ```

   `export` refuses a role that can write (`--allow-write-role` overrides; do not use it here). For the drill without TLS, add `--allow-plaintext-database` to `export` and `checkpoints`, and use `sslmode=disable` in the URL.

   Expected: both verifiers exit 0, or both exit 2 with the same warnings. Expect `uncovered_records` if the backup holds records after its newest checkpoint, and `outcome_missing` for calls whose outcome was written after the backup. Record every warning. Exit 1 is a failed drill: record the message and stop.
4. **Against the newest kept checkpoint (expected to fail).** Optional, and only when a kept checkpoint is newer than the restored chain: verify again with the full kept file. The expected result is exit 1 naming removed records. This shows that a restore which silently lost records would be caught.
5. **Non-evidence tables (by hand).** No tool compares them yet (not built). As the owner role, count the rows of `mandates`, `mandate_revocations`, `agent_states`, `agent_state_changes` and `change_requests` on the scratch instance and, if the deployment allows a read, on the deployment; a difference is expected only for rows written after the backup started.

## 5. Recovery point and recovery time

- **Recovery point:** what a restore of this backup would lose. Measured as the gap between the backup start (step 1) and the newest kept checkpoint's `ts`, and as the number of records after the restored head that the newest kept checkpoint names (its `seq` minus the restored chain's last `seq`, when positive).
- **Recovery time:** the time from deciding to restore to a verified copy: `pg_restore`'s time, plus grants, plus step 4.3. Starting `kavach-api` on the restored database (migrations, if the release is newer than the backup) adds to this; the rollout rehearsal measures it.

Both are inputs to the evidence-durability objectives proposed in `docs/SLO.md` (drafted in a separate change). This drill measures them; it does not set targets.

## 6. Results (filled in by the drill)

| Item | Result |
|---|---|
| Date, operator | |
| Backup method, start time, size | |
| Postgres version (deployment, scratch); TLS or not | |
| `pg_restore` time and exit status | |
| Newest migration in the restored copy | |
| Restored newest checkpoint `seq`, `ts` | |
| Kept checkpoint used (`seq`, `ts`) | |
| `verify-bundle` exit status and warnings | |
| `kavach_verify.py` exit status; agrees with `verify-bundle`? | |
| Step 4.4 result (expected exit 1) | |
| Non-evidence table counts (scratch, deployment) | |
| Recovery point; recovery time | |
| Corrections to this runbook | |

### Synthetic local rehearsal (non-qualifying)

This validates the basic schema backup/restore and offline agent-evidence verification flow with generated data. It does not use a deployment backup, off-host checkpoint store, production keys, TLS, or a separate scratch host. Do not use these measurements as RPO/RTO evidence or to mark the restore drill complete.

| Item | Result |
|---|---|
| Date and run type | 2026-11-19; automated, synthetic local rehearsal |
| Backup source | Disposable demo schema; `pg_dump --format=custom --schema=<schema>`; 153,354 bytes |
| PostgreSQL | 16.16 (Homebrew), macOS x86_64; loopback with trust auth; TLS disabled |
| Restored migration | 040, `active api write guards` |
| Evidence rows after restore | 1 agent decision, 1 outcome, 1 checkpoint; source and restored counts matched |
| Checkpoint compared | sequence 1; `2026-11-19T11:15:55.681612Z`; checkpoint matched after restore |
| `pg_restore` | Exit 0; approximately 1 second |
| `verify-bundle` | Exit 0; 1 record, 1 outcome, 1 checkpoint; no warnings |
| Independent `kavach_verify.py` | Exit 0; same verified result |
| Recovery point/time | End-to-end values not measured; this isolated snapshot had no later writes to lose |
| Temporary artifacts | Removed from `/tmp` after verification |
| Runbook/setup finding | Empty Postgres-backed demo startup rejects the seeded assignment with `unknown consent C-dev-1`: its generated consent fixture is not loaded into the persistent consent projection. The lab seeded synthetic consent and preference through signed authority updates in its temporary checkout before creating the agent evidence. Fixing the demo bootstrap is a separate planned follow-up; this run did not change application code. |

The actual drill still needs the deployment's backup, an off-host checkpoint copy, trusted public keys, and a scratch host. Repeat the procedure against those materials before recording SLO E-6 as rehearsed.

## 7. After the drill

Delete the scratch instance, the dump copy on the drill host, and the exported bundle, unless the results are to be kept as evidence of the drill (then store them with the same access rules as the deployment's evidence). Keep `verify-restored.json` and section 6.
