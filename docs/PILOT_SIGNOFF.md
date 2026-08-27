# Partner pilot sign-off

Automated exit gate for the three-week partner pilot playbook ([PARTNER_PILOT.md](PARTNER_PILOT.md)). Run after the pilot stack is up (Docker or source build with Postgres + Cedar).

## Automated sign-off

```bash
# Docker pilot (recommended)
cp deploy/pilot.env.example deploy/.env
docker compose -f deploy/docker-compose.pilot.yml up --build -d

export KAVACH_DATABASE_URL=postgres://kavach:change-me@localhost:5432/kavach
export PILOT_API_URL=http://localhost:8080
./scripts/pilot-signoff.sh
```

Source build (no Docker):

```bash
# Terminal 1 — Postgres must be running; create kavach DB/user per INSTALL.md
export KAVACH_DATABASE_URL=postgres://kavach:change-me@localhost:5432/kavach
cargo run -p kavach-api --release -- \
  --pack packs/finance/v0.yaml \
  --model models/finance/credit-underwriting-v1.yaml \
  --listen 0.0.0.0:8080 \
  --evidence-store postgres \
  --access-control cedar \
  --cedar-policy crates/kavach-auth/policies/kavach.cedar \
  --cedar-entities crates/kavach-auth/policies/entities.example.json

# Terminal 2
export KAVACH_DATABASE_URL=postgres://kavach:change-me@localhost:5432/kavach
export PILOT_API_URL=http://localhost:8080
./scripts/pilot-signoff.sh
```

The sign-off script runs, in order:

| Step | Script | Validates |
|---|---|---|
| 1 | `pilot-phase1.sh` | Schema contracts, shadow batch ≥99% success, Postgres batch jobs API (when DB URL set) |
| 2 | `pilot-phase2.sh` | Governance reads, dual-control guard, retention PATCH, audit log |
| 3 | `pilot-phase3.sh` | Enforce mode flip, sync evaluate, `policy_decision == returned_decision` |

When `KAVACH_DATABASE_URL` is set, Phase 1 runs `kavach-batch` with `--evidence-store postgres` so batch jobs appear in `GET /v1/admin/batch-jobs`.

After `./scripts/pilot-signoff.sh` passes, run the holistic gate: [SYSTEM_REVIEW_CHECKPOINT.md](SYSTEM_REVIEW_CHECKPOINT.md) (`./scripts/system-review.sh`).

## Sign-off checklist

### Automated (repo scripts)

- [ ] `./scripts/pilot-signoff.sh` exits 0 against pilot stack
- [ ] `cargo test --workspace` and CI green on `main`

### Console (manual)

- [ ] **Batch jobs** — `/batch` shows Phase 1 Postgres job
- [ ] **Policies / models** — `/policies`, `/models` match expected finance pack
- [ ] **Audit** — `/audit` shows retention mutation from Phase 2
- [ ] **Retention** — `/retention` shows restored 365-day default
- [ ] **Fairness** — `/fairness` loads sample disparity/inclusion JSON (optional viewer)
- [ ] Responsive check at 375px and 1280px

### Partner / bank (internal)

- [ ] LOS field mapping signed off against `partner/finance/credit_underwriting_v1_request.json`
- [ ] NDJSON export CronJob scheduled in bank VPC
- [ ] IdP groups mapped to Cedar principals (`operators`, `admins`, `viewers`)
- [ ] Postgres backup and retention policy agreed
- [ ] Incident runbook: `GET /v1/admin/incidents` by `correlation_id`
- [ ] Evidence export procedure + `kavach-evidence verify` on sample chain

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PILOT_API_URL` | `http://localhost:8080` | Pilot API base URL |
| `KAVACH_DATABASE_URL` | — | Postgres URL; enables Postgres batch + batch-jobs API check |
| `PILOT_PRINCIPAL` | `viewer-1` | Cedar read principal |
| `PILOT_ACTOR` | `admin-1` | Dual-control actor |
| `PILOT_APPROVER` | `admin-2` | Dual-control approver |
| `PILOT_EVAL_PRINCIPAL` | `admin-1` | Cedar principal for sync evaluate (Phase 3) |
| `PILOT_BATCH_JOBS_PRINCIPAL` | `admin-1` | Cedar principal for batch jobs API (Phase 1.4) |
| `PILOT_SKIP_WAIT` | — | Set `1` to skip API readiness poll |
| `PILOT_WAIT_SECS` | `60` | API readiness timeout |

## Related

- [PARTNER_PILOT.md](PARTNER_PILOT.md) — pilot phases and deliverables
- [INSTALL.md](INSTALL.md) — full on-prem install
- [MILESTONE_B_EXIT.md](MILESTONE_B_EXIT.md) — Milestone B gate
