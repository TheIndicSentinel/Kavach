# System review checkpoint

**This is the holistic review gate for everything built so far.**

Use it after Milestone A + B are merged, open feature PRs are landed, and you want to validate the full on-prem governance platform before deploying to a bank VPC or starting partner engagement.

## When you are here

You have:

- [x] Milestone A — evaluate API, batch worker, evidence chain ([MILESTONE_A_EXIT.md](MILESTONE_A_EXIT.md))
- [x] Milestone B — governance console, Cedar RBAC, retention, incidents, batch inventory ([MILESTONE_B_EXIT.md](MILESTONE_B_EXIT.md))
- [x] Partner pilot packaging — Docker compose, phase scripts, sign-off gate ([PARTNER_PILOT.md](PARTNER_PILOT.md), [PILOT_SIGNOFF.md](PILOT_SIGNOFF.md))
- [x] Fairness report console viewer — `/fairness` route

**Stop and review the system at this checkpoint.** Do not proceed to bank VPC deployment until automated gates pass and the manual console walkthrough is complete.

**Step-by-step startup commands:** [LOCAL_REVIEW_STEPS.md](LOCAL_REVIEW_STEPS.md) · `./scripts/start-local-review.sh`

## One-command automated gate

```bash
# Minimal (no live API — CI-equivalent)
./scripts/system-review.sh

# Full stack (pilot API + Postgres running)
export KAVACH_DATABASE_URL=postgres://kavach:change-me@localhost:5432/kavach
export PILOT_API_URL=http://localhost:8080
./scripts/system-review.sh
```

### What the script runs

| Layer | Command | Requires |
|---|---|---|
| 1 | `./scripts/verify.sh` | Rust, Node |
| 1b | `./scripts/pilot-smoke.sh` | Partner batch fixtures |
| 2 | `./scripts/pilot-signoff.sh` | Live pilot API (`PILOT_API_URL`) |
| 3 | `export-postgres-evidence.py` + `kavach-evidence verify` | Postgres (`KAVACH_DATABASE_URL`), `psql` |

Set `SKIP_VERIFY=1` to skip the slow workspace test suite when iterating on pilot layers only.

## Start the pilot stack (for full review)

```bash
cp deploy/pilot.env.example deploy/.env
docker compose -f deploy/docker-compose.pilot.yml up --build -d
```

Or source build — see [PILOT_SIGNOFF.md](PILOT_SIGNOFF.md).

Console is embedded in the API at `http://localhost:8080/`. Dev mode with hot reload: `cd console && npm run dev` (proxies to `:8080`).

## Manual console walkthrough (~30 min)

Use principal `admin-1` in **Settings** for admin routes. Test at **375px** (mobile) and **1280px** (desktop).

| Route | What to verify |
|---|---|
| `/overview` | API health green, active model `credit-underwriting-v1`, governance mode |
| `/evaluate` | Submit partner sample; decision badge + reason codes |
| `/policies` | Finance pack `finance-v0` rules listed |
| `/models` | `credit-underwriting-v1` posture; vendor model present |
| `/batch` | Postgres batch jobs from pilot Phase 1 (after sign-off) |
| `/fairness` | Load disparity + inclusion samples; group metrics render |
| `/audit` | Retention mutation entries from pilot Phase 2 |
| `/incidents` | Empty or prior shadow incidents (no fake rows) |
| `/retention` | 365-day default; tombstone list loads |
| `/settings` | Actor `admin-1`, approver `admin-2` for dual-control |

## API spot checks

```bash
# Health (Cedar pilot)
curl -s -H 'X-Kavach-Principal: viewer-1' http://localhost:8080/health

# Runtime
curl -s -H 'X-Kavach-Principal: viewer-1' http://localhost:8080/v1/runtime | jq .

# Batch jobs (admin)
curl -s -H 'X-Kavach-Principal: admin-1' 'http://localhost:8080/v1/admin/batch-jobs?limit=5' | jq .

# Evidence export + chain linkage (included in system-review.sh Layer 3)
export KAVACH_DATABASE_URL=postgres://kavach:change-me@localhost:5432/kavach
python3 scripts/export-postgres-evidence.py /tmp/kavach-evidence.ndjson
```

## Sign-off checklist

### Engineering (repo)

- [ ] `./scripts/system-review.sh` exits 0 (full stack with `PILOT_API_URL` + `KAVACH_DATABASE_URL`)
- [ ] CI green on `main`
- [ ] Console walkthrough complete at 375px and 1280px

### Partner / bank (external — not in repo)

- [ ] LOS field mapping signed off against `partner/finance/credit_underwriting_v1_request.json`
- [ ] IdP groups → Cedar principals (`viewers`, `operators`, `admins`)
- [ ] Postgres backup and retention policy agreed
- [ ] NDJSON export CronJob scheduled in bank VPC
- [ ] Incident runbook: query `/v1/admin/incidents` by `correlation_id`

## What comes after this checkpoint

1. **Partner pilot weeks 1–3** in bank VPC — [PARTNER_PILOT.md](PARTNER_PILOT.md)
2. **Production hardening** — HMAC, mTLS, Helm/operator (not in v1 repo scope)
3. **Live batch progress** and in-browser batch trigger (explicitly deferred)

## Related gates

| Gate | Scope |
|---|---|
| [MILESTONE_A_EXIT.md](MILESTONE_A_EXIT.md) | Core crates + partner payloads |
| [MILESTONE_B_EXIT.md](MILESTONE_B_EXIT.md) | Governance console + admin APIs |
| [PILOT_SIGNOFF.md](PILOT_SIGNOFF.md) | Automated pilot Phase 1–3 |
| **This doc** | Holistic review before bank deployment |
