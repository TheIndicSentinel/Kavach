# Milestone B exit gate

Sign-off after governance console, Cedar RBAC, policy lifecycle, fairness, retention, incidents, and supplier AI controls are merged.

## Milestone B deliverables

| # | Artifact | Status |
|---|---|---|
| B.1 | Cedar HTTP RBAC (`kavach-auth`) | done |
| B.2 | React governance console (`console/`) | done |
| B.3 | gRPC Cedar authorization | done |
| B.4 | Policy lifecycle UI + admin audit | done |
| B.5 | Dual-control pack/model mutations | done |
| B.6 | Polars fairness batch reports | done |
| B.7 | Retention policy + DPDP evidence tombstones | done |
| B.8 | Incident records + supplier AI enforce gate | done |
| B.9 | Batch job console inventory + responsive UI | done |

## Exit artifacts (this gate)

- [x] **Governance console** — policies, models, audit, incidents, retention, batch jobs, fairness reports
- [x] **Admin read APIs** — audit, retention, tombstones, incidents, batch jobs
- [x] **Responsive layout** — mobile drawer nav, card fallback for data tables
- [x] **Install docs** — [INSTALL.md](INSTALL.md) admin route table
- [x] **Partner pilot packaging** — [PARTNER_PILOT.md](PARTNER_PILOT.md), `deploy/`, `scripts/pilot-smoke.sh`
- [x] `cargo test --workspace` green locally (`./scripts/verify.sh`)
- [x] CI green on GitHub `main` after merge (includes `scripts/pilot-smoke.sh` batch path)

## Verification commands

```bash
./scripts/build-console.sh
./scripts/verify.sh

# Batch worker smoke (memory evidence)
cargo run -p kavach-batch -- run \
  --input partner/finance/credit_underwriting_v1_batch.ndjson \
  --output /tmp/kavach-partner-out.ndjson \
  --pack packs/finance/v0.yaml \
  --model models/finance/credit-underwriting-v1.yaml

# Console dev (responsive check at 375px / 768px / 1280px)
cd console && npm run dev
```

## Explicitly not Milestone B exit

- In-browser batch upload/trigger (batch remains CronJob/workflow invoked)
- Live batch progress streaming (`processed_rows` mid-run)
- Helm charts / operator — future packaging

## Post-B console additions

- [x] **Fairness report viewer** — `/fairness` route; upload or sample `kavach-batch fairness` JSON (client-side only)

## Sign-off

When all boxes above are checked, proceed with post-B hardening:

- Milestone B exit CI green on `main`
- Partner pilot engagement using [PARTNER_PILOT.md](PARTNER_PILOT.md)

**Milestone B status:** Complete — merged to `main` (PRs #18, #19).
