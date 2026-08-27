# Milestone A exit gate

Sign-off after Milestone A crates are merged and before further Milestone B work (policy lifecycle UI, etc.).

## Milestone A deliverables

| # | Crate / artifact | Status |
|---|---|---|
| A.1 | `kavach-policy` — CEL pack loader and evaluator | done |
| A.2 | `kavach-evidence` — hash chain, memory store, verify CLI | done |
| A.3 | `kavach-evaluate` — evaluate pipeline orchestration | done |
| A.4 | `kavach-api` — HTTP/gRPC sync evaluate, HMAC, mTLS, Postgres evidence, metrics | done |
| A.5 | `kavach-batch` — NDJSON batch worker | done |
| A.5+ | `kavach-storage` — shared Postgres evidence, incidents, batch job lifecycle | done |

## Exit artifacts (this gate)

- [x] **Partner real payload sample** — `partner/finance/` (request JSON + batch NDJSON)
- [x] **Bank install docs** — [INSTALL.md](INSTALL.md) (2 containers + Postgres + IdP)
- [x] Contract tests validate partner samples against `evaluate-request.schema.json`
- [ ] `cargo test --workspace` green locally (`./scripts/verify.sh`)
- [ ] CI green on GitHub `main` after merge

## Verification commands

```bash
./scripts/build-console.sh
./scripts/verify.sh

# Partner batch smoke (memory evidence; refresh timestamps if clock-skew fails)
cargo run -p kavach-batch -- run \
  --input partner/finance/credit_underwriting_v1_batch.ndjson \
  --output /tmp/kavach-partner-out.ndjson \
  --pack packs/finance/v0.yaml \
  --model models/finance/credit-underwriting-v1.yaml
```

## Explicitly not Milestone A exit

- React governance console (Milestone B.2) — shipped early but not an A gate
- Cedar RBAC (Milestone B.1/B.3) — optional at install time
- Policy lifecycle UI (Milestone B.4+)
- Helm charts / operator — future packaging

## Sign-off

When all boxes above are checked, proceed with Milestone B:

- B.1 Cedar HTTP — done
- B.2 React console — done
- B.3 gRPC Cedar — done
- **Next:** B.4 policy lifecycle UI

**Milestone A status:** Complete in repo; pending CI green after merge to `main`.
