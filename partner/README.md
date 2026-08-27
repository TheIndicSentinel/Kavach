# Partner payload samples

Production-shaped **EvaluateRequest** examples for Indian structured-credit integrations. These are integration references — not golden test oracles (see `golden/finance/v0/`).

## Layout

| Path | Use |
|---|---|
| `finance/credit_underwriting_v1_request.json` | Single HTTP/gRPC evaluate body |
| `finance/credit_underwriting_v1_batch.ndjson` | NDJSON input for `kavach-batch run` |
| `finance/scenarios/manifest.json` | Expected outcomes for policy simulation (CI) |
| `finance/scenarios/credit_underwriting_v1.ndjson` | LOS-shaped scenario library for simulation |

## Field notes

- **`input`** carries the partner LOS / bureau payload. Extra keys are allowed; the finance model schema requires `debt_ratio` only.
- **`credit_score`** and **`bureau_score`** mirror a typical CIBIL-style bureau pull; both map to the model's `credit_score` field for v1.
- **`monthly_income_inr`** and **`income`** are duplicated for partner ergonomics; policy rules use `debt_ratio` and optional thresholds on declared fields.
- **`correlation_id`** must be unique per model evaluation; reuse with the same `model_id` triggers idempotency (ADR-001 §11).
- **`consent.timestamp`** and **`decision_time`** must be within the server's clock-skew window (default ±5 minutes).

## Quick validation

```bash
# Schema contract (CI)
cargo test -p kavach-domain partner_finance

# Batch shadow run (memory evidence)
cargo run -p kavach-batch -- run \
  --input partner/finance/credit_underwriting_v1_batch.ndjson \
  --output /tmp/kavach-partner-out.ndjson \
  --pack packs/finance/v0.yaml \
  --model models/finance/credit-underwriting-v1.yaml
```

Update `decision_time` and `consent.timestamp` to the current UTC time if the batch run fails clock-skew validation.

## Policy simulation (git workflow)

For policy changes, use the manifest-driven harness instead of hand-editing timestamps:

```bash
./scripts/simulate-credit-underwriting.sh
```

See [docs/CREDIT_UNDERWRITING_SIMULATION.md](../docs/CREDIT_UNDERWRITING_SIMULATION.md) for the branch/PR workflow (`pack` + `scenarios/` + `manifest.json` in one commit).

## Privacy

Samples use synthetic identifiers only. Do not commit real PAN, Aadhaar, phone numbers, or account numbers. Kavach stores `input_digest` in evidence, not raw `input` (ADR-001 §8).
