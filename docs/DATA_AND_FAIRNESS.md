# Data and Fairness

**Status:** Phase 0 skeleton  
**Product:** Kavach  

## Data minimisation

### Never stored in evidence or logs

- Raw `input` JSON from evaluate requests  
- Aadhaar, PAN, full account numbers, full prompts  
- Passwords, API secrets, session tokens  

### Stored

- `input_digest` (SHA-256 of canonical input)  
- `pii_tokens[]` (references to ephemeral tokenization, not values)  
- `policy_decision`, `returned_decision`, `reason_codes[]`, pack/model metadata  
- Service identity id (mTLS/HMAC key id)  

### RAM-only

- Full `input` exists only in memory for CEL evaluation; discarded after request.

## Consent

Kavach checks **presence** of a consent object and **purpose match** with the request. It is **not** a DPDP Consent Manager. `consent.valid` is ignored in v1.

## Fairness

### Hot path (evaluate)

- Per-record CEL rules only: e.g. DTI threshold, prohibited use of a declared protected field if present in input schema.  
- **No cohort disparity** on a single row.  
- **No surname → caste inference.**

### Batch reports (Milestone B)

Two report types via Polars (`kavach-batch fairness`):

1. **Non-discrimination / disparity** — approval rate gaps on lawfully held declared attributes; sample-size guards.  
2. **Inclusion monitoring** — PSL/inclusion segments where applicable.

```bash
kavach-batch fairness \
  --requests batch_requests.ndjson \
  --results batch_results.ndjson \
  --report disparity \
  --attribute input.customer_segment \
  --output disparity_report.json
```

Schema: `schemas/fairness-report.schema.json`. Golden oracle: `golden/finance/fairness/`.

Attributes used in production require partner legal sign-off. MVP `caste_proxy_score` is a **golden test fixture only** (`golden/finance/mvp_mechanics/`), not a production field.

## Retention and erasure

- Tenant-configurable retention on evidence (Milestone B).  
- DPDP erasure: tombstone by `evidence_id` preserving chain integrity (Milestone B).

## Tenancy

v1: single-tenant on-prem, no `org_id`.
