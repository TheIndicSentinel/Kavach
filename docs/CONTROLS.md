# Controls Mapping (skeleton)

Mapped, not claimed. Product generates evidence; counsel signs compliance.

| Control area | Standard | Kavach feature | Milestone |
|---|---|---|---|
| Model inventory | ISO 42001 | `ModelRecord`, promotion workflow | B |
| Policy lifecycle | ISO 42001, FREE-AI | Pack draft→activate→rollback | B |
| Decision audit trail | FREE-AI, DPDP | Hash-chained `DecisionEvent` | A |
| Access control | ISO 27001 | mTLS/HMAC (A), Cedar RBAC (B) | A/B |
| Fairness monitoring | FREE-AI | Polars disparity + inclusion reports | B |
| Incident records | FREE-AI | Exception/incident table | B |
| Minimisation | DPDP | `input_digest` only | A |
| Erasure | DPDP | Tombstone by evidence_id | B |
| Change management | ISO 27001, SOC 2 | Admin audit log | B |
| Supplier AI | FREE-AI | `origin: vendor` on model | A |
