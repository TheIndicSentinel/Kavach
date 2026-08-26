# Threat Model (Phase 0 skeleton)

**Scope:** Milestone A evaluate path  

## Assets

- Policy packs (integrity)  
- Evidence hash chain (integrity, non-repudiation)  
- Service credentials (mTLS/HMAC)  
- Model records  

## STRIDE summary

| Threat | Mitigation |
|---|---|
| Spoofing (caller) | mTLS or HMAC with key rotation |
| Tampering (pack) | Git + activate audit (B); file checksum in A |
| Tampering (chain) | Hash chain + offline verify CLI |
| Repudiation | Append-only evidence + service identity on every row |
| Info disclosure | No raw input in DB; OTel without payloads |
| DoS | Body size limits, rate limits, CEL timeout/allocation cap |
| Elevation | No caller-set enforce mode; Cedar RBAC in B |

## CEL as untrusted code

- Wall-clock timeout  
- Allocation cap  
- No I/O from expressions  
- Max pack size  
- Pinned CEL interpreter version  

## Shadow infra failure

- Do not write fake healthy evidence  
- Incident record with `correlation_id`  
- Alert on-call  

## Insider: pack edit

- Milestone B: dual control on activate, admin audit log  

## Restore

- Postgres restore → run `kavach evidence verify` before accepting traffic  
