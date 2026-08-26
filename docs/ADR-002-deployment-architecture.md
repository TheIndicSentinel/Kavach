# ADR-002: Deployment Architecture (Modular Monolith)

**Status:** Accepted  
**Date:** 2026-08-27  

## Context

The product must follow SOLID principles, scale to multi-sector packs, and remain operable on-prem in regulated environments. There is a request to use **microservices** from day one.

## Decision

**Build a modular monolith with clear service boundaries, not a microservices mesh in v1.**

### Why not microservices now

| Microservices cost (v1) | Kavach impact |
|---|---|
| Distributed evidence writes | Conflicts with fail-closed single-transaction evidence |
| Network latency between policy/evaluate/evidence | Breaks 50 ms end-to-end SLO |
| Operational overhead (8+ deployables, service mesh) | Solo/small team; bank VPC with minimal ops |
| Partial failure modes | Harder to reason about shadow vs enforce |
| Saga/compensation for audit chain | Unacceptable for governance evidence |

Industry practice for regulated on-prem v1: **well-factored monolith** or **2–3 deployable processes**, not N services with separate databases. Extract services when measured pain exists (throughput, team size, independent release cadence).

References: modular monolith pattern (Sam Newman), "monolith first" for unproven domains, ISO 27001 change control favouring fewer moving parts on customer metal.

### What we build instead

**Rust workspace = bounded contexts (SOLID at crate boundary):**

| Crate | Responsibility (SRP) | Future extract? |
|---|---|---|
| `kavach-domain` | Types, invariants, no I/O | Never — shared kernel |
| `kavach-policy` | CEL load/eval, pack versioning | Possible |
| `kavach-detect` | PII detectors (trait + finance impl) | Possible |
| `kavach-evidence` | Hash chain, verify CLI | Possible |
| `kavach-evaluate` | Pipeline orchestration | Core |
| `kavach-api` | HTTP + gRPC servers | Deploy unit 1 |
| `kavach-batch` | Batch ingest worker | Deploy unit 2 (A) |

**SOLID mapping:**

- **S:** One reason to change per crate.
- **O:** New sector = new pack file + optional `Detector` impl, not fork core.
- **L:** Trait implementations interchangeable in tests.
- **I:** Small traits (`Detector`, `PolicyEngine`, `EvidenceStore`).
- **D:** `kavach-evaluate` depends on traits; Postgres adapters live in `kavach-api` / infra crates.

**Deploy units (Milestone A):**

1. `kavach-api` — sync evaluate + health + metrics  
2. `kavach-batch-worker` — batch ingest (same domain, separate process for scale/isolation)  

**Shared:** one PostgreSQL, one evidence chain. Not database-per-service.

**Milestone B adds:**

3. Static console (React) served by API or CDN in customer VPC  
4. Cedar RBAC in API process  

### Path to microservices (Milestone C+)

Extract when justified:

- `kavach-batch-worker` already separate process → scale horizontally first  
- Policy compilation service if pack CI becomes heavy  
- Never split evidence chain across services without distributed transaction design approved in new ADR  

### Platform vs v1 scope

Sector-agnostic **types** from day one (`sector` field, pack-driven rules). v1 ships **finance pack only**. No detector marketplace, no `packs/general/v0.yaml`, no plugin loader in A/B.

`kavach-detect`: one trait, one finance implementation (Aadhaar/PAN/UPI/IFSC). General detectors in Milestone C.

## Consequences

- Single binary option remains valid for PoC (`kavach-api` embeds evaluate).  
- Bank install docs describe 2 containers + Postgres + IdP, not a service mesh.  
- Feature tracking maps to crates and OpenAPI paths, not 12 micro-repos.  
