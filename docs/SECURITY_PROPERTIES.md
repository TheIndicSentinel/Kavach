# Security Properties and Limitations

This document states exactly what Kavach guarantees, what is planned, and what it does **not** protect. It is updated in the same pull request as any change to a guarantee ([PRD](PRD.md) NFR-6). Claims here must never be stronger than the implementation.

**Version:** draft for M0 (Decision Governance implemented; Agent Authorization planned).

## Guaranteed today (Decision Governance)

| Property | Mechanism | Verified by |
|---|---|---|
| Evidence records form a tamper-evident chain that can be verified offline | SHA-256 hash chain; `kavach-evidence verify` | `crates/kavach-evidence` tests; golden chain tests |
| A caller cannot switch a model into enforce mode | Governance mode is read only from the model record (ADR-001 §4) | `crates/kavach-evaluate` tests |
| Pack activation, rollback and model changes need two distinct principals | Dual control (`X-Kavach-Principal` ≠ `X-Kavach-Approver`), both authorised by Cedar | `crates/kavach-api/tests/http_api.rs` |
| Access control is on by default | `--access-control` defaults to `cedar`; disabling requires `--insecure-dev` and prints a warning | `crates/kavach-api/src/config.rs` tests |
| A pack file changed on disk after activation is not silently reloaded | SHA-256 digest recorded on activation; rollback and model update refuse a mismatch (HTTP 409, audited); optional `--pack-sha256` startup pin (API and batch) | `crates/kavach-policy` tests; `rollback_refuses_tampered_previous_pack` |
| When evidence cannot be written in enforce mode, the decision is `BLOCK` | ADR-001 fail-closed matrix | `crates/kavach-evaluate` tests |

## Planned for the MVP (not yet guaranteed)

Each becomes a guarantee only when its acceptance scenario passes in CI.

| Property | ADR | Acceptance scenario |
|---|---|---|
| For **brokered resources**, an agent without authority holds no credential to act | ADR-006, ADR-007 | 1, 11 |
| Actions stay within the mandate's subject, purpose, window, fields and ceilings | ADR-003, ADR-004 | 3, 4, 5 |
| Delegated authority only narrows | ADR-004 §6 | 7 |
| Critical actions need a human approval bound to the exact action, yielding a single-use credential | ADR-003 §5, PRD D17 | 6 |
| A minimal signed decision record is written before any credential for a critical action | ADR-005 §6 | 10 |
| Critical actions are blocked when a required dependency or trusted time is unavailable | ADR-003 §7, ADR-006 §3 | 12 |
| Subject references on the evidence chain can be erased by key destruction without breaking verification | ADR-005 §7 | 10 |
| Packs are signed; unsigned packs cannot be activated | ADR-006 (`KeyProvider`) | — (M1) |

## Not guaranteed

- **Resources not routed through Kavach.** The agent guarantees apply only to resources brokered by the Kavach gateway and credential broker, deployed with the network isolation in ADR-007.
- **`--insecure-dev` mode.** Every request is allowed; for local development only.
- **Legal or regulatory compliance.** Packs are controls *mapped to* regulations and are labelled guidance; they are not legal advice or a compliance certification.
- **v1 evidence signatures.** Existing `decision_event` records are hash-chained but not signed; checkpoint signing arrives with ADR-005.
- **Client-supplied time on `/v1/evaluate`.** `decision_time` is still used (within ±300 s) for pack-effective selection until ADR-003 §8 is implemented.
- **CEL memory limits.** `max_alloc_bytes` is declared in the pack schema but not yet enforced.
- **High availability, HSM/KMS key protection, air-gapped deployment** — Stage 2.
- **Correctness of data in the customer's systems of record.**
- **Production hardening of the reference implementation.** The MVP demo is a reference implementation, not a security certification.
