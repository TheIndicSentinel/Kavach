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
| If a pack file's bytes change after a digest was recorded, **rollback and model update** refuse to load it | SHA-256 digest recorded on activation; mismatch → HTTP 409, audited (`*_refused`); reloads with no recorded digest are allowed but audited (`*_unpinned`) | `rollback_refuses_tampered_previous_pack` |
| **Startup** refuses a pack whose bytes differ from an operator-supplied digest | `--pack-sha256` / `KAVACH_PACK_SHA256` on `kavach-api` and `kavach-batch run` (optional) | `crates/kavach-policy` loader tests |
| A failed pack/model change leaves live traffic on the previous pack | Validate, then persist pointers and audit, and only then swap the live evaluator | `crates/kavach-api` lifecycle code |
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
- **Caller authentication by default.** With Cedar on, the principal is the name the client sends in `X-Kavach-Principal`. Callers are authenticated only when HMAC (`--hmac-secret`) or mTLS (`--tls-client-ca`) is configured; the API warns at startup when neither is.
- **Pack integrity at startup without a pin.** Without `--pack-sha256`, a restart loads whatever bytes are at `--pack` and records their digest as current; the Postgres pointer row is not yet the startup source of truth (planned next). API and batch must be started with the same pin to guarantee they evaluate the same bytes.
- **Pack integrity during evaluation.** Evaluation uses the compiled pack held in memory and does not re-read or re-hash the file.
- **Pack authenticity.** A digest proves "same bytes as last measured", not "approved by a trusted signer". Signed packs are planned (M1).
- **Pack bytes on the evidence chain.** Evidence identifies packs by `pack_id` and `pack_version`, not by digest; the new agent record type carries the digest (ADR-005).
- **Integrity of the runtime pointer row.** Anyone with write access to Postgres can change pointer paths and digests; governance events on the evidence chain are planned (ADR-005).
- **Legal or regulatory compliance.** Packs are controls *mapped to* regulations and are labelled guidance; they are not legal advice or a compliance certification.
- **v1 evidence signatures.** Existing `decision_event` records are hash-chained but not signed; checkpoint signing arrives with ADR-005.
- **Client-supplied time on `/v1/evaluate`.** `decision_time` is still used (within ±300 s) for pack-effective selection until ADR-003 §8 is implemented.
- **CEL memory limits.** `max_alloc_bytes` is declared in the pack schema but not yet enforced.
- **High availability, HSM/KMS key protection, air-gapped deployment** — Stage 2.
- **Correctness of data in the customer's systems of record.**
- **Production hardening of the reference implementation.** The MVP demo is a reference implementation, not a security certification.
