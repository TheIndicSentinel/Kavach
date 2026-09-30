# ADR-006: Ports and Adapters

**Status:** Accepted  
**Date:** 2026-09-29  
**Deciders:** Kavach product/engineering  
**Related:** ADR-002 (modular monolith, SOLID at crate boundary), ADR-003, ADR-004, ADR-005, ADR-007, [PRD](PRD.md) D6, D12, NFR-1, NFR-3, NFR-4

## Context

The MVP must run entirely on free, local infrastructure (Keycloak, OpenBao, PostgreSQL, Ollama) while remaining able to move to enterprise infrastructure (HSM/KMS, Vault/CyberArk, enterprise IdPs, NATS/Kafka) **without rewriting the core** (PRD D6, NFR-4). ADR-002 already requires the core to depend on traits, with adapters at the edges.

Today:

- The only ports are `EvidenceStore` and `IncidentRecorder` in `crates/kavach-evaluate/src/ports.rs`. They are **synchronous**; the Postgres adapter bridges to async with `block_in_place` + `block_on`.
- `PolicyEngine` is a concrete struct (`crates/kavach-policy/src/engine.rs`), not a trait.
- The `Detector` trait named in ADR-002 does not exist in code.
- There is no shared place for port definitions, so new crates (broker, gateway, mandate, keys) would otherwise depend on each other directly.

PRD D12 limits the "second implementation" rule to security-critical ports; everything else may use fixtures.

## Decision

### 1. A dedicated ports crate

Create `kavach-ports`: trait definitions and typed error types only, no I/O and no adapter dependencies. Core crates (`kavach-evaluate`, `kavach-mandate`, `kavach-gateway`, …) depend on `kavach-ports`; adapter crates implement it. This prevents dependency cycles as the workspace grows.

### 2. Asynchronous ports

Ports use native `async fn` in traits (stable Rust, edition 2021) with `Send` bounds. `EvidenceStore` is migrated to async and the `block_in_place` bridge is removed.

### 3. Typed error classes

Every port error is classified:

| Class | Meaning | Default handling |
|---|---|---|
| `Unavailable` | Dependency down, timeout, lost sync | Critical actions fail closed (`BLOCK`); low-risk per risk policy |
| `Rejected` | Dependency answered "no" (bad signature, revoked, replay) | `BLOCK` with reason code |
| `Invalid` | Malformed input | `400` — never disguised as `PASS` (ADR-001) |

This classification drives the ADR-001 fail-closed matrix and PRD NFR-3 uniformly across all dependencies.

### 4. Port inventory

**Security-critical ports** — each has a real MVP adapter, a test double, and a shared **conformance test suite** in `kavach-ports-testkit` that every adapter (current and future) must pass:

| Port | MVP adapter | Test double | Later enterprise adapters |
|---|---|---|---|
| `IdentityProvider` | Keycloak / JWKS | Static JWKS | Entra, Okta, SPIFFE/SPIRE |
| `CredentialBroker` | Proxy injection; OpenBao dynamic secrets; Keycloak token exchange | In-memory | Vault, CyberArk |
| `KeyProvider` | Local encrypted keystore (Ed25519 signing, AEAD data keys) | In-memory | PKCS#11 HSM, cloud KMS |
| `EvidenceStore` | PostgreSQL (ADR-005) | In-memory chain | PostgreSQL cluster, archive tiering |
| `SystemOfRecord` | Signed-webhook receiver (ADR-004 §4) | Fixture emitter | LOS / LMS / CRM connectors |
| `EventBus` | PostgreSQL outbox + LISTEN/NOTIFY | In-process channel | NATS, Kafka |
| `TimeSource` | Kernel clock-sync status (ADR-003 §7) | Fake clock | — |
| `ReferenceResolver` | PostgreSQL reference vault (ADR-004 §7) | In-memory map | Enterprise tokenisation / vault |

**Fixture-only ports** (reference or non-security-critical):

| Port | MVP implementation |
|---|---|
| `ConsentSource` | `LocalConsentFixture` shaped as a ReBIT consent-artefact subset (PRD D7) |
| `Detector` | Rust recognisers for Aadhaar (checksum), PAN, UPI, IFSC, Indian phone numbers; optional Presidio bridge |
| `EvidenceAnchor` | Off by default; file-based implementation for tests |

**Engine ports:** `PolicyEngine` (CEL) becomes a trait; a new `AuthorizationEngine` trait wraps Cedar (ADR-003). Existing behaviour is preserved behind the traits.

### 5. Adapter selection

Adapters are selected by startup configuration only — no dynamic plugin loading. Adapter crates follow the existing naming: `kavach-broker`, `kavach-keys`, `kavach-events`, `kavach-identity`, etc. Configuration that selects a test double is refused when any resource is in enforce mode.

### 6. Licence rule

- Linked dependencies of every crate must pass `deny.toml`. A comment is added to `deny.toml` stating that `BSL-1.0` is the Boost Software License, not the Business Source License.
- External services used over the network (Keycloak — Apache-2.0; OpenBao — MPL-2.0; PostgreSQL; Ollama) are not linked and are covered by the PRD D6 free-source rule and the SBOM, not by `deny.toml`.

### 7. Implementation timing (M1.1)

- `kavach-ports` (traits, `PortError`/`ErrorClass`), `kavach-keys` (`LocalFileKeyProvider`, `InMemoryKeyProvider`) and `kavach-ports-testkit` (`FakeClock`, `InMemoryReplayGuard`, conformance suites) landed in M1.1.
- `EvidenceStore` / `IncidentRecorder` moved to `kavach-ports` and stay **synchronous** until evidence v2 (ADR-005, M2) rewrites the storage adapter; `kavach-evaluate` re-exports them. New ports are async (`impl Future + Send`), except `TimeSource`, which is synchronous (reading a clock does not block).
- Because `EvidenceStore`'s signature uses `kavach-evidence` types, `kavach-ports` depends on `kavach-evidence` and holds the `MemoryChain` implementation.
- `TimeSource` ships with `SystemClock` (sync status `Unknown`) and `FakeClock`; the kernel clock-sync adapter (ADR-003 §7) needs a small FFI crate and arrives in M3, when agent resources first run in enforce mode.
- `MandateStore` and `EventBus` are defined with the mandate service (M1.4) rather than ahead of their types.

## Consequences

- Enterprise infrastructure is added by writing a new adapter that passes the conformance suite — no core changes.
- The conformance suites make "test double" a real guarantee rather than a mock that drifts from production behaviour.
- One-time refactor cost: moving `EvidenceStore`/`IncidentRecorder` into `kavach-ports`, making them async, and converting `PolicyEngine` to a trait. Existing tests must pass unchanged in behaviour.

## References

- ADR-002 (bounded contexts, SOLID mapping, deploy units)
- [PRD](PRD.md) D6, D12, NFR-1, NFR-3, NFR-4
- `crates/kavach-evaluate/src/ports.rs`, `crates/kavach-storage/src/postgres/evidence.rs`, `crates/kavach-policy/src/engine.rs`
- `deny.toml`
