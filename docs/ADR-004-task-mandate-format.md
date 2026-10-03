# ADR-004: Task Mandate Format, Issuance and Delegation

**Status:** Accepted  
**Date:** 2026-09-29  
**Deciders:** Kavach product/engineering  
**Related:** ADR-003 (authorization model), ADR-005 (evidence), ADR-006 (ports), ADR-007 (network boundary), [PRD](PRD.md) D2, D7, D11, FR-1, FR-8, FR-9

## Context

In Kavach, authority for an agent action comes from a business transaction, not from the agent's identity. The Task Mandate is the root of that authority: a signed, time-bound, subject-bound grant created from a system-of-record event (e.g. a loan crossing 30 days past due). Because the mandate is the root of authority, it is also the most valuable target for an attacker: if model output could create or widen a mandate, every downstream control would pass.

PRD D2 locks JWS v1 behind a codec with server-side delegation. This ADR defines the format, the issuance rules, delegation, capability references and revocation.

Nothing mandate-related exists in the codebase today. `kavach-domain` holds I/O-free types; existing request/response types use `schema_version` strings and `serde` with `SCREAMING_SNAKE_CASE` enums.

## Decision

### 1. Domain type

`Mandate` lives in `kavach-domain` (no I/O):

| Field | Meaning |
|---|---|
| `id` | Unique mandate identifier |
| `mv` | Mandate format version (`1`) |
| `tenant_id` | Tenant (ADR-005 §2) |
| `issuer` | Kavach issuing instance / key owner |
| `source { system, record_ref, event_id }` | The system-of-record event this mandate was derived from |
| `principal` | The business system or human session on whose behalf the task runs |
| `subject_ref` | Capability reference to the customer (§7) |
| `purpose` | Purpose code (e.g. `loan_recovery`) |
| `consent_refs[]` | Consent artefacts / contact-preference records relied on (PRD D7) |
| `resources[]` | Resource types the task may touch |
| `actions[] { name, param_constraints }` | Permitted actions and their parameter constraints |
| `data_fields[]` | Purpose-minimal fields that may be read |
| `channels[]` | Permitted contact channels |
| `window { tz, from_min, to_min, max_per_day }` | Business window (minutes of day in `tz`) and daily cap |
| `ceilings {}` | Numeric limits (e.g. `waiver_pct`) |
| `delegation { max_depth, allowed_agents[] }` | Delegation rules |
| `parent_id?`, `depth` | Delegation lineage |
| `nbf`, `exp`, `nonce` | Validity and uniqueness |

### 2. Encoding

- JWS compact serialisation, `alg: EdDSA` (Ed25519), protected header `typ: kavach-mandate+jws` and `kid`.
- Payload is canonicalised with **RFC 8785 (JSON Canonicalization Scheme)** before signing, so signatures are stable across implementations and languages.
- All encoding and decoding goes through a `MandateCodec` trait (`encode`, `decode_verify`). The domain type never depends on JWS, so a W3C Verifiable Credential profile can be added later as a second codec.
- Signing keys come from the `KeyProvider` port (ADR-006).

### 3. A signed mandate is necessary, not sufficient

Mandate **status** (`active`, `revoked`, `expired`) is authoritative in the mandate store. Every authorization verifies the signature **and** checks status, through a cache that is invalidated by `mandate.*` events (§8). A valid signature on a revoked mandate is rejected.

### 4. System-of-record events

Mandates are created only from system-of-record events (PRD FR-1):

- Envelope: JWS with `typ: kavach-sor-event+jws`, signed by a **registered issuer key** (one per source system).
- Checks, in order: issuer allowlist → signature → `event_id` uniqueness and nonce table (replay protection) → freshness ≤ 300 s against trusted time (ADR-003 §7) → JSON-schema validation → size limit.
- Every mandate field is derived from the event payload and tenant configuration. **No field is ever taken from free text or model output.**
- The receiving endpoint is `POST /v1/sor/events`; it is not reachable from the agent network (ADR-007).

### 5. Issuance validation

A mandate is rejected at issuance if any of the following hold:

- `subject_ref` is empty or a wildcard.
- Any ceiling exceeds the corresponding limit in the Passport of any agent eligible to hold it.
- `purpose` is not covered by the referenced consent artefacts.
- `exp` is later than the earliest referenced consent expiry.
- `data_fields` is not a subset of the fields the active pack permits for `purpose`.

### 6. Delegation (server-side)

- `POST /v1/mandates/{id}:delegate` requests a child mandate for a named sub-agent.
- Child = parent ∩ requested scope ∩ the sub-agent's Passport. Effective authority can therefore only narrow, and a sub-agent is also capped by its own Passport — the parent need not hold every permission a sub-agent might need.
- `depth = parent.depth + 1` and must not exceed `parent.delegation.max_depth`.
- The child is issued and signed by Kavach. There is no offline attenuation (no Biscuit/macaroons) in the MVP.

### 7. Capability references

- Sensitive values are never given to agents. Tools take typed opaque references of the form `ref:<type>:<opaque>` (e.g. `ref:borrower:B-9382`), issued per tenant.
- **Reference format (published rule).** `<type>` and `<opaque>` are each 1–128 characters of `[A-Za-z0-9_.-]`. The whole reference holds **at most 8 digits** in total, however they are spread, and nothing in it may read as a PAN. A system of record issues short, opaque ids: a short counter (`B-9382`) or a random id drawn from letters only. Random hexadecimal or numeric ids are not suitable, because they routinely hold more than 8 digits. A reference that breaks the rule is refused (`BLOCK`, reason `raw_identifier:<field>:<kind>`), not repaired. If a partner needs longer numeric ids, the limit is raised per field in the signed tool registry, never globally.
- A raw value in a parameter that the tool registration marks as reference-only (phone number, account number, PAN, Aadhaar, email, payment destination) results in `BLOCK`. Detected today: Indian mobile numbers, Aadhaar numbers (12 digits with a valid Verhoeff check digit), PANs, and any run of 9 or more digits, in any supported script and through separators. Detectors for UPI IDs, IFSC codes and account-number formats follow (PRD FR-5).
- References are resolved to real values **only inside the gateway**, after authorization, through the `ReferenceResolver` port (ADR-006, ADR-007).

### 8. Revocation and expiry

- Payment, dispute, consent withdrawal, agent quarantine or manual kill sets status to `revoked` and emits `mandate.revoked` on the `EventBus` (ADR-006).
- Consumers invalidate caches and the Credential Broker revokes credentials bound to the mandate.
- Expiry is automatic at `exp`; the record remains as evidence and its subject reference is subject to crypto-shredding (ADR-005 §7).

### 9. Implementation notes (M1.4)

- **Scope source.** A signed SoR event supplies facts only (`subject_ref`, `record_ref`, `consent_refs`, `principal`, `assigned_agent`). Purpose, actions, data fields, channels, window, ceilings, lifetime and delegation rules come from a governed `MandateTemplate` selected by `(tenant_id, event_type)`. This satisfies §4 (no field from free text or model output).
- **Issuer binding.** Each SoR signing key is registered for exactly one source system; an event is rejected unless its `system` matches the key's registration. Freshness is ±300 s against trusted time; replay protection keys on `(tenant, system, event_id)`.
- **Validation (§5) as implemented.** The holder's passport must allow the purpose and must cover the template's actions, data fields and ceilings (a ceiling absent from the passport is treated as not allowed). The purpose-to-fields mapping is currently the template; checking it against an agent policy pack arrives with M1.5.
- **Actions** are a set of action names; per-parameter constraints are expressed as integer `ceilings` for now and as Cedar policies in M1.5.
- **Ceilings** are integers (e.g. `waiver_bps`) so the canonical encoding never involves floating point.
- **Encoding.** Header `{alg: EdDSA, kid, typ}` and payload are RFC 8785 canonical; verification rejects non-canonical header or payload bytes, unknown fields, padding and trailing base64 bits, and tokens over 16 KiB. The signature is verified before the payload is parsed.
- **Revocation** cascades to every mandate delegated from the revoked one (`parent_revoked`) and publishes `MandateRevoked` events.
- **Storage** is in-memory in M1 (`kavach-mandate::memory`); Postgres tables with `tenant_id` arrive with evidence v2 (M2).

## Consequences

- Authority is traceable end to end: evidence records carry `mandate_id`, and every mandate carries its source event.
- Mandate issuance becomes the most sensitive write path; it is covered by threat-model v2 and by scenario 11 (forged mandate, replayed event).
- JCS canonicalisation introduced here is reused by evidence v2 (ADR-005 §4).
- Adding a Verifiable Credential representation later requires a new codec only.

## References

- [PRD](PRD.md) D2, D7, D11, FR-1, FR-8, FR-9; acceptance scenarios 5, 7, 8, 11
- RFC 7515 (JSON Web Signature), RFC 8037 (EdDSA in JOSE), RFC 8785 (JSON Canonicalization Scheme)
- ReBIT Account Aggregator consent artefact specification (field subset used by `LocalConsentFixture`)
