# Second Review

Changes that need a second reviewer before v0.1 is tagged. One person wrote and merged them; this list is what an independent reviewer works through. It is kept up to date in the pull request that adds or clears an entry.

## Areas that always need one

- **Keys:** signing, key providers, key formats, key ids.
- **Credentials:** the broker, JWS and JWE, what a provider accepts.
- **Data plane:** authorization, the gateway, evidence, identifier detection.
- **Authentication:** tokens, certificates, HMAC, request parsing.
- **Migrations and database roles.**

## Open

| PR | Area | What to check |
|---|---|---|
| #94 | Keys, evidence | `kavach_ports::jcs::to_vec` is the only canonicaliser on signed and hashed paths; safe-integer bounds; output unchanged for valid input (vectors) |
| #96 | Authentication | HMAC v2 skew check with `abs_diff`; no other caller-controlled arithmetic in `hmac_auth` |
| #97 | Data plane | PAN and Aadhaar rules, the at-most-8-digits reference rule, where each is applied (extraction and core), false-positive risk |
| #99 | Authentication | Bearer-token header must be a UTF-8 JSON object before `jsonwebtoken` parses it |
| #103 | Keys, evidence | Canonical JSON refuses the serde raw-value key anywhere |
| #105 | Keys | PKCS#11 provider: key-attribute checks (generated in the HSM), startup proof, session pool and reconnect, fail-closed paths, `block_in_place` in the evidence commit |
| #106 | Data plane (policy) | `contained` around the CEL parser and interpreter; that a contained panic becomes a refused pack or a recorded BLOCK |
| #110 (K2) | Keys | Per-role HSM wiring (`signing.rs`): that a listed role never falls back to a file; key-separation checks on HSM public keys; strictness tied to `--insecure-dev` only; PIN file handling; fail-closed signing; `/v1/runtime` health |
| #111 (HSM recovery) | Keys | `reconnect`: restarting the module after a failed reconnect, re-finding the slot by label, which errors count as recoverable; that an outage never lets a call through unsigned |
| #112 (K3, key rotation) | Keys | `previous_mandate_keys`: verify-only, never a signing key; refusal of the current key by id or material; that removing an entry ends the old mandates' authority; the runbook's compromise steps |
| #114 (key limits) | Evidence verification | `KeyValidity::refuses`: the kept-checkpoint exception, the seq used for each kind (record, outcome, checkpoint, manifest), that a violation is a hard failure |
| #113 (export key in an HSM) | Keys | `Signing::Hsm` in the export command: the `export-` check before the HSM is opened, strict key attributes with no relaxation, PIN file handling |
| #107 | Authentication (request parsing) | The strict-JSON walk; that every route with free-form JSON uses it; that error responses are unchanged |
| C3a, C3c (`why`, evidence reads) | Data plane, authentication | `GET /v1/agent-decisions/{id}` and `GET /v1/decision-events/{id}` (the latter applies tombstone redaction and never holds the evaluate lock across an await): `read_evidence` granted to admins only; every read audited before the record is returned, and refused if the audit write fails; rate limit; no raw reference, destination, token or credential in the response. Sequential ids mean by-id is **not** an enumeration control. `kavach why` takes trusted keys from local files only |

## Done

None yet. When a reviewer has worked through an entry, move it here with the reviewer and the date, and link any follow-up.
