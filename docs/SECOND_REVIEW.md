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
| Key limits (this PR) | Evidence verification | `KeyValidity::refuses`: the kept-checkpoint exception, the seq used for each kind (record, outcome, checkpoint, manifest), that a violation is a hard failure |
| #107 | Authentication (request parsing) | The strict-JSON walk; that every route with free-form JSON uses it; that error responses are unchanged |

## Done

None yet. When a reviewer has worked through an entry, move it here with the reviewer and the date, and link any follow-up.
