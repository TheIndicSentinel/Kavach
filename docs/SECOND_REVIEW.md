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
| Dev clock (`--clock`, `POST /v1/dev/clock`) | Data plane, evidence | That `Dataplane::build` refuses a dev clock without `--insecure-dev` or with any non-`dev-` signing key (including the mandate key, checked after the mandate config loads) or an HSM; forward-only moves; audit before the move; that `dev_fixed` reaches records and checkpoints and both verifiers refuse it without `--dev` |
| C3a, C3c (`why`, evidence reads) | Data plane, authentication | `GET /v1/agent-decisions/{id}` and `GET /v1/decision-events/{id}` (the latter applies tombstone redaction and never holds the evaluate lock across an await): `read_evidence` granted to admins only; every read audited before the record is returned, and refused if the audit write fails; rate limit; no raw reference, destination, token or credential in the response. Sequential ids mean by-id is **not** an enumeration control. `kavach why` takes trusted keys from local files only |
| #129 (dev stack auth) | Authentication | `kavach dev up`'s operator API requires the operator token (Cedar); the Host and `X-Kavach-Principal` guards on every dev listener; that nothing relaxes them outside a dev stack |
| #133 (C6a, problem details) | Data plane, authentication | RFC 9457 bodies on the operator, agent and system-of-record listeners: a 5xx never carries its cause; `detail` never repeats caller input; `WWW-Authenticate`, `Retry-After`; the legacy `error` member equals `detail` |
| #142 (C7, release tooling) | Supply chain | `release.yml`: every action pinned by SHA; permissions per job; provenance attestation for every artifact; a tag only drafts a pre-release; the dry run in CI; that no token reaches a build step |
| #145 (pseudonym redaction) | Data plane (privacy) | Redaction exempted by field type (`output::Digest`, `DIGEST_FIELDS`, `psn:` plus up to 64 lowercase hex), never by widening the pattern; that no secret-shaped value can pass as a digest |
| #153 (replay after an unknown outcome) | Data plane | The gateway's retry answers: `Ok(Some(stored))` returns the stored reply for any outcome, `unknown` included; only `Ok(None)` or an error is `in_flight`; that nothing is re-minted or re-sent |
| #154 (R1a, revocation by event) | Data plane, migrations | `is_revoking_event` decodes the token **unverified** and only routes; the event is fully verified by whichever path handles it; `nbf <= occurred_at` ordering; replay and conflict by stored content hash; `mandate_in_force` re-check before `broker.issue` and its failure mapping (`mandate_revoked`, `mandate_unavailable`); migration 014, including `kavach_grant_runtime()` redefined in full |
| #155 (R1b-1, record kinds) | Migrations | Migration 015: `kind` default equals the signed payload's kind; the per-kind CHECKs; the partial unique indexes; grants and triggers unchanged. The CHECKs were added validated (a full-table check under a lock); the rule from the next migration on is `NOT VALID` then `VALIDATE` (`MIGRATIONS.md`) |
| #156 (R1b-2, revocation records) | Evidence, keys | `ChainRecord` read by its signed kind and unknown kinds refused; the kind check in `check_record`; `record_pseudonym` under its own HMAC label; `append_revocation` idempotent under the partition lock (one record per event, other content `Rejected`); the reconciler never advances its watermark past a record it could not write; migration 016 |
| #157 (R1b-3, bundle format 2) | Evidence verification | `BUNDLE_VERSIONS = [1, 2]`; a version 1 bundle may hold decisions only; unknown kinds are refused by file and line, never skipped; the `bundle-v1` vector is byte-identical |
| #159 (R1c-2, attacks v4) | Authentication, data plane | `claimed_tenant` reads the event **unverified** and is used only to refuse; `GET /v1/agent-revocations/{system}/{event_id}` (`read_evidence`, rate limit, audited before it returns, no loan reference in the body); that the attack runner's forged-key and backdated events exist only in the test tooling |
| #168 (specs and independent verifier) | Evidence verification | `parse_strict` refuses a repeated member name in records, outcomes, checkpoints, manifest and keys; `check_record` refuses a `hash_alg` other than `v2` before the hash is judged |
| #169 (mandate and SoR-event spec, event digest) | Data plane, evidence verification | `Mandate::check_form` runs in `check_record` (verify path): that nothing Kavach issues fails it (templates are validated by the same rules) and that it uses the mandate's own `nbf`/`exp`, never the clock; `event_digest` / legacy `event_sha256` exactly-one rule (`RevocationPayload::digest`, `ChainEntry::form`); that `same_event` accepts either stored form and nothing else; legacy records re-serialise byte-identically |
| #162 (orderly stop) | Data plane | `tool_call` runs the call in a task of its own (`Arc<AppState>` and an owned agent identity; nothing committed before the spawn); a panic in the task is a generic 500 and the in-flight counter drops (guard); `InFlight::drain` is armed before it checks; `stop_and_checkpoint` exits non-zero when a listener or a call did not finish |
| Agent-only mode | Authentication, data plane | The router omits the credit-track routes and the console fallback; `change_requests::propose` refuses in the mode; gRPC is not started; startup fails without agent surfaces; that no route is added to the operator router outside the `if agent_only` split without a decision |

**Coming, and security-critical when it lands:** binding each system-of-record issuer key to a tenant (today a key is bound to a `system` only, so on a shared stack one tenant's issuer could sign for another). It gets its own test (one tenant's key signs for another and must be refused) and an entry here.

## Done

None yet. When a reviewer has worked through an entry, move it here with the reviewer and the date, and link any follow-up.
