# Security Properties and Limitations

This document states exactly what Kavach guarantees, what is planned, and what it does **not** protect. It is updated in the same pull request as any change to a guarantee ([PRD](PRD.md) NFR-6). Claims here must never be stronger than the implementation.

**Version:** draft for M0 (Decision Governance implemented; Agent Authorization planned).

## Guaranteed today (Decision Governance)

| Property | Mechanism | Verified by |
|---|---|---|
| Editing an individual evidence row without re-hashing the rest of the chain is detected by verification | SHA-256 hash chain; `kavach-evidence verify` over an exported file | `crates/kavach-evidence` tests; golden chain tests |
| An evaluate caller cannot switch a model into enforce mode | Governance mode is read only from the model record (ADR-001 §4), never from the request | `crates/kavach-evaluate` tests |
| **With OIDC configured**, every API principal is the subject of a verified access token | `Authorization: Bearer` JWT checked against the configured issuer, audience, JWKS (`kid` required), expiry and not-before; only RS256/PS256/ES256/EdDSA accepted; `X-Kavach-Principal` refused (401) unless `--insecure-dev`; token + header together → 400 (ADR-008) | `crates/kavach-api/tests/oidc_api.rs` |
| **With `--mtls-principal-san`**, a machine caller's principal is the SAN of its verified client certificate | rustls verifies the chain against `--tls-client-ca`; the leaf's single URI (or DNS) SAN is the principal, over HTTP and gRPC; zero or several SANs → 401; certificates from another CA fail the handshake | `crates/kavach-api/tests/mtls_api.rs` |
| Cedar access control cannot start without an authenticated principal source | `--access-control cedar` without OIDC or mTLS principals fails startup unless `--insecure-dev`; `--mtls-principal-san` without `--tls-client-ca` fails startup | `cedar_without_an_authenticated_source_is_refused` |
| Group permissions come from the token or the entities file, never from request headers | Token groups claim → Cedar `Kavach::Group` parents, merged with static memberships | `groups_from_credentials_grant_group_permissions`; `oidc_api.rs` |
| With `--hmac-secret`, a signed `/v1/evaluate` request cannot be replayed or re-targeted | HMAC v2 over timestamp (±300 s), single-use nonce, method, path and body; v1 body-only signatures rejected | `hmac_v2_accepts_once_and_rejects_replay_and_v1`; `hmac_auth` unit tests |
| **Governance changes need two different principals** (pack activate/rollback, model update, retention change, erasure, retention run) | Maker-checker change requests (ADR-009): proposal authorised by `propose_<kind>`; approval by a principal with `approve_<kind>`, authenticated with an OIDC token (certificate principals cannot approve), whose source-qualified identity and id differ from the proposer's | `change_request_needs_a_distinct_approver_and_the_shown_digest`, `change_requests_use_token_identities`, `certificate_principals_may_propose_but_never_approve` |
| The approver approves exactly what was proposed, against the state it was proposed on | Parameters and binding (pointer version, pack digest, retention value, frozen retention set) fixed at proposal; `change_digest` must be echoed; binding re-checked at approval, stale requests fail | `approval_fails_when_the_runtime_moved_since_proposal`, `retention_applies_exactly_the_approved_set` |
| A change request applies at most once, including across replicas | Approval runs in one transaction: request row locked while `pending`, pointer version compared under lock, effect + audit + status committed together | `concurrent_approvals_on_two_replicas_apply_once` |
| Decided change requests cannot be edited or deleted through the application or by SQL `UPDATE`/`DELETE` | Database trigger on `change_requests` | `change_requests_are_immutable_once_decided` |
| **Postgres mode:** approved model status and governance mode survive restarts, and API and batch evaluate with the same governed values | `model_state` written in the approval transaction; one `govern_model()` used by API and batch; evidence and batch-job rows record the governed mode (ADR-010) | `governed_mode_survives_restart_and_reaches_evidence`, `run_batch_uses_the_governed_model` |
| **Postgres mode:** editing the model YAML cannot change the running model or its mode | Model file path and SHA-256 pinned on the runtime pointer; a mismatch refuses API and batch startup; `--bootstrap-model` re-pins path and digest only (audited), never status or mode | `edited_model_file_is_refused_and_bootstrap_keeps_governed_state`, `batch_never_baselines_and_refuses_a_changed_model_file` |
| An approved mode change is not silently reverted when upgrading from H3a | The baseline is refused when the last approved `update_model` differs from the YAML | `baseline_refused_when_approved_history_diverges_from_yaml` |
| A lower model version is never activated without the approver seeing it | `activate_model` needs `allow_downgrade`, which is in the change digest | `activate_model_switches_versions_and_guards_downgrades` |
| **With trusted signers configured**, no model file is loaded without a valid signature from a model signer | `<model>.sig` over id, version and SHA-256 (distinct prefix from packs); signer `roles` checked; API startup, `activate_model`, batch | `model_signatures_bind_id_version_digest_and_role`, `signed_packs_required_when_signers_configured` |
| Checks that would make a change unusable run before anyone approves it | Pack id match, signature and digest pin, model schema and **supplier controls** (vendor model in enforce needs `production`) at proposal and again at approval | `supplier_controls_are_checked_at_proposal` |
| Access control is on by default | `--access-control` defaults to `cedar`; disabling requires `--insecure-dev` and prints a warning | `crates/kavach-api/src/config.rs` tests |
| If a pack file's bytes change after a digest was recorded, **rollback and model update** refuse to load it | SHA-256 digest recorded on activation; mismatch → HTTP 409, audited (`*_refused`); reloads with no recorded digest are allowed but audited (`*_unpinned`) | `rollback_refuses_tampered_previous_pack` |
| **Startup** refuses a pack whose bytes differ from an operator-supplied digest | `--pack-sha256` / `KAVACH_PACK_SHA256` on `kavach-api` and `kavach-batch run` (optional) | `crates/kavach-policy` loader tests |
| **Postgres mode:** API and batch refuse to start with a pack path or bytes that differ from the governed runtime pointer | Pointer row written only by approved change requests (plus an audited first-start baseline); `--bootstrap-pack` override is audited (API only) | `crates/kavach-storage` startup tests |
| API RBAC policies are validated against the Cedar schema; a typo'd action or unknown entity type fails startup | Compiled-in schema, strict validation; principal header used as a literal id | `crates/kavach-auth` tests |
| Pack selection on `/v1/evaluate` uses trusted server time | Client `decision_time` validated (±300 s) and recorded only | `pack_effective_uses_server_time_not_client_time` |
| **With trusted signers configured**, no pack is loaded without a valid signature from a trusted key | Detached Ed25519 signature `<pack>.sig` over the pack's SHA-256; checked at startup, activate, rollback and model update (API) and before batch runs; refusals audited (`*_refused`, `pack_signature_invalid`) | `crates/kavach-keys/tests/pack_signatures.rs`; `signed_packs_required_when_signers_configured` |
| Evidence names the pack that actually produced the decision | `pack_id` taken from the loaded pack (was the model record's binding) | `evidence_records_the_loaded_pack_id` |
| An idempotent retry returns the stored decisions; a different request under the same key is refused | Input digest (and `idempotency_key` when both present) compared with the stored row; mismatch → HTTP 409 / gRPC `ALREADY_EXISTS` / batch row failure | `idempotent_retry_returns_stored_decisions_even_if_policy_changed`, `same_key_different_input_is_a_conflict`, `evaluate_idempotency_conflict_returns_409` |
| A CEL/runtime policy failure is a recorded decision, not a transport error | Policy decision `BLOCK` with reason `POLICY_EVALUATION_ERROR`, written to evidence, plus an incident; ADR-001 §5 matrix applies (enforce `BLOCK`, sync shadow `PASS`) | `cel_error_is_a_recorded_block_with_an_incident` |
| A failed incident write is never silent | Incident recorders return errors; the API increments `kavach_incident_write_failures_total` and logs `ALERT`; batch logs `ALERT` per row | `incident_write_failure_is_surfaced` |
| Batch over historical data validates rows against a declared window | `kavach-batch run --decision-from/--decision-to` (RFC 3339); default remains ±300 s of now | `batch_window_accepts_historical_rows_and_rejects_outside` |
| Packs are bounded in size and complexity | ≤ 256 KiB, ≤ 200 rules, expressions ≤ 2048 chars, `timeout_ms` 1–1000 | `load_limits_reject_oversized_packs` |
| A failed pack/model change leaves live traffic on the previous pack | Validate, then persist pointers and audit, and only then swap the live evaluator | `crates/kavach-api` lifecycle code |
| When evidence cannot be written in enforce mode, the decision is `BLOCK` | ADR-001 fail-closed matrix | `crates/kavach-evaluate` tests |

## Planned for the MVP (not yet guaranteed)

Each becomes a guarantee only when its acceptance scenario passes in CI.

| Property | ADR | Acceptance scenario |
|---|---|---|
| For **brokered resources**, an agent without authority holds no credential to act | ADR-006, ADR-007 | 1, 11 |
| Actions stay within the mandate's subject, purpose, window, fields and ceilings | ADR-003, ADR-004 | 3, 4, 5 — enforced by `kavach-authz` Cedar policies; subject binding, waiver ceiling and contact window **formally proven in CI** (`kavach-cedar-analysis`, cvc5) along with "no policy can raise an evaluation error"; exposed via `/v1/authorize` in M1.6 |
| Agent contact happens only 08:00–19:00 IST, within a mandate window, on a mandate channel, below the daily cap; missing or out-of-range parameters (waiver, channel, fields, negative counts) are refused; each action needs its own permit | ADR-011 | 3, 4, 5 — library level in `kavach-authz`: 16 properties **formally proven in CI** (cvc5) with 7 weakened-policy mutants caught; permit coverage derived from the schema and checked at load; enforced on agent requests from H5 |
| A delegated mandate is valid only while its whole chain is valid; revocation and delegation cannot leave an active child under a revoked parent | ADR-011 | 7 — library level in `kavach-mandate`: signature, stored value, status, time and narrowing checked for every ancestor; atomic `insert_child`/`revoke_tree` with a contract suite (including a delegate-vs-revoke race) that the H5 Postgres store must also pass |
| Delegated authority only narrows | ADR-004 §6 | 7 — narrowing implemented and property-tested (2,000 cases) in `kavach-mandate`; enforced on agent requests from M1.6 |
| Critical actions need a human approval bound to the exact action, yielding a single-use credential | ADR-003 §5, PRD D17 | 6 — `@escalate` → `HUMAN_REVIEW` implemented and tested in `kavach-authz`; approval binding and single-use credentials arrive with M4 |
| A minimal signed decision record is written before any credential for a critical action | ADR-005 §6 | 10 |
| Critical actions are blocked when a required dependency or trusted time is unavailable | ADR-003 §7, ADR-006 §3 | 12 |
| Subject references on the evidence chain can be erased by key destruction without breaking verification | ADR-005 §7 | 10 |

## Not guaranteed

- **Agent inputs that are still caller-supplied.** In the agent-authorization library, the delegating agent (`by_agent`) and `contacts_today` come from the caller until H5 derives them from authenticated agent identity and stored counters. Until then they are unsafe inputs (ADR-011).
- **Contact-hours source.** The 08:00–19:00 IST floor follows RBI directions on recovery agents as summarised in our research; it awaits compliance sign-off and is guidance, not legal advice.
- **Delivery time on asynchronous channels.** Authorising a WhatsApp or SMS contact at 18:59 does not guarantee delivery before 19:00; a send-by deadline is planned with the H5 gateway.
- **Resources not routed through Kavach.** The agent guarantees apply only to resources brokered by the Kavach gateway and credential broker, deployed with the network isolation in ADR-007.
- **`--insecure-dev` mode.** Every request is allowed; for local development only.
- **Two identities for one person.** Distinct approval assumes the IdP gives each person one identity and assigns `change-approvers` only to people; two accounts for one person pass as two principals. That is an IdP and process control.
- **Proposer revocation during a pending request.** The proposer's rights are checked at proposal; a group removed in the IdP afterwards is not re-checked (their token is gone). Pending requests expire (default 24 h), and an approver can reject.
- **Break-glass.** Every governance change needs two people; with a single admin available nothing can change, including urgent erasure.
- **Change-request and audit tables against a database administrator.** The trigger stops application-level edits; a superuser can disable it. Insert-only roles and signed governance events are planned (P1, ADR-005).
- **Evidence integrity against a database writer.** The chain is unkeyed, unsigned and not externally anchored, so someone with write access to Postgres can rewrite and re-hash the whole chain, or truncate its tail, undetected. There is no built-in export from Postgres yet. Signed chain heads, an INSERT-only database role and an export command are planned (P1, ADR-005).
- **Governed model state in memory mode.** Without Postgres (development), model state lives in memory and the YAML decides again at restart.
- **Pack/model binding.** A model written for one pack can run under another; it is reported (`model_pack_mismatch`, metric, console banner, approver warning) but not blocked (ADR-010 §4).
- **Downgrade protection at first baseline.** There is no prior version to compare against.
- **Replica convergence.** Only the replica that applies a change reloads; others serve the previous pack until restarted. `/v1/runtime` reports `pointer_drift`.
- **Shadow sync when evidence *and* the incident both fail.** The caller still receives `PASS` (shadow must not disrupt the lender's flow); the failure is visible only through `kavach_incident_write_failures_total` and an `ALERT` log line. Monitor that metric.
- **mTLS without `--mtls-principal-san`.** The certificate then only restricts who can connect; the principal comes from a token.
- **Client-certificate revocation.** No CRL or OCSP checking; a certificate stays usable until it expires or its CA is removed (restart needed). Issue short-lived certificates.
- **Binding a token to the certificate that presented it** (RFC 8705). A token presented over mTLS wins over the certificate principal and is not tied to that certificate.
- **Token revocation before expiry.** Access tokens are verified locally and stay valid until `exp` (plus leeway); keep token lifetimes short at the IdP. Certificate-bound tokens (RFC 8705) are P1.
- **HMAC on routes other than `/v1/evaluate`, and on gRPC.** HMAC v2 protects only the evaluate ingestion path; other routes rely on tokens (ADR-008 §3). The nonce cache is per process, so replicas behind a load balancer do not share it.
- **Pack integrity at startup in memory mode.** Without Postgres (memory evidence store, development) there is no pointer row; without `--pack-sha256` a restart loads whatever bytes are at `--pack`.
- **First-start baseline.** In a new database, the first API start records its `--pack` as the governed baseline without a change request (audited as `startup_baseline_recorded`); verify it before enabling enforce mode.
- **Pack integrity during evaluation.** Evaluation uses the compiled pack held in memory and does not re-read or re-hash the file.
- **Pack authenticity without signers.** Signature checks apply only when `--pack-signers` is configured; without it, a digest proves "same bytes as last measured", not "approved by a trusted signer".
- **Signing-key protection.** Signing keys are owner-only files (`kavach-keys`); they are not encrypted at rest and not in an HSM yet (Stage 2). Keep them off the API host.
- **Signer revocation.** Removing a key from the signers file stops future loads; packs already running stay loaded until the next reload or restart.
- **Pack bytes on the evidence chain.** Evidence identifies packs by `pack_id` and `pack_version`, not by digest; the new agent record type carries the digest (ADR-005).
- **Integrity of the runtime pointer row.** Anyone with write access to Postgres can change pointer paths and digests; governance events on the evidence chain are planned (ADR-005).
- **Legal or regulatory compliance.** Packs are controls *mapped to* regulations and are labelled guidance; they are not legal advice or a compliance certification.
- **v1 evidence signatures.** Existing `decision_event` records are hash-chained but not signed; checkpoint signing arrives with ADR-005.
- **Client time inside CEL rules.** Rules can still read `request.decision_time`; pack authors must use the trusted `now` variable for time decisions (available since M1.5a).
- **CEL memory limits.** The CEL interpreter has no allocation limit, and the timeout is checked between rules, so one expensive expression is not interrupted; packs are bounded by load-time limits instead, and `max_alloc_bytes` is advisory.
- **High availability, HSM/KMS key protection, air-gapped deployment** — Stage 2.
- **Correctness of data in the customer's systems of record.**
- **Production hardening of the reference implementation.** The MVP demo is a reference implementation, not a security certification.
