# Bypass Inventory

Every known way to get around a guarantee in [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md): who can do it, what it switches off, and how anyone would notice. A guarantee is only as strong as its weakest bypass. This list is updated in the same pull request as any change that adds, removes or narrows one ([PRD](PRD.md) NFR-6).

The bypasses fall into four groups:

- **Switches:** options that turn a check off on purpose, for development or recovery.
- **Absent options:** a guarantee marked *Conditional* that was never configured.
- **Privileged roles:** people or systems that sit below Kavach.
- **Paths around Kavach:** actions that never pass through it.

## 1. Switches

| Switch | What it switches off | Who can use it | How it shows | Guard |
|---|---|---|---|---|
| `kavach-api --insecure-dev` | See the next table: one flag, several relaxations | Whoever starts the API | Startup warnings in the log, one per relaxation. **Not** visible in `/v1/runtime` or in any metric after startup (gap, see below) | Off by default. The production image and the pilot compose stack never pass it. Only the development isolation stack (`deploy/agent-stack`) does. Development keys (`dev-…`) are refused without it, and dev-signed evidence fails the offline verifier |
| `kavach-batch --insecure-dev` | A weaker Postgres `sslmode`, when the URL also asks for it | Whoever runs the batch | Startup warning | Off by default; the flag alone downgrades nothing |
| `kavach-evidence export --allow-plaintext-database` | Postgres TLS for the export connection, when the URL also asks for it | Whoever runs the export | **Nothing** (gap) | The flag alone downgrades nothing |
| `kavach-evidence export --allow-write-role` | The refusal to export as a role that can write evidence | Whoever runs the export | **Nothing** (gap) | Default refuses. `kavach_auditor` is the intended role |
| `kavach-evidence verify-bundle --allow-warnings` | Exit 2 for an unsigned bundle, uncovered records, no kept checkpoint compared, or allows without a final outcome | Whoever verifies | The report still lists every warning first, under what is *not* protected | Default fails closed (exit 2). Hard failures (exit 1) cannot be allowed |
| `verify_dev_chain` (library) | The refusal of development-signed evidence | Code that calls it by name | The function name | `verify_chain`, which every command uses, refuses dev keys |
| `--bootstrap-pack` (API) | The runtime pointer check for the pack path and bytes at startup | Whoever starts the API | Audited (`startup_baseline_*` / bootstrap events) | Re-pins path and digest only. Status and mode never change without a change request |
| `--bootstrap-model` (API, batch) | The runtime pointer check for the model file path and digest | Whoever starts the API or batch | Audited | Never changes status or governance mode |
| `allow_downgrade` on `activate_model` | The refusal to activate a lower model version | A proposer | Part of the change digest the approver must echo | Needs a second principal to approve |

### What `kavach-api --insecure-dev` relaxes

| Relaxation | Normally |
|---|---|
| The self-asserted `X-Kavach-Principal` header is accepted, including as an approver of change requests | Principals come only from a verified token or client certificate; approvals need an OIDC user token |
| `--access-control none` is allowed: every request passes | Refused at startup |
| Cedar access control may run with no authenticated principal source | Refused at startup |
| Memory stores for mandates, replay and agent evidence | Agent surfaces refuse to start without Postgres |
| The system clock is declared synced for agent decisions; a test clock is allowed | Trusted time comes from the kernel's sync status, and startup fails if that is unreadable |
| The agent tool registry may be unsigned | A `tool`-role signature is required |
| Development keys (`dev-…`) for mandates, evidence, checkpoints, credentials and SoR issuers | Refused at startup |
| A test-double credential broker | Refused at startup |
| A weaker Postgres `sslmode`, when the URL also asks for it | `verify-full` only |

**Gaps** (to be closed by a later engineering item):
- Once the API is running, nothing but the startup log shows that it runs with `--insecure-dev`. It should be reported in `/v1/runtime` and as a metric, so that monitoring can alert on it.
- `kavach-evidence export` prints nothing when `--allow-plaintext-database` or `--allow-write-role` is used. Both should print a warning, and the bundle manifest should record that the export ran under them.

## 2. Absent options

A *Conditional* guarantee does not hold at all until its option is configured. Kavach refuses to start in some of these cases; in the others the guarantee is simply missing.

| Not configured | Guarantee missing | Refused at startup? |
|---|---|---|
| OIDC (`--oidc-*`) and mTLS principals (`--mtls-principal-san`) | Authenticated API principals | Yes, with Cedar access control (outside `--insecure-dev`) |
| `--pack-signers` | Pack and model authenticity: a digest proves "same bytes", not "approved by a signer" | No |
| `--pack-sha256` in memory mode | Pack integrity at restart | No |
| `--hmac-secret` | Replay protection for signed `/v1/evaluate` requests | No (tokens still authenticate) |
| Separate database roles (owner migrates, API runs as `kavach_runtime`) | The application cannot rewrite evidence, audit or governance history | No: a single-role deployment gives the application owner rights |
| Checkpoints copied off-host, and trusted keys and the export key kept away from the deployment | Detection of truncation and full rewrites by someone holding the database and the keys | No: it is an operator procedure |
| Postgres mode | Governed model state, the runtime pointer, durable evidence | Agent surfaces: yes. Decision Governance: no (memory mode is for development) |
| `hostssl`-only `pg_hba.conf` on a Postgres you run | Other clients cannot connect in plaintext | No: a server setting. The bundled stacks set it |

## 3. Privileged roles

These sit below Kavach. Kavach can make their actions detectable, but cannot prevent them.

| Role | Can | Detected by |
|---|---|---|
| Database owner or superuser | Rewrite or delete evidence, audit, change-request and pointer rows; drop the triggers that make them append-only | Agent evidence: an export verified against a checkpoint kept off-host. v1 evidence, audit, change requests and the pointer row: **nothing yet** (signed governance events are planned, P1) |
| Holder of the signing keys | Sign mandates, credentials, evidence and checkpoints that verify | Only a checkpoint or bundle kept off-host from before the key was misused. Keys are owner-only files, not in an HSM yet (KMS/HSM provider planned) |
| Identity-provider administrator | Create identities, put them in groups (including `change-approvers`), give one person two accounts | The IdP's own audit. Kavach records the authenticated identity of every proposer and approver |
| Root on the API host | Read keys, change memory, change the kernel clock, replace the binary | Nothing inside Kavach. Host hardening and a KMS/HSM are the controls |
| Root on the Docker host or cluster | Change networks so that an agent reaches more than the gateway | The isolation probe, which runs in CI on the development stack only, not continuously in a deployment |
| Whoever controls the signed tool registry or packs (`tool`, pack and model signer roles) | Widen what agents may call, or change policy | The signature is required; the registry digest is in every decision's `policy_versions` |

## 4. Paths around Kavach

| Path | Effect | Control |
|---|---|---|
| A resource the agent reaches without the gateway | No guarantee applies | Network isolation (ADR-007): the agent's only route is the gateway's agent listener. This is a deployment property |
| A provider that accepts its own long-lived token | The credential-accepting backend guarantees do not apply. The gateway holds the provider token | Network isolation; keep provider tokens out of agent containers |
| A system of record with a valid issuer key | Issues mandates within its templates | Templates, passports and consent records bound the scope. Freshness and the replay guard bound reuse |
| An agent token stolen before it expires | Acts as that agent until `exp` | Short token lifetimes at the IdP. No revocation before expiry (certificate-bound tokens, RFC 8705, planned) |
| A client certificate that was not revoked | Connects until it expires | No CRL or OCSP checking. Issue short-lived certificates |
| A JSON object whose first key is `$serde_json::private::RawValue`, in a field that takes free-form JSON (evaluate `input`, values inside tool parameters, change-request parameters) | serde_json, with the `raw_value` feature that axum and sqlx switch on, reads the key's value as a string of JSON and parses that instead. Kavach then sees a different structure from a WAF, a log or another parser looking at the same bytes. No new capability: the sender could send the inner JSON directly. Canonical JSON refuses the key, so nothing signed can carry it | **Open (decision pending):** a strict JSON check at every endpoint that takes JSON, refusing the key wherever it appears (escaped forms included) |
| An identifier the detectors do not see, in a tool parameter | It reaches the decision record and the provider. Detected today: mobile numbers, Aadhaar, PAN and runs of 9 or more digits, in any supported script and through separators. Reference-only fields also refuse more than 8 digits in total. **Not detected:** identifiers spelt out in words ("nine eight seven…"), encoded (base64, hex of the digits, a cipher), split across several parameters, and UPI IDs, IFSC codes and account-number formats (detectors planned, PRD FR-5) | Parameters are allowlists, integers or reference-only, never free text, which leaves little room to encode. The registry is signed, so a tool cannot add a free-text field without a `tool`-role signature |

## Keeping this list honest

- A new flag or option that weakens a check needs a row here in the same pull request.
- A switch must show up somewhere: a startup warning at least, and an audit event when it changes governed state.
- A switch that cannot be seen once the process is running, or not at all, is listed as a gap, as `--insecure-dev` and the two export flags are today.
