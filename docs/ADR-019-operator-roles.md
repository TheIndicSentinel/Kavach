# ADR-019: Operator Roles and Role Management

**Status:** Accepted (2026-11-16). Owner decision of 2026-11-16 (the roles track): the migration and the Cedar policy change below are pre-approved under this ADR. A breaking API or evidence-format change, a new runtime dependency, or anything that weakens a security property still needs the owner's go. Not implemented yet; the backend and console follow in their own pull requests. It is a second-review area (who may do what; see SECOND_REVIEW.md).  
**Date:** 2026-11-16  
**Deciders:** Kavach product/engineering (owner decision, 2026-11-16)  
**Related:** ADR-008 (API authentication), ADR-009 (change requests), ADR-013 (kill switch), ADR-014 (tenancy), ADR-018 (console login), [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md), [THREAT_MODEL.md](THREAT_MODEL.md)

**Scope.** Who an operator is allowed to be inside Kavach: named roles, how a role is given to a person or an IdP group and taken away, how the first administrator comes to exist, and how a bank reviews who holds what. Sign-in itself does not change: it stays with the bank's identity provider (ADR-018). Agent authorization (ADR-003) and workload certificates (ADR-008, the entities file) are out of scope.

## Context

What the code does today (read at `eb8e5e4`):

- **Groups come only from the token.** `crates/kavach-api/src/auth.rs` resolves the principal (OIDC token, then the mTLS SAN, then the dev header) with the token's groups claim. `authorize_principal` passes those groups to `Authorizer::authorize_with_groups` (`crates/kavach-auth/src/lib.rs`), which makes them the principal's parent `Kavach::Group` entities, with an empty Cedar context.
- **Four groups exist, in policy only.** `crates/kavach-auth/policies/kavach.cedar` permits by group: `admins` (every read, every `propose_*`, `stop_agent`, `set_dev_clock`), `change-approvers` (every `approve_*`, reading change requests and governance), `operators` (`evaluate`, `read_governance`) and `viewers` (`read_governance`, `read_health`).
- **Kavach cannot say who holds a group.** Membership lives in the IdP. Changing who may approve a pack activation is an IdP ticket, outside Kavach's maker-checker and outside its audit. There is no list of who has which access for a periodic access review, which banks run.
- **Maker-checker exists** for eight change kinds (ADR-009): frozen parameters, a digest the approver echoes, an approver whose `oidc:<iss>#<sub>` identity and display id differ from the proposer's, a TTL, one transaction, an audit row.
- **One tenant per process.** Tier 1 (ADR-014): the process serves `KAVACH_TENANT_ID`. The admin audit log has no tenant column.
- **The Cedar analysis job** (`crates/kavach-cedar-analysis`, cvc5 in CI) proves properties of the agent policies only. The operator policies are not analysed.

## Options considered

| | A. IdP groups only (today) | B. Roles in Kavach, bound to people or IdP groups, changed by maker-checker | C. Kavach as the identity store (local accounts, passwords) |
|---|---|---|---|
| Who changes access | The IdP team, outside Kavach | Two Kavach operators, recorded, through change requests | Kavach |
| Access review | Ask the IdP team | One export from Kavach (bindings; the IdP keeps group membership) | One export |
| Credentials Kavach holds | None | None | Password hashes, resets, MFA: a new, attractive target |
| Fits a bank's IdP-led joiner/mover/leaver process | Yes | Yes: a binding can name an IdP group, so the IdP stays the source for membership | No |

**Decision: B.** C is rejected outright: no passwords, ever. A stays available: the four groups keep working unchanged, as aliases.

## Decision

### 1. Roles

Seven roles, each a set of Cedar actions (the matrix in §2):

| Role | For |
|---|---|
| `superadmin` | Break-glass and setup. Every action. Every action it takes is flagged in the audit (§7). |
| `user_admin` | Proposes and approves role grants and revokes (never `superadmin`'s); reads the principals directory and the access review. |
| `policy_admin` | Proposes governance changes: packs, models, retention, erasure, reinstating an agent. |
| `approver` | Approves or rejects governance change requests. |
| `operator` | Runs the system: evaluates, reads governance, health, metrics, incidents, batch jobs and agent state, stops an agent. |
| `auditor` | Reads everything, changes nothing: audit log, evidence, change requests, principals, access review. |
| `viewer` | Reads governance and health. |

A role is a Cedar entity of its own type, `Kavach::Role::"<name>"`, **not** a `Kavach::Group`. An IdP group therefore never becomes a role by having the same name. A token carrying a group called `superadmin` gets nothing from it. Only a binding (§3) makes someone hold a role.

**The existing groups stay as aliases with exactly today's permissions:** `admins`, `change-approvers`, `operators` and `viewers`. Their policies are not edited, so no deployment gains or loses access on upgrade. Each alias is documented as the role it most resembles (`admins` ≈ `policy_admin` + `operator` + `auditor`'s reads; `change-approvers` ≈ `approver`; `operators` ⊂ `operator`; `viewers` = `viewer`). No alias may manage roles. A bank moves from aliases to roles at its own pace and can drop the aliases from its policy file when done.

### 2. Role-to-action matrix

New actions: `read_principals`, `read_access_review`, `propose_grant_role`, `approve_grant_role`, `propose_revoke_role` and `approve_revoke_role`. Approving includes rejecting, as in ADR-009.

| Action | superadmin | user_admin | policy_admin | approver | operator | auditor | viewer |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `read_health` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `read_governance` | ✓ | | ✓ | ✓ | ✓ | ✓ | ✓ |
| `read_metrics` | ✓ | | | | ✓ | ✓ | |
| `evaluate` | ✓ | | | | ✓ | | |
| `read_incidents`, `read_batch_jobs`, `read_agent_state` | ✓ | | ✓ | | ✓ | ✓ | |
| `stop_agent` | ✓ | | | | ✓ | | |
| `reconcile_closed_records` | ✓ | | | | ✓ | | |
| `read_retention`, `read_tombstones` | ✓ | | ✓ | ✓ | | ✓ | |
| `read_change_requests` | ✓ | ✓ | ✓ | ✓ | | ✓ | |
| `propose_*`, the eight governance kinds¹ | ✓ | | ✓ | | | | |
| `approve_*`, the eight governance kinds¹ | ✓ | | | ✓ | | | |
| `read_audit`, `read_evidence` | ✓ | | | | | ✓ | |
| `read_principals`, `read_access_review` | ✓ | ✓ | | | | ✓ | |
| `propose_grant_role`, `propose_revoke_role` | ✓ | ✓ (not `superadmin`) | | | | | |
| `approve_grant_role`, `approve_revoke_role` | ✓ | ✓ (not `superadmin`) | | | | | |
| `set_dev_clock` (dev stacks only) | ✓ | | | | | | |

¹ `activate_pack`, `rollback_pack`, `update_model`, `activate_model`, `update_retention`, `erase_evidence`, `apply_retention` and `reinstate_agent`.

How the matrix is enforced:

- **Maker-checker applies to everyone.** Every role, `superadmin` included, still cannot approve its own proposal: ADR-009's distinctness check runs before Cedar is asked.
- **The `superadmin` restriction is a Cedar condition, not code.** The four role actions carry a context attribute `role`, the role being granted or revoked. `user_admin`'s permits have `when { context.role != "superadmin" }`, so only a `superadmin` may propose or approve a change to `superadmin`.
- **The analysis job proves it.** It gains operator-policy properties, each with a sanity check that weakens the policy and must be caught:
  - only `superadmin` may propose or approve a `superadmin` grant or revoke;
  - `viewer` and `auditor` are allowed no `propose_*`, `approve_*`, `evaluate`, `stop_agent` or `set_dev_clock`;
  - no alias group is allowed a role action.

### 3. Bindings

A binding gives one role, in one tenant, to one of:

- **a person:** an OIDC issuer and subject, the same `oidc:<iss>#<sub>` identity ADR-009 compares; or
- **an IdP group:** an issuer and a group name from the groups claim. The IdP stays the source of who is in the group; Kavach records that the group holds the role.

Certificate (mTLS) principals are workloads, not people, and cannot be bound; they keep the entities file. The `--insecure-dev` header principal can be bound only on a dev stack, under its own `dev:` source, so a binding made there is never valid elsewhere.

How bindings take effect:

- **What Cedar sees.** For each operator request, Cedar gets the token's IdP groups as `Group` parents, plus as `Role` parents the roles bound to that person, and the roles bound to any of those groups. Bindings of other tenants are never read.
- **No cache.** Bindings are read per request (one indexed query), so a revoke takes effect on the next request. A cache is a decision for the performance run, not now.
- **Fail closed.** If the bindings cannot be read, the request is refused with 503. It is not decided on the token's groups alone, so a database fault can never shift what someone may do.
- **Tenant scoping.** Every binding carries `tenant_id`. A process reads only its `KAVACH_TENANT_ID`'s bindings (ADR-014 Tier 1). Tier 2 adds a tenant claim later; the schema needs no change for it.

### 4. Changing bindings: `grant_role` and `revoke_role` change requests

Two new change kinds use ADR-009 unchanged: frozen parameters, a digest the approver echoes, an approver whose identity differs from the proposer's, a TTL, one transaction, and an audit row.

- `grant_role {role, subject: {kind: "principal" | "group", issuer, value}}`
- `revoke_role {binding_id}`

**A binding exists only after approval.** The approval transaction inserts or ends the binding. Before that, the pending request grants nothing.

Refused at proposal and checked again inside the approval transaction:

- **No self-grant.** The proposer cannot grant a role to themselves, or to an IdP group their current token carries. The approver cannot approve a grant to themselves or to a group their token carries.
- **Escalation.** A `superadmin` grant or revoke needs `superadmin` on both sides (§2). Any other role needs `user_admin` or `superadmin`.
- **Last administrator.** A revoke that would leave the tenant with no active **person** binding for `superadmin`, or none for `user_admin`, is refused. Group bindings do not count, because Kavach cannot see whether the group has members. The check runs under a lock on the tenant's bindings of that role, so two concurrent revokes cannot both pass.
- **Duplicates.** A grant that duplicates an active binding is refused (409).

### 5. Bootstrap: the first `superadmin`

A new deployment has no bindings, and every grant needs two people who already hold roles. The first superadmins are created once, outside the change-request flow, and **always two at a time**. With one, nobody could approve anything, because maker-checker has no exception for bootstrap.

**One setting, on the command line or in config:** `--bootstrap-superadmins '<iss>#<sub>,<iss>#<sub>'`, or the environment variable `KAVACH_BOOTSTRAP_SUPERADMINS` (for container deployments). kavach-api applies it at startup, before it serves, against its own database. It needs exactly two different people. One person, a duplicate, or a non-OIDC identity is a startup error.

- **Writes only when the tenant has no active `superadmin` binding.** Because the last one cannot be revoked (§4), that is once per tenant in practice.
- **Leaves the setting inert afterwards.** When a `superadmin` already exists, the setting is ignored: one startup warning, never an error, so a leftover setting cannot block a restart.
- **Is audited.** In one transaction it writes the two bindings and one audit row per binding, of kind `bootstrap_superadmin`, each flagged as a `superadmin` action.

The two superadmins then grant `user_admin`, and every other role, through change requests: one proposes and the other approves. The INSTALL runbook says to remove the setting after the first start.

### 6. The principals directory

`principals (tenant_id, issuer, subject, display_name, first_seen_at, last_seen_at)`. Nothing else: no email, no name claim, no groups, no token. The display name is the value of the configured principal claim (`--oidc-principal-claim`, default `sub`), the same display id the audit already records, truncated to 200 characters.

- A row is upserted when a person signs in to the console, or makes an OIDC-authenticated request.
- `last_seen_at` is written at most once an hour per person, so a busy operator does not cause a write per request.
- The rows are the minimum needed to show a name next to a binding, and to show that a bound person has not been seen.

### 7. Superadmin actions are flagged

Every admin audit row gains `acting_as_superadmin`. It is set when the decision was allowed **only** by a `superadmin` policy: every determining policy's `@id` starts with `superadmin-`, read from Cedar's response. A `superadmin` who also holds `policy_admin` and proposes a pack activation is not flagged; the same person approving it is. The console shows an "acting as superadmin" banner while the signed-in person holds `superadmin` (step 3 of the track). The flag is an additive, nullable column on `admin_audit_log`. The evidence chain and bundle formats do not change.

### 8. Endpoints

All under Cedar, all in openapi:

| | Action |
|---|---|
| `GET /v1/principals` (paged; `?q=` matches display name or subject) | `read_principals` |
| `GET /v1/role-bindings` (active by default; `?include=ended`) | `read_principals` |
| `POST /v1/change-requests` with kind `grant_role` or `revoke_role`, then the existing approve, reject and cancel routes | `propose_*` / `approve_*` as in §2 |
| `GET /v1/access-review?format=json\|csv` | `read_access_review` |
| `GET /v1/me` gains `roles` (the roles bound to the caller now), so the console can gate its pages | none beyond the caller's existing session |

`/v1/me` only helps the console show the right pages. The server decides every request.

### 9. The access review export

One row per active binding:

- role, subject kind, issuer, subject, display name;
- granted at, with the change request id and the proposer and approver identities;
- last seen, and `stale` when last seen is more than 90 days ago or never (`--access-review-stale-days`).

A header section lists the alias groups that the policy still honours, and states that their membership is in the IdP and is not part of this export. CSV fields are quoted per RFC 4180, and a field starting with `=`, `+`, `-` or `@` gets a leading `'`, so a spreadsheet does not run it as a formula. Each export writes an audit row.

### 10. Out of scope

- **SCIM provisioning** (an IdP pushing users and groups into Kavach). A binding to an IdP group already lets the IdP lead membership. This is noted on #218.
- N-of-M approvals and time-boxed grants (an `expires_at` on a binding) are deferred. The access review's `stale` column is the mitigation for now.
- Per-resource roles (a role on one pack or one agent). Roles are per tenant.

## Threats

| Threat | Mitigation | Residual |
|---|---|---|
| **Escalation**: a `user_admin` makes themselves or a friend `superadmin` | Only `superadmin` may propose or approve a `superadmin` change (Cedar condition, proved by the analysis job); no self-grant; maker-checker | Two colluding `user_admin`s can give each other any non-`superadmin` role. Maker-checker does not stop collusion; the access review and the audit show it |
| **Self-grant through a group**: granting a role to an IdP group one belongs to | The proposer's and the approver's current token groups are checked | Membership the IdP adds later is outside Kavach's view |
| **Name confusion**: an IdP group named like a role | Roles are a separate entity type; only bindings create role parents | None known |
| **Stale binding after an IdP leaver** | IdP-led: a leaver stops getting tokens, so a person binding becomes inert. `last_seen` and `stale` in the access review show it; revoking is one change request | A bound subject the IdP reissues to someone else. Banks should not reuse subjects; SCIM is out of scope |
| **Break-glass misuse**: `superadmin` used for routine work | Every superadmin-only decision is flagged in the audit; the console banner; `superadmin` changes need a second `superadmin`; the access review lists it first; bootstrap is once | A `superadmin` can do anything a role can, with a second person approving. Keep two, and review the flagged rows |
| **Lock-out**: the last `user_admin` or `superadmin` revoked | Refused, under a lock, at proposal and at approval | If every `superadmin`'s IdP account is gone, recovery is a database-operator procedure (re-run the bootstrap after ending the dead bindings by SQL), documented in INSTALL and audited by the bootstrap row |
| **Bindings unreadable** | The request is refused with 503, never decided on token groups alone | Availability, not access |
| **Cross-tenant binding** | Every query filters on the process's tenant; a test proves a binding in tenant B has no effect in tenant A | Tier 2 needs the tenant claim (ADR-014 §3) |
| **A database writer adds a binding** | Same trust as today: a DB writer can already change the audit and pointer tables (THREAT_MODEL, "Repudiation") | Separate DB roles stay **Conditional** |

## Migration

One migration, pre-approved:

- **`principals`.** Primary key `(tenant_id, issuer, subject)`.
- **`role_bindings`.** Columns:
  - `id`, `tenant_id`, `role`, `subject_kind`, `issuer`, `subject`;
  - `granted_by_change_request`, `granted_at`;
  - `ended_by_change_request`, `ended_at`.

  A partial unique index allows one active binding per `(tenant, role, kind, issuer, subject)`.
- **Constraints.** CHECK constraints on `role` (the seven names) and `subject_kind` (`principal`, `group`), plus foreign keys to `change_requests`. Each is added `NOT VALID`, then `VALIDATE`d in a separate statement, so no long lock is taken on a large table.
- **`admin_audit_log.acting_as_superadmin`.** A nullable boolean, no default rewrite.

No existing row changes. Rollback: the tables are new and the column is nullable, so the previous binary ignores them.

## Consequences

- **Access changes inside Kavach** are maker-checker, audited, and reviewable in one export. The IdP stays the source of identity and, through group bindings, of membership.
- **No deployment changes on upgrade.** The aliases keep their exact permissions.
- **One more query per operator request** (indexed). Measured in the performance run, not claimed here.
- **Cedar gets a context** for the four role actions. The `Authorizer` API gains a call with context; the others are unchanged.
- **Docs.** SECURITY_PROPERTIES gains properties for self-grant, escalation, last-admin, tenant isolation and approval-before-effect, each naming its test once the CI log shows it. THREAT_MODEL gains the rows above, INSTALL the bootstrap and the access review, and SECOND_REVIEW the area.

## Test plan (backend PR)

- **Escalation.** A `user_admin` proposing or approving a `superadmin` grant gets 403. A `superadmin` gets through.
- **Self-grant.** Refused for the proposer, by person and by a group in their token, and for the approver.
- **Last admin.** The last `superadmin` and the last `user_admin` cannot be revoked, and neither can two concurrent revokes of the last two (Postgres).
- **Approval before effect.** A granted role does nothing until approval, and works on the next request after it. A revoke stops it on the next request.
- **Tenant isolation.** A binding in another tenant is ignored (Postgres).
- **Cedar denial for every role.** For each of the 7 roles, every action outside its column is denied. The test is generated from the §2 matrix, so the table and the policy cannot drift.
- **Fail closed.** A bindings lookup error gives 503.
- **Bootstrap.** Writes two bindings and two audit rows once. A restart with the setting still present, after a `superadmin` exists, writes nothing and warns. One subject, a duplicate, or a non-OIDC identity is a startup error.
- **Access review.** Contents, CSV formula escaping, and `stale`.
- **Analysis job.** The new operator properties hold, and their sanity checks are caught.

## References

ADR-008, ADR-009, ADR-013, ADR-014, ADR-018; `crates/kavach-auth/policies/kavach.cedar`; `crates/kavach-api/src/auth.rs`; `crates/kavach-cedar-analysis`.
