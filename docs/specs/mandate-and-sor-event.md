# Task Mandate and system-of-record event: format and checks

**Status:** normative, version 1 of both tokens (`mv: 1`). Design record: [ADR-004](../ADR-004-task-mandate-format.md), [ADR-012](../ADR-012-revocation-by-sor-event.md). Conventions: [README](README.md).

Two signed tokens carry authority into Kavach:

- a **system-of-record (SoR) event**, signed by the lender's system, states a fact (a loan is 30 days past due; it was paid);
- a **Task Mandate**, signed by Kavach, is the authority an agent holds because of such a fact.

A verifier of either needs the token, the public keys, and the reference time. Whether a mandate is still **live** is not in the token (section 4).

## 1. Token encoding (both tokens)

A token is a JWS compact serialisation (RFC 7515): `base64url(header) "." base64url(payload) "." base64url(signature)`.

1. The token MUST be at most 16 384 bytes and MUST have exactly three parts.
2. Each part MUST be base64url without padding, and the encoding MUST be canonical: a part whose last character carries non-zero trailing bits, or that ends in `=`, is refused.
3. The **header** is a JSON object with exactly the members `alg`, `kid`, `typ`. `alg` MUST be `EdDSA` (Ed25519). `typ` MUST be `kavach-mandate+jws` for a mandate and `kavach-sor-event+jws` for an event, and the verifier MUST check it against the kind it expects; a mandate token is not an event token. `kid` MUST name a key in the verifier's key set for that kind.
4. The header bytes and the payload bytes MUST each be the RFC 8785 canonical form of their JSON value. A token whose bytes differ from the canonical form of what they parse to is refused, so each token has exactly one valid encoding.
5. The signature is Ed25519 over the ASCII bytes `base64url(header) "." base64url(payload)`. It MUST be verified **before** the payload is parsed.
6. A JSON object MUST NOT repeat a member name, and a member the section below does not list MUST be refused (the payload is not an extension point).
7. Numbers are integers with magnitude at most 2^53 − 1. A fraction, an exponent, `-0`, or a larger integer is refused.

### Times

A time member is a string of RFC 3339 UTC with a `Z` suffix, written in **the shortest form that holds it exactly**: no fractional digits when the sub-second part is zero, otherwise three, six or nine digits (the fewest that represent it). `2026-10-01T05:30:00Z` is valid; `2026-10-01T05:30:00.000Z`, `2026-10-01T05:30:00+00:00` and `2026-10-01T05:30:00.5Z` are not (the last because it should be `.500Z`). A verifier that parses times leniently MUST still compare the string it parsed with the form it would write, and refuse a difference; this is how rule 4 applies to times.

## 2. SoR event

Members (all required, no others):

| Member | Type | Meaning |
|---|---|---|
| `event_id` | string | Unique per `(tenant_id, system)`. |
| `tenant_id` | string | The tenant. |
| `system` | string | The source system, e.g. `lms`. |
| `event_type` | string | e.g. `loan.dpd30` (issues a mandate), `loan.paid`, `loan.disputed` (revoke). A type Kavach has no rule for is refused. |
| `record_ref` | string | The record the event is about (the loan). |
| `subject_ref` | string | A capability reference `ref:<type>:<opaque>`: each of `<type>` and `<opaque>` is 1 to 128 characters of `[A-Za-z0-9_.-]`. A raw identifier is refused. |
| `principal` | string | The business principal the task runs for. |
| `consent_refs` | array of strings | Ids of the consents relied on, **sorted, without repeats**. |
| `assigned_agent` | string | The agent the event assigns. |
| `occurred_at` | time | When the fact happened, per the source system. |
| `nonce` | string | Free; part of the signed bytes. |

### Checks, in order

1. Section 1.
2. **Issuer binding.** The signing key is registered for exactly one `tenant_id` and one `system`, and `tenant_id` and `system` in the payload MUST equal them. A key registered for `crm` cannot state a fact about `lms`; a key registered for one tenant cannot state a fact about another. The same public key is never registered twice (not under two key ids, not for two tenants). A refusal for an unknown key id, a key of another tenant or system, or a bad signature is the same refusal: it does not say which keys exist.
3. **Freshness.** `|reference time − occurred_at| ≤ 300 s`. An event in the future by more than that is refused as well as an old one.
4. **Replay.** `(tenant_id, system, event_id)` is accepted once within 24 hours of first acceptance (single use). A retry of the *same content* is answered with the stored result, not refused (section 5).
5. `subject_ref` is a capability reference.

The vector file lists, per event, the reference time at which it is fresh (`fresh_at`).

## 3. Mandate

Members (all required; `window` and `parent_id` MAY be `null`; no others):

| Member | Type | Meaning |
|---|---|---|
| `mv` | integer | Format version, `1`. Another value is refused. |
| `id` | string | Unique mandate id. |
| `tenant_id` | string | The tenant. |
| `issuer` | string | The Kavach instance that signed. |
| `source` | object `{system, record_ref, event_id}` | The event this mandate came from. |
| `principal` | string | From the event. |
| `holder` | string | The agent that holds it. |
| `subject_ref` | string | A capability reference (section 2). |
| `purpose` | string | Purpose code, e.g. `loan_recovery`. |
| `consent_refs` | array of strings | Sorted, no repeats. |
| `actions` | array of strings | Permitted actions, sorted, no repeats. |
| `data_fields` | array of strings | Fields that may be read, sorted, no repeats. |
| `channels` | array of strings | Subset of `sms`, `voice`, `whatsapp`, sorted. |
| `window` | object or `null` | `{tz, from_min, to_min, max_per_day}`: `tz` is `Asia/Kolkata`; `from_min < to_min` are minutes of the day; a window MUST lie within 08:00 to 19:00 (480 to 1140) and `max_per_day` > 0. |
| `ceilings` | object of integers | Limits, e.g. `waiver_bps` in 0 to 10 000. |
| `delegation` | object `{max_depth, allowed_agents}` | `max_depth` 0 to 4; `allowed_agents` sorted array. |
| `parent_id` | string or `null` | `null` for a root. |
| `depth` | integer | 0 for a root; parent's depth + 1; at most 4. |
| `nbf`, `exp` | time | Valid for `nbf ≤ t < exp`. `exp` after `nbf`, and at most 30 days later. |
| `nonce` | string | Free; part of the signed bytes. |

Object members that are sets (`consent_refs`, `actions`, `data_fields`, `channels`, `delegation.allowed_agents`) are written as sorted arrays; because canonical form does not reorder arrays, a verifier MUST refuse an unsorted array or a repeat.

### What a token verifier checks
Section 1, then the member rules above, then, at reference time *t*: `nbf ≤ t < exp`. A root has `depth` 0 and `parent_id` `null`; a child has `parent_id` non-null and `depth ≥ 1`.

### Delegation: a child only narrows

A child mandate is valid under its parent when **all** hold:

- same `tenant_id`, `subject_ref`, `purpose`, `consent_refs`, `source` and `issuer`;
- `actions`, `data_fields`, `channels` are subsets of the parent's;
- if the parent has a `window`, the child has one inside it (`from_min` not earlier, `to_min` not later, `max_per_day` not larger); a parent without a window places no bound;
- every key in the child's `ceilings` is in the parent's with a value not larger;
- `nbf` not earlier and `exp` not later than the parent's;
- `depth` = parent's + 1, and no more than the parent's `delegation.max_depth`;
- `parent_id` is the parent's `id`; the child's `holder` is in the parent's `delegation.allowed_agents`;
- the child's `delegation.max_depth` is not larger, and its `allowed_agents` are a subset.

A verifier given a child and its chain MUST check every link; authority is the intersection down the chain.

## 4. A valid token is necessary, not sufficient

The token does **not** say the mandate is live. Kavach keeps the status (active or revoked) in its store and checks it, and the stored token, on every authorisation. A verifier that has only the token can say "this was a genuine, well-formed mandate and was inside its validity at *t*"; it cannot say "it had not been revoked". That is evidence from the chain (section 5), not from the token.

## 5. Revocation by event

`loan.paid` and `loan.disputed` revoke. They are verified exactly as in section 2.

- **Scope.** Every live **root** mandate with the same `tenant_id`, `source.system` and `source.record_ref` as the event, **and** with `nbf ≤ occurred_at` (inclusive: when in doubt, contact stops), and every mandate delegated from them. A mandate issued after `occurred_at` is not revoked, even if the event is replayed.
- **Reason.** `payment` for `loan.paid`, `dispute` for `loan.disputed`.
- **Result.** The set of revoked ids, possibly empty (an empty result is a success and is recorded). The same event again returns the stored result and revokes nothing.
- **Event digest.** `event_digest` is `sha256-jcs-v1:` followed by the lowercase hex SHA-256 of the event's RFC 8785 bytes: **the decoded payload part of the token, byte for byte**, which section 1 makes canonical. Anyone holding the token can recompute it. It is what the evidence record carries as `event_digest`, and it decides whether a second event with the same id is a retry (same digest) or a conflict (different digest, refused).
- **Legacy digest.** Before this version Kavach hashed the event's members as compact JSON in the declaration order of a Rust struct (`event_id`, `tenant_id`, `system`, `event_type`, `record_ref`, `subject_ref`, `principal`, `consent_refs`, `assigned_agent`, `occurred_at`, `nonce`) and wrote the bare hex as `event_sha256`. It is not written any more. A store that holds a revocation in that form recognises its retry by computing both digests and accepting either; the vector file gives both (`legacy_content_sha256`) so that an implementation can do the same.
- **Evidence.** Each revocation is a signed record of kind `mandate_revocation` in the evidence chain ([evidence-bundle.md](evidence-bundle.md)). The loan is named there by a keyed pseudonym, never by `record_ref`.

## 6. Test vectors

`crates/kavach-mandate/tests/vectors/mandate-v1.json`:

| Member | Content |
|---|---|
| `mandate_key`, `sor_issuers` | Test public keys as JWKs (Ed25519). `sor_issuers` binds each key to a tenant and a system. |
| `binding_refused` | Events with a genuine signature that MUST still not be accepted: another tenant's event signed by this tenant's key, another system's event, and another issuer's key. |
| `mandates` | A root and its child, each with `token` and decoded `payload`. |
| `events` | An issuing and a revoking event with `token`, `payload`, `event_digest`, `legacy_content_sha256`, `fresh_at`. |
| `refused` | Tokens that MUST be refused, each with its `typ` and the `rule` it breaks (a conforming verifier refuses each **for that rule**; the signature is genuine in every case but `bad-signature`, so no earlier check hides it): a changed signature, a token of the other kind, an unknown key, a payload or header not in canonical form, an unknown member, a time with an offset, a time with a zero fraction, a non-integer number, four parts, padding. |

A conforming verifier verifies every token in `mandates` and `events` to the stated payload, reproduces both digests, refuses everything in `refused` and in `binding_refused`, and refuses the events outside their `fresh_at ± 300 s`.
