# ADR-015: Provider Mode (a Gateway-Held Provider Token)

**Status:** Accepted (2026-10-13, with the owner's amendments below)  
**Date:** 2026-10-12  
**Deciders:** Kavach product/engineering  
**Related:** ADR-006 (ports), ADR-007 (network boundary and the provider status contract), ADR-012, ADR-014, [SECURITY_PROPERTIES.md](SECURITY_PROPERTIES.md)

## Context

The gateway forwards a Kavach credential: a signed-then-encrypted token that only the provider can open, for one request, this destination, channel and template. A provider that adopts the format verifies it, and the *Credential-accepting backends* property is scoped to such backends (the reference mock).

A real messaging provider (WhatsApp, SMS) does not accept that format. It accepts its own API token. Without a mode for that, no pilot can send a real message, and every pilot has to run a fixture.

## Decision

### 1. A provider mode in which the gateway holds the provider's token
- **Per tenant and per provider,** the gateway holds a secret that the agent never sees. It is read from a secret store by reference (OpenBao, a cloud KMS or secret manager, or an owner-only file in development), never from configuration text, an environment variable that is logged, the evidence, or a log line.
- **The decision is unchanged.** Authorization, the signed record, the contact cap and the send-by deadline come before anything is sent. A Kavach credential is still minted and recorded (its `jti` is the `credential_id`), as the internal artifact that ties a send to a decision.
- **The gateway builds the provider request itself,** from the registry's parameters and the resolved destination. The agent supplies a reference and registered values, never provider fields.
- **Idempotency:** where the provider supports an idempotency key, the `credential_id` is sent as it, so a send repeated by a retry or a restart is the provider's to refuse. Where it does not, forward-once and the unknown outcome apply as today.
- **Outcomes** follow the status contract of ADR-007 (2xx delivered, 4xx refused, 5xx or a lost response unknown). Delivery receipts that arrive later are a separate feature.

### 2. What the guarantee becomes
For a provider that adopts the credential format, **the provider verifies**: a send without a valid credential cannot happen even if the gateway were bypassed. For a real provider, **the gateway enforces**: no send without a recorded allow, because the gateway is the only holder of the token. That depends on:
- the network isolation of ADR-007 (agents cannot reach the provider or the secret store);
- the egress allowlist and TLS verification already in the forwarder (the configured provider host, no redirects, no ambient proxies);
- the secret never leaving the gateway: zeroised after use, redacted by type, absent from evidence.

`SECURITY_PROPERTIES.md` states both modes as **separate rows**. It must not describe the second with the first's wording, and the real-provider row says that it depends on network isolation being **deployed**, not merely configured (the *Network isolation* job proves it for the reference deployment, not for a customer's).

**Where the secret lives.** It sits in the same process as the signing keys, so: it is read from the store **at send time**, held only for that send, **zeroised** after, kept out of core dumps (no dump of the gateway process includes it) and out of `/v1/runtime`, and redacted by type. A test shows it never appears in a log line, an evidence record, a bundle or an error body, including the error of a failed provider authentication.

**Duplicate sends.** If the provider has no idempotency key, a retry after an unknown outcome could send twice. Forward-once and the `in_flight` rule stand as they are, and the property row says so: for such a provider the guarantee is "Kavach never sends a recorded call twice", not "the provider never delivers twice". Whether a candidate provider supports idempotency keys is part of choosing the first sandbox provider.

### 3. Rotation, revocation, failure
- **Rotation:** the secret store holds a current and a previous version; the gateway re-reads on a schedule and on an authentication failure from the provider.
- **Revocation:** removing a tenant's secret stops its sends at the next read. A provider authentication failure is an outcome of `failed` or `refused` (never `delivered`) and an alert.
- **Store unavailable:** a send needs the secret, so an outage is `not_executed`, never a guess.

### 4. Scope of the first delivery
One sandbox channel adapter, chosen with the first design partner (and partly on whether it supports idempotency keys), against that provider's test environment, with synthetic numbers. Nothing in this ADR sends to a real person.

**Precondition for anything beyond a synthetic sandbox.** A real provider receives a destination number, which is personal data. Before any real number goes to one there must be a **processor agreement** with the provider and **counsel's view on cross-border transfer** (where the provider processes it). This ADR does not make that decision and the code does not enforce it: it is a gate for the people who deploy it, listed in the pilot checklist.

## Consequences
- **A new class of secret in the gateway,** and with it the second-review areas "keys" and "credentials". The secret store adapter, redaction by type, and the egress path are the review focus.
- **The guarantee for real providers is weaker in kind** (enforced by the gateway, not verified by the provider). That is stated, and it is the reason network isolation stays a required check.
- **Pilot-ready:** with this, a design partner's sandbox can be exercised end to end.

## Open questions
1. **Secret store (decided 2026-10-13):** a file in development plus **one real store, OpenBao** (it fits the open-core rule: it is open source, and a deployment needs no paid service). Cloud managers follow as adapters behind the same port.
2. **Which provider and channel** for the sandbox adapter, and whether it has idempotency keys.
3. **Template approval:** WhatsApp templates are approved by the provider ahead of time; how the registry's `template_id` maps to them.
4. **Delivery receipts (decided 2026-10-13):** poll first; no webhooks yet. A webhook is a new inbound surface and needs its own design and review.

## Not addressed here
Per-tenant provider selection in a pooled deployment (ADR-014 Tier 2), inbound messages, and non-messaging providers.

## Implementation status (2026-11-17)

The implemented groundwork is provider-neutral: the gateway can pass its resolved destination, channel, approved template id and credential to a future adapter, and the provider-secret port has a development-only file implementation restricted to owner-only files. No third-party provider or paid service has been selected. These components are not yet connected to provider configuration or used for sends.

Twilio sandbox use was reported to require a paid plan upgrade. Twilio-specific request code was mistakenly added despite the no-paid constraint and has been removed. Twilio is not the chosen adapter. The no-cost next step is to test the provider boundary with a local fake HTTP server, then implement only an adapter/provider option that is available without a paid plan and is explicitly consistent with this ADR.

The credential broker currently requires an X25519 recipient for every registry provider. Before any real-provider adapter is enabled, the broker must preserve the internal decision artifact without implying that an external provider accepts or decrypts Kavach credentials. Provider configuration, local fake-server protocol tests (including proving no Kavach credential is sent), and the security properties and setup guide also remain pending. Production use remains gated by the processor/cross-border review and deployed network isolation described above.
