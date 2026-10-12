# ADR-015: Provider Mode (a Gateway-Held Provider Token)

**Status:** Proposed  
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

`SECURITY_PROPERTIES.md` states both modes separately. It must not describe the second with the first's wording.

### 3. Rotation, revocation, failure
- **Rotation:** the secret store holds a current and a previous version; the gateway re-reads on a schedule and on an authentication failure from the provider.
- **Revocation:** removing a tenant's secret stops its sends at the next read. A provider authentication failure is an outcome of `failed` or `refused` (never `delivered`) and an alert.
- **Store unavailable:** a send needs the secret, so an outage is `not_executed`, never a guess.

### 4. Scope of the first delivery
One sandbox channel adapter, chosen with the first design partner, against that provider's test environment, with synthetic numbers. Nothing in this ADR sends to a real person.

## Consequences
- **A new class of secret in the gateway,** and with it the second-review areas "keys" and "credentials". The secret store adapter, redaction by type, and the egress path are the review focus.
- **The guarantee for real providers is weaker in kind** (enforced by the gateway, not verified by the provider). That is stated, and it is the reason network isolation stays a required check.
- **Pilot-ready:** with this, a design partner's sandbox can be exercised end to end.

## Open questions
1. **Secret store:** which ones first (a file in development, OpenBao, one cloud manager)?
2. **Which provider and channel** for the sandbox adapter, and whether it has idempotency keys.
3. **Template approval:** WhatsApp templates are approved by the provider ahead of time; how the registry's `template_id` maps to them.
4. **Delivery receipts:** whether to take provider webhooks (a new inbound surface) or poll.

## Not addressed here
Per-tenant provider selection in a pooled deployment (ADR-014 Tier 2), inbound messages, and non-messaging providers.
