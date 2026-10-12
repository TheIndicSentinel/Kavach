# Open core boundary

Kavach is open source (Apache-2.0). A commercial **enterprise control plane** may be offered separately. This page states the boundary so users and contributors know what will always be free.

## Always in the open-source core

Everything needed to run Kavach for one organisation and to **verify** that it works:

- Enforcement: the gateway, Task Mandates, agent authorization, the tool registry, the credential broker, network-boundary configuration.
- Evidence: signed decision records, the verifier, export, and the evidence formats.
- Key protection: the `KeyProvider` port and at least one open hardware-backed or KMS-backed adapter (planned: PKCS#11, tested against SoftHSM, or OpenBao Transit), with key rotation and compromise runbooks. Protecting signing keys is a security property, so it is never enterprise-only.
- Revocation, contact caps, time controls and every other security guarantee in [docs/SECURITY_PROPERTIES.md](docs/SECURITY_PROPERTIES.md).
- **Replicas that behave correctly:** converging on pack and policy changes and sharing replay and nonce state. A replica serving stale rules is a correctness problem, so the high-availability *reference* is core.
- **The per-stack agent kill switch:** restrict, quarantine and revoke an agent, and reinstate it with two people (ADR-013).
- The developer CLI, including the attack harness and the decision trace.
- Policy packs and the formal policy analysis.
- All port interfaces and contract suites, so anyone can write an adapter.

**Security properties are never paywalled.** A guarantee does not move from the core to a paid product, and the core never depends on enterprise code.

**The rule, stated as a test:** if removing a capability would weaken a guarantee in [docs/SECURITY_PROPERTIES.md](docs/SECURITY_PROPERTIES.md), it stays open. What may be paid for is scale and operation: running many stacks, and running them for you.

## Possible enterprise control plane (separate, commercial)

Operating Kavach at scale across many teams or tenants, for example:

- multi-tenant fleet management and central policy distribution with approval workflows;
- SSO/SCIM;
- the operation of high availability: managed failover and multi-region operation (not the correctness of replicas, which is core);
- fleet-scale key operations (managed key ceremonies, cross-region KMS integrations) on top of the open key port;
- **fleet-wide quarantine:** one action across many stacks. The per-stack switch stays open;
- regulatory reporting and audit-export packs (RBI, DPDP and others);
- support and SLAs.

It lives in a separate repository and uses only the public interfaces of the core.
