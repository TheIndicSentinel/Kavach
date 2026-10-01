# Open core boundary

Kavach is open source (Apache-2.0). A commercial **enterprise control plane** may be offered separately. This page states the boundary so users and contributors know what will always be free.

## Always in the open-source core

Everything needed to run Kavach for one organisation and to **verify** that it works:

- Enforcement: the gateway, Task Mandates, agent authorization, the tool registry, the credential broker, network-boundary configuration.
- Evidence: signed decision records, the verifier, export, and the evidence formats.
- Revocation, contact caps, time controls and every other security guarantee in [docs/SECURITY_PROPERTIES.md](docs/SECURITY_PROPERTIES.md).
- The developer CLI, including the attack harness and the decision trace.
- Policy packs and the formal policy analysis.
- All port interfaces and contract suites, so anyone can write an adapter.

**Security properties are never paywalled.** A guarantee does not move from the core to a paid product, and the core never depends on enterprise code.

## Possible enterprise control plane (separate, commercial)

Operating Kavach at scale across many teams or tenants, for example:

- multi-tenant fleet management and central policy distribution with approval workflows;
- SSO/SCIM, high availability, and KMS/HSM adapters;
- regulatory reporting and audit-export packs (RBI, DPDP and others);
- support and SLAs.

It lives in a separate repository and uses only the public interfaces of the core.
