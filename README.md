# Kavach

**Authorization and runtime control for AI agents and consequential automated decisions.** India-first, on-prem, free and open source (Apache-2.0).

> *Kavach* is the internal working name; the public name is not settled yet.

An agent should not hold the credential to act unless it is authorised to act. Kavach puts a gateway between agents and the systems they touch. Every action needs a signed **Task Mandate** issued from a system-of-record event (not from a model), is checked against Cedar policy, trusted time and server-side counters, is recorded as signed evidence *before* it runs, and only then gets a short-lived credential bound to that exact request.

## What works today

| Area | Status |
|---|---|
| **Task Mandates**: issued only from signed system-of-record events, delegation with attenuation, revocation | ✅ library + Postgres store |
| **Agent authorization**: Cedar policies (formally analysed with cvc5 in CI), 08:00–19:00 IST contact floor, daily caps, raw-identifier blocking | ✅ |
| **Tool registry**: signed, digest-pinned; reference-only parameters, allowlisted values, no free text | ✅ |
| **Evidence**: signed, hash-chained decision records committed in one transaction, before anything executes | ✅ |
| **Credentials**: nested JWT, signed then encrypted to the provider (JWS in JWE, X25519 + A256GCM), ≤ 15 s, bound to the request | ✅ |
| **Mock provider** (protocol fixture) and **reference resolver** (synthetic numbers only) | ✅ |
| **Gateway** `POST /v1/tools/{tool}`: authorize and record → resolve → credential → deadline re-check → forward once → signed outcome | ✅ |
| **Network isolation** (compose, agent network with no egress) | 🚧 planned (H5b-2) |
| **Developer CLI** (`kavach init`, `dev up`, offline `authorize`, `why`, `attack`) | 🗺️ v0.1 (pre-alpha, `0.1.0-alpha.1`) |
| **Decision Governance** for credit decisions (packs, evaluate API, console, fairness, retention) | ✅ (earlier milestones) |

What each guarantee covers, and what it does not, is listed in [docs/SECURITY_PROPERTIES.md](docs/SECURITY_PROPERTIES.md).

### Honest limits

- **Real providers.** Only backends that adopt the Kavach credential format verify it themselves (the bundled mock provider does). For real WhatsApp or SMS providers, the boundary is the gateway holding the provider's own token plus network isolation.
- **Not production-ready.** This is pre-release software: no HA, no KMS/HSM integration, no external security review yet.
- **Fixtures.** The reference resolver holds synthetic numbers only; a reference vault with crypto-shredding is planned.

## Quick start

```bash
git clone https://github.com/TheIndicSentinel/Kavach.git && cd Kavach
cargo build            # the pinned toolchain installs itself via rustup
cargo test             # core crates; no database needed
./scripts/verify.sh    # everything CI runs that your machine supports
```

Full local setup (Postgres tests, the console, policy proofs, disk use): **[docs/DEVELOPING.md](docs/DEVELOPING.md)**.

## Documentation

| | |
|---|---|
| Architecture decisions | [docs/ADR-*.md](docs/) (start with ADR-003 agent authorization, ADR-004 mandates, ADR-007 network boundary) |
| Security properties and threat model | [docs/SECURITY_PROPERTIES.md](docs/SECURITY_PROPERTIES.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Install and configure | [docs/INSTALL.md](docs/INSTALL.md) |
| Product requirements | [docs/PRD.md](docs/PRD.md) |
| Open core boundary | [OPEN_CORE.md](OPEN_CORE.md) |

## Contributing and security

Contributions are welcome under the DCO (`git commit -s`); see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

## Licence

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
