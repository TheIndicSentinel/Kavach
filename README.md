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
| **Network isolation** (compose, agent network with no egress), proven on every pull request | ✅ |
| **Revocation by event**: a signed payment or dispute revokes a loan's mandates, recorded as a signed evidence record | ✅ |
| **Evidence bundles**: signed checkpoints and bundles (format 2), verified offline with keys you supply | ✅ |
| **Developer CLI** (`kavach init`, `dev up`, `authorize`, `call`, `why`, `attack`, `demo`, `simulate`, `evidence`) | ✅ pre-alpha (`0.1.0-alpha.1`), not yet released |
| **Agent kill switch** (restrict, quarantine, revoke; ADR-013) | 🚧 accepted design, in progress |
| **Decision Governance** for credit decisions (packs, evaluate API, console, fairness, retention) | ✅ (earlier milestones) |

What each guarantee covers, and what it does not, is listed in [docs/SECURITY_PROPERTIES.md](docs/SECURITY_PROPERTIES.md).

### Authorization is per action, not per utterance

Kavach decides when an agent asks to **do** something: a tool call such as sending a templated reminder. It does not sit in the path of the model's output, and it does not read or score what the agent says or thinks.

- **One decision per action.** Each call to a tool is authorized once, against a mandate, the tool registry and the time, then recorded, before anything is sent.
- **Parameters are references and allowlisted values,** never free text (ADR-004 §7), so the words of a reminder come from a template the registry names, not from the agent.
- **It does not govern what happens inside an authorized action.** A live conversation, for example, is outside what Kavach decides: the decision is whether the call may be placed, not each sentence of it.
- **No latency figure is published yet.** One is promised only after the reference-machine run; CI trends are not claims.

### Honest limits

- **Real providers.** Only backends that adopt the Kavach credential format verify it themselves (the bundled mock provider does). For real WhatsApp or SMS providers, the boundary is the gateway holding the provider's own token plus network isolation.
- **Not production-ready.** This is pre-release software: single-instance for now, HA decision open (run one instance; replicas do not converge on a pack change), no published performance figures, and no external security review yet. HSM support (PKCS#11) is tested against SoftHSM only.
- **Fixtures.** The reference resolver holds synthetic numbers only; a reference vault with crypto-shredding is planned.

## Quick start

```bash
git clone https://github.com/TheIndicSentinel/Kavach.git && cd Kavach
cargo build            # the pinned toolchain installs itself via rustup
cargo test             # core crates; no database needed
./scripts/verify.sh    # everything CI runs that your machine supports
```

To try the console signed in, with a seeded stack on your machine, start a local Postgres (no Docker needed; [docs/INSTALL.md](docs/INSTALL.md#try-it-on-one-machine-scriptsdemosh) shows how), then:

```bash
scripts/demo.sh        # builds, starts, seeds; prints the URL and the test users
scripts/demo.sh stop   # stops everything and drops its schema
```

Open the URL it prints (`http://127.0.0.1:8080/`, the console that kavach-api serves), choose Sign in, and pick a user. The sign-in goes through a local test identity provider.

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
