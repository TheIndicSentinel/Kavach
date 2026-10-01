# Contributing to Kavach

Thanks for helping. Kavach is security infrastructure, so the bar is correctness and honesty about guarantees, not speed.

## Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change or have the right to submit it under the project's licence (Apache-2.0).

```bash
git commit -s -m "feat(dataplane): ..."
```

This adds a `Signed-off-by: Your Name <you@example.com>` line. There is no CLA.

## Before you start

- For anything beyond a small fix, open an issue first. Architectural changes need an ADR in `docs/` (see the existing `ADR-*.md`).
- Read [docs/DEVELOPING.md](docs/DEVELOPING.md) for local setup.

## Rules for changes

1. **Privacy by default.** No telemetry, analytics or new data collection. Never log, record or return raw personal data; use the redacting types (`Destination`, `TokenSecret`) and pseudonyms.
2. **Guarantees are documented.** If a change adds, weakens or alters a security guarantee, update [docs/SECURITY_PROPERTIES.md](docs/SECURITY_PROPERTIES.md) in the same PR, with the test that proves it.
3. **Fail closed.** A dependency that is down produces a refusal (BLOCK, 503), never an allow.
4. **Ports and contracts.** A new adapter of a security-critical port must pass that port's suite in `kavach-ports-testkit`.
5. **Tests.** Add tests for the behaviour and for the refusals. Use synthetic data only (for phone numbers, the `+910…` range).
6. **Quality gates.** `./scripts/verify.sh` must pass: `cargo fmt`, `clippy` (pedantic, warnings as errors), tests, `cargo deny`. `unsafe` is forbidden outside `kavach-clocksync`.
7. **Dependencies.** Licences must be in the `deny.toml` allowlist; prefer crates already in the tree. Explain any new dependency in the PR.

## Pull requests

- Small, focused PRs with a clear summary and test plan.
- CI must be green, including the Postgres tests and the policy proofs.
- Security-sensitive changes get a second review.

By contributing you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
