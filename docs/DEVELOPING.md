# Developing Kavach locally

This is the setup for running and testing Kavach on your own machine. It is written for macOS and Linux; everything optional is marked so.

> **Coming in the v0.1 developer preview:** `kavach init` will generate the development keys, signed tool registry, fixtures and configuration below in one step, and `kavach dev up` will start the whole stack. Until then, the steps here are manual.

## 1. Prerequisites

| Tool | Needed for | Install |
|---|---|---|
| **rustup** | everything | <https://rustup.rs>. The toolchain is pinned in `rust-toolchain.toml` (1.98.0) and installs automatically on the first `cargo` command |
| **Docker** *(optional)* | Postgres integration tests, the compose stack | Docker Desktop, OrbStack or Colima |
| **Node.js 22** *(optional)* | building the governance console; the credential interop check | `brew install node@22` or nvm |
| **cvc5** *(optional)* | the formal proofs of the agent policies | see "Policy proofs" below |

Disk: a full build uses about 4–6 GB in `target/`. See "Disk use" below.

## 2. Build and test

```bash
cargo build                 # default members: the core, without the batch/fairness worker (Polars)
cargo test                  # unit and integration tests; Postgres tests skip without a database
cargo build --workspace     # everything, including kavach-batch and the mock provider
./scripts/verify.sh         # fmt, clippy, tests, audit/deny if installed (as CI)
```

The console is embedded into `kavach-api` only when `console/dist/` exists, so Node is not needed for the Rust build. To embed it: `./scripts/build-console.sh`.

## 3. Postgres tests (optional, recommended)

The Postgres suites (storage, mandates, agent evidence, the production-shaped API test) run against a real database when `KAVACH_TEST_DATABASE_URL` is set; each test uses its own schema.

```bash
docker run -d --name kavach-pg -p 5432:5432 \
  -e POSTGRES_USER=kavach -e POSTGRES_PASSWORD=kavach-dev -e POSTGRES_DB=kavach_test \
  postgres:16-alpine

export KAVACH_TEST_DATABASE_URL=postgres://kavach:kavach-dev@localhost:5432/kavach_test
cargo test --workspace
```

The tests create a `kavach_runtime` role to check least-privilege access. Use a throwaway database, never a shared one.

## 4. Running the API

`docs/INSTALL.md` lists every flag. Two things matter for local runs:

- **macOS has no Linux kernel clock status**, so the agent surfaces cannot prove synced time. Use `--insecure-dev` locally; it declares the system clock synced, allows in-memory stores and an unsigned tool registry, and prints a warning. Never use it in production.
- The agent surfaces need keys and fixtures (mandate, evidence and credential keys; a signed tool registry; providers; references). `kavach init` will generate them; until then, follow the agent-surfaces section of `docs/INSTALL.md` and use `kavach-keys` and `kavach-mock-provider keygen`.

## 5. Policy proofs (optional)

CI proves properties of the agent Cedar policies with cvc5 on every PR. To run them locally, install cvc5 (a release binary from <https://github.com/cvc5/cvc5/releases>) and run:

```bash
CVC5=/path/to/cvc5 ./scripts/verify.sh
```

## 6. Credential interop check (optional)

CI decrypts the checked-in credential vector with an independent JOSE library:

```bash
cd scripts/jose-crosscheck && npm ci --ignore-scripts && \
  node check.mjs ../../crates/kavach-credential/tests/vectors/credential-v1.json
```

## 7. Disk use

- Local builds skip debug info for dependencies (`[profile.dev]` in `Cargo.toml`), so `target/` stays around 4–6 GB.
- `scripts/disk-guard.sh` removes superseded test binaries when `target/` grows past 6 GB (`--check-size`), and runs `cargo clean` if free space drops below 8 GB. `verify.sh` runs it first. Limits: `KAVACH_MIN_FREE_GB`, `KAVACH_MAX_TARGET_GB`.
- It only ever touches `target/`, which cargo rebuilds.

## 8. Supply chain

- CI actions are pinned by commit SHA, CI tools by version, image bases by digest; `Cargo.lock` is committed and the image builds with `--locked`.
- The *Supply chain* workflow (weekly, on demand and on every push to `main`) re-runs `cargo audit` and `cargo deny` and uploads one CycloneDX 1.5 SBOM per shipped binary. Locally: `cargo install cargo-cyclonedx --locked --version 0.5.9`, then `cargo cyclonedx --format json --spec-version 1.5 --describe binaries`.
- `main` is protected: changes land through PRs with the six CI checks green on an up-to-date branch.

## 9. Before opening a PR

Run `./scripts/verify.sh`, sign off your commits (`git commit -s`), and update `docs/SECURITY_PROPERTIES.md` in the same PR if you change a guarantee. See [CONTRIBUTING.md](../CONTRIBUTING.md).
