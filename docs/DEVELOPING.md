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

## 4. A development bundle (`kavach-dev`)

`kavach-dev generate` writes everything a local stack needs: `dev-` keys, the signed tool registry, a dev CA and provider certificate, mandate config, consents, synthetic references, providers, JWKS and agent and operator tokens, plus a `kavach.env` with every `kavach-api` setting. Each directory is meant for one consumer (agents get only their token).

```bash
cargo run -q -p kavach-devkit --bin kavach-dev -- generate --out /tmp/kavach-dev \
  --provider-endpoint https://localhost:8443 --provider-host localhost
cargo run -q -p kavach-devkit --bin kavach-dev -- sor-event --bundle /tmp/kavach-dev \
  --url http://127.0.0.1:8090/v1/sor/events --event-id evt-1   # issues a mandate
```

`dev-` keys run only with `--insecure-dev`; production startup and the offline verifier refuse them.

The `kavach` command line wraps this into a project (pre-alpha; the commands may change before v0.1):

```bash
cargo install --path crates/kavach-cli   # or: cargo run -q -p kavach-cli --
kavach init            # kavach.toml, plus the bundle in .kavach/ (git-ignored)
kavach doctor          # checks the bundle, key permissions, ports, disk, database, clock
kavach dev up          # Kavach and a mock provider in one process, loopback only
kavach dev up --at 11:00   # contact is allowed 08:00–19:00 IST; this starts the clock at 11:00 IST
```

`kavach authorize` asks what the gateway would decide, offline: the authorization core runs in pre-check mode in the command's own process, with the project's mandate configuration, agent policies and signed tool registry. The mandate is issued in memory from a synthetic event and dropped on exit. Nothing is recorded and no contact is reserved, so you can vary the time, the contacts already made and the parameters. It exits 0 if the call would be allowed and 1 if not.

```bash
kavach authorize send_reminder                           # required parameters left out get defaults
kavach authorize send_reminder --at 20:30                # BLOCK: outside the contact window
kavach authorize send_reminder --contacts-today 3        # BLOCK: daily contact cap
kavach authorize propose_plan -p waiver_bps=2500         # HUMAN_REVIEW: above the waiver ceiling
kavach authorize send_reminder -p subject_ref=ref:borrower:9876543210   # BLOCK: raw identifier
```

### Policy tests (`kavach policy test`)

`kavach init` writes two starter suites to `policy-tests/`; commit them with your project. `kavach policy test [PATH]` runs every `.yaml` file in `policy-tests/`, or the file or directory you name. Each case gets an `ok` or `FAIL` line. A failing case shows what it expected and what it got, and the command exits 1; an invalid suite exits 64. `--json` gives the per-case results.

**What is tested.** The agent policies are the bundled Cedar policies built into `kavach`; your own are not configurable yet, and the output says so. The tool registry, CEL pack and model are your project's.

**Format, version 1 (pre-alpha: it may change before v0.1).** Every key is checked, so a typo fails the file. Every case asserts a `decision` or `refused`.

```yaml
version: 1
cases:
  - kind: tool_call                 # decided offline, as `kavach authorize` does
    name: no reminders at 20:30 IST # unique within the file
    tool: send_reminder
    at: "20:30"                     # RFC 3339, or HH:MM = IST on 2026-10-01 (default 11:00)
    contacts_today: 0               # contacts already made with the borrower today
    agent: collections-agent        # default: the delegate, else the mandate's agent
    params: { subject_ref: "ref:borrower:B-9382", channel: whatsapp, template_id: emi_reminder_v1 }
    mandate:                        # optional; a real mandate, issued in memory
      subject: ref:borrower:B-9382  # needs a consent for that borrower in the bundle
      assigned_to: collections-agent
      delegate: { to: translation-agent, actions: [read_fields] }   # through the real delegation rules
    expect: { decision: BLOCK, reasons_include: [contact-window] }

  - kind: evaluate                  # a decision request against the pack and model
    name: high debt ratio raises an alert
    governance_mode: enforce        # or shadow
    at: "2026-08-01T10:00:01Z"      # server time; default the request's decision_time
    request: { ... }                # as POST /v1/evaluate takes it
    expect: { decision: ALERT, reasons: [RBI_DTI_EXCEEDED] }
```

`expect` takes one of:
- `decision` (PASS, ALERT, BLOCK, HUMAN_REVIEW), optionally with `reasons` (exactly these, in any order) and `reasons_include` (at least these);
- `refused: true`, or `refused: { code: ... }`.

Refusal codes for tool calls are `unknown_tool`, `invalid_envelope`, `unknown_parameter`, `missing_parameter`, `invalid_parameter` and `no_passport`. For evaluate requests they are `validation`, `model_mismatch`, `pack_not_effective`, `conflict`, `policy` and `domain`. Params are sent exactly as written; nothing is defaulted. The mandate can't widen or narrow its own agent's actions, because no real mandate can do that: use `delegate.actions`.

The live path goes through the running stack, and the stack records it: mandates in its store, and calls in the evidence chain with their contact counts. With `kavach dev up` running in another terminal:

```bash
kavach sor event                                  # a signed SoR event; prints the mandate id
kavach call send_reminder --mandate <id>          # through the gateway: decision, record id, outcome
kavach call send_reminder --issue-mandate         # sends the event first, and says so
```

`dev up` writes `.kavach/run.json`, readable by its owner only. It holds the process id, the listener addresses and the clock offset from `--at`, and never a token. Events are stamped on the stack's clock. The file is removed on Ctrl-C or SIGTERM. If a killed stack leaves it behind, `call` notices that nothing answers there.

Every command takes `--json` and prints one document (schema `kavach.cli/v1`). Exit codes: 0 ok, 1 failed, 2 warnings, 64 usage error. Output passes through the same redaction as the logs. `kavach.toml` keeps everything in memory unless you uncomment its `[database]` section. Nothing is sent anywhere.

## 5. Running the API

`docs/INSTALL.md` lists every flag. Two things matter for local runs:

- **macOS has no Linux kernel clock status**, so the agent surfaces cannot prove synced time. Use `--insecure-dev` locally; it declares the system clock synced, allows in-memory stores and an unsigned tool registry, and prints a warning. Never use it in production.
- The agent surfaces need keys and fixtures (mandate, evidence and credential keys; a signed tool registry; providers; references). `kavach init` will generate them; until then, follow the agent-surfaces section of `docs/INSTALL.md` and use `kavach-keys` and `kavach-mock-provider keygen`.

## 6. Policy proofs (optional)

CI proves properties of the agent Cedar policies with cvc5 on every PR. To run them locally, install cvc5 (a release binary from <https://github.com/cvc5/cvc5/releases>) and run:

```bash
CVC5=/path/to/cvc5 ./scripts/verify.sh
```

## 7. Credential interop check (optional)

CI decrypts the checked-in credential vector with an independent JOSE library:

```bash
cd scripts/jose-crosscheck && npm ci --ignore-scripts && \
  node check.mjs ../../crates/kavach-credential/tests/vectors/credential-v1.json
```

## 8. Benchmarks (`kavach-bench`)

`kavach-bench` runs the real API in-process and drives the gateway path at fixed concurrency: decision, evidence commit, reference resolution, credential, forward to the mock provider, outcome. It reports p50/p95/p99/max latency and requests per second for each scenario and concurrency level, with the environment that produced them.

```sh
# A smoke run on the memory store (the figures mean nothing):
cargo run --release -p kavach-bench -- --subjects 100 --duration-seconds 5

# Against Postgres (a fresh schema per run, dropped afterwards):
KAVACH_BENCH_DATABASE_URL='postgres://kavach:…@db.internal/kavach' \
  cargo run --release -p kavach-bench -- --out bench.json
```

- **Scenarios:** `delivered` (spread over all subjects), `blocked` (decided and recorded, never forwarded), `precheck` (`/v1/authorize`, nothing recorded) and `hot-subject` (every call on one borrower: contention on one contact-counter row).
- **Defaults:** concurrency 1, 8, 32 and 64; 5 s warm-up and 30 s per run; 1,000 subjects; no provider delay. `--provider-delay-ms 50` stands in for a real provider. With no delay the figures measure Kavach's own cost only, and the report says so.
- **Database:** a URL without `sslmode` connects with `verify-full` (pass `--database-ca` for a private CA); `sslmode=disable` gives the plaintext baseline. The report records which.
- It runs with a fixed trusted clock and development keys, so it is a measuring tool, never a deployment. Numbers worth quoting come from a dedicated machine, not a laptop or a shared CI runner.

## 9. Disk use

- Local builds skip debug info for dependencies (`[profile.dev]` in `Cargo.toml`), so `target/` stays around 4–6 GB.
- `scripts/disk-guard.sh` removes superseded test binaries when `target/` grows past 6 GB (`--check-size`), and runs `cargo clean` if free space drops below 8 GB. `verify.sh` runs it first. Limits: `KAVACH_MIN_FREE_GB`, `KAVACH_MAX_TARGET_GB`.
- It only ever touches `target/`, which cargo rebuilds.

## 10. Supply chain

- CI actions are pinned by commit SHA, CI tools by version, image bases by digest; `Cargo.lock` is committed and the image builds with `--locked`.
- The *Supply chain* workflow (weekly, on demand and on every push to `main`) re-runs `cargo audit` and `cargo deny` and uploads one CycloneDX 1.5 SBOM per shipped binary. Locally: `cargo install cargo-cyclonedx --locked --version 0.5.9`, then `cargo cyclonedx --format json --spec-version 1.5 --describe binaries`.
- `main` is protected: changes land through PRs with the seven required checks (the six CI jobs and Network isolation) green on an up-to-date branch.

## 11. Before opening a PR

Run `./scripts/verify.sh`, sign off your commits (`git commit -s`), and update `docs/SECURITY_PROPERTIES.md` in the same PR if you change a guarantee. See [CONTRIBUTING.md](../CONTRIBUTING.md).
