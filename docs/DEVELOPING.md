# Developing Kavach locally

This is the setup for running and testing Kavach on your own machine. It is written for macOS and Linux; everything optional is marked so.

> **The quick way:** `kavach init` generates the development keys, signed tool registry, fixtures and configuration below in one step, and `kavach dev up` starts the whole stack (section 4). The manual steps here are what those commands do, for when you need one piece on its own.

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

## 3b. A one-minute tour (`kavach demo`)

```bash
cargo run -q -p kavach-cli -- demo     # or: kavach demo
```

`kavach demo` tells the story with the real commands, each shown so you can repeat it:
1. a mandate from a system-of-record event;
2. a reminder allowed at 11:00 and delivered, without the agent seeing the number;
3. `why` with the record's signature checked;
4. a raw phone number blocked;
5. another borrower blocked;
6. the clock moved to 20:30 and the same reminder blocked;
7. the offline what-if;
8. a credit decision whose shadow-mode PASS hides a would-be BLOCK;
9. the attack catalog refused.

It runs in a throwaway project (deleted afterwards; `--keep` to keep it) with a dev stack on free loopback ports and a fixed clock, so it works at any hour, and nothing leaves the machine. `--step` pauses between steps on a terminal, and `--no-attack` leaves out the last step. It exits 0 if every step behaved as scripted and 1 if one didn't, which means a regression. The 20× acceptance gate runs it.

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
kavach dev up --clock 11:00   # a fixed clock at 11:00 IST on 2026-10-01; it stays put
kavach dev clock 20:30        # move it forward (to its next 20:30): the same calls now BLOCK
```

`kavach authorize` asks what the gateway would decide, offline: the authorization core runs in pre-check mode in the command's own process, with the project's mandate configuration, agent policies and signed tool registry. The mandate is issued in memory from a synthetic event and dropped on exit. Nothing is recorded and no contact is reserved, so you can vary the time, the contacts already made and the parameters. It exits 0 if the call would be allowed and 1 if not.

```bash
kavach authorize send_reminder                           # required parameters left out get defaults
kavach authorize send_reminder --at 20:30                # BLOCK: outside the contact window
kavach authorize send_reminder --contacts-today 3        # BLOCK: daily contact cap
kavach authorize propose_plan -p waiver_bps=2500         # HUMAN_REVIEW: above the waiver ceiling
kavach authorize send_reminder -p subject_ref=ref:borrower:9876543210   # BLOCK: raw identifier
```

When exactly **one business constraint** blocks the call (contact window, daily cap, channel or waiver ceiling), `authorize` also says what single change would pass, and gives the bound. The heading is "what-if under current policies". Examples: "at 08:00 IST tomorrow (contact window 08:00–19:00 IST)", "after the daily cap resets (08:00 IST tomorrow), contacts < 3 per IST day", "channel ∈ {whatsapp}", "waiver_bps ≤ 1000". Candidates come from the mandate itself, not from a search, and each is confirmed by one real re-run of the authorization core. If two business constraints fail at once, it says no single change passes. A call blocked for a **safety** reason (a raw identifier, the mandate, the subject, the agent, trusted time) gets no suggestions, so nothing here is a bypass hint. Counterfactuals exist only in this offline command: the agent API never returns them.

### Explaining a decision (`kavach why`)

`kavach why <record-id>` explains a decision `kavach call` recorded: each reason in words, with the usual fix, plus the mandate, the time and its sync state, and the policy and registry digests. The subject appears only as its pseudonym.

```bash
kavach why adr:default:0:1                        # from the running dev stack
kavach why adr:default:0:1 --bundle ./export      # offline, from an evidence bundle
```

- **Live:** reads the record from the operator API (`read_evidence`; every read is audited). It checks the record's own hash and signature against **local** trusted keys (`--keys`, default `.kavach/auditor/trusted-keys.json`), never a key from the server. Dev records say "verified against dev keys". A single record proves nothing about the chain, and the output says so.
- **Explore:** for a decision blocked by business constraints only, `why` prints the `kavach authorize` command to explore it offline. The command has placeholders (`-p channel=<value>`), never the record's values, which the record does not hold anyway.
- **`--bundle`:** verifies the whole bundle first, as `kavach-evidence verify-bundle` does (files, chain, checkpoints), then explains the record from it. No network. It exits 2 if the bundle verifies but something is not protected.

**Credit (evaluate) decisions.** `kavach why <evidence-id>` (a UUID, as `/v1/evaluate` returns it) explains a credit decision:
- both decisions and the governance mode. In shadow mode a PASS return can hide a would-be BLOCK, and the output says so;
- the reasons, the pack and model versions, and the decision time;
- the input, only as its digest.

This evidence is hash-chained but **not signed** (v1). Anyone with write access to the database could rewrite a record and rehash the chain, so the output says "hash matches the content; not signed, so this does not prove the record wasn't rewritten". `--export <file>` checks the whole chain of a decision event export first, and reports a break before showing anything. There are no counterfactuals for credit decisions. A record written before schema 1.1.0 and read back from Postgres may fail only because storage dropped its nanoseconds. `why` then says it **cannot be re-checked (legacy precision)** and exits 2: never "verified", and not called tampered either. Re-baseline such chains (export, then start a fresh one).

### Evidence bundles (`kavach evidence`)

`kavach evidence export <dir>` writes the agent evidence chain as a bundle (`docs/EVIDENCE_BUNDLE.md`), signed with the auditor's export key in `.kavach/auditor/`, never a key of the stack. It needs `[database]` in `kavach.toml`: the memory store keeps nothing once `dev up` stops. A dev project reads with a role that can write, which a production export (`kavach-evidence export`, as `kavach_auditor`) refuses; the output says so.

`kavach evidence verify <dir>` checks a bundle offline against trusted keys (`.kavach/auditor/trusted-keys.json`, or `--keys`; never the bundle's). What is **not** protected comes first, then what verified. Exit 0 verified, 2 verified but not fully protected (`--allow-warnings` accepts that), 1 failed. Dev keys are accepted only when the trusted keys are themselves dev keys, and the output says "development". Pass `--checkpoint` with a checkpoint you kept off-host to detect a chain cut short or rewritten by someone holding the keys.

### Known attacks (`kavach attack`)

`kavach attack` runs the attack catalog against the running `kavach dev up`. The catalog (`crates/kavach-attacks`, version 3, 22 attacks) is the same one the acceptance suite runs in CI.

```bash
kavach attack --list            # the scope: every attack, nothing run
kavach dev up --clock 11:00     # in another terminal: a fixed clock the run can move
kavach attack                   # exit 0 all refused, 1 an attack succeeded or drifted, 2 inconclusive
```

- **Ground truth:** an attack **succeeded** if a credential was minted (an allowed gateway call, read from `/metrics`) or the mock provider's inbox changed, whatever the reply said.
- **Drift:** an attack refused for a reason the catalog doesn't expect fails the run too. The catalog no longer matches the policies.
- **Inconclusive (exit 2):** the stack is unhealthy, its trusted time is unsynced, or its clock is outside contact hours and can't be moved (`--at`, or no dev clock). The output says which. With `--clock`, the run moves the clock to 11:00 itself.
- **Clock attacks:** two attacks need a fixed clock (`dev up --clock`).
  - **out of hours:** the clock moves to 20:30 for the call, then on to 11:00.
  - **daily cap:** the clock moves to 11:00 on a fresh day, three allowed reminders are made as **declared setup**, and only the fourth call is judged. The setup is reported separately and sends three messages to the synthetic destination.
  - **Without a fixed clock** both are reported as skipped, never as passed.
- **Safety:**
  - loopback only, and only bundles with `dev-` keys;
  - at most ten requests a second;
  - every attack aims at a refusal, so it consumes no contact and sends nothing;
  - request ids start with `attack-`, so the BLOCK records are easy to tell apart in evidence.
- **Not a security assessment:** passing means these known attacks fail. `--list --json` maps each attack to its `SECURITY_PROPERTIES.md` row and, where one applies, its `BYPASS_INVENTORY.md` row.
- **The inbox listener:** `dev up` now serves the mock provider's inbox on a fifth loopback listener (`[listen] inspect`, default `127.0.0.1:8444`), which the attack run reads.

### Shell completions and man pages

Both are generated from the command tree, so they always match the binary:

```bash
kavach completions zsh > ~/.zfunc/_kavach        # also bash, fish, powershell, elvish
kavach man | man -l -                            # kavach(1)
kavach man --out ./man                           # one page per command: kavach-dev-up.1, ...
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

Every command takes `--json` and prints one document (schema `kavach.cli/v1`). Exit codes: 0 ok, 1 failed, 2 warnings, 64 usage error. Output passes through the same redaction as the logs. The one exception is known digest fields (`input_digest`, and the Cedar and registry digests): they are printed whole when they are well-formed digests. This is decided by field, never by pattern, so the same hex anywhere else is still masked. `kavach.toml` keeps everything in memory unless you uncomment its `[database]` section. Nothing is sent anywhere.

**Development clocks.** `--at HH:MM` starts the clock at an IST time today and lets it run. `--clock <time>` fixes it: `HH:MM` means IST on 2026-10-01, or give RFC 3339. It stays put until `kavach dev clock <time>` moves it, **only forward**: `HH:MM` means its next occurrence, so "back to 11:00" is 11:00 the next day. That keeps evidence timestamps and checkpoints in order.
- **Dev only:** both run only on a dev stack with `dev-` keys, and the API refuses them otherwise, even when `kavach-api` is started directly.
- **Shown:** both appear in the banner and in `/v1/runtime` (`dev_clock`).
- **Marked in evidence:** everything recorded under a dev clock, records and checkpoints, carries `time_sync: dev_fixed`. The offline verifiers refuse it unless told they are verifying a development stack.
- **Audited:** every move is recorded in the audit log (`dev_clock_set`).

**`dev up` is locked to you.** The operator API needs the project's operator token (`.kavach/operator.jwt`, made by `init`), checked by Cedar with the bundled policies. Every `dev up` listener (operator, agent, SoR, provider, inbox) refuses a Host header that isn't `localhost`, `127.0.0.1` or `[::1]`, which is what a web page attempting DNS rebinding sends, with 421. Every listener also refuses the self-asserted `X-Kavach-Principal` header, which `--insecure-dev` would otherwise accept, with 401. The `kavach` commands send the token for you. Projects made before this get their access-control files on the next `dev up`.

## 5. Running the API

`docs/INSTALL.md` lists every flag. Two things matter for local runs:

- **macOS has no Linux kernel clock status**, so the agent surfaces cannot prove synced time. Use `--insecure-dev` locally; it declares the system clock synced, allows in-memory stores and an unsigned tool registry, and prints a warning. Never use it in production.
- The agent surfaces need keys and fixtures (mandate, evidence and credential keys; a signed tool registry; providers; references). `kavach init` will generate them; until then, follow the agent-surfaces section of `docs/INSTALL.md` and use `kavach-keys` and `kavach-mock-provider keygen`.

### The API contract: `docs/openapi.yaml`

The HTTP API is described by hand in `docs/openapi.yaml` (OpenAPI 3.1; not served by the API; gRPC not covered). Tests keep it true:

- **Contract checks.** The API integration tests build their routers through `tests/contract`, which checks every response against the spec: the status is documented for the route, the content type is the documented one, and the body validates against the schema. A new route, status or field shows up as a failing test until the spec says so.
- **Drift test** (`tests/openapi.rs`). The routes and methods on each listener match the routers' source, the problem codes match `CODES`, and every schema compiles.
- **Lint.** CI runs a pinned Redocly CLI (`redocly.yaml`).

When you change a route or a response, change `docs/openapi.yaml` in the same PR.

### Errors: RFC 9457 problems

Every refusal, on every listener, is `application/problem+json` (RFC 9457):

```json
{
  "type": "/problems/unknown-parameter",
  "title": "Unknown parameter",
  "status": 400,
  "detail": "tool send_reminder: unknown parameter (not an identifier)",
  "code": "unknown_parameter",
  "fix": "send only the parameters the registry lists for this tool",
  "request_id": "6f1c0b9e-4c1a-4f7e-9d3a-2b8e5f0c7a11",
  "error": "tool send_reminder: unknown parameter (not an identifier)"
}
```

- `code` is stable and machine-readable; the full list, with titles and fixes, is `CODES` in `crates/kavach-api/src/problem.rs`. `type` is the relative URI `/problems/<code>`: valid under RFC 9457, but not meant to be dereferenced yet.
- `request_id` matches the `x-request-id` response header. Quote it when reporting a problem: a 5xx `detail` is generic on purpose, and the cause is only in the server's (redacted) log under that id.
- `detail` never repeats what the caller sent beyond plain identifiers.
- Headers: `WWW-Authenticate: Bearer` on 401 (RFC 6750), `Retry-After` on 429 and 503.
- `error` repeats `detail` for clients written against the old `{"error": …}` body. It stays through v0.1 and goes after that.
- A BLOCK or HUMAN_REVIEW is not a problem: it is a 200 reply with reasons.

`kavach` commands print a refusal's `code` and `request_id` under the error (and in `--json`, as `error.code` and `error.request_id`).

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
