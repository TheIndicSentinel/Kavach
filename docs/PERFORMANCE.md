# Performance

What Kavach's gateway path costs, how it is measured, and which figures may be quoted.

## Status

| Figures | Status |
|---|---|
| **Published numbers** (reference machine, below) | **Not yet measured.** No figure in this file is a performance claim until this row says otherwise. |
| CI trends (nightly, shared runners) | Running: the *Benchmarks* workflow. These are **trends**: they show whether a change made things faster or slower, not how fast Kavach is. |

Until the reference run exists, quote only CI trends, and say that they are trends.

## The targets (PRD NFR-2)

On the reference hardware (ADR-003 §10: 4 CPU cores, 16 GB RAM, local PostgreSQL 16):

| Target | Measured by |
|---|---|
| `authorize` p99 < 5 ms in-process | Not yet: the `precheck` scenario includes HTTP and authentication, so it is an upper bound. An in-process measurement is planned with the evidence micro-benchmarks. |
| Gateway overhead p99 < 15 ms, including the minimal critical evidence write | `delivered` and `hot-subject` with no provider delay; `commit` isolates the evidence write |
| 1,000 requests/s, single node | Requests per second of `delivered` at the highest concurrency |

ADR-003 named `criterion` and `oha` for these. The gateway is measured with `kavach-bench` instead: every request needs its own `request_id` and a mandate per subject, which a generic load tool does not produce.

## What is measured

`kavach-bench` ([DEVELOPING.md](DEVELOPING.md) §8) runs the real API in-process and drives it over loopback HTTP at fixed concurrency (1, 8, 32 and 64 agents; 5 s warm-up, 30 s per run).

| Scenario | What one request does |
|---|---|
| `delivered` | Decide, record the evidence (one Postgres transaction), resolve the reference, issue the credential, forward to the mock provider, record the outcome. Spread over 1,000 subjects. |
| `blocked` | Decide and record a BLOCK; nothing forwarded. |
| `precheck` | `POST /v1/authorize`: decide only, nothing recorded. |
| `hot-subject` | As `delivered`, every call on one borrower: all calls contend for one contact-counter row. |

**Where the time goes.** For every gateway run the report also gives the mean time per call in each stage (`decide`, `commit`, `resolve`, `credential`, `forward`, `outcome`), from the API's `kavach_gateway_stage_seconds` histogram, and "other": the rest of the mean, which is HTTP, token verification and request parsing. Stage means include the warm-up calls.

**Storage micro-benchmarks** (Postgres only, no HTTP), for two open questions: is the bottleneck the pool or the evidence partition lock, and what would E5's extra lock cost?

| Scenario | What one operation does |
|---|---|
| `commit` | The evidence commit alone: lock the partition head, insert the record, advance the head. |
| `outcome` | The outcome write as it is today: check the record, insert the outcome. Each operation first commits an allow, which is not timed. |
| `outcome-locked` | The same write as E5 would make it: in one transaction that locks a per-partition outcome head and then advances it. Timed the same way. |

**Pool size.** `--pool-sizes 5,16,32` runs everything once per pool size, each on its own stack and fresh schema, so the pool can be ruled in or out as the ceiling before blaming the partition lock. Every row of the report carries its pool size. Partitioning (by subject hash, so a borrower's daily cap stays in one partition) waits for the reference run to confirm where the ceiling is.

**What the figures do not measure:**
- **A real provider.** With no provider delay the figures are Kavach's own cost only; every real delivery adds the provider's latency. `--provider-delay-ms` stands in for one.
- **A real network.** Agent, Kavach and provider share one machine over loopback.
- **A deployment.** The harness uses a fixed trusted clock and development keys. The daily contact cap is set to its maximum: it is checked on every call but never reached.
- **Partitioning.** One evidence partition serialises every recorded decision; that is the configuration measured.
- **One pool size per row.** The API's Postgres pool defaults to 5 connections (`--database-pool-size`); each row of the report states the size it ran with.

## Every figure carries its environment

A figure without these is not quoted. The harness writes them into every report:

- Kavach version and commit
- CPU model and logical CPUs; OS and architecture
- Postgres version, and whether the connections use TLS (`sslmode`); the pool size
- The provider delay; the number of subjects; warm-up and run duration

**TLS (`verify-full`) is the figure to quote.** Plaintext runs are a baseline only, and the report says so.

## The reference run (procedure)

Run once, on a fixed cloud VM matching NFR-2, then whenever a release is tagged. The result goes into this file with its full report.

1. **Machine:** a dedicated VM with 4 vCPUs and 16 GB RAM (not burstable), Ubuntu 24.04. Note the provider, instance type and region.
2. **Postgres 16 on the same VM,** with TLS exactly as the compose stacks set it up (`deploy/postgres/tls-entrypoint.sh`, `deploy/postgres/pg_hba.conf`, a certificate from `scripts/pilot-db-tls.sh`):
   ```sh
   scripts/pilot-db-tls.sh /opt/kavach-db-tls
   echo "127.0.0.1 postgres" | sudo tee -a /etc/hosts
   docker run -d --name pg -p 5432:5432 \
     -e POSTGRES_USER=kavach -e POSTGRES_PASSWORD=<secret> -e POSTGRES_DB=kavach \
     -v "$PWD/deploy/postgres/tls-entrypoint.sh:/usr/local/bin/kavach-pg-tls.sh:ro" \
     -v "$PWD/deploy/postgres/pg_hba.conf:/etc/kavach-pg/pg_hba.conf:ro" \
     -v /opt/kavach-db-tls:/run/kavach-tls-src:ro \
     --entrypoint sh postgres:16-alpine /usr/local/bin/kavach-pg-tls.sh \
     postgres -c ssl=on -c ssl_cert_file=/etc/postgresql-tls/server.crt \
       -c ssl_key_file=/etc/postgresql-tls/server.key -c hba_file=/etc/kavach-pg/pg_hba.conf
   ```
3. **Build at the commit being measured:** `cargo build --release --locked -p kavach-bench`.
4. **Nothing else running.** Run three times; quote the median run, and keep all three reports:
   ```sh
   for i in 1 2 3; do
     KAVACH_BENCH_DATABASE_URL="postgres://kavach:<secret>@postgres:5432/kavach" \
       target/release/kavach-bench --database-ca /opt/kavach-db-tls/ca.pem \
       --out "reference-$i.json" | tee "reference-$i.md"
   done
   ```
5. **Also once with `--provider-delay-ms 50`,** to show the gateway behind a realistic provider.
6. **Record** in this file: the commit, the date, the VM (provider, instance type, region), the three reports, and each NFR-2 target as met or not met.

## CI trends

The *Benchmarks* workflow runs nightly and on demand on a shared GitHub runner: one run against Postgres with TLS (`verify-full`), every scenario at pool sizes 5, 16 and 32, and one without TLS (the baseline), the gateway scenarios at pool size 5. Each run's tables appear in its summary, and the JSON reports are kept for 90 days.

- **No pass/fail threshold yet.** Thresholds come after at least a week of nightly runs shows how much the figures vary between runs of the same commit.
- **Not a required check.** Neither is the nightly 20× acceptance gate.
