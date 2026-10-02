# Changelog

Notable changes to Kavach. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Kavach is pre-alpha: there are no releases yet, and anything may change before v0.1.

## [Unreleased]

### Changed

- **Breaking (configuration):** the agent data plane now requires a checkpoint signing key. Startup fails without `--checkpoint-keys-dir` (`KAVACH_CHECKPOINT_KEYS_DIR`); the key id defaults to `kavach-checkpoint-1` (`--checkpoint-key-id`).
  - Create it with `kavach-keys generate` in a key directory, as for the other keys.
  - It must not share an id with the mandate, evidence or credential key, or key material with the evidence key.
  - A `dev-` key is accepted only with `--insecure-dev`. Development bundles from `kavach-dev generate` already include `dev-checkpoint-1` and its settings; regenerate older bundles.
  - Deployments that do not enable the agent data plane are unaffected.

- The `kavach-evidence` binary moved to the new `kavach-evidence-cli` crate. Its name and its `verify` command are unchanged; build it with `-p kavach-evidence-cli` instead of `-p kavach-evidence`.
- The API refuses to start if its mandate, evidence, checkpoint or credential key id starts with `export-` (or `dev-export-`): those ids are reserved for evidence export keys.

### Added

- Evidence bundle format v1 (manifest, writer, test vector), the export key rules and the read-only `kavach_auditor` database role (migration 013).
- `kavach-evidence export` writes the agent chain (or a segment after a checkpoint) as a signed bundle from one read-only snapshot, and `kavach-evidence checkpoints` prints checkpoints to copy off-host. Both refuse a database role that can write evidence.
- Development bundles (`kavach-dev generate`) include an export key, `auditor/dev-export-1`.
- `kavach-evidence verify-bundle` checks a bundle offline with keys the operator supplies and, with `--expect-checkpoint`, against a checkpoint kept off-host: a chain cut short or rewritten is detected. It fails closed: exit `1` when the bundle does not verify, exit `2` when it verifies but is not fully protected (`--allow-warnings` accepts that), exit `0` otherwise.

- Signed evidence checkpoints for the agent chain (ADR-005 §13): a background writer, the `evidence_checkpoints` table (migration 012), `--checkpoint-interval-seconds` and `--checkpoint-stall-seconds`.
- Checkpoint health in `GET /v1/runtime` (`checkpoint_lag_seconds`, `checkpoint_stalled`, `checkpoint_last_seq`, `checkpoint_uncovered_records`) and in the metrics (`kavach_checkpoint_*`, `kavach_checkpoints_*`).
- Checkpoint format v1, with test vectors and a specification in `docs/EVIDENCE_BUNDLE.md`.

### Not yet

- Truncation and rewrites are detected only by verifying an export against a checkpoint the operator copied off-host; the live database is not checked continuously, and nothing is anchored outside the operator's own storage.
- A deleted outcome row is detected only against an earlier signed bundle that contains it.
