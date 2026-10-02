# Changelog

Notable changes to Kavach. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Kavach is pre-alpha: there are no releases yet, and anything may change before v0.1.

## [Unreleased]

### Changed

- **Breaking (configuration):** the agent data plane now requires a checkpoint signing key. Startup fails without `--checkpoint-keys-dir` (`KAVACH_CHECKPOINT_KEYS_DIR`); the key id defaults to `kavach-checkpoint-1` (`--checkpoint-key-id`).
  - Create it with `kavach-keys generate` in a key directory, as for the other keys.
  - It must not share an id with the mandate, evidence or credential key, or key material with the evidence key.
  - A `dev-` key is accepted only with `--insecure-dev`. Development bundles from `kavach-dev generate` already include `dev-checkpoint-1` and its settings; regenerate older bundles.
  - Deployments that do not enable the agent data plane are unaffected.

### Added

- Signed evidence checkpoints for the agent chain (ADR-005 §13): a background writer, the `evidence_checkpoints` table (migration 012), `--checkpoint-interval-seconds` and `--checkpoint-stall-seconds`.
- Checkpoint health in `GET /v1/runtime` (`checkpoint_lag_seconds`, `checkpoint_stalled`, `checkpoint_last_seq`, `checkpoint_uncovered_records`) and in the metrics (`kavach_checkpoint_*`, `kavach_checkpoints_*`).
- Checkpoint format v1, with test vectors and a specification in `docs/EVIDENCE_BUNDLE.md`.

### Not yet

- Export and offline verification of checkpoints are not shipped. Until they are, Kavach does not claim protection against a truncated or rewritten evidence chain.
