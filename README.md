# Kavach

Rust workspace for the Kavach AI governance platform.

## Remote

- **GitHub:** https://github.com/TheIndicSentinel/Kavach.git

## Quick start

```bash
# Requires Rust stable (https://rustup.rs)
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Phase status

See [docs/PHASE_0_EXIT.md](docs/PHASE_0_EXIT.md).

Phase 0 complete when CI is green on `main`. Milestone A starts with `kavach-policy`.
