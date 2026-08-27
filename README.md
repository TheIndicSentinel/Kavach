# Kavach

Rust workspace for the Kavach AI governance platform.

## Remote

- **GitHub:** https://github.com/TheIndicSentinel/Kavach.git

## Quick start

```bash
# Requires Rust stable (https://rustup.rs)
./scripts/build-console.sh   # embed governance console in kavach-api
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Full local verification: `./scripts/verify.sh`

## Phase status

| Milestone | Status |
|---|---|
| Phase 0 | Complete — [docs/PHASE_0_EXIT.md](docs/PHASE_0_EXIT.md) |
| Milestone A | Complete — [docs/MILESTONE_A_EXIT.md](docs/MILESTONE_A_EXIT.md) |
| Milestone B | In progress — B.1–B.3 done; B.4 policy lifecycle UI next |

**On-prem install:** [docs/INSTALL.md](docs/INSTALL.md)  
**Partner payloads:** [partner/](partner/)  
**Branching:** [docs/BRANCHING.md](docs/BRANCHING.md)
