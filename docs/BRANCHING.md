# Branching and GitHub setup

## Workflow

- **`main`** — stable; CI must pass before merge
- **`feat/*`** — short-lived feature branches → PR → merge → delete

Current work: `feat/kavach-policy` → PR into `main`.

## Protect `main` (one-time, GitHub UI)

1. Open https://github.com/TheIndicSentinel/Kavach/settings/branches
2. **Add branch protection rule** for `main`
3. Enable:
   - **Require a pull request before merging**
   - **Require status checks to pass** (select CI jobs after first green run):
     - `Format, Clippy, Test`
     - `Security audit`
     - `License and dependency policy`
   - **Do not allow bypassing the above settings**
   - **Restrict force pushes**

Solo founders may leave “Require approvals” at 0 until a collaborator joins.

## Commands

```bash
git checkout main && git pull
git checkout -b feat/my-feature
# work, commit, push
git push -u origin feat/my-feature
gh pr create --base main --title "..." --body "..."
# after CI green
gh pr merge --squash
```

## Policy pack changes (credit underwriting)

Keep **pack rules**, **scenario NDJSON**, and **manifest expectations** in the same PR. CI runs `./scripts/simulate-credit-underwriting.sh` on every push.

```bash
git checkout -b cursor/feat-policy-<change>-4a07
# edit packs/finance/v0.yaml
# edit partner/finance/scenarios/credit_underwriting_v1.ndjson
# edit partner/finance/scenarios/manifest.json
./scripts/simulate-credit-underwriting.sh
git push -u origin cursor/feat-policy-<change>-4a07
```

Details: [CREDIT_UNDERWRITING_SIMULATION.md](CREDIT_UNDERWRITING_SIMULATION.md).
