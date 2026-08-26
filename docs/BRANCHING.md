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
