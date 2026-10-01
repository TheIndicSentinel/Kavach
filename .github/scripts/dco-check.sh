#!/usr/bin/env bash
# DCO check: every non-merge commit in BASE..HEAD carries a
# `Signed-off-by:` trailer whose email matches the commit author's
# (Developer Certificate of Origin 1.1, see CONTRIBUTING.md).
#
#   dco-check.sh <base-sha> <head-sha>
set -euo pipefail
base=$1
head=$2
failed=0
while read -r sha; do
  [[ -n "$sha" ]] || continue
  author=$(git log -1 --format='%ae' "$sha" | tr '[:upper:]' '[:lower:]')
  signoffs=$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" \
    | sed -n 's/.*<\(.*\)>.*/\1/p' | tr '[:upper:]' '[:lower:]')
  if grep -qxF "$author" <<<"$signoffs"; then
    echo "ok      $sha"
  else
    echo "MISSING $sha $(git log -1 --format='%s' "$sha")"
    echo "        needs: Signed-off-by: <name> <$author>"
    failed=1
  fi
done < <(git rev-list --no-merges "$base..$head")
if (( failed )); then
  echo
  echo "Some commits are not signed off. Sign off with 'git commit -s', or fix"
  echo "existing commits with 'git rebase --signoff $base' and force-push."
  exit 1
fi
echo "DCO: all commits signed off."
