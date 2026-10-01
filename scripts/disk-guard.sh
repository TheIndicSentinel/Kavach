#!/usr/bin/env bash
# Keeps the local build output from filling the disk.
#
# Removes only what cargo regenerates (target/): first the leftovers that
# accumulate across builds (incremental caches, test binaries for old
# sources), and the whole target/ directory if free space is still low.
# Never touches sources, Cargo.lock, console/dist, the cargo registry or
# anything outside this repository.
#
# Cheap when nothing needs doing (one `df`), so it can run before every
# build: scripts/verify.sh calls it, and so can a Claude Code hook.
#
#   KAVACH_MIN_FREE_GB  clean below this much free space (default 8)
#   KAVACH_MAX_TARGET_GB  clean when target/ exceeds this (default 6;
#                         checked only with --check-size, since du is slower)
set -euo pipefail
cd "$(dirname "$0")/.."

min_free_gb=${KAVACH_MIN_FREE_GB:-8}
max_target_gb=${KAVACH_MAX_TARGET_GB:-6}

free_gb() { df -Pk . | awk 'NR==2 { printf "%d", $4 / 1048576 }'; }
target_gb() { [[ -d target ]] && du -sk target | awk '{ printf "%d", $1 / 1048576 }' || echo 0; }

[[ -d target ]] || exit 0

reason=""
if (( $(free_gb) < min_free_gb )); then
  reason="free space $(free_gb) GB < ${min_free_gb} GB"
elif [[ "${1:-}" == "--check-size" ]] && (( $(target_gb) > max_target_gb )); then
  reason="target/ $(target_gb) GB > ${max_target_gb} GB"
fi
[[ -n "$reason" ]] || exit 0

echo "disk-guard: $reason; pruning build output" >&2
# 1. Leftovers that are never reused once sources move on.
rm -rf target/debug/incremental target/release/incremental target/*/incremental
# Superseded test and binary executables: each rebuild leaves the previous
# `<name>-<hash>` behind. Keep the newest per name; cargo rebuilds on demand.
for dir in target/debug/deps target/release/deps; do
  [[ -d "$dir" ]] || continue
  ls -t "$dir" | while read -r file; do
    [[ -f "$dir/$file" && -x "$dir/$file" && "$file" != *.* ]] || continue
    name=${file%-*}
    if [[ " ${seen:-} " == *" $name "* ]]; then
      rm -f "$dir/$file"
    else
      seen="${seen:-} $name"
    fi
  done
done

# 2. Still low: drop the whole build output.
if (( $(free_gb) < min_free_gb )); then
  cargo clean >&2
fi
echo "disk-guard: free space now $(free_gb) GB" >&2
