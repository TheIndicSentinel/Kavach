#!/usr/bin/env bash
# Fails if a local secret path reaches the Docker build context.
#
# Plants a canary at each path .dockerignore must exclude, copies the build
# context into a scratch stage exported to a temporary directory (no base
# image, no image left behind) and checks that no canary arrived. Canary
# names are unique, so real local files (.demo/console.secret, deploy/.env)
# are never touched; everything the script creates is removed on exit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CANARIES=(
  .demo/canary-ctx
  .env.canary-ctx
  .tools/canary-ctx
  deploy/canary-ctx.env
  deploy/pilot-config/canary-ctx
  deploy/pilot-db-tls/canary-ctx
  deploy/agent-stack/bundle/canary-ctx
  crates/canary-ctx/.env
  crates/canary-ctx/tls.pem
  crates/canary-ctx/signing.key
  crates/canary-ctx/client.p12
  crates/canary-ctx/console.secret
)
# Paths the build needs: their absence means the check itself is wrong.
REQUIRED=(Cargo.toml Cargo.lock deploy/pilot.env.example packs models)

OUT="$(mktemp -d)"
CREATED_DIRS=()
cleanup() {
  for f in "${CANARIES[@]}"; do rm -f "$f"; done
  # Remove only directories this script created, deepest first.
  for ((i = ${#CREATED_DIRS[@]} - 1; i >= 0; i--)); do
    rmdir "${CREATED_DIRS[$i]}" 2>/dev/null || true
  done
  rm -rf "$OUT"
}
trap cleanup EXIT

for f in "${CANARIES[@]}"; do
  d="$(dirname "$f")"
  if [ ! -d "$d" ]; then
    mkdir -p "$d"
    CREATED_DIRS+=("$d")
  fi
  if [ -e "$f" ]; then
    echo "refusing to overwrite existing file: $f" >&2
    exit 2
  fi
  echo canary >"$f"
done

DOCKER_BUILDKIT=1 docker build --quiet --output "type=local,dest=$OUT" -f - . <<'EOF' >/dev/null
FROM scratch
COPY . /ctx/
EOF

status=0
for f in "${CANARIES[@]}"; do
  if [ -e "$OUT/ctx/$f" ]; then
    echo "LEAK: $f is in the build context" >&2
    status=1
  fi
done
for f in "${REQUIRED[@]}"; do
  if [ ! -e "$OUT/ctx/$f" ]; then
    echo "MISSING: $f is not in the build context" >&2
    status=1
  fi
done
if [ "$status" -eq 0 ]; then
  echo "build context: ${#CANARIES[@]} canaries excluded, ${#REQUIRED[@]} required paths present"
fi
exit "$status"
