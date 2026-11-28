#!/usr/bin/env bash
# Exercise the gated pilot Compose deployment and observe one API promotion.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STATE=$(mktemp -d "${TMPDIR:-/tmp}/kavach-ha-compose.XXXXXX")
PROJECT="kavach-ha-acceptance-${RANDOM}-${$}"
OIDC_PID=
COMPOSE=(docker compose -p "$PROJECT" -f "$ROOT/deploy/docker-compose.pilot.yml" -f "$ROOT/deploy/docker-compose.ha-reference.yml" --profile ha-reference-gated)

cleanup() {
  local status=$?
  if [[ -n "$OIDC_PID" ]]; then kill "$OIDC_PID" 2>/dev/null || true; wait "$OIDC_PID" 2>/dev/null || true; fi
  "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$STATE"
  return "$status"
}
trap cleanup EXIT

for command in cargo docker openssl curl python3; do
  command -v "$command" >/dev/null || { printf 'Required command not found: %s\n' "$command" >&2; exit 1; }
done

test_config="$STATE/config"
test_tls="$STATE/db-tls"
# The image runs as a non-root user (uid 10001), which must read this bind
# mount. It holds only the public JWKS and example entities; the OIDC client
# secret stays in the private $STATE directory.
mkdir -m 755 "$test_config"
cp "$ROOT/crates/kavach-auth/policies/entities.example.json" "$test_config/entities.json"
# Generate an actual signing key/JWKS using the repository's OIDC test double.
# The process is stopped as soon as the JWKS file is written.
cd "$ROOT"
cargo build -q -p kavach-api --example oidc_double
"$ROOT/target/debug/examples/oidc_double" \
  --listen 127.0.0.1:0 \
  --client-secret-file "$STATE/oidc.secret" \
  --jwks-out "$test_config/jwks.json" \
  >"$STATE/oidc.log" 2>&1 &
OIDC_PID=$!
for _ in $(seq 1 100); do
  if [[ -s "$test_config/jwks.json" ]] && ! grep -q '"keys":\[\]' "$test_config/jwks.json"; then break; fi
  kill -0 "$OIDC_PID" 2>/dev/null || { cat "$STATE/oidc.log" >&2; exit 1; }
  sleep 0.1
done
[[ -s "$test_config/jwks.json" ]] || { cat "$STATE/oidc.log" >&2; exit 1; }
chmod 0644 "$test_config/entities.json" "$test_config/jwks.json"
kill "$OIDC_PID" 2>/dev/null || true
wait "$OIDC_PID" 2>/dev/null || true
OIDC_PID=

"$ROOT/scripts/pilot-db-tls.sh" "$test_tls"
export KAVACH_PILOT_CONFIG_DIR="$test_config"
export KAVACH_PILOT_DB_TLS_DIR="$test_tls"
export POSTGRES_PASSWORD="acceptance-owner-${RANDOM}-${$}"
export KAVACH_RUNTIME_DB_PASSWORD="acceptance-runtime-${RANDOM}-${$}"
export KAVACH_OIDC_ISSUER="https://issuer.example.test"
export KAVACH_OIDC_AUDIENCE="kavach-api"
export KAVACH_BIND_ADDRESS=127.0.0.1
read -r active_http active_grpc standby_http standby_grpc <<<"$(python3 - <<'PY'
import socket

ports = []
for _ in range(4):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        ports.append(str(sock.getsockname()[1]))
print(" ".join(ports))
PY
 )"
[[ -n "$active_http" && -n "$active_grpc" && -n "$standby_http" && -n "$standby_grpc" ]] || {
  echo 'could not select temporary listener ports' >&2
  exit 1
}
export KAVACH_HTTP_PORT="$active_http"
export KAVACH_GRPC_PORT="$active_grpc"
export KAVACH_HA_STANDBY_HTTP_PORT="$standby_http"
export KAVACH_HA_STANDBY_GRPC_PORT="$standby_grpc"

if ! "${COMPOSE[@]}" up --build --detach --wait --wait-timeout 300 kavach-api kavach-api-standby; then
  echo 'HA Compose stack did not become healthy' >&2
  "${COMPOSE[@]}" ps --all >&2 || true
  "${COMPOSE[@]}" logs --no-color kavach-api kavach-api-standby >&2 || true
  exit 1
fi

lease() {
  "${COMPOSE[@]}" exec -T postgres psql -U "${POSTGRES_USER:-kavach}" -d "${POSTGRES_DB:-kavach}" \
    -At -F '|' -c "SELECT holder_id, epoch FROM active_api_leases WHERE tenant_id = 'default'"
}

initial=""
for _ in $(seq 1 60); do
  initial=$(lease 2>/dev/null || true)
  [[ -n "$initial" ]] && break
  sleep 1
done
[[ -n "$initial" ]] || { echo 'HA lease was not established' >&2; "${COMPOSE[@]}" logs --no-color; exit 1; }
initial_holder=${initial%%|*}
initial_epoch=${initial#*|}
[[ "$initial_epoch" == 1 ]] || { printf 'expected initial lease epoch 1, got %s\n' "$initial" >&2; exit 1; }

# Stopping only the API container models process loss; Postgres and the
# standby remain live. Promotion must change holder and advance the epoch.
"${COMPOSE[@]}" stop kavach-api >/dev/null
promoted=""
for _ in $(seq 1 40); do
  promoted=$(lease 2>/dev/null || true)
  if [[ -n "$promoted" && "${promoted%%|*}" != "$initial_holder" && "${promoted#*|}" -gt "$initial_epoch" ]]; then break; fi
  sleep 1
done
[[ -n "$promoted" && "${promoted%%|*}" != "$initial_holder" && "${promoted#*|}" -gt "$initial_epoch" ]] || {
  printf 'standby did not promote; initial=%s current=%s\n' "$initial" "$promoted" >&2
  "${COMPOSE[@]}" logs --no-color
  exit 1
}

# Both published HTTP listeners should respond once; the stopped active may
# refuse connection, while the promoted standby must be live.
for _ in $(seq 1 20); do
  if curl --silent --output /dev/null --max-time 2 "http://127.0.0.1:${KAVACH_HA_STANDBY_HTTP_PORT}/health"; then break; fi
  sleep 1
done
curl --silent --output /dev/null --max-time 2 "http://127.0.0.1:${KAVACH_HA_STANDBY_HTTP_PORT}/health"
printf 'HA Compose acceptance passed: lease moved from %s to %s\n' "$initial" "$promoted"
