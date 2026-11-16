#!/usr/bin/env bash
# One command to a running, seeded Kavach with the console signed in through
# a local test identity provider. For trying Kavach on this machine; not a
# deployment.
#
#   scripts/demo.sh          build, start, seed, print the URL and the users
#   scripts/demo.sh stop     stop everything it started, drop its schema
#   scripts/demo.sh status   say whether it runs
#
# Needs: a running Postgres it can reach (it never starts or stops one),
# psql and pg_isready, cargo, npm, curl.
#
# Environment:
#   KAVACH_DEMO_DATABASE_URL  Postgres to use (default
#                             postgres://kavach@127.0.0.1:55433/postgres).
#                             Each run creates its own schema,
#                             kavach_demo_<epoch seconds>, and `stop` drops it.
#                             Give the same value to `stop`.
#   KAVACH_DEMO_SKIP_BUILD=1  use the binaries and console/dist already built
#   CARGO_TARGET_DIR          where cargo puts the binaries (default target/)
#
# What runs, all on 127.0.0.1, until `scripts/demo.sh stop`:
#   kavach-api                :8080 console, /auth/* and the API
#                             (gRPC :8085, system of record :8090, agents :8091)
#   OIDC test double          :9400 asks on each sign-in who to sign in as
#   mock delivery provider    :8443 (inbox :8444)
# State (bundle, keys, logs, pids) is in .demo/ at the repository root,
# owner-only. Evidence goes to Postgres.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STATE="$ROOT/.demo"
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug"
DB_URL="${KAVACH_DEMO_DATABASE_URL:-postgres://kavach@127.0.0.1:55433/postgres}"

API_PORT=8080
GRPC_PORT=8085
SOR_PORT=8090
AGENT_PORT=8091
IDP_PORT=9400
PROVIDER_PORT=8443
PROVIDER_INSPECT_PORT=8444

ORIGIN="http://127.0.0.1:$API_PORT"
IDP="http://127.0.0.1:$IDP_PORT"
SUBJECT="ref:borrower:B-9382"

# One user per Cedar group (crates/kavach-auth/policies/kavach.cedar):
# sub, group, what the policy lets the group do.
USERS=(
  "demo-admin|admins|every proposal, stop and read"
  "demo-approver|change-approvers|approves or rejects change requests"
  "demo-operator|operators|evaluates; reads governance"
  "demo-viewer|viewers|reads governance and health"
)

say() { printf '%s\n' "$*"; }
fail() {
  printf 'demo.sh: %s\n' "$*" >&2
  exit 1
}

# The database as host:port/name, never with a password.
db_label() {
  local rest=${DB_URL#*://}
  rest=${rest#*@}
  printf '%s' "${rest%%\?*}"
}

# Exits unless Postgres answers; prints how to start one, never starts it.
require_postgres() {
  if ! command -v pg_isready >/dev/null || ! command -v psql >/dev/null; then
    fail "psql and pg_isready are needed (the PostgreSQL client tools)."
  fi
  if ! pg_isready -q -d "$DB_URL" -t 5; then
    say "Postgres is not reachable at $(db_label)." >&2
    say "Start your Postgres, then run scripts/demo.sh again. For the local recipe in docs/INSTALL.md:" >&2
    say "  pg_ctl -D <data directory> -l <log file> -o '-p 55433 -k /tmp -c listen_addresses=127.0.0.1' start" >&2
    say "Or point KAVACH_DEMO_DATABASE_URL at another Postgres (14 or newer)." >&2
    exit 1
  fi
}

# True when a pid file names a live process.
alive() { [[ -f "$1" ]] && kill -0 "$(cat "$1")" 2>/dev/null; }

running() {
  local pid
  for pid in "$STATE"/pids/*.pid; do
    [[ -e "$pid" ]] || continue
    alive "$pid" && return 0
  done
  return 1
}

port_taken() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# Waits until `url` answers 2xx, while the process of pid file `pid` lives.
wait_for() {
  local name=$1 url=$2 pid=$3 tries=${4:-120}
  while ((tries > 0)); do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then return 0; fi
    if ! alive "$pid"; then break; fi
    sleep 1
    tries=$((tries - 1))
  done
  say "$name did not start. Last lines of $STATE/logs/$name.log:" >&2
  tail -n 20 "$STATE/logs/$name.log" >&2 || true
  return 1
}

# Starts a command in the background, logging to .demo/logs/<name>.log.
start() {
  local name=$1
  shift
  nohup "$@" >"$STATE/logs/$name.log" 2>&1 &
  echo $! >"$STATE/pids/$name.pid"
}

stop_processes() {
  local pid
  for pid in "$STATE"/pids/*.pid; do
    [[ -e "$pid" ]] || continue
    if alive "$pid"; then kill "$(cat "$pid")" 2>/dev/null || true; fi
  done
  local tries=20
  while running && ((tries > 0)); do
    sleep 0.5
    tries=$((tries - 1))
  done
  for pid in "$STATE"/pids/*.pid; do
    [[ -e "$pid" ]] || continue
    if alive "$pid"; then kill -9 "$(cat "$pid")" 2>/dev/null || true; fi
    rm -f "$pid"
  done
}

# Drops the run's schema; only a name this script made.
drop_schema() {
  [[ -f "$STATE/schema" ]] || return 0
  local schema
  schema=$(cat "$STATE/schema")
  if [[ ! "$schema" =~ ^kavach_demo_[0-9]+$ ]]; then
    say "Not dropping schema '$schema': not a demo.sh schema." >&2
    return 0
  fi
  if pg_isready -q -d "$DB_URL" -t 5 &&
    psql "$DB_URL" -q -v ON_ERROR_STOP=1 -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1; then
    rm -f "$STATE/schema"
    say "Dropped schema $schema."
  else
    say "Could not drop schema $schema at $(db_label); drop it yourself, or run scripts/demo.sh stop again." >&2
  fi
}

cmd_stop() {
  if [[ ! -d "$STATE" ]]; then
    say "Nothing to stop."
    return 0
  fi
  stop_processes
  drop_schema
  say "Stopped."
}

cmd_status() {
  if running; then
    say "Running. Open $ORIGIN/ ; stop with scripts/demo.sh stop"
  else
    say "Not running."
    return 1
  fi
}

# The scoped runtime URL: the run's schema on the search path, plaintext
# (sslmode=disable, which kavach-api accepts only with --insecure-dev).
scoped_url() {
  local schema=$1 sep='?'
  [[ "$DB_URL" == *\?* ]] && sep='&'
  local url="$DB_URL${sep}options=-c%20search_path%3D$schema"
  [[ "$DB_URL" == *sslmode=* ]] || url="$url&sslmode=disable"
  printf '%s' "$url"
}

# kavach-dev sor-event: signs a system-of-record event with the bundle's key
# and posts it; prints the reply.
sor_event() {
  "$BIN/kavach-dev" sor-event --bundle "$STATE/bundle" \
    --url "http://127.0.0.1:$SOR_PORT/v1/sor/events" \
    --event-id "$1" --subject-ref "$SUBJECT" "${@:2}"
}

# One agent call through the gateway; a refusal is an answer, a 5xx or a 401
# fails the run.
agent_call() {
  local agent=$1 mandate=$2 request=$3 status
  status=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "authorization: Bearer $(cat "$STATE/bundle/agents/$agent.jwt")" \
    -H 'content-type: application/json' \
    --data "{\"mandate_id\":\"$mandate\",\"request_id\":\"$request\",\"params\":{\"subject_ref\":\"$SUBJECT\",\"channel\":\"whatsapp\",\"template_id\":\"emi_reminder_v1\"}}" \
    "http://127.0.0.1:$AGENT_PORT/v1/tools/send_reminder")
  if [[ "$status" == 401 || "$status" -ge 500 ]]; then
    fail "seeding: agent call $request answered $status"
  fi
}

# As the e2e seed (console/e2e/realSetup.ts): issue a mandate, call under
# it, with a forged mandate and as another agent, revoke it, call again.
seed() {
  local reply mandate
  reply=$(sor_event evt-demo-assign)
  mandate=$(printf '%s' "$reply" | sed -n 's/.*"mandate_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  [[ -n "$mandate" ]] || fail "seeding: the system-of-record event issued no mandate"
  agent_call collections-agent "$mandate" demo-live
  agent_call collections-agent mandate-that-was-never-issued demo-forged-mandate
  agent_call translation-agent "$mandate" demo-other-agent
  sor_event evt-demo-paid --revoke loan.paid >/dev/null
  agent_call collections-agent "$mandate" demo-after-revocation
}

cmd_start() {
  local tool
  for tool in cargo npm curl; do
    command -v "$tool" >/dev/null || fail "$tool is needed."
  done
  if running; then
    fail "already running (open $ORIGIN/). Stop it first: scripts/demo.sh stop"
  fi
  require_postgres
  local port
  for port in $API_PORT $GRPC_PORT $SOR_PORT $AGENT_PORT $IDP_PORT $PROVIDER_PORT $PROVIDER_INSPECT_PORT; do
    if port_taken "$port"; then
      fail "port $port on 127.0.0.1 is in use; stop what listens there (a Vite dev server proxies to :8080 but does not listen on it)."
    fi
  done

  if [[ "${KAVACH_DEMO_SKIP_BUILD:-}" != 1 ]]; then
    say "Building the console..."
    (
      cd "$ROOT/console"
      [[ -d node_modules ]] || npm ci --no-audit --no-fund >/dev/null
      npm run build >/dev/null
    )
    say "Building kavach-api, the OIDC test double, kavach-dev and the mock provider (the first build takes a while)..."
    (
      cd "$ROOT"
      cargo build -q -p kavach-api --bin kavach-api --example oidc_double \
        -p kavach-devkit --bin kavach-dev -p kavach-mock-provider --bin kavach-mock-provider
    )
  fi
  for tool in kavach-api examples/oidc_double kavach-dev kavach-mock-provider; do
    [[ -x "$BIN/$tool" ]] || fail "$BIN/$tool is missing; run without KAVACH_DEMO_SKIP_BUILD."
  done

  rm -rf "$STATE"
  mkdir -m 700 "$STATE"
  mkdir -m 700 "$STATE/logs" "$STATE/pids"

  # From here on, a failure stops what started and drops the schema.
  trap 'status=$?; if ((status != 0)); then say "Start failed; cleaning up." >&2; stop_processes; drop_schema; fi' EXIT

  local schema="kavach_demo_$(date +%s)"
  psql "$DB_URL" -q -v ON_ERROR_STOP=1 -c "CREATE SCHEMA $schema" >/dev/null ||
    fail "could not create schema $schema at $(db_label)"
  echo "$schema" >"$STATE/schema"

  local users="{\"users\":[" first=1 entry sub group
  for entry in "${USERS[@]}"; do
    IFS='|' read -r sub group _ <<<"$entry"
    ((first)) || users+=","
    users+="{\"sub\":\"$sub\",\"groups\":[\"$group\"]}"
    first=0
  done
  echo "$users]}" >"$STATE/users.json"

  "$BIN/kavach-dev" generate --out "$STATE/bundle" --kavach-mount "$STATE/bundle/kavach" \
    --provider-endpoint "https://localhost:$PROVIDER_PORT" \
    --provider-host localhost --provider-host 127.0.0.1 --database-host localhost \
    --issuer "$IDP" --token-hours 8 >/dev/null

  start oidc-double "$BIN/examples/oidc_double" --listen "127.0.0.1:$IDP_PORT" \
    --client-secret-file "$STATE/console.secret" --jwks-out "$STATE/jwks.json" \
    --also-trust "$STATE/bundle/kavach/jwks.json" \
    --sub demo-admin --groups admins --users "$STATE/users.json" --pick
  wait_for oidc-double "$IDP/.well-known/openid-configuration" "$STATE/pids/oidc-double.pid" 30

  local provider="$STATE/bundle/provider"
  start mock-provider "$BIN/kavach-mock-provider" serve \
    --listen "127.0.0.1:$PROVIDER_PORT" --inspect-listen "127.0.0.1:$PROVIDER_INSPECT_PORT" \
    --encryption-key "$provider/encryption.key" --encryption-kid dev-provider-enc-1 \
    --credential-keys "$provider/credential-keys.json" \
    --tls-cert "$provider/tls.pem" --tls-key "$provider/tls-key.pem"
  wait_for mock-provider "http://127.0.0.1:$PROVIDER_INSPECT_PORT/v1/inbox" "$STATE/pids/mock-provider.pid" 30

  # The bundle's settings, the run's schema (in the environment, not on the
  # command line), and console login against the double.
  (
    set -a
    # shellcheck disable=SC1091
    . "$STATE/bundle/kavach/kavach.env"
    set +a
    KAVACH_DATABASE_URL=$(scoped_url "$schema")
    export KAVACH_DATABASE_URL
    cd "$ROOT"
    start kavach-api "$BIN/kavach-api" \
      --listen "127.0.0.1:$API_PORT" --grpc-listen "127.0.0.1:$GRPC_PORT" \
      --sor-listen "127.0.0.1:$SOR_PORT" --agent-listen "127.0.0.1:$AGENT_PORT" \
      --pack packs/finance/v0.yaml --model models/finance/credit-underwriting-v1.yaml \
      --evidence-store postgres \
      --access-control cedar \
      --cedar-policy crates/kavach-auth/policies/kavach.cedar \
      --cedar-entities crates/kavach-auth/policies/entities.example.json \
      --insecure-dev --oidc-jwks-file "$STATE/jwks.json" \
      --console-client-id kavach-console --console-client-secret-file "$STATE/console.secret" \
      --console-redirect-uri "$ORIGIN/auth/callback"
  )
  wait_for kavach-api "$ORIGIN/auth/config" "$STATE/pids/kavach-api.pid" 180

  say "Seeding: a mandate, agent calls under it, its revocation..."
  seed
  trap - EXIT

  say ""
  say "Kavach is running. Open the console:"
  say ""
  say "  $ORIGIN/"
  say ""
  say "Sign in: the test identity provider asks who to sign in as, each time."
  for entry in "${USERS[@]}"; do
    IFS='|' read -r sub group what <<<"$entry"
    printf '  %-14s %-17s %s\n' "$sub" "$group" "$what"
  done
  say ""
  say "Evidence: Postgres $(db_label), schema $schema. Logs: .demo/logs/"
  say "Stop everything (and drop the schema): scripts/demo.sh stop"
}

case "${1:-start}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  *) fail "usage: scripts/demo.sh [start|stop|status]" ;;
esac
