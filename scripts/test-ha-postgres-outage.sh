#!/usr/bin/env bash
# Run the shared-Postgres outage test against a disposable local cluster.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STATE=$(mktemp -d "${TMPDIR:-/tmp}/kavach-ha-outage.XXXXXX")
DATA="$STATE/data"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
DB_USER=$(id -un)

cleanup() {
  if pg_ctl -D "$DATA" status >/dev/null 2>&1; then
    pg_ctl -D "$DATA" stop -m fast >/dev/null
  fi
  rm -rf "$STATE"
}
trap cleanup EXIT

for command in cargo initdb pg_ctl python3; do
  command -v "$command" >/dev/null || {
    printf 'Required command not found: %s\n' "$command" >&2
    exit 1
  }
done

LC_ALL=C initdb -D "$DATA" -U "$DB_USER" --auth=trust >/dev/null
touch "$DATA/.kavach-ha-outage-test-cluster"
cat >>"$DATA/postgresql.conf" <<EOF
listen_addresses = '127.0.0.1'
port = $PORT
EOF
pg_ctl -D "$DATA" -l "$STATE/postgres.log" start >/dev/null

cd "$ROOT"
KAVACH_TEST_DATABASE_URL="postgres://$DB_USER@127.0.0.1:$PORT/postgres?sslmode=disable" \
KAVACH_HA_TEST_PGDATA="$DATA" \
  cargo test -p kavach-api --test postgres_ha_server_outage -- --nocapture
