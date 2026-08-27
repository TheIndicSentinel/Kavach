#!/usr/bin/env bash
# Start Kavach pilot stack for local / cloud-agent system review.
# Console: http://localhost:8080  (embedded in API)
# Dev hot-reload: http://localhost:5173  (optional, second terminal)
set -euo pipefail
cd "$(dirname "$0")/.."

DB_URL="${KAVACH_DATABASE_URL:-postgres://kavach:change-me@localhost:5432/kavach}"
HTTP_PORT="${KAVACH_HTTP_PORT:-8080}"
SESSION="kavach-pilot-api"

echo "==> Step 0: prerequisites"
command -v cargo >/dev/null || { echo "ERROR: Rust/cargo not found"; exit 1; }
command -v npm >/dev/null || { echo "ERROR: npm not found"; exit 1; }

echo "==> Step 1: build console (embedded in API)"
./scripts/build-console.sh

echo "==> Step 2: build API (release)"
cargo build --release -p kavach-api

echo "==> Step 3: check Postgres"
if command -v pg_isready >/dev/null 2>&1; then
  if ! pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
    echo "WARN: Postgres not running on localhost:5432"
    echo "      Start Postgres or set KAVACH_DATABASE_URL to your instance."
    echo "      Docker: docker compose -f deploy/docker-compose.pilot.yml up -d postgres"
  else
    echo "Postgres OK"
  fi
else
  echo "WARN: pg_isready not found — skipping Postgres check"
fi

echo "==> Step 4: stop anything on port ${HTTP_PORT}"
if command -v fuser >/dev/null 2>&1; then
  fuser -k "${HTTP_PORT}/tcp" 2>/dev/null || true
fi
sleep 1

echo "==> Step 5: start kavach-api (tmux session: ${SESSION})"
tmux -f /exec-daemon/tmux.portal.conf has-session -t "=${SESSION}" 2>/dev/null \
  && tmux -f /exec-daemon/tmux.portal.conf kill-session -t "${SESSION}" || true

tmux -f /exec-daemon/tmux.portal.conf new-session -d -s "${SESSION}" -c "$(pwd)" -- "${SHELL:-bash}" -l
tmux -f /exec-daemon/tmux.portal.conf send-keys -t "${SESSION}:0.0" \
  "export KAVACH_DATABASE_URL='${DB_URL}' && ./target/release/kavach-api \
  --pack packs/finance/v0.yaml \
  --model models/finance/credit-underwriting-v1.yaml \
  --listen 0.0.0.0:${HTTP_PORT} \
  --grpc-listen 0.0.0.0:50051 \
  --evidence-store postgres \
  --access-control cedar \
  --cedar-policy crates/kavach-auth/policies/kavach.cedar \
  --cedar-entities crates/kavach-auth/policies/entities.example.json" C-m

echo "==> Step 6: wait for API"
for _ in $(seq 1 30); do
  if curl -fsS -H 'X-Kavach-Principal: viewer-1' "http://localhost:${HTTP_PORT}/health" >/dev/null 2>&1; then
    echo "API health OK"
    break
  fi
  sleep 1
done

if ! curl -fsS -H 'X-Kavach-Principal: viewer-1' "http://localhost:${HTTP_PORT}/health" >/dev/null 2>&1; then
  echo "ERROR: API did not start. Logs:"
  tmux -f /exec-daemon/tmux.portal.conf capture-pane -t "${SESSION}:0.0" -p | tail -20
  exit 1
fi

cat <<EOF

==============================================
Kavach pilot stack is running
==============================================

  Console (production build):  http://localhost:${HTTP_PORT}/
  API health:                  http://localhost:${HTTP_PORT}/health
  Overview:                    http://localhost:${HTTP_PORT}/overview

  Settings → set principal: admin-1  (for admin pages)

  Optional dev server (hot reload):
    cd console && npm run dev
    → http://localhost:5173

  Stop API:
    tmux -f /exec-daemon/tmux.portal.conf kill-session -t ${SESSION}

  Full system review:
    export KAVACH_DATABASE_URL='${DB_URL}'
    export PILOT_API_URL=http://localhost:${HTTP_PORT}
    ./scripts/system-review.sh

==============================================
CURSOR CLOUD AGENT USERS
==============================================
If you are in a Cloud Agent, localhost on YOUR laptop
does NOT reach this VM automatically.

  1. Open the Cursor **Ports** panel (or forwarded ports)
  2. Forward port ${HTTP_PORT}
  3. Click the forwarded URL (not bare localhost)

==============================================

EOF
