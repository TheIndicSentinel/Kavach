#!/bin/sh
# Creates the least-privilege runtime role on first database init
# (ADR-005 §1). The owner role (POSTGRES_USER) runs migrations; the
# migrations grant kavach_runtime exactly what the application uses.
# If the role is created after migrations already ran, grant it with:
#   psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c 'SELECT kavach_grant_runtime();'
set -eu
: "${KAVACH_RUNTIME_DB_PASSWORD:?set KAVACH_RUNTIME_DB_PASSWORD}"
psql -v ON_ERROR_STOP=1 -v pw="$KAVACH_RUNTIME_DB_PASSWORD" \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
SELECT format('CREATE ROLE kavach_runtime LOGIN PASSWORD %L', :'pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime')\gexec
SQL
