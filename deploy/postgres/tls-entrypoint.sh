#!/bin/sh
# Starts the official Postgres image with TLS (Kavach requires
# sslmode=verify-full). The certificate and key are mounted read-only at
# /run/kavach-tls-src, owned by whoever created them; Postgres accepts a key
# only if it is owned by its own user with mode 0600. So copy both first,
# as root, then hand over to the image's entrypoint, which drops privileges.
set -eu
src=/run/kavach-tls-src
dst=/etc/postgresql-tls
mkdir -p "$dst"
cp "$src/server.crt" "$dst/server.crt"
cp "$src/server.key" "$dst/server.key"
chown postgres:postgres "$dst/server.crt" "$dst/server.key"
chmod 0644 "$dst/server.crt"
chmod 0600 "$dst/server.key"
exec docker-entrypoint.sh "$@"
