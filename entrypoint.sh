#!/bin/sh
set -e

PUID=${PUID:-1000}
PGID=${PGID:-1000}

addgroup -g "$PGID" -S app 2>/dev/null || true
adduser -u "$PUID" -G app -S -H -D app 2>/dev/null || true

chown app:app /certs

echo "level=INFO msg=\"entrypoint ready\" uid=$PUID gid=$PGID"

exec su-exec app traefik-cert-watcher
