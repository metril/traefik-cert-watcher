#!/bin/sh
set -e

PUID=${PUID:-1000}
PGID=${PGID:-1000}

addgroup -g "$PGID" -S app 2>/dev/null || true
adduser -u "$PUID" -G app -S -H -D app 2>/dev/null || true

chown app:app /certs

echo "entrypoint: uid=$(id -u app) gid=$(id -g app) target=PUID=$PUID/PGID=$PGID"
ls -ldn /certs

exec su-exec app traefik-cert-watcher
