#!/usr/bin/env bash
set -e
# This is a simple script that restores a sql backup into local dev environment
#
# ex. > scripts/restore_pg.sh osidb-dump.sql

echo "Restore data from pg_dump sql."
echo

FILENAME=${1:-osidb-dump.sql}

podman cp "${FILENAME}" osidb-data:.
podman exec osidb-data psql -f "$(basename ${FILENAME})" -d osidb
podman exec osidb-data rm "$(basename ${FILENAME})"