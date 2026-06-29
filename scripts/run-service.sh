#!/usr/bin/env bash
set -euo pipefail

# Custom run script for starting osidb django service in deployed environments.

# collect static files
python3 manage.py collectstatic \
    --ignore '*.xml' \
    --ignore '*.bz2' \
    --ignore 'tmp*' \
    --noinput

ACCESS_LOG_FILE="/var/log/${OSIDB_ENV:-prod}-access.log"

# start gunicorn
pkill gunicorn || true
exec gunicorn config.wsgi --config gunicorn_config.py --access-logfile "$ACCESS_LOG_FILE"