#!/usr/bin/env bash

# Custom run script for starting osidb django service in deployed environments.

# collect static files
python3 manage.py collectstatic \
    --ignore '*.xml' \
    --ignore '*.bz2' \
    --ignore 'tmp*' \
    --noinput

# Defaults to stdout for local development
ACCESS_LOG_FILE="-"

if [ -n "$OSIDB_ENV" ]; then
    ACCESS_LOG_FILE="/var/log/${OSIDB_ENV}-access.log"
fi

# start gunicorn
pkill gunicorn || true
exec gunicorn config.wsgi --config gunicorn_config.py --access-logfile $ACCESS_LOG_FILE