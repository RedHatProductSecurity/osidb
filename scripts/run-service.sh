#!/usr/bin/env bash

# Custom run script for starting osidb django service in osidb-stage and osidb-prod environments.

# collect static files
python3 manage.py collectstatic \
    --ignore '*.xml' \
    --ignore '*.bz2' \
    --ignore 'tmp*' \
    --noinput

# Defaults to stdout for local development
ACCESS_LOG_FILE="-"

if [ "$DJANGO_SETTINGS_MODULE" = "config.settings_stage" ]; then
    ACCESS_LOG_FILE="/var/log/stage-access.log"
elif [ "$DJANGO_SETTINGS_MODULE" = "config.settings_prod" ]; then
    ACCESS_LOG_FILE="/var/log/prod-access.log"
fi

# start gunicorn
pkill gunicorn || true
exec gunicorn config.wsgi --config gunicorn_config.py --access-logfile $ACCESS_LOG_FILE