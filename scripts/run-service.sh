#!/usr/bin/env bash

# Custom run script for starting osidb django service in osidb-stage and osidb-prod environments.

# collect static files
python3 manage.py collectstatic \
    --ignore '*.xml' \
    --ignore '*.bz2' \
    --ignore 'tmp*' \
    --noinput

# apply django db migrations
python3 manage.py migrate --noinput

# start gunicorn
pkill gunicorn || true
exec gunicorn config.wsgi --config gunicorn_config.py