#!/usr/bin/env bash

# Note that you can see the output with "podman logs <container-name>"

# For details why dependency checking is not done in docker-compose.yml, see comments in docker-compose.yml.

function poormans_pg_isready() {
    timeout -k 1 -s 9 5 bash -c 'echo -n > /dev/tcp/osidb-data/5432' >/dev/null 2>&1 
}

echo "Waiting for osidb-data:5432 to become available"
while ! ( poormans_pg_isready ) ; do echo -n "." ; sleep 2 ; done
echo

# Postgresql makes the port available after the db is available, but wait some more to be sure. This can be removed if the real pg_isready is used.
sleep 2



python3 manage.py migrate --settings config.settings_local

# Leave this running even if the server is killed later.
while true; do
    ( python3 manage.py runserver 0.0.0.0:8000 || true )
    sleep 5
done


