#!/usr/bin/env bash
set -m

run-postgresql &
echo "Postgres service started"
until pg_isready
do
  echo "Waiting for postgres service to be ready..."
  sleep 2;
done

echo "Postgres service ready"
cp /pg/postgresql.conf /var/lib/pgsql/data/userdata/postgresql.conf
echo "Postgres configuration files successfully installed"
pg_ctl reload -D /var/lib/pgsql/data/userdata
echo "Postgres service reloaded"
until pg_isready
do
  echo "Waiting for postgres service to be ready..."
  sleep 2;
done

echo "Postgres service ready"
psql -f /pg/local-dev-app-user.sql -f /pg/local-dev-manage-user.sql
echo "Postgres users created"

fg
