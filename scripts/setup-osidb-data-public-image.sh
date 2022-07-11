#!/usr/bin/env bash
# set -m

# cp /pg/postgresql.conf /bitnami/postgresql/conf

# /opt/bitnami/scripts/postgresql/run.sh &
# echo "Postgres service started"
# until pg_isready
# do
#   echo "Waiting for postgres service to be ready..."
#   sleep 2;
# done

# echo "Postgres service ready"
# cp /pg/postgresql.conf /bitnami/postgresql/conf
# # cp /pg/postgresql.conf /bitnami/postgresql/data/post
# echo "Postgres configuration files successfully installed"
# pg_ctl reload -D /bitnami/postgresql
# echo "Postgres service reloaded"
# until pg_isready
# do
#   echo "Waiting for postgres service to be ready..."
#   sleep 2;
# done

# echo "Postgres service ready"
# psql -f /pg/local-dev-app-user.sql -f /pg/local-dev-manage-user.sql
# echo "Postgres users created"

# fg

cp /pg/local-dev-app-user.sql /pg/local-dev-manage-user.sql /docker-entrypoint-initdb.d
cp /pg/postgresql.conf /bitnami/postgresql/conf
