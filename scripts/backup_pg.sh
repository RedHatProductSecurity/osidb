#!/bin/bash

# example backup script for postgres ... we should gzip and encrypt contents
# > backup_pg hourly > gzip > <ENCRYPT FILE/> > out.enc

FILENAME=${1:-hourly}
PGPASSWORD=$OSIDB_DB_PASSWORD pg_dump -p $OSDIB_DB_PORT --schema public -U $OSIDB_DB_USER -d osidb > pg_dump_$(date -d "today" +"%Y%m%d%H%M").sql | true
