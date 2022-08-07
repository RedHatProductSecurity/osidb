############################################################################
## Database backup and restore
############################################################################

#***********************************
### Backup postgresql
#***********************************
# Git status and known migrations are recorded so that it is easier to debug an unsuccessful DB restore later on, or to provide information about the OSIDB version that produced the database.
.PHONY : db-backup
db-backup:
	@[ ! -f osidb_data_backup_dump.db.gz ] || { echo "Backup NOT created! Please remove the file osidb_data_backup_dump.db.gz first, or back it up elsewhere. (Protecting your backup from being mistakenly overwritten.)" ; exit 1 ; }
	@echo "Three recommendations for database backup:"
	@echo "1. Create backups only from master branch."
	@echo "2. Create backups only after having all migrations correctly applied. Check with:"
	@echo "   make compose-up"
	@echo "   podman exec -it osidb-service python3 manage.py showmigrations"
	@echo "3. Make a note of the list of migrations included in the backup. Record with:"
	@echo "   make compose-up"
	@echo "   podman exec -it osidb-service python3 manage.py showmigrations > osidb_data_backup_dump_showmigrations.txt"
	@echo ""
	@echo -n "Otherwise, restoring the DB might become problematic later on. Do you want to back up the database? [y/N]" && read ans && [ $${ans:-N} = y ]
	@echo ">backing up DB to osidb_data_backup_dump.db.gz"
	@make stop-local
	@make start-local-psql
	@$(podman) exec -it osidb-data bash -c 'rm -f /var/lib/postgresql/data/osidb_data_backup_dump.db.gz && pg_dump -Fp osidb | gzip > /var/lib/postgresql/data/osidb_data_backup_dump.db.gz && echo "pg_dump created inside container"'
	@$(podman) cp osidb-data:/var/lib/postgresql/data/osidb_data_backup_dump.db.gz osidb_data_backup_dump.db.gz && echo "pg_dump backup copied from container"
	@$(podman) exec -it osidb-data bash -c 'rm -f /var/lib/postgresql/data/osidb_data_backup_dump.db.gz'
	@ls -la osidb/migrations > osidb_data_backup_dump_known_migrations.txt
	@git log -v --source --log-size --notes -n 1 > osidb_data_backup_dump_git_commit_status.txt
	@echo -e "\n---\n" >> osidb_data_backup_dump_git_commit_status.txt
	@git status >> osidb_data_backup_dump_git_commit_status.txt


#***********************************
### Restore postgresql
#***********************************
# NOTE about commenting out search_path setting that limits public lookups:
# * https://stackoverflow.com/questions/63586022/pg-dump-pg-restore-error-with-extension-cube
# * https://stackoverflow.com/questions/23599926/dump-and-restore-of-postgresql-database-with-hstore-comparison-in-view-fails
# * https://www.postgresql.org/message-id/flat/ffefc172-a487-aa87-a0e7-472bf29735c8@gmail.com
# * https://www.postgresql.org/message-id/13985.1552685279@sss.pgh.pa.us
# * https://stackoverflow.com/questions/50157849/dump-fails-to-re-create-index-over-array-of-hstore-column
# * It might be better to use a more nuanced approach, but it's too complicated for me at the moment: https://stackoverflow.com/questions/19146433/best-way-to-install-hstore-on-multiple-schemas-in-a-postgres-database
#
# NOTE about creating a new database:
# * https://www.postgresql.org/docs/13/backup-dump.html#BACKUP-DUMP-RESTORE talks about template0
#
# NOTE: always using gzip so as not to fill too much disk space
.PHONY : db-restore
db-restore: stop-local start-local-psql
	@echo ">restoring osidb_data_backup_dump.db.gz"
	@[ -f osidb_data_backup_dump.db.gz ] || { echo "Error! osidb_data_backup_dump.db.gz doesn't exist." ; exit 1 ; }
	@$(podman) cp osidb_data_backup_dump.db.gz osidb-data:/var/lib/postgresql/data/osidb_data_backup_dump.db.gz.x && echo "backup dump copied to container"
	@$(podman) exec -it osidb-data bash -c 'zcat /var/lib/postgresql/data/osidb_data_backup_dump.db.gz.x | sed "s/^SELECT pg_catalog.set_config..search_path/-- &/" | gzip > /var/lib/postgresql/data/osidb_data_backup_dump.db.gz && echo "search path fixed"'
	@$(podman) exec -it osidb-data dropdb --if-exists -h osidb-data -p 5432 -U osidb_app_user osidb && echo "existing database osidb dropped"
	@sleep 1
	@$(podman) exec -it osidb-data createdb  -T template0  -U osidb_app_user osidb && echo "created new database"
	@sleep 1
	@$(podman) exec -it osidb-data bash -c 'zcat /var/lib/postgresql/data/osidb_data_backup_dump.db.gz | psql osidb && echo "dump restored inside container"'
	@$(podman) exec -it osidb-data bash -c 'rm -f /var/lib/postgresql/data/osidb_data_backup_dump.db.gz*'
	@sleep 3
	@$(podman) stop osidb-data


#***********************************
### Drop postgresql
#***********************************
.PHONY : db-drop
db-drop:
	@echo -n "This will delete data in the database. It will delete the osidb_pg-data volume. As a side effect, it will also remove all osidb containers. Are you sure? [y/N]" && read ans && [ $${ans:-N} = y ]
	$(podmancompose) -f docker-compose.yml -f docker-compose.test.yml down
	podman volume rm osidb_pg-data -f


# NOTE: The following approach doesn't work. If a new db is created, celery crashes with [1]. If a new db is not created, osidb-service crashes with [2]. It seems there's some inherent magic that auto-setups the db if the container and the volume are freshly created at the same time, and that magic is not run when the db is simply dropped or dropped & recreated.
# .PHONY : db-drop
# db-drop: stop-local start-local-psql
# 	@echo -n "This will delete data in the database. Are you sure? [y/N]" && read ans && [ $${ans:-N} = y ]
# 	@$(podman) exec -it osidb-data dropdb --if-exists -h osidb-data -p 5432 -U osidb_app_user osidb && echo "existing database osidb dropped"
# 	@sleep 1
# 	@$(podman) exec -it osidb-data createdb  -T template0  -U osidb_app_user osidb && echo "created new database"
# 	@sleep 3
# 	@$(podman) stop osidb-data

# [1]
# 2022-04-21 16:46:20,084 [ERROR] celery.app.trace: Task collectors.bzimport.tasks.process_flaw[32b4df6e-ce20-428f-962b-7627f5f12065] raised unexpected: DoesNotExist('JobItem matching query does not exist.')
# Traceback (most recent call last):
#   File "/usr/local/lib/python3.9/site-packages/celery/app/trace.py", line 451, in trace_task
#     R = retval = fun(*args, **kwargs)
#   File "/usr/local/lib/python3.9/site-packages/celery/app/trace.py", line 734, in __protected_call__
#     return self.run(*args, **kwargs)
#   File "/opt/app-root/src/collectors/bzimport/tasks.py", line 481, in process_flaw
#     jobitem = JobItem.objects.get(id=jobitem_id)
#   File "/usr/local/lib/python3.9/site-packages/django/db/models/manager.py", line 85, in manager_method
#     return getattr(self.get_queryset(), name)(*args, **kwargs)
#   File "/usr/local/lib/python3.9/site-packages/django/db/models/query.py", line 435, in get
#     raise self.model.DoesNotExist(
# collectors.bzimport.models.JobItem.DoesNotExist: JobItem matching query does not exist.

# [2]
# System check identified 1 issue (0 silenced).
# Exception in thread django-main-thread:
# Traceback (most recent call last):
#   File "/usr/local/lib/python3.9/site-packages/django/db/backends/base/base.py", line 219, in ensure_connection
#     self.connect()
#   File "/usr/local/lib/python3.9/site-packages/django/utils/asyncio.py", line 33, in inner
#     return func(*args, **kwargs)
#   File "/usr/local/lib/python3.9/site-packages/django/db/backends/base/base.py", line 200, in connect
#     self.connection = self.get_new_connection(conn_params)
#   File "/usr/local/lib/python3.9/site-packages/django/utils/asyncio.py", line 33, in inner
#     return func(*args, **kwargs)
#   File "/usr/local/lib/python3.9/site-packages/django/db/backends/postgresql/base.py", line 187, in get_new_connection
#     connection = Database.connect(**conn_params)
#   File "/usr/local/lib64/python3.9/site-packages/psycopg2/__init__.py", line 122, in connect
#     conn = _connect(dsn, connection_factory=connection_factory, **kwasync)
# psycopg2.OperationalError: FATAL:  database "osidb" does not exist
# 
# 
# The above exception was the direct cause of the following exception:
# 
# Traceback (most recent call last):
#   File "/usr/lib64/python3.9/threading.py", line 973, in _bootstrap_inner
#     self.run()
#   File "/usr/lib64/python3.9/threading.py", line 910, in run
#     self._target(*self._args, **self._kwargs)
#   File "/usr/local/lib/python3.9/site-packages/django/utils/autoreload.py", line 64, in wrapper
#     fn(*args, **kwargs)
#   File "/usr/local/lib/python3.9/site-packages/django/core/management/commands/runserver.py", line 121, in inner_run
#     self.check_migrations()
#   File "/usr/local/lib/python3.9/site-packages/django/core/management/base.py", line 486, in check_migrations
#     executor = MigrationExecutor(connections[DEFAULT_DB_ALIAS])
#   File "/usr/local/lib/python3.9/site-packages/django/db/migrations/executor.py", line 18, in __init__
#     self.loader = MigrationLoader(self.connection)
#   File "/usr/local/lib/python3.9/site-packages/django/db/migrations/loader.py", line 53, in __init__
#     self.build_graph()
#   File "/usr/local/lib/python3.9/site-packages/django/db/migrations/loader.py", line 220, in build_graph
#     self.applied_migrations = recorder.applied_migrations()
#   File "/usr/local/lib/python3.9/site-packages/django/db/migrations/recorder.py", line 77, in applied_migrations
#     if self.has_table():
#   File "/usr/local/lib/python3.9/site-packages/django/db/migrations/recorder.py", line 55, in has_table
#     with self.connection.cursor() as cursor:
#   File "/usr/local/lib/python3.9/site-packages/django/utils/asyncio.py", line 33, in inner
#     return func(*args, **kwargs)
#   File "/usr/local/lib/python3.9/site-packages/django/db/backends/base/base.py", line 259, in cursor
#     return self._cursor()
#   File "/usr/local/lib/python3.9/site-packages/django/db/backends/base/base.py", line 235, in _cursor
#     self.ensure_connection()
#   File "/usr/local/lib/python3.9/site-packages/django/utils/asyncio.py", line 33, in inner
#     return func(*args, **kwargs)
#   File "/usr/local/lib/python3.9/site-packages/django/db/backends/base/base.py", line 219, in ensure_connection
#     self.connect()
#   File "/usr/local/lib/python3.9/site-packages/django/db/utils.py", line 90, in __exit__
#     raise dj_exc_value.with_traceback(traceback) from exc_value
#   File "/usr/local/lib/python3.9/site-packages/django/db/backends/base/base.py", line 219, in ensure_connection
#     self.connect()
#   File "/usr/local/lib/python3.9/site-packages/django/utils/asyncio.py", line 33, in inner
#     return func(*args, **kwargs)
#   File "/usr/local/lib/python3.9/site-packages/django/db/backends/base/base.py", line 200, in connect
#     self.connection = self.get_new_connection(conn_params)
#   File "/usr/local/lib/python3.9/site-packages/django/utils/asyncio.py", line 33, in inner
#     return func(*args, **kwargs)
#   File "/usr/local/lib/python3.9/site-packages/django/db/backends/postgresql/base.py", line 187, in get_new_connection
#     connection = Database.connect(**conn_params)
#   File "/usr/local/lib64/python3.9/site-packages/psycopg2/__init__.py", line 122, in connect
#     conn = _connect(dsn, connection_factory=connection_factory, **kwasync)
# django.db.utils.OperationalError: FATAL:  database "osidb" does not exist
