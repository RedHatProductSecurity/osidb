############################################################################
## Local development
############################################################################


#***********************************
### Start containers for local development
#***********************************
.PHONY : start-local
start-local: check-venv generate_local_pg_tls_cert compose-up restart_django_foreground

.PHONY : start-local-bg
start-local-bg: check-venv generate_local_pg_tls_cert compose-up
	@echo ">Django is running in the background in osidb-service"
	@echo ">Use 'make restart_django_foreground' to attach to it"
	@echo ">Use 'make stop-local' to stop containers"

.PHONY : start-local-gunicorn
start-local-gunicorn: check-venv generate_local_pg_tls_cert compose-up start_gunicorn_fg

#***********************************
### Start only the postgresql container, for those local development usecases where anything else is not needed
#***********************************
# FYI, relevant useful targets: shell-local, command-local
.PHONY : start-local-psql
start-local-psql: check-reg check-venv generate_local_pg_tls_cert
	@echo ">starting osidb-data"
	@$(podman) compose -f docker-compose.yml start osidb-data
	@while ! $(compose) exec osidb-data bash -c "( pg_isready >/dev/null 2>&1 )" 2>/dev/null ; do echo ">waiting for osidb-data" ; sleep 2 ; done


#***********************************
### Stop containers without deleting
#***********************************
# NOTE: podman-compose 0.1.7 requires arguments for "stop" operation
.PHONY : stop-local
stop-local:
	@echo ">stopping local env without deleting containers"
	$(compose) stop || $(compose) stop testrunner testldap flower redis celery_beat celery osidb-service osidb-data



#***********************************
### Create migration files based on model changes
#***********************************
# Running inside osidb-service and not locally, because this is the most maintainable form of having access to psql in osidb-data.
.PHONY : migrations-create
migrations-create:
	@if ! $(compose) exec osidb-service bash -c '( { curl -f http://127.0.0.1:8000/osidb/healthy >/dev/null 2>&1 || exit 1 ; } )' 2>/dev/null ; then make compose-up ; fi
	@echo ">creating migrations in osidb-service"
	$(compose) exec osidb-service python3 manage.py makemigrations --settings config.settings_local


#***********************************
### Apply migration files on the DB
#***********************************
# Running inside osidb-service and not locally, because this is the most maintainable form of having access to psql in osidb-data.
.PHONY : migrations-apply
migrations-apply:
	@if ! $(compose) exec osidb-service bash -c '( { curl -f http://127.0.0.1:8000/osidb/healthy >/dev/null 2>&1 || exit 1 ; } )' 2>/dev/null ; then make compose-up ; fi
	@echo ">appyling migrations in osidb-service"
	$(compose) exec osidb-service python3 manage.py migrate --settings config.settings_local


#***********************************
### Create migration files based on model changes and apply them on the DB
#***********************************
# Running inside osidb-service and not locally, because this is the most maintainable form of having access to psql in osidb-data.
.PHONY : migrate
migrate:
	make migrations-create
	make migrations-apply


#***********************************
### Print changelog
#***********************************
.PHONY : changelog
changelog:
	git log --oneline --decorate --color


#***********************************
### Restart django and run it in foreground
#***********************************
# Useful for debugging
.PHONY : restart_django_foreground
restart_django_foreground:
	@echo ">Note that after CTRL+C, django server will restart in the background, as long as osidb-service is running."
	@sleep 0.5
	$(compose) exec osidb-service pkill -f "python3 manage.py runserver"
	$(compose) exec osidb-service python3 manage.py runserver 0.0.0.0:8000

.PHONY : start_gunicorn_fg
start_gunicorn_fg:
	@echo ">Note that after CTRL+C, django server will restart in the background, as long as osidb-service is running."
	@sleep 0.5
	$(compose) exec osidb-service pkill -f "python3 manage.py runserver"
	$(compose) exec osidb-service gunicorn config.wsgi --config gunicorn_config.py


#***********************************
### Kill django server so that it restarts in the background
#***********************************
.PHONY : kill_django
kill_django:
	@echo ">Note that the django server restarts automatically, as long as osidb-service is running."
	@sleep 0.5
	$(compose) exec osidb-service pkill -f "python3 manage.py runserver"


#***********************************
### Stop and delete containers and volumes, but not images
#***********************************
.PHONY : compose-down
compose-down:
	@echo ">$(podman) compose down - stopping and deleting containers and volumes, but not deleting images"
	@echo -n "Are you really sure? [y/N] " && read ans && [ $${ans:-N} = y ]
	$(compose) down -v


#***********************************
### Start development shell in osidb-service container
#***********************************
.PHONY : shell-service
shell-service:
	$(compose) exec osidb-service python3 manage.py shell --settings=config.settings_local


#***********************************
### Start bash shell in osidb-service container
#***********************************
.PHONY : bash-service
bash-service:
	$(compose) exec osidb-service bash


#***********************************
### Start development shell locally (not in container), with correct OSIDB_DB_PORT
#***********************************
.PHONY : shell-local
shell-local: check-venv-active
	OSIDB_DB_PORT=$$( $(compose) port osidb-data 5432 | awk -F':' '{ print $$2 }' ) && export OSIDB_DB_PORT && source .env && export OSIDB_DB_PASSWORD && python manage.py shell --settings=config.settings_shell


#***********************************
### Start command.py in a development shell locally, with correct OSIDB_DB_PORT
#***********************************
.PHONY : command-local
command-local: check-venv-active
	@[ -f command.py ] || { echo ">You must create command.py first." ; exit 1 ; }
	OSIDB_DB_PORT=$$( $(compose) port osidb-data 5432 | awk -F':' '{ print $$2 }' ) && export OSIDB_DB_PORT && source .env && export OSIDB_DB_PASSWORD && python manage.py shell --settings=config.settings_shell --command="$$( cat command.py )"


#***********************************
### Start bash shell locally, with activated venv and correct OSIDB_DB_PORT
#***********************************
.PHONY : bash-local
bash-local: check-venv-active
	OSIDB_DB_PORT=$$( $(compose) port osidb-data 5432 | awk -F':' '{ print $$2 }' ) && export OSIDB_DB_PORT && source .env && export OSIDB_DB_PASSWORD && bash


#***********************************
### Update generated API docs extracted from Django
#***********************************
.PHONY : update-schema
update-schema:
	@echo ">updating openapi.yml"
	./scripts/schema-check.sh


#***********************************
### Update .secrets.baseline using detect-secrets
#***********************************
.PHONY : update-secrets
update-secrets: check-venv-active
	@echo ">updating secret baseline"
	$(ds) scan --baseline .secrets.baseline
	$(ds) audit .secrets.baseline



#***********************************
### Stop any running OSIDB containers from other worktrees/projects
#***********************************
.PHONY : stop-other-osidb
stop-other-osidb:
	@running=$$($(podman) ps -q --filter "label=app=osidb" 2>/dev/null); \
	if [ -n "$$running" ]; then \
	  echo ">stopping other OSIDB containers"; \
	  $(podman) stop $$running; \
	fi

#***********************************
### podman-compose up (fetches images and starts containers)
#***********************************
# NOTE: Waits for osidb-service availability so that other targets can use this target without race conditions.
.PHONY : compose-up
compose-up: stop-other-osidb
	@echo ">compose up"
	@$(compose) up -d
	@while ! $(compose) exec osidb-service bash -c '( { curl -f http://127.0.0.1:8000/osidb/healthy >/dev/null 2>&1 || exit 1 ; } )' 2>/dev/null ; do echo ">waiting for osidb-service" ; sleep 2 ; done
	@sleep 2
	@echo ">compose is up"
