############################################################################
## Worktree-isolated development
############################################################################

# Load worktree-specific environment if it exists
-include .env.worktree


#***********************************
### Generate worktree environment file with unique ports
#***********************************
.PHONY: worktree-generate-env
worktree-generate-env:
	@./scripts/generate-worktree-ports.sh


#***********************************
### Ensure .env.worktree exists (generate if absent)
#***********************************
.PHONY : worktree-ensure-env
worktree-ensure-env:
	@[ -f .env.worktree ] || $(MAKE) worktree-generate-env


#***********************************
### Build worktree-isolated docker images
#***********************************
.PHONY: worktree-build
worktree-build: worktree-ensure-env
	@echo ">building docker images for worktree: $(COMPOSE_PROJECT_NAME)"
	$(podman) compose --env-file=.env.worktree -f docker-compose.yml -f docker-compose.worktree.yml -f docker-compose.test.yml -f docker-compose.test.worktree.yml down
	$(podman) compose --env-file=.env.worktree -f docker-compose.yml -f docker-compose.worktree.yml build
	$(podman) compose --env-file=.env.worktree -f docker-compose.yml -f docker-compose.worktree.yml pull
	$(podman) compose --env-file=.env.worktree -f docker-compose.test.yml -f docker-compose.test.worktree.yml build
	$(podman) compose --env-file=.env.worktree -f docker-compose.test.yml -f docker-compose.test.worktree.yml pull


#***********************************
### Build worktree dev env: images, venv, do checks
#***********************************
.PHONY: worktree-dev-env
worktree-dev-env:
	@echo -n "This will check installed RPMs, create certificate files, build podman images, and create a python venv for this worktree. Continue? [y/N]" && read ans && [ $${ans:-N} = y ]
	$(MAKE) worktree-generate-env
	$(MAKE) dev-rpm-install
	$(MAKE) check-reg
	$(MAKE) generate_local_pg_tls_cert
	$(MAKE) worktree-build
	$(MAKE) venv
	$(MAKE) check-venv


#***********************************
### Start containers for worktree-isolated development
#***********************************
# Automatically derives COMPOSE_PROJECT_NAME from directory name to avoid collisions
.PHONY : worktree-start
worktree-start: check-venv generate_local_pg_tls_cert
	$(MAKE) worktree-generate-env
	$(MAKE) worktree-compose-up
	$(MAKE) worktree-restart-django-foreground

.PHONY : worktree-start-bg
worktree-start-bg: check-venv generate_local_pg_tls_cert
	$(MAKE) worktree-generate-env
	$(MAKE) worktree-compose-up
	$(MAKE) worktree-start-bg-info

.PHONY : worktree-start-bg-info
worktree-start-bg-info:
	@echo ">Django is running in the background in $(COMPOSE_PROJECT_NAME)-service"
	@echo ">Use 'make worktree-restart-django-foreground' to attach to it"
	@echo ">Use 'make worktree-stop' to stop containers"


#***********************************
### Stop worktree containers without deleting
#***********************************
.PHONY : worktree-stop
worktree-stop: worktree-ensure-env
	@echo ">stopping worktree env without deleting containers"
	$(podman) compose --env-file=.env.worktree \
		-f docker-compose.yml -f docker-compose.worktree.yml \
		-f docker-compose.test.yml -f docker-compose.test.worktree.yml \
		stop \
	|| $(podman) compose --env-file=.env.worktree \
		-f docker-compose.yml -f docker-compose.worktree.yml \
		-f docker-compose.test.yml -f docker-compose.test.worktree.yml \
		stop testrunner testldap flower redis celery_beat celery \
		celery-fifo-1 celery-fifo-2 locust osidb-service osidb-data


#***********************************
### Stop and delete worktree containers and volumes, but not images
#***********************************
.PHONY : worktree-compose-down
worktree-compose-down: worktree-ensure-env
	@echo ">$(podman) compose down - stopping and deleting worktree containers and volumes, but not deleting images"
	@echo -n "Are you really sure? [y/N] " && read ans && [ $${ans:-N} = y ]
	$(podman) compose --env-file=.env.worktree -f docker-compose.yml -f docker-compose.worktree.yml -f docker-compose.test.yml -f docker-compose.test.worktree.yml down -v


#***********************************
### podman-compose up for worktree isolation
#***********************************
.PHONY : worktree-compose-up
worktree-compose-up: worktree-ensure-env
	$(MAKE) worktree-compose-up-exec

.PHONY : worktree-compose-up-exec
worktree-compose-up-exec:
	@echo ">compose up for worktree: $(COMPOSE_PROJECT_NAME)"
	@echo ">Ports: OSIDB=$(OSIDB_PORT) POSTGRES=$(POSTGRES_PORT) REDIS=$(REDIS_PORT) FLOWER=$(FLOWER_PORT) LDAP=$(LDAP_PORT) LDAPS=$(LDAPS_PORT) LOCUST=$(LOCUST_PORT)"
	@$(podman) compose --env-file=.env.worktree -f docker-compose.yml -f docker-compose.worktree.yml -f docker-compose.test.yml -f docker-compose.test.worktree.yml up -d
	@attempts=0; max=60; \
	while ! $(podman) exec -it $(COMPOSE_PROJECT_NAME)-service bash -c '( { curl -f http://127.0.0.1:8000/osidb/healthy >/dev/null 2>&1 || exit 1 ; } )' ; do \
	  attempts=$$((attempts + 1)) ; \
	  if [ $$attempts -ge $$max ] ; then echo ">$(COMPOSE_PROJECT_NAME)-service failed to become healthy after $$((max * 2)) seconds" ; exit 1 ; fi ; \
	  echo ">waiting for $(COMPOSE_PROJECT_NAME)-service ($$attempts/$$max)" ; \
	  sleep 2 ; \
	done
	@sleep 2
	@echo ">setting up static files directory and collecting static files"
	@$(podman) exec -it $(COMPOSE_PROJECT_NAME)-service bash -c "mkdir -p /var/www/osidb/static && python3 manage.py collectstatic --noinput --settings=config.settings_local"
	@echo ">compose is up"


#***********************************
### Restart django and run it in foreground (worktree)
#***********************************
.PHONY : worktree-restart-django-foreground
worktree-restart-django-foreground: worktree-ensure-env
	@echo ">Note that after CTRL+C, django server will restart in the background, as long as $(COMPOSE_PROJECT_NAME)-service is running."
	@sleep 0.5
	$(podman) exec -it $(COMPOSE_PROJECT_NAME)-service pkill -f "python3 manage.py runserver"
	$(podman) exec -it $(COMPOSE_PROJECT_NAME)-service python3 manage.py runserver 0.0.0.0:8000


#***********************************
### Start development shell in worktree osidb-service container
#***********************************
.PHONY : worktree-shell-service
worktree-shell-service: worktree-ensure-env
	$(podman) exec -it $(COMPOSE_PROJECT_NAME)-service python3 manage.py shell --settings=config.settings_local


#***********************************
### Start bash shell in worktree osidb-service container
#***********************************
.PHONY : worktree-bash-service
worktree-bash-service: worktree-ensure-env
	$(podman) exec -it $(COMPOSE_PROJECT_NAME)-service bash


#***********************************
### Create and apply migrations in worktree
#***********************************
.PHONY : worktree-migrate
worktree-migrate:
	$(MAKE) worktree-generate-env
	$(MAKE) worktree-migrate-exec

.PHONY : worktree-migrate-exec
worktree-migrate-exec:
	@if ! $(podman) exec -it $(COMPOSE_PROJECT_NAME)-service bash -c '( { curl -f http://127.0.0.1:8000/osidb/healthy >/dev/null 2>&1 || exit 1 ; } )' ; then $(MAKE) worktree-compose-up ; fi
	@echo ">creating migrations in $(COMPOSE_PROJECT_NAME)-service"
	$(podman) exec -it $(COMPOSE_PROJECT_NAME)-service python3 manage.py makemigrations --settings config.settings_local
	@echo ">applying migrations in $(COMPOSE_PROJECT_NAME)-service"
	$(podman) exec -it $(COMPOSE_PROJECT_NAME)-service python3 manage.py migrate --settings config.settings_local
