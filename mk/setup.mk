############################################################################
## Development environment setup
############################################################################


#***********************************
### Delete environment, containers
#***********************************
# NOTE: Useful if you need to rebuild the osidb-service image.
# NOTE: podman-compose 0.1.7 doesn't support argument '-v' for action 'down', hence deleting volume separately.
.PHONY: clean
clean:
	@echo -n "osidb: 'make clean' will force stop running osidb containers, REMOVE OSIDB_PG-DATA VOLUME, delete venv, remove .tox cache, pycache, pg keys, etc ... Are you really sure? [y/N] " && read ans && [ $${ans:-N} = y ]
	$(podman) compose -f docker-compose.yml -f docker-compose.test.yml down
	$(podman) volume rm osidb_pg-data || true
	$(podman) image rm localhost/osidb-service --force || true
	rm -rf .tox
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf bzimportcov
	rm -rf osidbcov
	rm -rf mypyreport
	rm -rf src/prodsec
	rm -rf .venv
	rm -f etc/pg/local-server.*


#***********************************
### Install githooks
#***********************************
.PHONY : githooks
githooks: check-venv-active
	@echo -n "This will install githooks that will prevent you from committing unless the commits meet the required criteria. Are you sure? [y/N]" && read ans && [ $${ans:-N} = y ]
	@echo "> installing git hooks"
	$(pre-commit) install -t pre-commit


#***********************************
### Build local dev env: images, venv, do checks
#***********************************
.PHONY: dev-env
dev-env:
	@echo -n "This will check installed RPMs, create certificate files within the current directory, build local podman images, and create a python venv within the current directory. Continue? [y/N]" && read ans && [ $${ans:-N} = y ]
	$(MAKE) dev-rpm-install
	$(MAKE) check-reg
	$(MAKE) generate_local_pg_tls_cert
	$(MAKE) build
	$(MAKE) venv
	$(MAKE) check-venv

#***********************************
### Compile deps from pyproject.toml to uv.lock
#***********************************
.PHONY : compile-deps
compile-deps: check-venv-active
	@echo ">compiling python dependencies"
	$(uv) lock && \
	[ ! -f local-requirements.in ] || \
	($(uv) export -o cons-requirements.txt && \
	$(uv) pip compile --generate-hashes 'local-requirements.in' -o 'local-requirements.txt'; \
	rm cons-requirements.txt)
	

#***********************************
### Sync local venv to match uv.lock
#***********************************
.PHONY : sync-deps
sync-deps: check-venv-active
	@echo ">synchronizing python dependencies in local venv"
	$(uv) sync --locked && \
	[ ! -f local-requirements.txt ] || $(uv) pip install -r 'local-requirements.txt' --no-deps


#***********************************
### Upgrade pinned package selectively. Read DEVELOP.md for details
#***********************************
.PHONY : upgrade-dep
upgrade-dep: check-venv-active
	@echo ">upgrading specified packages. Local package? [y/N] " && read ans && [ $${ans:-N} = y ] && \
	$(uv) pip compile --generate-hashes -P $(package) 'local-requirements.in' -o 'local-requirements.txt' || \
	$(uv) lock -P $(package) 
	

#***********************************
### Update installed python packages based on uv.lock both in local venv and in all containers
#***********************************
.PHONY : apply-uv-sync
apply-requirements-txt: check-reg check-venv sync-deps compose-up
	@echo ">appyling uv sync on osidb-service"
	$(podman) exec -it osidb-service uv sync --frozen --no-dev
	@echo ">appyling uv sync on osidb_celery_1"
	$(podman) exec -it osidb_celery_1 uv sync --frozen  --no-dev
	@echo ">appyling uv sync on osidb_celery_2" # if you have more celery replicas, you're on your own
	$(podman) exec -it osidb_celery_2 uv sync --frozen --no-dev || true  # do not fail if only 1 host is configured
	@echo ">appyling uv sync on celery_beat"
	$(podman) exec -it celery_beat uv sync --frozen --no-dev
	@echo ">appyling uv sync on flower"
	$(podman) exec -it flower uv sync --frozen --no-dev
	@echo ">appyling uv sync on testrunner"
	$(podman) exec -it testrunner uv sync --frozen --only-dev
	make stop-local
	@echo "FYI, containers stopped"


#***********************************
### Install necessary development packages
#***********************************
DEVRPMS = make podman podman-compose libpq-devel python3-devel gcc openldap-devel krb5-devel openldap-clients python3.9 black openssl libffi-devel libxslt-devel
.PHONY: dev-rpm-install
dev-rpm-install:
	@echo ">Checking whether necessary development RPMs are installed."
	@[ `rpm -qa --qf='%{NAME}\n' $(DEVRPMS) | wc -w ` == `echo $(DEVRPMS) | wc -w` ] || ( echo ">Some of the required packages are not installed. Installing." ; echo ">"dnf install $(DEVRPMS) ; sudo dnf install $(DEVRPMS) ; )


#***********************************
### Build local dockerfiles and delete existing containers (so that the built images are used on next start)
#***********************************
# Note that podman-compose down has no "-v" argument, so it doesn't delete volumes
# Note that podman-compose down is very important, because we need to delete existing containers so that they can be recreated from the updated images. If containers are not deleted, containers would still reflect the outdated images.
.PHONY: build
build:
	@echo ">building docker images and deleting existing containers"
	$(podman) compose -f docker-compose.yml -f docker-compose.test.yml down
	$(podman) compose -f docker-compose.yml build
	$(podman) compose -f docker-compose.yml pull
	$(podman) compose -f docker-compose.test.yml build
	$(podman) compose -f docker-compose.test.yml pull


#***********************************
### Virtual environment for local dev
#***********************************
.PHONY: venv
venv:
	@echo ">Creating venv for local development environment"
	python3.9 -m venv .venv
	source .venv/bin/activate && pip install uv==0.8.3 && $(uv) sync && \
	[ ! -f local-requirements.txt ] || $(uv) pip install -r 'local-requirements.txt' --no-deps 


#***********************************
### Generate certificates for local postgresql
#***********************************
# NOTE external changes to the key file perms cause a hard-to-debug failure, therefore resetting permissions always even if it is not osidb's fault.
.PHONY : generate_local_pg_tls_cert
generate_local_pg_tls_cert:
	@echo ">checking and/or generating local postgresql cert"
	@[ "(" -f etc/pg/local-server.crt ")" -a "(" -f etc/pg/local-server.key ")" ] || ( echo ">generating self-signed cert for local postgresql" && $(openssl) req -new -x509 -days 365 -nodes -text -out etc/pg/local-server.crt -keyout etc/pg/local-server.key -subj "/C=/ST=/L=/O=/OU=/CN=" )
	$(podman) unshare chmod 0600 etc/pg/local-server.*
	$(podman) unshare chown 999:999 etc/pg/local-server.*
