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
	$(podmancompose) -f docker-compose.yml -f docker-compose.test.yml down
	$(podman) volume rm osidb_pg-data || true
	$(podman) image rm localhost/osidb-service --force || true
	rm -rf .tox
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf bzimportcov
	rm -rf osidbcov
	rm -rf mypyreport
	rm -rf src/prodsec
	rm -rf venv
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
	make dev-rpm-install
	make check-reg
	make generate_local_pg_tls_cert
	make build
	make venv
	make check-venv
	source venv/bin/activate && make sync-deps


#***********************************
### Compile deps from requirements*.in into requirements*.txt
#***********************************
.PHONY : compile-deps
compile-deps: check-venv-active
	@echo ">compiling python dependencies"
	$(pc) --generate-hashes --allow-unsafe --no-emit-index-url requirements.in
	$(pc) --generate-hashes --allow-unsafe --no-emit-index-url devel-requirements.in
	[ -f local-requirements.in ] && $(pc) --generate-hashes --allow-unsafe --no-emit-index-url local-requirements.in || true


#***********************************
### Sync local venv to match requirements*.txt
#***********************************
.PHONY : sync-deps
sync-deps: check-venv-active
	@echo ">synchronizing python dependencies in local venv"
	$(ps) requirements.txt devel-requirements.txt $$([ -f local-requirements.txt ] && echo 'local-requirements.txt')


#***********************************
### Upgrade pinned package selectively. Read DEVELOP.md for details. Example: make upgrade-dep package=requests==2.0.0 reqfile=requirements.in
#***********************************
.PHONY : upgrade-dep
upgrade-dep: check-venv-active
	@echo ">upgrading specified packages"
	$(pc) --allow-unsafe --generate-hashes --no-emit-index-url -P $(package) $(reqfile)

#***********************************
### Update installed python packages based on requirements.txt both in local venv and in all containers
#***********************************
.PHONY : apply-requirements-txt
apply-requirements-txt: check-reg check-venv sync-deps compose-up
	@echo ">appyling requirements.txt on osidb-service"
	$(podman) exec -it osidb-service pip3 install -r /opt/app-root/src/requirements.txt
	@echo ">appyling requirements.txt on osidb_celery_1"
	$(podman) exec -it osidb_celery_1 pip3 install -r /opt/app-root/src/requirements.txt
	@echo ">appyling requirements.txt on osidb_celery_2" # if you have more celery replicas, you're on your own
	$(podman) exec -it osidb_celery_2 pip3 install -r /opt/app-root/src/requirements.txt || true  # do not fail if only 1 host is configured
	@echo ">appyling requirements.txt on celery_beat"
	$(podman) exec -it celery_beat pip3 install -r /opt/app-root/src/requirements.txt
	@echo ">appyling requirements.txt on flower"
	$(podman) exec -it flower pip3 install -r /opt/app-root/src/requirements.txt
	@echo ">appyling requirements.txt on testrunner"
	$(podman) exec -it testrunner pip install -r /opt/app-root/src/devel-requirements.txt
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
	$(podmancompose) -f docker-compose.yml -f docker-compose.test.yml down
	$(podmancompose) -f docker-compose.yml build
	$(podmancompose) -f docker-compose.yml pull
	$(podmancompose) -f docker-compose.test.yml build
	$(podmancompose) -f docker-compose.test.yml pull


#***********************************
### Virtual environment for local dev
#***********************************
.PHONY: venv
venv:
	@echo ">Creating venv for local development environment"
	python3.9 -m venv venv
	# --no-deps is a workaround to https://github.com/pypa/pip/issues/9644, see tox.ini for more info
	source venv/bin/activate && pip install wheel && pip install -r requirements.txt -r devel-requirements.txt $$([ -f local-requirements.txt ] && echo '-r local-requirements.txt') --no-deps


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
