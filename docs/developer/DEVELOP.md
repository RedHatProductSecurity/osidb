# DEVELOP

Instructions on how to setup local dev environment and contribute to osidb.

## Development environment setup

### Minimal requirements

The following dependencies are required for development and deployment:
* make
* podman (docker)
* podman-compose (docker-compose)

### Environment variables

Before starting osidb, you need to define environment variables.

Create a file named `.env` in repository root directory:

```
# Bugzilla REST API key
BZIMPORT_BZ_API_KEY=####################

# Bugzilla URL (optional, defaults to RedHat production Bugzilla)
# Never add the trailing slash to the URL as the python-bugzilla handles it wrong
BZIMPORT_BZ_URL="https://foo.bar"

# Jira REST API authentication token
JIRA_AUTH_TOKEN=####################

# Jira URL (optional, defaults to RedHat production Jira)
JIRA_URL="https://foo.bar"

# Task management Jira URL
JIRA_TASKMAN_URL="https://foo.bar"

# Project key used for task management
JIRA_TASKMAN_PROJECT_KEY="OSIM"

# If true, creating or editing a Flaw through REST API will require
# passing a Jira token and a task will be created / updated in your
# JIRA_TASKMAN_URL Jira instance for JIRA_TASKMAN_PROJECT_KEY project
JIRA_TASKMAN_AUTO_SYNC_FLAW=1

# Export the default local postgresql password
OSIDB_DB_PASSWORD=passw0rd

# Errata Tool URL
ET_URL="https://foo.bar"

# Product definitions git source
PRODUCT_DEF_URL="https://foo.bar"
PRODUCT_DEF_BRANCH="master"

# PS Constants git URL
PS_CONSTANTS_URL="https://foo.bar"

# Repository from which to pull pip packages (optional)
PIP_INDEX_URL="https://foo.bar"

# URL from which to pull Red Hat internal certificates (optional)
RH_CERT_URL="https://foo.bar"

# enable Bugzilla backwards sync to propagate writes to Bugzilla
# otherwise all the writes are performed only locally in OSIDB
BBSYNC_SYNC_TO_BZ=1
# enable Bugzilla backwards sync of the flaws
BBSYNC_SYNC_FLAWS_TO_BZ=1
# enable Bugzilla backwards sync of the trackers
BBSYNC_SYNC_TRACKERS_TO_BZ=1

# enable Jira tracker sync to propagate writes to Jira
# otherwise all the writes are performed only locally in OSIDB
TRACKERS_SYNC_TO_JIRA=1

# Run taskman tests behind a proxy (optional)
# This variable is only necessary if rewriting the taskman cassettes locally and using the Stage Red Hat JIRA instance, which requires a proxy to be accessed.
# Some tests apply the HTTPS_PROXY variable hardcoded in respective conftest files.
HTTPS_TASKMAN_PROXY="http://foo.bar"

# This variable is only necessary when using osidb locally and using the Stage Red Hat JIRA instance, which requires a proxy to be accessed. The jira library detects this env variable and uses it automatically.
HTTPS_PROXY="http://foo.bar"

# OSIDB CORS URLs
OSIDB_CORS_ALLOWED_ORIGINS='["http://localhost:8000", "http://127.0.0.1:8000", "http://0.0.0.0:8000"]'
# Custom headers allowed by OSIDB CORS policy
OSIDB_CORS_ALLOW_HEADERS='["bugzilla-api-key", "jira-api-key"]'

# To enable snippets creation in collectors (when date is not set, all snippets are created)
SNIPPET_CREATION=1
SNIPPET_CREATION_START="2024-01-01"

# Collector switches: set to 0 to turn each collector off, or 1 to turn it on (default)
FLAW_COLLECTOR_ENABLED=1
BZ_TRACKER_COLLECTOR_ENABLED=1
BZ_METADATA_COLLECTOR_ENABLED=1
ERRATA_COLLECTOR_ENABLED=1
JIRA_TASK_COLLECTOR_ENABLED=1
JIRA_TRACKER_COLLECTOR_ENABLED=1
JIRA_METADATA_COLLECTOR_ENABLED=1
NVD_COLLECTOR_ENABLED=1
OSV_COLLECTOR_ENABLED=1
```

The `.env` file is loaded automatically by podman-compose. It is also loaded as environment variables in a few Makefile targets (run `grep -rF '.env ' mk/` to see which ones).

If podman-compose older than 1.0 is used, `.env` values must not be quoted (e.g. `OSIDB_DB_PASSWORD="passw0rd"` makes the contents of the variable be `"passw0rd"` instead of `passw0rd`).

Note that your `.env` file contains secrets you should not share. Make sure that it stays in `.gitignore` and that you don't commit it to git.

**IMPORTANT:** Reference `.env` files for setting up OSIDB with Production or Stage instances are located in the `osidb-ops` repository in `env_files/` directory. Whenever a new environment variable is introduced in OSIDB it should be added to that reference files with relevant values as well.

### Image registries

Before starting osidb the first time, or when updating to newer images, you need to log in to registries.

Log in to **registry.redhat.io** using [customer portal](https://access.redhat.com) credentials
```
> podman login registry.redhat.io
Username: yourusername
Password: ************
```

Log in to **quay.io** using [Quay](https://quay.io) credentials
```
> podman login quay.io
Username: yourusername
Password: ************
```

Optional: Log in to **docker.io** for higher image pull limit
```
> podman login docker.io
Username: yourusername
Password: ************
```

To check that you are logged in, run and see whether "OK" is printed:

```bash
$ make check-reg && echo OK
```

### Set up development environment

To install required RPMs and set up a local dev environment:

```bash
$ make dev-env
```

This installs missing RPMs to the system, creates a python virtual environment, installs packages into the virtual environment, and pulls and builds podman images.

If you see the error `RuntimeError: Variable BZIMPORT_BZ_API_KEY must be set.`, please follow `DEVELOP.md` from the beginning.

If you see the error `ERROR: Failed building wheel for python-ldap` because it could not find `-lldap_r`, please refer to this [issue](https://github.com/python-ldap/python-ldap/issues/432).

### Set up githooks

It is strongly recommended to install githooks that check the code for secrets and other errors:

```bash
$ make githooks
```

To disable githooks, run

```bash
$ rm -f .git/hooks/pre-commit
```

### Debugging dev-env

If `make dev-env` doesn't work for some reason, the following details might help.

The following dependencies are required for development, if running tests in Tox (outside of the testrunner container):
* gcc
* krb5-devel
* libpq-devel
* openldap-devel
* python3.9
* python39-devel
* tox

The following dependencies are now required to build the cryptography Python library from source:
* cargo
* gcc
* libffi-devel
* openssl-devel
* python3-devel
* redhat-rpm-config

See [Installation - Cryptography](https://cryptography.io/en/latest/installation/#rust) for more details.

## Startup

### Start local dev env

Start the whole container compose (recommended):

```bash
$ make start-local
```

Optionally, also point browser to

    http://localhost:8000

### Run tests

To run all tests
```
> make testrunner.all-tests
```

or alternately using tox targets
````
> tox -e tests osidb/test_endpoints.py::TestEndpoints::test_list_flaws collectors/bzimport/tests/
````

Positional arguments after "tox -e environment_name" are passed through to Pytest.
You can specify tests by giving multiple folders, files, classes, or even individual test names.

To run selected tests via testrunner:
````
podman exec -it testrunner tox -e tests -- osidb/tests/test_endpoints.py::TestEndpoints::test_list_retrieve_multiple_flaws_by_cve_id
````

### Stop local dev env


To stop all the containers without deleting data:

```bash
$ make stop-local
```

To _delete_ the containers _and delete the database_ (remember to backup the DB if you care about the contents):

```bash
$ make compose-down
```

Note that deleting containers using `make compose-down` helps and doesn't help with the following:
* Doesn't help: Putting local git working tree code changes into the containers so that it runs there. (Containers bind-mount the local git working tree. A simple `make stop-local ; make start-local` or even just `make restart_django_foreground` or `make kill_django` is enough.)
* Doesn't help: Updating python packages. (Search this doc for `make apply-requirements-txt` instead.)
* Doesn't help: Cleaning the dev environment. (Containers bind-mount the local git working tree. Search this doc for `make clean` instead.)
* Doesn't help: Rebuilding badly-built images. (After updating `Dockerfile`, call `make build` explicitly.)
* Helps, but not the right tool: Dropping the database. (For a less heavy-handed approach, search this doc for `make db-drop`. However, if you are debugging other dev env issues, it's better to do `make compose-down` rather than `make db-drop`, because `db-drop` might make assumptions that might not be correct anymore by the time you do the debugging.)
* Might help: Fixing or debugging an unforeseen breakage, depending on the breakage. Also search this doc for `make build` and `make clean`.
* Helps: Cleaning existing osidb podman containers and volumes for whatever reason. (Easier and less heavy-handed than `podman rm -a` and similar actions.)

See `make help` for a short summary of these _make targets_.

## Usecase-oriented starting of local dev env

Other ways to start the **full environment**, for specific usecases:
* `make shell-service` (runs `manage.py shell` in `osidb-service` container)
* `make bash-service` (runs bash in `osidb-service` container)

## Non-container development

It's possible to perform local development outside of containers, in the venv that was created by `make dev-env`. However, for simplicity's sake, the database always runs in a container (`osidb-data` container).

* `make start-local-psql` (Starts only the `osidb-data` container.)
* `make shell-local` (Runs `manage.py shell` in local venv, with correctly set `OSIDB_DB_PORT`. Requires running `osidb-data` container.)
* `make bash-local` (Runs bash in local venv, with correctly set `OSIDB_DB_PORT`. Requires running `osidb-data` container.)
* `make command-local` (Runs `command.py` in `manage.py shell` in local venv, with correctly set `OSIDB_DB_PORT`. Requires running `osidb-data` container. You must create `command.py` manually. This is to allow repeated execution of the same set of expressions, as an alternative to running `make shell-local` and pasting those expressions manually every time.)

See `make help` for a short summary of these _make targets_.


## Updating dev env

### Updating python packages

If you have new `requirements*.txt` (e.g. after `git pull`) and want to apply them to the **local venv** only (this will install, uninstall, and upgrade/downgrade packages as needed to reflect `requirements*.txt` exactly):

```bash
$ make sync-deps
```

If you have new `requirements*.txt` and want to apply them to the local venv **and osidb containers** (so that you don't need to rebuild images and containers):

```bash
$ make apply-requirements-txt
```

For more information about changing `requirements*.txt` see the chapter "Using pip-tools" below.

### Updating images and containers

If you have new `Dockerfile` or `docker-compose.yml` (e.g. after `git pull`) and want to use it, you need to delete existing containers (which are now instantiated from outdated images) and rebuild images (so that containers are then instantiated from the updated images).
 the only strictly necessary step is to delete the existing containers, which then allows podman-compose to update the image and create a container from the image on the next `make start-local`. In practice, do any of the following two actions:

To rebuild images and containers, without deleting database volume:

```bash
$ make build
```

To restart osidb after `make build`, run e.g. `make start-local`.

To delete containers **and delete database volume**, and rebuild images:

```bash
$ make compose-down
$ make build
```

### Debugging issues when updating images and containers

If you don't mind losing the database and are experiencing issues, the fastest way to clean podman's osidb-related state and rebuild the images is:

```bash
$ make compose-down
$ make build
```

Careful reading of the output might help in spotting where the problem is.

Situations where combining `compose-down` and `build` is useful:

* Badly-built images that break the database state (without `build`, already-cached images are not rebuilt on next `make start-local`; without `compose-down`, the database volume is not recreated on the next `make start-local`).
* Debugging build problems that have secondary effects on the database (if an image doesn't work correctly, the DB might not get created correctly, which then makes debugging harder after the build problems are resolved, because osidb can still crash because of the corrupted database state).
* Debugging build problems when you don't care about database contents (same reasoning as above).


### Debugging ">waiting for osidb-service"

1. Before debugging, run `make start-local` again. This will (attempt to) create all the containers. If this is not done, error messages like `no such container` might have entirely different reasons than what is discussed below.

2. What does this return? `podman exec -it osidb-data pg_isready || echo error`

  - If `accepting connections`, the bug is not in the database container itself, but it still might be in how database tables or users are set up.
  - Look at `podman logs osidb-data` for more details about the database's state.

3. What does this return? `podman exec -it osidb-service bash -c "python3 manage.py migrate --settings config.settings_local"`

  - If `no container with name or ID "osidb-service" found: no such container`, there's a problem in building the osidb-service container. Most probably, other containers built from `Dockerfile` have the same problem. Run `make build` and carefully investigate the output.
  - If `Error: can only create exec sessions on running containers: container state improper`, there's something that causes the container to stop upon starting. Run `podman logs osidb-service`.
  - If `django.db.migrations.exceptions`, it's probably just a migration error/collision. You can resolve it outside of the osidb-service container, using `make stop-local; make start-local-psql; make bash-local` and then doing the appropriate Django-related software development steps.
  - If it seems to run correctly (e.g. `No migrations to apply.`), check `podman logs osidb-service` why the service doesn't start.
  - If `RuntimeError: populate() isn't reentrant`, it's most probably a broken database.
    - If you don't care about database contents, run `make db-drop` and try again.
    - If `make db-drop` doesn't fix it, run `make compose-down; make build`. It seems there's something that makes the database corrupted from the start.
    - If that doesn't fix it, do `make clean; make dev-env; make start-local`, but this probably won't fix it anyway.
    - For more involved debugging, use `podman logs osidb-service`, `podman logs osidg-data`, and inside `podman exec -it osidb-service bash` follow https://stackoverflow.com/a/55929118 to uncover a more specific Django error message.
  - If `django.db.utils.OperationalError: could not translate host name "osidb-data" to address: Name or service not known`, osidb-service can't find the hostname `osidb-data`, either because the container osidb-data is not running, or because there's a podman network issue that breaks container-to-container communication.
    - If `podman exec -it osidb-data pg_isready || echo error` returns an error, try to get the `osidb-data` container up and running first (see previous debugging steps).
    - If osidb-data is running correctly, it's possible this is an instance of the bug https://bugzilla.redhat.com/show_bug.cgi?id=1980157 (but actually who knows, I [jsvoboda] don't know enough about this :-( ).
    - Try `make stop-local; make start-local`,
    - or try creating a DB backup, stopping and deleting containers, recreating them, and restoring the DB: `make db-backup`, `make compose-down`, `make start-local`, `make db-restore`, `make start-local`

### Debugging ">waiting for osidb-data"

If the container osidb-data doesn't exist, you probably built/rebuilt/compose-down'd your environment and didn't call `make start-local`, so the images were not instantiated into containers.

Try starting the **full** development environment first:

```bash
$ make start-local

Then, you can stop the environment and retry the action you tried to do (such as `make start-local-psql` or `make db-restore`).

If that doesn't help, look at the logs of the container:

```bash
$ podman logs osidb-data
```


## Deleting development environment

To delete existing containers, database, built images, venv, and other development files:

```bash
$ make clean
```

To recreate the dev environment after that, continue with `make dev-env` as described in the chapter "Set up development environment".


## Database backup and restore

Because filling the DB might take a very long time, and because hunting for bugs might require cleaning the whole dev environment (or at least deleting all podman data), you can back up the local postgresql database to a file and restore it later:

To create `osidb_data_backup_dump.db.gz`:

```bash
$ make db-backup
```

Note that it runs successfully only if the file doesn't already exist (so as not to overwrite your existing backup). Managing multiple backups is left up to you.

To **delete the existing database** and restore from the file `osidb_data_backup_dump.db.gz`:

```bash
$ make db-restore
```

Then run migration:

```bash
$ make migrate
```

It is advisable to create database backups on the `master` branch. That way, you won't encounter migration conflicts after restore.


## Running tests, testrunner, tox

Tests are run using tox. Tox needs a specific Python interpreter version. The testrunner container contains the required Python interpreter version.

To run tests in the testrunner container:

```bash
$ make testrunner
$ make testrunner.all-tests
  ...or similar...
```

Some Makefile targets use tox, so they require that they are run in the testrunner container.

This wouldn't work when run locally on a modern Fedora:
```bash
$ make lint
>Checking that the testing environment has the requisite python version
Python 3.9 not installed! Read about testrunner and tox testing in DEVELOPMENT.md.
make: *** [Makefile:522: check-testenv] Error 1
$
```

Executing `make lint` inside the already-running testrunner container works:

```bash
$ podman exec -it testrunner make lint
```


## Makefile help

To display a quick summary of available makefile targets:

```bash
$ make help
```

## Docs

[REST API docs](http://localhost:8000/osidb/api/v1/schema/swagger-ui/)

[operations](OPERATIONS.md)


## Build, run and develop

### Flush database

This deletes database contents:

```bash
$ podman exec -it osidb-service python3 manage.py flush
```

Note that if the rest of the database gets broken, it's better to delete the whole volume and osidb-data container, which recreates the whole database with the correct ACLs, users, etc:

```bash
$ make db-drop
```

### Feature commit

1) Create feature branch

2) Check commit is clean by running
```bash
$ make testrunner
```

3) Run tests locally
```bash
$ make testrunner.all-tests
```

4) Push to branch

5) confirm branch passes CI - ***do not raise an MR if CI does not pass***

6) raise MR against master ensuring good title/description and bullet point
   all significant commits

### Using pip-tools
OSIDB has adopted `pip-tools` as its tool of choice for python dependency management,
in this section we'll go over the basics, the similarities and the differences between `pip-tools` and `pip`,
as well as how to use it effectively.

With `pip`, adding a dependency is as simple as adding it to the `requirements.txt`,
and optionally choosing which version(s) to use.

With `pip-tools`, the dependency (versioned or not) is added to either `requirements.in`,
`devel-requirements.in` or `local-requirements.in`, then we must execute the `pip-compile`
command in order to generate the corresponding `*-requirements.txt`.

```bash
$ source venv/bin/activate
$ pip-compile --generate-hashes --allow-unsafe	# this will compile requirements.in -> requirements.txt
$ pip-compile --generate-hashes --allow-unsafe devel-requirements.in	# be explicit for alternate requirements files
```

Instead of typing these commands manually you can simply do

```bash
$ make compile-deps
```

and all the necessary `requirements.txt` files will be compiled correctly.

So far the differences between `pip` and `pip-tools` are minimal, both use a `requirements.txt` file to express its dependencies, however the dependency tree generated by `pip-compile` is more thorough, it will include all implicit dependencies of the ones explicitly defined in the `*.in` files and will pin them to a very specific version.
Not only does this make it easier to reproduce prod/dev environments, but it can also be helpful for later security vulnerabilities scanning.

Note that if any dependencies are added to the `*.in` files, and then `pip-compile` is ran, the versions of the existing pinned dependencies will not change and only the new dependencies will be added to the `requirements.txt`

Updating dependencies with `pip` and `pip-tools` is largely the same, the command for doing so with `pip-tools` is the following

```bash
$ source venv/bin/activate
$ pip-compile --generate-hashes --allow-unsafe --upgrade-package django --upgrade-package requests==2.0.0
```

Instead of running this command manually, you can use the following make entrypoint:

```bash
$ make upgrade-dep package=requests==2.0.0 reqfile=requirements.in
```

To install the dependencies with `pip`, you simply pass the requirements file(s) to the `-r` option and all the requirements in the file will be installed, even if the file was generated by `pip-compile`!

With `pip-tools`, the command for installing dependencies is `pip-sync requirements.txt` (or any other file generated by `pip-compile`), however `pip-sync` will not only install the requirements, but it will also uninstall any packages or versions that do **not** match the one defined in the requirements file.

If installing multiple requirements files, they can simply be passed as additional positional arguments to `pip-sync`

```bash
$ source venv/bin/activate
$ pip-sync requirements.txt devel-requirements.txt local-requirements.txt
```

Instead of running this command manually, you can also use

```bash
$ make sync-deps
```

> :warning: Make sure to run `pip-sync` within a virtual environment, otherwise you risk having system-wide packages that are not in the `requirements.txt` be uninstalled

As for what each requirements file holds, here's a quick explanation for each:
- `requirements.txt`: dependencies necessary for running OSIDB
- `devel-requirements.txt`: dependencies necessary to develop OSIDB
- `local-requirements.txt`: dependencies specific to your workflow (e.g. `ipython` or any other custom shell/debugger)

`local-requirements.txt` is a special case, it is ignored in the `.gitignore` because it's specific to every developer. Without it, every time `pip-sync` is ran any packages specific to your workflow would be uninstalled and would have to be manually installed.

When synchronizing multiple requirements files, it is important that every subsequent requirements files "includes" the previous one, e.g.:

```
# requirements.in
django
```

```
# devel-requirements.in
-c requirements.txt
pytest
```

```
# local-requirements.in
-c devel-requirements.txt
ipython
```

This is so `pip-sync` can properly synchronize the versions of dependencies that appear in all the requirements files.

For more information on `pip-tools` and its usage, check the [official documentation](https://pip-tools.readthedocs.io/en/latest/).

### Run local development shell
Database running inside a container can be complemented with a locally running Django development shell.

Setup before running the shell for the first time:
```bash
$ make dev-env  # create python virtual environment and build database container
$ source venv/bin/activate  # source into the python virtual environment
```

`make dev-env` already created the virtual environment, but if you want to synchronize which packages are installed inside the venv manually, you can:

```bash
$ source venv/bin/activate  # source into the python virtual environment, if you haven't already
$ pip install -r devel-requirements.txt
$ pip-sync requirements.txt devel-requirements.txt # install python dependencies
```

> Note: you can also install dependencies with pip, but we recommend using pip-sync to make sure that you have only the absolutely necessary.

The same pip-sync synchronization can be performed using `make sync-deps`.

For a more clever shell with command history, auto-completions, etc.
you can install **ipython**. It is used by Django shell by default.
```bash
$ source venv/bin/activate  # source into the python virtual environment, if you haven't already
$ touch local-requirements.in
$ echo "-c devel-requirements.txt" >> local-requirements.in
$ echo "ipython" >> local-requirements.in
$ pip-compile local-requirements.in
$ pip-sync requirements.txt devel-requirements.txt local-requirements.txt
```

The last line can be also performed using `make sync-deps`.

Running the shell
```bash
make start-local  # run all the containers including the DB container
source venv/bin/activate  # source into the python virtual environment
export OSIDB_DB_PORT="$( podman port osidb-data | awk -F':' '/5432/ { print $2 }' )"  # get the local port of psql
export OSIDB_DB_PASSWORD=passw0rd  # this is the password used in docker-compose.yml
# ...set other necessary variables...
python3 manage.py shell --settings=config.settings_shell
```

alternately you may also run the shell directly on osidb_service container (once it has
been created)

```bash
podman exec -it osidb-service python3 manage.py shell --settings=config.settings_shell

```

The two snippets above have make target shortcuts `make shell-local` and `make shell-service`.

For any customization you can export the following env variables to change the DB settings:
 * OSIDB_DB_NAME (default "osidb")
 * OSIDB_DB_USER (default "osidb_admin_user")
 * OSIDB_DB_HOST (default "localhost")
 * OSIDB_DB_PORT (default "5432")

If you do that, it is recommended to also add these env variables to your virtual environment's activate script (eg. `venv/bin/activate`).

### Deprecate fields

When we decide to remove a field from a model, above removing the related functionality we need to carefully
consider the DB and API compatibility. For the DB we need to ensure that OSIDB is N-1 compatible meaning
that the app of version N can work with the DB of version N-1 and vice-versa. For the API we need to ensure
that the breaking changes are introduced only in major releases. The standard procedure is as follows.

* Optionally remove functionality using the field, if whatever code that
  depends on the field being deprecated can/should work with the in-memory-only
  version of the field, then it is not necessary to remove the usage until it
  is completely removed.
* Mark model field as deprecated with `osidb.helpers.deprecate_field` which is
  our vendored version of [deprecate-fields](https://github.com/3YOURMIND/django-deprecate-fields).
* If the field is the product of a rename or restructuring and the logic can be
  extracted from another field, you can provide a single-argument
  function/method in which the argument is the Model object instance for which
  the field was accessed.

```python
class MyModel(models.Model):

    def extrapolate_foo(self):
      return self.new_foo

    foo = deprecate_field(models.CharField(), return_instead=extrapolate_foo)
```

* Mark serializer field as deprecated with [drf-spectacular](https://drf-spectacular.readthedocs.io/en/latest/drf_spectacular.html#drf_spectacular.utils.extend_schema).
* Create Django DB migration.

```bash
$ make migrate
```

* Update OpenAPI schema.

```bash
$ make update-schema
```

* Do [release](OPERATIONS.md#Release).
* Wait until the next major release is ahead.
* Remove deprecated model field and callsites.
* Remove deprecated serializer field and decorator.
* Create Django DB migration.
* Update OpenAPI schema.
* Do major release.

Obviously the procedure is simplified and omits steps like review or release
announcement.
An example pull request can be seen [here](https://github.com/RedHatProductSecurity/osidb/pull/55).

## Row-level security & dummy data

Row-level security ensures only the the same group that created the data can view it.
Every record has acl_read and acl_write parameters set when calling Model.save().
These are just identifiers for whichever group created the data, not lists mapping users to read / write permissions.

The default LDAP group used for local development is "data-prodsec".
The group name is hashed (UUIDv5) before being used as an identifier.
You will need to set these values when adding dummy data through a shell (e.g. when testing manually)

### Django shell

Before calling any Model function, make sure the ACLs are set correctly:

    import uuid
    from django.db import connection
    from osidb.models import Flaw

    acls = [uuid.uuid5(
                uuid.NAMESPACE_URL, "https://osidb.prod.redhat.com/ns/acls#data-prodsec"
            )]

    stmt = "SET osidb.acl='%s';"  # Set parameter once before any DB calls
    connection.cursor().execute(stmt % ",".join(str(acl) for acl in acls))
    Flaw.objects.all()  # Use UUID of "data-prodsec" LDAP group when reading records from DB

When you call Model.save(), make sure the ACLs are set correctly:

    Flaw(title='test', cve_id='CVE-TEST-1234', type='VULNERABILITY', state='NEW', resolution='NONE', impact='LOW',
         description='test', acl_read=acls, acl_write=acls
    ).save()  # Use UUID for "data-prodsec" LDAP group when writing records to DB


### DB Shell

You can connect to the database via Django:

    podman exec -it osidb-service python3 manage.py dbshell --database osidb --settings config.settings_shell
    # config.settings_local also works, if unspecified manage.py should default to what osidb-service already uses

Or directly:

    podman exec -it osidb-data psql --db osidb --username=osidb_app_user or osidb_admin_user

Once connected, be sure to set osidb.acl:

    SET osidb.acl='1a1f73d5-2ada-507c-868f-e9e505140b45';
    -- This is uuid.uuid5(uuid.NAMESPACE_URL, "https://osidb.prod.redhat.com/ns/acls#data-prodsec")
    -- uuid3 is b64006d4-8c94-37c3-b86a-fdc8de891e7a

SELECT queries should now show records with matching ACLs you inserted previously:

    SELECT * FROM osidb_flaw;

### Django Admin Site

If you want to use the web-based UI, log in first:

http://localhost:8000/admin/login/

Usernames and passwords to use are in the "etc/openldap/local-export.ldif" file. You can add your own for testing.
In stage / prod, authentication is done through an LDAP server instead of this file.

### Testing external APIs

Given the usage of collectors, it's probably a common occurrence to want to test queries to external APIs, however this can be troublesome in tests since the request may randomly fail (throttling, service down, etc.) and cause all CI jobs to fail and hinder development for an issue that is out of our control.

Enter `vcr.py` and `pytest-recording`:

Both of these are dev dependencies (`pip-sync requirements.txt devel-requirements.txt`) and allow you to record the request/response combination from tests that perform network requests. This information is then saved in "cassette" files and subsequent runs of the tests will use those cassette files instead of performing network calls.

To use this feature, you can simply decorate whichever test performs network operations with `pytest.mark.vcr`

```python
import pytest

...

@pytest.mark.vcr
def test_my_network_operation(self)
    ...
```

Once you have marked your test, you will need to record the network interactions from your test module, to do this you can either run tox manually to hit the `record-new` target and pass your test files/modules as positional arguments

```bash
$ podman exec -ti testrunner tox -e record-new my_module/tests
```

or you can simply append your module to the `testrunner.record-new` section of the `Makefile` and run it

```bash
$ make testrunner.record-new
```

If something has changed in the external API and you need to modify your tests and record a new cassette, follow the same steps as above but instead of using the `record-new` environment, use the `record-rewrite` one, note that if using the `Makefile` you might rewrite more cassettes than needed (resulting in an unnecessarily huge diff), in this case it may be best to manually invoke tox with a specific module/file/test.

By default, some information is scrubbed from the recorded request/response (e.g. Authorization headers), the information to be scrubbed is defined in the `conftest.py` file at the project's root (also referred to as global conftest),you can override this behavior and/or add to it by defining a `vcr_config` fixture in your test module's `conftest.py`, but be aware that most of the time the defaults configured in the global conftest are enough, and you are responsible for any sensitive data leaks resulting from your overrides.

For more information on `vcr.py` and `pytest-recording` usage, check the corresponding documentation:

- [vcr.py](https://vcrpy.readthedocs.io/en/latest/)
- [pytest-recording](https://pytest-vcr.readthedocs.io/en/latest/)

### Django config with DJANGO_SETTINGS_MODULE

The preferred method for denoting active django settings is via setting of DJANGO_SETTINGS_MODULE environment variable.

The local dev environment defines this in the related docker-compose.yml: 

```
    osidb-service:
      container_name: osidb-service
      build: .
      image: osidb-service
      stdin_open: true
      tty: true
      ports:
        - "8000:8000"
      environment:
        OSIDB_DEBUG: ${OSIDB_DEBUG}
        DJANGO_SETTINGS_MODULE: "config.settings_local"
        BZIMPORT_BZ_API_KEY: ${BZIMPORT_BZ_API_KEY}
        JIRA_AUTH_TOKEN: ${JIRA_AUTH_TOKEN}
      command: ./scripts/setup-osidb-service.sh
      volumes:
        - ${PWD}:/opt/app-root/src:z
      depends_on: ["osidb-data"]
```

DJANGO_SETTINGS_MODULE to config.settings_local.

Similarly, this environment variable is set (in openshift) for stage/prod environments:

```
  - name: DJANGO_SETTINGS_MODULE
    value: "config.settings_{{ env }}"

```

### Secrets within the codebase

It is possible that during development, a developer may unknowingly introduce secrets (passwords, tokens, etc.) into the codebase. To avoid this, OSIDB uses the `detect-secrets` tool both as a CI step and a pre-commit hook to avoid having any active secrets being merged into the master branch.

Sometimes, the secrets found by the tool can be false-positives, if you believe that this is the case, then you should update the baseline and audit the newly found secret. This can be easily done by calling the `update-secrets` Makefile entrypoint. There are other ways of ignoring false-positives (such as pragma directives) but it is recommended to follow the aforementioned approach to easily keep track of all false positives and their history.

### Enabling Django signals for a specific test

Django signals are globally disabled via an autouse pytest fixture in the
global `conftest.py` file, in order to enable them for a specific test
you can mark your test with the `@pytest.mark.enable_signals` decorator.

### Configuring CORS Rules for API Access

In order to permit API access from different domains, Cross-Origin Resource
Sharing (CORS) is configured using the corsheaders Django app.
This is crucial for development scenarios where changes to CORS rules are
necessary, and for operations to load in CORS URLs correctly.

Ensure that the `OSIDB_CORS_ALLOWED_ORIGINS` environment variable is set
correctly when deploying the application, for instance:

The `OSIDB_CORS_ALLOWED_ORIGINS` environment variable should be set as a JSON
array like so: `["http://example-ui1.com", "http://example-ui2.com"]`.

This configuration allows developers to adjust CORS rules as needed and gives
operations the information necessary for setting up the correct environment.

### Creating data migrations

Whenever a data migration is created for the purpose of retroactively fixing
existing data and/or applying new processes to old data, one must be wary to
remember that unlike in the local dev environment, stage and production are
subject to row-level security, meaning that by default the database user used
to read and write to the database might not have access to any row and this
could make the data migration fail.

In order to solve it, append the following snippet to the beginning of your
migration regardless of whether it's a python or sql migration:

```python
from osidb.core import set_user_acls
from django.conf import settings


def forwards_func(...):
    # set up user acls so that we can read/write to the database
    set_user_acls(settings.ALL_GROUPS)
    # execute migration logic
    ...
```

The `set_user_acls` is the important part here, you should apply it to both
the forwards and backwards function before performing any database operations.

### History audit

We generate an audit of activity on Flaw and Affect. This information is
surfaced up to the REST API via usage of **include_history=True** url param.

To retrieve raw events related to an entity use the **.events**: 
```python
flaw1 = Flaw.objects.all()[1]
print(flaw1.events.count())
```
This provides queryset of entity snapshots over time.

Alternately, to retrieve Events specific to any entity one can employ the 
**pghistory.models.Events** entrypoint with **tracks** method.
```python
flaw1 = Flaw.objects.all()[1]
print(pghistory.models.Events.objects.tracks(flaw1).count())
```
This approach helpfully returns diff of changes from previous events.

We can retrieve all events specific to any entity including any foreign key
relationships using **references** method. 
```python
flaw1 = Flaw.objects.all()[1]
print(pghistory.models.Events.objects.references(flaw1).count())
```
This would include events on the specific Flaw and Affect events
linked to the Flaw.

To dynamically add context to any audit event:
```python
with pghistory.context(somekey="somevalue"):
    # do something
```

This context can then be searched using normal django filterset approaches:
```python
pghistory.models.Events.objects.references(flaw1)
                .filter(pgh_context__somekey="somevalue")
                .count()
```
                
#### Disabling history audit

We can dynamically disable using django-pgtrigger, in code, using the **pgtrigger.ignore** primitive:

```
with pgtrigger.ignore($TRIGGER_URI(S)):
    #execute code ignoring trigger(s)
```

which we might employ in django migrations.

Alternately, we can temporarily disable event triggers at the pg table level with 'brute force'
by directly disabling in postgres with something like:

```
ALTER TABLE osidb_flaw DISABLE TRIGGER ALL;
ALTER TABLE osidb_affect DISABLE TRIGGER ALL;
```

For operations it is probably best to use management command

To list triggers:
```
> python3 manage.py pgtrigger ls
```

To disable a trigger:
```
> python3 manage.py pgtrigger disable osidb.Flaw:insert_insert
```

To disable a trigger:
```
> python3 manage.py pgtrigger enable osidb.Flaw:insert_insert
```
