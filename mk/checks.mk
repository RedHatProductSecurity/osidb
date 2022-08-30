############################################################################
## Checks
############################################################################


#***********************************
### Check podman registry login
#***********************************
.PHONY: check-reg
check-reg:
	@echo ">Checking podman registry login"
	@$(podman) login --get-login registry.redhat.io > /dev/null


#***********************************
### Check that venv exists
#***********************************
# NOTE that using make's "conditional syntax" (such as ifeq) would not work for `make dev-env`, because the test would run *before* the venv would get created.
.PHONY: check-venv
check-venv:
	@echo ">Checking local dev venv existence"
	@[[ -d venv ]] || [[ -f .python-version ]] || { echo "venv not created! Read about make dev-env in DEVELOPMENT.md." ; exit 1 ; }


#***********************************
### Check that venv is activated
#***********************************
# NOTE this might not be 100% compatible with all possible venv implementations
# but it should be compatible with most of them
.PHONY: check-venv-active
check-venv-active: check-venv
	@echo ">Checking for active venv"
	@[[ -z "${VIRTUAL_ENV}" ]] && { echo "venv is not active, if it is active your venv management system has not set the VIRTUAL_ENV environment variable" ; exit 1 ; } || true


#***********************************
### Check that the environment has the requisite python versions
#***********************************
.PHONY: check-testenv
check-testenv:
	@echo ">Checking that the testing environment has the requisite python version"
	@command -v python3.9 || { echo "Python 3.9 not installed! Read about testrunner and tox testing in DEVELOPMENT.md." ; exit 1 ; }
	@command -v tox || { echo "tox not installed! Read about testrunner and tox testing in DEVELOPMENT.md." ; exit 1 ; }
