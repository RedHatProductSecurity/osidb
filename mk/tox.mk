############################################################################
## Tests run using tox
############################################################################

#***********************************
### All CI lint checks
#***********************************
.PHONY : lint-all
lint-all: osidb collectors apps check-testenv
	@echo ">running all CI lint checks"
	$(tox) -e secrets,ruff-check,ruff-isort,ruff-format,migrations,schema-check


#***********************************
### Ruff checks (lint + isort + format)
#***********************************
.PHONY : lint
lint: osidb collectors apps check-testenv
	@echo ">running ruff checks"
	$(tox) -e ruff-check,ruff-isort,ruff-format


#***********************************
### Secret detection
#***********************************
.PHONY : lint-secrets
lint-secrets: check-testenv
	@echo ">running secret detection"
	$(tox) -e secrets


#***********************************
### Migration check
#***********************************
.PHONY : lint-migrations
lint-migrations: osidb collectors apps check-testenv
	@echo ">running migration check"
	$(tox) -e migrations


#***********************************
### Schema check
#***********************************
.PHONY : lint-schema
lint-schema: osidb collectors apps check-testenv
	@echo ">running schema check"
	$(tox) -e schema-check


#***********************************
### Static typecheck with mypy
#***********************************
.PHONY : typecheck
typecheck: osidb collectors apps check-testenv
	@echo ">running mypy"
	$(tox) -e mypy


#***********************************
### tox test
#***********************************
.PHONY : test
test: testunit
testunit: osidb collectors apps check-testenv
	$(tox) -e osidb


#***********************************
### tox checkin
#***********************************
.PHONY : checkin
checkin: check-testenv
	@echo ">running check"
	$(tox)

all: checkin
