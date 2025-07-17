############################################################################
## Tests run using tox
############################################################################

#***********************************
### Lint/security check with ruff
#***********************************
.PHONY : lint
lint: osidb collectors apps check-testenv
	@echo ">running lint"
	$(tox) -e ruff-check


#***********************************
### Isort with ruff
#***********************************
.PHONY : ruff-isort
ruff-isort: osidb collectors apps check-testenv
	@echo ">running ruff's isort"
	$(tox) -e ruff-isort


#***********************************
### Autoformat with ruff
#***********************************
.PHONY : format
format: osidb collectors apps check-testenv
	@echo ">running formatting"
	$(tox) -e ruff-format


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
