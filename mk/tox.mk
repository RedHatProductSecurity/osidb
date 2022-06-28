############################################################################
## Tests run using tox
############################################################################

#***********************************
### pylint,flake8
#***********************************
.PHONY : lint
lint: osidb collectors apps check-testenv
	@echo ">running lint"
	$(tox) -e pylint,flake8



#***********************************
### Static typecheck with mypy
#***********************************
.PHONY : typecheck
typecheck: osidb collectors apps check-testenv
	@echo ">running mypy"
	$(tox) -e mypy


#***********************************
### Autoformat with black
#***********************************
.PHONY : format
format: osidb collectors apps check-testenv
	@echo ">running formatting"
	$(tox) -e black


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


#***********************************
### osidb pre-push check for githook
#***********************************
.PHONY : osidb-pre-push
osidb-pre-push: check-venv-active
	@echo ">running osidb pre-push check"
	make check-testenv && $(tox) -e pylint,flake8,bandit
