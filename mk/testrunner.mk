############################################################################
## testrunner entrypoints
############################################################################
testrunner:
	$(compose) exec testrunner make checkin
testrunner.lint:
	$(compose) exec testrunner make lint
testrunner.format:
	$(compose) exec testrunner make format
testrunner.typecheck:
	$(compose) exec testrunner make typecheck
testrunner.osidb:
	$(compose) exec testrunner tox -e unit-tests -- osidb
testrunner.bzimport:
	$(compose) exec testrunner tox -e unit-tests -- collectors/bzimport
testrunner.jiraffe:
	$(compose) exec testrunner tox -e unit-tests -- collectors/jiraffe
testrunner.product_definitions:
	$(compose) exec testrunner tox -e unit-tests -- collectors/product_definitions
testrunner.framework:
	$(compose) exec testrunner tox -e unit-tests -- collectors/framework
testrunner.sla:
	$(compose) exec testrunner tox -e unit-tests -- apps/sla
testrunner.workflows:
	$(compose) exec testrunner tox -e unit-tests -- apps/workflows
testrunner.all-unit-tests:
	$(compose) exec testrunner tox -e unit-tests -- collectors/bzimport collectors/jiraffe collectors/product_definitions osidb
testrunner.all-integration-tests:
	$(compose) exec testrunner tox -e integration-tests
testrunner.all-tests:
	$(compose) exec testrunner tox -e tests
testrunner.all-tests-in-parallel:
	$(compose) exec testrunner tox -e tests-in-parallel
testrunner.queryset-tests:
	$(compose) exec testrunner tox -e queryset-tests
testrunner.record-new:
	rm -rf *_cache.sqlite
	$(compose) exec testrunner tox -e record-new -- osidb/ collectors/jiraffe collectors/bzimport collectors/product_definitions
testrunner.record-rewrite:
	rm -rf *_cache.sqlite
	$(compose) exec testrunner tox -e record-rewrite -- collectors/jiraffe collectors/bzimport collectors/product_definitions
testrunner.secrets:
	$(compose) exec testrunner tox -e secrets
testrunner.krb5-auth:
	$(compose) exec testrunner tox -e krb5-auth
testrunner.rls:
	$(compose) exec testrunner tox -e rls
