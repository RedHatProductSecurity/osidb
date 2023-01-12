############################################################################
## testrunner entrypoints
############################################################################
testrunner:
	$(podman) exec -it testrunner make checkin
testrunner.lint:
	$(podman) exec -it testrunner make lint
testrunner.format:
	$(podman) exec -it testrunner make format
testrunner.typecheck:
	$(podman) exec -it testrunner make typecheck
testrunner.osidb:
	$(podman) exec -it testrunner tox -e unit-tests osidb
testrunner.bzimport:
	$(podman) exec -it testrunner tox -e unit-tests collectors/bzimport
testrunner.jiraffe:
	$(podman) exec -it testrunner tox -e unit-tests collectors/jiraffe
testrunner.product_definitions:
	$(podman) exec -it testrunner tox -e unit-tests collectors/product_definitions
testrunner.errata:
	$(podman) exec -it testrunner tox -e unit-tests collectors/errata
testrunner.framework:
	$(podman) exec -it testrunner tox -e unit-tests collectors/framework
testrunner.osim:
	$(podman) exec -it testrunner tox -e unit-tests apps/osim
testrunner.all-unit-tests:
	$(podman) exec -it testrunner tox -e unit-tests collectors/bzimport collectors/jiraffe collectors/product_definitions osidb
testrunner.all-integration-tests:
	$(podman) exec -it testrunner tox -e integration-tests collectors/bzimport collectors/jiraffe collectors/product_definitions osidb
testrunner.all-tests:
	$(podman) exec -it testrunner tox -e tests
testrunner.record-new:
	rm -rf *_cache.sqlite
	$(podman) exec -it testrunner tox -e record-new osidb/ collectors/jiraffe collectors/bzimport collectors/product_definitions
testrunner.record-rewrite:
	rm -rf *_cache.sqlite
	$(podman) exec -it testrunner tox -e record-rewrite collectors/jiraffe collectors/bzimport collectors/product_definitions
testrunner.secrets:
	$(podman) exec -it testrunner tox -e secrets
testrunner.krb5-auth:
	$(podman) exec -it testrunner tox -e krb5-auth
