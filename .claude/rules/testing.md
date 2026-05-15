---
paths:
  - '**/*'
---
# Running Tests in OSIDB

OSIDB uses **tox** inside a **testrunner container** (podman). Most tests require a running database and/or web server, so the general path is via `podman exec` into the testrunner container.

## Quick Reference

| Scenario | Command |
|---|---|
| Pure unit tests (no DB/server) | `tox -e unit-tests -- path/to/test.py::TestClass` |
| Everything else (general path) | `podman exec -it testrunner tox -e tests -- path/to/test.py::TestClass` |
| All tests | `make testrunner.all-tests` |

## Running a Specific Test

For most tests (integration, endpoint, anything needing DB or web server):

```bash
podman exec -it testrunner tox -e tests -- osidb/tests/test_foo.py::TestClass
podman exec -it testrunner tox -e tests -- osidb/tests/test_foo.py::TestClass::test_method
```

For pure unit tests that have no DB or web server dependency, tox can be run locally:

```bash
tox -e unit-tests -- osidb/tests/test_foo.py::TestClass
```

## `make testrunner` Entrypoints

Run these from the repo root (they all exec into the testrunner container):

| Target | What it runs |
|---|---|
| `make testrunner` | `make checkin` (lint + typecheck + unit tests) |
| `make testrunner.all-tests` | Full test suite (`tox -e tests`) |
| `make testrunner.all-unit-tests` | All unit tests across modules |
| `make testrunner.all-integration-tests` | Integration tests only |
| `make testrunner.osidb` | Unit tests for `osidb/` |
| `make testrunner.bzimport` | Unit tests for `collectors/bzimport` |
| `make testrunner.jiraffe` | Unit tests for `collectors/jiraffe` |
| `make testrunner.workflows` | Unit tests for `apps/workflows` |
| `make testrunner.sla` | Unit tests for `apps/sla` |
| `make testrunner.lint` | Linting only |
| `make testrunner.typecheck` | Type checking only |
| `make testrunner.rls` | Row-level security tests |

## Tox Environments

- `tests` — full suite (unit + integration; requires DB and web server)
- `unit-tests` — unit tests only (no DB/server required)
- `integration-tests` — integration tests only
- `record-new` / `record-rewrite` — record VCR cassettes for network tests

## Prerequisites

The testrunner container must be running (started via `make start-local`).
Check with: `podman ps | grep testrunner`

## Development Docs

- Setup & full test docs: `docs/developer/DEVELOP.md`
- Contributing guidelines: `docs/developer/CONTRIBUTING.md`
- Makefile targets overview: `make help`
