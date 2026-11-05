# ACE — Affect Creation Engine

ACE is a self-contained Django app within [OSIDB](https://github.com/RedHatProductSecurity/osidb) that **automatically creates affects on flaws** based on product component data queried from [`lib_newtopia`](https://gitlab.cee.redhat.com/prodsec-dev/newtopia-cli).

## Goals

* **Accurate affects, automatically** — leverage `lib_newtopia`'s product-definition awareness to populate affects without manual analyst work.
* **Self-contained** — all ACE logic (Celery tasks, Django signals, configuration) lives in this app; nothing ACE-specific leaks into the `osidb` core.
* **Optional dependency** — `lib_newtopia` is an internal package not available on PyPI. If it is not installed the Celery task is a no-op and logs a warning; OSIDB continues to operate normally without it.
* **Configurable scope** — the set of PS modules targeted by auto-creation is controlled at runtime via environment variables (see [Configuration](#configuration)).
* **Idempotent** — running the task more than once for the same flaw and component never creates duplicate affects; existing `(ps_update_stream, ps_component)` pairs are silently skipped.
* **Opt-in** — disabled by default; operators enable it by setting `OSIDB_AFFECTS_AUTO_CREATE=true`.

## How it works

ACE qualifies a flaw once, the first time it enters a processable `DEFAULT` state from `NEW`, an empty workflow, or `EMBARGOED`. That check applies pre-filter labels and records `assist_meta["ace_qualified"]`. It does not run again when components change, or when a flaw leaves `DONE`, `MANUAL`, or `REJECTED`.

Affect creation runs only when an `auto-affects` workflow label is created. That happens automatically for a strict or special-case component during qualification. A user can run it again by deleting that label and creating it while the flaw is still eligible (`TRIAGE` through `SECONDARY_ASSESSMENT`). A label created while the flaw is `NEW`, `DONE`, or not in `DEFAULT` is stored, and the task skips.

The task:

1. Checks that `lib_newtopia` is installed; if not, logs a warning and returns immediately.
2. Refuses flaws that are not in an eligible `DEFAULT` state.
3. Pre-filters each component. `potential-rejection`, `manual-triage`, and `auto-rejected` stay labels. Only `auto-affects` (and the Chromium / Go stdlib handlers) create affects.
4. Calls `NewtopiaQuerier().search([component], strict=True).filter(products=ps_modules).all()` for those components.
5. Creates an `Affect` for each result that does not already have a matching affect on the flaw. Existing `(ps_update_stream, ps_component)` pairs are left unchanged, so a later run can still add streams that did not exist before.

## Architecture

```
Flaw.save()
  └─▶ classification_changed, first entry into an eligible state
          └─▶ transaction.on_commit
                  └─▶ qualify_flaw_for_ace(flaw_id)
                          └─▶ pre-filter labels
                          └─▶ auto-affects WorkflowLabel, when a component qualifies
                                  └─▶ post_save
                                          └─▶ sync_flaw_affects_from_newcli.delay(...)
```

## Installation of lib-newtopia

`lib_newtopia` and its dependency `deptopia-client` are hosted on the internal Nexus
repository — they are **not** available on PyPI. When building the container image, pass
the Nexus simple-index URL as the `PRODSEC_PYPI_INDEX_URL` build argument:

```bash
docker build \
  --build-arg PRODSEC_PYPI_INDEX_URL=$PRODSEC_PYPI_INDEX_URL \
  .
```

or via `docker-compose` by setting the environment variable before running:

```bash
export PRODSEC_PYPI_INDEX_URL=...
podman compose up --build
```

If `PRODSEC_PYPI_INDEX_URL` is not set the image is built without `lib_newtopia` and ACE
runs as a no-op (the task returns `{"skipped_reason": "lib_newtopia not installed"}`).

## Configuration

ACE reads its settings from environment variables via `AffectSettings` (pydantic-settings, prefix `OSIDB_AFFECTS_`):

| Environment variable | Default | Description |
|---|---|---|
| `OSIDB_AFFECTS_AUTO_CREATE` | `false` | Enable qualification on first entry and affect creation when the `auto-affects` label is created. |
| `OSIDB_AFFECTS_AUTO_CREATE_PS_MODULES` | `["hummingbird-1"]` | JSON list of PS module names passed to `NewtopiaQuerier.filter(products=…)`. |

## Structure

| Path | Purpose |
|---|---|
| `apps/ace/apps.py` | `AppConfig` — registers the app and imports signals on `ready()` |
| `apps/ace/signals.py` | Qualifies a flaw on its first eligible classification, and enqueues ACE when the `auto-affects` label is created |
| `apps/ace/tasks.py` | Celery task `sync_flaw_affects_from_newcli` and its helpers |
| `apps/ace/tests/` | Unit tests |
