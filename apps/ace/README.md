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

When a `Flaw`'s `components` list is set or changed, ACE schedules a background Celery task that:

1. Checks that `lib_newtopia` is installed; if not, logs a warning and returns immediately.
2. Iterates over each component in `Flaw.components`.
3. Calls `NewtopiaQuerier().search([component], strict=True).filter(products=ps_modules).all()` to query the Deptopia / manifest-cube product tree.
4. Creates a new `Affect` (with `AFFECTED` / `DELEGATED` affectedness/resolution and the flaw's impact) for each result that does not already have a matching affect on the flaw.

## Architecture

```
Flaw.save()
  └─▶ pre_save signal  (apps/ace/signals.py)
          └─▶ transaction.on_commit
                  └─▶ sync_flaw_affects_from_newcli.delay(flaw_id)   [Celery task]
                          └─▶ HAS_LIB_NEWTOPIA?  No → no-op (warning logged)
                          └─▶ _flaw_components(flaw)
                          └─▶ for each component:
                                  └─▶ NewtopiaQuerier().search([component], strict=True)
                                                       .filter(products=ps_modules)
                                                       .all()
                                  └─▶ _sync_affects_from_results(flaw, results)
                                          └─▶ Affect.save()  per new (stream, purl) pair
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
| `OSIDB_AFFECTS_AUTO_CREATE` | `false` | Enable automatic affect creation on `Flaw.components` change. |
| `OSIDB_AFFECTS_AUTO_CREATE_PS_MODULES` | `["hummingbird-1"]` | JSON list of PS module names passed to `NewtopiaQuerier.filter(products=…)`. |

## Structure

| Path | Purpose |
|---|---|
| `apps/ace/apps.py` | `AppConfig` — registers the app and imports signals on `ready()` |
| `apps/ace/signals.py` | `pre_save` on `Flaw` — schedules the Celery task on commit |
| `apps/ace/tasks.py` | Celery task `sync_flaw_affects_from_newcli` and its helpers |
| `apps/ace/tests/` | Unit tests |
