# ACE — Affect Creation Engine

ACE logic lives in [OSIDB](https://github.com/RedHatProductSecurity/osidb) for
component-mapping pre-filter rules, affect resolution, and REST APIs consumed by
the **affect-creator** microservice.

## Goals

* **Accurate affects, automatically** — affect-creator queries `lib_newtopia` and
  creates affects via the OSIDB REST API using ACE rules exposed here.
* **Self-contained** — ACE helpers and API views live in this app; nothing
  ACE-specific leaks into the `osidb` core.

## How it works

```text
affect-creator poll_flaws (every 5 min)
  └─▶ FlawSyncManager.sync_task → process_flaw(flaw_uuid)
          └─▶ GET /component-mapping/pre-filter   (OSIDB ACE API)
          └─▶ NewtopiaQuerier (lib-newtopia)
          └─▶ GET /affects/auto-resolve           (OSIDB ACE API)
          └─▶ GET /ps-modules/active-streams      (Go stdlib Phase 4)
          └─▶ POST /affects, POST /flaws/…/labels
```

## REST APIs (for affect-creator)

| Endpoint | Purpose |
|---|---|
| `GET /osidb/api/v1/component-mapping/pre-filter` | Component-mapping pre-filter decision tree |
| `GET /osidb/api/v1/affects/auto-resolve` | `Affect.auto_resolve()` rules |
| `GET /osidb/api/v1/ps-modules/active-streams` | Active PS update streams per module |

## Configuration

`AffectSettings` (`OSIDB_AFFECTS_*` environment variables) is retained for
compatibility but **in-process auto-create is disabled**. Use affect-creator
and its `ACE_PS_MODULES` setting instead.

| Environment variable | Default | Description |
|---|---|---|
| `OSIDB_AFFECTS_AUTO_CREATE` | `false` | **Deprecated** — no longer triggers in-process ACE |
| `OSIDB_AFFECTS_AUTO_CREATE_PS_MODULES` | `["hummingbird-1"]` | Used only by legacy `sync_flaw_affects_from_newcli` |

## Structure

| Path | Purpose |
|---|---|
| `apps/ace/apps.py` | `AppConfig` |
| `apps/ace/api_views.py` | REST APIs for affect-creator |
| `apps/ace/tasks.py` | Shared ACE logic |
| `apps/ace/tests/` | Unit tests |
