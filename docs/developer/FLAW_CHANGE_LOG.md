# Flaw change-log writers

This release adds an internal append-only latest-state projection. It does not
change API reads, filters, serialization, parent RLS, or existing timestamp
writers. Keep those legacy writers for the one-release rollout; their removal
is a separate change, not part of this backend.

## Storage and mutation semantics

`FlawChangeEvent` has an automatic bigint ID, a Flaw UUID and
`local_updated_dt`. The logical relation has `db_constraint=False` and
`DO_NOTHING`: neither PostgreSQL nor Django cascades events when a Flaw is
deleted. There is no per-Flaw rollup row, queue, transaction flush, parent lock,
transaction ID, or public delivery cursor. IDs break timestamp ties only; they
are not commit order or a client polling cursor.

Three AFTER STATEMENT transition-table triggers on each of 14 concrete source
tables append one event per distinct live parent, using the mutation's database
`statement_timestamp()`. Parent discovery includes old/new child assignments,
Tracker/Affect association changes and surviving sibling parents, Affect CVSS,
and concrete label subclasses. Hidden parents are resolved by trusted trigger
functions, not by runtime visibility. Rolled-back source mutations roll back
their events. Deleting a parent does not recreate it or publish a tombstone.

UPDATE predicates are generated from local concrete Django metadata, with
explicit bookkeeping exclusions rather than a business-field allowlist. New
business fields (including `Flaw.bz_id`) participate by default. Visibility is
meaningful even though it is generated; unchanged values, legacy timestamps,
ACL-only edits with unchanged visibility, search vectors, and internal metadata
do not append. Existing business signals and workflow/alert effects remain.

The effective head is the greatest `(local_updated_dt, id)` per Flaw, never
the newest inserted ID alone. Out-of-order statement completion cannot lower
the effective timestamp. Future readers must start from authorized live Flaws
and apply both timestamp bounds to that latest state, not arbitrary history.

## Fresh migrations and online upgrade

* `0284_flaw_change_events` creates the final table/indexes and all 42 frozen
  pgtrigger functions directly after current master's `0283`. It creates no
  intermediate projection or bootstrap stages.
* `0285_backfill_flaw_change_events` runs non-atomically in bounded UUID-keyset
  batches, copying each quiet Flaw's exact legacy timestamp. It only inserts
  where no event exists. Every batch commits independently and retries skip
  previously populated parents. It never updates/locks a Flaw or repairs history.

Writers are active before backfill. An intervening event prevents a baseline;
a race can leave an extra baseline but cannot overwrite a higher MAX. New
UUIDs behind the keyset are protected by the INSERT trigger. A concurrent
parent deletion can leave a soft orphan, which maintenance removes. Reversing
the backfill is a no-op; reversing the schema drops only the new projection,
leaving all legacy fields/writers intact.

## Permissions and rollout contract

Apply writer migrations as a trusted owner with `BYPASSRLS` (or superuser), never
the runtime application role. Writer trigger functions use SECURITY DEFINER,
pin `search_path` to `pg_catalog, osidb_admin, public, pg_temp`, transfer ownership
to the installer and revoke PUBLIC EXECUTE. Trigger functions validate their
source attachment, statement level and operation. Runtime cannot attach these
functions to caller-controlled tables. Only trusted roles may CREATE in either
project schema (`osidb_admin` or `public`); deployment must revoke PUBLIC/runtime
CREATE there. Both schema layouts are supported.

The event table intentionally has no RLS policy; Flaw RLS remains enabled and
forced. Direct event SQL is internal and is **not** an authorization boundary.
No public viewset exposes the log. FlawQL and sparse prefetch exclude its reverse
relation. Runtime needs normal DML/sequence grants on the new table. Ops must
provision the trusted writer migration owner/schema privileges before 0284.
Pruning uses only the ordinary APP connection: no database pruning function,
extra role, SYSTEM credentials, or function EXECUTE grant is required.

Tests install/replay DDL under `OSIDB_TEST_MIGRATION_USER` and
`OSIDB_TEST_MIGRATION_PASSWORD` (local default `osidb_manage_user` and the configured
database password), then run ordinary test bodies under restricted app credentials.
CI supplies its privileged migration owner explicitly.

## Bounded maintenance

`manage.py compact_flaw_change_events` runs head-only compaction by default.
The Celery task uses the project's `@bypass_rls` decorator, temporarily setting
the normal application's session ACLs to `ALL_GROUPS` and restoring the previous
ACLs in `finally`, on success or failure. The decorator does not wrap a transaction.
The management command uses the same decorated entry pattern and batch algorithm.
Do not call the internal batch core with restricted ACLs: that would mistake
hidden parents for deleted ones.

The task runs daily at 03:15 by default. Configure its crontab in
`CELERY_BEAT_SCHEDULE` (default `FLAW_CHANGE_LOG_COMPACTION_CRONTAB`), following the
existing project settings pattern. Both the task and beat entry explicitly use
the `low` queue. Operational database errors retry twice with backoff; already
committed batches remain committed and retrying is idempotent.
Each batch is a short independent transaction, capped at 5000
victims, with a 1-second lock timeout and 10-second statement timeout. The default
run budget is 60 seconds / 1000 batches; CLI limits are validated.

Only eligible event rows are locked, with `FOR UPDATE SKIP LOCKED`; source/parent
rows are not locked. The decorated task checks parent existence with all-group visibility,
so a hidden Flaw is never misclassified as an orphan. It removes true orphans and
non-head history while preserving even a very old quiet head, including the highest
ID on timestamp ties. Optional history retention does not expire the head. Concurrent
pruners may skip each other's locked victims; a later scheduled pass catches them.
Concurrent writers append independently. Compaction is not event delivery, audit
retention, or a guarantee that every statement remains queryable forever.
