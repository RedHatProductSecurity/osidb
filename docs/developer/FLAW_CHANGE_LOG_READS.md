# Flaw change-log reads

This is the read-side rollout on top of [the append-only backend](FLAW_CHANGE_LOG.md).
`OSIDB_USE_FLAW_WATERMARK` defaults to **false**. Local Compose forwards it only
to the web service. Deploy the application and complete migrations through
`0285_backfill_flaw_change_events` before enabling it in each environment through
ops configuration. No extra pruning role, function, or environment variable is
needed. Existing timestamp columns, writers, signals, and indexes remain for
rollback; their removal is explicitly out of scope.

## Read contract

Both versions keep authorized, live `Flaw` as the query root. `changed_after`
and `changed_before` constrain the **same latest event timestamp**, inclusively.
An older event at 10:00 cannot qualify a Flaw for 09:00–11:00 if its latest event
is 12:00. Deleting superseded history is compatible with these latest-state
predicates: the log is not a lossless feed, audit log, or commit-order cursor.

Polling filters do not annotate a latest-value subquery for every Flaw:

* After-only uses distinct Flaw IDs from events at or after the lower bound.
* Both bounds restrict those candidates to the window, then reject any parent
  with an event newer than the upper bound (`NOT EXISTS`).
* Before-only requires event coverage and rejects newer events. Missing coverage
  never accidentally qualifies; complete baseline coverage is an enablement
  prerequisite, not something the API silently repairs from legacy timestamps.
* Reversed effective bounds return no results; equal bounds remain inclusive.

The explicit `DISTINCT` candidate relation matters for ordered LIMIT pages; the
prototype's plain-IN alternative could choose a parent-first semi-loop. The
other bound comes from the already validated form's typed `cleaned_data`, not
reparsed request text. Method iteration order does not change the result. V1
retains its five-minute lower overlap exactly once; V2 adds none. That overlap
is existing materialized-view compensation, **not** a commit/delivery guarantee.

Only timestamp projection (`/flaws/index`) uses a scalar latest-event subquery,
ordered by `(local_updated_dt DESC, id DESC)`. UUID, live CVE assignment, null-CVE
exclusion, RLS, model ordering, pagination, JSON datetime rendering and response
shapes remain unchanged. No serializer or optimistic-concurrency field is added
or repurposed. The internal reverse relation remains excluded from FlawQL and
sparse traversal by the backend. Flag false uses the original legacy-column
predicates/SQL and index projection; it does not disable append writers.

## Reproduction and evidence

`perf/flaw_change_reads.py` is standalone, local-only diagnostic tooling, not a
management command or runtime library. Use the ordinary restricted app role in
the normal local environment, with an explicit database and fixed bounds:

```sh
python perf/flaw_change_reads.py --database osidb \
  --after=2026-11-06T20:36:00+00:00 --before=2026-11-06T21:36:00+00:00 \
  --repeats=5 --acl=public > /tmp/read-plans.json
```

Repeat with `--acl=all`. It runs actual `FlawFilter`/`FlawV1Filter` count/page
queries and UUID/CVE index projections with both flag values, captures their
executed SQL for `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)`, and reports row counts
and individual/median client timings. It uses a read-only transaction and bounded
timeouts, repeats and page size; it does not seed, migrate, prune or vacuum.
Use fixed absolute bounds for paired comparisons. The event count is the total
internal table count, **not** an authorized Flaw count. Large index projections
still return every visible identity and can be expensive.

### Fresh-stack bounded smoke

On the `c98ad4cf` master + backend `5463a000` stack, a disposable local PostgreSQL
16 database was populated through the current models: 1,000 synthetic Flaws
(800 public, 200 embargoed), 16,000 events, six baseline/history rows per Flaw
and 100 extra older events on each of 100 hot Flaws. Quiet heads are 30 days old;
the hot heads span 50 minutes. Legacy/head timestamps match. This is a deliberately
small read-plan smoke, not a production-shaped corpus or write-contention test.
Normal app credentials, both ACL scopes, five samples per query, and fixed one-hour
bounds above were used. Public/all runs overlapped on the same host; warm-cache
client timings include ORM/materialization costs and are not isolated capacity
measurements. No planner/memory tuning was applied.

V2 median milliseconds, public / all-group:

| Operation | Legacy | Events |
| --- | ---: | ---: |
| Count (80 / 100 matching Flaws) | 0.89 / 0.76 | 2.89 / 2.92 |
| Ordered first page (50 rows) | 6.26 / 6.83 | 10.37 / 9.95 |
| Full UUID index (800 / 1,000 rows) | 5.65 / 6.90 | 7.42 / 5.85 |
| Full CVE index (800 / 1,000 rows) | 5.04 / 3.97 | 5.62 / 7.99 |

Selected event count/page plans both use `flaw_event_time_idx` for 6,940 range
candidates, aggregate to 100 distinct parent IDs, join authorized Flaws, and
probe `flaw_event_latest_idx` for the anti-newer check (80 / 100 loops). Page
sorts use in-memory quicksort, not an all-parent latest-value projection.
The tiny corpus does not establish production latency or a universal speedup.
Raw local results: `/tmp/opencode/pr2-perf-{public,all}.json` (ephemeral artifacts).

### Prior prototype evidence, not rerun on this stack

Read-only prototype `75ffb37c` reported 3,530 passing tests, a write matrix with
824 verified commits and no DB deadlocks/timeouts, and 18 lock probes. Its 700k
event history was compacted by 600k rows in about 15.7s. Reported one-hour count
times were about 59/65ms dense and 3.44/4.67ms compacted; full UUID/CVE indexes
were about 445/254ms. These are **prototype-base measurements**, retained only
as context; the old full-schema dump was not restored into current master and
that matrix/large corpus was not rerun here. They are not an SLA or proof of
commit-order delivery. See that revision's prototype report for original plans,
dataset and limitations rather than carrying its historical tooling into runtime.

## Correctness validation

Focused tests cover exact legacy SQL, typed/relative/equal/reversed/single bounds,
missing coverage, the historical-window trap, and projection ordering. Actual
API tests run both versions with signals enabled, exercising update/bulk/raw
save-bypass writes, normal child saves, CVSS callback effects, labels/MTI,
Tracker/reference/comment/acknowledgment changes, rollback flag selection,
quiet indexes, live CVE changes, visibility versus ACL bookkeeping, RLS,
serialization/concurrency timestamps, ordering and pagination.

Coordinated real writer/reader connections hold a source mutation uncommitted
while actual API requests assert neither content nor events leak. After commit
both are discoverable; after rollback neither is. These regressions do not mute
business signals, replace triggers, or assert that statement time is commit time.

Run the focused regressions and the complete suite through the normal local
testrunner (`tox -e tests -- --no-cov`, optionally passing the two new test
modules). No alternate settings, old-schema restore, migration bypass, or
test selection is needed for the complete suite. Repository pre-commit checks
include migration drift and OpenAPI schema parity. CodeRabbit reviewed the
selected read changes against backend `5463a000` with zero findings.

Final local results on this stack: **3,603 passed** (753 warnings, 692.80s) for
the complete suite, then **71 passed** (105 warnings, 56.97s) for the focused
regressions. Neither run had failures or skips. Normal repository hooks passed.
