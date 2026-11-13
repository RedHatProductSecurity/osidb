"""Upgrade real master data, with live restricted writers during the backfill."""

from datetime import UTC, datetime
from importlib import import_module
from uuid import UUID

import pytest
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from osidb.models import Flaw, FlawChangeEvent
from osidb.tests.event_helpers import latest_event
from osidb.tests.factories import FlawCommentFactory, FlawFactory

pytestmark = [pytest.mark.unit, pytest.mark.django_db(transaction=True)]
backfill = import_module("osidb.migrations.0285_backfill_flaw_change_events")


def test_populated_upgrade_exact_retry_safe_live_writes_and_deletion(
    migrate_database, monkeypatch
):
    latest = MigrationExecutor(connection).loader.graph.leaf_nodes()
    monkeypatch.setattr(backfill, "BATCH_SIZE", 1)
    writer = None
    old = datetime(2001, 2, 3, 4, 5, 6, 123456, tzinfo=UTC)
    during = None
    inserted_id = UUID(int=1)
    try:
        migrate_database([("osidb", "0283_publish_triage_flaws")])
        flaws = sorted(
            FlawFactory.create_batch(5, local_updated_dt=old), key=lambda f: f.pk
        )
        child = FlawCommentFactory(flaw=flaws[-1])
        migrate_database([("osidb", "0284_flaw_change_events")])
        assert not FlawChangeEvent.objects.exists()
        Flaw.objects.filter(pk=flaws[0].pk).update(title="before backfill")
        before = latest_event(flaws[0]).local_updated_dt
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_setting('osidb.acl')")
            acl = cursor.fetchone()[0]
        writer = connection.copy()
        with writer.cursor() as cursor:
            cursor.execute("SELECT set_config('osidb.acl', %s, false)", [acl])
            cursor.execute("SET lock_timeout='100ms'")
            cursor.execute("SET statement_timeout='5s'")

        def live_writes(execute, sql, params, many, context):
            nonlocal during
            if "INSERT INTO osidb_flawchangeevent" in sql and during is None:
                with writer.cursor() as cursor:
                    cursor.execute(
                        "UPDATE osidb_flawcomment SET text='during backfill' WHERE uuid=%s",
                        [child.pk],
                    )
                    cursor.execute(
                        "SELECT MAX(local_updated_dt) FROM osidb_flawchangeevent WHERE flaw_id=%s",
                        [flaws[-1].pk],
                    )
                    during = cursor.fetchone()[0]
                    # A new UUID behind the keyset is covered by the INSERT trigger.
                    fields = [
                        f for f in Flaw._meta.local_concrete_fields if not f.generated
                    ]
                    columns = ",".join(
                        connection.ops.quote_name(f.column) for f in fields
                    )
                    values = ",".join(
                        "%s::uuid"
                        if f.primary_key
                        else "NULL"
                        if f.name in {"cve_id", "bz_id"}
                        else connection.ops.quote_name(f.column)
                        for f in fields
                    )
                    cursor.execute(
                        f"INSERT INTO osidb_flaw ({columns}) SELECT {values} FROM osidb_flaw WHERE uuid=%s",  # noqa: S608 -- fixed metadata identifiers
                        [inserted_id, flaws[1].pk],
                    )
                    # No parent-row lock is taken by backfill; deletion can commit.
                    cursor.execute(
                        "DELETE FROM osidb_flaw WHERE uuid=%s", [flaws[-2].pk]
                    )
            return execute(sql, params, many, context)

        with connection.execute_wrapper(live_writes):
            migrate_database(latest)
        assert latest_event(flaws[0]).local_updated_dt == before > old
        assert latest_event(flaws[-1]).local_updated_dt == during > old
        assert latest_event(flaws[1]).local_updated_dt == old
        assert latest_event(flaws[2]).local_updated_dt == old
        assert latest_event(inserted_id).local_updated_dt > old
        assert not Flaw.objects.filter(pk=flaws[-2].pk).exists()
        assert set(Flaw.objects.values_list("local_updated_dt", flat=True)) == {old}
        expected = list(
            FlawChangeEvent.objects.order_by("id").values_list("id", "local_updated_dt")
        )
        migrate_database([("osidb", "0284_flaw_change_events")])
        migrate_database(latest)
        assert (
            list(
                FlawChangeEvent.objects.order_by("id").values_list(
                    "id", "local_updated_dt"
                )
            )
            == expected
        )
    finally:
        if writer:
            writer.close()
        migrate_database(latest)


def test_backfill_resumes_after_committed_batch(migrate_database, monkeypatch):
    latest = MigrationExecutor(connection).loader.graph.leaf_nodes()
    monkeypatch.setattr(backfill, "BATCH_SIZE", 2)
    inserts = 0
    try:
        migrate_database([("osidb", "0283_publish_triage_flaws")])
        flaws = FlawFactory.create_batch(5)
        migrate_database([("osidb", "0284_flaw_change_events")])

        def interrupt(execute, sql, params, many, context):
            nonlocal inserts
            if "INSERT INTO osidb_flawchangeevent" in sql:
                inserts += 1
                if inserts == 2:
                    raise RuntimeError("interrupted batch")
            return execute(sql, params, many, context)

        with (
            connection.execute_wrapper(interrupt),
            pytest.raises(RuntimeError, match="interrupted batch"),
        ):
            migrate_database(latest)
        assert FlawChangeEvent.objects.count() == 2
        Flaw.objects.filter(pk=flaws[0].pk).update(title="between migration attempts")
        live = latest_event(flaws[0]).local_updated_dt
        migrate_database(latest)
        assert FlawChangeEvent.objects.values("flaw_id").distinct().count() == 5
        assert latest_event(flaws[0]).local_updated_dt == live
    finally:
        migrate_database(latest)
