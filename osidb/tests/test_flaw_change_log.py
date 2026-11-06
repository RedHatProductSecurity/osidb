import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from io import StringIO
from uuid import uuid4

import pytest
from django.conf import settings
from django.core.management import call_command
from django.db import OperationalError, connection, connections, transaction
from django.utils import timezone

from osidb.change_log import compact_change_events
from osidb.core import set_user_acls
from osidb.models import Flaw, FlawChangeEvent
from osidb.tasks import compact_flaw_change_events
from osidb.tests.event_helpers import latest_event, reset_events
from osidb.tests.factories import FlawCommentFactory, FlawFactory

pytestmark = [pytest.mark.unit, pytest.mark.django_db(transaction=True)]


def test_append_immediate_visibility_atomic_rollback_no_head_update():
    flaw = FlawFactory()
    old = list(
        FlawChangeEvent.objects.filter(flaw=flaw).values_list("id", "local_updated_dt")
    )
    with transaction.atomic():
        Flaw.objects.filter(pk=flaw.pk).update(title="uncommitted")
        assert FlawChangeEvent.objects.filter(flaw=flaw).count() == len(old) + 1
        assert latest_event(flaw).local_updated_dt >= old[-1][1]
        transaction.set_rollback(True)
    assert (
        list(
            FlawChangeEvent.objects.filter(flaw=flaw).values_list(
                "id", "local_updated_dt"
            )
        )
        == old
    )
    Flaw.objects.filter(pk=flaw.pk).update(title="committed")
    assert FlawChangeEvent.objects.filter(flaw=flaw).count() == len(old) + 1
    assert FlawChangeEvent.objects.filter(
        id=old[0][0], local_updated_dt=old[0][1]
    ).exists()


@pytest.mark.enable_rls
def test_head_only_prune_retains_quiet_hidden_heads_and_ties_purges_real_orphans():
    set_user_acls(settings.ALL_GROUPS)
    public = FlawFactory(embargoed=False)
    hidden = FlawFactory(embargoed=True)
    old = timezone.now() - timedelta(days=3650)
    reset_events([public, hidden], old)
    for flaw in [public, hidden]:
        FlawChangeEvent.objects.create(
            flaw=flaw, local_updated_dt=old - timedelta(days=1)
        )
        FlawChangeEvent.objects.create(flaw=flaw, local_updated_dt=old)
    heads = {flaw.pk: latest_event(flaw).pk for flaw in [public, hidden]}
    orphan = uuid4()
    FlawChangeEvent.objects.create(flaw_id=orphan, local_updated_dt=timezone.now())
    set_user_acls(settings.PUBLIC_READ_GROUPS)
    assert not Flaw.objects.filter(pk=hidden.pk).exists()
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_user,current_setting('osidb.acl')")
        runtime, acl = cursor.fetchone()
    assert compact_flaw_change_events(batch_size=1)["deleted"] == 5
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_user,current_setting('osidb.acl')")
        assert cursor.fetchone() == (runtime, acl)
    assert not Flaw.objects.filter(pk=hidden.pk).exists()
    assert set(FlawChangeEvent.objects.values_list("id", flat=True)) == set(
        heads.values()
    )
    assert not FlawChangeEvent.objects.filter(flaw_id=orphan).exists()
    assert compact_flaw_change_events()["deleted"] == 0
    FlawChangeEvent.objects.create(
        flaw_id=hidden.pk, local_updated_dt=old - timedelta(days=2)
    )
    compact_flaw_change_events()
    assert latest_event(hidden).pk == heads[hidden.pk]


def test_optional_history_retention():
    flaw = FlawFactory()
    now = timezone.now()
    reset_events([flaw], now)
    FlawChangeEvent.objects.create(flaw=flaw, local_updated_dt=now - timedelta(hours=1))
    FlawChangeEvent.objects.create(flaw=flaw, local_updated_dt=now - timedelta(days=10))
    assert compact_change_events(history_days=7)["deleted"] == 1
    assert FlawChangeEvent.objects.filter(flaw=flaw).count() == 2
    assert compact_change_events()["deleted"] == 1
    assert latest_event(flaw).local_updated_dt == now


def test_prune_arguments_and_budgets_bounded():
    for kwargs in [
        {"batch_size": 0},
        {"history_days": -1},
        {"max_batches": 0},
        {"seconds": 0},
    ]:
        with pytest.raises(ValueError):
            compact_change_events(**kwargs)
    with transaction.atomic(), pytest.raises(ValueError):
        compact_change_events()


def test_daily_schedule_calls_bounded_head_only_task():
    entry = settings.CELERY_BEAT_SCHEDULE["compact_flaw_change_events"]
    assert entry["task"] == "osidb.tasks.compact_flaw_change_events"
    assert entry["schedule"].hour == {3} and entry["schedule"].minute == {15}
    assert compact_flaw_change_events.queue == "low"
    assert entry["options"]["queue"] == "low"
    assert entry["schedule"] == settings.FLAW_CHANGE_LOG_COMPACTION_CRONTAB
    result = compact_flaw_change_events()
    assert result["history_days"] == 0 and result["deleted"] == 0


def test_cli_prunes_only_eligible_unlocked_events():
    flaw = FlawFactory()
    head = latest_event(flaw)
    victim = FlawChangeEvent.objects.create(
        flaw=flaw, local_updated_dt=head.local_updated_dt - timedelta(days=1)
    )
    other = connection.copy()
    try:
        other.set_autocommit(False)
        with other.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM osidb_flawchangeevent WHERE id=%s FOR UPDATE",
                [victim.pk],
            )
        output = StringIO()
        call_command(
            "compact_flaw_change_events", batch_size=1, max_batches=1, stdout=output
        )
        assert json.loads(output.getvalue())["deleted"] == 0
        assert FlawChangeEvent.objects.filter(pk=victim.pk).exists()
        other.rollback()
        output = StringIO()
        call_command("compact_flaw_change_events", batch_size=1, stdout=output)
        assert json.loads(output.getvalue())["deleted"] == 1
        assert latest_event(flaw).pk == head.pk
        assert FlawChangeEvent.objects.filter(flaw=flaw).count() == 1
    finally:
        other.close()


@pytest.mark.enable_rls
def test_task_restores_public_acl_on_exception_without_role_elevation():
    set_user_acls(settings.ALL_GROUPS)
    hidden = FlawFactory(embargoed=True)
    set_user_acls(settings.PUBLIC_READ_GROUPS)
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_user,current_setting('osidb.acl')")
        runtime, acl = cursor.fetchone()
    statements = []

    def fail_batch(execute, sql, params, many, context):
        statements.append(sql)
        if "WITH victims AS MATERIALIZED" in sql:
            assert Flaw.objects.filter(pk=hidden.pk).exists()
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT current_user,rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user"
                )
                assert cursor.fetchone() == (runtime, False, False)
            raise RuntimeError("failed maintenance")
        return execute(sql, params, many, context)

    with (
        connection.execute_wrapper(fail_batch),
        pytest.raises(RuntimeError, match="failed maintenance"),
    ):
        compact_flaw_change_events()
    assert not connection.in_atomic_block
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_user,current_setting('osidb.acl')")
        assert cursor.fetchone() == (runtime, acl)
    assert not Flaw.objects.filter(pk=hidden.pk).exists()
    assert not any(
        "SET ROLE" in statement.upper()
        or "SET SESSION AUTHORIZATION" in statement.upper()
        for statement in statements
    )


@pytest.mark.enable_rls
def test_task_retries_after_committed_batch_and_restores_acl():
    set_user_acls(settings.ALL_GROUPS)
    flaw = FlawFactory(embargoed=True)
    head = latest_event(flaw)
    victims = FlawChangeEvent.objects.bulk_create(
        [
            FlawChangeEvent(
                flaw=flaw,
                local_updated_dt=head.local_updated_dt - timedelta(days=i + 1),
            )
            for i in range(2)
        ]
    )
    set_user_acls(settings.PUBLIC_READ_GROUPS)
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_setting('osidb.acl')")
        acl = cursor.fetchone()[0]
    other = connection.copy()
    batches = 0
    committed = []

    def interrupt_once(execute, sql, params, many, context):
        nonlocal batches
        if "WITH victims AS MATERIALIZED" in sql:
            batches += 1
            if batches == 1:
                connection.on_commit(lambda: committed.append(True))
            if batches == 2:
                assert committed == [True]
                with other.cursor() as cursor:
                    cursor.execute(
                        "SELECT id FROM osidb_flawchangeevent WHERE id=%s",
                        [victims[0].pk],
                    )
                    assert cursor.fetchone() is None
                raise OperationalError("retry after committed prefix")
        return execute(sql, params, many, context)

    try:
        with connection.execute_wrapper(interrupt_once):
            result = compact_flaw_change_events.apply(
                kwargs={"batch_size": 1}, throw=False
            ).get()
        assert (
            result["deleted"] == 1
        )  # The successful retry accounts for its own batches.
        assert batches == 4
        assert FlawChangeEvent.objects.filter(flaw_id=flaw.pk).count() == 1
        assert latest_event(flaw).pk == head.pk
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_setting('osidb.acl')")
            assert cursor.fetchone()[0] == acl
        assert not Flaw.objects.filter(pk=flaw.pk).exists()
    finally:
        other.close()


def test_overlapping_pruners_and_real_source_writer_preserve_latest():
    flaw = FlawFactory()
    child = FlawCommentFactory(flaw=flaw)
    before = latest_event(flaw).local_updated_dt
    FlawChangeEvent.objects.bulk_create(
        [
            FlawChangeEvent(flaw=flaw, local_updated_dt=before - timedelta(days=i + 1))
            for i in range(200)
        ]
    )
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_setting('osidb.acl')")
        acl = cursor.fetchone()[0]

    def run(kind):
        connections.close_all()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('osidb.acl', %s, false)", [acl])
                cursor.execute("SET statement_timeout='10s'")
            if kind == "write":
                for i in range(10):
                    type(child).objects.filter(pk=child.pk).update(
                        text=f"concurrent {i}"
                    )
            else:
                return compact_change_events(batch_size=3)
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(run, kind) for kind in ["prune", "write", "prune"]]
        [future.result(timeout=30) for future in futures]
    after = latest_event(flaw).local_updated_dt
    assert after > before
    compact_change_events()
    assert FlawChangeEvent.objects.filter(flaw=flaw).count() == 1
    assert latest_event(flaw).local_updated_dt == after
