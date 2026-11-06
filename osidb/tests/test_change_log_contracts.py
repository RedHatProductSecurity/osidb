"""Internal storage and unchanged public authorization/legacy writer contracts."""

import pgtrigger
import pytest
from django.conf import settings
from django.db import connection, models
from django.test.utils import isolate_apps
from rest_framework.test import APIClient

from osidb.core import set_user_acls
from osidb.djangoql import FlawQLSchema
from osidb.filters import AffectFilter, FlawFilter
from osidb.models import Flaw, FlawChangeEvent
from osidb.tests.event_helpers import latest_event
from osidb.tests.factories import FlawCommentFactory, FlawCVSSFactory, FlawFactory
from osidb.watermark_triggers import register_watermark_triggers

pytestmark = pytest.mark.unit


@pytest.mark.enable_rls
def test_internal_soft_relation_schema_parent_security_unchanged():
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM pg_proc WHERE proname LIKE 'osidb_prune_flaw_change_events%'"
        )
        assert cursor.fetchone() == (0,)
        cursor.execute(
            "SELECT contype FROM pg_constraint WHERE conrelid='osidb_flawchangeevent'::regclass AND contype='f'"
        )
        assert cursor.fetchall() == []
        constraints = connection.introspection.get_constraints(
            cursor, "osidb_flawchangeevent"
        )
        assert constraints["flaw_event_latest_idx"]["columns"] == [
            "flaw_id",
            "local_updated_dt",
            "id",
        ]
        assert constraints["flaw_event_time_idx"]["columns"] == [
            "local_updated_dt",
            "flaw_id",
        ]
        cursor.execute(
            "SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='osidb_flawchangeevent'::regclass"
        )
        assert cursor.fetchone() == (False, False)
        cursor.execute(
            "SELECT count(*) FROM pg_policy WHERE polrelid='osidb_flawchangeevent'::regclass"
        )
        assert cursor.fetchone() == (0,)
        cursor.execute(
            "SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='osidb_flaw'::regclass"
        )
        assert cursor.fetchone() == (True, True)
    relation = FlawChangeEvent._meta.get_field("flaw")
    assert (
        not relation.db_constraint
        and relation.remote_field.on_delete is models.DO_NOTHING
    )


@pytest.mark.enable_rls
@pytest.mark.parametrize("version", ["v1", "v2"])
def test_api_remains_flaw_rooted_and_internal_relation_not_exposed(version):
    set_user_acls(settings.ALL_GROUPS)
    public = FlawFactory(embargoed=False)
    hidden = FlawFactory(embargoed=True)
    assert latest_event(hidden)
    set_user_acls(settings.PUBLIC_READ_GROUPS)
    client = APIClient()
    base = f"/osidb/api/{version}/flaws"
    response = client.get(
        base, {"include_fields": "uuid,change_events.local_updated_dt"}
    )
    assert response.status_code == 200
    assert [row["uuid"] for row in response.json()["results"]] == [str(public.pk)]
    assert "change_events" not in response.json()["results"][0]
    assert client.get(f"{base}/{hidden.pk}").status_code == 404
    assert "change_events" not in FlawQLSchema(Flaw).get_fields(Flaw)
    assert FlawFilter()._filter_fields({"change_events__local_updated_dt"}) == (
        set(),
        set(),
    )
    assert FlawFilter()._filter_fields(
        {"affects__flaw__change_events__local_updated_dt"}
    ) == (set(), set())
    assert AffectFilter()._filter_fields({"flaw__change_events__local_updated_dt"}) == (
        set(),
        set(),
    )


@pytest.mark.enable_signals
def test_real_metadata_signal_still_updates_legacy_timestamp_without_extra_event():
    flaw = FlawFactory(embargoed=False)
    before = flaw.local_updated_dt
    count = FlawChangeEvent.objects.filter(flaw=flaw).count()
    FlawCommentFactory(flaw=flaw)
    flaw.refresh_from_db()
    assert flaw.local_updated_dt > before
    # The metadata signal's excluded-only parent update does not append twice.
    assert FlawChangeEvent.objects.filter(flaw=flaw).count() == count + 1


@pytest.mark.parametrize("excluded", [None, "future_json"])
@isolate_apps()
def test_future_business_fields_participate_by_default(excluded):
    class MetadataProbe(models.Model):
        flaw_id = models.UUIDField()
        future_text = models.TextField(db_column='future "text" column')
        future_json = models.JSONField()
        future_domain_dt = models.DateTimeField()
        future_visibility = models.GeneratedField(
            expression=models.Value("PUBLIC"),
            output_field=models.CharField(max_length=10),
            db_persist=True,
        )

        class Meta:
            app_label = "change_log_contracts"
            db_table = "change_log_metadata_probe"

    before = list(pgtrigger.registered())
    try:
        register_watermark_triggers(
            MetadataProbe, exclude=() if excluded is None else (excluded,)
        )
        triggers = [
            trigger
            for model, trigger in pgtrigger.registered()
            if model is MetadataProbe
        ]
        assert {str(trigger.operation) for trigger in triggers} == {
            "INSERT",
            "UPDATE",
            "DELETE",
        }
        update = next(
            trigger for trigger in triggers if trigger.operation == pgtrigger.Update
        )
        sql = update.compile(MetadataProbe).install_sql
        for name in [
            "future_text",
            "future_json",
            "future_domain_dt",
            "future_visibility",
        ]:
            column = MetadataProbe._meta.get_field(name).column
            quoted = '"' + column.replace('"', '""') + '"'
            if name == excluded:
                assert quoted not in sql
            else:
                assert f"o.{quoted} IS DISTINCT FROM n.{quoted}" in sql
    finally:
        for model, trigger in list(pgtrigger.registered()):
            if model is MetadataProbe:
                trigger.unregister(model)
    assert pgtrigger.registered() == before


@pytest.mark.enable_signals
def test_real_cvss_business_signal_and_dependent_flaw_save_remain_active():
    flaw = FlawFactory(embargoed=False)
    legacy_before = flaw.local_updated_dt
    event_before = latest_event(flaw).pk
    cvss = FlawCVSSFactory(
        flaw=flaw,
        issuer="NIST",
        version="V3",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        score=0,
    )
    cvss.refresh_from_db()
    flaw.refresh_from_db()
    assert cvss.score == 9.8  # populate_cvss_score actually ran.
    assert flaw.local_updated_dt > legacy_before  # Dependent full Flaw save remains.
    assert latest_event(flaw).pk > event_before
