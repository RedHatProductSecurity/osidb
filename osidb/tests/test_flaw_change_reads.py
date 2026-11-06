"""Read-source selection and bounded latest-state polling SQL."""

from collections import OrderedDict
from datetime import timedelta

import pytest
from django.test import override_settings
from django.utils import timezone

from osidb.djangoql import FlawQLSchema
from osidb.filters import FlawFilter, FlawV1Filter
from osidb.flaw_watermarks import flaw_timestamp_field, with_flaw_timestamp
from osidb.models import Flaw, FlawChangeEvent
from osidb.serializer import FlawSerializer, FlawV1Serializer
from osidb.tests.event_helpers import reset_events
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("filter_class", [FlawFilter, FlawV1Filter])
@pytest.mark.parametrize("bounds", ["both", "after", "before", "equal", "inverted"])
def test_candidate_semantics_and_sql(filter_class, bounds, settings):
    settings.OSIDB_USE_FLAW_WATERMARK = True
    inside, newer, older, missing = FlawFactory.create_batch(4)
    at = timezone.now().replace(minute=0, second=0, microsecond=0)
    reset_events([inside, newer], at)
    FlawChangeEvent.objects.create(flaw=newer, local_updated_dt=at + timedelta(hours=2))
    reset_events([older], at - timedelta(hours=2))
    FlawChangeEvent.objects.filter(flaw=missing).delete()
    params = {}
    expected = {
        "both": {inside.pk},
        "after": {inside.pk, newer.pk},
        "before": {inside.pk, older.pk},
        "equal": {inside.pk},
        "inverted": set(),
    }[bounds]
    if bounds in ("both", "after"):
        params["changed_after"] = (at - timedelta(hours=1)).isoformat()
    if bounds in ("both", "before"):
        params["changed_before"] = (at + timedelta(hours=1)).isoformat()
    if bounds == "equal":
        params = {"changed_after": at.isoformat(), "changed_before": at.isoformat()}
    if bounds == "inverted":
        params = {
            "changed_after": (at + timedelta(hours=1)).isoformat(),
            "changed_before": at.isoformat(),
        }
    filters = filter_class(params)
    assert filters.is_valid(), filters.errors
    assert set(filters.qs.values_list("pk", flat=True)) == expected
    assert "_change_updated_dt" not in filters.qs.query.annotation_select
    if bounds != "inverted":
        sql, _ = filters.qs.query.sql_with_params()
        assert "osidb_flawchangeevent" in sql
        assert "_change_updated_dt" not in sql
        assert "DESC LIMIT 1" not in sql
        if bounds != "before":
            assert "SELECT DISTINCT" in sql
        if bounds != "after":
            assert "NOT EXISTS" in sql


@pytest.mark.parametrize("filter_class", [FlawFilter, FlawV1Filter])
def test_bounds_use_cleaned_values_independent_of_method_order(filter_class, settings):
    settings.OSIDB_USE_FLAW_WATERMARK = True
    flaw = FlawFactory()
    at = timezone.now().replace(second=0, microsecond=0)
    reset_events([flaw], at)
    data = {
        "changed_after": (at - timedelta(minutes=1)).isoformat(),
        "changed_before": at.isoformat(),
    }
    filters = filter_class(data)
    assert filters.is_valid()
    filters.form.cleaned_data = OrderedDict(
        reversed(list(filters.form.cleaned_data.items()))
    )
    data["changed_before"] = "not-a-date"
    assert list(filters.qs.values_list("pk", flat=True)) == [flaw.pk]
    _, params = filters.qs.query.sql_with_params()
    assert "not-a-date" not in repr(params)
    assert at in params


def test_relative_bounds_and_v1_overlap_once(settings):
    settings.OSIDB_USE_FLAW_WATERMARK = True
    flaw = FlawFactory()
    reset_events([flaw], timezone.now() - timedelta(minutes=30))
    filters = FlawFilter({"changed_after": "-1h", "changed_before": "+1h"})
    assert filters.is_valid(), filters.errors
    assert list(filters.qs.values_list("pk", flat=True)) == [flaw.pk]
    assert not FlawFilter({"changed_before": "-1h"}).qs.exists()
    assert FlawV1Filter({"changed_before": "+1h"}).qs.exists()
    low = timezone.now().replace(second=0, microsecond=0)
    reset_events([flaw], low - timedelta(minutes=4))
    params = {"changed_after": low.isoformat(), "changed_before": low.isoformat()}
    assert FlawV1Filter(params).qs.exists()
    assert not FlawFilter(params).qs.exists()
    reset_events([flaw], low - timedelta(minutes=6))
    assert not FlawV1Filter(params).qs.exists()


@pytest.mark.parametrize("filter_class", [FlawFilter, FlawV1Filter])
def test_flag_off_preserves_exact_legacy_sql(filter_class, settings):
    settings.OSIDB_USE_FLAW_WATERMARK = False
    low, high = timezone.now() - timedelta(hours=1), timezone.now()
    filters = filter_class(
        {"changed_after": low.isoformat(), "changed_before": high.isoformat()}
    )
    assert filters.is_valid()
    expected_low = low - (
        timedelta(minutes=5) if filter_class is FlawV1Filter else timedelta()
    )
    expected = Flaw.objects.filter(local_updated_dt__gte=expected_low).filter(
        local_updated_dt__lte=high
    )
    assert filters.qs.query.sql_with_params() == expected.query.sql_with_params()
    assert (
        with_flaw_timestamp(expected).query.sql_with_params()
        == expected.query.sql_with_params()
    )
    assert flaw_timestamp_field() == "local_updated_dt"


def test_projection_selects_latest_timestamp_not_latest_insert(settings):
    settings.OSIDB_USE_FLAW_WATERMARK = True
    flaw = FlawFactory()
    at = timezone.now()
    reset_events([flaw], at)
    FlawChangeEvent.objects.create(flaw=flaw, local_updated_dt=at - timedelta(days=1))
    query = with_flaw_timestamp(Flaw.objects.all())
    assert query.values_list(flaw_timestamp_field(), flat=True).get() == at
    latest = query.query.annotations["_change_updated_dt"].query
    assert latest.order_by == ("-local_updated_dt", "-id")
    assert latest.high_mark == 1
    with override_settings(OSIDB_USE_FLAW_WATERMARK=False):
        assert flaw_timestamp_field() == "local_updated_dt"
    assert flaw_timestamp_field() == "_change_updated_dt"


def test_no_public_event_or_timestamp_surface():
    assert "change_events" not in FlawQLSchema(Flaw).get_fields(Flaw)
    for filter_class in (FlawFilter, FlawV1Filter):
        assert not any("change_events" in name for name in filter_class.base_filters)
        assert filter_class()._filter_fields(
            ["change_events", "change_events__local_updated_dt"]
        ) == (set(), set())
    for serializer_class in (FlawSerializer, FlawV1Serializer):
        assert "local_updated_dt" not in serializer_class.Meta.fields
        assert "change_events" not in serializer_class.Meta.fields
