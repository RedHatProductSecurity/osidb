from datetime import timedelta

import pytest
from django.conf import settings
from django.utils import timezone

from apps.stats.aggregation import DIMENSIONS
from osidb.core import set_user_acls
from osidb.models import Impact
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
)

pytestmark = pytest.mark.unit

STATS_URI: str = "http://osidb-service:8000/stats/api/v1beta/flaws"

# Standard OSIDB response envelope keys wrapped around every payload.
ENVELOPE_KEYS: set[str] = {"dt", "env", "revision", "version"}


def groups_by(body, *dimensions):
    """
    Map dimension value(s) to count. A single dimension yields scalar keys,
    multiple dimensions yield tuple keys.
    """
    counts = {}
    for group in body["groups"]:
        key = tuple(group[d] for d in dimensions)
        counts[key[0] if len(dimensions) == 1 else key] = group["count"]
    return counts


class TestStatsFlawsAuth:
    def test_unauthenticated_rejected(self, client):
        response = client.get(f"{STATS_URI}?group_by=impact")
        assert response.status_code == 401

    def test_authenticated_ok(self, auth_client):
        response = auth_client().get(f"{STATS_URI}?group_by=impact")
        assert response.status_code == 200


class TestStatsFlawsValidation:
    def test_group_by_required(self, auth_client):
        response = auth_client().get(STATS_URI)
        assert response.status_code == 400

    def test_unknown_dimension(self, auth_client):
        response = auth_client().get(f"{STATS_URI}?group_by=nonsense")
        assert response.status_code == 400

    @pytest.mark.parametrize("bounds", ["0,10", "30,7", "5,5", "abc"])
    def test_invalid_age_bucket_bounds(self, auth_client, bounds):
        response = auth_client().get(
            f"{STATS_URI}?group_by=age_bucket&age_bucket_bounds={bounds}"
        )
        assert response.status_code == 400


class TestStatsFlawsFlawLevel:
    def test_group_by_impact_additive(self, auth_client):
        FlawFactory(impact=Impact.LOW, embargoed=False)
        FlawFactory(impact=Impact.LOW, embargoed=False)
        FlawFactory(impact=Impact.IMPORTANT, embargoed=False)

        response = auth_client().get(f"{STATS_URI}?group_by=impact")
        assert response.status_code == 200
        body = response.json()

        counts = groups_by(body, "impact")
        assert counts[Impact.LOW] == 2
        assert counts[Impact.IMPORTANT] == 1
        assert body["meta"]["total_flaws"] == 3
        assert body["meta"]["sum_group_counts"] == 3
        assert body["meta"]["group_by"] == ["impact"]

    def test_group_by_multiple_dimensions(self, auth_client):
        FlawFactory(impact=Impact.LOW, workflow_state="NEW", embargoed=False)
        FlawFactory(impact=Impact.LOW, workflow_state="TRIAGE", embargoed=False)

        response = auth_client().get(f"{STATS_URI}?group_by=impact,workflow_state")
        assert response.status_code == 200
        body = response.json()

        counts = groups_by(body, "impact", "workflow_state")
        assert counts[(Impact.LOW, "NEW")] == 1
        assert counts[(Impact.LOW, "TRIAGE")] == 1
        assert body["meta"]["sum_group_counts"] == body["meta"]["total_flaws"] == 2


class TestStatsFlawsBuckets:
    def test_age_bucket_default_bounds(self, auth_client):
        now = timezone.now()
        FlawFactory(created_dt=now - timedelta(days=3), embargoed=False)
        FlawFactory(created_dt=now - timedelta(days=20), embargoed=False)
        FlawFactory(created_dt=now - timedelta(days=200), embargoed=False)

        response = auth_client().get(f"{STATS_URI}?group_by=age_bucket")
        assert response.status_code == 200
        body = response.json()

        counts = groups_by(body, "age_bucket")
        assert counts["0-7"] == 1
        assert counts["8-30"] == 1
        assert counts["91+"] == 1
        assert body["meta"]["age_bucket_bounds"] == [7, 30, 90]
        assert body["meta"]["sum_group_counts"] == body["meta"]["total_flaws"] == 3

    def test_age_bucket_custom_bounds(self, auth_client):
        now = timezone.now()
        FlawFactory(created_dt=now - timedelta(days=10), embargoed=False)
        FlawFactory(created_dt=now - timedelta(days=50), embargoed=False)

        response = auth_client().get(
            f"{STATS_URI}?group_by=age_bucket&age_bucket_bounds=30"
        )
        assert response.status_code == 200
        body = response.json()

        counts = groups_by(body, "age_bucket")
        assert counts["0-30"] == 1
        assert counts["31+"] == 1
        assert body["meta"]["age_bucket_bounds"] == [30]

    def test_embargo_duration_bucket(self, auth_client):
        now = timezone.now()
        # currently embargoed: duration = now - created_dt (~3 days)
        FlawFactory(
            embargoed=True,
            created_dt=now - timedelta(days=3),
            unembargo_dt=now + timedelta(days=10),
        )
        # lifted: duration = unembargo_dt - created_dt (~50 days)
        FlawFactory(
            embargoed=False,
            created_dt=now - timedelta(days=100),
            unembargo_dt=now - timedelta(days=50),
        )
        # public from creation: unembargo_dt == created_dt -> ~0 duration
        FlawFactory(
            embargoed=False,
            created_dt=now - timedelta(days=10),
            unembargo_dt=now - timedelta(days=10),
        )

        response = auth_client().get(f"{STATS_URI}?group_by=embargo_duration_bucket")
        assert response.status_code == 200
        body = response.json()

        counts = groups_by(body, "embargo_duration_bucket")
        # the embargoed (~3d) and public-from-creation (~0d) flaws share "0-7"
        assert counts["0-7"] == 2
        assert counts["31-90"] == 1
        assert body["meta"]["sum_group_counts"] == body["meta"]["total_flaws"] == 3


class TestStatsFlawsPsProduct:
    def test_ps_product_fanout(self, auth_client):
        product_a = PsProductFactory(short_name="prod-a")
        product_b = PsProductFactory(short_name="prod-b")
        module_a1 = PsModuleFactory(ps_product=product_a)
        module_a2 = PsModuleFactory(ps_product=product_a)
        module_b = PsModuleFactory(ps_product=product_b)
        stream_a1 = PsUpdateStreamFactory(ps_module=module_a1)
        stream_a2 = PsUpdateStreamFactory(ps_module=module_a2)
        stream_b = PsUpdateStreamFactory(ps_module=module_b)

        # flaw spanning two products fans out into both groups
        flaw_span = FlawFactory(embargoed=False)
        AffectFactory(
            flaw=flaw_span,
            ps_module=module_a1.name,
            ps_update_stream=stream_a1.name,
            ps_component="c1",
        )
        AffectFactory(
            flaw=flaw_span,
            ps_module=module_b.name,
            ps_update_stream=stream_b.name,
            ps_component="c2",
        )

        # flaw in two modules of the same product counted once
        flaw_same = FlawFactory(embargoed=False)
        AffectFactory(
            flaw=flaw_same,
            ps_module=module_a1.name,
            ps_update_stream=stream_a1.name,
            ps_component="c3",
        )
        AffectFactory(
            flaw=flaw_same,
            ps_module=module_a2.name,
            ps_update_stream=stream_a2.name,
            ps_component="c4",
        )

        response = auth_client().get(f"{STATS_URI}?group_by=ps_product")
        assert response.status_code == 200
        body = response.json()

        counts = groups_by(body, "ps_product")
        assert counts["prod-a"] == 2
        assert counts["prod-b"] == 1
        assert body["meta"]["total_flaws"] == 2
        assert body["meta"]["sum_group_counts"] == 3


class TestStatsFlawsFilters:
    def test_impact_in(self, auth_client):
        FlawFactory(impact=Impact.LOW, embargoed=False)
        FlawFactory(impact=Impact.IMPORTANT, embargoed=False)

        response = auth_client().get(
            f"{STATS_URI}?group_by=impact&impact__in={Impact.LOW}"
        )
        body = response.json()
        assert body["meta"]["total_flaws"] == 1
        assert body["meta"]["filters"]["impact__in"] == [Impact.LOW]

    def test_impact_not_in(self, auth_client):
        FlawFactory(impact=Impact.LOW, embargoed=False)
        FlawFactory(impact=Impact.IMPORTANT, embargoed=False)

        response = auth_client().get(
            f"{STATS_URI}?group_by=impact&impact__not_in={Impact.LOW}"
        )
        body = response.json()
        assert body["meta"]["total_flaws"] == 1
        counts = groups_by(body, "impact")
        assert Impact.LOW not in counts

    def test_ps_product_filter(self, auth_client):
        product = PsProductFactory(short_name="prod-x")
        module = PsModuleFactory(ps_product=product)
        stream = PsUpdateStreamFactory(ps_module=module)
        flaw = FlawFactory(embargoed=False)
        AffectFactory(
            flaw=flaw,
            ps_module=module.name,
            ps_update_stream=stream.name,
            ps_component="c1",
        )
        FlawFactory(embargoed=False)

        response = auth_client().get(
            f"{STATS_URI}?group_by=impact&ps_product__in=prod-x"
        )
        body = response.json()
        assert body["meta"]["total_flaws"] == 1

    def test_empty_filters_echoed_as_empty(self, auth_client):
        FlawFactory(embargoed=False)
        response = auth_client().get(f"{STATS_URI}?group_by=impact")
        body = response.json()
        assert body["meta"]["filters"] == {}


class TestStatsFlawsSafetyContract:
    def test_dimensions_allowlist_is_pinned(self):
        """
        Tripwire for the bypass_rls trust boundary. Every dimension is exposed
        to all authenticated users, embargoed flaws included, so the allowlist
        must contain only non-identifying, low-cardinality fields. If this test
        fails, a dimension was added or removed: confirm the new dimension
        cannot leak embargoed flaw identity (no cve_id/title/component/free text)
        before updating this set.
        """
        assert set(DIMENSIONS) == {
            "impact",
            "workflow_state",
            "workflow_name",
            "ps_product",
            "age_bucket",
            "embargo_duration_bucket",
        }


class TestStatsFlawsEmbargoExposure:
    @pytest.mark.enable_rls
    def test_embargoed_counts_exposed_without_flaw_details(self, auth_client):
        """
        A caller without embargo groups still receives embargoed aggregate
        counts (proving bypass_rls), and the response leaks no per-flaw data.
        """
        set_user_acls(settings.ALL_GROUPS)
        FlawFactory(embargoed=True, impact=Impact.CRITICAL)
        FlawFactory(embargoed=False, impact=Impact.LOW)

        # pubread lacks the embargo (data-topsecret) groups
        response = auth_client("pubread").get(f"{STATS_URI}?group_by=impact")
        assert response.status_code == 200
        body = response.json()

        assert body["meta"]["total_flaws"] == 2
        counts = groups_by(body, "impact")
        assert counts[Impact.CRITICAL] == 1

        # only aggregate payload is present, no per-flaw rows: pin the exact
        # top-level and meta keys so any new field (per-flaw or otherwise)
        # breaks this safety-contract test rather than silently leaking data
        assert set(body.keys()) == {"groups", "meta"} | ENVELOPE_KEYS
        assert set(body["meta"].keys()) == {
            "total_flaws",
            "sum_group_counts",
            "group_by",
            "filters",
            "generated_at",
        }
        assert body["groups"]
        for group in body["groups"]:
            assert set(group.keys()) == {"impact", "count"}
