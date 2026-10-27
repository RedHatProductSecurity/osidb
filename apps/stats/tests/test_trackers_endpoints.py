import pytest

from apps.stats.aggregation import TRACKER_DIMENSIONS
from osidb.acls import ACL
from osidb.models import Affect, Flaw, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit

STATS_URI: str = "http://osidb-service:8000/stats/api/v1beta/trackers"

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


class TestStatsTrackersAuth:
    def test_unauthenticated_rejected(self, client):
        response = client.get(f"{STATS_URI}?group_by=ps_product")
        assert response.status_code == 401

    def test_authenticated_ok(self, auth_client):
        response = auth_client().get(f"{STATS_URI}?group_by=ps_product")
        assert response.status_code == 200


class TestStatsTrackersValidation:
    def test_group_by_required(self, auth_client):
        response = auth_client().get(STATS_URI)
        assert response.status_code == 400

    def test_unknown_dimension(self, auth_client):
        response = auth_client().get(f"{STATS_URI}?group_by=nonsense")
        assert response.status_code == 400


class TestStatsTrackersSafetyContract:
    def test_dimensions_allowlist_is_pinned(self):
        """
        Tripwire for the bypass_rls trust boundary. Every dimension is exposed
        to all authenticated users, embargoed flaws included, so the allowlist
        must contain only non-identifying, low-cardinality fields. If this test
        fails, a dimension was added or removed: confirm the new dimension
        cannot leak embargoed flaw identity (no cve_id/title/component/free text)
        before updating this set.
        """
        assert set(TRACKER_DIMENSIONS) == {
            "ps_product",
        }


class TestStatsTrackersFilters:
    def test_visibility_in(self, auth_client):
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(
            name="deep-stream", ps_module=ps_module
        )
        flaw = FlawFactory(
            cve_id="CVE-2020-12345",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        affect1 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component1",
        )
        affect2 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component2",
        )
        affect3 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component3",
        )
        TrackerFactory(
            embargoed=False,
            affects=[affect1],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        TrackerFactory(
            embargoed=False,
            affects=[affect2],
            acl_read=ACL.INTERNAL.uuid_read,
            acl_write=ACL.INTERNAL.uuid_write,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        TrackerFactory(
            embargoed=True,
            affects=[affect3],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        response = auth_client().get(
            f"{STATS_URI}?group_by=ps_product&visibility__in=INTERNAL"
        )
        body = response.json()
        assert body["meta"]["total_trackers"] == 1

        response = auth_client().get(
            f"{STATS_URI}?group_by=ps_product&visibility__in=EMBARGOED"
        )
        body = response.json()
        assert body["meta"]["total_trackers"] == 1

        response = auth_client().get(
            f"{STATS_URI}?group_by=ps_product&visibility__in=PUBLIC"
        )
        body = response.json()
        assert body["meta"]["total_trackers"] == 1

    def test_visibility_not_in(self, auth_client):
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(
            name="deep-stream", ps_module=ps_module
        )
        flaw = FlawFactory(
            cve_id="CVE-2020-12345",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component",
        )
        TrackerFactory(
            embargoed=False,
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        TrackerFactory(
            embargoed=False,
            affects=[affect],
            acl_read=ACL.INTERNAL.uuid_read,
            acl_write=ACL.INTERNAL.uuid_write,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        TrackerFactory(
            embargoed=True,
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        response = auth_client().get(
            f"{STATS_URI}?group_by=ps_product&visibility__not_in=INTERNAL"
        )
        body = response.json()
        assert body["meta"]["total_trackers"] == 2

        response = auth_client().get(
            f"{STATS_URI}?group_by=ps_product&visibility__not_in=EMBARGOED"
        )
        body = response.json()
        assert body["meta"]["total_trackers"] == 2

        response = auth_client().get(
            f"{STATS_URI}?group_by=ps_product&visibility__not_in=PUBLIC"
        )
        body = response.json()
        assert body["meta"]["total_trackers"] == 2

    def test_ps_product_filter(self, auth_client):
        # tracker for prod x
        product = PsProductFactory(short_name="prod-x")
        modulex = PsModuleFactory(ps_product=product)
        ps_update_stream = PsUpdateStreamFactory(name="deep-streamx", ps_module=modulex)
        flaw = FlawFactory(
            cve_id="CVE-2020-12345",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component",
        )
        TrackerFactory(
            embargoed=False,
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[modulex.bts_name],
        )

        # tracker for prod y
        product = PsProductFactory(short_name="prod-y")
        moduley = PsModuleFactory(ps_product=product)
        ps_update_stream = PsUpdateStreamFactory(name="deep-streamy", ps_module=moduley)
        flaw = FlawFactory(
            cve_id="CVE-2020-12346",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component",
        )
        TrackerFactory(
            embargoed=False,
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[moduley.bts_name],
        )

        response = auth_client().get(
            f"{STATS_URI}?group_by=ps_product&ps_product__in=prod-x"
        )
        body = response.json()
        assert body["meta"]["total_trackers"] == 1

        response = auth_client().get(
            f"{STATS_URI}?group_by=ps_product&ps_product__in=prod-y"
        )
        body = response.json()
        assert body["meta"]["total_trackers"] == 1

        response = auth_client().get(
            f"{STATS_URI}?group_by=ps_product&ps_product__not_in=prod-x"
        )
        body = response.json()
        assert body["meta"]["total_trackers"] == 1

        response = auth_client().get(
            f"{STATS_URI}?group_by=ps_product&ps_product__not_in=prod-y"
        )
        body = response.json()
        assert body["meta"]["total_trackers"] == 1

    def test_empty_filters_echoed_as_empty(self, auth_client):
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(
            name="deep-stream", ps_module=ps_module
        )
        flaw = FlawFactory(
            cve_id="CVE-2020-12345",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component",
        )
        TrackerFactory(
            embargoed=False,
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        response = auth_client().get(f"{STATS_URI}?group_by=ps_product")
        body = response.json()
        assert body["meta"]["filters"] == {}


class TestStatsTrackersGroupings:
    def test_ps_product_grouping(self, auth_client):
        # tracker for prod x
        product = PsProductFactory(short_name="prod-x")
        modulex = PsModuleFactory(ps_product=product)
        ps_update_stream = PsUpdateStreamFactory(name="deep-streamx", ps_module=modulex)
        flaw = FlawFactory(
            cve_id="CVE-2020-12345",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component",
        )
        TrackerFactory(
            embargoed=False,
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[modulex.bts_name],
        )

        # tracker for prod y
        product = PsProductFactory(short_name="prod-y")
        moduley = PsModuleFactory(ps_product=product)
        ps_update_stream = PsUpdateStreamFactory(name="deep-streamy", ps_module=moduley)
        flaw = FlawFactory(
            cve_id="CVE-2020-12346",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component",
        )
        TrackerFactory(
            embargoed=False,
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[moduley.bts_name],
        )

        response = auth_client().get(f"{STATS_URI}?group_by=ps_product")
        body = response.json()
        assert body["meta"]["total_trackers"] == 2
        assert body["meta"]["sum_group_counts"] == 2
        assert groups_by(body, "ps_product") == {"prod-x": 1, "prod-y": 1}

    def test_multiple_affects_per_tracker(self, auth_client):
        # tracker for prod x
        product = PsProductFactory(short_name="prod-x")
        modulex = PsModuleFactory(ps_product=product)
        ps_update_stream = PsUpdateStreamFactory(name="deep-streamx", ps_module=modulex)
        flaw = FlawFactory(
            cve_id="CVE-2020-12345",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        flaw2 = FlawFactory(
            cve_id="CVE-2020-12346",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component",
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component",
        )
        TrackerFactory(
            embargoed=False,
            affects=[affect, affect2],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[modulex.bts_name],
        )

        # tracker for prod y
        product = PsProductFactory(short_name="prod-y")
        moduley = PsModuleFactory(ps_product=product)
        ps_update_stream = PsUpdateStreamFactory(name="deep-streamy", ps_module=moduley)
        flaw = FlawFactory(
            cve_id="CVE-2020-12347",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        flaw2 = FlawFactory(
            cve_id="CVE-2020-12348",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="serious flaw",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component",
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="large-component",
        )
        TrackerFactory(
            embargoed=False,
            affects=[affect, affect2],
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[moduley.bts_name],
        )

        response = auth_client().get(f"{STATS_URI}?group_by=ps_product")
        body = response.json()
        assert body["meta"]["total_trackers"] == 2
        assert body["meta"]["sum_group_counts"] == 2
        assert groups_by(body, "ps_product") == {"prod-x": 1, "prod-y": 1}
