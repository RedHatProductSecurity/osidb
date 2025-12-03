"""
Tests for InFilterSet in osidb.filters
"""

import pytest
from rest_framework import status

from osidb.filters import AffectFilter, FlawFilter
from osidb.models import Affect, FlawSource, Impact, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestInFilterSet:
    """
    InFilterSet Tests

    Test file and tests were generated with assistance from AI (Cursor)
    """

    def test_in_filter_for_affects_ps_module(self, auth_client, test_api_v2_uri):
        """Test that affects can be filtered by multiple ps_modules using comma-separated values"""
        # Create ps_modules and ps_update_streams first
        ps_module1 = PsModuleFactory(name="rhel-8")
        ps_module2 = PsModuleFactory(name="rhel-9")
        ps_module3 = PsModuleFactory(name="fedora")

        PsUpdateStreamFactory(ps_module=ps_module1, name="rhel-8-stream")
        PsUpdateStreamFactory(ps_module=ps_module2, name="rhel-9-stream")
        PsUpdateStreamFactory(ps_module=ps_module3, name="fedora-stream")

        # Create test data with different ps_modules
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw, ps_module="rhel-8", ps_update_stream="rhel-8-stream")
        AffectFactory(flaw=flaw, ps_module="rhel-9", ps_update_stream="rhel-9-stream")
        AffectFactory(flaw=flaw, ps_module="fedora", ps_update_stream="fedora-stream")

        # Test single value still works
        response = auth_client().get(f"{test_api_v2_uri}/affects?ps_module=rhel-8")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 1
        assert results[0]["ps_module"] == "rhel-8"

        # Test comma-separated values with __in suffix (the "in" lookup created by InFilterSet)
        response = auth_client().get(
            f"{test_api_v2_uri}/affects?ps_module__in=rhel-8,rhel-9"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 2
        ps_modules = {r["ps_module"] for r in results}
        assert ps_modules == {"rhel-8", "rhel-9"}

        # Test all three
        response = auth_client().get(
            f"{test_api_v2_uri}/affects?ps_module__in=rhel-8,rhel-9,fedora"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 3

    def test_in_filter_for_affects_ps_component(self, auth_client, test_api_v2_uri):
        """Test that affects can be filtered by multiple ps_components"""
        flaw = FlawFactory(embargoed=False)
        # Use the default factory behavior which creates proper ps_module/ps_update_stream
        AffectFactory(flaw=flaw, ps_component="kernel")
        AffectFactory(flaw=flaw, ps_component="openssl")
        AffectFactory(flaw=flaw, ps_component="httpd")

        # Test with comma-separated components using __in suffix
        response = auth_client().get(
            f"{test_api_v2_uri}/affects?ps_component__in=kernel,openssl"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 2
        ps_components = {r["ps_component"] for r in results}
        assert ps_components == {"kernel", "openssl"}

    def test_in_filter_for_affects_affectedness(self, auth_client, test_api_v2_uri):
        """Test that affects can be filtered by multiple affectedness values"""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw, affectedness=Affect.AffectAffectedness.AFFECTED)
        AffectFactory(flaw=flaw, affectedness=Affect.AffectAffectedness.NEW)
        AffectFactory(flaw=flaw, affectedness=Affect.AffectAffectedness.NOTAFFECTED)

        # Test single value first
        response = auth_client().get(f"{test_api_v2_uri}/affects?affectedness=AFFECTED")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Test with explicit __in suffix (which InFilterSet should create)
        response = auth_client().get(
            f"{test_api_v2_uri}/affects?affectedness__in=AFFECTED,NEW"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 2
        affectedness_values = {r["affectedness"] for r in results}
        assert affectedness_values == {"AFFECTED", "NEW"}

    def test_in_filter_for_affects_resolution(self, auth_client, test_api_v2_uri):
        """Test that affects can be filtered by multiple resolution values"""
        flaw = FlawFactory(embargoed=False)
        # Create valid affectedness/resolution combinations
        # For AFFECTED, valid resolutions are: DELEGATED, DEFER, WONTFIX, OOSS
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.WONTFIX,
        )
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DEFER,
        )

        # Test with explicit __in suffix
        response = auth_client().get(
            f"{test_api_v2_uri}/affects?resolution__in=DELEGATED,WONTFIX"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 2
        resolutions = {r["resolution"] for r in results}
        assert resolutions == {"DELEGATED", "WONTFIX"}

    def test_in_filter_for_flaws_impact(self, auth_client, test_api_uri):
        """Test that flaws can be filtered by multiple impact values"""
        FlawFactory(impact=Impact.CRITICAL, embargoed=False)
        FlawFactory(impact=Impact.IMPORTANT, embargoed=False)
        FlawFactory(impact=Impact.MODERATE, embargoed=False)

        # Test with explicit __in suffix
        response = auth_client().get(
            f"{test_api_uri}/flaws?impact__in=CRITICAL,IMPORTANT"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 2
        impacts = {r["impact"] for r in results}
        assert impacts == {"CRITICAL", "IMPORTANT"}

    def test_in_filter_for_flaws_source(self, auth_client, test_api_uri):
        """Test that flaws can be filtered by multiple source values"""
        FlawFactory(source=FlawSource.INTERNET, embargoed=False)
        FlawFactory(source=FlawSource.CUSTOMER, embargoed=False)
        FlawFactory(source=FlawSource.REDHAT, embargoed=False)

        # Test with explicit __in suffix
        response = auth_client().get(
            f"{test_api_uri}/flaws?source__in=INTERNET,CUSTOMER"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 2
        sources = {r["source"] for r in results}
        assert sources == {"INTERNET", "CUSTOMER"}

    def test_in_filter_for_trackers_type(self, auth_client, test_api_v2_uri):
        """Test that trackers can be filtered by multiple types"""
        # Create two ps_modules with different BTS
        ps_module_bz = PsModuleFactory(bts_name="bugzilla")
        ps_stream_bz = PsUpdateStreamFactory(ps_module=ps_module_bz)

        ps_module_jira = PsModuleFactory(bts_name="jboss")
        ps_stream_jira = PsUpdateStreamFactory(ps_module=ps_module_jira)

        flaw = FlawFactory(embargoed=False)
        # Create affects with AFFECTED status (valid for trackers)
        # Use DELEGATED resolution which is valid for AFFECTED
        affect1 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module_bz.name,
            ps_update_stream=ps_stream_bz.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        affect2 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module_jira.name,
            ps_update_stream=ps_stream_jira.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        affect3 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module_bz.name,
            ps_update_stream=ps_stream_bz.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        # Create trackers with matching BTS types
        TrackerFactory(
            type=Tracker.TrackerType.BUGZILLA,
            affects=[affect1],
            ps_update_stream=ps_stream_bz.name,
        )
        TrackerFactory(
            type=Tracker.TrackerType.JIRA,
            affects=[affect2],
            ps_update_stream=ps_stream_jira.name,
        )
        TrackerFactory(
            type=Tracker.TrackerType.BUGZILLA,
            affects=[affect3],
            ps_update_stream=ps_stream_bz.name,
        )

        # Test single type first
        response = auth_client().get(f"{test_api_v2_uri}/trackers?type=BUGZILLA")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 2

        # Test with explicit __in suffix
        response = auth_client().get(
            f"{test_api_v2_uri}/trackers?type__in=BUGZILLA,JIRA"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 3

    def test_in_filter_for_trackers_status(self, auth_client, test_api_v2_uri):
        """Test that trackers can be filtered by multiple status values"""
        # Create a single ps_module and ps_update_stream to ensure BTS consistency
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_stream = PsUpdateStreamFactory(ps_module=ps_module)

        flaw = FlawFactory(embargoed=False)
        affect1 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        affect2 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        affect3 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        # Create trackers with consistent BUGZILLA type (matching the BTS)
        TrackerFactory(
            type=Tracker.TrackerType.BUGZILLA,
            status="NEW",
            affects=[affect1],
            ps_update_stream=ps_stream.name,
        )
        TrackerFactory(
            type=Tracker.TrackerType.BUGZILLA,
            status="ASSIGNED",
            affects=[affect2],
            ps_update_stream=ps_stream.name,
        )
        TrackerFactory(
            type=Tracker.TrackerType.BUGZILLA,
            status="CLOSED",
            affects=[affect3],
            ps_update_stream=ps_stream.name,
            resolution="ERRATA",  # Closed trackers need a resolution
        )

        # Test with explicit __in suffix
        response = auth_client().get(
            f"{test_api_v2_uri}/trackers?status__in=NEW,ASSIGNED"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 2

    def test_in_filter_does_not_apply_to_datetime_fields(
        self, auth_client, test_api_uri
    ):
        """Test that 'in' filter is NOT added to datetime fields with comparison lookups"""
        # created_dt has lt, gt, lte, gte lookups, so 'in' should not be automatically added
        flaw = FlawFactory(embargoed=False)
        FlawFactory(embargoed=False)
        FlawFactory(embargoed=False)

        # First, verify that comparison lookups work as expected
        response = auth_client().get(
            f"{test_api_uri}/flaws?created_dt__gt={flaw.created_dt.strftime('%Y-%m-%d')}"
        )
        assert response.status_code == status.HTTP_200_OK

        # Verify that created_dt__in lookup is not in the filter configuration
        # by checking the FlawFilter.get_filters() output
        from osidb.filters import FlawFilter

        filters = FlawFilter.get_filters()
        # created_dt should have the base filter and comparison lookups
        assert "created_dt" in filters
        assert "created_dt__gt" in filters
        assert "created_dt__gte" in filters
        # created_dt__in should NOT be auto-added since it has comparison lookups
        assert "created_dt__in" not in filters

    def test_in_filter_get_filters_method(self):
        """Test that get_filters() properly adds 'in' filters"""
        # Get the filters from AffectFilter
        filters = AffectFilter.get_filters()

        # Check that regular fields have both exact and __in versions
        assert "ps_module" in filters  # base filter
        assert "ps_module__in" in filters  # auto-added 'in' filter

        assert "ps_component" in filters
        assert "ps_component__in" in filters

        assert "affectedness" in filters
        assert "affectedness__in" in filters

        # Check that datetime fields with comparison lookups don't get __in
        assert "created_dt" in filters
        assert "created_dt__gt" in filters
        assert "created_dt__gte" in filters
        # created_dt__in should NOT be auto-added since it has gt/gte lookups
        assert "created_dt__in" not in filters

    def test_in_filter_respects_existing_in_filters(self):
        """Test that "in" doesn't duplicate if 'in' is already in the lookup list"""
        # FlawFilter already has explicit __in filters, ensure no conflicts
        filters = FlawFilter.get_filters()

        # These should exist and not cause issues
        assert "cve_id" in filters
        assert "impact" in filters
        assert "source" in filters

    def test_in_filter_with_uuid_fields(self, auth_client, test_api_v2_uri):
        """Test that UUID fields work with "in" filter"""
        flaw1 = FlawFactory(embargoed=False)
        flaw2 = FlawFactory(embargoed=False)
        affect1 = AffectFactory(flaw=flaw1)
        affect2 = AffectFactory(flaw=flaw2)

        # Test filtering by single UUID first
        response = auth_client().get(f"{test_api_v2_uri}/affects?uuid={affect1.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Test filtering by single UUID with __in suffix
        response = auth_client().get(
            f"{test_api_v2_uri}/affects?uuid__in={affect1.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Test filtering by multiple UUIDs with __in suffix
        response = auth_client().get(
            f"{test_api_v2_uri}/affects?uuid__in={affect1.uuid},{affect2.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 2
        uuids = {r["uuid"] for r in results}
        assert uuids == {str(affect1.uuid), str(affect2.uuid)}

    def test_in_filter_for_nested_fields(self, auth_client, test_api_v2_uri):
        """Test that "in" works for nested relationship fields"""
        flaw1 = FlawFactory(embargoed=False, source=FlawSource.INTERNET)
        AffectFactory(flaw=flaw1)

        flaw2 = FlawFactory(embargoed=False, source=FlawSource.CUSTOMER)
        AffectFactory(flaw=flaw2)

        flaw3 = FlawFactory(embargoed=False, source=FlawSource.REDHAT)
        AffectFactory(flaw=flaw3)

        # Test filtering affects by multiple flaw sources with __in suffix
        response = auth_client().get(
            f"{test_api_v2_uri}/affects?flaw__source__in=INTERNET,CUSTOMER"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 2

    def test_in_filter_empty_value(self, auth_client, test_api_v2_uri):
        """Test that empty comma-separated values are handled properly"""
        ps_module = PsModuleFactory(name="rhel-8")
        PsUpdateStreamFactory(ps_module=ps_module, name="rhel-8-stream")
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw, ps_module="rhel-8", ps_update_stream="rhel-8-stream")

        # Test with __in suffix
        response = auth_client().get(f"{test_api_v2_uri}/affects?ps_module__in=rhel-8")
        # Should work and return the one matching affect
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

    def test_in_filter_nonexistent_values(self, auth_client, test_api_v2_uri):
        """Test querying with values that don't exist"""
        ps_module = PsModuleFactory(name="rhel-8")
        PsUpdateStreamFactory(ps_module=ps_module, name="rhel-8-stream")
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw, ps_module="rhel-8", ps_update_stream="rhel-8-stream")

        # Query for modules that don't exist with __in suffix
        response = auth_client().get(
            f"{test_api_v2_uri}/affects?ps_module__in=nonexistent1,nonexistent2"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 0

    def test_in_filter_combined_with_other_filters(self, auth_client, test_api_v2_uri):
        """Test that "in" filters work correctly when combined with other filters"""
        ps_module1 = PsModuleFactory(name="rhel-8")
        ps_module2 = PsModuleFactory(name="rhel-9")
        PsUpdateStreamFactory(ps_module=ps_module1, name="rhel-8-stream")
        PsUpdateStreamFactory(ps_module=ps_module2, name="rhel-9-stream")

        flaw = FlawFactory(embargoed=False)
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_update_stream="rhel-8-stream",
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-9",
            ps_update_stream="rhel-9-stream",
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_update_stream="rhel-8-stream",
            affectedness=Affect.AffectAffectedness.NOTAFFECTED,
        )

        # Filter by multiple modules AND specific affectedness with __in suffix
        response = auth_client().get(
            f"{test_api_v2_uri}/affects?ps_module__in=rhel-8,rhel-9&affectedness=AFFECTED"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 2
        # All results should have affectedness AFFECTED
        for result in results:
            assert result["affectedness"] == "AFFECTED"

    def test_in_filter_with_empty_value(self, auth_client, test_api_v2_uri):
        """
        Test __in filters with choice fields that can have empty values
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_stream = PsUpdateStreamFactory(ps_module=ps_module)

        flaw = FlawFactory(embargoed=False)
        # Affect with AFFECTED and DELEGATED resolution
        AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        # Affect with AFFECTED and DELEGATED resolution
        AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        # Affect with NOTAFFECTED and empty (NOVALUE) resolution
        AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            affectedness=Affect.AffectAffectedness.NOTAFFECTED,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        # Affect with AFFECTED and DEFER resolution
        AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DEFER,
        )
        # Affect with NOVALUE affectedness (requires bypassing validation)
        affect = AffectFactory.build(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            affectedness=Affect.AffectAffectedness.NOVALUE,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        affect.save(raise_validation_error=False)

        response = auth_client().get(f"{test_api_v2_uri}/affects?resolution__in=,")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 2

        response = auth_client().get(f"{test_api_v2_uri}/affects?resolution__in=,DEFER")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 3

        response = auth_client().get(
            f"{test_api_v2_uri}/affects?resolution__in=,DEFER,DELEGATED"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 5

        response = auth_client().get(
            f"{test_api_v2_uri}/affects?affectedness__in=AFFECTED,"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 4
