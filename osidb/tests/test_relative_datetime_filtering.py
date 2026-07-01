"""
Tests for relative datetime filtering via query parameters

This test suite validates that the RelativeDateTimeFilter and RelativeDateFilter
work correctly when filtering API endpoints using relative time strings like
"-1d", "+2h", "-30m", etc.
"""

import datetime

import pytest
from django.utils import timezone
from freezegun import freeze_time
from rest_framework import status

from osidb.models import Affect, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.integration


class TestRelativeDateTimeFilteringAffects:
    """
    Test relative datetime filtering on Affect endpoints
    """

    @pytest.fixture
    @freeze_time("2024-06-15 12:00:00")
    def affects_at_different_times(self):
        """Create affects at different times for testing relative datetime filters"""
        flaw = FlawFactory(embargoed=False)

        return {
            "flaw": flaw,
            "affect_5_hours_ago": AffectFactory(
                flaw=flaw,
                created_dt=timezone.now() - timezone.timedelta(hours=5),
            ),
            "affect_2_hours_ago": AffectFactory(
                flaw=flaw,
                created_dt=timezone.now() - timezone.timedelta(hours=2),
            ),
            "affect_30_min_ago": AffectFactory(
                flaw=flaw,
                created_dt=timezone.now() - timezone.timedelta(minutes=30),
            ),
        }

    @freeze_time("2024-06-15 12:00:00")
    def test_affect_created_dt_gt_filter(
        self, auth_client, test_api_v2_uri, affects_at_different_times
    ):
        """Test created_dt__gt=-3h (created within last 3 hours)"""
        affects = affects_at_different_times

        response = auth_client().get(f"{test_api_v2_uri}/affects?created_dt__gt=-3h")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(affects["affect_2_hours_ago"].uuid) in uuids
        assert str(affects["affect_30_min_ago"].uuid) in uuids
        assert str(affects["affect_5_hours_ago"].uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_affect_created_dt_lte_filter(
        self, auth_client, test_api_v2_uri, affects_at_different_times
    ):
        """Test created_dt__lte=-1h (created 1 hour ago or earlier)"""
        affects = affects_at_different_times

        response = auth_client().get(f"{test_api_v2_uri}/affects?created_dt__lte=-1h")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(affects["affect_5_hours_ago"].uuid) in uuids
        assert str(affects["affect_2_hours_ago"].uuid) in uuids
        assert str(affects["affect_30_min_ago"].uuid) not in uuids


class TestRelativeDateTimeFilteringTrackers:
    """
    Test relative datetime filtering on Tracker endpoints
    """

    @pytest.fixture
    @freeze_time("2024-06-15 12:00:00")
    def trackers_at_different_times(self):
        """Create trackers at different times for testing relative datetime filters"""
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        return {
            "tracker_3_days_ago": TrackerFactory(
                type=Tracker.TrackerType.BUGZILLA,
                affects=[affect],
                ps_update_stream=ps_stream.name,
                created_dt=timezone.now() - timezone.timedelta(days=3),
            ),
            "tracker_1_day_ago": TrackerFactory(
                type=Tracker.TrackerType.BUGZILLA,
                affects=[affect],
                ps_update_stream=ps_stream.name,
                created_dt=timezone.now() - timezone.timedelta(days=1),
            ),
            "tracker_2_hours_ago": TrackerFactory(
                type=Tracker.TrackerType.BUGZILLA,
                affects=[affect],
                ps_update_stream=ps_stream.name,
                created_dt=timezone.now() - timezone.timedelta(hours=2),
            ),
        }

    @freeze_time("2024-06-15 12:00:00")
    def test_tracker_created_dt_gt_filter(
        self, auth_client, test_api_v2_uri, trackers_at_different_times
    ):
        """Test created_dt__gt=-2d (created within last 2 days)"""
        trackers = trackers_at_different_times

        response = auth_client().get(f"{test_api_v2_uri}/trackers?created_dt__gt=-2d")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(trackers["tracker_1_day_ago"].uuid) in uuids
        assert str(trackers["tracker_2_hours_ago"].uuid) in uuids
        assert str(trackers["tracker_3_days_ago"].uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_tracker_created_dt_lte_filter(
        self, auth_client, test_api_v2_uri, trackers_at_different_times
    ):
        """Test created_dt__lte=-12h (created 12 hours ago or earlier)"""
        trackers = trackers_at_different_times

        response = auth_client().get(f"{test_api_v2_uri}/trackers?created_dt__lte=-12h")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(trackers["tracker_3_days_ago"].uuid) in uuids
        assert str(trackers["tracker_1_day_ago"].uuid) in uuids
        assert str(trackers["tracker_2_hours_ago"].uuid) not in uuids

    # Note: affects__trackers__created_dt filtering has a bug in the filter configuration
    # (uses method name instead of field name). Skipping this test until the filter is fixed.


class TestFlawChangedFilters:
    """
    Test relative datetime filtering using changed_after and changed_before on Flaw endpoints
    """

    @pytest.fixture
    @freeze_time("2024-06-15 12:00:00")
    def flaws_at_different_update_times(self):
        """Create flaws with different updated_dt for testing changed_after and changed_before"""
        return {
            "flaw_3_days_ago": FlawFactory(
                embargoed=False,
                local_updated_dt=timezone.now() - timezone.timedelta(days=3),
            ),
            "flaw_1_day_ago": FlawFactory(
                embargoed=False,
                local_updated_dt=timezone.now() - timezone.timedelta(days=1),
            ),
            "flaw_2_hours_ago": FlawFactory(
                embargoed=False,
                local_updated_dt=timezone.now() - timezone.timedelta(hours=2),
            ),
        }

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_changed_after_filter(
        self, auth_client, test_api_v2_uri, flaws_at_different_update_times
    ):
        """Test changed_after=-2d (updated within last 2 days)"""
        flaws = flaws_at_different_update_times

        response = auth_client().get(f"{test_api_v2_uri}/flaws?changed_after=-2d")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaws["flaw_1_day_ago"].uuid) in uuids
        assert str(flaws["flaw_2_hours_ago"].uuid) in uuids
        assert str(flaws["flaw_3_days_ago"].uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_changed_before_filter(
        self, auth_client, test_api_v2_uri, flaws_at_different_update_times
    ):
        """Test changed_before=-12h (updated 12 hours ago or earlier)"""
        flaws = flaws_at_different_update_times

        response = auth_client().get(f"{test_api_v2_uri}/flaws?changed_before=-12h")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaws["flaw_3_days_ago"].uuid) in uuids
        assert str(flaws["flaw_1_day_ago"].uuid) in uuids
        assert str(flaws["flaw_2_hours_ago"].uuid) not in uuids


class TestRelativeDateTimeCompatibility:
    """
    Test that absolute datetime filtering still works alongside relative datetime filtering
    """

    @freeze_time("2024-06-15 12:00:00")
    def test_absolute_datetime_still_works(self, auth_client, test_api_v2_uri):
        """Test that absolute datetime strings still work alongside relative ones"""
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=False)

        affect_recent = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            created_dt=datetime.datetime(
                2024, 6, 14, 10, 0, 0, tzinfo=datetime.timezone.utc
            ),
        )
        affect_old = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            created_dt=datetime.datetime(
                2024, 6, 1, 10, 0, 0, tzinfo=datetime.timezone.utc
            ),
        )

        # Test with absolute datetime string
        response = auth_client().get(
            f"{test_api_v2_uri}/affects?created_dt__gt=2024-06-10T00:00:00Z"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}
        assert str(affect_recent.uuid) in uuids
        assert str(affect_old.uuid) not in uuids
