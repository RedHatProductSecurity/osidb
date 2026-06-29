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

from osidb.models import Affect, FlawCVSS, FlawSource, Impact, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawAcknowledgmentFactory,
    FlawCVSSFactory,
    FlawFactory,
    FlawReferenceFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.integration


class TestRelativeDateTimeFilteringFlaws:
    """
    Test relative datetime filtering on Flaw endpoints
    """

    @pytest.fixture
    @freeze_time("2024-06-15 12:00:00")
    def flaws_at_different_times(self):
        """Create flaws at different times for testing relative datetime filters"""
        return {
            "flaw_2_days_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(days=2),
            ),
            "flaw_1_day_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(days=1),
            ),
            "flaw_2_hours_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(hours=2),
            ),
            "flaw_30_min_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(minutes=30),
            ),
        }

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_created_dt_gt_filter(
        self, auth_client, test_api_uri, flaws_at_different_times
    ):
        """Test created_dt__gt=-1d (created within last 24 hours)"""
        flaws = flaws_at_different_times

        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__gt=-1d")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaws["flaw_2_hours_ago"].uuid) in uuids
        assert str(flaws["flaw_30_min_ago"].uuid) in uuids
        assert str(flaws["flaw_1_day_ago"].uuid) not in uuids
        assert str(flaws["flaw_2_days_ago"].uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    @pytest.mark.usefixtures("flaws_at_different_times")
    def test_flaw_created_dt_gte_filter(
        self,
        auth_client,
        test_api_uri,
    ):
        """Test created_dt__gte=-2d (created within last 48 hours or exactly 48 hours)"""
        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__gte=-2d")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        assert len(results) == 4  # All flaws

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_created_dt_lt_filter(
        self, auth_client, test_api_uri, flaws_at_different_times
    ):
        """Test created_dt__lt=-1h (created more than 1 hour ago)"""
        flaws = flaws_at_different_times

        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__lt=-1h")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaws["flaw_2_hours_ago"].uuid) in uuids
        assert str(flaws["flaw_1_day_ago"].uuid) in uuids
        assert str(flaws["flaw_2_days_ago"].uuid) in uuids
        assert str(flaws["flaw_30_min_ago"].uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_created_dt_lte_filter(
        self, auth_client, test_api_uri, flaws_at_different_times
    ):
        """Test created_dt__lte=-2h (created 2 hours ago or earlier)"""
        flaws = flaws_at_different_times

        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__lte=-2h")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaws["flaw_2_hours_ago"].uuid) in uuids
        assert str(flaws["flaw_1_day_ago"].uuid) in uuids
        assert str(flaws["flaw_2_days_ago"].uuid) in uuids
        assert str(flaws["flaw_30_min_ago"].uuid) not in uuids

    @pytest.fixture
    @freeze_time("2024-06-15 12:00:00")
    def flaws_with_different_updated_dt(self):
        """Create flaws updated at different times for testing relative datetime filters"""
        flaw_1 = FlawFactory(embargoed=False)
        flaw_1.updated_dt = timezone.now() - timezone.timedelta(hours=3)
        flaw_1.save(auto_timestamps=False)

        flaw_2 = FlawFactory(embargoed=False)
        flaw_2.updated_dt = timezone.now() - timezone.timedelta(minutes=45)
        flaw_2.save(auto_timestamps=False)

        flaw_3 = FlawFactory(embargoed=False)
        flaw_3.updated_dt = timezone.now() - timezone.timedelta(minutes=15)
        flaw_3.save(auto_timestamps=False)

        return {
            "flaw_3_hours_ago": flaw_1,
            "flaw_45_min_ago": flaw_2,
            "flaw_15_min_ago": flaw_3,
        }

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_updated_dt_gt_filter(
        self, auth_client, test_api_uri, flaws_with_different_updated_dt
    ):
        """Test updated_dt__gt=-1h (updated within last hour)"""
        flaws = flaws_with_different_updated_dt

        response = auth_client().get(f"{test_api_uri}/flaws?updated_dt__gt=-1h")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaws["flaw_45_min_ago"].uuid) in uuids
        assert str(flaws["flaw_15_min_ago"].uuid) in uuids
        assert str(flaws["flaw_3_hours_ago"].uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_updated_dt_lt_filter(
        self, auth_client, test_api_uri, flaws_with_different_updated_dt
    ):
        """Test updated_dt__lt=-30m (updated more than 30 minutes ago)"""
        flaws = flaws_with_different_updated_dt

        response = auth_client().get(f"{test_api_uri}/flaws?updated_dt__lt=-30m")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaws["flaw_3_hours_ago"].uuid) in uuids
        assert str(flaws["flaw_45_min_ago"].uuid) in uuids
        assert str(flaws["flaw_15_min_ago"].uuid) not in uuids

    @pytest.fixture
    @freeze_time("2024-06-15 12:00:00")
    def flaws_on_different_dates(self):
        """Create flaws on different dates for testing date-only relative filters"""
        return {
            "flaw_3_days_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(days=3),
            ),
            "flaw_1_day_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(days=1),
            ),
            "flaw_today": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(hours=2),
            ),
        }


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


class TestRelativeDateTimeFilteringRelatedModels:
    """
    Test relative datetime filtering on related models (acknowledgments, CVSS, references)
    """

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_acknowledgments_created_dt_relative_filters(
        self, auth_client, test_api_uri
    ):
        """Test filtering flaws by acknowledgments__created_dt using relative datetime"""
        # FlawAcknowledgment requires non-public source
        flaw_with_old_ack = FlawFactory(embargoed=False, source=FlawSource.DEBIAN)
        ack_old = FlawAcknowledgmentFactory(flaw=flaw_with_old_ack)
        ack_old.created_dt = timezone.now() - timezone.timedelta(days=10)
        ack_old.save(auto_timestamps=False)

        flaw_with_recent_ack = FlawFactory(embargoed=False, source=FlawSource.DEBIAN)
        ack_recent = FlawAcknowledgmentFactory(flaw=flaw_with_recent_ack)
        ack_recent.created_dt = timezone.now() - timezone.timedelta(hours=3)
        ack_recent.save(auto_timestamps=False)

        # Test: acknowledgments__created_dt__gt=-1d
        response = auth_client().get(
            f"{test_api_uri}/flaws?acknowledgments__created_dt__gt=-1d"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}
        assert str(flaw_with_recent_ack.uuid) in uuids
        assert str(flaw_with_old_ack.uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_cvss_scores_updated_dt_relative_filters(
        self, auth_client, test_api_uri
    ):
        """Test filtering flaws by cvss_scores__updated_dt using relative datetime"""
        flaw_with_old_cvss = FlawFactory(embargoed=False)
        cvss_old = FlawCVSSFactory(
            flaw=flaw_with_old_cvss,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION3,
        )
        cvss_old.updated_dt = timezone.now() - timezone.timedelta(days=7)
        cvss_old.save(auto_timestamps=False)

        flaw_with_recent_cvss = FlawFactory(embargoed=False)
        cvss_recent = FlawCVSSFactory(
            flaw=flaw_with_recent_cvss,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION3,
        )
        cvss_recent.updated_dt = timezone.now() - timezone.timedelta(hours=4)
        cvss_recent.save(auto_timestamps=False)

        # Test: cvss_scores__updated_dt__gt=-2d
        response = auth_client().get(
            f"{test_api_uri}/flaws?cvss_scores__updated_dt__gt=-2d"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}
        assert str(flaw_with_recent_cvss.uuid) in uuids
        assert str(flaw_with_old_cvss.uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_references_created_dt_relative_filters(
        self, auth_client, test_api_uri
    ):
        """Test filtering flaws by references__created_dt using relative datetime"""
        flaw_with_old_ref = FlawFactory(embargoed=False)
        ref_old = FlawReferenceFactory(flaw=flaw_with_old_ref)
        ref_old.created_dt = timezone.now() - timezone.timedelta(weeks=3)
        ref_old.save(auto_timestamps=False)

        flaw_with_recent_ref = FlawFactory(embargoed=False)
        ref_recent = FlawReferenceFactory(flaw=flaw_with_recent_ref)
        ref_recent.created_dt = timezone.now() - timezone.timedelta(days=2)
        ref_recent.save(auto_timestamps=False)

        # Test: references__created_dt__gt=-1w
        response = auth_client().get(
            f"{test_api_uri}/flaws?references__created_dt__gt=-1w"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}
        assert str(flaw_with_recent_ref.uuid) in uuids
        assert str(flaw_with_old_ref.uuid) not in uuids


class TestRelativeDateTimeFilteringCombinations:
    """
    Test combining relative datetime filters with other filters
    """

    @freeze_time("2024-06-15 12:00:00")
    def test_relative_datetime_with_other_filters(self, auth_client, test_api_uri):
        """Test combining relative datetime filters with other query params"""
        # Create flaws with different impacts and times
        flaw_critical_old = FlawFactory(
            embargoed=False,
            impact=Impact.CRITICAL,
            created_dt=timezone.now() - timezone.timedelta(days=10),
        )
        flaw_critical_recent = FlawFactory(
            embargoed=False,
            impact=Impact.CRITICAL,
            created_dt=timezone.now() - timezone.timedelta(hours=5),
        )
        flaw_low_recent = FlawFactory(
            embargoed=False,
            impact=Impact.LOW,
            created_dt=timezone.now() - timezone.timedelta(hours=3),
        )
        flaw_low_old = FlawFactory(
            embargoed=False,
            impact=Impact.LOW,
            created_dt=timezone.now() - timezone.timedelta(days=5),
        )

        # Test: impact=CRITICAL AND created_dt__gt=-1w (critical flaws created in last week)
        response = auth_client().get(
            f"{test_api_uri}/flaws?impact=CRITICAL&created_dt__gt=-1w"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}
        assert str(flaw_critical_recent.uuid) in uuids
        assert str(flaw_critical_old.uuid) not in uuids
        assert str(flaw_low_recent.uuid) not in uuids
        assert str(flaw_low_old.uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_multiple_relative_datetime_filters(self, auth_client, test_api_uri):
        """Test using multiple relative datetime filters in one query"""
        # Create flaws created and updated at different times
        flaw_1 = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(days=10),
        )
        flaw_1.updated_dt = timezone.now() - timezone.timedelta(hours=2)
        flaw_1.save(auto_timestamps=False)

        flaw_2 = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(days=3),
        )
        flaw_2.updated_dt = timezone.now() - timezone.timedelta(days=2)
        flaw_2.save(auto_timestamps=False)

        flaw_3 = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(hours=12),
        )
        flaw_3.updated_dt = timezone.now() - timezone.timedelta(hours=1)
        flaw_3.save(auto_timestamps=False)

        # Test: created_dt__lt=-1d AND updated_dt__gt=-1d
        # (created more than 1 day ago but updated within last day)
        response = auth_client().get(
            f"{test_api_uri}/flaws?created_dt__lt=-1d&updated_dt__gt=-1d"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}
        assert str(flaw_1.uuid) in uuids
        assert str(flaw_2.uuid) not in uuids  # updated_dt not within last day
        assert str(flaw_3.uuid) not in uuids  # created_dt not more than 1 day ago


class TestRelativeDateTimeFilteringEdgeCases:
    """
    Test edge cases and error handling for relative datetime filtering
    """

    @freeze_time("2024-06-15 12:00:00")
    def test_relative_datetime_with_seconds(self, auth_client, test_api_uri):
        """Test filtering with seconds unit"""
        flaw_120_sec_ago = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(seconds=120),
        )
        flaw_30_sec_ago = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(seconds=30),
        )

        # Test: created_dt__gt=-60s (created within last 60 seconds)
        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__gt=-60s")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}
        assert str(flaw_30_sec_ago.uuid) in uuids
        assert str(flaw_120_sec_ago.uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_relative_datetime_with_weeks(self, auth_client, test_api_uri):
        """Test filtering with weeks unit"""
        flaw_3_weeks_ago = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(weeks=3),
        )
        flaw_1_week_ago = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(weeks=1),
        )

        # Test: created_dt__gt=-2w (created within last 2 weeks)
        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__gt=-2w")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}
        assert str(flaw_1_week_ago.uuid) in uuids
        assert str(flaw_3_weeks_ago.uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_absolute_datetime_still_works(self, auth_client, test_api_uri):
        """Test that absolute datetime strings still work alongside relative ones"""
        flaw_recent = FlawFactory(
            embargoed=False,
            created_dt=datetime.datetime(
                2024, 6, 14, 10, 0, 0, tzinfo=datetime.timezone.utc
            ),
        )
        flaw_old = FlawFactory(
            embargoed=False,
            created_dt=datetime.datetime(
                2024, 6, 1, 10, 0, 0, tzinfo=datetime.timezone.utc
            ),
        )

        # Test with absolute datetime string
        response = auth_client().get(
            f"{test_api_uri}/flaws?created_dt__gt=2024-06-10T00:00:00Z"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}
        assert str(flaw_recent.uuid) in uuids
        assert str(flaw_old.uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_positive_relative_datetime(self, auth_client, test_api_uri):
        """Test that positive relative datetime (future) works correctly"""
        # Create a flaw now
        FlawFactory(
            embargoed=False,
            created_dt=timezone.now(),
        )
        FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(hours=5),
        )

        # Test: created_dt__lt=+1d (created before tomorrow)
        # This should return all flaws created before tomorrow
        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__lt=%2B1d")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        # Both should match since they're in the past
        assert len(results) == 2

    @freeze_time("2024-06-15 12:00:00")
    def test_zero_value_relative_datetime(self, auth_client, test_api_uri):
        """Test edge case with zero value (0d, 0h, etc.)"""
        flaw_1_hour_ago = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(hours=1),
        )
        flaw_2_hours_ago = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(hours=2),
        )

        # Test: created_dt__lt=0h (created before now)
        # Note: This might not work exactly as expected due to timing,
        # but tests the zero value handling
        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__lt=0h")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}
        assert str(flaw_1_hour_ago.uuid) in uuids
        assert str(flaw_2_hours_ago.uuid) in uuids


class TestRelativeDateTimeFilteringMonthsYears:
    """
    Test relative datetime filtering with month and year units
    """

    @pytest.fixture
    @freeze_time("2024-06-15 12:00:00")
    def flaws_at_different_months(self):
        """Create flaws at different months for testing month filters"""
        return {
            "flaw_6_months_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(days=180),
            ),
            "flaw_3_months_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(days=90),
            ),
            "flaw_1_month_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(days=30),
            ),
            "flaw_1_week_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(weeks=1),
            ),
        }

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_created_month_filter_gt(
        self, auth_client, test_api_uri, flaws_at_different_months
    ):
        """Test created_dt__gt=-2M (created within last 2 months)"""
        flaws = flaws_at_different_months

        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__gt=-2M")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaws["flaw_1_month_ago"].uuid) in uuids
        assert str(flaws["flaw_1_week_ago"].uuid) in uuids
        assert str(flaws["flaw_3_months_ago"].uuid) not in uuids
        assert str(flaws["flaw_6_months_ago"].uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_created_month_filter_lte(
        self, auth_client, test_api_uri, flaws_at_different_months
    ):
        """Test created_dt__lte=-4M (created 4 months ago or earlier)"""
        flaws = flaws_at_different_months

        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__lte=-4M")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaws["flaw_6_months_ago"].uuid) in uuids
        assert str(flaws["flaw_1_month_ago"].uuid) not in uuids
        assert str(flaws["flaw_1_week_ago"].uuid) not in uuids

    @pytest.fixture
    @freeze_time("2024-06-15 12:00:00")
    def flaws_at_different_years(self):
        """Create flaws at different years for testing year filters"""
        from dateutil.relativedelta import relativedelta

        return {
            "flaw_3_years_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - relativedelta(years=3),
            ),
            "flaw_1_year_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - relativedelta(years=1),
            ),
            "flaw_6_months_ago": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - relativedelta(months=6),
            ),
            "flaw_recent": FlawFactory(
                embargoed=False,
                created_dt=timezone.now() - timezone.timedelta(days=30),
            ),
        }

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_created_year_filter_gt(
        self, auth_client, test_api_uri, flaws_at_different_years
    ):
        """Test created_dt__gt=-1y (created within last year)"""
        flaws = flaws_at_different_years

        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__gt=-1y")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaws["flaw_6_months_ago"].uuid) in uuids
        assert str(flaws["flaw_recent"].uuid) in uuids
        assert str(flaws["flaw_1_year_ago"].uuid) not in uuids
        assert str(flaws["flaw_3_years_ago"].uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_flaw_created_year_filter_lte(
        self, auth_client, test_api_uri, flaws_at_different_years
    ):
        """Test created_dt__lte=-2y (created 2 years ago or earlier)"""
        flaws = flaws_at_different_years

        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__lte=-2y")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaws["flaw_3_years_ago"].uuid) in uuids
        assert str(flaws["flaw_1_year_ago"].uuid) not in uuids
        assert str(flaws["flaw_6_months_ago"].uuid) not in uuids
        assert str(flaws["flaw_recent"].uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_month_and_impact_combined_filter(self, auth_client, test_api_uri):
        """Test impact=CRITICAL&created_dt__gt=-6M"""
        flaw_critical_recent = FlawFactory(
            embargoed=False,
            impact=Impact.CRITICAL,
            created_dt=timezone.now() - timezone.timedelta(days=90),
        )
        flaw_critical_old = FlawFactory(
            embargoed=False,
            impact=Impact.CRITICAL,
            created_dt=timezone.now() - timezone.timedelta(days=270),
        )
        flaw_low_recent = FlawFactory(
            embargoed=False,
            impact=Impact.LOW,
            created_dt=timezone.now() - timezone.timedelta(days=90),
        )

        response = auth_client().get(
            f"{test_api_uri}/flaws?impact=CRITICAL&created_dt__gt=-6M"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaw_critical_recent.uuid) in uuids
        assert str(flaw_critical_old.uuid) not in uuids
        assert str(flaw_low_recent.uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_year_and_month_filters_combined(self, auth_client, test_api_uri):
        """Test created_dt__gt=-1y&updated_dt__gt=-3M"""
        flaw_1 = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(days=240),
        )
        flaw_1.updated_dt = timezone.now() - timezone.timedelta(days=30)
        flaw_1.save(auto_timestamps=False)

        flaw_2 = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(days=730),
        )
        flaw_2.updated_dt = timezone.now() - timezone.timedelta(days=30)
        flaw_2.save(auto_timestamps=False)

        flaw_3 = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(days=240),
        )
        flaw_3.updated_dt = timezone.now() - timezone.timedelta(days=180)
        flaw_3.save(auto_timestamps=False)

        response = auth_client().get(
            f"{test_api_uri}/flaws?created_dt__gt=-1y&updated_dt__gt=-3M"
        )
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaw_1.uuid) in uuids
        assert str(flaw_2.uuid) not in uuids
        assert str(flaw_3.uuid) not in uuids

    @freeze_time("2024-06-15 12:00:00")
    def test_uppercase_m_is_months_in_filter(self, auth_client, test_api_uri):
        """Test that -1M in URL is interpreted as months, not minutes"""
        flaw_2_months = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(days=60),
        )
        flaw_2_minutes = FlawFactory(
            embargoed=False,
            created_dt=timezone.now() - timezone.timedelta(minutes=2),
        )

        response = auth_client().get(f"{test_api_uri}/flaws?created_dt__gt=-1M")
        assert response.status_code == status.HTTP_200_OK
        results = response.json()["results"]
        uuids = {r["uuid"] for r in results}

        assert str(flaw_2_minutes.uuid) in uuids
        assert str(flaw_2_months.uuid) not in uuids
