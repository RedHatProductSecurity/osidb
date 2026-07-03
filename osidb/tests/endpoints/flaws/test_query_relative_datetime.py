"""
Integration tests for DjangoQL relative datetime queries
"""

import datetime

import pytest
from freezegun import freeze_time

from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.integration


class TestRelativeDateTimeQueries:
    """Test DjangoQL queries with relative datetime formats"""

    @freeze_time("2024-06-15 12:00:00")
    @pytest.mark.parametrize(
        "test_api_uri", ["test_api_uri", "test_api_v2_uri"], indirect=True
    )
    def test_query_updated_dt_relative_days(
        self, auth_client, test_api_uri, flaws_at_different_update_times
    ):
        """Test query with relative days format"""
        query = 'updated_dt > "-2d"'
        response = auth_client().get(f"{test_api_uri}/flaws?query={query}")

        assert response.status_code == 200
        body = response.json()

        returned_uuids = {flaw["uuid"] for flaw in body["results"]}
        expected_uuids = {
            str(flaws_at_different_update_times["flaw_1_day_ago"].uuid),
            str(flaws_at_different_update_times["flaw_2_hours_ago"].uuid),
        }

        assert returned_uuids == expected_uuids

    @freeze_time("2024-06-15 12:00:00")
    @pytest.mark.parametrize(
        "test_api_uri", ["test_api_uri", "test_api_v2_uri"], indirect=True
    )
    def test_query_updated_dt_relative_hours(
        self, auth_client, test_api_uri, flaws_at_different_update_times
    ):
        """Test query with relative hours format"""
        query = 'updated_dt >= "-3h"'
        response = auth_client().get(f"{test_api_uri}/flaws?query={query}")

        assert response.status_code == 200
        body = response.json()

        returned_uuids = {flaw["uuid"] for flaw in body["results"]}
        expected_uuids = {
            str(flaws_at_different_update_times["flaw_2_hours_ago"].uuid),
        }

        assert returned_uuids == expected_uuids

    @freeze_time("2024-06-15 12:00:00")
    @pytest.mark.parametrize(
        "test_api_uri", ["test_api_uri", "test_api_v2_uri"], indirect=True
    )
    def test_query_updated_dt_relative_weeks(
        self, auth_client, test_api_uri, flaws_at_different_update_times
    ):
        """Test query with relative weeks format"""
        query = 'updated_dt > "-1w"'
        response = auth_client().get(f"{test_api_uri}/flaws?query={query}")

        assert response.status_code == 200
        body = response.json()

        # All test flaws are within the past week
        assert body["count"] == 3

    @freeze_time("2024-06-15 12:00:00")
    @pytest.mark.parametrize(
        "test_api_uri", ["test_api_uri", "test_api_v2_uri"], indirect=True
    )
    def test_query_created_dt_absolute_format(self, auth_client, test_api_uri):
        """Test that absolute datetime formats still work"""
        flaw1 = FlawFactory(
            created_dt=datetime.datetime(2024, 6, 10, tzinfo=datetime.timezone.utc)
        )
        FlawFactory(
            created_dt=datetime.datetime(2024, 6, 1, tzinfo=datetime.timezone.utc)
        )

        query = 'created_dt > "2024-06-05"'
        response = auth_client().get(f"{test_api_uri}/flaws?query={query}")

        assert response.status_code == 200
        body = response.json()

        assert body["count"] == 1
        assert body["results"][0]["uuid"] == str(flaw1.uuid)

    @freeze_time("2024-06-15 12:00:00")
    @pytest.mark.parametrize(
        "test_api_uri", ["test_api_uri", "test_api_v2_uri"], indirect=True
    )
    def test_query_updated_dt_mixed_relative_and_absolute(
        self, auth_client, test_api_uri, flaws_at_different_update_times
    ):
        """Test query combining relative and absolute datetime formats"""
        query = 'updated_dt > "-4d" and updated_dt < "-12h"'
        response = auth_client().get(f"{test_api_uri}/flaws?query={query}")

        assert response.status_code == 200
        body = response.json()

        returned_uuids = {flaw["uuid"] for flaw in body["results"]}
        expected_uuids = {
            str(flaws_at_different_update_times["flaw_1_day_ago"].uuid),
            str(flaws_at_different_update_times["flaw_3_days_ago"].uuid),
        }

        assert returned_uuids == expected_uuids

    @freeze_time("2024-06-15 12:00:00")
    @pytest.mark.parametrize(
        "test_api_uri", ["test_api_uri", "test_api_v2_uri"], indirect=True
    )
    def test_query_updated_dt_no_sign_defaults_positive(
        self, auth_client, test_api_uri, flaws_at_different_update_times
    ):
        """Test that omitting sign defaults to positive (future)"""
        # All test flaws are in the past, so querying for future should return all
        query = 'updated_dt < "1d"'
        response = auth_client().get(f"{test_api_uri}/flaws?query={query}")

        assert response.status_code == 200
        body = response.json()

        # Should return all test flaws (they're all before tomorrow)
        assert body["count"] == 3
