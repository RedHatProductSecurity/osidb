"""
Unit tests for datetime_utils module
"""

from datetime import timedelta

import pytest
from dateutil.relativedelta import relativedelta
from django.utils import timezone as django_timezone
from freezegun import freeze_time

from osidb.datetime_utils import parse_relative_datetime

pytestmark = pytest.mark.unit


class TestParseRelativeDatetime:
    """
    Unit tests for parse_relative_datetime function
    """

    @pytest.mark.parametrize(
        "value,delta",
        [
            pytest.param("+1d", timedelta(days=1), id="plus_one_day"),
            pytest.param("-30s", -timedelta(seconds=30), id="minus_thirty_seconds"),
            pytest.param("-1w", -timedelta(weeks=1), id="minus_one_week"),
            pytest.param("-30m", -timedelta(minutes=30), id="minus_thirty_minutes"),
            pytest.param("-2h", -timedelta(hours=2), id="minus_two_hours"),
            pytest.param("-1d", -timedelta(days=1), id="minus_one_day"),
            pytest.param("-0d", timedelta(days=0), id="zero_days"),
            pytest.param("1h", timedelta(hours=1), id="no_sign_defaults_positive"),
            pytest.param("-1M", relativedelta(months=-1), id="minus_one_month"),
            pytest.param("+1y", relativedelta(years=1), id="plus_one_year"),
        ],
    )
    def test_parse_relative_time_offset(self, value, delta):
        """Test that relative time offsets are parsed correctly"""
        base_time = django_timezone.now()
        result = parse_relative_datetime(value, base_time)

        expected_time = base_time + delta

        # Allow 1 second tolerance for test execution time
        assert abs(result - expected_time) < timedelta(seconds=1)

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(" -1d ", id="leading_and_trailing_whitespace"),
            pytest.param("- 1d", id="whitespace_after_sign"),
            pytest.param("-1 d", id="whitespace_before_unit"),
        ],
    )
    def test_whitespace_handling(self, value):
        """Test that whitespace is handled correctly in relative datetimes"""
        base_time = django_timezone.now()
        result = parse_relative_datetime(value, base_time)
        expected_time = base_time - timedelta(days=1)

        assert abs(result - expected_time) < timedelta(seconds=1)

    @freeze_time("2024-01-31 12:00:00")
    def test_month_overflow_datetime_jan_to_feb(self):
        """Jan 31 12:00 + 1M should be Feb 29 12:00 (leap year)"""
        base_time = django_timezone.now()
        result = parse_relative_datetime("+1M", base_time)
        expected = django_timezone.make_aware(
            django_timezone.datetime(2024, 2, 29, 12, 0, 0)
        )
        assert abs(result - expected) < timedelta(seconds=1)

    @freeze_time("2024-02-29 12:00:00")
    def test_leap_day_datetime_plus_year(self):
        """Feb 29, 2024 12:00 + 1y should be Feb 28, 2025 12:00"""
        base_time = django_timezone.now()
        result = parse_relative_datetime("+1y", base_time)
        expected = django_timezone.make_aware(
            django_timezone.datetime(2025, 2, 28, 12, 0, 0)
        )
        assert abs(result - expected) < timedelta(seconds=1)

    @freeze_time("2024-06-15 12:00:00")
    def test_uppercase_m_is_months_not_minutes_datetime(self):
        """-1M should be 1 month ago, not 1 minute"""
        base_time = django_timezone.now()
        result = parse_relative_datetime("-1M", base_time)
        expected_month = django_timezone.make_aware(
            django_timezone.datetime(2024, 5, 15, 12, 0, 0)
        )
        expected_minute = django_timezone.make_aware(
            django_timezone.datetime(2024, 6, 15, 11, 59, 0)
        )
        # Should match month calculation, not minute
        assert abs(result - expected_month) < timedelta(seconds=1)
        assert abs(result - expected_minute) > timedelta(minutes=1)

    @freeze_time("2024-06-15 12:00:00")
    def test_lowercase_m_is_minutes_not_months_datetime(self):
        """-1m should be 1 minute ago, not 1 month"""
        base_time = django_timezone.now()
        result = parse_relative_datetime("-1m", base_time)
        expected_minute = django_timezone.make_aware(
            django_timezone.datetime(2024, 6, 15, 11, 59, 0)
        )
        expected_month = django_timezone.make_aware(
            django_timezone.datetime(2024, 5, 15, 12, 0, 0)
        )
        # Should match minute calculation, not month
        assert abs(result - expected_minute) < timedelta(seconds=1)
        assert abs(result - expected_month) > timedelta(days=1)

    @pytest.mark.parametrize(
        "invalid_value",
        [
            pytest.param("999999999999999999999d", id="overflow_days"),
            pytest.param("-999999999999999999999y", id="overflow_years"),
            pytest.param("1.5d", id="fractional_days"),
            pytest.param("-1.5d", id="fractional_days_negative"),
            pytest.param("1x", id="invalid_unit_x"),
            pytest.param("-1x", id="invalid_unit_x_negative"),
            pytest.param("abc", id="not_a_number"),
            pytest.param("d", id="missing_number"),
            pytest.param("d1", id="reversed_format"),
            pytest.param("--1d", id="double_negative"),
            pytest.param("1D", id="uppercase_day_unit"),
            pytest.param("-1d2h", id="multiple_units"),
        ],
    )
    def test_invalid_relative_formats_return_none(self, invalid_value):
        """Test that invalid relative formats return None"""
        base_time = django_timezone.now()
        result = parse_relative_datetime(invalid_value, base_time)
        assert result is None

    def test_empty_value_returns_none(self):
        """Test that empty values return None"""
        base_time = django_timezone.now()
        assert parse_relative_datetime(None, base_time) is None
        assert parse_relative_datetime("", base_time) is None
