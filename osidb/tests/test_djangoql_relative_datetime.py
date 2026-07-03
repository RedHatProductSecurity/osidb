"""
Unit tests for RelativeDateTimeQLField in osidb.djangoql
"""

from datetime import datetime, timedelta

import pytest
from dateutil.relativedelta import relativedelta
from django.utils import timezone as django_timezone

from osidb.djangoql import RelativeDateTimeQLField

pytestmark = pytest.mark.unit


class TestRelativeDateTimeQLField:
    """
    Unit tests for RelativeDateTimeQLField class
    """

    @pytest.mark.parametrize(
        "value,expected",
        [
            pytest.param(
                "2024-06-15",
                datetime(2024, 6, 15, 0, 0, 0),
                id="date_only",
            ),
            pytest.param(
                "2024-06-15 14:30",
                datetime(2024, 6, 15, 14, 30, 0),
                id="datetime_no_seconds",
            ),
            pytest.param(
                "2024-06-15 14:30:45",
                datetime(2024, 6, 15, 14, 30, 45),
                id="datetime_with_seconds",
            ),
        ],
    )
    def test_get_lookup_value_with_absolute_formats(self, value, expected):
        """Test that absolute date/datetime strings are parsed correctly"""
        field = RelativeDateTimeQLField(model=None, name="test_field")
        result = field.get_lookup_value(value)
        expected_aware = django_timezone.make_aware(expected)

        assert result == expected_aware

    @pytest.mark.parametrize(
        "value,delta",
        [
            pytest.param("-1d", -timedelta(days=1), id="minus_one_day"),
            pytest.param("+2h", timedelta(hours=2), id="plus_two_hours"),
            pytest.param("1h", timedelta(hours=1), id="one_hour_no_sign"),
            pytest.param("-30m", -timedelta(minutes=30), id="minus_thirty_minutes"),
            pytest.param("-6M", relativedelta(months=-6), id="minus_six_months"),
            pytest.param("+1y", relativedelta(years=1), id="plus_one_year"),
        ],
    )
    def test_get_lookup_value_with_relative_formats(self, value, delta):
        """Test that relative datetime strings are parsed correctly"""
        field = RelativeDateTimeQLField(model=None, name="test_field")
        base_time = django_timezone.now()
        result = field.get_lookup_value(value)
        expected_time = base_time + delta

        # Allow 1 second tolerance for test execution time
        assert abs(result - expected_time) < timedelta(seconds=1)

    def test_get_lookup_value_with_empty_value(self):
        """Test that empty values return None"""
        field = RelativeDateTimeQLField(model=None, name="test_field")
        assert field.get_lookup_value(None) is None
        assert field.get_lookup_value("") is None

    def test_get_lookup_value_with_invalid_format_raises_value_error(self):
        """Test that invalid formats raise ValueError"""
        field = RelativeDateTimeQLField(model=None, name="test_field")
        with pytest.raises(ValueError):
            field.get_lookup_value("invalid_format")
