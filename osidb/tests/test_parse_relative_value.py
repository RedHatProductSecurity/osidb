"""
Unit tests for parse_relative_value helper function in osidb.forms
"""

from datetime import date, datetime, timedelta, timezone

import pytest
from dateutil.relativedelta import relativedelta
from django.utils import timezone as django_timezone
from freezegun import freeze_time

from osidb.forms import parse_relative_value

pytestmark = pytest.mark.unit


class TestParseRelativeValue:
    """
    Unit tests for the parse_relative_value helper function.
    This function is shared by both RelativeDateField and RelativeDateTimeField.
    """

    @freeze_time("2024-06-15 12:00:00")
    @pytest.mark.parametrize(
        "value,unit,expected_offset",
        [
            # Days
            ("+1d", "days", 1),
            ("-1d", "days", -1),
            ("-0d", "days", 0),
            ("-30d", "days", -30),
            # Weeks
            ("+1w", "weeks", 1),
            ("-1w", "weeks", -1),
            ("+2w", "weeks", 2),
            # Months
            ("+1M", "months", 1),
            ("-1M", "months", -1),
            ("-6M", "months", -6),
            # Years
            ("+1y", "years", 1),
            ("-1y", "years", -1),
            # Hours
            ("+1h", "hours", 1),
            ("-2h", "hours", -2),
            # Minutes
            ("+30m", "minutes", 30),
            ("-30m", "minutes", -30),
            # Seconds
            ("+10s", "seconds", 10),
            ("-30s", "seconds", -30),
        ],
    )
    def test_parse_various_units(self, value, unit, expected_offset):
        """Test parsing different time units with various offsets"""
        base = django_timezone.now()
        result = parse_relative_value(value, base)

        assert result is not None
        expected = base + relativedelta(**{unit: expected_offset})

        # Allow 1 second tolerance for execution time
        if isinstance(result, datetime):
            assert abs(result - expected) < timedelta(seconds=1)
        else:
            # For date comparisons
            assert result == expected.date()

    @freeze_time("2024-06-15 12:00:00")
    @pytest.mark.parametrize(
        "value,unit,expected_offset",
        [
            ("1d", "days", 1),  # Missing sign defaults to +
            ("5d", "days", 5),
            ("2w", "weeks", 2),
            ("1M", "months", 1),
            ("1y", "years", 1),
        ],
    )
    def test_default_positive_sign(self, value, unit, expected_offset):
        """Test that omitting the sign defaults to positive"""
        base = date(2024, 6, 15)
        result = parse_relative_value(value, base)

        assert result is not None
        expected = base + relativedelta(**{unit: expected_offset})
        assert result == expected

    def test_empty_value_returns_none(self):
        """Test that empty values return None"""
        base = django_timezone.now()

        assert parse_relative_value(None, base) is None
        assert parse_relative_value("", base) is None

    def test_large_relative_values(self):
        """Test that large relative values work correctly"""
        base = date(2024, 6, 15)

        # Test with 365 days
        result = parse_relative_value("-365d", base)
        expected = base - timedelta(days=365)
        assert result == expected

    def test_zero_value(self):
        """Test that 0 offset returns base value"""
        base = date(2024, 6, 15)

        result = parse_relative_value("0d", base)
        assert result == base

        result = parse_relative_value("0M", base)
        assert result == base

    @pytest.mark.parametrize(
        "value,expected",
        [
            (" -1d ", date(2024, 6, 14)),  # Leading and trailing whitespace
            ("- 1d", date(2024, 6, 14)),  # Whitespace after sign
            ("-1 d", date(2024, 6, 14)),  # Whitespace before unit
            (" + 5 w ", date(2024, 7, 20)),  # Multiple whitespace
        ],
    )
    def test_whitespace_handling(self, value, expected):
        """Test that whitespace is handled correctly"""
        base = date(2024, 6, 15)
        result = parse_relative_value(value, base)

        assert result == expected

    @pytest.mark.parametrize(
        "invalid_value",
        [
            "1.5d",  # Fractional values not supported
            "1x",  # Invalid unit
            "abc",  # Not a number
            "d1",  # Reversed format
            "--1d",  # Double negative
            "1D",  # Uppercase d (case-sensitive for m vs M)
            "",  # Empty string
        ],
    )
    def test_invalid_format_returns_none(self, invalid_value):
        """Test that invalid formats return None"""
        base = date(2024, 6, 15)
        result = parse_relative_value(invalid_value, base)
        assert result is None

    def test_case_sensitive_m_vs_capital_m(self):
        """Test that 'm' (minutes) and 'M' (months) are distinguished"""
        base = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

        # 'm' should be minutes
        result_minutes = parse_relative_value("-1m", base)
        expected_minutes = base - timedelta(minutes=1)
        assert abs(result_minutes - expected_minutes) < timedelta(seconds=1)

        # 'M' should be months
        result_months = parse_relative_value("-1M", base)

        expected_months = base + relativedelta(months=-1)
        assert abs(result_months - expected_months) < timedelta(seconds=1)

    def test_overflow_error_handling(self):
        """Test that extreme values that cause overflow return None"""
        base = date(2024, 6, 15)

        # Extremely large values that would cause OverflowError
        result = parse_relative_value("999999999999999999999d", base)
        assert result is None

        result = parse_relative_value("-999999999999999999999y", base)
        assert result is None

    @freeze_time("2024-01-31")
    def test_month_overflow_edge_case(self):
        """Test that adding months handles day overflow (e.g., Jan 31 + 1M)"""
        base = date(2024, 1, 31)

        # Adding 1 month to Jan 31 should give Feb 29 (2024 is a leap year)
        result = parse_relative_value("+1M", base)
        assert result == date(2024, 2, 29)

    def test_works_with_date_base(self):
        """Test that function works with date as base_value"""
        base = date(2024, 6, 15)
        result = parse_relative_value("-1d", base)

        assert isinstance(result, date)
        assert result == date(2024, 6, 14)

    def test_works_with_datetime_base(self):
        """Test that function works with datetime as base_value"""
        base = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = parse_relative_value("-1h", base)

        assert isinstance(result, datetime)
        expected = base - timedelta(hours=1)
        assert abs(result - expected) < timedelta(seconds=1)
