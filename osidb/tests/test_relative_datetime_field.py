"""
Unit tests for RelativeDateTimeField in osidb.forms
"""

from datetime import timedelta, timezone

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone as django_timezone
from freezegun import freeze_time

from osidb.forms import RelativeDateTimeField

pytestmark = pytest.mark.unit


class TestRelativeDateTimeField:
    """
    Unit tests for RelativeDateTimeField class
    """

    @pytest.mark.parametrize(
        "value,delta",
        [
            ("+1d", timedelta(days=1)),
            ("-30s", -timedelta(seconds=30)),
            ("-1w", -timedelta(weeks=1)),
            ("-30m", -timedelta(minutes=30)),
            ("-2h", -timedelta(hours=2)),
            ("-1d", -timedelta(days=1)),
            ("-0d", timedelta(days=0)),
        ],
    )
    def test_parse_relative_time_offset(self, value, delta):
        """Test that -1d is parsed to a datetime 1 day ago"""
        field = RelativeDateTimeField()

        result = field.to_python(value)

        # The datetime should be approximately 1 day ago
        expected_time = django_timezone.now() + delta

        # Allow 1 second tolerance for test execution time
        assert abs(result - expected_time) < timedelta(seconds=1)

    def test_parse_invalid_format_no_sign(self):
        """Test that missing sign but valid number returns datetime (defaults to +)"""
        # Note: Based on regex, this should actually work (sign is optional)
        field = RelativeDateTimeField()

        result = field.to_python("5h")
        # The datetime should be approximately 1 day ago
        expected_time = django_timezone.now() + timedelta(hours=5)

        # Allow 1 second tolerance for test execution time
        assert abs(result - expected_time) < timedelta(seconds=1)

    def test_fallback_to_absolute_datetime(self):
        """Test that absolute datetime strings are parsed correctly"""
        field = RelativeDateTimeField()

        # Use an absolute ISO datetime string
        absolute_datetime_str = "2024-01-15T10:30:00Z"

        result = field.to_python(absolute_datetime_str)

        # Should parse successfully as an absolute datetime
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 10
        assert result.minute == 30

    def test_default_positive_sign(self):
        """Test that omitting the sign defaults to positive (future)"""
        field = RelativeDateTimeField()

        # "1h" without sign should mean +1h (1 hour from now)
        result = field.to_python("1h")

        expected_time = django_timezone.now() + timedelta(hours=1)
        assert abs(result - expected_time) < timedelta(seconds=1)

    def test_empty_value_returns_none(self):
        """Test that empty values return None"""
        field = RelativeDateTimeField()

        # Test with None
        result = field.to_python(None)
        assert result is None

        # Test with empty string
        result = field.to_python("")
        assert result is None

    def test_required_field_with_empty_value(self):
        """Test that required field raises ValidationError for empty values"""
        field = RelativeDateTimeField(required=True)

        with pytest.raises(ValidationError):
            field.clean(None)

        with pytest.raises(ValidationError):
            field.clean("")

    def test_optional_field_with_empty_value(self):
        """Test that optional field accepts empty values"""
        field = RelativeDateTimeField(required=False)

        # Should not raise exception
        result = field.clean(None)
        assert result is None

        result = field.clean("")
        assert result is None

    def test_large_relative_values(self):
        """Test that large relative values work correctly"""
        field = RelativeDateTimeField()

        # Test with 365 days (1 year)
        result = field.to_python("-365d")

        expected_time = django_timezone.now() - timedelta(days=365)
        assert abs(result - expected_time) < timedelta(seconds=1)

    def test_zero_value_relative_time(self):
        """Test that 0d resolves to current time"""
        field = RelativeDateTimeField()

        result = field.to_python("0d")

        # 0 days should be very close to now
        expected_time = django_timezone.now()
        assert abs(result - expected_time) < timedelta(seconds=1)

    def test_leap_year_relative_values(self):
        """Test that leap year calculations work (366 days ago)"""
        field = RelativeDateTimeField()

        # Test with 366 days (leap year scenario)
        result = field.to_python("-366d")

        expected_time = django_timezone.now() - timedelta(days=366)
        assert abs(result - expected_time) < timedelta(seconds=1)

    @pytest.mark.parametrize(
        "invalid_value",
        [
            "1.5d",  # fractional values not supported
            "1x",  # invalid unit
            "abc",  # not a number
            "d1",  # reversed format
            "--1d",  # double negative
        ],
    )
    def test_invalid_format_falls_back_to_absolute(self, invalid_value):
        """Test that invalid relative formats fall back to absolute datetime parsing"""
        field = RelativeDateTimeField()
        # Should raise ValidationError from DateTimeField's parsing
        with pytest.raises(ValidationError):
            field.clean(invalid_value)

    def test_clean_method_with_relative_datetime(self):
        """Test that clean() method properly processes relative datetimes"""
        field = RelativeDateTimeField()

        result = field.clean("-1d")

        # Should return a datetime approximately 1 day ago
        expected_time = django_timezone.now() - timedelta(days=1)
        assert abs(result - expected_time) < timedelta(seconds=1)

    def test_clean_method_with_absolute_datetime(self):
        """Test that clean() method properly processes absolute datetimes"""
        field = RelativeDateTimeField()

        result = field.clean("2024-06-15T14:30:00Z")

        assert result is not None
        assert result.year == 2024
        assert result.month == 6
        assert result.day == 15

    @pytest.mark.parametrize(
        "value",
        [
            " -1d ",  # leading and trailing whitespace
            "- 1d",  # whitespace after sign
            "-1 d",  # whitespace before unit
        ],
    )
    def test_whitespace_handling(self, value):
        """Test that whitespace is handled correctly in relative datetimes"""
        field = RelativeDateTimeField()

        result = field.to_python(value)
        expected_time = django_timezone.now() - timedelta(days=1)

        assert abs(result - expected_time) < timedelta(seconds=1)

    def test_strptime_with_absolute_datetime(self):
        """Test that strptime works with absolute datetime strings"""
        field = RelativeDateTimeField()

        # Standard ISO format
        result = field.strptime("2024-06-15T14:30:00", "%Y-%m-%dT%H:%M:%S")

        assert result.year == 2024
        assert result.month == 6
        assert result.day == 15
        assert result.hour == 14
        assert result.minute == 30

    def test_strptime_with_relative_datetime(self):
        """Test that strptime falls back to relative parsing when format fails"""
        field = RelativeDateTimeField()

        # When strptime is called with a format that doesn't match,
        # it should fall back to relative datetime parsing
        result = field.strptime("-1d", "%Y-%m-%d")

        expected_time = django_timezone.now() - timedelta(days=1)
        assert abs(result - expected_time) < timedelta(seconds=1)

    @pytest.mark.parametrize(
        "value,delta",
        [
            ("-2h", timedelta(hours=-2)),
            ("+1w", timedelta(weeks=1)),
            ("-30m", timedelta(minutes=-30)),
            ("1d", timedelta(days=1)),
        ],
    )
    def test_strptime_with_various_relative_formats(self, value, delta):
        """Test that strptime handles various relative formats as fallback"""
        field = RelativeDateTimeField()

        # Test different relative formats with mismatched format string
        result = field.strptime(value, "%Y-%m-%d")

        expected_time = django_timezone.now() + delta

        assert abs(result - expected_time) < timedelta(seconds=1)

    def test_strptime_invalid_format_and_not_relative(self):
        """Test that strptime raises ValueError when neither format nor relative parse works"""
        field = RelativeDateTimeField()

        # Neither matches the format nor is a valid relative datetime
        with pytest.raises(ValueError):
            field.strptime("invalid-value", "%Y-%m-%d")

    def test_strptime_with_custom_format(self):
        """Test that strptime respects custom formats for absolute datetimes"""
        field = RelativeDateTimeField()

        # Custom format: DD/MM/YYYY
        result = field.strptime("15/06/2024", "%d/%m/%Y")

        assert result.year == 2024
        assert result.month == 6
        assert result.day == 15

    def test_strptime_called_internally_during_clean(self):
        """Test that strptime is called during field.clean() and handles relative datetimes"""
        field = RelativeDateTimeField(input_formats=["%Y-%m-%d"])

        # This should trigger strptime internally with the input format
        # When the format doesn't match, it should fall back to relative parsing
        result = field.clean("-1d")

        expected_time = django_timezone.now() - timedelta(days=1)
        assert abs(result - expected_time) < timedelta(seconds=1)

    @pytest.mark.parametrize("value", ["-1x", "d", "abc", "-1.5d"])
    def test_parse_invalid_format_none(self, value):
        field = RelativeDateTimeField()
        with pytest.raises(ValidationError):
            field.to_python(value)

    def test_parse_multiple_units_invalid(self):
        """Test that multiple units return None"""
        field = RelativeDateTimeField()
        with pytest.raises(ValidationError):
            field.to_python("-1d2h")

    @freeze_time("2024-06-15 12:00:00")
    def test_one_month_ago_datetime(self):
        """Test -1M returns datetime 1 month ago"""
        field = RelativeDateTimeField()
        result = field.to_python("-1M")
        expected = django_timezone.make_aware(
            django_timezone.datetime(2024, 5, 15, 12, 0, 0)
        )
        assert abs(result - expected) < timedelta(seconds=1)

    @freeze_time("2024-06-15 12:00:00")
    def test_one_year_ago_datetime(self):
        """Test -1y returns datetime 1 year ago"""
        field = RelativeDateTimeField()
        result = field.to_python("-1y")
        expected = django_timezone.make_aware(
            django_timezone.datetime(2023, 6, 15, 12, 0, 0)
        )
        assert abs(result - expected) < timedelta(seconds=1)

    @freeze_time("2024-01-31 12:00:00")
    def test_month_overflow_datetime_jan_to_feb(self):
        """Jan 31 12:00 + 1M should be Feb 29 12:00 (leap year)"""
        field = RelativeDateTimeField()
        result = field.to_python("+1M")
        expected = django_timezone.make_aware(
            django_timezone.datetime(2024, 2, 29, 12, 0, 0)
        )
        assert abs(result - expected) < timedelta(seconds=1)

    @freeze_time("2024-02-29 12:00:00")
    def test_leap_day_datetime_plus_year(self):
        """Feb 29, 2024 12:00 + 1y should be Feb 28, 2025 12:00"""
        field = RelativeDateTimeField()
        result = field.to_python("+1y")
        expected = django_timezone.make_aware(
            django_timezone.datetime(2025, 2, 28, 12, 0, 0)
        )
        assert abs(result - expected) < timedelta(seconds=1)

    @freeze_time("2024-06-15 14:30:00")
    def test_month_preserves_time(self):
        """Test that month arithmetic preserves time component"""
        field = RelativeDateTimeField()
        result = field.to_python("-3M")
        expected = django_timezone.make_aware(
            django_timezone.datetime(2024, 3, 15, 14, 30, 0)
        )
        assert abs(result - expected) < timedelta(seconds=1)

    @freeze_time("2024-12-31 23:59:59")
    def test_year_preserves_time_end_of_year(self):
        """Test that year arithmetic preserves time at year boundary"""
        field = RelativeDateTimeField()
        result = field.to_python("+1y")
        expected = django_timezone.make_aware(
            django_timezone.datetime(2025, 12, 31, 23, 59, 59)
        )
        assert abs(result - expected) < timedelta(seconds=1)

    @freeze_time("2024-06-15 12:00:00")
    def test_uppercase_m_is_months_not_minutes_datetime(self):
        """-1M should be 1 month ago, not 1 minute"""
        field = RelativeDateTimeField()
        result = field.to_python("-1M")
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
        field = RelativeDateTimeField()
        result = field.to_python("-1m")
        expected_minute = django_timezone.make_aware(
            django_timezone.datetime(2024, 6, 15, 11, 59, 0)
        )
        expected_month = django_timezone.make_aware(
            django_timezone.datetime(2024, 5, 15, 12, 0, 0)
        )
        # Should match minute calculation, not month
        assert abs(result - expected_minute) < timedelta(seconds=1)
        assert abs(result - expected_month) > timedelta(days=1)

    @pytest.mark.parametrize("value", ["-1d", "+2h", "-30m", "-1w", "+1s"])
    def test_timezone_aware(self, value):
        """Test that all returned datetimes are timezone-aware"""

        field = RelativeDateTimeField()
        result = field.to_python(value)
        assert result is not None
        assert result.tzinfo is not None
        # Should be UTC timezone since Django USE_TZ=True with UTC
        assert result.tzinfo == timezone.utc
