"""
Unit tests for RelativeDateTimeField in osidb.filters
"""

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone as django_timezone

from osidb.filters import RelativeDateTimeField

pytestmark = pytest.mark.unit


class TestRelativeDateTimeField:
    """
    Unit tests for RelativeDateTimeField class - Django integration only
    """

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

    def test_clean_method_with_absolute_datetime(self):
        """Test that clean() method properly processes absolute datetimes"""
        field = RelativeDateTimeField()

        result = field.clean("2024-06-15T14:30:00Z")

        assert result is not None
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

    def test_relative_datetime_parsing_integration(self):
        """Test basic relative datetime parsing through the field"""
        field = RelativeDateTimeField()

        result = field.clean("-1d")
        expected_time = django_timezone.now() - timedelta(days=1)

        assert abs(result - expected_time) < timedelta(seconds=1)

    def test_invalid_relative_format_raises_validation_error(self):
        """Test that invalid relative formats raise ValidationError"""
        field = RelativeDateTimeField()

        with pytest.raises(ValidationError):
            field.clean("invalid_format")
