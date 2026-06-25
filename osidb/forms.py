"""
Custom form fields for OSIDB
"""

import re
from datetime import timedelta

from django import forms
from django.utils import timezone

# Module-level constants for relative date/datetime parsing
RELATIVE_TIME_UNIT_MAP = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
    "w": "weeks",
}

RELATIVE_DATETIME_REGEX = re.compile(
    r"^\s*([+-]?)\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE
)


def _parse_relative_value(value, base_value):
    """
    Parse relative date/datetime strings and return absolute value.

    Accepts relative time strings in the format: [+/-]<number><unit>
    where unit is one of: s (seconds), m (minutes), h (hours), d (days), w (weeks)

    Examples:
        -1d     -> 1 day ago from base_value
        +2h     -> 2 hours from base_value
        -30m    -> 30 minutes ago from base_value
        -1w     -> 1 week ago from base_value
        +1s     -> 1 second from base_value

    Args:
        value: String to parse as relative date/datetime
        base_value: Base date or datetime to calculate relative to

    Returns:
        Absolute date or datetime object if the value is a valid relative string,
        None otherwise (allowing fallback to absolute parsing)

    Notes:
        - Sign defaults to '+' if omitted (e.g., "1d" means "+1d")
        - Fractional values are not supported (e.g., "1.5d" will return None)
        - Whitespace is allowed but excessive whitespace may cause parsing to fail
    """
    if not value:
        return None

    match = RELATIVE_DATETIME_REGEX.match(str(value))
    if not match:
        return None

    sign, amount, unit = match.groups()
    amount = int(amount) if sign != "-" else -int(amount)
    delta_kwargs = {RELATIVE_TIME_UNIT_MAP[unit.lower()]: amount}
    return base_value + timedelta(**delta_kwargs)


class RelativeDateTimeField(forms.DateTimeField):
    """
    DateTimeField that accepts both absolute datetime values (default behavior)
    and relative datetime strings like "-1d", "+2h", "-30m", etc.

    Relative format: [+/-]<number><unit>
    where unit is one of: s (seconds), m (minutes), h (hours), d (days), w (weeks)

    Examples:
        -1d     -> 1 day ago
        +2h     -> 2 hours from now
        -30m    -> 30 minutes ago

    If the value doesn't match the relative format, it falls back to standard
    absolute datetime parsing.
    """

    def strptime(self, value, format):
        """
        Parse a datetime string using the given format.

        First tries standard strptime parsing with the given format.
        If that fails, attempts to parse as a relative datetime.
        This ensures relative datetimes work even when strptime is called directly.
        """
        try:
            return super().strptime(value, format)
        except (ValueError, TypeError):
            parsed = _parse_relative_value(value, timezone.now())
            if parsed is not None:
                return parsed
            raise
