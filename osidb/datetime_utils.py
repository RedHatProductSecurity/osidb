"""
Utility functions for parsing and handling date/time values
"""

import re

from dateutil.relativedelta import relativedelta

# Constants for relative date/datetime parsing
RELATIVE_TIME_UNIT_MAP = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
    "w": "weeks",
    "M": "months",
    "y": "years",
}

RELATIVE_DATETIME_REGEX = re.compile(r"^\s*([+-]?)\s*(\d+)\s*([smhdwMy])\s*$")


def parse_relative_datetime(value, base_value):
    """
    Parse relative date/datetime strings and return absolute value.

    Accepts relative time strings in the format: [+/-]<number><unit>
    where unit is one of: s (seconds), m (minutes), h (hours), d (days),
    w (weeks), M (months), y (years)

    Examples:
        -1d     -> 1 day ago from base_value
        +2h     -> 2 hours from base_value
        -30m    -> 30 minutes ago from base_value
        -6M     -> 6 months ago from base_value
         1y     -> 1 year from base_value
        -1w     -> 1 week ago from base_value
         1s     -> 1 second from base_value

    Args:
        value: String to parse as relative datetime
        base_value: Base date or datetime to calculate relative to

    Returns:
        Absolute date or datetime object if the value is a valid relative string,
        None otherwise (allowing fallback to absolute parsing)

    Notes:
        - Sign defaults to '+' if omitted (e.g., "1d" means "+1d")
        - Fractional values are not supported (e.g., "1.5d" will return None)
        - Whitespace is allowed but excessive whitespace may cause parsing to fail
        - Unit 'M' (uppercase) = months; 'm' (lowercase) = minutes
        - Month/year arithmetic uses calendar dates, not fixed durations
        - If target day doesn't exist (e.g., Jan 31 + 1M), uses last day
          of target month (Feb 28/29)
        - Uses relativedelta for all units for simplicity and consistency
    """
    if not value:
        return None

    match = RELATIVE_DATETIME_REGEX.match(str(value))
    if not match:
        return None

    sign, amount, unit = match.groups()
    amount = int(amount) if sign != "-" else -int(amount)

    # Case-sensitive lookup to distinguish 'm' (minutes) from 'M' (months)
    delta_unit = RELATIVE_TIME_UNIT_MAP.get(unit)
    if not delta_unit:
        return None

    delta_kwargs = {delta_unit: amount}
    try:
        return base_value + relativedelta(**delta_kwargs)
    except OverflowError:
        return None
