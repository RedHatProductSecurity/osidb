"""
custom time-related functions tests
"""

import pytest
from django.utils.timezone import datetime, timedelta
from pytz import timezone

from apps.sla import time


@pytest.mark.parametrize(
    "dt,days,expected",
    [
        (datetime(2017, 8, 5, 15, 37, 55), 1, datetime(2017, 8, 6, 15, 37, 55)),
        (datetime(2017, 8, 5), 10, datetime(2017, 8, 15)),
        (datetime(2020, 1, 1, 10, 10, 10), 100, datetime(2020, 4, 10, 10, 10, 10)),
        (datetime(2020, 1, 1), -2, datetime(2019, 12, 30)),
    ],
)
def test_add_days(dt, days, expected):
    assert expected == time.add_days(dt, days)


####################################################################
# the stuff below was originally defined in prodsec Python library #
# but was brought here to prevent the dependency to that old thing #
####################################################################

UTC = timezone("UTC")
EASTERN = timezone("US/Eastern")
CET = timezone("Europe/Prague")


@pytest.mark.parametrize(
    "dt,expected",
    [
        (datetime(2017, 8, 5, 15, 37, 55), False),  # Saturday
        (datetime(2017, 8, 5), False),  # Saturday
        (datetime(2017, 8, 28, 15, 37, 55), True),  # Monday
        (datetime(2017, 8, 28), True),  # Monday
    ],
)
def test_is_business_day(dt, expected):
    is_business = time.is_business_day(dt)
    assert is_business is expected


@pytest.mark.parametrize(
    "dt, expected",
    [
        [datetime(2018, 1, 3), datetime(2018, 1, 4)],
        [
            UTC.localize(datetime(2018, 1, 3, 2)),
            UTC.localize(datetime(2018, 1, 4, 2)),
        ],
        [
            EASTERN.localize(datetime(2018, 1, 3)),
            EASTERN.localize(datetime(2018, 1, 4)),
        ],
        [
            CET.localize(datetime(2018, 1, 3)),
            CET.localize(datetime(2018, 1, 4)),
        ],
        # UTC midnight before weekend (Saturday UTC midnight is still Friday for Eastern)
        [datetime(2018, 1, 5), datetime(2018, 1, 6)],
        # Spanning weekend
        # noon
        [datetime(2018, 1, 5, 12), datetime(2018, 1, 8, 12)],
        [
            EASTERN.localize(datetime(2018, 1, 5, 12)),
            EASTERN.localize(datetime(2018, 1, 8, 12)),
        ],
        [
            CET.localize(datetime(2018, 1, 5, 12)),
            CET.localize(datetime(2018, 1, 8, 12)),
        ],
        # Starting on holiday
        # Eastern is 5 hours behind UTC
        [datetime(2017, 12, 24), datetime(2018, 1, 3, 5)],
        [
            UTC.localize(datetime(2017, 12, 24, 2)),
            UTC.localize(datetime(2018, 1, 3, 5)),
        ],
        [
            EASTERN.localize(datetime(2017, 12, 24)),
            EASTERN.localize(datetime(2018, 1, 3)),
        ],
        [
            CET.localize(datetime(2017, 12, 24)),
            CET.localize(datetime(2018, 1, 3, 6)),
        ],
    ],
)
def test_add_business_days(dt, expected):
    bdt = time.add_business_days(dt, days=1)
    assert bdt == expected
    assert time.business_timedelta(dt, bdt) == timedelta(days=1)


def test_add_business_days_through_weekend():
    dt = datetime(2018, 1, 15)
    bdt = time.add_business_days(dt, days=5)
    assert bdt == datetime(2018, 1, 22, 5)
    assert time.business_timedelta(dt, bdt) == timedelta(days=5)

    dt = datetime(2018, 1, 15, 5)
    bdt = time.add_business_days(dt, days=5)
    assert bdt == datetime(2018, 1, 22, 5)
    assert time.business_timedelta(dt, bdt) == timedelta(days=5)

    dt = datetime(2018, 1, 13, 0)
    bdt = time.add_business_days(dt, days=5)
    assert bdt == datetime(2018, 1, 20, 0)
    assert time.business_timedelta(dt, bdt) == timedelta(days=5)

    dt = datetime(2018, 1, 13, 5)
    bdt = time.add_business_days(dt, days=5)
    assert bdt == datetime(2018, 1, 22, 5)
    assert time.business_timedelta(dt, bdt) == timedelta(days=5)


@pytest.mark.parametrize(
    "dt, expected",
    [
        [datetime(2018, 1, 4), datetime(2018, 1, 3)],
        [
            UTC.localize(datetime(2018, 1, 4, 2)),
            UTC.localize(datetime(2018, 1, 3, 2)),
        ],
        [
            EASTERN.localize(datetime(2018, 1, 4)),
            EASTERN.localize(datetime(2018, 1, 3)),
        ],
        [
            CET.localize(datetime(2018, 1, 4)),
            CET.localize(datetime(2018, 1, 3)),
        ],
        # UTC midnight before weekend (Saturday UTC midnight is still Friday for Eastern)
        [datetime(2018, 1, 6), datetime(2018, 1, 5)],
        # Spanning weekend
        # noon
        [datetime(2018, 1, 8, 12), datetime(2018, 1, 5, 12)],
        [
            EASTERN.localize(datetime(2018, 1, 8, 12)),
            EASTERN.localize(datetime(2018, 1, 5, 12)),
        ],
        [
            CET.localize(datetime(2018, 1, 8, 12)),
            CET.localize(datetime(2018, 1, 5, 12)),
        ],
    ],
)
def test_subtract_business_days(dt, expected):
    bdt = time.add_business_days(dt, days=-1)
    assert bdt == expected
    assert time.business_timedelta(dt, bdt) == timedelta(days=-1)
