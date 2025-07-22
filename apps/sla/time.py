"""
custom time-related functions
"""

from django.utils.timezone import datetime, timedelta
from pytz import timezone

ONE_DAY = timedelta(days=1)


def add_days(dt: datetime, days: int) -> datetime:
    """
    add the given number of days to the given date
    """
    return dt + ONE_DAY * days


####################################################################
# the stuff below was originally defined in prodsec Python library #
# but was brought here to prevent the dependency to that old thing #
####################################################################

EASTERN = timezone("US/Eastern")
UTC = timezone("UTC")
WEEKEND = (6, 7)  # Sat, Sun


def is_business_day(day):
    """
    Returns True if the day is a working day for Red Hat in the USA.
    Returns False for weekends, holidays, or the end-of-year shutdown.

    Args:
      day (datetime or date): the day in question

    Returns:
      boolean: if the day is a working day or not
    """
    try:
        day = day.date()  # get date from datetime
    except AttributeError:
        pass  # is already a date

    return day.isoweekday() not in WEEKEND and not (
        (day.month == 1 and day.day == 1) or (day.month == 12 and day.day > 23)
    )


def business_timedelta(start, end=None):
    """
    Subtracts out US Red Hat non-working days (including Saturdays, Sundays,
    Holidays, and the end-of-year shutdown) to give a time delta only counting
    "business time".

    Args:
      start (datetime): the start time, usually when the "thing" happened. Naive
                        datetimes assumed to be in UTC.
      end (datetime): The later of the two. Defaults to datetime.datetime.utcnow().
                      Naive datetimes assumed to be in UTC.

    Returns:
      timedelta: A "business time" delta
    """
    if not end:
        end = datetime.utcnow()

    negative_mul = 1
    # if they're in the wrong order, just swap them, and mark negative
    if start > end:
        start, end = end, start
        negative_mul = -1  # makes negative

    # SIGH. We have to subtract out US non-working days right? Well that means we have to
    # localize to a US timezone first so that the 'non-working day' contains the 'right'
    # hours. The headquarters are in Raleigh, so we'll localize to eastern here.
    # Tell the naive incoming datetimes that they are utc.
    if not start.tzinfo:
        start = start.replace(tzinfo=UTC)

    if not end.tzinfo:
        end = end.replace(tzinfo=UTC)

    # And then localize into Eastern.
    start = start.astimezone(EASTERN)
    end = end.astimezone(EASTERN)

    end_cal = end.isocalendar()

    # simplifying assumption: if time and end are on the same day, just return the time diff
    if end_cal == start.isocalendar():
        if not is_business_day(start):
            return timedelta(0)
        else:
            return negative_mul * (end - start)

    # beginning boundary condition: if a ticket (or whatever) came in on the weekend, ignore
    # that day's time and only count actual business time later
    last_midnight = datetime(start.year, start.month, start.day)
    tomorrow_midnight = last_midnight + ONE_DAY
    tomorrow_midnight = EASTERN.localize(tomorrow_midnight)
    if not is_business_day(start):
        delta = timedelta(0)
    else:
        delta = tomorrow_midnight - start
    start = tomorrow_midnight

    # step through adding one day at a time until we arrive at the same day
    while end_cal > start.isocalendar():
        if is_business_day(start):
            delta += ONE_DAY
        start += ONE_DAY

    # ending boundary condition: if we're ending on a non-business day, don't include the
    # non-business time here either.
    if is_business_day(start):
        delta += end - start

    return negative_mul * delta


def add_business_days(dt, days):
    """
    Adds/subtract US Red Hat working business days to date (excludes Saturdays, Sundays,
    Holidays, and the end-of-year shutdown).

    Args:
        dt (date/datetime): the date. Naive datetimes assumed to be in UTC.
        days (int): business days to add or subtract (when negative)

    Returns:
      datetime: datetime with added/subtracted business days
    """
    # We have to localize to a US timezone first so that the 'non-working day' contains the 'right'
    # hours. The headquarters are in Raleigh, so we'll localize to eastern here.
    # Tell the naive incoming datetimes that they are utc.
    orig_tz = dt.tzinfo
    new_dt = dt
    if not orig_tz:
        new_dt = new_dt.replace(tzinfo=UTC)

    # And then localize into Eastern.
    new_dt = new_dt.astimezone(EASTERN)

    midnight = EASTERN.localize(datetime(new_dt.year, new_dt.month, new_dt.day))

    negative_mul = 1
    if days < 0:
        negative_mul = -1  # makes negative
        if not is_business_day(new_dt):
            # round down
            new_dt = midnight
    elif not is_business_day(new_dt):
        # round up
        new_dt = midnight + timedelta(days=1)
        if not is_business_day(new_dt):
            days += 1

    counted = 0
    while counted < abs(days):
        new_dt += negative_mul * ONE_DAY
        if is_business_day(new_dt):
            counted += 1

    if not orig_tz:
        new_dt = new_dt.astimezone(UTC).replace(tzinfo=None)
    else:
        new_dt = new_dt.astimezone(orig_tz)

    return new_dt


# as both weekend and also Friday are not considered suitable for
# risky operations we need to extend the definition beyond weekend
WEEK_ENDING = (5, 6, 7)  # Fri, Sat, Sun


def is_week_ending(day):
    """
    Returns True if the day is Friday, Saturday, Sunday.
    Returns False otherwise.

    Args:
      day (datetime or date): the day in question

    Returns:
      boolean: if the day is in the week ending
    """
    try:
        day = day.date()  # get date from datetime
    except AttributeError:
        pass  # is already a date

    return day.isoweekday() in WEEK_ENDING


def skip_week_ending(dt):
    """
    if the given date falls on Friday or weekend move it to the next Monday
    """
    while is_week_ending(dt):
        dt = add_days(dt, 1)

    return dt
