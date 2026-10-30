"""Tests of umilib.calendar, against the rules of the Gregorian calendar and Python's datetime."""

import calendar
import datetime

import pytest

from umilib.calendar import Date
from umilib.ffi import FFIError

EPOCH = datetime.date(1970, 1, 1).toordinal()


def test_leap_years_follow_the_gregorian_rule():
    for year in range(1, 2501):
        assert Date.is_leap_year(year) == calendar.isleap(year), year
    assert Date.is_leap_year(0) and Date.is_leap_year(-400) and not Date.is_leap_year(-100)


def test_months_have_their_days():
    for year in (1900, 2000, 2023, 2024):
        for month in range(1, 13):
            assert Date.days_in_month(year, month) == calendar.monthrange(year, month)[1]
    assert Date.days_in_month(2024, 0) == 0 and Date.days_in_month(2024, 13) == 0


def test_dates_are_checked():
    assert Date(2024, 2, 29).day == 29
    for year, month, day in [(2023, 2, 29), (1900, 2, 29), (2023, 4, 31), (2023, 1, 0), (2023, 13, 1), (Date.MAX_YEAR + 1, 1, 1)]:
        with pytest.raises(FFIError) as error:
            Date(year, month, day)
        assert error.value.name == "InvalidArgument"
    with pytest.raises(OverflowError):
        Date(2024, 256, 1)


def test_days_agree_with_datetime():
    # Every 37th day of years 1 to 9999, which datetime covers.
    for ordinal in range(1, datetime.date.max.toordinal() + 1, 37):
        expected = datetime.date.fromordinal(ordinal)
        date = Date.from_days(ordinal - EPOCH)
        assert (date.year, date.month, date.day) == (expected.year, expected.month, expected.day)
        assert Date(expected.year, expected.month, expected.day).days() == ordinal - EPOCH


def test_range_ends():
    first, last = Date(Date.MIN_YEAR, 1, 1), Date(Date.MAX_YEAR, 12, 31)
    assert Date.from_days(first.days()) == first and Date.from_days(last.days()) == last
    for days in (first.days() - 1, last.days() + 1):
        with pytest.raises(FFIError):
            Date.from_days(days)


def test_dates_order():
    assert Date(-1, 12, 31) < Date(0, 1, 1) < Date(2024, 1, 31) < Date(2024, 2, 1)
