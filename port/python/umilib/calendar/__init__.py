"""The proleptic Gregorian calendar. Mirrors ``umilib::calendar``.

A :class:`Date` is always a day of the calendar: making one checks the month,
the day of the month and the range of years, and raises
:class:`umilib.ffi.FFIError` (``InvalidArgument``) for any other, or
``OverflowError`` for a number the C type cannot hold. ``Date.MIN_YEAR`` and
``Date.MAX_YEAR`` repeat the constants of Rust, which the C ABI does not carry.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import ClassVar

from umilib.ffi import Library, Structures


@dataclass(frozen=True, order=True)
class Date:
    """A date of the proleptic Gregorian calendar; dates order as they follow each other."""

    C_TYPE: ClassVar[str] = "umilib_calendar_Date"
    MIN_YEAR: ClassVar[int] = -999_999_999_999
    MAX_YEAR: ClassVar[int] = 999_999_999_999

    year: int
    month: int
    day: int

    def __post_init__(self) -> None:
        library = Library.default()
        out = library.type(Date.C_TYPE)()
        library.call("umilib_calendar_date_new", self.year, self.month, self.day, ctypes.byref(out))

    @staticmethod
    def is_leap_year(year: int) -> bool:
        return bool(Library.default().function("umilib_calendar_date_is_leap_year")(year))

    @staticmethod
    def days_in_month(year: int, month: int) -> int:
        """The number of days of ``month`` (1 to 12) of ``year``, or 0 for other months."""
        return Library.default().function("umilib_calendar_date_days_in_month")(year, month)

    def days(self) -> int:
        """The number of days from 1970-01-01 to the date, negative before it."""
        return Library.default().value("umilib_calendar_date_days", ctypes.c_int64, Structures.to_structure(self))

    @classmethod
    def from_days(cls, days: int) -> Date:
        """The date ``days`` days after 1970-01-01 (before it if negative); raises
        ``InvalidArgument`` outside the first and the last date."""
        library = Library.default()
        out = library.type(Date.C_TYPE)()
        library.call("umilib_calendar_date_from_days", days, ctypes.byref(out))
        return Structures.from_structure(cls, out)


__all__ = ["Date"]
