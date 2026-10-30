# `umilib::calendar`

The proleptic Gregorian calendar. Feature: `calendar` (no dependencies).

| Item | Purpose |
| --- | --- |
| `Date` | A year, a month (1 to 12) and a day of that month. Every `Date` is a day of the calendar: `Date::new` checks it, and the fields are only read through `year()`, `month()` and `day()`. Dates order as they follow each other. |
| `Date::days`, `Date::from_days` | The number of days since 1970-01-01 (negative before it), and the date of such a number. |
| `Date::is_leap_year`, `Date::days_in_month` | The rules of the calendar: a leap year is a multiple of 4 that is not a multiple of 100, or a multiple of 400; `days_in_month` is 0 for a month not 1 to 12. |
| `Date::MIN_YEAR`, `Date::MAX_YEAR`, `Date::MIN`, `Date::MAX`, `Date::EPOCH` | The range of years (±999,999,999,999), its first and last dates, and 1970-01-01. |

```rust
use umilib::calendar::Date;

let date = Date::new(2024, 2, 29).expect("2024 is a leap year");
assert_eq!(date.days(), 19_782);
assert_eq!(Date::from_days(19_782), Some(date));
assert!(Date::new(2023, 2, 29).is_none());

// Seconds since 1970 to a date and a time of day.
let seconds: i64 = 1_709_210_096;
let date = Date::from_days(seconds.div_euclid(86_400)).expect("every i64 second count is of a date");
let time = seconds.rem_euclid(86_400);
```

The calendar is proleptic: it extends to every year, with a year 0 (1 BC) and
negative years before it, as ISO 8601 numbers them. The range of years holds
the day of every second count of `i64` since 1970, so a time of a protocol
always has a date; `from_days` returns `None` only beyond it.

The time of day, leap seconds and time zones are not part of a date. The
protocols add them: `MailDate`, `FTPTime`, `IMAPDateTime`, `ASN1Time` and
the RRSIG and trust-anchor times of DNS read and write their dates with
`Date`.

## C and Python

C passes a date as `umilib_calendar_Date` (`int64_t year; uint8_t month;
uint8_t day`). C can write any fields, so every function that takes one
checks it and fails with `InvalidArgument` if it is not a date:
`umilib_calendar_date_new`, `_is_leap_year`, `_days_in_month`, `_days`,
`_from_days`.

Python's `umilib.calendar.Date` is a frozen dataclass that checks itself
when made (`FFIError` with `InvalidArgument`, or `OverflowError` for a month
or day beyond 255), with `days()`, `Date.from_days(days)`,
`Date.is_leap_year(year)` and `Date.days_in_month(year, month)`.
`Date.MIN_YEAR` and `Date.MAX_YEAR` repeat the Rust constants.
