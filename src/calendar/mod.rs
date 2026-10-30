//! The proleptic Gregorian calendar.
//!
//! A [`Date`] is a year, a month and a day that the calendar has: its
//! constructor checks the month, the day of the month (leap years included)
//! and the range of years, and its fields cannot be set otherwise. A date
//! converts to its number of days since 1970-01-01 and back, which is how
//! the times of the protocols (seconds since 1970) meet their dates.

mod date;

pub use date::Date;
