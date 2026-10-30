//! The C ABI of [`crate::calendar`].
//!
//! Dates are passed as [`CDate`] (`umilib_calendar_Date`) structures. C can
//! write any fields into one, so every function that takes a date checks it
//! as [`Date::new`] does and fails with `InvalidArgument` if it is not a date.

use crate::calendar::Date;
use crate::ffi::{Definition, Module, Parameter, Pointer, Status, Type, Value};

/// The C form of a [`Date`].
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CDate {
    pub year: i64,
    pub month: u8,
    pub day: u8,
}

impl CDate {
    pub fn decode(self) -> Result<Date, &'static Status> {
        Date::new(self.year, self.month, self.day).ok_or(&Status::INVALID_ARGUMENT)
    }

    pub fn encode(date: Date) -> CDate {
        CDate { year: date.year(), month: date.month(), day: date.day() }
    }
}

impl Value for CDate {
    const TYPE: Type = Type::Named("umilib_calendar_Date");
}

crate::ffi_functions! {
    /// Writes the date of `day` of `month` (1 to 12) of `year` into `out`; fails if the
    /// calendar has no such day or the year is out of range.
    pub unsafe extern "C" fn umilib_calendar_date_new(year: i64, month: u8, day: u8, out: *mut CDate) -> *const Status {
        Status::from_result((|| {
            let date = CDate { year, month, day }.decode()?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, CDate::encode(date)) }
        })())
    }

    /// Returns whether `year` is a leap year.
    pub unsafe extern "C" fn umilib_calendar_date_is_leap_year(year: i64) -> bool {
        Date::is_leap_year(year)
    }

    /// Returns the number of days of `month` (1 to 12) in `year`, or 0 for other months.
    pub unsafe extern "C" fn umilib_calendar_date_days_in_month(year: i64, month: u8) -> u8 {
        Date::days_in_month(year, month)
    }

    /// Writes the number of days from 1970-01-01 to `date` (negative before it) into `out`.
    pub unsafe extern "C" fn umilib_calendar_date_days(date: CDate, out: *mut i64) -> *const Status {
        Status::from_result((|| {
            let date = date.decode()?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, date.days()) }
        })())
    }

    /// Writes the date `days` days after 1970-01-01 (before it if negative) into `out`;
    /// fails outside the first and the last date.
    pub unsafe extern "C" fn umilib_calendar_date_from_days(days: i64, out: *mut CDate) -> *const Status {
        Status::from_result((|| {
            let date = Date::from_days(days).ok_or(&Status::INVALID_ARGUMENT)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, CDate::encode(date)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "calendar",
    definitions: &[Definition::Structure {
        name: "umilib_calendar_Date",
        documentation: " A date of the proleptic Gregorian calendar: a year, a month of 1 to 12 and a day of the month.",
        fields: &[
            Parameter { name: "year", value: Type::I64 },
            Parameter { name: "month", value: Type::U8 },
            Parameter { name: "day", value: Type::U8 },
        ],
    }],
    functions: FUNCTIONS,
    modules: &[],
};
