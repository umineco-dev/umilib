use std::ptr;

use umilib::calendar::Date;
use umilib::ffi::calendar::*;

use super::Check;

#[test]
fn dates_are_checked() {
    let mut out = CDate { year: 0, month: 0, day: 0 };
    unsafe {
        Check::ok(umilib_calendar_date_new(2024, 2, 29, &mut out));
        assert_eq!(out, CDate { year: 2024, month: 2, day: 29 });
        Check::fails(umilib_calendar_date_new(2023, 2, 29, &mut out), "ffi", "InvalidArgument");
        Check::fails(umilib_calendar_date_new(Date::MAX_YEAR + 1, 1, 1, &mut out), "ffi", "InvalidArgument");
        Check::fails(umilib_calendar_date_new(2024, 1, 1, ptr::null_mut()), "ffi", "NullPointer");
        assert!(umilib_calendar_date_is_leap_year(2000));
        assert!(!umilib_calendar_date_is_leap_year(1900));
        assert_eq!(umilib_calendar_date_days_in_month(2024, 2), 29);
        assert_eq!(umilib_calendar_date_days_in_month(2024, 13), 0);
    }
}

#[test]
fn days_convert_both_ways() {
    let mut days = 0i64;
    let mut date = CDate { year: 0, month: 0, day: 0 };
    unsafe {
        Check::ok(umilib_calendar_date_days(CDate { year: 2000, month: 3, day: 1 }, &mut days));
        assert_eq!(days, 11_017);
        Check::fails(
            umilib_calendar_date_days(CDate { year: 2023, month: 4, day: 31 }, &mut days),
            "ffi",
            "InvalidArgument",
        );
        Check::ok(umilib_calendar_date_from_days(-1, &mut date));
        assert_eq!(date, CDate { year: 1969, month: 12, day: 31 });
        Check::fails(umilib_calendar_date_from_days(i64::MAX, &mut date), "ffi", "InvalidArgument");
    }
}
