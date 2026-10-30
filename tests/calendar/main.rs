//! Tests of `umilib::calendar`: the rules of the proleptic Gregorian calendar
//! (ISO 8601-1 §3.2.1 and §4.3.2.1) and day counts known from elsewhere.

use umilib::calendar::Date;

#[test]
fn leap_years_follow_the_gregorian_rule() {
    // Every fourth year, except centuries not divisible by 400; year 0 is 1 BC.
    for (year, leap) in [
        (2024, true),
        (2023, false),
        (2000, true),
        (1900, false),
        (2100, false),
        (2400, true),
        (0, true),
        (-4, true),
        (-1, false),
        (-100, false),
        (-400, true),
    ] {
        assert_eq!(Date::is_leap_year(year), leap, "{year}");
    }
}

#[test]
fn months_have_their_days() {
    let days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for (month, days) in (1..=12).zip(days) {
        assert_eq!(Date::days_in_month(2023, month), days, "month {month}");
    }
    assert_eq!(Date::days_in_month(2024, 2), 29);
    assert_eq!(Date::days_in_month(1900, 2), 28);
    assert_eq!(Date::days_in_month(2024, 0), 0);
    assert_eq!(Date::days_in_month(2024, 13), 0);
}

#[test]
fn new_accepts_only_days_of_the_calendar() {
    let date = Date::new(2026, 10, 30).unwrap();
    assert_eq!((date.year(), date.month(), date.day()), (2026, 10, 30));
    assert!(Date::new(2024, 2, 29).is_some());
    assert!(Date::new(2000, 2, 29).is_some());
    assert!(Date::new(2023, 2, 29).is_none());
    assert!(Date::new(1900, 2, 29).is_none());
    assert!(Date::new(2023, 2, 31).is_none());
    assert!(Date::new(2023, 4, 31).is_none());
    assert!(Date::new(2023, 1, 0).is_none());
    assert!(Date::new(2023, 0, 1).is_none());
    assert!(Date::new(2023, 13, 1).is_none());
    assert!(Date::new(-1, 12, 31).is_some());
}

#[test]
fn new_accepts_only_years_in_range() {
    assert_eq!(Date::new(Date::MIN_YEAR, 1, 1), Some(Date::MIN));
    assert_eq!(Date::new(Date::MAX_YEAR, 12, 31), Some(Date::MAX));
    assert!(Date::new(Date::MIN_YEAR - 1, 12, 31).is_none());
    assert!(Date::new(Date::MAX_YEAR + 1, 1, 1).is_none());
    assert!(Date::new(i64::MIN, 1, 1).is_none());
    assert!(Date::new(i64::MAX, 1, 1).is_none());
}

#[test]
fn days_count_from_1970() {
    // POSIX time: 1970-01-01 is day 0; 2000-03-01 is 951868800 seconds;
    // 2^31 - 1 and 2^32 - 1 seconds are in 2038-01-19 and 2106-02-07.
    // Python's date.toordinal: 0001-01-01 is 1 and 1970-01-01 is 719163.
    for ((year, month, day), days) in [
        ((1970, 1, 1), 0),
        ((1969, 12, 31), -1),
        ((1970, 3, 1), 59),
        ((2000, 3, 1), 951_868_800 / 86_400),
        ((2038, 1, 19), 2_147_483_647 / 86_400),
        ((2106, 2, 7), 4_294_967_295 / 86_400),
        ((1, 1, 1), 1 - 719_163),
        ((0, 1, 1), 1 - 719_163 - 366),
        ((9999, 12, 31), 3_652_059 - 719_163),
    ] {
        let date = Date::new(year, month, day).unwrap();
        assert_eq!(date.days(), days, "{year}-{month}-{day}");
        assert_eq!(Date::from_days(days), Some(date), "{days}");
    }
    assert_eq!(Date::EPOCH.days(), 0);
}

#[test]
fn consecutive_days_are_consecutive_dates() {
    // Two eras of 400 years on each side of 1970, day by day: each date is
    // the day after the one before, as the months and leap years say.
    let start = -2 * 146_097;
    let mut previous = Date::from_days(start).unwrap();
    assert_eq!(previous.days(), start);
    for days in start + 1..=2 * 146_097 {
        let date = Date::from_days(days).unwrap();
        let expected = if previous.day() < Date::days_in_month(previous.year(), previous.month()) {
            Date::new(previous.year(), previous.month(), previous.day() + 1)
        } else if previous.month() < 12 {
            Date::new(previous.year(), previous.month() + 1, 1)
        } else {
            Date::new(previous.year() + 1, 1, 1)
        };
        assert_eq!(Some(date), expected, "{days}");
        assert_eq!(date.days(), days);
        assert!(previous < date);
        previous = date;
    }
}

#[test]
fn every_second_of_i64_is_of_a_date() {
    // The first and the last day of i64 seconds since 1970 (as Go's time
    // package documents its range: years -292277022657 to 292277026596).
    let first = Date::from_days(i64::MIN.div_euclid(86_400)).unwrap();
    let last = Date::from_days(i64::MAX.div_euclid(86_400)).unwrap();
    assert_eq!(first.year(), -292_277_022_657);
    assert_eq!(last.year(), 292_277_026_596);
    assert!(Date::MIN < first && last < Date::MAX);
}

#[test]
fn from_days_stops_at_the_first_and_the_last_date() {
    assert_eq!(Date::from_days(Date::MIN.days()), Some(Date::MIN));
    assert_eq!(Date::from_days(Date::MAX.days()), Some(Date::MAX));
    assert_eq!(Date::from_days(Date::MIN.days() - 1), None);
    assert_eq!(Date::from_days(Date::MAX.days() + 1), None);
    assert_eq!(Date::from_days(i64::MIN), None);
    assert_eq!(Date::from_days(i64::MAX), None);
    // 400 years are 146097 days, at the ends as anywhere.
    let after = Date::new(Date::MIN_YEAR + 400, 1, 1).unwrap();
    assert_eq!(after.days() - Date::MIN.days(), 146_097);
    let before = Date::new(Date::MAX_YEAR - 400, 12, 31).unwrap();
    assert_eq!(Date::MAX.days() - before.days(), 146_097);
}

#[test]
fn dates_order_by_year_month_and_day() {
    let dates = [(-1, 12, 31), (0, 1, 1), (2024, 1, 31), (2024, 2, 1), (2024, 12, 31), (2025, 1, 1)];
    let dates = dates.map(|(year, month, day)| Date::new(year, month, day).unwrap());
    for pair in dates.windows(2) {
        assert!(pair[0] < pair[1] && pair[0].days() < pair[1].days());
    }
}
