/// A date of the proleptic Gregorian calendar: the Gregorian calendar
/// extended to every year, with a year 0 (1 BC) and negative years before it,
/// as ISO 8601 numbers them. Dates order as they follow each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: i64,
    month: u8,
    day: u8,
}

impl Date {
    /// The first year of a date. Together with [`Date::MAX_YEAR`] it holds
    /// the date of every second count of `i64` since 1970 (years
    /// -292277022657 to 292277026596), and keeps the arithmetic of the days
    /// far from overflowing `i64`.
    pub const MIN_YEAR: i64 = -999_999_999_999;
    /// The last year of a date.
    pub const MAX_YEAR: i64 = 999_999_999_999;
    /// The first date: January 1 of [`Date::MIN_YEAR`].
    pub const MIN: Date = Date { year: Date::MIN_YEAR, month: 1, day: 1 };
    /// The last date: December 31 of [`Date::MAX_YEAR`].
    pub const MAX: Date = Date { year: Date::MAX_YEAR, month: 12, day: 31 };
    /// The date of day 0: 1970-01-01.
    pub const EPOCH: Date = Date { year: 1970, month: 1, day: 1 };

    /// The date of `day` of `month` (1 to 12) of `year`; `None` if the
    /// calendar has no such day or the year is out of range.
    pub const fn new(year: i64, month: u8, day: u8) -> Option<Date> {
        if year < Date::MIN_YEAR || year > Date::MAX_YEAR || day == 0 || day > Date::days_in_month(year, month) {
            return None;
        }
        Some(Date { year, month, day })
    }

    pub const fn year(self) -> i64 {
        self.year
    }

    /// The month, 1 to 12.
    pub const fn month(self) -> u8 {
        self.month
    }

    /// The day of the month, from 1.
    pub const fn day(self) -> u8 {
        self.day
    }

    /// Whether `year` has a February 29: a multiple of 4 that is not a
    /// multiple of 100, or a multiple of 400.
    pub const fn is_leap_year(year: i64) -> bool {
        year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
    }

    /// The number of days of `month` (1 to 12) of `year`, or 0 for other months.
    pub const fn days_in_month(year: i64, month: u8) -> u8 {
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if Date::is_leap_year(year) => 29,
            2 => 28,
            _ => 0,
        }
    }

    /// The number of days from 1970-01-01 to the date, negative before it.
    pub const fn days(self) -> i64 {
        // Howard Hinnant's days_from_civil: years are counted from March, so
        // a leap day is the last day of its year, in eras of 400 years
        // (146097 days); 719468 is the day of 1970-01-01 from 0000-03-01.
        let (month, day) = (self.month as i64, self.day as i64);
        let year = if month <= 2 { self.year - 1 } else { self.year };
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }

    /// The date `days` days after 1970-01-01 (before it if negative); `None`
    /// outside [`Date::MIN`] to [`Date::MAX`]. The inverse of [`Date::days`].
    pub const fn from_days(days: i64) -> Option<Date> {
        if days < Date::MIN.days() || days > Date::MAX.days() {
            return None;
        }
        // Howard Hinnant's civil_from_days, the steps of days in reverse.
        let days = days + 719_468;
        let era = days.div_euclid(146_097);
        let day_of_era = days - era * 146_097;
        let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_index = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_index + 2) / 5 + 1;
        let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
        let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
        Some(Date { year, month: month as u8, day: day as u8 })
    }
}
