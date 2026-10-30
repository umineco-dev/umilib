//! Fuzz targets of `umilib::calendar`.

use umilib::calendar::Date;
use umilib::platform::fuzz::{FuzzFunction, FuzzTarget};

/// A year, a month and a day make a date exactly when the calendar has that
/// day, and a date and its days convert to each other; any days do too.
pub const DATES: FuzzFunction<fn(&[u8])> = FuzzFunction::new("calendar-dates", |data| {
    let mut bytes = [0u8; 10];
    let length = data.len().min(bytes.len());
    bytes[..length].copy_from_slice(&data[..length]);
    let number = i64::from_le_bytes(bytes[..8].try_into().expect("eight bytes"));
    // Half of the inputs take years of at most four digits, where leap years are; the others any i64.
    let year = if bytes[8] & 0x80 == 0 { number % 10_000 } else { number };
    let (month, day) = (bytes[8] & 0x0F, bytes[9] & 0x1F);
    let valid = (Date::MIN_YEAR..=Date::MAX_YEAR).contains(&year)
        && (1..=12).contains(&month)
        && (1..=Date::days_in_month(year, month)).contains(&day);
    let date = Date::new(year, month, day);
    assert_eq!(date.is_some(), valid);
    if let Some(date) = date {
        assert_eq!((date.year(), date.month(), date.day()), (year, month, day));
        assert_eq!(Date::from_days(date.days()), Some(date));
    }
    match Date::from_days(number) {
        Some(date) => assert_eq!(date.days(), number),
        None => assert!(number < Date::MIN.days() || number > Date::MAX.days()),
    }
});

pub const TARGETS: &[&dyn FuzzTarget] = &[&DATES];
