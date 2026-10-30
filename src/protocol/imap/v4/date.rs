use core::fmt;

use super::{IMAPError, IMAPReader};
use crate::calendar::Date;
use crate::codec::mail::MailDate;

/// A date-time of IMAP (RFC 9051 §9 `date-time`): `"dd-Mon-yyyy hh:mm:ss +zzzz"`;
/// the instant (seconds since 1970, UTC) and the zone's offset in minutes east.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IMAPDateTime {
    pub seconds: i64,
    pub offset: i16,
}

/// A date of SEARCH (RFC 9051 §9 `date`): `d-Mon-yyyy`, quoted or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IMAPDate {
    pub year: i64,
    pub month: u8,
    pub day: u8,
}

impl IMAPDateTime {
    pub fn new(seconds: i64, offset: i16) -> IMAPDateTime {
        IMAPDateTime { seconds, offset }
    }

    /// A month name of three letters, in any case (§9 `date-month`); 1 to 12.
    pub fn month(reader: &mut IMAPReader<'_>) -> Result<u8, IMAPError> {
        let name = reader.data.get(reader.position..reader.position + 3).ok_or(reader.error("not a month"))?;
        let month = MailDate::MONTHS.iter().position(|month| month.as_bytes().eq_ignore_ascii_case(name));
        let month = month.ok_or(reader.error("not a month"))?;
        reader.position += 3;
        Ok(month as u8 + 1)
    }

    /// `count` digits.
    pub fn digits(reader: &mut IMAPReader<'_>, count: usize) -> Result<i64, IMAPError> {
        let digits = reader
            .data
            .get(reader.position..reader.position + count)
            .filter(|digits| digits.iter().all(u8::is_ascii_digit));
        let digits = digits.ok_or(reader.error("not the digits of a date"))?;
        reader.position += count;
        Ok(digits.iter().fold(0, |value, digit| value * 10 + i64::from(digit - b'0')))
    }

    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPDateTime, IMAPError> {
        reader.expect(b'"', "not a date-time")?;
        // date-day-fixed: SP DIGIT or 2DIGIT.
        let day = match reader.eat(b' ') {
            true => IMAPDateTime::digits(reader, 1)?,
            false => IMAPDateTime::digits(reader, 2)?,
        };
        reader.expect(b'-', "a date without -")?;
        let month = i64::from(IMAPDateTime::month(reader)?);
        reader.expect(b'-', "a date without -")?;
        let year = IMAPDateTime::digits(reader, 4)?;
        reader.sp()?;
        let hour = IMAPDateTime::digits(reader, 2)?;
        reader.expect(b':', "a time without :")?;
        let minute = IMAPDateTime::digits(reader, 2)?;
        reader.expect(b':', "a time without :")?;
        let second = IMAPDateTime::digits(reader, 2)?;
        reader.sp()?;
        let sign = match reader.peek() {
            Some(b'+') => 1,
            Some(b'-') => -1,
            _ => return Err(reader.error("a zone without a sign")),
        };
        reader.position += 1;
        let zone = IMAPDateTime::digits(reader, 4)?;
        reader.expect(b'"', "a date-time not closed")?;
        let (zone_hours, zone_minutes) = (zone / 100, zone % 100);
        let date = IMAPDate { year, month: month as u8, day: day as u8 };
        let days = date.days().filter(|_| hour <= 23 && minute <= 59 && second <= 60 && zone_minutes <= 59);
        let Some(days) = days else {
            return Err(reader.error("a date-time out of range"));
        };
        let offset = (sign * (zone_hours * 60 + zone_minutes)) as i16;
        let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second.min(59) - i64::from(offset) * 60;
        Ok(IMAPDateTime { seconds, offset })
    }

    /// The date-time in its local time: its date.
    pub fn date(&self) -> IMAPDate {
        let local = self.seconds + i64::from(self.offset) * 60;
        let date = Date::from_days(local.div_euclid(86_400)).expect("every day of i64 seconds is of a date");
        IMAPDate { year: date.year(), month: date.month(), day: date.day() }
    }
}

impl fmt::Display for IMAPDateTime {
    /// The date-time as §9 writes it, its quotes included.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let local = self.seconds + i64::from(self.offset) * 60;
        // Every day of i64 seconds is of a date (`Date::MIN_YEAR`).
        let date = Date::from_days(local.div_euclid(86_400)).ok_or(fmt::Error)?;
        let time = local.rem_euclid(86_400);
        let sign = if self.offset < 0 { '-' } else { '+' };
        let offset = self.offset.unsigned_abs();
        write!(
            formatter,
            "\"{:02}-{}-{:04} {:02}:{:02}:{:02} {sign}{:02}{:02}\"",
            date.day(),
            MailDate::MONTHS[usize::from(date.month()) - 1],
            date.year(),
            time / 3_600,
            time / 60 % 60,
            time % 60,
            offset / 60,
            offset % 60
        )
    }
}

impl From<MailDate> for IMAPDateTime {
    fn from(date: MailDate) -> IMAPDateTime {
        IMAPDateTime { seconds: date.seconds, offset: date.offset }
    }
}

impl IMAPDate {
    pub fn new(year: i64, month: u8, day: u8) -> IMAPDate {
        IMAPDate { year, month, day }
    }

    /// Whether the day is of the month (the Gregorian calendar).
    pub fn is_valid(&self) -> bool {
        Date::new(self.year, self.month, self.day).is_some()
    }

    /// The days since 1970-01-01; `None` if the date is not valid.
    pub fn days(&self) -> Option<i64> {
        Date::new(self.year, self.month, self.day).map(Date::days)
    }

    pub fn read(reader: &mut IMAPReader<'_>) -> Result<IMAPDate, IMAPError> {
        let quoted = reader.eat(b'"');
        let start = reader.position;
        let day = reader.take_while(|byte| byte.is_ascii_digit(), "not a day")?;
        if day.len() > 2 {
            return Err(IMAPError::Syntax { position: start, reason: "a day of more than 2 digits" });
        }
        let day = day.iter().fold(0u8, |value, digit| value * 10 + (digit - b'0'));
        reader.expect(b'-', "a date without -")?;
        let month = IMAPDateTime::month(reader)?;
        reader.expect(b'-', "a date without -")?;
        let year = IMAPDateTime::digits(reader, 4)?;
        if quoted {
            reader.expect(b'"', "a date not closed")?;
        }
        let date = IMAPDate { year, month, day };
        match date.is_valid() {
            true => Ok(date),
            false => Err(IMAPError::Syntax { position: start, reason: "a date out of range" }),
        }
    }
}

impl fmt::Display for IMAPDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}-{}-{:04}",
            self.day,
            MailDate::MONTHS[usize::from(self.month.clamp(1, 12)) - 1],
            self.year
        )
    }
}
