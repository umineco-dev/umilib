use alloc::string::String;
use core::fmt;

use super::{MailError, MailReader};
use crate::calendar::Date;

/// A date-time of RFC 5322 §3.3: the instant (seconds since 1970, UTC)
/// and the offset of the local time it was written in (minutes east), or,
/// with `zone_unknown`, a time of UTC whose local time is not known
/// (`-0000`, and the military zones of §4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct MailDate {
    pub seconds: i64,
    pub offset: i16,
    pub zone_unknown: bool,
}

impl MailDate {
    pub const DAYS: [&'static str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    pub const MONTHS: [&'static str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    pub fn new(seconds: i64, offset: i16) -> MailDate {
        MailDate { seconds, offset, zone_unknown: false }
    }

    /// The date-time of `text`, with CFWS anywhere and the obsolete forms of
    /// §4.3: two- and three-digit years, the zones of names, military zones
    /// (taken as -0000, of a local time unknown, as §4.3 says they should be). A day of the week, if
    /// given, must be the day of the date (§3.3).
    pub fn parse(text: &[u8]) -> Result<MailDate, MailError> {
        let mut reader = MailReader::new(text, false);
        reader.skip_cfws()?;
        let mut weekday = None;
        if reader.peek().is_some_and(|byte| byte.is_ascii_alphabetic()) {
            let name = reader.atom()?;
            let day = MailDate::DAYS.iter().position(|day| day.as_bytes().eq_ignore_ascii_case(name));
            weekday = Some(day.ok_or(reader.error("not a day of the week"))?);
            reader.expect(b',', "a day of the week without a comma")?;
        }
        let day = MailDate::number(&mut reader, 1, 2)?;
        let name = reader.atom()?;
        let month = MailDate::MONTHS.iter().position(|month| month.as_bytes().eq_ignore_ascii_case(name));
        let month = month.ok_or(reader.error("not a month"))? as u8 + 1;
        reader.skip_cfws()?;
        let digits = reader.text[reader.position..].iter().take_while(|byte| byte.is_ascii_digit()).count();
        let year = MailDate::number(&mut reader, 2, 9)?;
        let year = match digits {
            2 if year < 50 => year + 2000,
            2 | 3 => year + 1900,
            _ => year,
        };
        let hour = MailDate::number(&mut reader, 2, 2)?;
        reader.expect(b':', "a time without a colon")?;
        let minute = MailDate::number(&mut reader, 2, 2)?;
        let second = if reader.eat(b':') { MailDate::number(&mut reader, 2, 2)? } else { 0 };
        // §3.3: a year of 1900 or later; a second of 60 is a leap second. A day of two digits fits u8.
        let date = Date::new(year, month, day as u8);
        let Some(date) = date.filter(|_| year >= 1900 && hour <= 23 && minute <= 59 && second <= 60) else {
            return Err(reader.error("a date or time out of range"));
        };
        reader.skip_cfws()?;
        let (offset, zone_unknown) = MailDate::zone(&mut reader)?;
        reader.skip_cfws()?;
        if !reader.is_end() {
            return Err(reader.error("more after a date"));
        }
        let days = date.days();
        if weekday.is_some_and(|weekday| weekday as i64 != (days + 3).rem_euclid(7)) {
            return Err(MailError::Syntax { position: 0, reason: "a day of the week not of the date" });
        }
        // A leap second is the last second of its minute.
        let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second.min(59) - i64::from(offset) * 60;
        Ok(MailDate { seconds, offset, zone_unknown })
    }

    /// A number of `least` to `most` digits.
    pub fn number(reader: &mut MailReader<'_>, least: usize, most: usize) -> Result<i64, MailError> {
        reader.skip_cfws()?;
        let start = reader.position;
        while reader.peek().is_some_and(|byte| byte.is_ascii_digit()) && reader.position - start < most {
            reader.position += 1;
        }
        if reader.position - start < least || reader.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            return Err(reader.error("not a number of its digits"));
        }
        let digits = core::str::from_utf8(&reader.text[start..reader.position]).unwrap_or_default();
        let value = digits.parse().map_err(|_| reader.error("not a number"))?;
        reader.skip_cfws()?;
        Ok(value)
    }

    /// A zone: ±hhmm, or a name of §4.3; minutes east of UTC, and whether the local time is
    /// unknown: `-0000` (§3.3) and the military zones, which §4.3 says SHOULD be taken as it.
    pub fn zone(reader: &mut MailReader<'_>) -> Result<(i16, bool), MailError> {
        if let Some(sign @ (b'+' | b'-')) = reader.peek() {
            reader.position += 1;
            let start = reader.position;
            let digits = reader.text.get(start..start + 4).filter(|digits| digits.iter().all(u8::is_ascii_digit));
            let digits = digits.ok_or(reader.error("a zone not of four digits"))?;
            reader.position += 4;
            let (hours, minutes) = (
                i16::from(digits[0] - b'0') * 10 + i16::from(digits[1] - b'0'),
                i16::from(digits[2] - b'0') * 10 + i16::from(digits[3] - b'0'),
            );
            if minutes > 59 {
                return Err(reader.error("a zone of more than 59 minutes"));
            }
            let offset = hours * 60 + minutes;
            return Ok(match sign {
                b'-' => (-offset, offset == 0),
                _ => (offset, false),
            });
        }
        let name = reader.atom()?;
        let hours: i16 = match name.to_ascii_uppercase().as_slice() {
            b"UT" | b"GMT" | b"Z" => 0,
            b"EST" => -5,
            b"EDT" | b"AST" => -4,
            b"CST" => -6,
            b"CDT" => -5,
            b"MST" => -7,
            b"MDT" => -6,
            b"PST" => -8,
            b"PDT" => -7,
            [letter] if letter.is_ascii_alphabetic() && *letter != b'J' => return Ok((0, true)),
            _ => return Err(reader.error("not a zone")),
        };
        Ok((hours * 60, false))
    }

    /// The date-time as §3.3 writes it: `Thu, 29 Oct 2026 12:00:00 +0900`.
    pub fn format(&self) -> String {
        alloc::format!("{self}")
    }
}

impl fmt::Display for MailDate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Saturating: a date far outside any calendar a message has is written without overflow.
        let local = self.seconds.saturating_add(i64::from(self.offset) * 60);
        let days = local.div_euclid(86_400);
        let time = local.rem_euclid(86_400);
        // Every day of i64 seconds is of a date (`Date::MIN_YEAR`).
        let date = Date::from_days(days).ok_or(fmt::Error)?;
        let weekday = MailDate::DAYS[(days + 3).rem_euclid(7) as usize];
        let sign = if self.offset < 0 || (self.zone_unknown && self.offset == 0) { '-' } else { '+' };
        let offset = self.offset.unsigned_abs();
        write!(
            formatter,
            "{weekday}, {:02} {} {:04} {:02}:{:02}:{:02} {sign}{:02}{:02}",
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
