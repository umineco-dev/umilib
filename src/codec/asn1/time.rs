use alloc::vec::Vec;
use core::fmt::Write;

use super::ASN1Error;
use crate::calendar::Date;

/// A moment in UTC, as held by UTCTime and GeneralizedTime.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ASN1Time {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanosecond: u32,
}

impl ASN1Time {
    /// Creates a time, checking the calendar (leap years included) and the
    /// ranges of every field. Leap seconds (second 60) are not accepted.
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
    ) -> Result<ASN1Time, ASN1Error> {
        let valid = Date::new(i64::from(year), month, day).is_some()
            && hour < 24
            && minute < 60
            && second < 60
            && nanosecond < 1_000_000_000;
        if !valid {
            return Err(ASN1Error::InvalidContent { position: 0 });
        }
        Ok(ASN1Time { year, month, day, hour, minute, second, nanosecond })
    }

    /// [`Date::is_leap_year`] of a year of a time.
    pub fn is_leap_year(year: u16) -> bool {
        Date::is_leap_year(i64::from(year))
    }

    /// [`Date::days_in_month`] of a year of a time: 28 to 31, or 0 for a month not 1 to 12.
    pub fn days_in_month(year: u16, month: u8) -> u8 {
        Date::days_in_month(i64::from(year), month)
    }

    /// The decimal value of the ASCII digits `bytes`; `None` if any is not a digit.
    pub fn digits(bytes: &[u8]) -> Option<u32> {
        bytes.iter().try_fold(0u32, |value, &byte| byte.is_ascii_digit().then(|| value * 10 + (byte - b'0') as u32))
    }

    /// Reads a UTCTime in the form DER requires: `YYMMDDhhmmssZ` (X.690
    /// section 11.8). Two-digit years 50 to 99 are 1950 to 1999 and 00 to 49
    /// are 2000 to 2049, as RFC 5280 section 4.1.2.5.1 specifies.
    pub fn decode_utc_time(content: &[u8]) -> Result<ASN1Time, ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        if content.len() != 13 || content[12] != b'Z' {
            return Err(invalid);
        }
        let field = |range: core::ops::Range<usize>| ASN1Time::digits(&content[range]).ok_or(invalid);
        let year = field(0..2)?;
        let year = if year >= 50 { 1900 + year } else { 2000 + year };
        ASN1Time::new(
            year as u16,
            field(2..4)? as u8,
            field(4..6)? as u8,
            field(6..8)? as u8,
            field(8..10)? as u8,
            field(10..12)? as u8,
            0,
        )
    }

    /// Checks a GeneralizedTime in the form DER requires: `YYYYMMDDhhmmss`,
    /// an optional fraction of a second (`.` and one or more digits, the last
    /// not zero), and `Z` (X.690 section 11.7). Any number of fraction digits
    /// is allowed. Returns the time without its fraction and the fraction digits.
    pub fn check_generalized_time(content: &[u8]) -> Result<(ASN1Time, &[u8]), ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        if content.len() < 15 || content[content.len() - 1] != b'Z' {
            return Err(invalid);
        }
        let field = |range: core::ops::Range<usize>| ASN1Time::digits(&content[range]).ok_or(invalid);
        let fraction = &content[14..content.len() - 1];
        let digits = if fraction.is_empty() { fraction } else { fraction.strip_prefix(b".").ok_or(invalid)? };
        if !fraction.is_empty()
            && (digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) || digits.last() == Some(&b'0'))
        {
            return Err(invalid);
        }
        let time = ASN1Time::new(
            field(0..4)? as u16,
            field(4..6)? as u8,
            field(6..8)? as u8,
            field(8..10)? as u8,
            field(10..12)? as u8,
            field(12..14)? as u8,
            0,
        )?;
        Ok((time, digits))
    }

    /// Reads a GeneralizedTime in the form DER requires (see
    /// [`ASN1Time::check_generalized_time`]); fails with `OutOfRange` if the
    /// fraction has more than nine digits, which nanoseconds cannot hold.
    pub fn decode_generalized_time(content: &[u8]) -> Result<ASN1Time, ASN1Error> {
        let (time, digits) = ASN1Time::check_generalized_time(content)?;
        time.with_fraction(digits)
    }

    /// The time with the fraction of a second `digits` (decimal, possibly
    /// empty); fails with `OutOfRange` beyond nanoseconds.
    pub fn with_fraction(self, digits: &[u8]) -> Result<ASN1Time, ASN1Error> {
        let significant = &digits[..digits.len() - digits.iter().rev().take_while(|&&digit| digit == b'0').count()];
        if significant.len() > 9 {
            return Err(ASN1Error::OutOfRange);
        }
        let value = ASN1Time::digits(significant).ok_or(ASN1Error::InvalidContent { position: 0 })?;
        Ok(ASN1Time { nanosecond: value * 10u32.pow(9 - significant.len() as u32), ..self })
    }

    /// Appends the DER contents of a UTCTime; fails outside 1950 to 2049 or with a fraction.
    pub fn encode_utc_time(&self, output: &mut Vec<u8>) -> Result<(), ASN1Error> {
        if !(1950..=2049).contains(&self.year) || self.nanosecond != 0 {
            return Err(ASN1Error::OutOfRange);
        }
        let mut text = alloc::string::String::new();
        let _ = write!(
            text,
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            self.year % 100,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second
        );
        output.extend_from_slice(text.as_bytes());
        Ok(())
    }

    /// Appends the DER contents of a GeneralizedTime; fails after year 9999.
    pub fn encode_generalized_time(&self, output: &mut Vec<u8>) -> Result<(), ASN1Error> {
        if self.year > 9999 {
            return Err(ASN1Error::OutOfRange);
        }
        let mut text = alloc::string::String::new();
        let _ = write!(
            text,
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        );
        if self.nanosecond != 0 {
            let fraction = alloc::format!("{:09}", self.nanosecond);
            text.push('.');
            text.push_str(fraction.trim_end_matches('0'));
        }
        text.push('Z');
        output.extend_from_slice(text.as_bytes());
        Ok(())
    }

    /// The date of the time; `None` for a time made without [`ASN1Time::new`]
    /// whose day is not of its month.
    pub fn date(&self) -> Option<Date> {
        Date::new(i64::from(self.year), self.month, self.day)
    }

    /// Seconds since 1970-01-01T00:00:00Z, ignoring the fraction. A time made
    /// without [`ASN1Time::new`] whose day is not of its month counts as
    /// 1970-01-01.
    pub fn to_unix_seconds(&self) -> i64 {
        self.date().map_or(0, Date::days) * 86_400
            + self.hour as i64 * 3600
            + self.minute as i64 * 60
            + self.second as i64
    }

    /// The time `seconds` after 1970-01-01T00:00:00Z; fails outside years 0 to 65535.
    pub fn from_unix_seconds(seconds: i64) -> Result<ASN1Time, ASN1Error> {
        let days = seconds.div_euclid(86_400);
        let time = seconds.rem_euclid(86_400);
        let date = Date::from_days(days).ok_or(ASN1Error::OutOfRange)?;
        let year = u16::try_from(date.year()).map_err(|_| ASN1Error::OutOfRange)?;
        ASN1Time::new(year, date.month(), date.day(), (time / 3600) as u8, (time / 60 % 60) as u8, (time % 60) as u8, 0)
    }
}

impl ASN1Time {
    /// Reads the zone at the end of a BER time: `Z` or `+hhmm`/`-hhmm`, and
    /// returns the offset east of UTC in seconds and the length of the rest.
    pub fn decode_zone(content: &[u8], allow_hours_only: bool) -> Result<(i64, usize), ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        if content.last() == Some(&b'Z') {
            return Ok((0, content.len() - 1));
        }
        for length in [5usize, 3] {
            if length == 3 && !allow_hours_only {
                continue;
            }
            if content.len() > length && matches!(content[content.len() - length], b'+' | b'-') {
                let sign = if content[content.len() - length] == b'-' { -1 } else { 1 };
                let zone = &content[content.len() - length + 1..];
                let hours = ASN1Time::digits(&zone[..2]).ok_or(invalid)? as i64;
                let minutes = if zone.len() == 4 { ASN1Time::digits(&zone[2..]).ok_or(invalid)? as i64 } else { 0 };
                if hours > 23 || minutes > 59 {
                    return Err(invalid);
                }
                return Ok((sign * (hours * 3600 + minutes * 60), content.len() - length));
            }
        }
        // A local time without zone cannot be converted to UTC.
        Err(invalid)
    }

    /// Shifts a time read with a zone `offset` seconds east of UTC to UTC.
    pub fn to_utc(self, offset: i64) -> Result<ASN1Time, ASN1Error> {
        if offset == 0 {
            return Ok(self);
        }
        let mut shifted = ASN1Time::from_unix_seconds(self.to_unix_seconds() - offset)?;
        shifted.nanosecond = self.nanosecond;
        Ok(shifted)
    }

    /// Reads a UTCTime in any form BER allows: `YYMMDDhhmm`, optional seconds,
    /// and `Z` or an offset (X.680 section 47). The result is in UTC.
    pub fn decode_utc_time_ber(content: &[u8]) -> Result<ASN1Time, ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        let (offset, length) = ASN1Time::decode_zone(content, false)?;
        let body = &content[..length];
        if body.len() != 10 && body.len() != 12 {
            return Err(invalid);
        }
        let field = |range: core::ops::Range<usize>| ASN1Time::digits(&body[range]).ok_or(invalid);
        let year = field(0..2)?;
        let year = if year >= 50 { 1900 + year } else { 2000 + year };
        let second = if body.len() == 12 { field(10..12)? } else { 0 };
        ASN1Time::new(
            year as u16,
            field(2..4)? as u8,
            field(4..6)? as u8,
            field(6..8)? as u8,
            field(8..10)? as u8,
            second as u8,
            0,
        )?
        .to_utc(offset)
    }

    /// The product of the decimal `digits` and `factor`, as decimal digits
    /// with at least as many digits as `digits`.
    pub fn multiply_digits(digits: &[u8], factor: u32) -> Vec<u8> {
        let mut product = Vec::with_capacity(digits.len() + 10);
        let mut carry = 0u64;
        for &digit in digits.iter().rev() {
            let value = (digit - b'0') as u64 * factor as u64 + carry;
            product.push(b'0' + (value % 10) as u8);
            carry = value / 10;
        }
        while carry > 0 {
            product.push(b'0' + (carry % 10) as u8);
            carry /= 10;
        }
        product.reverse();
        product
    }

    /// Reads a GeneralizedTime in the forms BER allows with a zone (X.680
    /// section 46): `YYYYMMDDhh`, optional minutes and seconds, an optional
    /// fraction of the last of them after `.` or `,`, and `Z` or an offset.
    /// Local times without a zone are rejected, because they cannot be
    /// converted to UTC. Returns the time in UTC without its fraction and the
    /// exact fraction of a second as decimal digits without trailing zeros.
    pub fn decode_generalized_time_exact(content: &[u8]) -> Result<(ASN1Time, Vec<u8>), ASN1Error> {
        let invalid = ASN1Error::InvalidContent { position: 0 };
        let (offset, length) = ASN1Time::decode_zone(content, true)?;
        let body = &content[..length];
        let (fields, fraction) = match body.iter().position(|&byte| byte == b'.' || byte == b',') {
            Some(index) => (&body[..index], &body[index + 1..]),
            None => (body, &body[body.len()..]),
        };
        let has_fraction = fields.len() < body.len();
        if !matches!(fields.len(), 10 | 12 | 14)
            || (has_fraction && (fraction.is_empty() || !fraction.iter().all(u8::is_ascii_digit)))
        {
            return Err(invalid);
        }
        let field = |range: core::ops::Range<usize>| ASN1Time::digits(&fields[range]).ok_or(invalid);
        let minute = if fields.len() >= 12 { field(10..12)? } else { 0 };
        let second = if fields.len() == 14 { field(12..14)? } else { 0 };
        let time = ASN1Time::new(
            field(0..4)? as u16,
            field(4..6)? as u8,
            field(6..8)? as u8,
            field(8..10)? as u8,
            minute as u8,
            second as u8,
            0,
        )?;
        // The fraction applies to the last element: an hour, a minute or a
        // second. As a number of seconds it is fraction * unit / 10^digits,
        // whose decimal expansion is exact.
        let unit = match fields.len() {
            10 => 3600,
            12 => 60,
            _ => 1,
        };
        let product = ASN1Time::multiply_digits(fraction, unit);
        let (whole, rest) = product.split_at(product.len() - fraction.len());
        let whole_seconds = ASN1Time::digits(whole).ok_or(invalid)? as i64;
        let mut digits = Vec::from(rest);
        while digits.last() == Some(&b'0') {
            digits.pop();
        }
        let utc = ASN1Time::from_unix_seconds(time.to_unix_seconds() + whole_seconds - offset)?;
        Ok((utc, digits))
    }

    /// Reads a GeneralizedTime in the forms BER allows (see
    /// [`ASN1Time::decode_generalized_time_exact`]), converted to UTC; fails
    /// with `OutOfRange` if the fraction of a second needs more than nanoseconds.
    pub fn decode_generalized_time_ber(content: &[u8]) -> Result<ASN1Time, ASN1Error> {
        let (time, digits) = ASN1Time::decode_generalized_time_exact(content)?;
        time.with_fraction(&digits)
    }

    /// Converts a GeneralizedTime in any BER form with a zone to its DER
    /// contents, keeping every digit of the fraction (X.690 section 11.7).
    pub fn generalized_time_ber_to_der(content: &[u8]) -> Result<Vec<u8>, ASN1Error> {
        let (time, digits) = ASN1Time::decode_generalized_time_exact(content)?;
        let mut output = Vec::new();
        time.encode_generalized_time(&mut output)?;
        if !digits.is_empty() {
            // Insert the fraction before the final `Z`.
            output.pop();
            output.push(b'.');
            output.extend_from_slice(&digits);
            output.push(b'Z');
        }
        Ok(output)
    }
}
