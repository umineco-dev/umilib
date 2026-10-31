use core::fmt;

use super::OTPError;

/// A one-time password: a number of a fixed count of decimal digits,
/// written with leading zeros.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OTPCode {
    value: u32,
    digits: u32,
}

impl OTPCode {
    /// The fewest digits of a password (RFC 4226 R4).
    pub const MINIMUM_DIGITS: usize = 6;
    /// The most digits of a password: the truncated value of RFC 4226
    /// §5.3 is below 2^31, so more digits would only add leading zeros.
    pub const MAXIMUM_DIGITS: usize = 10;

    /// The password `value` of `digits` digits; fails with `Digits` unless
    /// `digits` is from [`OTPCode::MINIMUM_DIGITS`] to
    /// [`OTPCode::MAXIMUM_DIGITS`] and `value` is below `10^digits`.
    pub const fn new(value: u32, digits: u32) -> Result<OTPCode, OTPError> {
        if digits < OTPCode::MINIMUM_DIGITS as u32 || digits > OTPCode::MAXIMUM_DIGITS as u32 {
            return Err(OTPError::Digits);
        }
        if value as u64 >= 10u64.pow(digits) {
            return Err(OTPError::Digits);
        }
        Ok(OTPCode { value, digits })
    }

    pub fn value(&self) -> u32 {
        self.value
    }

    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// The ASCII digits of the password (with leading zeros) in the first
    /// [`OTPCode::digits`] bytes of the array.
    pub fn to_ascii(&self) -> [u8; OTPCode::MAXIMUM_DIGITS] {
        let mut text = [b'0'; OTPCode::MAXIMUM_DIGITS];
        let mut value = self.value;
        for index in (0..self.digits as usize).rev() {
            text[index] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        text
    }
}

impl fmt::Display for OTPCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.to_ascii();
        // The digits are ASCII.
        formatter.write_str(core::str::from_utf8(&text[..self.digits as usize]).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for OTPCode {
    /// The digits are a credential: they are not printed.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OTPCode({} digits)", self.digits)
    }
}
