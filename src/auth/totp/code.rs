use core::fmt;

/// A one-time password: a number of a fixed count of decimal digits,
/// written with leading zeros.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OTPCode {
    value: u32,
    digits: u32,
}

impl OTPCode {
    /// The most digits of a password.
    pub const MAXIMUM_DIGITS: usize = 10;

    /// The password `value` of `digits` digits (`value` below `10^digits`).
    pub const fn new(value: u32, digits: u32) -> OTPCode {
        OTPCode { value, digits }
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
