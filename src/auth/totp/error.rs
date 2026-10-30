/// Why a one-time password generator cannot be made, or a password not checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OTPError {
    /// A key shorter than 128 bits (RFC 4226 R6).
    KeyTooShort,
    /// Fewer than 6 digits (RFC 4226 R4) or more than 10 (the truncated value has 31 bits).
    Digits,
    /// A time step of zero seconds.
    Period,
    /// A time before the origin of the time steps.
    Time,
    /// A hash function whose output is shorter than the 19 bytes the dynamic truncation reads.
    Hash,
}

impl core::fmt::Display for OTPError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            OTPError::KeyTooShort => "the key is shorter than 128 bits",
            OTPError::Digits => "a password has 6 to 10 digits",
            OTPError::Period => "the time step is zero seconds",
            OTPError::Time => "the time is before the origin of the time steps",
            OTPError::Hash => "the hash function's output is shorter than 19 bytes",
        })
    }
}

impl core::error::Error for OTPError {}
