use core::fmt;

use crate::codec::stringprep::StringPrepError;

/// Why a SASL message is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SASLError {
    /// A message that does not follow the syntax of its mechanism, or is
    /// not UTF-8 where the mechanism requires it.
    Format,
    /// A field that is empty where it must not be, or longer than its limit.
    Length,
    /// A string the stringprep profile of the mechanism refuses.
    Prepare(StringPrepError),
}

impl From<StringPrepError> for SASLError {
    fn from(error: StringPrepError) -> SASLError {
        SASLError::Prepare(error)
    }
}

impl fmt::Display for SASLError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SASLError::Format => formatter.write_str("malformed SASL message"),
            SASLError::Length => formatter.write_str("a field of the SASL message is empty or too long"),
            SASLError::Prepare(error) => write!(formatter, "{error}"),
        }
    }
}

impl core::error::Error for SASLError {}
