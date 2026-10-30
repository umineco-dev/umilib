use core::fmt;

use crate::codec::base::BaseError;

/// An error of the Internet Message Format or MIME. Positions are byte
/// offsets in the text read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailError {
    /// The text at `position` is not of the grammar of what was read.
    Syntax { position: usize, reason: &'static str },
    /// A line, a field, or the whole message is longer than the configuration takes.
    TooLong { length: usize, maximum: usize },
    /// More fields, parts, or nested entities than the configuration takes.
    TooMany { maximum: usize },
    /// A character set this crate does not convert (RFC 2047 §6.2 leaves such words as they are).
    Charset,
    /// A Content-Transfer-Encoding this crate does not decode (RFC 2045 §6.4).
    Encoding,
    /// Base64 data that cannot be decoded.
    Base64(BaseError),
}

impl fmt::Display for MailError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MailError::Syntax { position, reason } => write!(formatter, "{reason} at {position}"),
            MailError::TooLong { length, maximum } => {
                write!(formatter, "{length} bytes, longer than the maximum of {maximum}")
            }
            MailError::TooMany { maximum } => write!(formatter, "more than the maximum of {maximum}"),
            MailError::Charset => formatter.write_str("a character set that is not converted"),
            MailError::Encoding => formatter.write_str("a transfer encoding that is not decoded"),
            MailError::Base64(error) => write!(formatter, "invalid base64 data: {error}"),
        }
    }
}

impl core::error::Error for MailError {}

impl From<BaseError> for MailError {
    fn from(error: BaseError) -> MailError {
        MailError::Base64(error)
    }
}
