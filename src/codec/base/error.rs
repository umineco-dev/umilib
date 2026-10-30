use core::fmt;

/// An error of a binary-to-text [`Encoding`](super::Encoding).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseError {
    /// `character` at `position` is not part of the encoding.
    InvalidCharacter { position: usize, character: u8 },
    /// No valid encoding has `length` characters.
    InvalidLength { length: usize },
    /// The padding at `position` is missing, misplaced or not allowed.
    InvalidPadding { position: usize },
    /// The character at `position` encodes bits that must be zero, so the text
    /// is not the canonical encoding of any data (RFC 4648 section 3.5).
    NonCanonical { position: usize },
    /// A group at `position` encodes a value larger than its bytes can hold.
    Overflow { position: usize },
    /// The output needs `needed` bytes, but only `available` were given.
    OutputTooSmall { needed: usize, available: usize },
    /// The input is longer than the configured `maximum`.
    InputTooLong { length: usize, maximum: usize },
    /// The memory for the output could not be allocated.
    AllocationFailed { length: usize },
}

impl fmt::Display for BaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseError::InvalidCharacter { position, character } => {
                write!(formatter, "invalid character {character:#04x} at position {position}")
            }
            BaseError::InvalidLength { length } => write!(formatter, "invalid encoded length {length}"),
            BaseError::InvalidPadding { position } => write!(formatter, "invalid padding at position {position}"),
            BaseError::NonCanonical { position } => {
                write!(formatter, "non-canonical encoding: unused bits are set at position {position}")
            }
            BaseError::Overflow { position } => write!(formatter, "group at position {position} overflows"),
            BaseError::OutputTooSmall { needed, available } => {
                write!(formatter, "output too small: {needed} bytes needed, {available} available")
            }
            BaseError::InputTooLong { length, maximum } => {
                write!(formatter, "input of {length} bytes is longer than the maximum of {maximum}")
            }
            BaseError::AllocationFailed { length } => write!(formatter, "cannot allocate {length} bytes"),
        }
    }
}

impl core::error::Error for BaseError {}
