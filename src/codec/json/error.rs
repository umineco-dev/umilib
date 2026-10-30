use core::fmt;

/// An error of JSON parsing or conversion. Positions are byte offsets in the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JSONError {
    /// `character` at `position` is not allowed there by the grammar.
    UnexpectedCharacter { position: usize, character: u8 },
    /// The input ends before the value is complete.
    UnexpectedEnd { position: usize },
    /// Something other than white space follows the value.
    TrailingData { position: usize },
    /// The number at `position` does not follow the grammar of RFC 8259 section 6.
    InvalidNumber { position: usize },
    /// The escape sequence at `position` is not one of RFC 8259 section 7.
    InvalidEscape { position: usize },
    /// A control character (U+0000 to U+001F) appears unescaped in a string.
    ControlCharacter { position: usize },
    /// The bytes at `position` are not valid UTF-8 (RFC 8259 section 8.1).
    InvalidUTF8 { position: usize },
    /// A `\u` escape at `position` is half of a surrogate pair without the other half.
    LoneSurrogate { position: usize },
    /// Arrays and objects nest deeper than `maximum` at `position`.
    TooDeep { position: usize, maximum: usize },
    /// The input is longer than `maximum` bytes.
    TooLong { length: usize, maximum: usize },
    /// An object has the key at `position` twice.
    DuplicateKey { position: usize },
    /// A number does not fit in the requested type.
    OutOfRange,
    /// The memory for a value could not be allocated.
    AllocationFailed,
}

impl fmt::Display for JSONError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JSONError::UnexpectedCharacter { position, character } => {
                write!(formatter, "unexpected character {character:#04x} at {position}")
            }
            JSONError::UnexpectedEnd { position } => write!(formatter, "unexpected end of input at {position}"),
            JSONError::TrailingData { position } => write!(formatter, "data after the value at {position}"),
            JSONError::InvalidNumber { position } => write!(formatter, "invalid number at {position}"),
            JSONError::InvalidEscape { position } => write!(formatter, "invalid escape sequence at {position}"),
            JSONError::ControlCharacter { position } => write!(formatter, "unescaped control character at {position}"),
            JSONError::InvalidUTF8 { position } => write!(formatter, "invalid UTF-8 at {position}"),
            JSONError::LoneSurrogate { position } => write!(formatter, "unpaired surrogate escape at {position}"),
            JSONError::TooDeep { position, maximum } => {
                write!(formatter, "nesting deeper than {maximum} at {position}")
            }
            JSONError::TooLong { length, maximum } => {
                write!(formatter, "input of {length} bytes is longer than the maximum of {maximum}")
            }
            JSONError::DuplicateKey { position } => write!(formatter, "duplicate key at {position}"),
            JSONError::OutOfRange => formatter.write_str("number out of range"),
            JSONError::AllocationFailed => formatter.write_str("allocation failed"),
        }
    }
}

impl core::error::Error for JSONError {}
