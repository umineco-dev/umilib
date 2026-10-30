use core::fmt;

/// Why a string cannot be prepared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringPrepError {
    /// A code point the profile prohibits.
    Prohibited(char),
    /// A code point unassigned in Unicode 3.2, in a stored string (RFC 3454 §7).
    Unassigned(char),
    /// Right-to-left characters that break the rules of RFC 3454 §6.
    Bidi,
}

impl fmt::Display for StringPrepError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StringPrepError::Prohibited(character) => {
                write!(formatter, "prohibited code point U+{:04X}", *character as u32)
            }
            StringPrepError::Unassigned(character) => {
                write!(formatter, "unassigned code point U+{:04X}", *character as u32)
            }
            StringPrepError::Bidi => formatter.write_str("invalid bidirectional text"),
        }
    }
}

impl core::error::Error for StringPrepError {}
