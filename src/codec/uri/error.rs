use core::fmt;

/// An error of reading a URI or a form. Positions are byte offsets in the text read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum URIError {
    /// Text not of the grammar of RFC 3986 at `position`.
    Syntax { position: usize, reason: &'static str },
    /// A `%` not followed by two hexadecimal digits at `position` (§2.1).
    Percent { position: usize },
    /// Decoded octets that are not UTF-8, where text is read.
    UTF8,
    /// Resolution against a base that is not an absolute URI (§5.2.1).
    NotAbsolute,
}

impl fmt::Display for URIError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            URIError::Syntax { position, reason } => write!(formatter, "not a URI at {position}: {reason}"),
            URIError::Percent { position } => write!(formatter, "a % not of two hexadecimal digits at {position}"),
            URIError::UTF8 => formatter.write_str("decoded octets that are not UTF-8"),
            URIError::NotAbsolute => formatter.write_str("a base that is not an absolute URI"),
        }
    }
}
