use core::fmt;

/// An error of a Huffman code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HuffmanError {
    /// The code lengths give more codes of some length than exist
    /// (Σ 2^-length > 1), or a length above `maximum`.
    InvalidLengths { maximum: u32 },
    /// The alphabet has no symbol, or more than `maximum`.
    InvalidAlphabet { maximum: usize },
    /// The bits are not a code of the table (of an incomplete code).
    InvalidCode,
}

impl fmt::Display for HuffmanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HuffmanError::InvalidLengths { maximum } => {
                write!(formatter, "code lengths are over-subscribed or above {maximum}")
            }
            HuffmanError::InvalidAlphabet { maximum } => {
                write!(formatter, "the alphabet must have 1 to {maximum} symbols")
            }
            HuffmanError::InvalidCode => formatter.write_str("bits are not a code"),
        }
    }
}

impl core::error::Error for HuffmanError {}
