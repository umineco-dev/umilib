use core::fmt;

/// An error in the parameters of a hash function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashError {
    /// An output of `length` bytes is outside `minimum..=maximum`.
    OutputLength { length: usize, minimum: usize, maximum: usize },
    /// A key of `length` bytes is outside `minimum..=maximum`.
    KeyLength { length: usize, minimum: usize, maximum: usize },
    /// A parameter is outside the range the function allows.
    InvalidParameter,
}

impl fmt::Display for HashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashError::OutputLength { length, minimum, maximum } => {
                write!(formatter, "output length {length} is outside {minimum} to {maximum}")
            }
            HashError::KeyLength { length, minimum, maximum } => {
                write!(formatter, "key length {length} is outside {minimum} to {maximum}")
            }
            HashError::InvalidParameter => formatter.write_str("invalid parameter"),
        }
    }
}

impl core::error::Error for HashError {}
