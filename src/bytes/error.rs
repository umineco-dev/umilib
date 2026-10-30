use core::fmt;

/// An error from [`Reader`](super::Reader) or a [`Writer`](super::Writer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BytesError {
    /// The input ended before `needed` bytes could be read.
    UnexpectedEnd { needed: usize, remaining: usize },
    /// Writing `requested` more bytes would exceed the capacity `limit`.
    CapacityExceeded { requested: usize, limit: usize },
    /// The value does not fit in the requested number of bytes.
    ValueTooLarge { length: usize },
    /// The requested length is zero or larger than the integer type.
    InvalidLength { length: usize, maximum: usize },
    /// A line of at least `length` bytes, more than the `maximum` taken.
    LineTooLong { length: usize, maximum: usize },
}

impl fmt::Display for BytesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BytesError::UnexpectedEnd { needed, remaining } => {
                write!(formatter, "unexpected end of input: needed {needed} bytes, {remaining} remaining")
            }
            BytesError::CapacityExceeded { requested, limit } => {
                write!(formatter, "capacity exceeded: {requested} more bytes requested, limit is {limit}")
            }
            BytesError::ValueTooLarge { length } => write!(formatter, "value does not fit in {length} bytes"),
            BytesError::InvalidLength { length, maximum } => {
                write!(formatter, "invalid integer length {length}: must be between 1 and {maximum}")
            }
            BytesError::LineTooLong { length, maximum } => {
                write!(formatter, "a line of {length} bytes, longer than the maximum of {maximum}")
            }
        }
    }
}

impl core::error::Error for BytesError {}
