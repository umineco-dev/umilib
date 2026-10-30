use core::fmt;

/// An error of the lattice arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LatticeError {
    /// An input or output has `length` elements or bytes instead of `expected`.
    InvalidLength { length: usize, expected: usize },
    /// A width of `bits` bits outside 1 to 32.
    InvalidBits { bits: u32 },
}

impl fmt::Display for LatticeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LatticeError::InvalidLength { length, expected } => {
                write!(formatter, "length {length} instead of {expected}")
            }
            LatticeError::InvalidBits { bits } => write!(formatter, "{bits} bits, not 1 to 32"),
        }
    }
}

impl core::error::Error for LatticeError {}
