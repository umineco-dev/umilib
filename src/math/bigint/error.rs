use core::fmt;

/// An error of big integer or modular arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MathError {
    /// The value does not fit in the precision or the output.
    Overflow,
    /// The operands have different precisions.
    SizeMismatch,
    /// The divisor is zero.
    DivisionByZero,
    /// The value has no inverse for the modulus.
    NotInvertible,
    /// The modulus is even or smaller than 3, which Montgomery arithmetic does not allow.
    InvalidModulus,
    /// The text is not a hexadecimal number.
    InvalidDigit { position: usize },
    /// The requested precision in bits exceeds `maximum`.
    InvalidPrecision { precision: u32, maximum: u32 },
    /// Memory for the value could not be allocated.
    AllocationFailed,
}

impl fmt::Display for MathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MathError::Overflow => formatter.write_str("value does not fit"),
            MathError::SizeMismatch => formatter.write_str("operands have different precisions"),
            MathError::DivisionByZero => formatter.write_str("division by zero"),
            MathError::NotInvertible => formatter.write_str("value is not invertible"),
            MathError::InvalidModulus => formatter.write_str("modulus must be odd and at least 3"),
            MathError::InvalidDigit { position } => write!(formatter, "invalid hexadecimal digit at {position}"),
            MathError::InvalidPrecision { precision, maximum } => {
                write!(formatter, "precision of {precision} bits exceeds the maximum of {maximum}")
            }
            MathError::AllocationFailed => formatter.write_str("allocation failed"),
        }
    }
}

impl core::error::Error for MathError {}
