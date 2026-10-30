use core::fmt;

/// An error of ASN.1 encoding or decoding. Positions are byte offsets in the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ASN1Error {
    /// The input ends inside the element at `position`.
    UnexpectedEnd { position: usize },
    /// The identifier octets at `position` are invalid or not minimal.
    InvalidTag { position: usize },
    /// The length octets at `position` are invalid, or not minimal in DER.
    InvalidLength { position: usize },
    /// The element at `position` has another tag than expected.
    UnexpectedTag { position: usize },
    /// The contents of the element at `position` are invalid for its type.
    InvalidContent { position: usize },
    /// The element at `position` uses a form DER does not allow (indefinite
    /// length, constructed string, non-canonical value or order).
    NonCanonical { position: usize },
    /// Data follows the last expected element at `position`.
    TrailingData { position: usize },
    /// Elements nest deeper than `maximum` at `position`.
    TooDeep { position: usize, maximum: usize },
    /// A value does not fit in the requested type.
    OutOfRange,
    /// The memory for a value could not be allocated.
    AllocationFailed,
}

impl fmt::Display for ASN1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ASN1Error::UnexpectedEnd { position } => {
                write!(formatter, "unexpected end of input in the element at {position}")
            }
            ASN1Error::InvalidTag { position } => write!(formatter, "invalid tag at {position}"),
            ASN1Error::InvalidLength { position } => write!(formatter, "invalid length at {position}"),
            ASN1Error::UnexpectedTag { position } => write!(formatter, "unexpected tag at {position}"),
            ASN1Error::InvalidContent { position } => write!(formatter, "invalid contents at {position}"),
            ASN1Error::NonCanonical { position } => write!(formatter, "non-canonical encoding at {position}"),
            ASN1Error::TrailingData { position } => write!(formatter, "trailing data at {position}"),
            ASN1Error::TooDeep { position, maximum } => {
                write!(formatter, "nesting deeper than {maximum} at {position}")
            }
            ASN1Error::OutOfRange => formatter.write_str("value out of range"),
            ASN1Error::AllocationFailed => formatter.write_str("allocation failed"),
        }
    }
}

impl core::error::Error for ASN1Error {}
