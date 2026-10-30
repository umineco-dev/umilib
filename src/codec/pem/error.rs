use core::fmt;

use crate::codec::base::BaseError;

/// An error of PEM parsing. Positions are byte offsets in the text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PEMError {
    /// The text contains no BEGIN line.
    NotFound,
    /// The label at `position` contains characters RFC 7468 section 3 does not allow.
    InvalidLabel { position: usize },
    /// The BEGIN line at `position` has no END line.
    MissingEnd { position: usize },
    /// The END line at `position` has another label than the BEGIN line.
    LabelMismatch { position: usize },
    /// The line at `position` does not follow the chosen grammar.
    InvalidLine { position: usize },
    /// The base64 text of the document is invalid.
    Base64(BaseError),
    /// The text is longer than `maximum` bytes.
    TooLong { length: usize, maximum: usize },
    /// The memory for the data could not be allocated.
    AllocationFailed,
}

impl fmt::Display for PEMError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PEMError::NotFound => formatter.write_str("no PEM document found"),
            PEMError::InvalidLabel { position } => write!(formatter, "invalid label at {position}"),
            PEMError::MissingEnd { position } => write!(formatter, "the document at {position} has no END line"),
            PEMError::LabelMismatch { position } => write!(formatter, "the END line at {position} has another label"),
            PEMError::InvalidLine { position } => write!(formatter, "invalid line at {position}"),
            PEMError::Base64(error) => write!(formatter, "invalid base64 text: {error}"),
            PEMError::TooLong { length, maximum } => {
                write!(formatter, "text of {length} bytes is longer than the maximum of {maximum}")
            }
            PEMError::AllocationFailed => formatter.write_str("allocation failed"),
        }
    }
}

impl core::error::Error for PEMError {}

impl From<BaseError> for PEMError {
    fn from(error: BaseError) -> PEMError {
        PEMError::Base64(error)
    }
}
