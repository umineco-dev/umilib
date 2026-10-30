use crate::codec::CompressionError;
use crate::ffi::{Status, ToStatus};

/// The statuses of [`CompressionError`], one per variant (the reason of
/// `InvalidData` and the feature of `Unsupported` are not carried).
pub struct CompressionStatus;

impl CompressionStatus {
    pub const INVALID_DATA: Status =
        Status::new(c"codec", c"InvalidData", c"the compressed data do not follow their format");
    pub const CHECKSUM_MISMATCH: Status =
        Status::new(c"codec", c"ChecksumMismatch", c"a checksum does not match the data");
    pub const LIMIT_EXCEEDED: Status = Status::new(c"codec", c"LimitExceeded", c"the data exceed the configured limit");
    pub const UNEXPECTED_END: Status =
        Status::new(c"codec", c"UnexpectedEnd", c"the input ended inside the compressed data");
    pub const INVALID_PARAMETER: Status =
        Status::new(c"codec", c"InvalidParameter", c"a parameter is outside what the format allows");
    pub const MISSING_DICTIONARY: Status =
        Status::new(c"codec", c"MissingDictionary", c"the stream needs a preset dictionary it was not given");
    pub const ALLOCATION: Status = Status::new(c"codec", c"Allocation", c"memory could not be allocated");
    pub const UNSUPPORTED: Status =
        Status::new(c"codec", c"Unsupported", c"the stream uses a feature this implementation does not support");
}

impl ToStatus for CompressionError {
    fn to_status(&self) -> &'static Status {
        match self {
            CompressionError::InvalidData { .. } => &CompressionStatus::INVALID_DATA,
            CompressionError::ChecksumMismatch => &CompressionStatus::CHECKSUM_MISMATCH,
            CompressionError::LimitExceeded { .. } => &CompressionStatus::LIMIT_EXCEEDED,
            CompressionError::UnexpectedEnd => &CompressionStatus::UNEXPECTED_END,
            CompressionError::InvalidParameter => &CompressionStatus::INVALID_PARAMETER,
            CompressionError::MissingDictionary { .. } => &CompressionStatus::MISSING_DICTIONARY,
            CompressionError::Allocation => &CompressionStatus::ALLOCATION,
            CompressionError::Unsupported { .. } => &CompressionStatus::UNSUPPORTED,
        }
    }
}
