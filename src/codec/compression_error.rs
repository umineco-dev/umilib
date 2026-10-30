use core::fmt;

/// An error of a [`Compressor`](super::Compressor) or a [`Decompressor`](super::Decompressor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionError {
    /// The compressed data does not follow its format; `reason` says how.
    InvalidData { reason: &'static str },
    /// A checksum of the format does not match the data.
    ChecksumMismatch,
    /// The data would exceed the limit of `limit` bytes the decompressor was
    /// configured with (its output, or the window a stream asks for).
    LimitExceeded { limit: u64 },
    /// The input ended inside the compressed data.
    UnexpectedEnd,
    /// A parameter (a level, a size, a dictionary) is outside what the format allows.
    InvalidParameter,
    /// The stream needs a preset dictionary, which the decompressor was not
    /// given, or was given another one; `identifier` is what the stream names
    /// it by (the Adler-32 of a zlib dictionary).
    MissingDictionary { identifier: u32 },
    /// Memory for a buffer could not be allocated.
    Allocation,
    /// The stream uses a feature its format reserves or allows but this
    /// implementation does not support (a reserved check or field, an
    /// unknown filter); `feature` says which. The data may be intact.
    Unsupported { feature: &'static str },
}

impl fmt::Display for CompressionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompressionError::InvalidData { reason } => write!(formatter, "invalid compressed data: {reason}"),
            CompressionError::ChecksumMismatch => formatter.write_str("checksum mismatch"),
            CompressionError::LimitExceeded { limit } => write!(formatter, "limit of {limit} bytes exceeded"),
            CompressionError::UnexpectedEnd => formatter.write_str("unexpected end of compressed data"),
            CompressionError::InvalidParameter => formatter.write_str("invalid parameter"),
            CompressionError::MissingDictionary { identifier } => {
                write!(formatter, "the dictionary {identifier:#010x} is needed")
            }
            CompressionError::Allocation => formatter.write_str("allocation failed"),
            CompressionError::Unsupported { feature } => write!(formatter, "unsupported feature: {feature}"),
        }
    }
}

impl core::error::Error for CompressionError {}
