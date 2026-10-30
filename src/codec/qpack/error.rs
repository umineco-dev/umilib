use core::fmt;

use crate::codec::hpack::HPACKError;

/// Why QPACK failed (RFC 9204 §6): a field section, the encoder stream or
/// the decoder stream broke a rule, each with its HTTP/3 error code; or a
/// field section larger than the decoder takes, which ends only its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QPACKError {
    /// QPACK_DECOMPRESSION_FAILED: a field section cannot be decoded.
    DecompressionFailed(&'static str),
    /// QPACK_ENCODER_STREAM_ERROR: an encoder instruction cannot be processed.
    EncoderStream(&'static str),
    /// QPACK_DECODER_STREAM_ERROR: a decoder instruction cannot be processed.
    DecoderStream(&'static str),
    /// A field section larger than the decoder's limit (RFC 9114 §4.2.2).
    FieldListTooLarge,
}

impl QPACKError {
    pub const DECOMPRESSION_FAILED: u64 = 0x200;
    pub const ENCODER_STREAM_ERROR: u64 = 0x201;
    pub const DECODER_STREAM_ERROR: u64 = 0x202;

    /// The HTTP/3 error code; `None` for an error of the stream alone.
    pub const fn code(self) -> Option<u64> {
        match self {
            QPACKError::DecompressionFailed(_) => Some(QPACKError::DECOMPRESSION_FAILED),
            QPACKError::EncoderStream(_) => Some(QPACKError::ENCODER_STREAM_ERROR),
            QPACKError::DecoderStream(_) => Some(QPACKError::DECODER_STREAM_ERROR),
            QPACKError::FieldListTooLarge => None,
        }
    }

    /// The error of a field section for an error of HPACK's primitives.
    pub fn section(error: HPACKError) -> QPACKError {
        match error {
            HPACKError::FieldListTooLarge => QPACKError::FieldListTooLarge,
            _ => QPACKError::DecompressionFailed("a field line that does not decode"),
        }
    }
}

impl fmt::Display for QPACKError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QPACKError::DecompressionFailed(reason) => write!(formatter, "QPACK decompression failed: {reason}"),
            QPACKError::EncoderStream(reason) => write!(formatter, "QPACK encoder stream error: {reason}"),
            QPACKError::DecoderStream(reason) => write!(formatter, "QPACK decoder stream error: {reason}"),
            QPACKError::FieldListTooLarge => formatter.write_str("a field section larger than the limit"),
        }
    }
}

impl core::error::Error for QPACKError {}
