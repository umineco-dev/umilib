use alloc::string::String;
use alloc::vec::Vec;

use super::BaseError;

/// A binary-to-text encoding.
pub trait Encoding {
    /// The largest number of characters encoding `length` bytes can produce,
    /// or `None` if it does not fit in `usize`. It is exact for Base16, Base32
    /// and Base64.
    fn maximum_encoded_length(&self, length: usize) -> Option<usize>;

    /// The largest number of bytes decoding `length` characters can produce.
    fn maximum_decoded_length(&self, length: usize) -> usize;

    /// Encodes `input` into the start of `output` and returns the number of characters written.
    fn encode_to_slice(&self, input: &[u8], output: &mut [u8]) -> Result<usize, BaseError>;

    /// Decodes `input` into the start of `output` and returns the number of
    /// bytes written. On failure, `output` may have been partly overwritten.
    fn decode_to_slice(&self, input: &[u8], output: &mut [u8]) -> Result<usize, BaseError>;

    /// Encodes `input` into a new string, failing only if memory cannot be allocated.
    fn try_encode(&self, input: &[u8]) -> Result<String, BaseError> {
        let length =
            self.maximum_encoded_length(input.len()).ok_or(BaseError::AllocationFailed { length: usize::MAX })?;
        let mut output = Vec::new();
        output.try_reserve_exact(length).map_err(|_| BaseError::AllocationFailed { length })?;
        output.resize(length, 0);
        let written = self.encode_to_slice(input, &mut output)?;
        output.truncate(written);
        // Every encoding writes ASCII characters only.
        String::from_utf8(output).map_err(|_| BaseError::InvalidLength { length: written })
    }

    /// Encodes `input` into a new string. Panics if memory cannot be allocated.
    fn encode(&self, input: &[u8]) -> String {
        match self.try_encode(input) {
            Ok(text) => text,
            Err(error) => panic!("encoding failed: {error}"),
        }
    }

    /// Decodes `input` into a new vector.
    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, BaseError> {
        let length = self.maximum_decoded_length(input.len());
        let mut output = Vec::new();
        output.try_reserve_exact(length).map_err(|_| BaseError::AllocationFailed { length })?;
        output.resize(length, 0);
        let written = self.decode_to_slice(input, &mut output)?;
        output.truncate(written);
        Ok(output)
    }
}
