use alloc::vec::Vec;

use crate::bytes::{Buffer, Reader, Writer};

use super::TLSError;

/// The vectors of the TLS presentation language (RFC 9846 §3.4): a length
/// of 1, 2 or 3 bytes, then that many bytes. Reads check the length's
/// bounds and fail with `decode_error`, as RFC 9846 §4 requires of
/// malformed messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TLSVector;

impl TLSVector {
    /// Reads a vector of `size` length bytes whose length is in `minimum..=maximum`.
    pub fn read<'a>(
        reader: &mut Reader<'a>,
        size: usize,
        minimum: usize,
        maximum: usize,
    ) -> Result<&'a [u8], TLSError> {
        let length: u32 = reader.read_be_sized(size).map_err(|_| TLSError::decode())?;
        let length = length as usize;
        if length < minimum || length > maximum {
            return Err(TLSError::decode());
        }
        reader.read_slice(length).map_err(|_| TLSError::decode())
    }

    /// [`TLSVector::read`] as a reader of its content.
    pub fn read_reader<'a>(
        reader: &mut Reader<'a>,
        size: usize,
        minimum: usize,
        maximum: usize,
    ) -> Result<Reader<'a>, TLSError> {
        TLSVector::read(reader, size, minimum, maximum).map(Reader::new)
    }

    /// Writes `content` as a vector of `size` length bytes; fails with
    /// `internal_error` if it is longer than `maximum`.
    pub fn write(out: &mut impl Writer, size: usize, maximum: usize, content: &[u8]) -> Result<(), TLSError> {
        if content.len() > maximum {
            return Err(TLSError::Protocol(super::TLSAlertDescription::INTERNAL_ERROR));
        }
        out.write_be_sized(content.len() as u32, size)?;
        out.write(content)?;
        Ok(())
    }

    /// Writes what `write` writes as a vector of `size` length bytes.
    pub fn write_with(
        out: &mut impl Writer,
        size: usize,
        maximum: usize,
        write: impl FnOnce(&mut Buffer) -> Result<(), TLSError>,
    ) -> Result<(), TLSError> {
        let mut content = Buffer::new();
        write(&mut content)?;
        TLSVector::write(out, size, maximum, content.as_slice())
    }

    /// Reads a vector of 16-bit values whose length in bytes is in
    /// `minimum..=maximum` and even.
    pub fn read_u16s(
        reader: &mut Reader<'_>,
        size: usize,
        minimum: usize,
        maximum: usize,
    ) -> Result<Vec<u16>, TLSError> {
        let content = TLSVector::read(reader, size, minimum, maximum)?;
        if content.len() % 2 != 0 {
            return Err(TLSError::decode());
        }
        Ok(content.as_chunks::<2>().0.iter().map(|pair| u16::from_be_bytes(*pair)).collect())
    }

    /// Writes 16-bit values as a vector of `size` length bytes.
    pub fn write_u16s(out: &mut impl Writer, size: usize, maximum: usize, values: &[u16]) -> Result<(), TLSError> {
        TLSVector::write_with(out, size, maximum, |content| {
            for value in values {
                content.write_be(*value)?;
            }
            Ok(())
        })
    }

    /// Fails with `decode_error` unless every byte of `reader` was read.
    pub fn finish(reader: &Reader<'_>) -> Result<(), TLSError> {
        if reader.is_empty() { Ok(()) } else { Err(TLSError::decode()) }
    }

    /// Whether a value of `values` appears twice: in O(n log n), since a
    /// peer sends thousands of entries in a handshake message of 64 KiB.
    pub fn repeats(mut values: Vec<u16>) -> bool {
        values.sort_unstable();
        values.windows(2).any(|pair| pair[0] == pair[1])
    }
}
