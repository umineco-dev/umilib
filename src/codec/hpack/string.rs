use alloc::vec::Vec;

use super::{HPACKError, HPACKHuffman, HPACKInteger};

/// The string literals of HPACK and QPACK (RFC 7541 §5.2, RFC 9204
/// §4.1.2): a flag H, the Huffman code, just above an N-bit prefix of the
/// length, then the bytes, plain or Huffman-coded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HPACKString;

impl HPACKString {
    /// Writes `bytes` with an N-bit prefix of the length (7 in HPACK), the H
    /// flag above it and `flags` in the bits above that; Huffman-coded with
    /// `huffman` if given and shorter.
    pub fn write(out: &mut Vec<u8>, prefix: u32, flags: u8, bytes: &[u8], huffman: Option<&HPACKHuffman>) {
        let flag = 1u8 << prefix;
        let flags = flags & !(flag | (flag - 1));
        match huffman.filter(|huffman| huffman.encoded_length(bytes) < bytes.len()) {
            Some(huffman) => {
                HPACKInteger::write(out, prefix, flags | flag, huffman.encoded_length(bytes) as u64);
                huffman.encode(bytes, out);
            }
            None => {
                HPACKInteger::write(out, prefix, flags, bytes.len() as u64);
                out.extend_from_slice(bytes);
            }
        }
    }

    /// Reads a string of an N-bit prefix from the front of `input`, advancing
    /// it; returns the bits above the H flag and the bytes, decoded with
    /// `huffman` if coded. Fails if the string is cut short, its code is
    /// invalid, or it is longer than `limit` bytes, coded or decoded.
    pub fn read(
        input: &mut &[u8],
        prefix: u32,
        huffman: &HPACKHuffman,
        limit: usize,
    ) -> Result<(u8, Vec<u8>), HPACKError> {
        let mut rest = *input;
        let (flags, length) = HPACKInteger::read(&mut rest, prefix)?;
        let flag = 1u8 << prefix;
        let coded = flags & flag != 0;
        if length > limit as u64 {
            return Err(HPACKError::StringTooLong);
        }
        let length = length as usize;
        if rest.len() < length {
            return Err(HPACKError::Truncated);
        }
        let (bytes, after) = rest.split_at(length);
        let value = if coded {
            let mut decoded = Vec::with_capacity(length + length / 2);
            huffman.decode(bytes, &mut decoded, limit)?;
            decoded
        } else {
            bytes.to_vec()
        };
        *input = after;
        Ok((flags & !(flag | (flag - 1)), value))
    }
}
