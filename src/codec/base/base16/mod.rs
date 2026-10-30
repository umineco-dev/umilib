//! Base16 (hexadecimal), RFC 4648 section 8.

use super::{Alphabet, AlphabetRange, BaseError, BitEncoding, Encoding, Padding};

/// The Base16 encoding. Decoding accepts both letter cases; encoding writes
/// the case of the preset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base16 {
    pub encoding: BitEncoding,
}

impl Base16 {
    /// Uppercase digits, as specified by RFC 4648.
    pub const UPPER: Base16 = Base16::new(Alphabet::new(&[
        AlphabetRange::new(b'0', 10, 0),
        AlphabetRange::new(b'A', 6, 10),
        AlphabetRange::decode_only(b'a', 6, 10),
    ]));
    /// Lowercase digits.
    pub const LOWER: Base16 = Base16::new(Alphabet::new(&[
        AlphabetRange::new(b'0', 10, 0),
        AlphabetRange::new(b'a', 6, 10),
        AlphabetRange::decode_only(b'A', 6, 10),
    ]));

    /// A Base16 encoding with `alphabet`, which must encode 16 values.
    pub const fn new(alphabet: Alphabet) -> Base16 {
        Base16 { encoding: BitEncoding { alphabet, bits: 4, padding: Padding::Forbidden, padding_character: b'=' } }
    }
}

impl Encoding for Base16 {
    fn maximum_encoded_length(&self, length: usize) -> Option<usize> {
        self.encoding.maximum_encoded_length(length)
    }

    fn maximum_decoded_length(&self, length: usize) -> usize {
        self.encoding.maximum_decoded_length(length)
    }

    fn encode_to_slice(&self, input: &[u8], output: &mut [u8]) -> Result<usize, BaseError> {
        self.encoding.encode_to_slice(input, output)
    }

    fn decode_to_slice(&self, input: &[u8], output: &mut [u8]) -> Result<usize, BaseError> {
        self.encoding.decode_to_slice(input, output)
    }
}
