//! Base32, RFC 4648 sections 6 (standard alphabet) and 7 ("Extended Hex" alphabet).

use super::{Alphabet, AlphabetRange, BaseError, BitEncoding, Encoding, Padding};

/// The Base32 encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base32 {
    pub encoding: BitEncoding,
}

impl Base32 {
    /// The standard alphabet `A`–`Z`, `2`–`7`.
    pub const STANDARD_ALPHABET: Alphabet =
        Alphabet::new(&[AlphabetRange::new(b'A', 26, 0), AlphabetRange::new(b'2', 6, 26)]);
    /// The standard alphabet, also accepting lowercase letters when decoding.
    pub const STANDARD_ALPHABET_ANY_CASE: Alphabet = Alphabet::new(&[
        AlphabetRange::new(b'A', 26, 0),
        AlphabetRange::new(b'2', 6, 26),
        AlphabetRange::decode_only(b'a', 26, 0),
    ]);
    /// The "Extended Hex" alphabet `0`–`9`, `A`–`V`, which preserves sort order.
    pub const HEX_ALPHABET: Alphabet =
        Alphabet::new(&[AlphabetRange::new(b'0', 10, 0), AlphabetRange::new(b'A', 22, 10)]);
    /// The "Extended Hex" alphabet, also accepting lowercase letters when decoding.
    pub const HEX_ALPHABET_ANY_CASE: Alphabet = Alphabet::new(&[
        AlphabetRange::new(b'0', 10, 0),
        AlphabetRange::new(b'A', 22, 10),
        AlphabetRange::decode_only(b'a', 22, 10),
    ]);

    /// The standard alphabet with padding (RFC 4648 section 6).
    pub const STANDARD: Base32 = Base32::new(Base32::STANDARD_ALPHABET, Padding::Required);
    /// The standard alphabet without padding.
    pub const STANDARD_NO_PADDING: Base32 = Base32::new(Base32::STANDARD_ALPHABET, Padding::Forbidden);
    /// The "Extended Hex" alphabet with padding (RFC 4648 section 7).
    pub const HEX: Base32 = Base32::new(Base32::HEX_ALPHABET, Padding::Required);
    /// The "Extended Hex" alphabet without padding.
    pub const HEX_NO_PADDING: Base32 = Base32::new(Base32::HEX_ALPHABET, Padding::Forbidden);

    /// A Base32 encoding with `alphabet` (32 values) and `padding`.
    pub const fn new(alphabet: Alphabet, padding: Padding) -> Base32 {
        Base32 { encoding: BitEncoding { alphabet, bits: 5, padding, padding_character: b'=' } }
    }
}

impl Encoding for Base32 {
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
