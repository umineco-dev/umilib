//! Base64, RFC 4648 sections 4 (standard alphabet) and 5 (URL and filename safe alphabet).

use super::{Alphabet, AlphabetRange, BaseError, BitEncoding, Encoding, Padding};

/// The Base64 encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base64 {
    pub encoding: BitEncoding,
}

impl Base64 {
    /// The standard alphabet `A`–`Z`, `a`–`z`, `0`–`9`, `+`, `/`.
    pub const STANDARD_ALPHABET: Alphabet = Alphabet::new(&[
        AlphabetRange::new(b'A', 26, 0),
        AlphabetRange::new(b'a', 26, 26),
        AlphabetRange::new(b'0', 10, 52),
        AlphabetRange::new(b'+', 1, 62),
        AlphabetRange::new(b'/', 1, 63),
    ]);
    /// The URL and filename safe alphabet, with `-` and `_` instead of `+` and `/`.
    pub const URL_SAFE_ALPHABET: Alphabet = Alphabet::new(&[
        AlphabetRange::new(b'A', 26, 0),
        AlphabetRange::new(b'a', 26, 26),
        AlphabetRange::new(b'0', 10, 52),
        AlphabetRange::new(b'-', 1, 62),
        AlphabetRange::new(b'_', 1, 63),
    ]);

    /// The standard alphabet with padding (RFC 4648 section 4).
    pub const STANDARD: Base64 = Base64::new(Base64::STANDARD_ALPHABET, Padding::Required);
    /// The standard alphabet without padding.
    pub const STANDARD_NO_PADDING: Base64 = Base64::new(Base64::STANDARD_ALPHABET, Padding::Forbidden);
    /// The URL and filename safe alphabet with padding (RFC 4648 section 5).
    pub const URL_SAFE: Base64 = Base64::new(Base64::URL_SAFE_ALPHABET, Padding::Required);
    /// The URL and filename safe alphabet without padding, as used by JWT (RFC 7515 section 2).
    pub const URL_SAFE_NO_PADDING: Base64 = Base64::new(Base64::URL_SAFE_ALPHABET, Padding::Forbidden);

    /// A Base64 encoding with `alphabet` (64 values) and `padding`.
    pub const fn new(alphabet: Alphabet, padding: Padding) -> Base64 {
        Base64 { encoding: BitEncoding { alphabet, bits: 6, padding, padding_character: b'=' } }
    }
}

impl Encoding for Base64 {
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
