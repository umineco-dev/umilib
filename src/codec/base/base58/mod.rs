//! Base58: the encoding of a big-endian number in base 58, with each leading
//! zero byte written as the first character of the alphabet, as used by
//! Bitcoin addresses, IPFS and others.
//!
//! The conversion takes time quadratic in the length, so inputs are limited
//! by [`Base58::maximum_length`]. It is not constant-time.

use super::{Alphabet, AlphabetRange, BaseError, Encoding};

/// The Base58 encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base58 {
    pub alphabet: Alphabet,
    /// The longest input, in bytes when encoding and in characters when decoding.
    pub maximum_length: usize,
}

impl Base58 {
    /// The default limit of the input length.
    pub const DEFAULT_MAXIMUM_LENGTH: usize = 4096;

    /// The Bitcoin alphabet: digits and letters without `0`, `O`, `I` and `l`.
    pub const BITCOIN_ALPHABET: Alphabet = Alphabet::new(&[
        AlphabetRange::new(b'1', 9, 0),
        AlphabetRange::new(b'A', 8, 9),
        AlphabetRange::new(b'J', 5, 17),
        AlphabetRange::new(b'P', 11, 22),
        AlphabetRange::new(b'a', 11, 33),
        AlphabetRange::new(b'm', 14, 44),
    ]);
    /// The Flickr alphabet: the Bitcoin alphabet with lowercase letters first.
    pub const FLICKR_ALPHABET: Alphabet = Alphabet::new(&[
        AlphabetRange::new(b'1', 9, 0),
        AlphabetRange::new(b'a', 11, 9),
        AlphabetRange::new(b'm', 14, 20),
        AlphabetRange::new(b'A', 8, 34),
        AlphabetRange::new(b'J', 5, 42),
        AlphabetRange::new(b'P', 11, 47),
    ]);
    /// The Ripple alphabet.
    pub const RIPPLE_ALPHABET: Alphabet = Alphabet::new(&[
        AlphabetRange::new(b'r', 1, 0),
        AlphabetRange::new(b'p', 1, 1),
        AlphabetRange::new(b's', 1, 2),
        AlphabetRange::new(b'h', 1, 3),
        AlphabetRange::new(b'n', 1, 4),
        AlphabetRange::new(b'a', 1, 5),
        AlphabetRange::new(b'f', 1, 6),
        AlphabetRange::new(b'3', 1, 7),
        AlphabetRange::new(b'9', 1, 8),
        AlphabetRange::new(b'w', 1, 9),
        AlphabetRange::new(b'B', 1, 10),
        AlphabetRange::new(b'U', 1, 11),
        AlphabetRange::new(b'D', 1, 12),
        AlphabetRange::new(b'N', 1, 13),
        AlphabetRange::new(b'E', 1, 14),
        AlphabetRange::new(b'G', 2, 15),
        AlphabetRange::new(b'J', 4, 17),
        AlphabetRange::new(b'4', 1, 21),
        AlphabetRange::new(b'P', 5, 22),
        AlphabetRange::new(b'7', 1, 27),
        AlphabetRange::new(b'V', 5, 28),
        AlphabetRange::new(b'2', 1, 33),
        AlphabetRange::new(b'b', 4, 34),
        AlphabetRange::new(b'C', 1, 38),
        AlphabetRange::new(b'g', 1, 39),
        AlphabetRange::new(b'6', 1, 40),
        AlphabetRange::new(b'5', 1, 41),
        AlphabetRange::new(b'j', 2, 42),
        AlphabetRange::new(b'm', 1, 44),
        AlphabetRange::new(b'8', 1, 45),
        AlphabetRange::new(b'o', 1, 46),
        AlphabetRange::new(b'F', 1, 47),
        AlphabetRange::new(b'q', 1, 48),
        AlphabetRange::new(b'i', 1, 49),
        AlphabetRange::new(b'1', 1, 50),
        AlphabetRange::new(b't', 3, 51),
        AlphabetRange::new(b'A', 1, 54),
        AlphabetRange::new(b'x', 3, 55),
    ]);

    pub const BITCOIN: Base58 = Base58::new(Base58::BITCOIN_ALPHABET);
    pub const FLICKR: Base58 = Base58::new(Base58::FLICKR_ALPHABET);
    pub const RIPPLE: Base58 = Base58::new(Base58::RIPPLE_ALPHABET);

    /// A Base58 encoding with `alphabet` (58 values) and the default length limit.
    pub const fn new(alphabet: Alphabet) -> Base58 {
        Base58 { alphabet, maximum_length: Base58::DEFAULT_MAXIMUM_LENGTH }
    }

    /// The same encoding with another length limit.
    pub const fn with_maximum_length(self, maximum_length: usize) -> Base58 {
        Base58 { alphabet: self.alphabet, maximum_length }
    }

    /// Fails if `length` exceeds the limit.
    pub fn check_length(&self, length: usize) -> Result<(), BaseError> {
        if length > self.maximum_length {
            return Err(BaseError::InputTooLong { length, maximum: self.maximum_length });
        }
        Ok(())
    }
}

impl Encoding for Base58 {
    fn maximum_encoded_length(&self, length: usize) -> Option<usize> {
        // log(256) / log(58) < 1.37, so 137 characters per 100 bytes suffice.
        length.checked_mul(137).map(|digits| digits / 100 + 1)
    }

    fn maximum_decoded_length(&self, length: usize) -> usize {
        // Every character encodes less than one byte.
        length
    }

    fn encode_to_slice(&self, input: &[u8], output: &mut [u8]) -> Result<usize, BaseError> {
        self.check_length(input.len())?;
        let zeros = input.iter().take_while(|&&byte| byte == 0).count();
        let zero_character = self.alphabet.encode(0);
        if output.len() < zeros {
            return Err(BaseError::OutputTooSmall { needed: zeros, available: output.len() });
        }
        output[..zeros].fill(zero_character);
        // Digits in base 58, least significant first, after the leading zeros.
        let digits = &mut output[zeros..];
        let mut count = 0;
        for &byte in &input[zeros..] {
            let mut carry = byte as u32;
            for digit in digits[..count].iter_mut() {
                carry += (*digit as u32) << 8;
                *digit = (carry % 58) as u8;
                carry /= 58;
            }
            while carry > 0 {
                if count == digits.len() {
                    let needed = self.maximum_encoded_length(input.len()).unwrap_or(usize::MAX);
                    return Err(BaseError::OutputTooSmall { needed, available: zeros + digits.len() });
                }
                digits[count] = (carry % 58) as u8;
                count += 1;
                carry /= 58;
            }
        }
        digits[..count].reverse();
        for digit in digits[..count].iter_mut() {
            *digit = self.alphabet.encode(*digit);
        }
        Ok(zeros + count)
    }

    fn decode_to_slice(&self, input: &[u8], output: &mut [u8]) -> Result<usize, BaseError> {
        self.check_length(input.len())?;
        let zero_character = self.alphabet.encode(0);
        let zeros = input.iter().take_while(|&&character| character == zero_character).count();
        if output.len() < zeros {
            return Err(BaseError::OutputTooSmall { needed: zeros, available: output.len() });
        }
        output[..zeros].fill(0);
        // Bytes, least significant first, after the leading zeros.
        let bytes = &mut output[zeros..];
        let mut count = 0;
        for (position, &character) in input.iter().enumerate().skip(zeros) {
            let value = self.alphabet.decode(character).ok_or(BaseError::InvalidCharacter { position, character })?;
            let mut carry = value as u32;
            for byte in bytes[..count].iter_mut() {
                carry += *byte as u32 * 58;
                *byte = carry as u8;
                carry >>= 8;
            }
            while carry > 0 {
                if count == bytes.len() {
                    return Err(BaseError::OutputTooSmall { needed: input.len(), available: zeros + bytes.len() });
                }
                bytes[count] = carry as u8;
                count += 1;
                carry >>= 8;
            }
        }
        bytes[..count].reverse();
        Ok(zeros + count)
    }
}
