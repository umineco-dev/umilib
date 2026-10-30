use super::{Alphabet, BaseError, Encoding, Padding};

/// An encoding that writes every `bits` bits of input as one character, in
/// groups that end on a byte boundary (RFC 4648): Base16 (4 bits), Base32
/// (5 bits) and Base64 (6 bits).
///
/// Decoding is strict: characters outside the alphabet, misplaced or
/// unexpected padding, impossible lengths and set unused bits (non-canonical
/// text, RFC 4648 section 3.5) are errors. The padding and the length are
/// checked first, then the characters in order, then the unused bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitEncoding {
    pub alphabet: Alphabet,
    /// Bits per character: 1 to 7, and `2^bits` must be the alphabet size.
    pub bits: u32,
    pub padding: Padding,
    pub padding_character: u8,
}

impl BitEncoding {
    /// Whether the fields form an encoding: 1 to 7 bits per character, an
    /// alphabet of exactly `2^bits` characters, and a padding character that
    /// is not in the alphabet (otherwise text could not be told from padding).
    pub fn is_valid(&self) -> bool {
        (1..=7).contains(&self.bits)
            && self.alphabet.size() == 1 << self.bits
            && self.alphabet.decode(self.padding_character).is_none()
    }

    /// The number of characters in a group: the smallest multiple of `bits`
    /// that is also a multiple of 8, divided by `bits`.
    pub const fn group_characters(&self) -> usize {
        let mut characters = 1;
        while !(characters * self.bits as usize).is_multiple_of(8) {
            characters += 1;
        }
        characters
    }

    /// The number of bytes in a group.
    pub const fn group_bytes(&self) -> usize {
        self.group_characters() * self.bits as usize / 8
    }

    /// Whether `remainder` characters can end the text after the last full group.
    pub const fn is_valid_remainder(&self, remainder: usize) -> bool {
        // A remainder is valid when its last character carries at least one
        // bit of data: the bits left after the last whole byte are fewer than
        // the bits of one character.
        remainder == 0 || (remainder * self.bits as usize) % 8 < self.bits as usize
    }
}

impl Encoding for BitEncoding {
    fn maximum_encoded_length(&self, length: usize) -> Option<usize> {
        let groups = length / self.group_bytes();
        let remainder = length % self.group_bytes();
        let full = groups.checked_mul(self.group_characters())?;
        let last = match (remainder, self.padding) {
            (0, _) => 0,
            (_, Padding::Required) => self.group_characters(),
            (remainder, _) => (remainder * 8).div_ceil(self.bits as usize),
        };
        full.checked_add(last)
    }

    fn maximum_decoded_length(&self, length: usize) -> usize {
        length / self.group_characters() * self.group_bytes()
            + length % self.group_characters() * self.bits as usize / 8
    }

    fn encode_to_slice(&self, input: &[u8], output: &mut [u8]) -> Result<usize, BaseError> {
        let needed =
            self.maximum_encoded_length(input.len()).ok_or(BaseError::InvalidLength { length: input.len() })?;
        if output.len() < needed {
            return Err(BaseError::OutputTooSmall { needed, available: output.len() });
        }
        let mask = (1u32 << self.bits) - 1;
        let mut accumulator = 0u32;
        let mut held = 0u32;
        let mut written = 0;
        for &byte in input {
            accumulator = (accumulator << 8) | byte as u32;
            held += 8;
            while held >= self.bits {
                held -= self.bits;
                output[written] = self.alphabet.encode(((accumulator >> held) & mask) as u8);
                written += 1;
            }
            accumulator &= (1 << held) - 1;
        }
        if held > 0 {
            output[written] = self.alphabet.encode(((accumulator << (self.bits - held)) & mask) as u8);
            written += 1;
        }
        while written < needed {
            output[written] = self.padding_character;
            written += 1;
        }
        Ok(written)
    }

    fn decode_to_slice(&self, input: &[u8], output: &mut [u8]) -> Result<usize, BaseError> {
        let group = self.group_characters();
        // Separate the padding at the end from the data.
        let mut data = input.len();
        while data > 0 && input[data - 1] == self.padding_character {
            data -= 1;
        }
        let padding = input.len() - data;
        let remainder = data % group;
        match self.padding {
            Padding::Forbidden if padding > 0 => return Err(BaseError::InvalidPadding { position: data }),
            Padding::Required if !input.len().is_multiple_of(group) => {
                return Err(BaseError::InvalidLength { length: input.len() });
            }
            _ => {}
        }
        if padding > 0 && (remainder == 0 || padding != group - remainder) {
            return Err(BaseError::InvalidPadding { position: data });
        }
        if !self.is_valid_remainder(remainder) {
            return Err(BaseError::InvalidLength { length: input.len() });
        }
        let needed = self.maximum_decoded_length(data);
        if output.len() < needed {
            return Err(BaseError::OutputTooSmall { needed, available: output.len() });
        }

        let mut accumulator = 0u32;
        let mut held = 0u32;
        let mut written = 0;
        for (position, &character) in input[..data].iter().enumerate() {
            let value = self.alphabet.decode(character).ok_or(BaseError::InvalidCharacter { position, character })?;
            accumulator = (accumulator << self.bits) | value as u32;
            held += self.bits;
            if held >= 8 {
                held -= 8;
                output[written] = (accumulator >> held) as u8;
                written += 1;
                accumulator &= (1 << held) - 1;
            }
        }
        // The bits after the last whole byte must be zero (RFC 4648 section 3.5).
        if accumulator != 0 {
            return Err(BaseError::NonCanonical { position: data - 1 });
        }
        Ok(written)
    }
}
