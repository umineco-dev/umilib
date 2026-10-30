//! Base85: groups of four bytes written as five base-85 digits.
//!
//! Presets cover Ascii85 (Adobe PostScript and PDF), Z85 (ZeroMQ RFC 32) and
//! the RFC 1924 alphabet used by Git and Python's `base64.b85encode`.

use super::{Alphabet, AlphabetRange, BaseError, Encoding};

/// The Base85 encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base85 {
    pub alphabet: Alphabet,
    /// The character that stands for a group of four zero bytes, if any (`z` in Ascii85).
    pub zero_group: Option<u8>,
    /// Whether the input may end with a partial group of one to three bytes,
    /// written as two to four characters.
    pub partial_groups: bool,
    /// Text written before and after the encoding, and required around it when decoding.
    pub delimiters: Option<(&'static [u8], &'static [u8])>,
    /// Whether decoding skips white space (space, tab, line feed, form feed,
    /// carriage return and NUL, as in PDF).
    pub ignore_whitespace: bool,
}

impl Base85 {
    /// The Ascii85 alphabet: the characters `!` to `u`.
    pub const ASCII85_ALPHABET: Alphabet = Alphabet::new(&[AlphabetRange::new(b'!', 85, 0)]);
    /// The Z85 alphabet of ZeroMQ.
    pub const Z85_ALPHABET: Alphabet = Alphabet::new(&[
        AlphabetRange::new(b'0', 10, 0),
        AlphabetRange::new(b'a', 26, 10),
        AlphabetRange::new(b'A', 26, 36),
        AlphabetRange::new(b'.', 1, 62),
        AlphabetRange::new(b'-', 1, 63),
        AlphabetRange::new(b':', 1, 64),
        AlphabetRange::new(b'+', 1, 65),
        AlphabetRange::new(b'=', 1, 66),
        AlphabetRange::new(b'^', 1, 67),
        AlphabetRange::new(b'!', 1, 68),
        AlphabetRange::new(b'/', 1, 69),
        AlphabetRange::new(b'*', 1, 70),
        AlphabetRange::new(b'?', 1, 71),
        AlphabetRange::new(b'&', 1, 72),
        AlphabetRange::new(b'<', 1, 73),
        AlphabetRange::new(b'>', 1, 74),
        AlphabetRange::new(b'(', 2, 75),
        AlphabetRange::new(b'[', 1, 77),
        AlphabetRange::new(b']', 1, 78),
        AlphabetRange::new(b'{', 1, 79),
        AlphabetRange::new(b'}', 1, 80),
        AlphabetRange::new(b'@', 1, 81),
        AlphabetRange::new(b'%', 1, 82),
        AlphabetRange::new(b'$', 1, 83),
        AlphabetRange::new(b'#', 1, 84),
    ]);
    /// The alphabet of RFC 1924.
    pub const RFC1924_ALPHABET: Alphabet = Alphabet::new(&[
        AlphabetRange::new(b'0', 10, 0),
        AlphabetRange::new(b'A', 26, 10),
        AlphabetRange::new(b'a', 26, 36),
        AlphabetRange::new(b'!', 1, 62),
        AlphabetRange::new(b'#', 4, 63),
        AlphabetRange::new(b'(', 4, 67),
        AlphabetRange::new(b'-', 1, 71),
        AlphabetRange::new(b';', 6, 72),
        AlphabetRange::new(b'^', 3, 78),
        AlphabetRange::new(b'{', 4, 81),
    ]);

    /// Ascii85 without delimiters, as `base64.a85encode` writes by default.
    pub const ASCII85: Base85 = Base85 {
        alphabet: Base85::ASCII85_ALPHABET,
        zero_group: Some(b'z'),
        partial_groups: true,
        delimiters: None,
        ignore_whitespace: true,
    };
    /// Ascii85 between `<~` and `~>`, as in Adobe PostScript.
    pub const ASCII85_ADOBE: Base85 = Base85 { delimiters: Some((b"<~", b"~>")), ..Base85::ASCII85 };
    /// Z85 (ZeroMQ RFC 32): the input must be a multiple of four bytes.
    pub const Z85: Base85 = Base85 {
        alphabet: Base85::Z85_ALPHABET,
        zero_group: None,
        partial_groups: false,
        delimiters: None,
        ignore_whitespace: false,
    };
    /// The RFC 1924 alphabet with partial groups, as used by Git and `base64.b85encode`.
    pub const RFC1924: Base85 = Base85 {
        alphabet: Base85::RFC1924_ALPHABET,
        zero_group: None,
        partial_groups: true,
        delimiters: None,
        ignore_whitespace: false,
    };

    /// The white space skipped when [`Base85::ignore_whitespace`] is set.
    pub const WHITESPACE: [u8; 6] = [b' ', b'\t', b'\n', 0x0C, b'\r', 0];

    /// The length of the delimiters, before and after.
    pub fn delimiter_lengths(&self) -> (usize, usize) {
        self.delimiters.map_or((0, 0), |(start, end)| (start.len(), end.len()))
    }

    /// Writes the five digits of `value`, most significant first.
    pub fn encode_group(&self, value: u32, output: &mut [u8; 5]) {
        let mut value = value;
        for digit in output.iter_mut().rev() {
            *digit = self.alphabet.encode((value % 85) as u8);
            value /= 85;
        }
    }
}

impl Encoding for Base85 {
    fn maximum_encoded_length(&self, length: usize) -> Option<usize> {
        let (start, end) = self.delimiter_lengths();
        let remainder = length % 4;
        (length / 4)
            .checked_mul(5)?
            .checked_add(if remainder == 0 { 0 } else { remainder + 1 })?
            .checked_add(start + end)
    }

    fn maximum_decoded_length(&self, length: usize) -> usize {
        if self.zero_group.is_some() { length.saturating_mul(4) } else { length / 5 * 4 + length % 5 }
    }

    fn encode_to_slice(&self, input: &[u8], output: &mut [u8]) -> Result<usize, BaseError> {
        if !self.partial_groups && !input.len().is_multiple_of(4) {
            return Err(BaseError::InvalidLength { length: input.len() });
        }
        let needed =
            self.maximum_encoded_length(input.len()).ok_or(BaseError::InvalidLength { length: input.len() })?;
        if output.len() < needed {
            return Err(BaseError::OutputTooSmall { needed, available: output.len() });
        }
        let mut written = 0;
        if let Some((start, _)) = self.delimiters {
            output[..start.len()].copy_from_slice(start);
            written += start.len();
        }
        let mut digits = [0u8; 5];
        for group in input.chunks(4) {
            let mut bytes = [0u8; 4];
            bytes[..group.len()].copy_from_slice(group);
            let value = u32::from_be_bytes(bytes);
            if group.len() == 4
                && value == 0
                && let Some(zero) = self.zero_group
            {
                output[written] = zero;
                written += 1;
                continue;
            }
            self.encode_group(value, &mut digits);
            // A partial group of n bytes keeps the first n + 1 digits.
            let count = group.len() + 1;
            output[written..written + count].copy_from_slice(&digits[..count]);
            written += count;
        }
        if let Some((_, end)) = self.delimiters {
            output[written..written + end.len()].copy_from_slice(end);
            written += end.len();
        }
        Ok(written)
    }

    fn decode_to_slice(&self, input: &[u8], output: &mut [u8]) -> Result<usize, BaseError> {
        let mut body = input;
        let mut offset = 0;
        if let Some((start, end)) = self.delimiters {
            body = body.strip_prefix(start).ok_or(BaseError::InvalidPadding { position: 0 })?;
            body = body.strip_suffix(end).ok_or(BaseError::InvalidPadding { position: input.len() })?;
            offset = start.len();
        }
        let mut written = 0;
        let mut group = [0u8; 5];
        let mut positions = [0usize; 5];
        let mut count = 0;
        let mut write = |bytes: &[u8], written: &mut usize| -> Result<(), BaseError> {
            let end = *written + bytes.len();
            if end > output.len() {
                return Err(BaseError::OutputTooSmall { needed: end, available: output.len() });
            }
            output[*written..end].copy_from_slice(bytes);
            *written = end;
            Ok(())
        };
        for (index, &character) in body.iter().enumerate() {
            let position = offset + index;
            if self.ignore_whitespace && Base85::WHITESPACE.contains(&character) {
                continue;
            }
            if Some(character) == self.zero_group {
                if count != 0 {
                    return Err(BaseError::InvalidCharacter { position, character });
                }
                write(&[0; 4], &mut written)?;
                continue;
            }
            group[count] =
                self.alphabet.decode(character).ok_or(BaseError::InvalidCharacter { position, character })?;
            positions[count] = position;
            count += 1;
            if count == 5 {
                let value = group.iter().fold(0u64, |value, &digit| value * 85 + digit as u64);
                let value = u32::try_from(value).map_err(|_| BaseError::Overflow { position: positions[0] })?;
                write(&value.to_be_bytes(), &mut written)?;
                count = 0;
            }
        }
        if count > 0 {
            if !self.partial_groups || count == 1 {
                return Err(BaseError::InvalidLength { length: input.len() });
            }
            // A partial group of n digits is completed with the largest digit
            // and decodes to its first n - 1 bytes.
            group[count..].fill(84);
            let value = group.iter().fold(0u64, |value, &digit| value * 85 + digit as u64);
            let value = u32::try_from(value).map_err(|_| BaseError::Overflow { position: positions[0] })?;
            let bytes = value.to_be_bytes();
            // Only one text encodes these bytes: re-encoding must give the same digits.
            let mut padded = [0u8; 4];
            padded[..count - 1].copy_from_slice(&bytes[..count - 1]);
            let mut digits = [0u8; 5];
            self.encode_group(u32::from_be_bytes(padded), &mut digits);
            for (digit, &position) in digits[..count].iter().zip(&positions[..count]) {
                if *digit != input[position] {
                    return Err(BaseError::NonCanonical { position });
                }
            }
            write(&bytes[..count - 1], &mut written)?;
        }
        Ok(written)
    }
}
