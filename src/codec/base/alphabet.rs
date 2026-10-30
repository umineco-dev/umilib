/// A run of consecutive characters encoding consecutive values.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlphabetRange {
    /// The first character of the run.
    pub first: u8,
    /// The number of characters in the run.
    pub count: u8,
    /// The value of `first`.
    pub value: u8,
    /// Whether encoding uses this run. A run that is not canonical is only
    /// accepted when decoding, for example lowercase letters in Base16.
    pub canonical: bool,
}

impl AlphabetRange {
    /// A run used for encoding and decoding.
    pub const fn new(first: u8, count: u8, value: u8) -> AlphabetRange {
        AlphabetRange { first, count, value, canonical: true }
    }

    /// A run only accepted when decoding.
    pub const fn decode_only(first: u8, count: u8, value: u8) -> AlphabetRange {
        AlphabetRange { first, count, value, canonical: false }
    }
}

/// The characters of an encoding, described as runs of consecutive characters.
///
/// Conversions inspect every run with arithmetic masks instead of looking up
/// a table or branching, so their timing does not depend on the data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alphabet {
    pub ranges: &'static [AlphabetRange],
}

impl Alphabet {
    /// Creates an alphabet from its runs. The canonical runs must cover the
    /// values `0..n` exactly once, and no two runs may share a character.
    pub const fn new(ranges: &'static [AlphabetRange]) -> Alphabet {
        Alphabet { ranges }
    }

    /// The number of values the alphabet encodes.
    pub const fn size(&self) -> usize {
        let mut size = 0;
        let mut index = 0;
        while index < self.ranges.len() {
            if self.ranges[index].canonical {
                size += self.ranges[index].count as usize;
            }
            index += 1;
        }
        size
    }

    /// `0xFF` if `value` is in `start..start + count`, otherwise `0`, without branching.
    pub fn mask_in(value: u8, start: u8, count: u8) -> u8 {
        let offset = (value as u16).wrapping_sub(start as u16);
        // `offset < count` exactly when the subtraction below borrows.
        ((offset.wrapping_sub(count as u16) >> 8) as u8) & (((offset >> 8) as u8) ^ 0xFF)
    }

    /// The character encoding `value`, which must be smaller than [`Alphabet::size`].
    pub fn encode(&self, value: u8) -> u8 {
        let mut character = 0u8;
        for range in self.ranges.iter().filter(|range| range.canonical) {
            let mask = Alphabet::mask_in(value, range.value, range.count);
            character |= mask & value.wrapping_sub(range.value).wrapping_add(range.first);
        }
        core::hint::black_box(character)
    }

    /// The value of `character`, or `None` if it is not part of the alphabet.
    /// Only the result `None` depends on the data in a way an observer can time.
    pub fn decode(&self, character: u8) -> Option<u8> {
        let mut value = 0u8;
        let mut valid = 0u8;
        for range in self.ranges {
            let mask = Alphabet::mask_in(character, range.first, range.count);
            value |= mask & character.wrapping_sub(range.first).wrapping_add(range.value);
            valid |= mask;
        }
        if core::hint::black_box(valid) == 0 { None } else { Some(value) }
    }
}
