use std::vec::Vec;

/// A deterministic generator of input mutations.
///
/// Randomness comes from SplitMix64, which is fast and reproducible but not
/// suitable for anything other than testing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mutator {
    state: u64,
}

impl Mutator {
    /// Values that often reveal boundary errors.
    pub const INTERESTING: [u64; 12] =
        [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF];

    /// Creates a mutator from a seed.
    pub const fn new(seed: u64) -> Mutator {
        Mutator { state: seed }
    }

    /// The next pseudo-random 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    /// A pseudo-random value in `0..bound`; `bound` must not be zero.
    pub fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    /// Applies between one and four random mutations to `data`, keeping it at most
    /// `maximum_length` bytes long. `corpus` supplies material for splicing.
    pub fn mutate(&mut self, data: &mut Vec<u8>, maximum_length: usize, corpus: &[Vec<u8>]) {
        let count = 1 + self.below(4);
        for _ in 0..count {
            match self.below(8) {
                0 if !data.is_empty() => {
                    let index = self.below(data.len());
                    data[index] ^= 1 << self.below(8);
                }
                1 if !data.is_empty() => {
                    let index = self.below(data.len());
                    data[index] = self.next_u64() as u8;
                }
                2 => {
                    let index = self.below(data.len() + 1);
                    let length = 1 + self.below(8);
                    for _ in 0..length {
                        data.insert(index, self.next_u64() as u8);
                    }
                }
                3 if !data.is_empty() => {
                    let start = self.below(data.len());
                    let end = (start + 1 + self.below(8)).min(data.len());
                    data.drain(start..end);
                }
                4 if !data.is_empty() => {
                    let start = self.below(data.len());
                    let end = (start + 1 + self.below(16)).min(data.len());
                    let block: Vec<u8> = data[start..end].to_vec();
                    let index = self.below(data.len() + 1);
                    data.splice(index..index, block);
                }
                5 => {
                    let value = Mutator::INTERESTING[self.below(Mutator::INTERESTING.len())];
                    let width = [1, 2, 4, 8][self.below(4)];
                    let bytes = if self.below(2) == 0 { value.to_be_bytes() } else { value.to_le_bytes() };
                    let bytes = if self.below(2) == 0 { &bytes[8 - width..] } else { &bytes[..width] };
                    let index = self.below(data.len() + 1);
                    let end = (index + width).min(data.len());
                    data.splice(index..end, bytes.iter().copied());
                }
                6 if !corpus.is_empty() => {
                    let other = &corpus[self.below(corpus.len())];
                    if !other.is_empty() {
                        let start = self.below(other.len());
                        let end = start + 1 + self.below(other.len() - start);
                        let index = self.below(data.len() + 1);
                        data.splice(index..index, other[start..end].iter().copied());
                    }
                }
                _ => {
                    let index = self.below(data.len() + 1);
                    data.truncate(index);
                }
            }
        }
        data.truncate(maximum_length);
    }
}
