use core::fmt;

use crate::secret::Zeroize;

/// The Ascon permutation Ascon-p\[rnd\] (SP 800-232 section 3) on the 320-bit
/// state of five 64-bit words S0 to S4. The substitution layer is computed
/// on the words with bitwise operations (64 S-boxes at once), so the time
/// does not depend on the state.
///
/// Bytes map to the words little-endian (appendix A.1): byte `k` of the
/// state is byte `k mod 8` of word `k / 8`.
#[derive(Clone, PartialEq, Eq)]
pub struct AsconPermutation {
    words: [u64; 5],
}

impl AsconPermutation {
    /// const_0 to const_15 (table 5); round `i` of Ascon-p\[rnd\] adds const_(16 - rnd + i).
    pub const CONSTANTS: [u64; 16] =
        [0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b];
    pub const MAXIMUM_ROUNDS: usize = 16;

    pub const fn from_words(words: [u64; 5]) -> AsconPermutation {
        AsconPermutation { words }
    }

    pub fn words(&self) -> &[u64; 5] {
        &self.words
    }

    pub fn words_mut(&mut self) -> &mut [u64; 5] {
        &mut self.words
    }

    /// The substitution layer p_S (section 3.3): the 5-bit S-box on the bits
    /// of the same position in the five words, as a circuit of xors, ands and
    /// nots (figure 3).
    pub fn substitute(&mut self) {
        let [mut x0, mut x1, mut x2, mut x3, mut x4] = self.words;
        x0 ^= x4;
        x4 ^= x3;
        x2 ^= x1;
        let (t0, t1, t2, t3, t4) = (!x0 & x1, !x1 & x2, !x2 & x3, !x3 & x4, !x4 & x0);
        x0 ^= t1;
        x1 ^= t2;
        x2 ^= t3;
        x3 ^= t4;
        x4 ^= t0;
        x1 ^= x0;
        x0 ^= x4;
        x3 ^= x2;
        x2 = !x2;
        self.words = [x0, x1, x2, x3, x4];
    }

    /// The linear diffusion layer p_L (section 3.4).
    pub fn diffuse(&mut self) {
        let [x0, x1, x2, x3, x4] = self.words;
        self.words = [
            x0 ^ x0.rotate_right(19) ^ x0.rotate_right(28),
            x1 ^ x1.rotate_right(61) ^ x1.rotate_right(39),
            x2 ^ x2.rotate_right(1) ^ x2.rotate_right(6),
            x3 ^ x3.rotate_right(10) ^ x3.rotate_right(17),
            x4 ^ x4.rotate_right(7) ^ x4.rotate_right(41),
        ];
    }

    /// One round p = p_L ∘ p_S ∘ p_C with the round constant `constant`.
    pub fn round(&mut self, constant: u64) {
        self.words[2] ^= constant;
        self.substitute();
        self.diffuse();
    }

    /// Ascon-p\[`rounds`\], 1 to 16 rounds (section 3).
    pub fn permute(&mut self, rounds: usize) {
        assert!((1..=AsconPermutation::MAXIMUM_ROUNDS).contains(&rounds), "Ascon-p has 1 to 16 rounds");
        for &constant in &AsconPermutation::CONSTANTS[AsconPermutation::MAXIMUM_ROUNDS - rounds..] {
            self.round(constant);
        }
    }

    /// Byte `index` (0 to 39) of the state.
    pub fn byte(&self, index: usize) -> u8 {
        (self.words[index / 8] >> (8 * (index % 8))) as u8
    }

    /// Adds `data` to the bytes of the state from `offset`.
    pub fn xor_bytes(&mut self, offset: usize, data: &[u8]) {
        for (index, byte) in data.iter().enumerate() {
            let position = offset + index;
            self.words[position / 8] ^= (*byte as u64) << (8 * (position % 8));
        }
    }

    /// Replaces the bytes of the state from `offset` with `data`.
    pub fn set_bytes(&mut self, offset: usize, data: &[u8]) {
        for (index, byte) in data.iter().enumerate() {
            let position = offset + index;
            let shift = 8 * (position % 8);
            let word = &mut self.words[position / 8];
            *word = (*word & !(0xFF << shift)) | ((*byte as u64) << shift);
        }
    }

    /// The bytes of the state from `offset` into `out`.
    pub fn extract_bytes(&self, offset: usize, out: &mut [u8]) {
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = self.byte(offset + index);
        }
    }
}

impl Zeroize for AsconPermutation {
    fn zeroize(&mut self) {
        self.words.zeroize();
    }
}

impl Drop for AsconPermutation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for AsconPermutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AsconPermutation(..)")
    }
}
