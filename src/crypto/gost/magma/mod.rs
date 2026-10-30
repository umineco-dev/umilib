//! Magma (GOST R 34.12-2015, RFC 8891): the 64-bit block cipher of GOST
//! 28147-89 with the substitutions fixed by GOST R 34.12-2015.

use core::fmt;

use crate::crypto::{BlockCipher, CryptoError, KeyInit};
use crate::secret::{ConstantTimeTable, Zeroize};

/// Magma with a 256-bit key: 32 rounds of a Feistel network on two 32-bit
/// halves. The substitutions are read as [`ConstantTimeTable`]s, so no
/// memory access depends on the key or the data.
#[derive(Clone)]
pub struct Magma {
    /// The round keys K_1 to K_32.
    round_keys: [u32; 32],
}

impl Magma {
    pub const KEY_SIZE: usize = 32;
    pub const ROUNDS: usize = 32;
    /// The substitutions Pi_0 to Pi_7 of the nibbles a_0 (the least significant) to a_7 (section 4.1).
    pub const SUBSTITUTIONS: [ConstantTimeTable<1, 4>; 8] = [
        ConstantTimeTable::from_bytes(&[12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1]),
        ConstantTimeTable::from_bytes(&[6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15]),
        ConstantTimeTable::from_bytes(&[11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0]),
        ConstantTimeTable::from_bytes(&[12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11]),
        ConstantTimeTable::from_bytes(&[7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12]),
        ConstantTimeTable::from_bytes(&[5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0]),
        ConstantTimeTable::from_bytes(&[8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7]),
        ConstantTimeTable::from_bytes(&[1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]),
    ];

    /// The round keys of section 4.3: K_1 to K_8 are the words of the key,
    /// repeated twice, then in the reverse order.
    pub fn new(key: &[u8; 32]) -> Magma {
        let mut words = [0u32; 8];
        for (index, word) in words.iter_mut().enumerate() {
            *word = u32::from_be_bytes(key[4 * index..4 * index + 4].try_into().expect("four bytes"));
        }
        let mut round_keys = [0u32; 32];
        for (index, round_key) in round_keys.iter_mut().enumerate() {
            *round_key = if index < 24 { words[index % 8] } else { words[31 - index] };
        }
        words.zeroize();
        Magma { round_keys }
    }

    /// The transformation t: Pi_i on each nibble a_i (section 4.2).
    pub fn t(word: u32) -> u32 {
        let mut out = 0u32;
        for (index, substitution) in Magma::SUBSTITUTIONS.iter().enumerate() {
            let nibble = (word >> (4 * index)) & 0xF;
            out |= substitution.get(nibble as usize) << (4 * index);
        }
        out
    }

    /// The transformation g\[k\](a) = t(a \[+\] k) <<< 11 (section 4.2).
    pub fn g(key: u32, word: u32) -> u32 {
        Magma::t(word.wrapping_add(key)).rotate_left(11)
    }

    /// G\[K_32\] ... G\[K_1\] with the keys in `keys`, the last one as G* (section 5).
    pub fn apply_rounds<'a>(block: &mut [u8; 8], keys: impl Iterator<Item = &'a u32>) {
        let mut a1 = u32::from_be_bytes(block[..4].try_into().expect("four bytes"));
        let mut a0 = u32::from_be_bytes(block[4..].try_into().expect("four bytes"));
        for &key in keys {
            let next = Magma::g(key, a0) ^ a1;
            a1 = a0;
            a0 = next;
        }
        // G* does not swap: undo the swap of the last round.
        block[..4].copy_from_slice(&a0.to_be_bytes());
        block[4..].copy_from_slice(&a1.to_be_bytes());
    }

    /// The round keys K_1 to K_32.
    pub fn round_keys(&self) -> &[u32; 32] {
        &self.round_keys
    }
}

impl BlockCipher for Magma {
    const BLOCK_SIZE: usize = 8;
    type Block = [u8; 8];

    fn encrypt_block(&self, block: &mut [u8; 8]) {
        Magma::apply_rounds(block, self.round_keys.iter());
    }

    /// Decryption applies the round keys from K_32 to K_1 (section 5.2).
    fn decrypt_block(&self, block: &mut [u8; 8]) {
        Magma::apply_rounds(block, self.round_keys.iter().rev());
    }
}

impl KeyInit for Magma {
    const MINIMUM_KEY_SIZE: usize = 32;
    const MAXIMUM_KEY_SIZE: usize = 32;

    fn new_from_slice(key: &[u8]) -> Result<Magma, CryptoError> {
        Magma::check_key_length(key.len())?;
        let key: &[u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidParameter)?;
        Ok(Magma::new(key))
    }
}

impl Zeroize for Magma {
    fn zeroize(&mut self) {
        self.round_keys.zeroize();
    }
}

impl Drop for Magma {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for Magma {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Magma(..)")
    }
}
