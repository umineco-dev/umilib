use core::fmt;

use super::AESBitslice;
use crate::crypto::{BlockCipher, CryptoError, KeyInit};
use crate::secret::Zeroize;

/// The key expansion of AES (FIPS 197 section 5.2), shared by the key sizes.
pub struct AESKeySchedule;

impl AESKeySchedule {
    /// The round constants: x^(i - 1) in GF(2^8).
    pub const ROUND_CONSTANTS: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    /// SubWord: the S-box on the four bytes of `word`.
    pub fn sub_word(word: [u8; 4]) -> [u8; 4] {
        let mut block = [0u8; 16];
        block[..4].copy_from_slice(&word);
        let mut state = AESBitslice::from_blocks(&[block]);
        block.zeroize();
        state.sub_bytes();
        let mut blocks = [[0u8; 16]; 1];
        state.to_blocks(&mut blocks);
        state.zeroize();
        let mut result = [0u8; 4];
        result.copy_from_slice(&blocks[0][..4]);
        blocks.zeroize();
        result
    }

    /// The `4 × (rounds + 1)` words of the expanded key of `key` (`Nk` = `key.len() / 4`).
    pub fn expand(key: &[u8], words: &mut [[u8; 4]]) {
        let nk = key.len() / 4;
        for (word, bytes) in words.iter_mut().zip(key.as_chunks::<4>().0) {
            *word = *bytes;
        }
        for i in nk..words.len() {
            let mut temp = words[i - 1];
            if i % nk == 0 {
                temp.rotate_left(1);
                temp = AESKeySchedule::sub_word(temp);
                temp[0] ^= AESKeySchedule::ROUND_CONSTANTS[i / nk - 1];
            } else if nk > 6 && i % nk == 4 {
                temp = AESKeySchedule::sub_word(temp);
            }
            for (byte, previous) in temp.iter_mut().zip(words[i - nk]) {
                *byte ^= previous;
            }
            words[i] = temp;
            temp.zeroize();
        }
    }
}

/// Defines AES with a key of `$key` bytes and `$rounds` rounds.
macro_rules! aes {
    ($(#[$documentation:meta])* $name:ident, $key:literal, $rounds:literal) => {
        $(#[$documentation])*
        ///
        /// The round keys are held as bit planes; four blocks go through the
        /// rounds together, so [`BlockCipher::encrypt_blocks`] is faster per
        /// block than [`BlockCipher::encrypt_block`].
        #[derive(Clone)]
        pub struct $name {
            round_keys: [AESBitslice; $rounds + 1],
        }

        impl $name {
            pub const KEY_SIZE: usize = $key;
            pub const ROUNDS: usize = $rounds;

            pub fn new(key: &[u8; $key]) -> $name {
                let mut words = [[0u8; 4]; 4 * ($rounds + 1)];
                AESKeySchedule::expand(key, &mut words);
                let mut round_keys = [AESBitslice::zero(); $rounds + 1];
                for (round, key) in round_keys.iter_mut().enumerate() {
                    let mut block = [0u8; 16];
                    for (column, word) in words[4 * round..4 * round + 4].iter().enumerate() {
                        block[4 * column..4 * column + 4].copy_from_slice(word);
                    }
                    *key = AESBitslice::from_block(&block);
                    block.zeroize();
                }
                words.zeroize();
                $name { round_keys }
            }

            /// The cipher (section 5.1) on `blocks`, four at a time in the bitsliced state.
            pub fn encrypt_group(&self, blocks: &mut [[u8; 16]]) {
                for group in blocks.chunks_mut(AESBitslice::BLOCKS) {
                    let mut state = AESBitslice::from_blocks(group);
                    state.add(&self.round_keys[0]);
                    for round in 1..$rounds {
                        state.sub_bytes();
                        state.shift_rows();
                        state.mix_columns();
                        state.add(&self.round_keys[round]);
                    }
                    state.sub_bytes();
                    state.shift_rows();
                    state.add(&self.round_keys[$rounds]);
                    state.to_blocks(group);
                    state.zeroize();
                }
            }

            /// The inverse cipher (section 5.3) on `blocks`, four at a time in the bitsliced state.
            pub fn decrypt_group(&self, blocks: &mut [[u8; 16]]) {
                for group in blocks.chunks_mut(AESBitslice::BLOCKS) {
                    let mut state = AESBitslice::from_blocks(group);
                    state.add(&self.round_keys[$rounds]);
                    for round in (1..$rounds).rev() {
                        state.inv_shift_rows();
                        state.inv_sub_bytes();
                        state.add(&self.round_keys[round]);
                        state.inv_mix_columns();
                    }
                    state.inv_shift_rows();
                    state.inv_sub_bytes();
                    state.add(&self.round_keys[0]);
                    state.to_blocks(group);
                    state.zeroize();
                }
            }
        }

        impl BlockCipher for $name {
            const BLOCK_SIZE: usize = 16;
            type Block = [u8; 16];

            fn encrypt_block(&self, block: &mut [u8; 16]) {
                self.encrypt_group(core::slice::from_mut(block));
            }

            fn decrypt_block(&self, block: &mut [u8; 16]) {
                self.decrypt_group(core::slice::from_mut(block));
            }

            fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
                self.encrypt_group(blocks);
            }

            fn decrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
                self.decrypt_group(blocks);
            }
        }

        impl KeyInit for $name {
            const MINIMUM_KEY_SIZE: usize = $key;
            const MAXIMUM_KEY_SIZE: usize = $key;

            fn new_from_slice(key: &[u8]) -> Result<$name, CryptoError> {
                $name::check_key_length(key.len())?;
                let key: &[u8; $key] = key.try_into().map_err(|_| CryptoError::InvalidParameter)?;
                Ok($name::new(key))
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.round_keys.iter_mut().for_each(Zeroize::zeroize);
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

aes!(
    /// AES-128 (FIPS 197): a 128-bit key and 10 rounds.
    AES128, 16, 10
);
aes!(
    /// AES-192 (FIPS 197): a 192-bit key and 12 rounds.
    AES192, 24, 12
);
aes!(
    /// AES-256 (FIPS 197): a 256-bit key and 14 rounds.
    AES256, 32, 14
);
