//! IDEA (Lai and Massey, ISO/IEC 18033-3): the 64-bit block cipher of
//! three algebraic groups on 16-bit words.

use core::fmt;

use crate::crypto::{BlockCipher, CryptoError, KeyInit};
use crate::secret::Zeroize;

/// IDEA with a 128-bit key: 8 rounds and an output transformation on four
/// 16-bit words, mixing xor, addition modulo 2^16 and multiplication modulo
/// 2^16 + 1 (where 0 stands for 2^16).
///
/// The multiplication reduces with masks instead of branches or a division,
/// and the inverses of the decryption subkeys are computed by a fixed chain
/// of multiplications, so the time depends on neither the key nor the data.
#[derive(Clone)]
pub struct IDEA {
    /// The 52 encryption subkeys Z1 to Z52, then the 52 decryption subkeys.
    encryption_keys: [u16; 52],
    decryption_keys: [u16; 52],
}

impl IDEA {
    pub const KEY_SIZE: usize = 16;
    pub const ROUNDS: usize = 8;

    pub fn new(key: &[u8; 16]) -> IDEA {
        let mut value = u128::from_be_bytes(*key);
        let mut encryption_keys = [0u16; 52];
        // Eight subkeys from each 128-bit value, rotated left by 25 bits between them.
        for (index, subkey) in encryption_keys.iter_mut().enumerate() {
            if index > 0 && index % 8 == 0 {
                value = value.rotate_left(25);
            }
            *subkey = (value >> (112 - 16 * (index % 8))) as u16;
        }
        value.zeroize();
        let decryption_keys = IDEA::invert_keys(&encryption_keys);
        IDEA { encryption_keys, decryption_keys }
    }

    /// The product modulo 2^16 + 1, where 0 stands for 2^16.
    pub fn multiply(a: u16, b: u16) -> u16 {
        // 0 becomes 2^16: the borrow of a - 1 is set exactly for a = 0.
        let a = a as u64 + ((((a as u32).wrapping_sub(1) >> 16) & 1) << 16) as u64;
        let b = b as u64 + ((((b as u32).wrapping_sub(1) >> 16) & 1) << 16) as u64;
        let product = a * b;
        // 2^16 ≡ -1: product = high · 2^16 + low ≡ low - high; add the modulus back when negative.
        let (low, high) = (product & 0xFFFF, product >> 16);
        let difference = low.wrapping_sub(high);
        let negative = difference >> 63;
        (difference.wrapping_add(0x1_0001 * negative)) as u16
    }

    /// The multiplicative inverse modulo 2^16 + 1 (0 stands for 2^16, its own
    /// inverse): x^(2^16 - 1) by Fermat's theorem, with 15 squarings and 15
    /// multiplications whatever x is.
    pub fn invert(x: u16) -> u16 {
        let mut result = x;
        for _ in 0..15 {
            result = IDEA::multiply(IDEA::multiply(result, result), x);
        }
        result
    }

    /// The decryption subkeys: the inverses of the encryption subkeys in the
    /// reverse order of the rounds, the additive inverses swapped in the
    /// rounds 2 to 8.
    pub fn invert_keys(keys: &[u16; 52]) -> [u16; 52] {
        let mut inverse = [0u16; 52];
        for round in 0..9 {
            // Round `round` of decryption undoes round 8 - round of encryption (the output transformation is round 8).
            let source = &keys[6 * (8 - round)..];
            let swap = round != 0 && round != 8;
            let target = &mut inverse[6 * round..];
            target[0] = IDEA::invert(source[0]);
            target[1] = source[if swap { 2 } else { 1 }].wrapping_neg();
            target[2] = source[if swap { 1 } else { 2 }].wrapping_neg();
            target[3] = IDEA::invert(source[3]);
            if round < 8 {
                target[4] = keys[6 * (7 - round) + 4];
                target[5] = keys[6 * (7 - round) + 5];
            }
        }
        inverse
    }

    /// The 8 rounds and the output transformation with the subkeys `keys`.
    pub fn apply_rounds(block: &mut [u8; 8], keys: &[u16; 52]) {
        let word = |index: usize| u16::from_be_bytes([block[2 * index], block[2 * index + 1]]);
        let (mut x1, mut x2, mut x3, mut x4) = (word(0), word(1), word(2), word(3));
        for round in keys[..48].as_chunks::<6>().0 {
            x1 = IDEA::multiply(x1, round[0]);
            x2 = x2.wrapping_add(round[1]);
            x3 = x3.wrapping_add(round[2]);
            x4 = IDEA::multiply(x4, round[3]);
            let t0 = IDEA::multiply(x1 ^ x3, round[4]);
            let t1 = IDEA::multiply(t0.wrapping_add(x2 ^ x4), round[5]);
            let t0 = t0.wrapping_add(t1);
            x1 ^= t1;
            x4 ^= t0;
            // The middle words are swapped after each round.
            (x2, x3) = (x3 ^ t1, x2 ^ t0);
        }
        let output = [
            IDEA::multiply(x1, keys[48]),
            x3.wrapping_add(keys[49]),
            x2.wrapping_add(keys[50]),
            IDEA::multiply(x4, keys[51]),
        ];
        for (index, value) in output.iter().enumerate() {
            block[2 * index..2 * index + 2].copy_from_slice(&value.to_be_bytes());
        }
    }

    /// The encryption subkeys Z1 to Z52.
    pub fn encryption_keys(&self) -> &[u16; 52] {
        &self.encryption_keys
    }

    /// The decryption subkeys.
    pub fn decryption_keys(&self) -> &[u16; 52] {
        &self.decryption_keys
    }
}

impl BlockCipher for IDEA {
    const BLOCK_SIZE: usize = 8;
    type Block = [u8; 8];

    fn encrypt_block(&self, block: &mut [u8; 8]) {
        IDEA::apply_rounds(block, &self.encryption_keys);
    }

    fn decrypt_block(&self, block: &mut [u8; 8]) {
        IDEA::apply_rounds(block, &self.decryption_keys);
    }
}

impl KeyInit for IDEA {
    const MINIMUM_KEY_SIZE: usize = 16;
    const MAXIMUM_KEY_SIZE: usize = 16;

    fn new_from_slice(key: &[u8]) -> Result<IDEA, CryptoError> {
        IDEA::check_key_length(key.len())?;
        let key: &[u8; 16] = key.try_into().map_err(|_| CryptoError::InvalidParameter)?;
        Ok(IDEA::new(key))
    }
}

impl Zeroize for IDEA {
    fn zeroize(&mut self) {
        self.encryption_keys.zeroize();
        self.decryption_keys.zeroize();
    }
}

impl Drop for IDEA {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for IDEA {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IDEA(..)")
    }
}
