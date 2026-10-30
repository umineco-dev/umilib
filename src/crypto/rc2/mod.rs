//! RC2 (RFC 2268): the 64-bit block cipher of Rivest with a variable key
//! length and a separate effective key length, kept for PKCS #12 and other
//! legacy formats.

use core::fmt;

use crate::crypto::{BlockCipher, CryptoError, KeyInit};
use crate::secret::{ConstantTimeTable, Zeroize};

/// RC2 with a key of 1 to 128 bytes and an effective key length of 1 to
/// 1024 bits (section 2).
///
/// PITABLE and the expanded key, which the key expansion and the mashing
/// rounds index with secret values, are read as [`ConstantTimeTable`]s, so
/// no memory access depends on the key or the data.
#[derive(Clone)]
pub struct RC2 {
    /// The expanded key K[0] to K[63], read in order by the mixing rounds.
    words: [u16; 64],
    /// The same words, indexed by the data in the mashing rounds.
    table: ConstantTimeTable<16, 16>,
}

impl RC2 {
    pub const MAXIMUM_KEY_SIZE: usize = 128;
    pub const MAXIMUM_EFFECTIVE_BITS: usize = 1024;
    /// The rotations s\[0\] to s\[3\] of the mixing operations (section 3.1).
    pub const ROTATIONS: [u32; 4] = [1, 2, 3, 5];
    /// PITABLE, a permutation of the bytes from the digits of π (section 2).
    pub const PITABLE: ConstantTimeTable<32, 8> = ConstantTimeTable::from_bytes(&[
        0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED, 0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D, 0xC6, 0x7E,
        0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E, 0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2, 0x17, 0x9A, 0x59, 0xF5,
        0x87, 0xB3, 0x4F, 0x13, 0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32, 0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7,
        0x7B, 0x0B, 0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82, 0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C,
        0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC, 0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1, 0x42, 0x3D,
        0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26, 0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57, 0x27, 0xF2, 0x1D, 0x9B,
        0xBC, 0x94, 0x43, 0x03, 0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7, 0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66,
        0x1E, 0xD7, 0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7, 0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
        0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74, 0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC, 0xC2, 0xE0,
        0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC, 0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39, 0x99, 0x7C, 0x3A, 0x85,
        0x23, 0xB8, 0xB4, 0x7A, 0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31, 0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A,
        0x92, 0xAE, 0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9, 0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C,
        0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9, 0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0, 0xBB, 0x48,
        0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E, 0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77, 0x0A, 0xA6, 0x20, 0x68,
        0xFE, 0x7F, 0xC1, 0xAD,
    ]);

    /// The key expansion of section 2 with `effective_bits` effective key bits.
    pub fn new(key: &[u8], effective_bits: usize) -> Result<RC2, CryptoError> {
        if key.is_empty() || key.len() > RC2::MAXIMUM_KEY_SIZE {
            return Err(CryptoError::KeyLength { length: key.len(), minimum: 1, maximum: RC2::MAXIMUM_KEY_SIZE });
        }
        if !(1..=RC2::MAXIMUM_EFFECTIVE_BITS).contains(&effective_bits) {
            return Err(CryptoError::InvalidParameter);
        }
        let t = key.len();
        let t8 = effective_bits.div_ceil(8);
        let tm = (0xFFu32 >> (8 * t8 - effective_bits)) as u8;
        let mut l = [0u8; 128];
        l[..t].copy_from_slice(key);
        let pi = |index: u8| RC2::PITABLE.get(index as usize) as u8;
        for i in t..128 {
            l[i] = pi(l[i - 1].wrapping_add(l[i - t]));
        }
        l[128 - t8] = pi(l[128 - t8] & tm);
        for i in (0..128 - t8).rev() {
            l[i] = pi(l[i + 1] ^ l[i + t8]);
        }
        let mut words = [0u16; 64];
        let mut table = ConstantTimeTable::new();
        for (index, word) in words.iter_mut().enumerate() {
            // K[i] = L[2i] + 256 · L[2i + 1].
            *word = u16::from_le_bytes([l[2 * index], l[2 * index + 1]]);
            table.set(index, *word as u32);
        }
        l.zeroize();
        Ok(RC2 { words, table })
    }

    /// Five mixing rounds, a mashing round, six mixing rounds, a mashing
    /// round and five mixing rounds (section 3.5).
    pub fn encrypt_words(&self, r: &mut [u16; 4]) {
        let mut j = 0;
        for (mixing_rounds, mash) in [(5, true), (6, true), (5, false)] {
            for _ in 0..mixing_rounds {
                for i in 0..4 {
                    let composite = (r[(i + 3) % 4] & r[(i + 2) % 4]) | (!r[(i + 3) % 4] & r[(i + 1) % 4]);
                    r[i] = r[i].wrapping_add(self.words[j]).wrapping_add(composite).rotate_left(RC2::ROTATIONS[i]);
                    j += 1;
                }
            }
            if mash {
                for i in 0..4 {
                    r[i] = r[i].wrapping_add(self.table.get((r[(i + 3) % 4] & 63) as usize) as u16);
                }
            }
        }
    }

    /// The reverse operations in the reverse order (section 4.5).
    pub fn decrypt_words(&self, r: &mut [u16; 4]) {
        let mut j = 64;
        for (mixing_rounds, mash) in [(5, true), (6, true), (5, false)] {
            for _ in 0..mixing_rounds {
                for i in (0..4).rev() {
                    j -= 1;
                    let rotated = r[i].rotate_right(RC2::ROTATIONS[i]);
                    let composite = (r[(i + 3) % 4] & r[(i + 2) % 4]) | (!r[(i + 3) % 4] & r[(i + 1) % 4]);
                    r[i] = rotated.wrapping_sub(self.words[j]).wrapping_sub(composite);
                }
            }
            if mash {
                for i in (0..4).rev() {
                    r[i] = r[i].wrapping_sub(self.table.get((r[(i + 3) % 4] & 63) as usize) as u16);
                }
            }
        }
    }

    /// The expanded key K\[0\] to K\[63\].
    pub fn expanded_key(&self) -> &[u16; 64] {
        &self.words
    }
}

impl BlockCipher for RC2 {
    const BLOCK_SIZE: usize = 8;
    type Block = [u8; 8];

    /// The words R\[0\] to R\[3\] are the bytes of the block in pairs, the low byte first.
    fn encrypt_block(&self, block: &mut [u8; 8]) {
        let mut r = [0u16; 4];
        for (index, word) in r.iter_mut().enumerate() {
            *word = u16::from_le_bytes([block[2 * index], block[2 * index + 1]]);
        }
        self.encrypt_words(&mut r);
        for (index, word) in r.iter().enumerate() {
            block[2 * index..2 * index + 2].copy_from_slice(&word.to_le_bytes());
        }
        r.zeroize();
    }

    fn decrypt_block(&self, block: &mut [u8; 8]) {
        let mut r = [0u16; 4];
        for (index, word) in r.iter_mut().enumerate() {
            *word = u16::from_le_bytes([block[2 * index], block[2 * index + 1]]);
        }
        self.decrypt_words(&mut r);
        for (index, word) in r.iter().enumerate() {
            block[2 * index..2 * index + 2].copy_from_slice(&word.to_le_bytes());
        }
        r.zeroize();
    }
}

/// The effective key length is 8 bits for each byte of the key, up to 1024.
impl KeyInit for RC2 {
    const MINIMUM_KEY_SIZE: usize = 1;
    const MAXIMUM_KEY_SIZE: usize = 128;

    fn new_from_slice(key: &[u8]) -> Result<RC2, CryptoError> {
        RC2::check_key_length(key.len())?;
        RC2::new(key, 8 * key.len())
    }
}

impl Zeroize for RC2 {
    fn zeroize(&mut self) {
        self.words.zeroize();
        self.table.zeroize();
    }
}

impl Drop for RC2 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for RC2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RC2(..)")
    }
}
