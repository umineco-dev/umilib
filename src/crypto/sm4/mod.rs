//! SM4 (GB/T 32907-2016, draft-ribose-cfrg-sm4): the 128-bit block cipher of
//! the Chinese commercial cryptography standards.

use core::fmt;

use crate::crypto::{BlockCipher, CryptoError, KeyInit};
use crate::secret::{ConstantTimeTable, Zeroize};

/// SM4 with a 128-bit key: 32 rounds of an unbalanced Feistel network on
/// four 32-bit words. The S-box is read as a [`ConstantTimeTable`], so no
/// memory access depends on the key or the data.
#[derive(Clone)]
pub struct SM4 {
    round_keys: [u32; 32],
}

impl SM4 {
    pub const KEY_SIZE: usize = 16;
    pub const ROUNDS: usize = 32;
    /// The S-box S (section 6.2.3).
    pub const SBOX: ConstantTimeTable<32, 8> = ConstantTimeTable::from_bytes(&[
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67,
        0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
        0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62, 0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08,
        0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
        0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB,
        0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35, 0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
        0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4,
        0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6,
        0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
        0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51, 0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD,
        0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
        0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9,
        0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84, 0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
        0xD7, 0xCB, 0x39, 0x48,
    ]);
    /// The family key FK (section 7.3.1).
    pub const FAMILY_KEY: [u32; 4] = [0xA3B1_BAC6, 0x56AA_3350, 0x677D_9197, 0xB270_22DC];

    pub fn new(key: &[u8; 16]) -> SM4 {
        let mut k = [0u32; 4];
        for (index, word) in k.iter_mut().enumerate() {
            *word = u32::from_be_bytes(key[4 * index..4 * index + 4].try_into().expect("four bytes"))
                ^ SM4::FAMILY_KEY[index];
        }
        let mut round_keys = [0u32; 32];
        for (index, round_key) in round_keys.iter_mut().enumerate() {
            let next = k[0] ^ SM4::key_transform(k[1] ^ k[2] ^ k[3] ^ SM4::constant_key(index));
            k = [k[1], k[2], k[3], next];
            *round_key = next;
        }
        k.zeroize();
        SM4 { round_keys }
    }

    /// The constant key CK_i: bytes (4i + j) × 7 mod 256 (section 7.3.2).
    pub const fn constant_key(index: usize) -> u32 {
        let mut word = 0u32;
        let mut byte = 0;
        while byte < 4 {
            word = (word << 8) | (((4 * index + byte) * 7) % 256) as u32;
            byte += 1;
        }
        word
    }

    /// tau: the S-box on each byte (section 6.2.1).
    pub fn substitute(word: u32) -> u32 {
        let mut out = 0u32;
        for byte in word.to_be_bytes() {
            out = (out << 8) | SM4::SBOX.get(byte as usize);
        }
        out
    }

    /// T = L(tau(.)), the permutation of the rounds (section 6.2).
    pub fn transform(word: u32) -> u32 {
        let b = SM4::substitute(word);
        b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
    }

    /// T' = L'(tau(.)), the permutation of the key schedule (section 6.2).
    pub fn key_transform(word: u32) -> u32 {
        let b = SM4::substitute(word);
        b ^ b.rotate_left(13) ^ b.rotate_left(23)
    }

    /// The 32 rounds with the round keys `keys`, then the reverse transformation R.
    pub fn apply_rounds(&self, block: &mut [u8; 16], keys: impl Iterator<Item = u32>) {
        let mut x = [0u32; 4];
        for (index, word) in x.iter_mut().enumerate() {
            *word = u32::from_be_bytes(block[4 * index..4 * index + 4].try_into().expect("four bytes"));
        }
        for key in keys {
            let next = x[0] ^ SM4::transform(x[1] ^ x[2] ^ x[3] ^ key);
            x = [x[1], x[2], x[3], next];
        }
        for (index, word) in x.iter().rev().enumerate() {
            block[4 * index..4 * index + 4].copy_from_slice(&word.to_be_bytes());
        }
        x.zeroize();
    }

    /// The round keys rk_0 to rk_31.
    pub fn round_keys(&self) -> &[u32; 32] {
        &self.round_keys
    }
}

impl BlockCipher for SM4 {
    const BLOCK_SIZE: usize = 16;
    type Block = [u8; 16];

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.apply_rounds(block, self.round_keys.iter().copied());
    }

    /// Decryption is encryption with the round keys reversed (section 7.2).
    fn decrypt_block(&self, block: &mut [u8; 16]) {
        self.apply_rounds(block, self.round_keys.iter().rev().copied());
    }
}

impl KeyInit for SM4 {
    const MINIMUM_KEY_SIZE: usize = 16;
    const MAXIMUM_KEY_SIZE: usize = 16;

    fn new_from_slice(key: &[u8]) -> Result<SM4, CryptoError> {
        SM4::check_key_length(key.len())?;
        let key: &[u8; 16] = key.try_into().map_err(|_| CryptoError::InvalidParameter)?;
        Ok(SM4::new(key))
    }
}

impl Zeroize for SM4 {
    fn zeroize(&mut self) {
        self.round_keys.zeroize();
    }
}

impl Drop for SM4 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for SM4 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SM4(..)")
    }
}
