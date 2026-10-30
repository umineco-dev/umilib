//! Kuznyechik (GOST R 34.12-2015, RFC 7801): the 128-bit block cipher of
//! GOST R 34.12-2015, a substitution-permutation network.

use core::fmt;

use crate::crypto::{BlockCipher, CryptoError, KeyInit};
use crate::secret::{ConstantTimeTable, Zeroize};

/// Kuznyechik with a 256-bit key: nine rounds of X, S and L, then X.
///
/// The substitution is read as a [`ConstantTimeTable`], and the linear
/// transformation L, which is linear over GF(2), is applied as a 128 × 128
/// bit matrix computed at compile time: each input bit selects a row with a
/// mask. No branch or memory access depends on the key or the data. Blocks
/// are big-endian `u128`: the byte a_15 of RFC 7801 is the first byte.
#[derive(Clone)]
pub struct Kuznyechik {
    /// The round keys K_1 to K_10.
    round_keys: [u128; 10],
}

impl Kuznyechik {
    pub const KEY_SIZE: usize = 32;
    /// The substitution pi (section 4.1).
    pub const PI: ConstantTimeTable<32, 8> = ConstantTimeTable::from_bytes(&[
        0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D, 0xE9, 0x77,
        0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1, 0xF9, 0x18, 0x65, 0x5A,
        0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F, 0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A,
        0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F, 0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
        0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC, 0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72,
        0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87, 0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F,
        0x9D, 0x9E, 0xB2, 0xB1, 0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD,
        0x0D, 0x57, 0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
        0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A, 0xA7, 0x97,
        0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41, 0xAD, 0x45, 0x46, 0x92,
        0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B, 0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC,
        0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89, 0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
        0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61, 0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B,
        0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52, 0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2,
        0x39, 0x4B, 0x63, 0xB6,
    ]);
    /// The inverse of pi (section 4.1).
    pub const PI_INVERSE: ConstantTimeTable<32, 8> = ConstantTimeTable::from_bytes(&[
        0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91, 0x64, 0x03,
        0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F, 0xE0, 0x27, 0x8D, 0x0C,
        0x82, 0xEA, 0xAE, 0xB4, 0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7, 0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75,
        0x19, 0xC9, 0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5, 0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,
        0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F, 0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F, 0xC1, 0xF0,
        0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E, 0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 0x4A, 0xBC, 0x35, 0xCA,
        0xEE, 0x78, 0x05, 0x6B, 0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB,
        0x77, 0x3C, 0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
        0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD, 0x37, 0x61,
        0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0, 0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA, 0x96, 0x6F, 0x6E, 0xC2,
        0xF6, 0x50, 0xFF, 0x5D, 0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58, 0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D,
        0x7A, 0x67, 0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04, 0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,
        0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80, 0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 0x99, 0x10,
        0x44, 0x40, 0x92, 0x3A, 0x01, 0x26, 0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 0xD6, 0x20, 0x0A, 0x08,
        0x00, 0x4C, 0xD7, 0x74,
    ]);
    /// The coefficients of l for a_15 to a_0 (section 4.2, with the erratum
    /// that the second one is for a_14).
    pub const COEFFICIENTS: [u8; 16] = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1];
    /// The images of the 128 unit vectors under L: row `i` is L(2^i).
    pub const L_MATRIX: [u128; 128] = Kuznyechik::matrix(false);
    /// The images of the 128 unit vectors under L^-1.
    pub const L_INVERSE_MATRIX: [u128; 128] = Kuznyechik::matrix(true);

    /// The product in the field Q = GF(2)\[x\]/(x^8 + x^7 + x^6 + x + 1), in constant time.
    pub const fn multiply(mut a: u8, mut b: u8) -> u8 {
        let mut product = 0u8;
        let mut bit = 0;
        while bit < 8 {
            product ^= a & 0u8.wrapping_sub(b & 1);
            a = (a << 1) ^ (0xC3 & 0u8.wrapping_sub(a >> 7));
            b >>= 1;
            bit += 1;
        }
        product
    }

    /// l(a_15, ..., a_0) (section 4.2), with a_15 the most significant byte of `value`.
    pub const fn l(value: u128) -> u8 {
        let bytes = value.to_be_bytes();
        let mut sum = 0u8;
        let mut index = 0;
        while index < 16 {
            sum ^= Kuznyechik::multiply(bytes[index], Kuznyechik::COEFFICIENTS[index]);
            index += 1;
        }
        sum
    }

    /// R(a) = l(a) || a_15 || ... || a_1 (section 4.3).
    pub const fn r(value: u128) -> u128 {
        ((Kuznyechik::l(value) as u128) << 120) | (value >> 8)
    }

    /// R^-1(a) = a_14 || ... || a_0 || l(a_14, ..., a_0, a_15) (section 4.3).
    pub const fn r_inverse(value: u128) -> u128 {
        let shifted = value << 8;
        shifted | Kuznyechik::l(shifted | (value >> 120)) as u128
    }

    /// L = R^16 or L^-1 = (R^-1)^16 by its definition, which the matrices compute at compile time.
    pub const fn linear_by_definition(mut value: u128, inverse: bool) -> u128 {
        let mut step = 0;
        while step < 16 {
            value = if inverse { Kuznyechik::r_inverse(value) } else { Kuznyechik::r(value) };
            step += 1;
        }
        value
    }

    pub const fn matrix(inverse: bool) -> [u128; 128] {
        let mut rows = [0u128; 128];
        let mut bit = 0;
        while bit < 128 {
            rows[bit] = Kuznyechik::linear_by_definition(1u128 << bit, inverse);
            bit += 1;
        }
        rows
    }

    /// The sum of the rows of `matrix` selected by the bits of `value`: masks, not branches.
    pub fn apply_matrix(matrix: &[u128; 128], value: u128) -> u128 {
        let mut out = 0u128;
        for (bit, row) in matrix.iter().enumerate() {
            out ^= row & 0u128.wrapping_sub((value >> bit) & 1);
        }
        out
    }

    /// L (section 4.3).
    pub fn linear(value: u128) -> u128 {
        Kuznyechik::apply_matrix(&Kuznyechik::L_MATRIX, value)
    }

    /// L^-1 (section 4.3).
    pub fn linear_inverse(value: u128) -> u128 {
        Kuznyechik::apply_matrix(&Kuznyechik::L_INVERSE_MATRIX, value)
    }

    /// S, or S^-1 with `inverse`: pi on each byte (section 4.3).
    pub fn substitute(value: u128, inverse: bool) -> u128 {
        let table = if inverse { &Kuznyechik::PI_INVERSE } else { &Kuznyechik::PI };
        let mut bytes = value.to_be_bytes();
        for byte in bytes.iter_mut() {
            *byte = table.get(*byte as usize) as u8;
        }
        u128::from_be_bytes(bytes)
    }

    /// LSX\[k\](a).
    pub fn round(key: u128, value: u128) -> u128 {
        Kuznyechik::linear(Kuznyechik::substitute(value ^ key, false))
    }

    /// The round keys of section 4.4: the two halves of the key, then four
    /// times eight Feistel rounds F\[C_i\] with the constants C_i = L(Vec_128(i)).
    pub fn new(key: &[u8; 32]) -> Kuznyechik {
        let mut round_keys = [0u128; 10];
        let mut a1 = u128::from_be_bytes(key[..16].try_into().expect("16 bytes"));
        let mut a0 = u128::from_be_bytes(key[16..].try_into().expect("16 bytes"));
        round_keys[0] = a1;
        round_keys[1] = a0;
        for pair in 1..5 {
            for index in 8 * (pair - 1) + 1..=8 * pair {
                let constant = Kuznyechik::linear(index as u128);
                let next = Kuznyechik::round(constant, a1) ^ a0;
                a0 = a1;
                a1 = next;
            }
            round_keys[2 * pair] = a1;
            round_keys[2 * pair + 1] = a0;
        }
        a1.zeroize();
        a0.zeroize();
        Kuznyechik { round_keys }
    }

    /// The round keys K_1 to K_10.
    pub fn round_keys(&self) -> &[u128; 10] {
        &self.round_keys
    }
}

impl BlockCipher for Kuznyechik {
    const BLOCK_SIZE: usize = 16;
    type Block = [u8; 16];

    /// E = X\[K_10\] LSX\[K_9\] ... LSX\[K_1\] (section 4.5.1).
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut value = u128::from_be_bytes(*block);
        for key in &self.round_keys[..9] {
            value = Kuznyechik::round(*key, value);
        }
        *block = (value ^ self.round_keys[9]).to_be_bytes();
        value.zeroize();
    }

    /// D = X\[K_1\] S^-1 L^-1 X\[K_2\] ... S^-1 L^-1 X\[K_10\] (section 4.5.2).
    fn decrypt_block(&self, block: &mut [u8; 16]) {
        let mut value = u128::from_be_bytes(*block);
        for key in self.round_keys[1..].iter().rev() {
            value = Kuznyechik::substitute(Kuznyechik::linear_inverse(value ^ key), true);
        }
        *block = (value ^ self.round_keys[0]).to_be_bytes();
        value.zeroize();
    }
}

impl KeyInit for Kuznyechik {
    const MINIMUM_KEY_SIZE: usize = 32;
    const MAXIMUM_KEY_SIZE: usize = 32;

    fn new_from_slice(key: &[u8]) -> Result<Kuznyechik, CryptoError> {
        Kuznyechik::check_key_length(key.len())?;
        let key: &[u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidParameter)?;
        Ok(Kuznyechik::new(key))
    }
}

impl Zeroize for Kuznyechik {
    fn zeroize(&mut self) {
        self.round_keys.zeroize();
    }
}

impl Drop for Kuznyechik {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for Kuznyechik {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Kuznyechik(..)")
    }
}
