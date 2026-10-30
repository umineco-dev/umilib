//! Arithmetic in GF(2^8), for the S-boxes that are defined by it.

pub struct GF256;

impl GF256 {
    /// The product of `a` and `b` modulo x^8 + `reduction` (the low eight
    /// bits of the polynomial: 0x1B for x^8 + x^4 + x^3 + x + 1 of AES).
    pub fn multiply(mut a: u8, mut b: u8, reduction: u8) -> u8 {
        let mut product = 0u8;
        while b != 0 {
            if b & 1 == 1 {
                product ^= a;
            }
            a = (a << 1) ^ if a & 0x80 != 0 { reduction } else { 0 };
            b >>= 1;
        }
        product
    }

    /// The inverse of `x`, and 0 for 0.
    pub fn inverse(x: u8, reduction: u8) -> u8 {
        (1..=255u8).find(|&y| GF256::multiply(x, y, reduction) == 1).unwrap_or(0)
    }

    /// The S-box of AES (FIPS 197 section 5.1.1): the inverse in GF(2^8)
    /// followed by the affine transformation.
    pub fn aes_sbox(x: u8) -> u8 {
        let inverse = GF256::inverse(x, 0x1B);
        let mut result = 0x63u8;
        for bit in 0..8 {
            let value = (inverse >> bit)
                ^ (inverse >> ((bit + 4) % 8))
                ^ (inverse >> ((bit + 5) % 8))
                ^ (inverse >> ((bit + 6) % 8))
                ^ (inverse >> ((bit + 7) % 8));
            result ^= (value & 1) << bit;
        }
        result
    }
}
