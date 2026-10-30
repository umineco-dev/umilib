//! Adler-32, the checksum of zlib streams (RFC 1950 sections 8 and 9).

use crate::hash::Digest;

/// The Adler-32 checksum: A = 1 plus the sum of the bytes and B the sum of
/// the values of A after each byte, both modulo 65521; the value is
/// B × 65536 + A. As a [`Digest`] the output is the value in big-endian
/// order, as zlib streams store it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adler32 {
    a: u32,
    b: u32,
}

impl Adler32 {
    /// The largest prime below 2^16.
    pub const MODULUS: u32 = 65521;
    /// The most bytes summed before reducing modulo [`Adler32::MODULUS`]
    /// without overflowing 32 bits: the largest n with
    /// 255 n (n + 1) / 2 + (n + 1)(65521 - 1) < 2^32.
    pub const BLOCK: usize = 5552;

    /// The state of no input (A = 1, B = 0).
    pub const fn new() -> Adler32 {
        Adler32 { a: 1, b: 0 }
    }

    /// The state whose checksum so far is `value`, to continue a checksum.
    pub const fn with_value(value: u32) -> Adler32 {
        Adler32 { a: (value & 0xFFFF) % Adler32::MODULUS, b: (value >> 16) % Adler32::MODULUS }
    }

    /// The checksum of `data`.
    pub fn checksum(data: &[u8]) -> u32 {
        let mut adler = Adler32::new();
        adler.update(data);
        adler.value()
    }

    pub fn update(&mut self, data: &[u8]) {
        for block in data.chunks(Adler32::BLOCK) {
            for &byte in block {
                self.a += byte as u32;
                self.b += self.a;
            }
            self.a %= Adler32::MODULUS;
            self.b %= Adler32::MODULUS;
        }
    }

    /// The checksum of the input so far.
    pub const fn value(&self) -> u32 {
        self.b << 16 | self.a
    }

    pub fn reset(&mut self) {
        *self = Adler32::new();
    }
}

impl Default for Adler32 {
    fn default() -> Adler32 {
        Adler32::new()
    }
}

impl Digest for Adler32 {
    const OUTPUT_SIZE: usize = 4;
    const BLOCK_SIZE: usize = 1;
    type Output = [u8; 4];

    fn update(&mut self, data: &[u8]) {
        Adler32::update(self, data);
    }

    fn finalize(self) -> [u8; 4] {
        self.value().to_be_bytes()
    }

    fn reset(&mut self) {
        Adler32::reset(self);
    }
}
