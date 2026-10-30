//! SHA-1 (FIPS 180-4 section 6.1).
//!
//! SHA-1 is broken for collision resistance (practical collisions exist since
//! 2017): use it only where a protocol requires it, such as HMAC-SHA-1 or
//! legacy identifiers, never for new signatures.

use core::fmt;

use crate::hash::{BlockBuffer, CryptographicDigest, Digest};
use crate::secret::Zeroize;

/// SHA-1 (FIPS 180-4 section 6.1).
#[derive(Clone)]
pub struct SHA1 {
    state: [u32; 5],
    buffer: BlockBuffer<64>,
    /// The number of bytes hashed, modulo 2^64.
    length: u64,
}

impl SHA1 {
    /// The initial hash value of section 5.3.1.
    pub const INITIAL_STATE: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    /// The constants of section 4.2.1, one per twenty rounds.
    pub const K: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

    pub const fn new() -> SHA1 {
        SHA1 { state: SHA1::INITIAL_STATE, buffer: BlockBuffer::new(), length: 0 }
    }

    /// The SHA-1 compression function (section 6.1.2) on one block.
    pub fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
        let mut schedule = [0u32; 80];
        for (word, bytes) in schedule.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for t in 16..80 {
            schedule[t] = (schedule[t - 3] ^ schedule[t - 8] ^ schedule[t - 14] ^ schedule[t - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *state;
        for (t, &word) in schedule.iter().enumerate() {
            let function = match t / 20 {
                0 => (b & c) ^ (!b & d),
                2 => (b & c) ^ (b & d) ^ (c & d),
                _ => b ^ c ^ d,
            };
            let temporary = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(SHA1::K[t / 20])
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temporary;
        }
        for (word, value) in state.iter_mut().zip([a, b, c, d, e]) {
            *word = word.wrapping_add(value);
        }
        schedule.zeroize();
    }
}

impl Digest for SHA1 {
    const OUTPUT_SIZE: usize = 20;
    const BLOCK_SIZE: usize = 64;
    type Output = [u8; 20];

    fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        let state = &mut self.state;
        self.buffer.update(data, |block| SHA1::compress(state, block));
    }

    fn finalize(mut self) -> [u8; 20] {
        let bits = self.length.wrapping_mul(8).to_be_bytes();
        let state = &mut self.state;
        self.buffer.pad(&bits, |block| SHA1::compress(state, block));
        let mut output = [0; 20];
        for (bytes, word) in output.chunks_mut(4).zip(self.state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    fn reset(&mut self) {
        self.zeroize();
        self.state = SHA1::INITIAL_STATE;
    }
}

impl Default for SHA1 {
    fn default() -> SHA1 {
        SHA1::new()
    }
}

impl CryptographicDigest for SHA1 {}

impl Zeroize for SHA1 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.length.zeroize();
    }
}

impl Drop for SHA1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for SHA1 {
    /// Does not print the state, which depends on the input.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SHA1(..)")
    }
}
