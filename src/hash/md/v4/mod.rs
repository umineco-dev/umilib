//! MD4 (RFC 1320).

use core::fmt;

use crate::hash::{BlockBuffer, CryptographicDigest, Digest};
use crate::secret::Zeroize;

/// MD4 (RFC 1320).
#[derive(Clone)]
pub struct MD4 {
    state: [u32; 4],
    buffer: BlockBuffer<64>,
    /// The number of bytes hashed, modulo 2^64.
    length: u64,
}

impl MD4 {
    /// The initial buffer of section 3.3.
    pub const INITIAL_STATE: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    /// The constants added in rounds 1 to 3 (section 3.4).
    pub const CONSTANTS: [u32; 3] = [0, 0x5a827999, 0x6ed9eba1];
    /// The order of the message words in rounds 1 to 3.
    pub const ORDER: [[usize; 16]; 3] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15],
        [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15],
    ];
    /// The rotation amounts of the four steps of rounds 1 to 3.
    pub const SHIFTS: [[u32; 4]; 3] = [[3, 7, 11, 19], [3, 5, 9, 13], [3, 9, 11, 15]];

    pub const fn new() -> MD4 {
        MD4 { state: MD4::INITIAL_STATE, buffer: BlockBuffer::new(), length: 0 }
    }

    /// The auxiliary functions F, G and H of rounds 1 to 3 (section 3.4).
    pub fn function(round: usize, x: u32, y: u32, z: u32) -> u32 {
        match round {
            0 => (x & y) | (!x & z),
            1 => (x & y) | (x & z) | (y & z),
            _ => x ^ y ^ z,
        }
    }

    /// The MD4 compression function (section 3.4) on one block.
    pub fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
        let mut x = [0u32; 16];
        for (word, bytes) in x.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        let [mut a, mut b, mut c, mut d] = *state;
        // Each round applies its operation to (a, b, c, d), (d, a, b, c),
        // (c, d, a, b) and (b, c, d, a) in turn, four times.
        for round in 0..3 {
            for (step, &index) in MD4::ORDER[round].iter().enumerate() {
                let value = a
                    .wrapping_add(MD4::function(round, b, c, d))
                    .wrapping_add(x[index])
                    .wrapping_add(MD4::CONSTANTS[round]);
                (a, b, c, d) = (d, value.rotate_left(MD4::SHIFTS[round][step % 4]), b, c);
            }
        }
        for (word, value) in state.iter_mut().zip([a, b, c, d]) {
            *word = word.wrapping_add(value);
        }
        x.zeroize();
    }
}

impl Digest for MD4 {
    const OUTPUT_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 64;
    type Output = [u8; 16];

    fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        let state = &mut self.state;
        self.buffer.update(data, |block| MD4::compress(state, block));
    }

    fn finalize(mut self) -> [u8; 16] {
        let bits = self.length.wrapping_mul(8).to_le_bytes();
        let state = &mut self.state;
        self.buffer.pad(&bits, |block| MD4::compress(state, block));
        let mut output = [0; 16];
        for (bytes, word) in output.chunks_mut(4).zip(self.state) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        output
    }

    fn reset(&mut self) {
        self.zeroize();
        self.state = MD4::INITIAL_STATE;
    }
}

impl Default for MD4 {
    fn default() -> MD4 {
        MD4::new()
    }
}

impl CryptographicDigest for MD4 {}

impl Zeroize for MD4 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.length.zeroize();
    }
}

impl Drop for MD4 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for MD4 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MD4(..)")
    }
}
