//! SM3 (GB/T 32905-2016, ISO/IEC 10118-3:2018), the hash function of the
//! Chinese commercial cryptography standards, as described in
//! draft-sca-cfrg-sm3.

use core::fmt;

use crate::hash::{BlockBuffer, CryptographicDigest, Digest};
use crate::secret::Zeroize;

/// SM3 (GB/T 32905-2016).
#[derive(Clone)]
pub struct SM3 {
    state: [u32; 8],
    buffer: BlockBuffer<64>,
    /// The number of bytes hashed, modulo 2^64.
    length: u64,
}

impl SM3 {
    /// The initialization vector (section 4.1 of the draft).
    pub const INITIAL_STATE: [u32; 8] =
        [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];
    /// The constants T_j for steps 0 to 15 and 16 to 63 (section 4.2).
    pub const T: [u32; 2] = [0x79cc4519, 0x7a879d8a];

    pub const fn new() -> SM3 {
        SM3 { state: SM3::INITIAL_STATE, buffer: BlockBuffer::new(), length: 0 }
    }

    /// The permutation P_0 (section 4.4).
    pub const fn p0(x: u32) -> u32 {
        x ^ x.rotate_left(9) ^ x.rotate_left(17)
    }

    /// The permutation P_1 (section 4.4).
    pub const fn p1(x: u32) -> u32 {
        x ^ x.rotate_left(15) ^ x.rotate_left(23)
    }

    /// The compression function CF (section 5.3.3) after the message
    /// expansion ME (section 5.3.2), on one block.
    pub fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 68];
        for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for j in 16..68 {
            w[j] = SM3::p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15)) ^ w[j - 13].rotate_left(7) ^ w[j - 6];
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for j in 0..64 {
            let first = j < 16;
            let constant = SM3::T[if first { 0 } else { 1 }].rotate_left((j % 32) as u32);
            let ss1 = a.rotate_left(12).wrapping_add(e).wrapping_add(constant).rotate_left(7);
            let ss2 = ss1 ^ a.rotate_left(12);
            let ff = if first { a ^ b ^ c } else { (a & b) | (a & c) | (b & c) };
            let gg = if first { e ^ f ^ g } else { (e & f) | (!e & g) };
            let tt1 = ff.wrapping_add(d).wrapping_add(ss2).wrapping_add(w[j] ^ w[j + 4]);
            let tt2 = gg.wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);
            d = c;
            c = b.rotate_left(9);
            b = a;
            a = tt1;
            h = g;
            g = f.rotate_left(19);
            f = e;
            e = SM3::p0(tt2);
        }
        for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word ^= value;
        }
        w.zeroize();
    }
}

impl Digest for SM3 {
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    type Output = [u8; 32];

    fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        let state = &mut self.state;
        self.buffer.update(data, |block| SM3::compress(state, block));
    }

    fn finalize(mut self) -> [u8; 32] {
        let bits = self.length.wrapping_mul(8).to_be_bytes();
        let state = &mut self.state;
        self.buffer.pad(&bits, |block| SM3::compress(state, block));
        let mut output = [0; 32];
        for (bytes, word) in output.chunks_mut(4).zip(self.state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    fn reset(&mut self) {
        self.zeroize();
        self.state = SM3::INITIAL_STATE;
    }
}

impl Default for SM3 {
    fn default() -> SM3 {
        SM3::new()
    }
}

impl CryptographicDigest for SM3 {}

impl Zeroize for SM3 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.length.zeroize();
    }
}

impl Drop for SM3 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for SM3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SM3(..)")
    }
}
