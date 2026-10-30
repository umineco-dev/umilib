use core::fmt;

use crate::hash::{BlockBuffer, CryptographicDigest, Digest, HashError};
use crate::secret::Zeroize;

/// SHA-256 (FIPS 180-4 section 6.2).
#[derive(Clone)]
pub struct SHA256 {
    state: [u32; 8],
    /// The initial hash value, to which `reset` returns.
    initial: [u32; 8],
    buffer: BlockBuffer<64>,
    /// The number of bytes hashed, modulo 2^64.
    length: u64,
}

impl SHA256 {
    /// The initial hash value of section 5.3.3.
    pub const INITIAL_STATE: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    /// The constants of section 4.2.2.
    pub const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub const fn new() -> SHA256 {
        SHA256::with_state(SHA256::INITIAL_STATE)
    }

    /// The function with another initial hash value, as SHA-224 uses.
    pub const fn with_state(state: [u32; 8]) -> SHA256 {
        SHA256 { state, initial: state, buffer: BlockBuffer::new(), length: 0 }
    }

    /// The SHA-256 compression function (section 6.2.2) on one block.
    pub fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut schedule = [0u32; 64];
        for (word, bytes) in schedule.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for t in 16..64 {
            let s0 = schedule[t - 15].rotate_right(7) ^ schedule[t - 15].rotate_right(18) ^ (schedule[t - 15] >> 3);
            let s1 = schedule[t - 2].rotate_right(17) ^ schedule[t - 2].rotate_right(19) ^ (schedule[t - 2] >> 10);
            schedule[t] = schedule[t - 16].wrapping_add(s0).wrapping_add(schedule[t - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for (constant, word) in SHA256::K.iter().zip(schedule) {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(sum1).wrapping_add(choose).wrapping_add(*constant).wrapping_add(word);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = word.wrapping_add(value);
        }
        schedule.zeroize();
    }

    /// Pads the input (section 5.1.1) and returns the final hash value.
    pub fn finalize_state(mut self) -> [u32; 8] {
        let bits = self.length.wrapping_mul(8).to_be_bytes();
        let state = &mut self.state;
        self.buffer.pad(&bits, |block| SHA256::compress(state, block));
        self.state
    }

    /// Writes the final hash value as big-endian bytes, truncated to
    /// `out.len()` bytes, as the truncated functions use; fails unless that
    /// is 1 to 32.
    pub fn finalize_truncated(self, out: &mut [u8]) -> Result<(), HashError> {
        if out.is_empty() || out.len() > 32 {
            return Err(HashError::OutputLength { length: out.len(), minimum: 1, maximum: 32 });
        }
        let mut state = self.finalize_state();
        for (bytes, word) in out.chunks_mut(4).zip(state) {
            bytes.copy_from_slice(&word.to_be_bytes()[..bytes.len()]);
        }
        state.zeroize();
        Ok(())
    }
}

impl Digest for SHA256 {
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    type Output = [u8; 32];

    fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        let state = &mut self.state;
        self.buffer.update(data, |block| SHA256::compress(state, block));
    }

    fn finalize(self) -> [u8; 32] {
        let mut output = [0; 32];
        // The output has the full length.
        let _ = self.finalize_truncated(&mut output);
        output
    }

    fn reset(&mut self) {
        let initial = self.initial;
        self.zeroize();
        self.state = initial;
        self.initial = initial;
    }
}

impl Default for SHA256 {
    fn default() -> SHA256 {
        SHA256::new()
    }
}

impl CryptographicDigest for SHA256 {}

impl Zeroize for SHA256 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.length.zeroize();
    }
}

impl Drop for SHA256 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for SHA256 {
    /// Does not print the state, which depends on the input.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SHA256(..)")
    }
}

/// SHA-224 (FIPS 180-4 section 6.3): SHA-256 with another initial hash
/// value, truncated to 224 bits.
#[derive(Clone)]
pub struct SHA224 {
    inner: SHA256,
}

impl SHA224 {
    /// The initial hash value of section 5.3.2.
    pub const INITIAL_STATE: [u32; 8] =
        [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];

    pub const fn new() -> SHA224 {
        SHA224 { inner: SHA256::with_state(SHA224::INITIAL_STATE) }
    }
}

impl Digest for SHA224 {
    const OUTPUT_SIZE: usize = 28;
    const BLOCK_SIZE: usize = 64;
    type Output = [u8; 28];

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> [u8; 28] {
        let mut output = [0; 28];
        // The output is shorter than the full hash value.
        let _ = self.inner.finalize_truncated(&mut output);
        output
    }

    fn reset(&mut self) {
        *self = SHA224::new();
    }
}

impl Default for SHA224 {
    fn default() -> SHA224 {
        SHA224::new()
    }
}

impl CryptographicDigest for SHA224 {}

impl Zeroize for SHA224 {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl fmt::Debug for SHA224 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SHA224(..)")
    }
}
