use core::fmt;

use crate::hash::{BlockBuffer, CryptographicDigest, Digest, HashError};
use crate::secret::Zeroize;

/// SHA-512 (FIPS 180-4 section 6.4).
#[derive(Clone)]
pub struct SHA512 {
    state: [u64; 8],
    /// The initial hash value, to which `reset` returns.
    initial: [u64; 8],
    buffer: BlockBuffer<128>,
    /// The number of bytes hashed, modulo 2^128.
    length: u128,
}

impl SHA512 {
    /// The initial hash value of section 5.3.5.
    pub const INITIAL_STATE: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    /// The constants of section 4.2.3.
    pub const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    pub const fn new() -> SHA512 {
        SHA512::with_state(SHA512::INITIAL_STATE)
    }

    /// The function with another initial hash value, as SHA-384 and SHA-512/t use.
    pub const fn with_state(state: [u64; 8]) -> SHA512 {
        SHA512 { state, initial: state, buffer: BlockBuffer::new(), length: 0 }
    }

    /// The initial hash value of SHA-512/t, generated as section 5.3.6
    /// describes: SHA-512 of the text "SHA-512/t" with the initial value
    /// XOR `0xa5a5a5a5a5a5a5a5`. `None` unless `t` is below 512, not 384, and
    /// not zero.
    pub fn truncated_initial_state(t: u32) -> Option<[u64; 8]> {
        if t == 0 || t >= 512 || t == 384 {
            return None;
        }
        let mut state = SHA512::INITIAL_STATE;
        for word in state.iter_mut() {
            *word ^= 0xa5a5a5a5a5a5a5a5;
        }
        // "SHA-512/" and t in decimal, of at most three digits.
        let mut name = *b"SHA-512/000";
        let digits = if t >= 100 {
            3
        } else if t >= 10 {
            2
        } else {
            1
        };
        let mut value = t;
        for index in (0..digits).rev() {
            name[8 + index] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        let mut hash = SHA512::with_state(state);
        hash.update(&name[..8 + digits]);
        Some(hash.finalize_state())
    }

    /// The SHA-512 compression function (section 6.4.2) on one block.
    pub fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
        let mut schedule = [0u64; 80];
        for (word, bytes) in schedule.iter_mut().zip(block.as_chunks::<8>().0) {
            *word = u64::from_be_bytes(*bytes);
        }
        for t in 16..80 {
            let s0 = schedule[t - 15].rotate_right(1) ^ schedule[t - 15].rotate_right(8) ^ (schedule[t - 15] >> 7);
            let s1 = schedule[t - 2].rotate_right(19) ^ schedule[t - 2].rotate_right(61) ^ (schedule[t - 2] >> 6);
            schedule[t] = schedule[t - 16].wrapping_add(s0).wrapping_add(schedule[t - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for (constant, word) in SHA512::K.iter().zip(schedule) {
            let sum1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let choose = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(sum1).wrapping_add(choose).wrapping_add(*constant).wrapping_add(word);
            let sum0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
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

    /// Pads the input (section 5.1.2) and returns the final hash value.
    pub fn finalize_state(mut self) -> [u64; 8] {
        let bits = self.length.wrapping_mul(8).to_be_bytes();
        let state = &mut self.state;
        self.buffer.pad(&bits, |block| SHA512::compress(state, block));
        self.state
    }

    /// Writes the final hash value as big-endian bytes, truncated to
    /// `out.len()` bytes, as the truncated functions use; fails unless that
    /// is 1 to 64.
    pub fn finalize_truncated(self, out: &mut [u8]) -> Result<(), HashError> {
        if out.is_empty() || out.len() > 64 {
            return Err(HashError::OutputLength { length: out.len(), minimum: 1, maximum: 64 });
        }
        let mut state = self.finalize_state();
        for (bytes, word) in out.chunks_mut(8).zip(state) {
            bytes.copy_from_slice(&word.to_be_bytes()[..bytes.len()]);
        }
        state.zeroize();
        Ok(())
    }
}

impl Digest for SHA512 {
    const OUTPUT_SIZE: usize = 64;
    const BLOCK_SIZE: usize = 128;
    type Output = [u8; 64];

    fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u128);
        let state = &mut self.state;
        self.buffer.update(data, |block| SHA512::compress(state, block));
    }

    fn finalize(self) -> [u8; 64] {
        let mut output = [0; 64];
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

impl Default for SHA512 {
    fn default() -> SHA512 {
        SHA512::new()
    }
}

impl CryptographicDigest for SHA512 {}

impl Zeroize for SHA512 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.length.zeroize();
    }
}

impl Drop for SHA512 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for SHA512 {
    /// Does not print the state, which depends on the input.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SHA512(..)")
    }
}

/// Defines a function that is SHA-512 with another initial hash value,
/// truncated to `$output` bytes.
macro_rules! truncated_sha512 {
    ($(#[$documentation:meta])* $name:ident, $output:literal, $state:expr) => {
        $(#[$documentation])*
        #[derive(Clone)]
        pub struct $name {
            inner: SHA512,
        }

        impl $name {
            pub const INITIAL_STATE: [u64; 8] = $state;

            pub const fn new() -> $name {
                $name { inner: SHA512::with_state($name::INITIAL_STATE) }
            }
        }

        impl Digest for $name {
            const OUTPUT_SIZE: usize = $output;
            const BLOCK_SIZE: usize = 128;
            type Output = [u8; $output];

            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            fn finalize(self) -> [u8; $output] {
                let mut output = [0; $output];
                // The output is shorter than the full hash value.
        let _ = self.inner.finalize_truncated(&mut output);
                output
            }

            fn reset(&mut self) {
                *self = $name::new();
            }
        }

        impl Default for $name {
            fn default() -> $name {
                $name::new()
            }
        }

        impl CryptographicDigest for $name {}

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.inner.zeroize();
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

truncated_sha512!(
    /// SHA-384 (FIPS 180-4 section 6.5), with the initial hash value of section 5.3.4.
    SHA384,
    48,
    [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ]
);

truncated_sha512!(
    /// SHA-512/224 (FIPS 180-4 section 6.6), with the initial hash value of section 5.3.6.1.
    SHA512_224,
    28,
    [
        0x8C3D37C819544DA2,
        0x73E1996689DCD4D6,
        0x1DFAB7AE32FF9C82,
        0x679DD514582F9FCF,
        0x0F6D2B697BD44DA8,
        0x77E36F7304C48942,
        0x3F9D85A86A1D36C8,
        0x1112E6AD91D692A1,
    ]
);

truncated_sha512!(
    /// SHA-512/256 (FIPS 180-4 section 6.7), with the initial hash value of section 5.3.6.2.
    SHA512_256,
    32,
    [
        0x22312194FC2BF72C,
        0x9F555FA3C84C64C2,
        0x2393B86B6F53B151,
        0x963877195940EABD,
        0x96283EE2A88EFFE3,
        0xBE5E1E2553863992,
        0x2B0199FC2C85B8AA,
        0x0EB72DDC81C52CA2,
    ]
);
