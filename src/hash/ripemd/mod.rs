//! RIPEMD-128, RIPEMD-160, RIPEMD-256 and RIPEMD-320 (H. Dobbertin,
//! A. Bosselaers, B. Preneel, "RIPEMD-160: A strengthened version of RIPEMD",
//! 1996, and the extensions of <https://homes.esat.kuleuven.be/~bosselae/ripemd160.html>).
//!
//! Two parallel lines of MD4-like steps process every block. RIPEMD-256 and
//! RIPEMD-320 keep the lines apart for a longer result, but are no stronger
//! than RIPEMD-128 and RIPEMD-160. RIPEMD-160 remains in use in Bitcoin
//! addresses and OpenPGP; prefer SHA-2 or SHA-3 elsewhere.

use core::fmt;

use crate::hash::{BlockBuffer, CryptographicDigest, Digest};
use crate::secret::Zeroize;

/// The constants that the four functions share, indexed by step.
pub struct RIPEMDConstants;

impl RIPEMDConstants {
    /// The message word of each step of the left line.
    pub const R: [usize; 80] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3,
        10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0,
        5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ];
    /// The message word of each step of the right line.
    pub const R_PRIME: [usize; 80] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15,
        5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15,
        10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ];
    /// The rotation of each step of the left line.
    pub const S: [u32; 80] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ];
    /// The rotation of each step of the right line.
    pub const S_PRIME: [u32; 80] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ];
    /// The constants of the left line, one per round: int(2^30 * sqrt(2, 3, 5, 7)).
    pub const K: [u32; 5] = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
    /// The constants of the right line of RIPEMD-160 and RIPEMD-320: int(2^30 * cbrt(2, 3, 5, 7)).
    pub const K_PRIME: [u32; 5] = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];
    /// The constants of the right line of RIPEMD-128 and RIPEMD-256, which have four rounds.
    pub const K_PRIME_128: [u32; 4] = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x00000000];
    /// The initial values; RIPEMD-256 and RIPEMD-320 start their right line with the extended ones.
    pub const INITIAL: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    pub const INITIAL_EXTENDED: [u32; 5] = [0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567, 0x3C2D1E0F];

    /// The nonlinear function of round `round` (0 to 4).
    pub fn f(round: usize, x: u32, y: u32, z: u32) -> u32 {
        match round {
            0 => x ^ y ^ z,
            1 => (x & y) | (!x & z),
            2 => (x | !y) ^ z,
            3 => (x & z) | (y & !z),
            _ => x ^ (y | !z),
        }
    }

    /// The words of a block, little-endian.
    pub fn words(block: &[u8; 64]) -> [u32; 16] {
        let mut words = [0u32; 16];
        for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        words
    }

    /// One step of the four-word lines (RIPEMD-128 and RIPEMD-256) on `line` = (A, B, C, D).
    pub fn step4(line: &mut [u32; 4], value: u32, rotation: u32) {
        let t = line[0].wrapping_add(value).rotate_left(rotation);
        *line = [line[3], t, line[1], line[2]];
    }

    /// One step of the five-word lines (RIPEMD-160 and RIPEMD-320) on `line` = (A, B, C, D, E).
    pub fn step5(line: &mut [u32; 5], value: u32, rotation: u32) {
        let t = line[0].wrapping_add(value).rotate_left(rotation).wrapping_add(line[4]);
        *line = [line[4], t, line[1], line[2].rotate_left(10), line[3]];
    }

    /// Runs the 64 steps of the two four-word lines, calling `exchange` after every round.
    pub fn lines4(
        left: &mut [u32; 4],
        right: &mut [u32; 4],
        x: &[u32; 16],
        mut exchange: impl FnMut(usize, &mut [u32; 4], &mut [u32; 4]),
    ) {
        for j in 0..64 {
            let round = j / 16;
            let value = RIPEMDConstants::f(round, left[1], left[2], left[3])
                .wrapping_add(x[RIPEMDConstants::R[j]])
                .wrapping_add(RIPEMDConstants::K[round]);
            RIPEMDConstants::step4(left, value, RIPEMDConstants::S[j]);
            let value = RIPEMDConstants::f(3 - round, right[1], right[2], right[3])
                .wrapping_add(x[RIPEMDConstants::R_PRIME[j]])
                .wrapping_add(RIPEMDConstants::K_PRIME_128[round]);
            RIPEMDConstants::step4(right, value, RIPEMDConstants::S_PRIME[j]);
            if j % 16 == 15 {
                exchange(round, left, right);
            }
        }
    }

    /// Runs the 80 steps of the two five-word lines, calling `exchange` after every round.
    pub fn lines5(
        left: &mut [u32; 5],
        right: &mut [u32; 5],
        x: &[u32; 16],
        mut exchange: impl FnMut(usize, &mut [u32; 5], &mut [u32; 5]),
    ) {
        for j in 0..80 {
            let round = j / 16;
            let value = RIPEMDConstants::f(round, left[1], left[2], left[3])
                .wrapping_add(x[RIPEMDConstants::R[j]])
                .wrapping_add(RIPEMDConstants::K[round]);
            RIPEMDConstants::step5(left, value, RIPEMDConstants::S[j]);
            let value = RIPEMDConstants::f(4 - round, right[1], right[2], right[3])
                .wrapping_add(x[RIPEMDConstants::R_PRIME[j]])
                .wrapping_add(RIPEMDConstants::K_PRIME[round]);
            RIPEMDConstants::step5(right, value, RIPEMDConstants::S_PRIME[j]);
            if j % 16 == 15 {
                exchange(round, left, right);
            }
        }
    }
}

/// Defines a RIPEMD function with `$words` words of state.
macro_rules! ripemd {
    ($(#[$documentation:meta])* $name:ident, $words:literal, $initial:expr, $compress:expr) => {
        $(#[$documentation])*
        #[derive(Clone)]
        pub struct $name {
            state: [u32; $words],
            buffer: BlockBuffer<64>,
            /// The number of bytes hashed, modulo 2^64.
            length: u64,
        }

        impl $name {
            pub const INITIAL_STATE: [u32; $words] = $initial;

            pub const fn new() -> $name {
                $name { state: $name::INITIAL_STATE, buffer: BlockBuffer::new(), length: 0 }
            }

            /// The compression function on one block.
            pub fn compress(state: &mut [u32; $words], block: &[u8; 64]) {
                let compress: fn(&mut [u32; $words], &[u32; 16]) = $compress;
                let mut x = RIPEMDConstants::words(block);
                compress(state, &x);
                x.zeroize();
            }
        }

        impl Digest for $name {
            const OUTPUT_SIZE: usize = 4 * $words;
            const BLOCK_SIZE: usize = 64;
            type Output = [u8; 4 * $words];

            fn update(&mut self, data: &[u8]) {
                self.length = self.length.wrapping_add(data.len() as u64);
                let state = &mut self.state;
                self.buffer.update(data, |block| $name::compress(state, block));
            }

            fn finalize(mut self) -> [u8; 4 * $words] {
                // The padding of MD4: the length in bits, little-endian.
                let bits = self.length.wrapping_mul(8).to_le_bytes();
                let state = &mut self.state;
                self.buffer.pad(&bits, |block| $name::compress(state, block));
                let mut output = [0; 4 * $words];
                for (bytes, word) in output.chunks_mut(4).zip(self.state) {
                    bytes.copy_from_slice(&word.to_le_bytes());
                }
                output
            }

            fn reset(&mut self) {
                self.zeroize();
                self.state = $name::INITIAL_STATE;
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
                self.state.zeroize();
                self.buffer.zeroize();
                self.length.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

ripemd!(
    /// RIPEMD-128: two lines of four rounds, combined after every block.
    RIPEMD128,
    4,
    [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
    |state, x| {
        let (mut left, mut right) = (*state, *state);
        RIPEMDConstants::lines4(&mut left, &mut right, x, |_, _, _| {});
        *state = [
            state[1].wrapping_add(left[2]).wrapping_add(right[3]),
            state[2].wrapping_add(left[3]).wrapping_add(right[0]),
            state[3].wrapping_add(left[0]).wrapping_add(right[1]),
            state[0].wrapping_add(left[1]).wrapping_add(right[2]),
        ];
    }
);

ripemd!(
    /// RIPEMD-160: two lines of five rounds, combined after every block.
    RIPEMD160,
    5,
    RIPEMDConstants::INITIAL,
    |state, x| {
        let (mut left, mut right) = (*state, *state);
        RIPEMDConstants::lines5(&mut left, &mut right, x, |_, _, _| {});
        *state = [
            state[1].wrapping_add(left[2]).wrapping_add(right[3]),
            state[2].wrapping_add(left[3]).wrapping_add(right[4]),
            state[3].wrapping_add(left[4]).wrapping_add(right[0]),
            state[4].wrapping_add(left[0]).wrapping_add(right[1]),
            state[0].wrapping_add(left[1]).wrapping_add(right[2]),
        ];
    }
);

ripemd!(
    /// RIPEMD-256: RIPEMD-128 whose lines are kept apart and exchange word
    /// A, B, C and D after rounds 1 to 4.
    RIPEMD256,
    8,
    [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567],
    |state, x| {
        let mut left = [state[0], state[1], state[2], state[3]];
        let mut right = [state[4], state[5], state[6], state[7]];
        RIPEMDConstants::lines4(&mut left, &mut right, x, |round, left, right| {
            // After round 1 A, after round 2 B, after round 3 C, after round 4 D.
            core::mem::swap(&mut left[round], &mut right[round]);
        });
        for (index, value) in left.into_iter().chain(right).enumerate() {
            state[index] = state[index].wrapping_add(value);
        }
    }
);

ripemd!(
    /// RIPEMD-320: RIPEMD-160 whose lines are kept apart and exchange word
    /// B, D, A, C and E after rounds 1 to 5.
    RIPEMD320,
    10,
    [
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0, 0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567,
        0x3C2D1E0F,
    ],
    |state, x| {
        let mut left = [state[0], state[1], state[2], state[3], state[4]];
        let mut right = [state[5], state[6], state[7], state[8], state[9]];
        RIPEMDConstants::lines5(&mut left, &mut right, x, |round, left, right| {
            let word = [1, 3, 0, 2, 4][round];
            core::mem::swap(&mut left[word], &mut right[word]);
        });
        for (index, value) in left.into_iter().chain(right).enumerate() {
            state[index] = state[index].wrapping_add(value);
        }
    }
);
