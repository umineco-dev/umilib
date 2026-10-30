//! XXH32, with 32-bit arithmetic for 32-bit processors.

use core::fmt;

use crate::hash::Digest;
use crate::secret::Zeroize;

/// XXH32 with a 32-bit seed, which is hidden from `Debug` and zeroized
/// on drop because a seed that protects a hash table is a key. The output bytes are the canonical form, the
/// value in big-endian order; [`XXH32::value`] gives the value itself.
#[derive(Clone)]
pub struct XXH32 {
    seed: u32,
    accumulators: [u32; 4],
    stripe: [u8; XXH32::STRIPE_SIZE],
    buffered: usize,
    length: u64,
}

impl XXH32 {
    pub const STRIPE_SIZE: usize = 16;
    pub const PRIME_1: u32 = 0x9E3779B1;
    pub const PRIME_2: u32 = 0x85EBCA77;
    pub const PRIME_3: u32 = 0xC2B2AE3D;
    pub const PRIME_4: u32 = 0x27D4EB2F;
    pub const PRIME_5: u32 = 0x165667B1;

    /// The seed 0.
    pub const fn new() -> XXH32 {
        XXH32::with_seed(0)
    }

    pub const fn with_seed(seed: u32) -> XXH32 {
        XXH32 {
            seed,
            accumulators: XXH32::initial_accumulators(seed),
            stripe: [0; XXH32::STRIPE_SIZE],
            buffered: 0,
            length: 0,
        }
    }

    /// The accumulators before the first stripe (step 1).
    pub const fn initial_accumulators(seed: u32) -> [u32; 4] {
        [
            seed.wrapping_add(XXH32::PRIME_1).wrapping_add(XXH32::PRIME_2),
            seed.wrapping_add(XXH32::PRIME_2),
            seed,
            seed.wrapping_sub(XXH32::PRIME_1),
        ]
    }

    /// The hash of `data` with `seed`.
    pub fn hash(seed: u32, data: &[u8]) -> u32 {
        let mut state = XXH32::with_seed(seed);
        state.update(data);
        state.value()
    }

    /// A round on one lane (step 2).
    pub fn round(accumulator: u32, lane: u32) -> u32 {
        accumulator.wrapping_add(lane.wrapping_mul(XXH32::PRIME_2)).rotate_left(13).wrapping_mul(XXH32::PRIME_1)
    }

    pub fn process_stripe(accumulators: &mut [u32; 4], stripe: &[u8; XXH32::STRIPE_SIZE]) {
        for (accumulator, lane) in accumulators.iter_mut().zip(stripe.as_chunks::<4>().0) {
            *accumulator = XXH32::round(*accumulator, u32::from_le_bytes(*lane));
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let take = (XXH32::STRIPE_SIZE - self.buffered).min(data.len());
            self.stripe[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < XXH32::STRIPE_SIZE {
                return;
            }
            XXH32::process_stripe(&mut self.accumulators, &self.stripe);
            self.buffered = 0;
        }
        let (stripes, rest) = data.as_chunks::<{ XXH32::STRIPE_SIZE }>();
        for stripe in stripes {
            XXH32::process_stripe(&mut self.accumulators, stripe);
        }
        self.stripe[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// The hash of the input so far (steps 3 to 6), without changing the state.
    pub fn value(&self) -> u32 {
        let [a, b, c, d] = self.accumulators;
        let mut accumulator = if self.length >= XXH32::STRIPE_SIZE as u64 {
            a.rotate_left(1)
                .wrapping_add(b.rotate_left(7))
                .wrapping_add(c.rotate_left(12))
                .wrapping_add(d.rotate_left(18))
        } else {
            self.seed.wrapping_add(XXH32::PRIME_5)
        };
        accumulator = accumulator.wrapping_add(self.length as u32);
        let (words, bytes) = self.stripe[..self.buffered].as_chunks::<4>();
        for word in words {
            accumulator = accumulator.wrapping_add(u32::from_le_bytes(*word).wrapping_mul(XXH32::PRIME_3));
            accumulator = accumulator.rotate_left(17).wrapping_mul(XXH32::PRIME_4);
        }
        for &byte in bytes {
            accumulator = accumulator.wrapping_add((byte as u32).wrapping_mul(XXH32::PRIME_5));
            accumulator = accumulator.rotate_left(11).wrapping_mul(XXH32::PRIME_1);
        }
        XXH32::avalanche(accumulator)
    }

    /// The final mix (step 6).
    pub fn avalanche(mut accumulator: u32) -> u32 {
        accumulator ^= accumulator >> 15;
        accumulator = accumulator.wrapping_mul(XXH32::PRIME_2);
        accumulator ^= accumulator >> 13;
        accumulator = accumulator.wrapping_mul(XXH32::PRIME_3);
        accumulator ^ (accumulator >> 16)
    }

    /// Returns to the empty input with the same seed.
    pub fn reset(&mut self) {
        *self = XXH32::with_seed(self.seed);
    }
}

impl Digest for XXH32 {
    const OUTPUT_SIZE: usize = 4;
    const BLOCK_SIZE: usize = XXH32::STRIPE_SIZE;
    type Output = [u8; 4];

    fn update(&mut self, data: &[u8]) {
        XXH32::update(self, data);
    }

    fn finalize(self) -> [u8; 4] {
        self.value().to_be_bytes()
    }

    fn finalize_reset(&mut self) -> [u8; 4] {
        let output = self.value().to_be_bytes();
        self.reset();
        output
    }

    fn reset(&mut self) {
        XXH32::reset(self);
    }
}

impl Default for XXH32 {
    /// The seed 0.
    fn default() -> XXH32 {
        XXH32::new()
    }
}

impl Zeroize for XXH32 {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.accumulators.zeroize();
        self.stripe.zeroize();
        self.buffered.zeroize();
        self.length.zeroize();
    }
}

impl Drop for XXH32 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for XXH32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XXH32(..)")
    }
}
