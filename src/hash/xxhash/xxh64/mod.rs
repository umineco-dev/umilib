//! XXH64, with 64-bit arithmetic.

use core::fmt;
use core::hash::Hasher;

use crate::hash::Digest;
use crate::secret::Zeroize;

/// XXH64 with a 64-bit seed, which is hidden from `Debug` and zeroized
/// on drop because a seed that protects a hash table is a key. The output bytes are the canonical form, the
/// value in big-endian order; [`XXH64::value`] gives the value itself.
#[derive(Clone)]
pub struct XXH64 {
    seed: u64,
    accumulators: [u64; 4],
    stripe: [u8; XXH64::STRIPE_SIZE],
    buffered: usize,
    length: u64,
}

impl XXH64 {
    pub const STRIPE_SIZE: usize = 32;
    pub const PRIME_1: u64 = 0x9E3779B185EBCA87;
    pub const PRIME_2: u64 = 0xC2B2AE3D27D4EB4F;
    pub const PRIME_3: u64 = 0x165667B19E3779F9;
    pub const PRIME_4: u64 = 0x85EBCA77C2B2AE63;
    pub const PRIME_5: u64 = 0x27D4EB2F165667C5;

    /// The seed 0.
    pub const fn new() -> XXH64 {
        XXH64::with_seed(0)
    }

    pub const fn with_seed(seed: u64) -> XXH64 {
        XXH64 {
            seed,
            accumulators: XXH64::initial_accumulators(seed),
            stripe: [0; XXH64::STRIPE_SIZE],
            buffered: 0,
            length: 0,
        }
    }

    /// The accumulators before the first stripe (step 1).
    pub const fn initial_accumulators(seed: u64) -> [u64; 4] {
        [
            seed.wrapping_add(XXH64::PRIME_1).wrapping_add(XXH64::PRIME_2),
            seed.wrapping_add(XXH64::PRIME_2),
            seed,
            seed.wrapping_sub(XXH64::PRIME_1),
        ]
    }

    /// The hash of `data` with `seed`.
    pub fn hash(seed: u64, data: &[u8]) -> u64 {
        let mut state = XXH64::with_seed(seed);
        state.update(data);
        state.value()
    }

    /// A round on one lane (step 2).
    pub fn round(accumulator: u64, lane: u64) -> u64 {
        accumulator.wrapping_add(lane.wrapping_mul(XXH64::PRIME_2)).rotate_left(31).wrapping_mul(XXH64::PRIME_1)
    }

    /// Merges a lane accumulator into the converged one (step 3).
    pub fn merge_accumulator(accumulator: u64, lane: u64) -> u64 {
        (accumulator ^ XXH64::round(0, lane)).wrapping_mul(XXH64::PRIME_1).wrapping_add(XXH64::PRIME_4)
    }

    pub fn process_stripe(accumulators: &mut [u64; 4], stripe: &[u8; XXH64::STRIPE_SIZE]) {
        for (accumulator, lane) in accumulators.iter_mut().zip(stripe.as_chunks::<8>().0) {
            *accumulator = XXH64::round(*accumulator, u64::from_le_bytes(*lane));
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let take = (XXH64::STRIPE_SIZE - self.buffered).min(data.len());
            self.stripe[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < XXH64::STRIPE_SIZE {
                return;
            }
            XXH64::process_stripe(&mut self.accumulators, &self.stripe);
            self.buffered = 0;
        }
        let (stripes, rest) = data.as_chunks::<{ XXH64::STRIPE_SIZE }>();
        for stripe in stripes {
            XXH64::process_stripe(&mut self.accumulators, stripe);
        }
        self.stripe[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// The hash of the input so far (steps 3 to 6), without changing the state.
    pub fn value(&self) -> u64 {
        let [a, b, c, d] = self.accumulators;
        let mut accumulator = if self.length >= XXH64::STRIPE_SIZE as u64 {
            let mut converged = a
                .rotate_left(1)
                .wrapping_add(b.rotate_left(7))
                .wrapping_add(c.rotate_left(12))
                .wrapping_add(d.rotate_left(18));
            for lane in self.accumulators {
                converged = XXH64::merge_accumulator(converged, lane);
            }
            converged
        } else {
            self.seed.wrapping_add(XXH64::PRIME_5)
        };
        accumulator = accumulator.wrapping_add(self.length);
        let (words, rest) = self.stripe[..self.buffered].as_chunks::<8>();
        for word in words {
            accumulator ^= XXH64::round(0, u64::from_le_bytes(*word));
            accumulator = accumulator.rotate_left(27).wrapping_mul(XXH64::PRIME_1).wrapping_add(XXH64::PRIME_4);
        }
        let bytes = match rest.split_first_chunk::<4>() {
            Some((word, bytes)) => {
                accumulator ^= (u32::from_le_bytes(*word) as u64).wrapping_mul(XXH64::PRIME_1);
                accumulator = accumulator.rotate_left(23).wrapping_mul(XXH64::PRIME_2).wrapping_add(XXH64::PRIME_3);
                bytes
            }
            None => rest,
        };
        for &byte in bytes {
            accumulator ^= (byte as u64).wrapping_mul(XXH64::PRIME_5);
            accumulator = accumulator.rotate_left(11).wrapping_mul(XXH64::PRIME_1);
        }
        XXH64::avalanche(accumulator)
    }

    /// The final mix (step 6).
    pub fn avalanche(mut accumulator: u64) -> u64 {
        accumulator ^= accumulator >> 33;
        accumulator = accumulator.wrapping_mul(XXH64::PRIME_2);
        accumulator ^= accumulator >> 29;
        accumulator = accumulator.wrapping_mul(XXH64::PRIME_3);
        accumulator ^ (accumulator >> 32)
    }

    /// Returns to the empty input with the same seed.
    pub fn reset(&mut self) {
        *self = XXH64::with_seed(self.seed);
    }
}

impl Digest for XXH64 {
    const OUTPUT_SIZE: usize = 8;
    const BLOCK_SIZE: usize = XXH64::STRIPE_SIZE;
    type Output = [u8; 8];

    fn update(&mut self, data: &[u8]) {
        XXH64::update(self, data);
    }

    fn finalize(self) -> [u8; 8] {
        self.value().to_be_bytes()
    }

    fn finalize_reset(&mut self) -> [u8; 8] {
        let output = self.value().to_be_bytes();
        self.reset();
        output
    }

    fn reset(&mut self) {
        XXH64::reset(self);
    }
}

/// The integer methods of [`Hasher`] write the bytes in native order, so
/// their results differ between byte orders.
impl Hasher for XXH64 {
    fn write(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }

    fn finish(&self) -> u64 {
        self.value()
    }
}

impl Default for XXH64 {
    /// The seed 0.
    fn default() -> XXH64 {
        XXH64::new()
    }
}

impl Zeroize for XXH64 {
    fn zeroize(&mut self) {
        self.seed.zeroize();
        self.accumulators.zeroize();
        self.stripe.zeroize();
        self.buffered.zeroize();
        self.length.zeroize();
    }
}

impl Drop for XXH64 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for XXH64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XXH64(..)")
    }
}
