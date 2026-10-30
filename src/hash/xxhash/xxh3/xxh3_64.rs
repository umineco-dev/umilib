use core::fmt;
use core::hash::Hasher;

use super::{XXH3, XXH3Secret};
use crate::hash::{Digest, HashError};

/// XXH3 with 64 bits of output. The output bytes are the canonical form,
/// the value in big-endian order; [`XXH3_64::value`] gives the value itself.
#[derive(Clone)]
pub struct XXH3_64 {
    state: XXH3,
}

impl XXH3_64 {
    /// The seed 0 and the default secret.
    pub fn new() -> XXH3_64 {
        XXH3_64 { state: XXH3::new(XXH3Secret::default()) }
    }

    pub fn with_seed(seed: u64) -> XXH3_64 {
        XXH3_64 { state: XXH3::new(XXH3Secret::with_seed(seed)) }
    }

    /// A secret of at least [`XXH3::MINIMUM_SECRET_SIZE`] bytes.
    pub fn with_secret(secret: &[u8]) -> Result<XXH3_64, HashError> {
        Ok(XXH3_64 { state: XXH3::new(XXH3Secret::with_secret(secret)?) })
    }

    /// The hash of `data` with `seed`.
    pub fn hash(seed: u64, data: &[u8]) -> u64 {
        let mut state = XXH3_64::with_seed(seed);
        state.update(data);
        state.value()
    }

    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// The hash of the input so far, without changing the state.
    pub fn value(&self) -> u64 {
        let secret = self.state.secret();
        match self.state.short_input() {
            Some(input) => XXH3_64::hash_short(input, secret.short_secret(), secret.seed()),
            None => {
                let accumulators = self.state.long_accumulators();
                XXH3::merge(&accumulators, secret.secret(), 11, self.state.len().wrapping_mul(XXH3::PRIME64_1))
            }
        }
    }

    /// The algorithms of inputs of at most [`XXH3::MEDIUM_SIZE`] bytes.
    ///
    /// # Panics
    ///
    /// If `input` is longer than [`XXH3::MEDIUM_SIZE`] or `secret` shorter
    /// than [`XXH3::MINIMUM_SECRET_SIZE`].
    pub fn hash_short(input: &[u8], secret: &[u8], seed: u64) -> u64 {
        assert!(input.len() <= XXH3::MEDIUM_SIZE, "hash_short takes at most 240 bytes");
        assert!(secret.len() >= XXH3::MINIMUM_SECRET_SIZE, "the secret has at least 136 bytes");
        let length = input.len();
        match length {
            0 => XXH3::avalanche_xxh64(seed ^ XXH3::read64(secret, 56) ^ XXH3::read64(secret, 64)),
            1..=3 => {
                let combined = (input[length - 1] as u32)
                    | ((length as u32) << 8)
                    | ((input[0] as u32) << 16)
                    | ((input[length >> 1] as u32) << 24);
                let value =
                    ((XXH3::read32(secret, 0) ^ XXH3::read32(secret, 4)) as u64).wrapping_add(seed) ^ combined as u64;
                XXH3::avalanche_xxh64(value)
            }
            4..=8 => {
                let first = XXH3::read32(input, 0) as u64;
                let last = XXH3::read32(input, length - 4) as u64;
                let seed = seed ^ (((seed as u32).swap_bytes() as u64) << 32);
                let combined = last | (first << 32);
                let mut value = ((XXH3::read64(secret, 8) ^ XXH3::read64(secret, 16)).wrapping_sub(seed)) ^ combined;
                value ^= value.rotate_left(49) ^ value.rotate_left(24);
                value = value.wrapping_mul(XXH3::PRIME_MX2);
                value ^= (value >> 35).wrapping_add(length as u64);
                value = value.wrapping_mul(XXH3::PRIME_MX2);
                value ^ (value >> 28)
            }
            9..=16 => {
                let low =
                    (XXH3::read64(secret, 24) ^ XXH3::read64(secret, 32)).wrapping_add(seed) ^ XXH3::read64(input, 0);
                let high = (XXH3::read64(secret, 40) ^ XXH3::read64(secret, 48)).wrapping_sub(seed)
                    ^ XXH3::read64(input, length - 8);
                let value = (length as u64)
                    .wrapping_add(low.swap_bytes())
                    .wrapping_add(high)
                    .wrapping_add(XXH3::fold(low, high));
                XXH3::avalanche(value)
            }
            17..=128 => {
                let mut accumulator = (length as u64).wrapping_mul(XXH3::PRIME64_1);
                for round in (0..(length - 1) / 32 + 1).rev() {
                    accumulator = accumulator.wrapping_add(XXH3::mix_step(input, 16 * round, secret, 32 * round, seed));
                    accumulator = accumulator.wrapping_add(XXH3::mix_step(
                        input,
                        length - 16 * round - 16,
                        secret,
                        32 * round + 16,
                        seed,
                    ));
                }
                XXH3::avalanche(accumulator)
            }
            _ => {
                let mut accumulator = (length as u64).wrapping_mul(XXH3::PRIME64_1);
                for chunk in 0..8 {
                    accumulator = accumulator.wrapping_add(XXH3::mix_step(input, 16 * chunk, secret, 16 * chunk, seed));
                }
                accumulator = XXH3::avalanche(accumulator);
                for chunk in 8..length / 16 {
                    accumulator =
                        accumulator.wrapping_add(XXH3::mix_step(input, 16 * chunk, secret, 16 * (chunk - 8) + 3, seed));
                }
                accumulator = accumulator.wrapping_add(XXH3::mix_step(input, length - 16, secret, 119, seed));
                XXH3::avalanche(accumulator)
            }
        }
    }

    /// Returns to the empty input with the same key.
    pub fn reset(&mut self) {
        self.state.reset();
    }
}

impl Digest for XXH3_64 {
    const OUTPUT_SIZE: usize = 8;
    const BLOCK_SIZE: usize = XXH3::STRIPE_SIZE;
    type Output = [u8; 8];

    fn update(&mut self, data: &[u8]) {
        XXH3_64::update(self, data);
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
        XXH3_64::reset(self);
    }
}

/// The integer methods of [`Hasher`] write the bytes in native order, so
/// their results differ between byte orders.
impl Hasher for XXH3_64 {
    fn write(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }

    fn finish(&self) -> u64 {
        self.value()
    }
}

impl Default for XXH3_64 {
    fn default() -> XXH3_64 {
        XXH3_64::new()
    }
}

impl fmt::Debug for XXH3_64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "XXH3_64({:?})", self.state.secret())
    }
}
