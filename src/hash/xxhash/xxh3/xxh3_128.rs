use core::fmt;

use super::{XXH3, XXH3Secret};
use crate::hash::{Digest, HashError};

/// XXH3 with 128 bits of output (XXH128). The output bytes are the canonical
/// form, the value in big-endian order; [`XXH3_128::value`] gives the value
/// itself, whose low half is in general not the output of
/// [`XXH3_64`](super::XXH3_64) (it is for inputs of 1 to 3 bytes).
#[derive(Clone)]
pub struct XXH3_128 {
    state: XXH3,
}

impl XXH3_128 {
    /// The seed 0 and the default secret.
    pub fn new() -> XXH3_128 {
        XXH3_128 { state: XXH3::new(XXH3Secret::default()) }
    }

    pub fn with_seed(seed: u64) -> XXH3_128 {
        XXH3_128 { state: XXH3::new(XXH3Secret::with_seed(seed)) }
    }

    /// A secret of at least [`XXH3::MINIMUM_SECRET_SIZE`] bytes.
    pub fn with_secret(secret: &[u8]) -> Result<XXH3_128, HashError> {
        Ok(XXH3_128 { state: XXH3::new(XXH3Secret::with_secret(secret)?) })
    }

    /// The hash of `data` with `seed`.
    pub fn hash(seed: u64, data: &[u8]) -> u128 {
        let mut state = XXH3_128::with_seed(seed);
        state.update(data);
        state.value()
    }

    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// The hash of the input so far, without changing the state.
    pub fn value(&self) -> u128 {
        let secret = self.state.secret();
        let (low, high) = match self.state.short_input() {
            Some(input) => XXH3_128::hash_short(input, secret.short_secret(), secret.seed()),
            None => {
                let accumulators = self.state.long_accumulators();
                let secret = secret.secret();
                let length = self.state.len();
                (
                    XXH3::merge(&accumulators, secret, 11, length.wrapping_mul(XXH3::PRIME64_1)),
                    XXH3::merge(&accumulators, secret, secret.len() - 64 - 11, !length.wrapping_mul(XXH3::PRIME64_2)),
                )
            }
        };
        ((high as u128) << 64) | low as u128
    }

    /// Two chunks of 16 bytes of the medium-input algorithm, mixed into both accumulators.
    pub fn mix_two_chunks(
        accumulators: &mut [u64; 2],
        input: &[u8],
        first: usize,
        second: usize,
        secret: &[u8],
        secret_offset: usize,
        seed: u64,
    ) {
        accumulators[0] = accumulators[0].wrapping_add(XXH3::mix_step(input, first, secret, secret_offset, seed));
        accumulators[1] = accumulators[1].wrapping_add(XXH3::mix_step(input, second, secret, secret_offset + 16, seed));
        accumulators[0] ^= XXH3::read64(input, second).wrapping_add(XXH3::read64(input, second + 8));
        accumulators[1] ^= XXH3::read64(input, first).wrapping_add(XXH3::read64(input, first + 8));
    }

    /// The algorithms of inputs of at most [`XXH3::MEDIUM_SIZE`] bytes, as
    /// (low, high) halves.
    ///
    /// # Panics
    ///
    /// If `input` is longer than [`XXH3::MEDIUM_SIZE`] or `secret` shorter
    /// than [`XXH3::MINIMUM_SECRET_SIZE`].
    pub fn hash_short(input: &[u8], secret: &[u8], seed: u64) -> (u64, u64) {
        assert!(input.len() <= XXH3::MEDIUM_SIZE, "hash_short takes at most 240 bytes");
        assert!(secret.len() >= XXH3::MINIMUM_SECRET_SIZE, "the secret has at least 136 bytes");
        let length = input.len();
        match length {
            0 => (
                XXH3::avalanche_xxh64(seed ^ XXH3::read64(secret, 64) ^ XXH3::read64(secret, 72)),
                XXH3::avalanche_xxh64(seed ^ XXH3::read64(secret, 80) ^ XXH3::read64(secret, 88)),
            ),
            1..=3 => {
                let combined = (input[length - 1] as u32)
                    | ((length as u32) << 8)
                    | ((input[0] as u32) << 16)
                    | ((input[length >> 1] as u32) << 24);
                let low =
                    ((XXH3::read32(secret, 0) ^ XXH3::read32(secret, 4)) as u64).wrapping_add(seed) ^ combined as u64;
                let high = ((XXH3::read32(secret, 8) ^ XXH3::read32(secret, 12)) as u64).wrapping_sub(seed)
                    ^ combined.swap_bytes().rotate_left(13) as u64;
                (XXH3::avalanche_xxh64(low), XXH3::avalanche_xxh64(high))
            }
            4..=8 => {
                let first = XXH3::read32(input, 0) as u64;
                let last = XXH3::read32(input, length - 4) as u64;
                let seed = seed ^ (((seed as u32).swap_bytes() as u64) << 32);
                let combined = first | (last << 32);
                let value = ((XXH3::read64(secret, 16) ^ XXH3::read64(secret, 24)).wrapping_add(seed)) ^ combined;
                let (mut low, mut high) = XXH3::multiply(value, XXH3::PRIME64_1.wrapping_add((length as u64) << 2));
                high = high.wrapping_add(low << 1);
                low ^= high >> 3;
                low ^= low >> 35;
                low = low.wrapping_mul(XXH3::PRIME_MX2);
                low ^= low >> 28;
                (low, XXH3::avalanche(high))
            }
            9..=16 => {
                let first = XXH3::read64(input, 0);
                let last = XXH3::read64(input, length - 8);
                let value1 = (XXH3::read64(secret, 32) ^ XXH3::read64(secret, 40)).wrapping_sub(seed) ^ first ^ last;
                let value2 = (XXH3::read64(secret, 48) ^ XXH3::read64(secret, 56)).wrapping_add(seed) ^ last;
                let (low, high) = XXH3::multiply(value1, XXH3::PRIME64_1);
                let low = low.wrapping_add(((length - 1) as u64) << 54);
                let high = high
                    .wrapping_add((value2 >> 32) << 32)
                    .wrapping_add((value2 & 0xFFFFFFFF).wrapping_mul(XXH3::PRIME32_2));
                let low = low ^ high.swap_bytes();
                let (product_low, product_high) = XXH3::multiply(low, XXH3::PRIME64_2);
                let high = product_high.wrapping_add(high.wrapping_mul(XXH3::PRIME64_2));
                (XXH3::avalanche(product_low), XXH3::avalanche(high))
            }
            _ => {
                let mut accumulators = [(length as u64).wrapping_mul(XXH3::PRIME64_1), 0];
                if length <= 128 {
                    for round in (0..(length - 1) / 32 + 1).rev() {
                        XXH3_128::mix_two_chunks(
                            &mut accumulators,
                            input,
                            16 * round,
                            length - 16 * round - 16,
                            secret,
                            32 * round,
                            seed,
                        );
                    }
                } else {
                    for chunk in 0..4 {
                        XXH3_128::mix_two_chunks(
                            &mut accumulators,
                            input,
                            32 * chunk,
                            32 * chunk + 16,
                            secret,
                            32 * chunk,
                            seed,
                        );
                    }
                    accumulators = accumulators.map(XXH3::avalanche);
                    for chunk in 4..length / 32 {
                        let offset = 32 * (chunk - 4) + 3;
                        XXH3_128::mix_two_chunks(
                            &mut accumulators,
                            input,
                            32 * chunk,
                            32 * chunk + 16,
                            secret,
                            offset,
                            seed,
                        );
                    }
                    // The halves in reverse order and the negated seed.
                    XXH3_128::mix_two_chunks(
                        &mut accumulators,
                        input,
                        length - 16,
                        length - 32,
                        secret,
                        103,
                        seed.wrapping_neg(),
                    );
                }
                let low = accumulators[0].wrapping_add(accumulators[1]);
                let high = accumulators[0]
                    .wrapping_mul(XXH3::PRIME64_1)
                    .wrapping_add(accumulators[1].wrapping_mul(XXH3::PRIME64_4))
                    .wrapping_add((length as u64).wrapping_sub(seed).wrapping_mul(XXH3::PRIME64_2));
                (XXH3::avalanche(low), XXH3::avalanche(high).wrapping_neg())
            }
        }
    }

    /// Returns to the empty input with the same key.
    pub fn reset(&mut self) {
        self.state.reset();
    }
}

impl Digest for XXH3_128 {
    const OUTPUT_SIZE: usize = 16;
    const BLOCK_SIZE: usize = XXH3::STRIPE_SIZE;
    type Output = [u8; 16];

    fn update(&mut self, data: &[u8]) {
        XXH3_128::update(self, data);
    }

    fn finalize(self) -> [u8; 16] {
        self.value().to_be_bytes()
    }

    fn finalize_reset(&mut self) -> [u8; 16] {
        let output = self.value().to_be_bytes();
        self.reset();
        output
    }

    fn reset(&mut self) {
        XXH3_128::reset(self);
    }
}

impl Default for XXH3_128 {
    fn default() -> XXH3_128 {
        XXH3_128::new()
    }
}

impl fmt::Debug for XXH3_128 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "XXH3_128({:?})", self.state.secret())
    }
}
