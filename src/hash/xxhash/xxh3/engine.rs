use core::fmt;

use super::XXH3Secret;
use crate::secret::Zeroize;

/// The state of XXH3 shared by [`XXH3_64`](super::XXH3_64) and
/// [`XXH3_128`](super::XXH3_128): the input of small and medium inputs, or
/// the accumulators of the large-input algorithm, fed one stripe at a time.
///
/// A stripe is consumed only once more input follows it, because the stripe
/// with the last byte is the final one (the last 64 bytes of the input,
/// processed with its own secret offset). The buffer keeps the last consumed
/// stripe at its end for the final stripe of inputs whose tail is shorter.
#[derive(Clone)]
pub struct XXH3 {
    secret: XXH3Secret,
    accumulators: [u64; 8],
    buffer: [u8; XXH3::BUFFER_SIZE],
    buffered: usize,
    /// The stripes consumed in the current block.
    stripes: usize,
    length: u64,
}

impl XXH3 {
    pub const STRIPE_SIZE: usize = 64;
    pub const BUFFER_SIZE: usize = 256;
    /// The largest input of the medium-input algorithm.
    pub const MEDIUM_SIZE: usize = 240;
    pub const DEFAULT_SECRET_SIZE: usize = 192;
    pub const MINIMUM_SECRET_SIZE: usize = 136;
    pub const PRIME32_1: u64 = 0x9E3779B1;
    pub const PRIME32_2: u64 = 0x85EBCA77;
    pub const PRIME32_3: u64 = 0xC2B2AE3D;
    pub const PRIME64_1: u64 = 0x9E3779B185EBCA87;
    pub const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4F;
    pub const PRIME64_3: u64 = 0x165667B19E3779F9;
    pub const PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
    pub const PRIME64_5: u64 = 0x27D4EB2F165667C5;
    pub const PRIME_MX1: u64 = 0x165667919E3779F9;
    pub const PRIME_MX2: u64 = 0x9FB21C651E98DF25;
    pub const INITIAL_ACCUMULATORS: [u64; 8] = [
        XXH3::PRIME32_3,
        XXH3::PRIME64_1,
        XXH3::PRIME64_2,
        XXH3::PRIME64_3,
        XXH3::PRIME64_4,
        XXH3::PRIME32_2,
        XXH3::PRIME64_5,
        XXH3::PRIME32_1,
    ];
    pub const DEFAULT_SECRET: [u8; XXH3::DEFAULT_SECRET_SIZE] = [
        0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c, 0xde, 0xd4,
        0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f, 0xcb, 0x79, 0xe6, 0x4e,
        0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21, 0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43,
        0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c, 0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb,
        0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3, 0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19,
        0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8, 0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7,
        0xc7, 0x0b, 0x4f, 0x1d, 0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78,
        0x73, 0x64, 0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
        0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e, 0x2b, 0x16,
        0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce, 0x45, 0xcb, 0x3a, 0x8f,
        0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
    ];

    pub fn new(secret: XXH3Secret) -> XXH3 {
        XXH3 {
            secret,
            accumulators: XXH3::INITIAL_ACCUMULATORS,
            buffer: [0; XXH3::BUFFER_SIZE],
            buffered: 0,
            stripes: 0,
            length: 0,
        }
    }

    pub fn secret(&self) -> &XXH3Secret {
        &self.secret
    }

    /// The total input length so far.
    pub fn len(&self) -> u64 {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// The whole input, while it is at most [`XXH3::MEDIUM_SIZE`] bytes.
    pub fn short_input(&self) -> Option<&[u8]> {
        (self.length <= XXH3::MEDIUM_SIZE as u64).then(|| &self.buffer[..self.buffered])
    }

    /// The little-endian word at `offset` of `bytes`.
    pub fn read64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("eight bytes"))
    }

    pub fn read32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"))
    }

    /// The product of `a` and `b` as (low, high) halves.
    pub fn multiply(a: u64, b: u64) -> (u64, u64) {
        let product = a as u128 * b as u128;
        (product as u64, (product >> 64) as u64)
    }

    /// The xor of the two halves of the product of `a` and `b`.
    pub fn fold(a: u64, b: u64) -> u64 {
        let (low, high) = XXH3::multiply(a, b);
        low ^ high
    }

    pub fn avalanche(mut x: u64) -> u64 {
        x ^= x >> 37;
        x = x.wrapping_mul(XXH3::PRIME_MX1);
        x ^ (x >> 32)
    }

    /// The final mix of XXH64.
    pub fn avalanche_xxh64(mut x: u64) -> u64 {
        x ^= x >> 33;
        x = x.wrapping_mul(XXH3::PRIME64_2);
        x ^= x >> 29;
        x = x.wrapping_mul(XXH3::PRIME64_3);
        x ^ (x >> 32)
    }

    /// The mixing step of medium inputs: 16 bytes of `data` at `offset`
    /// with 16 bytes of `secret` at `secret_offset`.
    pub fn mix_step(data: &[u8], offset: usize, secret: &[u8], secret_offset: usize, seed: u64) -> u64 {
        XXH3::fold(
            XXH3::read64(data, offset) ^ XXH3::read64(secret, secret_offset).wrapping_add(seed),
            XXH3::read64(data, offset + 8) ^ XXH3::read64(secret, secret_offset + 8).wrapping_sub(seed),
        )
    }

    /// The accumulation step of large inputs: one stripe with 64 bytes of the secret.
    pub fn accumulate(accumulators: &mut [u64; 8], stripe: &[u8], secret: &[u8], secret_offset: usize) {
        for index in 0..8 {
            let lane = XXH3::read64(stripe, 8 * index);
            let value = lane ^ XXH3::read64(secret, secret_offset + 8 * index);
            accumulators[index ^ 1] = accumulators[index ^ 1].wrapping_add(lane);
            accumulators[index] = accumulators[index].wrapping_add((value & 0xFFFFFFFF).wrapping_mul(value >> 32));
        }
    }

    /// The scramble at the end of a block, with the last 64 bytes of the secret.
    pub fn scramble(accumulators: &mut [u64; 8], secret: &[u8]) {
        let offset = secret.len() - 64;
        for (index, accumulator) in accumulators.iter_mut().enumerate() {
            *accumulator ^= *accumulator >> 47;
            *accumulator ^= XXH3::read64(secret, offset + 8 * index);
            *accumulator = accumulator.wrapping_mul(XXH3::PRIME32_1);
        }
    }

    /// The final merge of the accumulators with 64 bytes of the secret at `secret_offset`.
    pub fn merge(accumulators: &[u64; 8], secret: &[u8], secret_offset: usize, initial: u64) -> u64 {
        let mut result = initial;
        for index in 0..4 {
            result = result.wrapping_add(XXH3::fold(
                accumulators[2 * index] ^ XXH3::read64(secret, secret_offset + 16 * index),
                accumulators[2 * index + 1] ^ XXH3::read64(secret, secret_offset + 16 * index + 8),
            ));
        }
        XXH3::avalanche(result)
    }

    /// The number of stripes per block for `secret`.
    pub fn stripes_per_block(secret: &[u8]) -> usize {
        (secret.len() - 64) / 8
    }

    /// Consumes whole stripes of `stripes`, scrambling at the end of each block.
    pub fn consume(accumulators: &mut [u64; 8], count: &mut usize, stripes: &[u8], secret: &[u8]) {
        let per_block = XXH3::stripes_per_block(secret);
        for stripe in stripes.as_chunks::<{ XXH3::STRIPE_SIZE }>().0 {
            XXH3::accumulate(accumulators, stripe, secret, 8 * *count);
            *count += 1;
            if *count == per_block {
                XXH3::scramble(accumulators, secret);
                *count = 0;
            }
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered + data.len() <= XXH3::BUFFER_SIZE {
            self.buffer[self.buffered..self.buffered + data.len()].copy_from_slice(data);
            self.buffered += data.len();
            return;
        }
        // More input follows the full buffer, so all of its stripes are consumed.
        let fill = XXH3::BUFFER_SIZE - self.buffered;
        self.buffer[self.buffered..].copy_from_slice(&data[..fill]);
        data = &data[fill..];
        let secret = self.secret.secret();
        XXH3::consume(&mut self.accumulators, &mut self.stripes, &self.buffer, secret);
        self.buffered = 0;
        if data.len() > XXH3::BUFFER_SIZE {
            // Every stripe but the one with the last byte.
            let whole = (data.len() - 1) / XXH3::STRIPE_SIZE * XXH3::STRIPE_SIZE;
            XXH3::consume(&mut self.accumulators, &mut self.stripes, &data[..whole], secret);
            self.buffer[XXH3::BUFFER_SIZE - XXH3::STRIPE_SIZE..]
                .copy_from_slice(&data[whole - XXH3::STRIPE_SIZE..whole]);
            data = &data[whole..];
        }
        self.buffer[..data.len()].copy_from_slice(data);
        self.buffered = data.len();
    }

    /// The accumulators of a large input after its final stripe.
    pub fn long_accumulators(&self) -> [u64; 8] {
        let secret = self.secret.secret();
        let mut accumulators = self.accumulators;
        let mut stripes = self.stripes;
        let mut last = [0u8; XXH3::STRIPE_SIZE];
        if self.buffered >= XXH3::STRIPE_SIZE {
            let whole = (self.buffered - 1) / XXH3::STRIPE_SIZE * XXH3::STRIPE_SIZE;
            XXH3::consume(&mut accumulators, &mut stripes, &self.buffer[..whole], secret);
            last.copy_from_slice(&self.buffer[self.buffered - XXH3::STRIPE_SIZE..self.buffered]);
        } else {
            let previous = XXH3::STRIPE_SIZE - self.buffered;
            last[..previous].copy_from_slice(&self.buffer[XXH3::BUFFER_SIZE - previous..]);
            last[previous..].copy_from_slice(&self.buffer[..self.buffered]);
        }
        XXH3::accumulate(&mut accumulators, &last, secret, secret.len() - XXH3::STRIPE_SIZE - 7);
        accumulators
    }

    /// Returns to the empty input with the same key.
    pub fn reset(&mut self) {
        self.buffer.zeroize();
        self.accumulators = XXH3::INITIAL_ACCUMULATORS;
        self.buffered = 0;
        self.stripes = 0;
        self.length = 0;
    }
}

impl Zeroize for XXH3 {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        self.accumulators.zeroize();
        self.buffer.zeroize();
        self.buffered.zeroize();
        self.stripes.zeroize();
        self.length.zeroize();
    }
}

impl Drop for XXH3 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for XXH3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "XXH3({:?})", self.secret)
    }
}
