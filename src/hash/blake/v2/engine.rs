use core::fmt;

use super::{BLAKE2bParameters, BLAKE2sParameters};
use crate::hash::HashError;
use crate::secret::Zeroize;

/// Defines a BLAKE2 function on words of type `$word`.
macro_rules! blake2 {
    (
        $(#[$documentation:meta])*
        $name:ident, $parameters:ident, $word:ty, $block:literal, $output:literal, $rounds:literal,
        [$r1:literal, $r2:literal, $r3:literal, $r4:literal], $iv:expr
    ) => {
        $(#[$documentation])*
        #[derive(Clone)]
        pub struct $name {
            h: [$word; 8],
            /// The number of bytes compressed, as a double word.
            t: [$word; 2],
            buffer: [u8; $block],
            buffered: usize,
            output_length: usize,
            last_node: bool,
            /// The chaining value after the parameter block, to which `reset` returns.
            initial: [$word; 8],
            /// The key block, processed first and again after `reset`.
            key: [u8; $block],
            keyed: bool,
        }

        impl $name {
            /// The number of bytes per block.
            pub const BLOCK_SIZE: usize = $block;
            /// The longest output and key, in bytes.
            pub const MAXIMUM_OUTPUT: usize = $output;
            pub const MAXIMUM_KEY: usize = $output;
            pub const ROUNDS: usize = $rounds;
            /// The initialization vector (RFC 7693 section 2.6).
            pub const IV: [$word; 8] = $iv;
            /// The message schedule permutations σ (RFC 7693 section 2.7).
            pub const SIGMA: [[usize; 16]; 10] = [
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
                [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
                [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
                [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
                [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
                [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
                [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
                [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
                [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
            ];

            /// Unkeyed BLAKE2 with `output_length` bytes of output (1 to the maximum).
            pub fn new(output_length: usize) -> Result<$name, HashError> {
                $name::with_key(&[], output_length)
            }

            /// Keyed BLAKE2 (a MAC) with `key` (at most the maximum) and `output_length` bytes.
            pub fn with_key(key: &[u8], output_length: usize) -> Result<$name, HashError> {
                if output_length == 0 || output_length > $output {
                    return Err(HashError::OutputLength { length: output_length, minimum: 1, maximum: $output });
                }
                let mut parameters = $parameters::new(output_length as u8);
                parameters.key_length = key.len().min(u8::MAX as usize) as u8;
                $name::with_parameters(&parameters, key)
            }

            /// BLAKE2 with every parameter given; `parameters.key_length` must be `key.len()`.
            pub fn with_parameters(parameters: &$parameters, key: &[u8]) -> Result<$name, HashError> {
                if key.len() > $output {
                    return Err(HashError::KeyLength { length: key.len(), minimum: 0, maximum: $output });
                }
                if parameters.key_length as usize != key.len() {
                    return Err(HashError::InvalidParameter);
                }
                let mut state = $name::without_key_block(parameters)?;
                state.key[..key.len()].copy_from_slice(key);
                state.keyed = !key.is_empty();
                if state.keyed {
                    let mut key = state.key;
                    state.update(&key);
                    key.zeroize();
                }
                Ok(state)
            }

            /// BLAKE2 with the parameter block `parameters` and no key block,
            /// whatever `key_length` says, as the root node of the parallel
            /// modes uses.
            pub fn without_key_block(parameters: &$parameters) -> Result<$name, HashError> {
                let output_length = parameters.digest_length as usize;
                if output_length == 0 || output_length > $output {
                    return Err(HashError::OutputLength { length: output_length, minimum: 1, maximum: $output });
                }
                // Depth 0 is allowed: the output nodes of BLAKE2X use it.
                if parameters.inner_length as usize > $output {
                    return Err(HashError::InvalidParameter);
                }
                if parameters.key_length as usize > $output {
                    return Err(HashError::KeyLength { length: parameters.key_length as usize, minimum: 0, maximum: $output });
                }
                let block = parameters.to_bytes();
                let mut initial = $name::IV;
                for (word, bytes) in initial.iter_mut().zip(block.as_chunks::<{ core::mem::size_of::<$word>() }>().0) {
                    *word ^= <$word>::from_le_bytes(*bytes);
                }
                Ok($name {
                    h: initial,
                    t: [0; 2],
                    buffer: [0; $block],
                    buffered: 0,
                    output_length,
                    last_node: false,
                    initial,
                    key: [0; $block],
                    keyed: false,
                })
            }

            /// Marks the state as the last node of its tree level (the flag f1).
            pub fn set_last_node(&mut self, last_node: bool) {
                self.last_node = last_node;
            }

            pub fn output_length(&self) -> usize {
                self.output_length
            }

            /// The compression function F (RFC 7693 section 3.2).
            pub fn compress(h: &mut [$word; 8], block: &[u8; $block], t: [$word; 2], last: bool, last_node: bool) {
                let mut m = [0 as $word; 16];
                for (word, bytes) in m.iter_mut().zip(block.as_chunks::<{ core::mem::size_of::<$word>() }>().0) {
                    *word = <$word>::from_le_bytes(*bytes);
                }
                let mut v = [0 as $word; 16];
                v[..8].copy_from_slice(h);
                v[8..].copy_from_slice(&$name::IV);
                v[12] ^= t[0];
                v[13] ^= t[1];
                if last {
                    v[14] = !v[14];
                }
                if last_node {
                    v[15] = !v[15];
                }
                let mix = |v: &mut [$word; 16], a: usize, b: usize, c: usize, d: usize, x: $word, y: $word| {
                    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
                    v[d] = (v[d] ^ v[a]).rotate_right($r1);
                    v[c] = v[c].wrapping_add(v[d]);
                    v[b] = (v[b] ^ v[c]).rotate_right($r2);
                    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
                    v[d] = (v[d] ^ v[a]).rotate_right($r3);
                    v[c] = v[c].wrapping_add(v[d]);
                    v[b] = (v[b] ^ v[c]).rotate_right($r4);
                };
                for round in 0..$rounds {
                    let s = &$name::SIGMA[round % 10];
                    mix(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
                    mix(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
                    mix(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
                    mix(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
                    mix(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
                    mix(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
                    mix(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
                    mix(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
                }
                for (index, word) in h.iter_mut().enumerate() {
                    *word ^= v[index] ^ v[index + 8];
                }
                m.zeroize();
                v.zeroize();
            }

            /// Adds `bytes` to the counter of compressed bytes.
            pub fn increment_counter(&mut self, bytes: usize) {
                let (low, overflow) = self.t[0].overflowing_add(bytes as $word);
                self.t[0] = low;
                self.t[1] = self.t[1].wrapping_add(overflow as $word);
            }

            /// Adds `data` to the input. A full block is compressed only once
            /// more input follows, because the last block is compressed with the
            /// finalization flag.
            pub fn update(&mut self, mut data: &[u8]) {
                if data.is_empty() {
                    return;
                }
                let fill = $block - self.buffered;
                if data.len() > fill {
                    self.buffer[self.buffered..].copy_from_slice(&data[..fill]);
                    self.increment_counter($block);
                    $name::compress(&mut self.h, &self.buffer, self.t, false, false);
                    self.buffered = 0;
                    data = &data[fill..];
                    while data.len() > $block
                        && let Some((block, rest)) = data.split_first_chunk::<$block>()
                    {
                        self.increment_counter($block);
                        $name::compress(&mut self.h, block, self.t, false, false);
                        data = rest;
                    }
                }
                self.buffer[self.buffered..self.buffered + data.len()].copy_from_slice(data);
                self.buffered += data.len();
            }

            /// Writes the output into `out`, which must hold exactly the output
            /// length, and resets the state.
            pub fn finalize_into(&mut self, out: &mut [u8]) -> Result<(), HashError> {
                if out.len() != self.output_length {
                    return Err(HashError::OutputLength { length: out.len(), minimum: self.output_length, maximum: self.output_length });
                }
                self.increment_counter(self.buffered);
                self.buffer[self.buffered..].fill(0);
                $name::compress(&mut self.h, &self.buffer, self.t, true, self.last_node);
                let size = core::mem::size_of::<$word>();
                for (index, byte) in out.iter_mut().enumerate() {
                    *byte = self.h[index / size].to_le_bytes()[index % size];
                }
                self.reset();
                Ok(())
            }

            /// Returns to the state after the parameters and the key.
            pub fn reset(&mut self) {
                self.h = self.initial;
                self.t = [0; 2];
                self.buffer.zeroize();
                self.buffered = 0;
                if self.keyed {
                    let mut key = self.key;
                    self.update(&key);
                    key.zeroize();
                }
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.h.zeroize();
                self.t.zeroize();
                self.buffer.zeroize();
                self.buffered.zeroize();
                self.initial.zeroize();
                self.key.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!(stringify!($name), "({} bytes, ..)"), self.output_length)
            }
        }
    };
}

blake2!(
    /// BLAKE2b: 64-bit words, 128-byte blocks, 12 rounds, up to 64 bytes of
    /// output and key (RFC 7693).
    BLAKE2b,
    BLAKE2bParameters,
    u64,
    128,
    64,
    12,
    [32, 24, 16, 63],
    [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ]
);

blake2!(
    /// BLAKE2s: 32-bit words, 64-byte blocks, 10 rounds, up to 32 bytes of
    /// output and key (RFC 7693).
    BLAKE2s,
    BLAKE2sParameters,
    u32,
    64,
    32,
    10,
    [16, 12, 8, 7],
    [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
);
