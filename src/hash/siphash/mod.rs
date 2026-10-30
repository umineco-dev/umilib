//! SipHash and HalfSipHash, keyed hash functions for short inputs (the
//! SipHash paper of Aumasson and Bernstein and its reference code), with any
//! numbers of compression and finalization rounds.

use core::fmt;
use core::hash::Hasher;

use crate::hash::Digest;
use crate::secret::Zeroize;

/// Defines a SipHash function on words of type `$word`.
///
/// `$constants` are the initialization constants of v0 to v3, `$rotations`
/// the rotation amounts of SipRound in order, and `$output` the function of
/// the state that gives each output word.
macro_rules! siphash {
    (
        $(#[$documentation:meta])*
        $name:ident, $word:ty, $outputs:literal,
        $constants:expr, [$r0:literal, $r1:literal, $r2:literal, $r3:literal, $r4:literal, $r5:literal],
        $output:expr
    ) => {
        $(#[$documentation])*
        #[derive(Clone)]
        pub struct $name<const C: usize, const D: usize> {
            v: [$word; 4],
            /// The bytes of the word not yet complete.
            tail: [u8; core::mem::size_of::<$word>()],
            buffered: usize,
            /// The input length so far, of which the lowest byte is used.
            length: u64,
            /// The state after the key, to which `reset` returns.
            initial: [$word; 4],
        }

        impl<const C: usize, const D: usize> $name<C, D> {
            /// The size of a word, the unit of compression, in bytes.
            pub const WORD_SIZE: usize = core::mem::size_of::<$word>();
            pub const KEY_SIZE: usize = 2 * core::mem::size_of::<$word>();
            pub const OUTPUT_SIZE: usize = $outputs * core::mem::size_of::<$word>();
            /// The initialization constants of v0, v1, v2 and v3.
            pub const CONSTANTS: [$word; 4] = $constants;

            pub fn new(key: &[u8; 2 * core::mem::size_of::<$word>()]) -> $name<C, D> {
                let (k0, k1) = key.split_at(core::mem::size_of::<$word>());
                let mut k = [
                    <$word>::from_le_bytes(k0.try_into().expect("half of the key")),
                    <$word>::from_le_bytes(k1.try_into().expect("half of the key")),
                ];
                let mut v = $name::<C, D>::CONSTANTS;
                v[0] ^= k[0];
                v[1] ^= k[1];
                v[2] ^= k[0];
                v[3] ^= k[1];
                if $outputs == 2 {
                    v[1] ^= 0xEE;
                }
                k.zeroize();
                $name { v, tail: [0; core::mem::size_of::<$word>()], buffered: 0, length: 0, initial: v }
            }

            /// The output for `data` under `key`.
            pub fn hash(key: &[u8; 2 * core::mem::size_of::<$word>()], data: &[u8]) -> [u8; $outputs * core::mem::size_of::<$word>()] {
                let mut state = $name::<C, D>::new(key);
                state.update(data);
                state.output()
            }

            /// SipRound.
            pub fn round(v: &mut [$word; 4]) {
                v[0] = v[0].wrapping_add(v[1]);
                v[1] = v[1].rotate_left($r0);
                v[1] ^= v[0];
                v[0] = v[0].rotate_left($r1);
                v[2] = v[2].wrapping_add(v[3]);
                v[3] = v[3].rotate_left($r2);
                v[3] ^= v[2];
                v[0] = v[0].wrapping_add(v[3]);
                v[3] = v[3].rotate_left($r3);
                v[3] ^= v[0];
                v[2] = v[2].wrapping_add(v[1]);
                v[1] = v[1].rotate_left($r4);
                v[1] ^= v[2];
                v[2] = v[2].rotate_left($r5);
            }

            /// Compresses the message word `m` with C rounds.
            pub fn compress(v: &mut [$word; 4], m: $word) {
                v[3] ^= m;
                for _ in 0..C {
                    $name::<C, D>::round(v);
                }
                v[0] ^= m;
            }

            pub fn update(&mut self, mut data: &[u8]) {
                self.length = self.length.wrapping_add(data.len() as u64);
                if self.buffered > 0 {
                    let take = ($name::<C, D>::WORD_SIZE - self.buffered).min(data.len());
                    self.tail[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
                    self.buffered += take;
                    data = &data[take..];
                    if self.buffered < $name::<C, D>::WORD_SIZE {
                        return;
                    }
                    $name::<C, D>::compress(&mut self.v, <$word>::from_le_bytes(self.tail));
                    self.buffered = 0;
                }
                let (words, rest) = data.as_chunks::<{ core::mem::size_of::<$word>() }>();
                for word in words {
                    $name::<C, D>::compress(&mut self.v, <$word>::from_le_bytes(*word));
                }
                self.tail[..rest.len()].copy_from_slice(rest);
                self.buffered = rest.len();
            }

            /// The output of the input so far, without changing the state.
            pub fn output(&self) -> [u8; $outputs * core::mem::size_of::<$word>()] {
                let mut v = self.v;
                let mut last = [0u8; core::mem::size_of::<$word>()];
                last[..self.buffered].copy_from_slice(&self.tail[..self.buffered]);
                last[$name::<C, D>::WORD_SIZE - 1] = self.length as u8;
                $name::<C, D>::compress(&mut v, <$word>::from_le_bytes(last));
                v[2] ^= if $outputs == 2 { 0xEE } else { 0xFF };
                let mut out = [0u8; $outputs * core::mem::size_of::<$word>()];
                for (index, chunk) in out.as_chunks_mut::<{ core::mem::size_of::<$word>() }>().0.iter_mut().enumerate() {
                    if index == 1 {
                        v[1] ^= 0xDD;
                    }
                    for _ in 0..D {
                        $name::<C, D>::round(&mut v);
                    }
                    *chunk = ($output)(&v).to_le_bytes();
                }
                v.zeroize();
                last.zeroize();
                out
            }

            /// Returns to the state after the key.
            pub fn reset(&mut self) {
                self.v = self.initial;
                self.tail.zeroize();
                self.buffered = 0;
                self.length = 0;
            }
        }

        impl<const C: usize, const D: usize> Digest for $name<C, D> {
            const OUTPUT_SIZE: usize = $outputs * core::mem::size_of::<$word>();
            const BLOCK_SIZE: usize = core::mem::size_of::<$word>();
            type Output = [u8; $outputs * core::mem::size_of::<$word>()];

            fn update(&mut self, data: &[u8]) {
                $name::update(self, data);
            }

            fn finalize(self) -> Self::Output {
                self.output()
            }

            fn finalize_reset(&mut self) -> Self::Output {
                let output = self.output();
                $name::reset(self);
                output
            }

            fn reset(&mut self) {
                $name::reset(self);
            }
        }

        impl<const C: usize, const D: usize> Zeroize for $name<C, D> {
            fn zeroize(&mut self) {
                self.v.zeroize();
                self.tail.zeroize();
                self.buffered.zeroize();
                self.length.zeroize();
                self.initial.zeroize();
            }
        }

        impl<const C: usize, const D: usize> Drop for $name<C, D> {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl<const C: usize, const D: usize> fmt::Debug for $name<C, D> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!(stringify!($name), "-{}-{}(..)"), C, D)
            }
        }
    };
}

/// Implements [`Hasher`] for a function with 64 bits of output, read as a
/// little-endian integer. The integer methods of [`Hasher`] write the bytes
/// in native order, so their results differ between byte orders; hash byte
/// slices for results that are the same everywhere.
macro_rules! siphash_hasher {
    ($name:ident) => {
        impl<const C: usize, const D: usize> Hasher for $name<C, D> {
            fn write(&mut self, bytes: &[u8]) {
                self.update(bytes);
            }

            fn finish(&self) -> u64 {
                u64::from_le_bytes(self.output())
            }
        }
    };
}

siphash!(
    /// SipHash-C-D with 64 bits of output and a 128-bit key.
    SipHash,
    u64,
    1,
    [0x736F6D6570736575, 0x646F72616E646F6D, 0x6C7967656E657261, 0x7465646279746573],
    [13, 32, 16, 21, 17, 32],
    |v: &[u64; 4]| v[0] ^ v[1] ^ v[2] ^ v[3]
);

siphash!(
    /// SipHash-C-D with 128 bits of output and a 128-bit key.
    SipHash128,
    u64,
    2,
    [0x736F6D6570736575, 0x646F72616E646F6D, 0x6C7967656E657261, 0x7465646279746573],
    [13, 32, 16, 21, 17, 32],
    |v: &[u64; 4]| v[0] ^ v[1] ^ v[2] ^ v[3]
);

siphash!(
    /// HalfSipHash-C-D: 32-bit words, 32 bits of output and a 64-bit key.
    HalfSipHash,
    u32,
    1,
    [0, 0, 0x6C796765, 0x74656462],
    [5, 16, 8, 7, 13, 16],
    |v: &[u32; 4]| v[1] ^ v[3]
);

siphash!(
    /// HalfSipHash-C-D: 32-bit words, 64 bits of output and a 64-bit key.
    HalfSipHash64,
    u32,
    2,
    [0, 0, 0x6C796765, 0x74656462],
    [5, 16, 8, 7, 13, 16],
    |v: &[u32; 4]| v[1] ^ v[3]
);

siphash_hasher!(SipHash);
siphash_hasher!(HalfSipHash64);

/// SipHash-2-4, the recommended SipHash.
pub type SipHash24 = SipHash<2, 4>;
/// SipHash-1-3, the faster variant (used by the Rust standard library).
pub type SipHash13 = SipHash<1, 3>;
/// SipHash-2-4 with 128 bits of output.
pub type SipHash128_24 = SipHash128<2, 4>;
/// SipHash-1-3 with 128 bits of output.
pub type SipHash128_13 = SipHash128<1, 3>;
/// HalfSipHash-2-4 with 32 bits of output.
pub type HalfSipHash24 = HalfSipHash<2, 4>;
/// HalfSipHash-1-3 with 32 bits of output.
pub type HalfSipHash13 = HalfSipHash<1, 3>;
/// HalfSipHash-2-4 with 64 bits of output.
pub type HalfSipHash64_24 = HalfSipHash64<2, 4>;
/// HalfSipHash-1-3 with 64 bits of output.
pub type HalfSipHash64_13 = HalfSipHash64<1, 3>;
