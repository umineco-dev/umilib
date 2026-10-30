use core::fmt;

use super::Sponge;
use crate::hash::{ExtendableOutput, HashError};
use crate::secret::Zeroize;

/// The encodings of SP 800-185 section 2.3, which the functions derived from
/// SHA-3 use to frame their inputs unambiguously.
pub struct SP800185;

impl SP800185 {
    /// `left_encode(x)`: the number of bytes of `x`, then `x` big-endian in
    /// the fewest bytes (at least one). Returns the encoding and its length.
    pub fn left_encode(x: u128) -> ([u8; 17], usize) {
        let bytes = x.to_be_bytes();
        let start = bytes.iter().position(|&byte| byte != 0).unwrap_or(15).min(15);
        let length = 16 - start;
        let mut encoded = [0u8; 17];
        encoded[0] = length as u8;
        encoded[1..1 + length].copy_from_slice(&bytes[start..]);
        (encoded, 1 + length)
    }

    /// `right_encode(x)`: `x` big-endian in the fewest bytes, then their number.
    pub fn right_encode(x: u128) -> ([u8; 17], usize) {
        let (left, length) = SP800185::left_encode(x);
        let mut encoded = [0u8; 17];
        encoded[..length - 1].copy_from_slice(&left[1..length]);
        encoded[length - 1] = left[0];
        (encoded, length)
    }

    /// Absorbs `encode_string(string)`: `left_encode` of its length in bits, then the string.
    pub fn absorb_string<const RATE: usize>(sponge: &mut Sponge<RATE>, string: &[u8]) {
        let (length, size) = SP800185::left_encode(string.len() as u128 * 8);
        sponge.absorb(&length[..size]);
        sponge.absorb(string);
    }

    /// Absorbs `bytepad(encode_string(name) || encode_string(customization), RATE)`
    /// into a sponge at the start of a block.
    pub fn absorb_prefix<const RATE: usize>(sponge: &mut Sponge<RATE>, name: &[u8], customization: &[u8]) {
        let (rate, size) = SP800185::left_encode(RATE as u128);
        sponge.absorb(&rate[..size]);
        SP800185::absorb_string(sponge, name);
        SP800185::absorb_string(sponge, customization);
        sponge.fill_block();
    }
}

/// Defines cSHAKE (section 3) on the sponge with `RATE` bytes.
macro_rules! cshake {
    ($(#[$documentation:meta])* $name:ident, $rate:literal) => {
        $(#[$documentation])*
        #[derive(Clone)]
        pub struct $name {
            sponge: Sponge<$rate>,
            /// The sponge after the prefix, to which `reset` returns.
            initial: Sponge<$rate>,
        }

        impl $name {
            /// The domain separation bits `00` of cSHAKE and the first padding bit.
            pub const SUFFIX: u8 = 0x04;

            /// cSHAKE with the function name `name` (reserved for NIST) and the
            /// customization string `customization`; with both empty it is SHAKE.
            pub fn new(name: &[u8], customization: &[u8]) -> $name {
                let sponge = if name.is_empty() && customization.is_empty() {
                    Sponge::new(0x1F)
                } else {
                    let mut sponge = Sponge::new($name::SUFFIX);
                    SP800185::absorb_prefix(&mut sponge, name, customization);
                    sponge
                };
                $name { initial: sponge.clone(), sponge }
            }
        }

        impl ExtendableOutput for $name {
            const BLOCK_SIZE: usize = $rate;
            type Reader = Sponge<$rate>;

            fn update(&mut self, data: &[u8]) {
                self.sponge.absorb(data);
            }

            fn finalize_xof(self) -> Sponge<$rate> {
                let mut sponge = self.sponge;
                sponge.pad();
                sponge
            }

            fn reset(&mut self) {
                self.sponge = self.initial.clone();
            }
        }

        impl Default for $name {
            /// cSHAKE without name and customization, which is SHAKE.
            fn default() -> $name {
                $name::new(&[], &[])
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.sponge.zeroize();
                self.initial.zeroize();
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

cshake!(
    /// cSHAKE128 (SP 800-185 section 3).
    CSHAKE128, 168
);
cshake!(
    /// cSHAKE256 (SP 800-185 section 3).
    CSHAKE256, 136
);

/// Defines TupleHash (section 5) over the cSHAKE `$cshake`.
macro_rules! tuple_hash {
    ($(#[$documentation:meta])* $name:ident, $cshake:ident, $rate:literal) => {
        $(#[$documentation])*
        #[derive(Clone, Debug)]
        pub struct $name {
            cshake: $cshake,
        }

        impl $name {
            /// TupleHash with the customization string `customization`.
            pub fn new(customization: &[u8]) -> $name {
                $name { cshake: $cshake::new(b"TupleHash", customization) }
            }

            /// Adds the next string of the tuple: `encode_string(element)`.
            pub fn push(&mut self, element: &[u8]) {
                SP800185::absorb_string(&mut self.cshake.sponge, element);
            }

            /// Writes the `out.len()` bytes of TupleHash of the tuple so far
            /// (the output length is part of the input).
            pub fn finalize(self, out: &mut [u8]) {
                let (length, size) = SP800185::right_encode(out.len() as u128 * 8);
                let mut cshake = self.cshake;
                cshake.update(&length[..size]);
                cshake.finalize_xof().squeeze(out);
            }

            /// TupleHashXOF (section 5.3.1): the output does not depend on its length.
            pub fn finalize_xof(self) -> Sponge<$rate> {
                let (length, size) = SP800185::right_encode(0);
                let mut cshake = self.cshake;
                cshake.update(&length[..size]);
                cshake.finalize_xof()
            }

            /// Returns to the empty tuple.
            pub fn reset(&mut self) {
                self.cshake.reset();
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.cshake.zeroize();
            }
        }
    };
}

tuple_hash!(
    /// TupleHash128 (SP 800-185 section 5), over cSHAKE128.
    TupleHash128, CSHAKE128, 168
);
tuple_hash!(
    /// TupleHash256 (SP 800-185 section 5), over cSHAKE256.
    TupleHash256, CSHAKE256, 136
);

/// Defines ParallelHash (section 6) over the cSHAKE `$cshake`, whose blocks
/// are hashed to `$chaining` bytes.
macro_rules! parallel_hash {
    ($(#[$documentation:meta])* $name:ident, $cshake:ident, $rate:literal, $chaining:literal) => {
        $(#[$documentation])*
        #[derive(Clone, Debug)]
        pub struct $name {
            outer: $cshake,
            /// The outer state after the prefix and the block size, to which `reset` returns.
            initial: $cshake,
            /// The block being hashed: cSHAKE with empty name and customization.
            inner: $cshake,
            block_size: usize,
            in_block: usize,
            blocks: u128,
        }

        impl $name {
            /// ParallelHash with blocks of `block_size` bytes and the
            /// customization string `customization`; fails if `block_size` is 0.
            pub fn new(block_size: usize, customization: &[u8]) -> Result<$name, HashError> {
                if block_size == 0 {
                    return Err(HashError::InvalidParameter);
                }
                let mut outer = $cshake::new(b"ParallelHash", customization);
                let (size, length) = SP800185::left_encode(block_size as u128);
                outer.update(&size[..length]);
                Ok($name { initial: outer.clone(), outer, inner: $cshake::default(), block_size, in_block: 0, blocks: 0 })
            }

            pub fn block_size(&self) -> usize {
                self.block_size
            }

            /// Adds `data` to the input.
            pub fn update(&mut self, mut data: &[u8]) {
                while !data.is_empty() {
                    let taken = data.len().min(self.block_size - self.in_block);
                    self.inner.update(&data[..taken]);
                    self.in_block += taken;
                    data = &data[taken..];
                    if self.in_block == self.block_size {
                        self.finish_block();
                    }
                }
            }

            /// Hashes the current block into the outer input; does nothing if
            /// it is empty, because ParallelHash has no empty blocks.
            pub fn finish_block(&mut self) {
                if self.in_block == 0 {
                    return;
                }
                let mut chaining = [0u8; $chaining];
                let inner = core::mem::take(&mut self.inner);
                inner.finalize_xof().squeeze(&mut chaining);
                self.outer.update(&chaining);
                chaining.zeroize();
                self.in_block = 0;
                self.blocks += 1;
            }

            /// Ends the input with the output length `length_bits` (0 for
            /// ParallelHashXOF) and returns the reader of the output.
            pub fn finalize_bits(mut self, length_bits: u128) -> Sponge<$rate> {
                self.finish_block();
                let (count, size) = SP800185::right_encode(self.blocks);
                self.outer.update(&count[..size]);
                let (length, size) = SP800185::right_encode(length_bits);
                self.outer.update(&length[..size]);
                self.outer.finalize_xof()
            }

            /// Writes the `out.len()` bytes of ParallelHash of the input.
            pub fn finalize(self, out: &mut [u8]) {
                let length = out.len() as u128 * 8;
                self.finalize_bits(length).squeeze(out);
            }

            /// ParallelHashXOF (section 6.3.1).
            pub fn finalize_xof(self) -> Sponge<$rate> {
                self.finalize_bits(0)
            }

            /// Returns to the empty input with the same block size and customization.
            pub fn reset(&mut self) {
                self.outer = self.initial.clone();
                self.inner.reset();
                self.in_block = 0;
                self.blocks = 0;
            }
        }

        impl ExtendableOutput for $name {
            const BLOCK_SIZE: usize = $rate;
            type Reader = Sponge<$rate>;

            fn update(&mut self, data: &[u8]) {
                $name::update(self, data);
            }

            /// ParallelHashXOF.
            fn finalize_xof(self) -> Sponge<$rate> {
                $name::finalize_xof(self)
            }

            fn reset(&mut self) {
                $name::reset(self);
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.outer.zeroize();
                self.initial.zeroize();
                self.inner.zeroize();
            }
        }
    };
}

parallel_hash!(
    /// ParallelHash128 (SP 800-185 section 6), over cSHAKE128 with 256-bit block hashes.
    ParallelHash128, CSHAKE128, 168, 32
);
parallel_hash!(
    /// ParallelHash256 (SP 800-185 section 6), over cSHAKE256 with 512-bit block hashes.
    ParallelHash256, CSHAKE256, 136, 64
);
