use core::fmt;

use super::{BLAKE2b, BLAKE2bParameters, BLAKE2s, BLAKE2sParameters};
use crate::hash::HashError;
use crate::secret::Zeroize;

/// Defines the parallel mode of BLAKE2 with `$lanes` leaves: the input is
/// split into blocks dealt to the leaves in turn, and a root node hashes the
/// leaves' outputs (fanout `$lanes`, depth 2).
macro_rules! parallel_blake2 {
    ($(#[$documentation:meta])* $name:ident, $engine:ident, $parameters:ident, $lanes:literal, $block:literal, $output:literal) => {
        $(#[$documentation])*
        #[derive(Clone)]
        pub struct $name {
            leaves: [$engine; $lanes],
            root: $engine,
            buffer: [u8; $lanes * $block],
            buffered: usize,
        }

        impl $name {
            pub const LANES: usize = $lanes;

            pub fn new(output_length: usize) -> Result<$name, HashError> {
                $name::with_key(&[], output_length)
            }

            /// The keyed function: every leaf processes the key block first.
            pub fn with_key(key: &[u8], output_length: usize) -> Result<$name, HashError> {
                if output_length == 0 || output_length > $output {
                    return Err(HashError::OutputLength { length: output_length, minimum: 1, maximum: $output });
                }
                if key.len() > $output {
                    return Err(HashError::KeyLength { length: key.len(), minimum: 0, maximum: $output });
                }
                let node = |offset: u32, node_depth: u8, digest_length: usize| {
                    let mut parameters = $parameters::new(digest_length as u8);
                    parameters.key_length = key.len() as u8;
                    parameters.fanout = $lanes;
                    parameters.depth = 2;
                    parameters.node_offset = offset;
                    parameters.node_depth = node_depth;
                    parameters.inner_length = $output;
                    parameters
                };
                // The root has the key length in its parameters but no key block.
                let mut root = $engine::without_key_block(&node(0, 1, output_length))?;
                root.set_last_node(true);
                // Leaves output `inner_length` bytes; their parameters are valid
                // because the output and key lengths were checked above.
                let mut leaves: [$engine; $lanes] = core::array::from_fn(|lane| {
                    $engine::with_parameters(&node(lane as u32, 0, $output), key).expect("valid leaf parameters")
                });
                leaves[$lanes - 1].set_last_node(true);
                Ok($name { leaves, root, buffer: [0; $lanes * $block], buffered: 0 })
            }

            pub fn update(&mut self, mut data: &[u8]) {
                let fill = self.buffer.len() - self.buffered;
                if self.buffered > 0 && data.len() >= fill {
                    self.buffer[self.buffered..].copy_from_slice(&data[..fill]);
                    for (lane, leaf) in self.leaves.iter_mut().enumerate() {
                        leaf.update(&self.buffer[lane * $block..(lane + 1) * $block]);
                    }
                    self.buffered = 0;
                    data = &data[fill..];
                }
                while data.len() >= $lanes * $block {
                    for (lane, leaf) in self.leaves.iter_mut().enumerate() {
                        leaf.update(&data[lane * $block..(lane + 1) * $block]);
                    }
                    data = &data[$lanes * $block..];
                }
                self.buffer[self.buffered..self.buffered + data.len()].copy_from_slice(data);
                self.buffered += data.len();
            }

            /// Writes the output, which must have the output length, and resets the state.
            pub fn finalize_into(&mut self, out: &mut [u8]) -> Result<(), HashError> {
                if out.len() != self.root.output_length() {
                    let length = self.root.output_length();
                    return Err(HashError::OutputLength { length: out.len(), minimum: length, maximum: length });
                }
                for (lane, leaf) in self.leaves.iter_mut().enumerate() {
                    let start = lane * $block;
                    if self.buffered > start {
                        let end = self.buffered.min(start + $block);
                        leaf.update(&self.buffer[start..end]);
                    }
                    let mut hash = [0u8; $output];
                    leaf.finalize_into(&mut hash)?;
                    self.root.update(&hash);
                    hash.zeroize();
                }
                self.root.finalize_into(out)?;
                self.buffer.zeroize();
                self.buffered = 0;
                Ok(())
            }

            pub fn output_length(&self) -> usize {
                self.root.output_length()
            }

            /// Returns to the state after the parameters and the key.
            pub fn reset(&mut self) {
                self.leaves.iter_mut().for_each($engine::reset);
                self.root.reset();
                self.buffer.zeroize();
                self.buffered = 0;
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.leaves.iter_mut().for_each(Zeroize::zeroize);
                self.root.zeroize();
                self.buffer.zeroize();
                self.buffered.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.buffer.zeroize();
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

parallel_blake2!(
    /// BLAKE2bp: BLAKE2b over 4 interleaved leaves.
    BLAKE2bp, BLAKE2b, BLAKE2bParameters, 4, 128, 64
);
parallel_blake2!(
    /// BLAKE2sp: BLAKE2s over 8 interleaved leaves.
    BLAKE2sp, BLAKE2s, BLAKE2sParameters, 8, 64, 32
);
