use core::fmt;

use super::{BLAKE2b, BLAKE2bParameters, BLAKE2s, BLAKE2sParameters};
use crate::hash::{ExtendableOutput, HashError, XOFReader};
use crate::secret::Zeroize;

/// Defines BLAKE2X over `$engine`: a root hash whose parameters declare the
/// output length, then one output node per `$output` bytes, each a hash of
/// the root hash with its own node offset (the BLAKE2X specification), and
/// `$reader`, which computes the output nodes as they are read.
macro_rules! blake2x {
    (
        $(#[$documentation:meta])* $name:ident,
        $(#[$reader_documentation:meta])* $reader:ident,
        $engine:ident, $parameters:ident, $length:ty, $output:literal
    ) => {
        $(#[$documentation])*
        #[derive(Clone)]
        pub struct $name {
            root: $engine,
            parameters: $parameters,
        }

        impl $name {
            /// The output length that leaves it open, fixed only when finalizing.
            pub const UNKNOWN_LENGTH: $length = <$length>::MAX;
            /// The size of an output node, the most bytes one node gives.
            pub const NODE_SIZE: usize = $output;

            /// BLAKE2X with an output of `output_length` bytes (1 to
            /// `UNKNOWN_LENGTH - 1`, or `UNKNOWN_LENGTH`).
            pub fn new(output_length: $length) -> Result<$name, HashError> {
                $name::with_key(&[], output_length)
            }

            /// The keyed function.
            pub fn with_key(key: &[u8], output_length: $length) -> Result<$name, HashError> {
                let mut parameters = $parameters::new($output);
                parameters.key_length = key.len().min(u8::MAX as usize) as u8;
                parameters.xof_length = output_length;
                $name::with_parameters(&parameters, key)
            }

            /// BLAKE2X with every parameter of the root given, such as a salt
            /// and a personalization, which the output nodes share. The digest
            /// length must be the node size, `key_length` the length of `key`
            /// and `xof_length` the output length (not 0).
            pub fn with_parameters(parameters: &$parameters, key: &[u8]) -> Result<$name, HashError> {
                if parameters.xof_length == 0 {
                    return Err(HashError::OutputLength { length: 0, minimum: 1, maximum: <$length>::MAX as usize });
                }
                if parameters.digest_length as usize != $output {
                    return Err(HashError::InvalidParameter);
                }
                let root = $engine::with_parameters(parameters, key)?;
                Ok($name { root, parameters: *parameters })
            }

            /// The declared output length.
            pub fn output_length(&self) -> $length {
                self.parameters.xof_length
            }

            pub fn update(&mut self, data: &[u8]) {
                self.root.update(data);
            }

            /// Returns to the state after the parameters and the key.
            pub fn reset(&mut self) {
                self.root.reset();
            }

            /// The parameters of the output nodes, from those of the root.
            pub fn node_parameters(&self) -> $parameters {
                let mut node = self.parameters;
                node.key_length = 0;
                node.fanout = 0;
                node.depth = 0;
                node.leaf_length = $output;
                node.inner_length = $output;
                node.node_depth = 0;
                node
            }

            /// Writes the output into `out`, whose length must be the declared
            /// output length (any length but 0 if it is unknown), and resets the state.
            pub fn finalize_into(&mut self, out: &mut [u8]) -> Result<(), HashError> {
                let declared = self.parameters.xof_length;
                let valid = if declared == $name::UNKNOWN_LENGTH {
                    !out.is_empty() && out.len().div_ceil($output) <= u32::MAX as usize
                } else {
                    out.len() == declared as usize
                };
                if !valid {
                    return Err(HashError::OutputLength { length: out.len(), minimum: 1, maximum: declared as usize });
                }
                let mut root = [0u8; $output];
                self.root.finalize_into(&mut root)?;
                let mut node = self.node_parameters();
                for (index, chunk) in out.chunks_mut($output).enumerate() {
                    node.digest_length = chunk.len() as u8;
                    node.node_offset = index as u32;
                    let mut hash = $engine::with_parameters(&node, &[])?;
                    hash.update(&root);
                    hash.finalize_into(chunk)?;
                }
                root.zeroize();
                Ok(())
            }

            /// The reader of the output, which computes each output node when
            /// it is first read. With a declared length it gives exactly
            /// [`finalize_into`](Self::finalize_into)'s output; with
            /// `UNKNOWN_LENGTH` every node is whole, which equals that output
            /// for lengths that are multiples of the node size.
            pub fn finalize_xof(mut self) -> $reader {
                let mut root = [0u8; $output];
                // The root has its own output length, which `root` holds.
                let _ = self.root.finalize_into(&mut root);
                let declared = self.parameters.xof_length;
                let length = if declared == $name::UNKNOWN_LENGTH {
                    $output as u64 * (u32::MAX as u64 + 1)
                } else {
                    declared as u64
                };
                $reader { root, node: self.node_parameters(), length, position: 0 }
            }
        }

        impl ExtendableOutput for $name {
            const BLOCK_SIZE: usize = $engine::BLOCK_SIZE;
            type Reader = $reader;

            fn update(&mut self, data: &[u8]) {
                $name::update(self, data);
            }

            fn finalize_xof(self) -> $reader {
                $name::finalize_xof(self)
            }

            fn reset(&mut self) {
                $name::reset(self);
            }
        }

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.root.zeroize();
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }

        $(#[$reader_documentation])*
        #[derive(Clone)]
        pub struct $reader {
            /// The hash of the root node, which every output node hashes.
            root: [u8; $output],
            node: $parameters,
            /// The number of output bytes: the declared length, or 2^32 nodes.
            length: u64,
            position: u64,
        }

        impl $reader {
            /// The number of bytes before the next one read.
            pub fn position(&self) -> u64 {
                self.position
            }

            /// The number of bytes the output has.
            pub fn len(&self) -> u64 {
                self.length
            }

            pub fn is_empty(&self) -> bool {
                self.length == 0
            }

            /// Output node `index`, of `length` bytes, written into the start of `out`.
            pub fn node(&self, index: u64, out: &mut [u8; $output]) -> usize {
                let length = ($output as u64).min(self.length - index * $output as u64) as usize;
                let mut node = self.node;
                node.digest_length = length as u8;
                node.node_offset = index as u32;
                // The node parameters are valid: the lengths are within the engine's.
                if let Ok(mut hash) = $engine::with_parameters(&node, &[]) {
                    hash.update(&self.root);
                    let _ = hash.finalize_into(&mut out[..length]);
                }
                length
            }
        }

        impl XOFReader for $reader {
            /// Reads the next bytes; panics past the end of the output.
            fn read(&mut self, mut out: &mut [u8]) {
                let end = self.position.checked_add(out.len() as u64);
                assert!(end.is_some_and(|end| end <= self.length), "the output of BLAKE2X ends after its length");
                let mut block = [0u8; $output];
                while !out.is_empty() {
                    let index = self.position / $output as u64;
                    let offset = (self.position % $output as u64) as usize;
                    let length = self.node(index, &mut block);
                    let take = (length - offset).min(out.len());
                    out[..take].copy_from_slice(&block[offset..offset + take]);
                    out = &mut out[take..];
                    self.position += take as u64;
                }
                block.zeroize();
            }
        }

        impl Zeroize for $reader {
            fn zeroize(&mut self) {
                self.root.zeroize();
                self.position.zeroize();
            }
        }

        impl Drop for $reader {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl fmt::Debug for $reader {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($reader), "(..)"))
            }
        }
    };
}

blake2x!(
    /// BLAKE2Xb: outputs of up to 2^32 - 2 bytes over BLAKE2b.
    BLAKE2Xb,
    /// The output of BLAKE2Xb.
    BLAKE2XbReader,
    BLAKE2b, BLAKE2bParameters, u32, 64
);
blake2x!(
    /// BLAKE2Xs: outputs of up to 2^16 - 2 bytes over BLAKE2s.
    BLAKE2Xs,
    /// The output of BLAKE2Xs.
    BLAKE2XsReader,
    BLAKE2s, BLAKE2sParameters, u16, 32
);
