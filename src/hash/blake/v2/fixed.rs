use super::{BLAKE2b, BLAKE2s};
use crate::hash::{CryptographicDigest, Digest, HashError};
use crate::secret::Zeroize;

/// Defines BLAKE2 with a fixed output length, which implements [`Digest`].
macro_rules! fixed_blake2 {
    ($(#[$documentation:meta])* $name:ident, $engine:ident, $bytes:literal) => {
        $(#[$documentation])*
        #[derive(Clone, Debug)]
        pub struct $name {
            inner: $engine,
        }

        impl $name {
            pub fn new() -> $name {
                // The output length is within the range of the engine.
                $name { inner: $engine::new($bytes).expect("a valid output length") }
            }

            /// The keyed function (a MAC); fails if the key is too long.
            pub fn with_key(key: &[u8]) -> Result<$name, HashError> {
                Ok($name { inner: $engine::with_key(key, $bytes)? })
            }
        }

        impl Digest for $name {
            const OUTPUT_SIZE: usize = $bytes;
            const BLOCK_SIZE: usize = $engine::BLOCK_SIZE;
            type Output = [u8; $bytes];

            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            fn finalize(mut self) -> [u8; $bytes] {
                let mut output = [0u8; $bytes];
                // The output has the length of the engine.
                let _ = self.inner.finalize_into(&mut output);
                output
            }

            fn reset(&mut self) {
                self.inner.reset();
            }
        }

        impl Default for $name {
            fn default() -> $name {
                $name::new()
            }
        }

        impl CryptographicDigest for $name {}

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.inner.zeroize();
            }
        }
    };
}

fixed_blake2!(
    /// BLAKE2b-512.
    BLAKE2b512, BLAKE2b, 64
);
fixed_blake2!(
    /// BLAKE2b-384.
    BLAKE2b384, BLAKE2b, 48
);
fixed_blake2!(
    /// BLAKE2b-256.
    BLAKE2b256, BLAKE2b, 32
);
fixed_blake2!(
    /// BLAKE2b-160.
    BLAKE2b160, BLAKE2b, 20
);
fixed_blake2!(
    /// BLAKE2s-256.
    BLAKE2s256, BLAKE2s, 32
);
fixed_blake2!(
    /// BLAKE2s-224.
    BLAKE2s224, BLAKE2s, 28
);
fixed_blake2!(
    /// BLAKE2s-160.
    BLAKE2s160, BLAKE2s, 20
);
fixed_blake2!(
    /// BLAKE2s-128.
    BLAKE2s128, BLAKE2s, 16
);
