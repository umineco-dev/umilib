use core::fmt;

use super::Sponge;
use crate::hash::{CryptographicDigest, Digest};
use crate::secret::Zeroize;

/// Defines a fixed-length function on the sponge with `RATE` bytes, the
/// `suffix` and an output of `OUTPUT` bytes.
macro_rules! sponge_digest {
    ($(#[$documentation:meta])* $name:ident, $rate:literal, $output:literal, $suffix:literal) => {
        $(#[$documentation])*
        #[derive(Clone)]
        pub struct $name {
            sponge: Sponge<$rate>,
        }

        impl $name {
            /// The domain separation bits and the first padding bit.
            pub const SUFFIX: u8 = $suffix;

            pub const fn new() -> $name {
                $name { sponge: Sponge::new($suffix) }
            }
        }

        impl Digest for $name {
            const OUTPUT_SIZE: usize = $output;
            const BLOCK_SIZE: usize = $rate;
            type Output = [u8; $output];

            fn update(&mut self, data: &[u8]) {
                self.sponge.absorb(data);
            }

            fn finalize(mut self) -> [u8; $output] {
                let mut output = [0; $output];
                self.sponge.squeeze(&mut output);
                output
            }

            fn reset(&mut self) {
                self.sponge.reset();
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
                self.sponge.zeroize();
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

sponge_digest!(
    /// SHA3-224 (FIPS 202 section 6.1): capacity 448 bits.
    SHA3_224, 144, 28, 0x06
);
sponge_digest!(
    /// SHA3-256 (FIPS 202 section 6.1): capacity 512 bits.
    SHA3_256, 136, 32, 0x06
);
sponge_digest!(
    /// SHA3-384 (FIPS 202 section 6.1): capacity 768 bits.
    SHA3_384, 104, 48, 0x06
);
sponge_digest!(
    /// SHA3-512 (FIPS 202 section 6.1): capacity 1024 bits.
    SHA3_512, 72, 64, 0x06
);
sponge_digest!(
    /// Keccak-224: SHA3-224 with the padding of the Keccak submission
    /// (no domain separation bits), as some protocols still use.
    Keccak224, 144, 28, 0x01
);
sponge_digest!(
    /// Keccak-256: SHA3-256 with the padding of the Keccak submission, as
    /// Ethereum uses.
    Keccak256, 136, 32, 0x01
);
sponge_digest!(
    /// Keccak-384: SHA3-384 with the padding of the Keccak submission.
    Keccak384, 104, 48, 0x01
);
sponge_digest!(
    /// Keccak-512: SHA3-512 with the padding of the Keccak submission.
    Keccak512, 72, 64, 0x01
);
