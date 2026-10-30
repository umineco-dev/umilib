use core::fmt;

use super::Sponge;
use crate::hash::ExtendableOutput;
use crate::secret::Zeroize;

/// Defines a SHAKE function on the sponge with `RATE` bytes.
macro_rules! shake {
    ($(#[$documentation:meta])* $name:ident, $rate:literal) => {
        $(#[$documentation])*
        #[derive(Clone)]
        pub struct $name {
            sponge: Sponge<$rate>,
        }

        impl $name {
            /// The domain separation bits `1111` and the first padding bit.
            pub const SUFFIX: u8 = 0x1F;

            pub const fn new() -> $name {
                $name { sponge: Sponge::new($name::SUFFIX) }
            }
        }

        impl ExtendableOutput for $name {
            const BLOCK_SIZE: usize = $rate;
            type Reader = Sponge<$rate>;

            fn update(&mut self, data: &[u8]) {
                self.sponge.absorb(data);
            }

            fn finalize_xof(mut self) -> Sponge<$rate> {
                let mut sponge = core::mem::replace(&mut self.sponge, Sponge::new($name::SUFFIX));
                sponge.pad();
                sponge
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

shake!(
    /// SHAKE128 (FIPS 202 section 6.2): 128-bit security, rate 168 bytes.
    SHAKE128, 168
);
shake!(
    /// SHAKE256 (FIPS 202 section 6.2): 256-bit security, rate 136 bytes.
    SHAKE256, 136
);
