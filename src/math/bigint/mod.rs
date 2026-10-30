//! Unsigned big integers of fixed precision, in constant time.
//!
//! The algorithms are written once, on slices of [`Limb`]s, in [`Limbs`].
//! [`Uint`] holds a number of limbs fixed at compile time on the stack (for
//! elliptic curve fields), and [`BoxedUint`] a number chosen at run time on
//! the heap (for RSA and Diffie-Hellman moduli); [`UnsignedInteger`] is
//! the interface of `Uint` for code generic over the precision. Unless a method name ends in
//! `_vartime`, its timing depends only on the precision and on public
//! arguments such as shift amounts, never on the values.

mod boxed;
mod error;
mod limb;
mod limbs;
mod uint;
mod unsigned_integer;

pub use boxed::BoxedUint;
pub use error::MathError;
pub use limb::{Limb, WideLimb};
pub use limbs::Limbs;
pub use uint::{
    U64, U128, U192, U256, U320, U384, U448, U512, U576, U640, U768, U896, U1024, U1536, U2048, U3072, U4096, U6144,
    U8192, Uint,
};
pub use unsigned_integer::UnsignedInteger;
